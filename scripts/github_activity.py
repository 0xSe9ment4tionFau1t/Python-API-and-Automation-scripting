"""GitHub activity extractor.
 
Collects commits, pull requests, and issues from all repositories the
token can access, normalizes them into one common record format, and
writes a chronological timeline as JSON Lines and CSV.
"""
import csv
import json
import logging
import sys
import time
from getpass import getpass
from pathlib import Path

import requests

# ---------- Configuration ----------
# Output files are written to the folder containing this script
BASE_DIR = Path(__file__).parent 
JSONL_PATH = BASE_DIR / "github_activity.jsonl"
CSV_PATH = BASE_DIR / "github_activity.csv"
LOG_PATH = BASE_DIR / "github_activity.log"

API_URL = "https://api.github.com" # Base Github url
MAX_PAGES = 50 # Safety limit: max pages fetched per endpoint 
MAX_RETRIES = 3 # Max attempts per request before giving up
BACKOFF = 2       # Initial retry delay in seconds; doubles each attempt (2s, 4s, ...)
MAX_WAIT = 300    # longest rate-limit wait we accept, in seconds

# Activity sources to collect per repository, with their query parameters.
# Keys are GitHub endpoint names and must match the keys in NORMALIZERS.
ENDPOINTS = {
    "commits": {"per_page": 100},
    "pulls":   {"per_page": 100, "state": "all"},
    "issues":  {"per_page": 100, "state": "all"},
}
# Log to the console and to a file, with timestamps and severity levels
logging.basicConfig( 
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)


# ---------- HTTP helpers ----------

def backoff_sleep(attempt):
    """Wait before the next attempt, but not after the last one."""
    if attempt < MAX_RETRIES:
        time.sleep(BACKOFF * 2 ** (attempt - 1))


def rate_limit_wait(r):
    """Return seconds to wait if the response is a rate limit, otherwise None.
 
    GitHub signals rate limits with 403 or 429, plus either a Retry-After
    header or X-RateLimit-Remaining: 0 with a reset timestamp.
    """
    if r.status_code not in (403, 429):
        return None
    if "Retry-After" in r.headers:
        return int(r.headers["Retry-After"])
    if r.headers.get("X-RateLimit-Remaining") == "0":
        reset = int(r.headers["X-RateLimit-Reset"])
        return max(reset - time.time(), 0) + 1
    return None  # a 403 that isn't a rate limit, e.g. missing permissions
 
def fetch(session, label, url, **kwargs):
    """Send a GET request with retries and rate-limit handling.
    Retries timeouts, connection errors, and 5xx responses with exponential
    backoff, and waits out rate limits up to MAX_WAIT seconds.
    Returns the response on success (2xx, even with an empty body),
    or None if the request failed. Failures are logged.
    """
    kwargs.setdefault("timeout", 10)
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = session.get(url, **kwargs)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            log.warning(f"{label}: attempt {attempt}/{MAX_RETRIES} failed: {e}")
            backoff_sleep(attempt)
            continue

        # Rate limited: wait as long as GitHub asks, unless that's too long
        wait = rate_limit_wait(r)
        if wait is not None:
            if wait > MAX_WAIT:
                log.error(f"{label}: rate limited for {wait:.0f}s (over {MAX_WAIT}s limit), giving up")
                return None
            log.warning(f"{label}: rate limited, waiting {wait:.0f}s")
            time.sleep(wait)
            continue
        # Server errors (5xx) handling, retry based on MAX_RETRIES
        if r.status_code >= 500:
            log.warning(f"{label}: server error {r.status_code}, attempt {attempt}/{MAX_RETRIES}")
            backoff_sleep(attempt)
            continue
        # Other 4xx errors (401, 404, 409, ...) handling
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            log.error(f"{label}: {e.response.status_code} -> {e}")
            return None
        return r # Success
    # Only reached if every attempt hit a retryable failure
    log.error(f"{label}: giving up after {MAX_RETRIES} attempts")
    return None


def fetch_all(session, label, url, params=None):
    """Fetch every page of a paginated GitHub list endpoint.
    Follows the "next" links in the Link response header until there are
    no more pages, or until MAX_PAGES is reached
    """
    items = []
    pages = 0
    while url is not None:
        if pages >= MAX_PAGES:
            log.warning(f"{label}: reached {MAX_PAGES} pages, stopping early")
            break

        resp = fetch(session, label, url, params=params)
        if resp is None:
            return None

        items.extend(resp.json())
        pages += 1

        next_link = resp.links.get("next")
        url = next_link["url"] if next_link else None
        params = None  # the next URL already contains the query parameters
    return items


# ---------- Normalizers ----------
# Each normalizer turns one raw API item into a record with the same six keys
# (timestamp, repo, type, actor, summary, details), so all activity types can
# be merged, sorted, and exported together.
def normalize_commit(repo, commit):
    return { # Git author date and name are self-declared by the committer, not verified by GitHub
        "timestamp": commit["commit"]["author"]["date"],
        "repo": repo,
        "type": "commit",
        "actor": commit["commit"]["author"]["name"],
        "summary": commit["commit"]["message"].splitlines()[0], # First line of the message only
        "details": f"sha={commit['sha'][:7]} verified={commit['commit']['verification']['verified']}",
    }


def normalize_pull(repo, pr):
    return {
        "timestamp": pr["created_at"],
        "repo": repo,
        "type": "pull",
        "actor": pr["user"]["login"],
        "summary": pr["title"],
        "details": f"#{pr['number']} state={pr['state']} merged={pr['merged_at']}",
    }


def normalize_issue(repo, issue):
    return {
        "timestamp": issue["created_at"],
        "repo": repo,
        "type": "issue",
        "actor": issue["user"]["login"],
        "summary": issue["title"],
        "details": f"#{issue['number']} state={issue['state']}",
    }

# Maps each endpoint name to its normalizer; keys must match ENDPOINTS
NORMALIZERS = {
    "commits": normalize_commit,
    "pulls":   normalize_pull,
    "issues":  normalize_issue,
}


# ---------- Main steps ----------

def make_session(token):
    # Create a session that sends the auth and API headers with every request.
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    return session


def collect_records(session, repos):
    """Fetch all activity types for every repo and return normalized records.
    A failed endpoint is skipped (and logged) without affecting the others.
    """
    records = []
    for repo in repos:
        name = repo["full_name"]
        for kind, params in ENDPOINTS.items():
            url = f"{API_URL}/repos/{name}/{kind}"
            items = fetch_all(session, f"{kind} {name}", url, params=params)
            if items is None:
                continue # Skip only this activity type, e.g. commits of an empty repo (409)

            log.info(f"{kind} {name}: {len(items)} items fetched")
            normalize = NORMALIZERS[kind]
            for item in items:
                if kind == "issues" and "pull_request" in item:
                    continue  # skip pull-requests hiding in the issues list
                records.append(normalize(name, item))
    return records


def write_outputs(records):
    """Write records as JSON Lines (for tools/SIEM) and CSV (for spreadsheets)."""
    with open(JSONL_PATH, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    fieldnames = list(records[0].keys())
    with open(CSV_PATH, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)


def main():
    # getpass hides the input and keeps the token out of command history and process logs
    # TODO: look for some other ways for token passing 
    token = getpass("GitHub token: ").strip()
    session = make_session(token)

    # test = fetch(session, "test", "https://httpbin.org/status/503") testing server error

    repos = fetch_all(session, "repos", f"{API_URL}/user/repos", params={"per_page": 100})
    if repos is None:
        log.error("Could not fetch repos, stopping")
        sys.exit(1)
    log.info(f"Found {len(repos)} repos")

    records = collect_records(session, repos)
    if not records:
        log.info("No records collected, nothing to write")
        return

    records.sort(key=lambda r: r["timestamp"])
    write_outputs(records)
    log.info(f"Wrote {len(records)} records to {JSONL_PATH} and {CSV_PATH}")


if __name__ == "__main__":
    main()
