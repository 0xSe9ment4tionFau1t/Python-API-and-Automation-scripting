import csv
import json
import logging
import sys
import time
from getpass import getpass
from pathlib import Path

import requests

# ---------- Configuration ----------

BASE_DIR = Path(__file__).parent
JSONL_PATH = BASE_DIR / "github_activity.jsonl"
CSV_PATH = BASE_DIR / "github_activity.csv"
LOG_PATH = BASE_DIR / "github_activity.log"

API_URL = "https://api.github.com"
MAX_PAGES = 50
MAX_RETRIES = 3
BACKOFF = 2       # seconds; doubles each attempt (2s, 4s, ...)
MAX_WAIT = 300    # longest rate-limit wait we accept, in seconds

ENDPOINTS = {
    "commits": {"per_page": 100},
    "pulls":   {"per_page": 100, "state": "all"},
    "issues":  {"per_page": 100, "state": "all"},
}

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
    """Return seconds to wait if the response is a rate limit, otherwise None."""
    if r.status_code not in (403, 429):
        return None
    if "Retry-After" in r.headers:
        return int(r.headers["Retry-After"])
    if r.headers.get("X-RateLimit-Remaining") == "0":
        reset = int(r.headers["X-RateLimit-Reset"])
        return max(reset - time.time(), 0) + 1
    return None  # a 403 that isn't a rate limit, e.g. missing permissions


def fetch(session, label, url, **kwargs):
    kwargs.setdefault("timeout", 10)
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = session.get(url, **kwargs)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            log.warning(f"{label}: attempt {attempt}/{MAX_RETRIES} failed: {e}")
            backoff_sleep(attempt)
            continue

        wait = rate_limit_wait(r)
        if wait is not None:
            if wait > MAX_WAIT:
                log.error(f"{label}: rate limited for {wait:.0f}s (over {MAX_WAIT}s limit), giving up")
                return None
            log.warning(f"{label}: rate limited, waiting {wait:.0f}s")
            time.sleep(wait)
            continue

        if r.status_code >= 500:
            log.warning(f"{label}: server error {r.status_code}, attempt {attempt}/{MAX_RETRIES}")
            backoff_sleep(attempt)
            continue

        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            log.error(f"{label}: {e.response.status_code} -> {e}")
            return None
        return r

    log.error(f"{label}: giving up after {MAX_RETRIES} attempts")
    return None


def fetch_all(session, label, url, params=None):
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

def normalize_commit(repo, commit):
    return {
        "timestamp": commit["commit"]["author"]["date"],
        "repo": repo,
        "type": "commit",
        "actor": commit["commit"]["author"]["name"],
        "summary": commit["commit"]["message"].splitlines()[0],
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


NORMALIZERS = {
    "commits": normalize_commit,
    "pulls":   normalize_pull,
    "issues":  normalize_issue,
}


# ---------- Main steps ----------

def make_session(token):
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    return session


def collect_records(session, repos):
    records = []
    for repo in repos:
        name = repo["full_name"]
        for kind, params in ENDPOINTS.items():
            url = f"{API_URL}/repos/{name}/{kind}"
            items = fetch_all(session, f"{kind} {name}", url, params=params)
            if items is None:
                continue

            log.info(f"{kind} {name}: {len(items)} items fetched")
            normalize = NORMALIZERS[kind]
            for item in items:
                if kind == "issues" and "pull_request" in item:
                    continue  # skip PRs hiding in the issues list
                records.append(normalize(name, item))
    return records


def write_outputs(records):
    with open(JSONL_PATH, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    fieldnames = list(records[0].keys())
    with open(CSV_PATH, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)


def main():
    token = getpass("GitHub token: ").strip()
    session = make_session(token)

    # test = fetch(session, "test", "https://httpbin.org/status/503") testing

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