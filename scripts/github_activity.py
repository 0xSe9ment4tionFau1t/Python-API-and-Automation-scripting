"""GitHub activity extractor.
Collects commits, pull requests, and issues from all repositories the
token can access, normalizes them into one common record format, and
writes a chronological timeline as JSON Lines and CSV.
"""
import csv
import json
import logging
import os
import sys
import time
from getpass import getpass
from pathlib import Path
from urllib.parse import urlparse

import requests

# ---------- Configuration ----------

# Output files are written to the folder containing this script
BASE_DIR = Path(__file__).parent
JSONL_PATH = BASE_DIR / "github_activity.jsonl"
CSV_PATH = BASE_DIR / "github_activity.csv"
LOG_PATH = BASE_DIR / "github_activity.log"

API_URL = "https://api.github.com"  # Base URL of the GitHub REST API
API_HOST = urlparse(API_URL).netloc  # "api.github.com": the only host that may receive the token
MAX_PAGES = 50      # Safety limit: max pages fetched per endpoint
MAX_RETRIES = 3     # Max attempts per request before giving up
BACKOFF = 2         # Initial retry delay in seconds; doubles each attempt (2s, 4s, ...)
MAX_WAIT = 300      # Longest rate-limit wait accepted, in seconds
DEFAULT_WAIT = 60   # Wait used when a rate-limit header can't be parsed

VAULT_URL_ENV = "GH_ACTIVITY_VAULT_URL"
SECRET_NAME = "github-token"

# Excel treats cells starting with these characters as formulas
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# Activity sources to collect per repository, with their query parameters.
# Keys are GitHub endpoint names and must match the keys in NORMALIZERS.
ENDPOINTS = {
    "commits": {"per_page": 100},
    "pulls":   {"per_page": 100, "state": "all"},   # "all" includes closed PRs
    "issues":  {"per_page": 100, "state": "all"},   # "all" includes closed issues
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
logging.getLogger("azure").setLevel(logging.WARNING)

# ---------- Azure auth ---------- 

def fetch_secret_from_vault(vault_url, name):
    """Read one secret from Azure Key Vault using DefaultAzureCredential."""
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient

    client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
    return client.get_secret(name).value


def get_token():
    vault_url = os.environ.get(VAULT_URL_ENV)
    if not vault_url:
        return getpass("GitHub token: ").strip()
    try:
        secret = fetch_secret_from_vault(vault_url, SECRET_NAME)
    except Exception as e:
        log.error("Could not read token from Key Vault: %s", type(e).__name__)
        return None
    token = (secret or "").strip()
    if not token:
        log.error("Key Vault returned an empty token")
        return None
    return token


# ---------- HTTP helpers ----------

def is_trusted_url(url):
    """Return True only for HTTPS URLs on the GitHub API host.

    The session sends the token with every request, so any URL taken from a
    response (like a next-page link) must be checked before following it.
    """
    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.netloc == API_HOST


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
    # Secondary rate limit: GitHub tells us directly how long to wait
    if "Retry-After" in r.headers:
        try:
            return max(int(r.headers["Retry-After"]), 0)
        except ValueError:
            log.warning(f"unparseable Retry-After header, waiting {DEFAULT_WAIT}s")
            return DEFAULT_WAIT
    # Primary rate limit: wait until the reset time (Unix timestamp), +1s margin
    if r.headers.get("X-RateLimit-Remaining") == "0":
        try:
            reset = int(r.headers["X-RateLimit-Reset"])
        except (KeyError, ValueError):
            log.warning(f"unparseable X-RateLimit-Reset header, waiting {DEFAULT_WAIT}s")
            return DEFAULT_WAIT
        return max(reset - time.time(), 0) + 1
    return None  # A 403 that isn't a rate limit, e.g. missing permissions


def fetch(session, label, url, **kwargs):
    """Send a GET request with retries and rate-limit handling.

    Retries timeouts, connection errors, and 5xx responses with exponential
    backoff, and waits out rate limits up to MAX_WAIT seconds.

    Returns the response on success (2xx, even with an empty body),
    or None if the request failed. Failures are logged.
    """
    kwargs.setdefault("timeout", 10)  # Never wait forever for a response
    for attempt in range(1, MAX_RETRIES + 1):
        # Network-level failures: no response at all, so retry
        try:
            r = session.get(url, **kwargs)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError,
                requests.exceptions.ChunkedEncodingError) as e:
            log.warning(f"{label}: attempt {attempt}/{MAX_RETRIES} failed: {e}")
            backoff_sleep(attempt)
            continue
        except requests.exceptions.RequestException as e:
            # Log only the type: some messages contain header values, including the token
            log.error(f"{label}: request failed: {type(e).__name__}")
            return None

        # Rate limited: wait as long as GitHub asks, unless that's too long
        wait = rate_limit_wait(r)
        if wait is not None:
            if wait > MAX_WAIT:
                log.error(f"{label}: rate limited for {wait:.0f}s (over {MAX_WAIT}s limit), giving up")
                return None
            log.warning(f"{label}: rate limited, waiting {wait:.0f}s")
            time.sleep(wait)
            continue

        # Server errors (5xx) are often temporary, so retry
        if r.status_code >= 500:
            log.warning(f"{label}: server error {r.status_code}, attempt {attempt}/{MAX_RETRIES}")
            backoff_sleep(attempt)
            continue

        # Other 4xx errors (401, 404, 409, ...) won't fix themselves: fail immediately
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            log.error(f"{label}: {e.response.status_code} -> {e}")
            return None
        return r  # Success

    # Only reached if every attempt hit a retryable failure
    log.error(f"{label}: giving up after {MAX_RETRIES} attempts")
    return None


def fetch_all(session, label, url, params=None):
    """Fetch every page of a paginated GitHub list endpoint.

    Follows the "next" links in the Link response header until there are
    no more pages, or until MAX_PAGES is reached (then logs a warning and
    returns what was collected so far). params are sent with the first
    request only, since the next-page URLs already contain them.

    Returns a list of all items from all pages (an empty list if the
    endpoint has no data), or None if any page failed: a failed request,
    a body that isn't valid JSON, or JSON that isn't a list.
    """
    items = []
    pages = 0
    while url is not None:
        if pages >= MAX_PAGES:
            log.warning(f"{label}: reached {MAX_PAGES} pages, stopping early")
            break

        resp = fetch(session, label, url, params=params)
        if resp is None:
            return None  # Partial data could look complete, so discard it

        # Validate the body before trusting it: an HTML error page (e.g. from a proxy)
        # would crash json(), and a JSON object would silently add its keys as items
        try:
            data = resp.json()
        except requests.exceptions.JSONDecodeError as e:
            log.error(f"{label}: response is not valid JSON: {e}")
            return None
        if not isinstance(data, list):
            log.error(f"{label}: expected a JSON list, got {type(data).__name__}")
            return None
        items.extend(data)
        pages += 1

        # GitHub puts the next page URL in the Link header, requests parses it into resp.links
        next_link = resp.links.get("next")
        url = next_link["url"] if next_link else None  # None on the last page ends the loop
        if url is not None and not is_trusted_url(url):
            # Log only the host: the rest of an attacker-supplied URL could contain anything
            log.error(f"{label}: refusing to follow next link to untrusted URL (host: {urlparse(url).netloc})")
            return None
        params = None  # The next URL already contains the query parameters
    return items


# ---------- Normalizers ----------
# Each normalizer turns one raw API item into a record with the same six keys
# (timestamp, repo, type, actor, summary, details), so all activity types can
# be merged, sorted, and exported together.
#
# Null handling follows GitHub's API schema: fields documented as nullable get
# a safe default, fields documented as never null raise MalformedRecord, so a
# broken item is reported where it occurs instead of corrupting the output.

class MalformedRecord(ValueError):
    """Raised when an API item lacks data that GitHub documents as never null."""


def require(item, field, label, expected_type=None):
    """Return item[field], or raise MalformedRecord if it is None or of the wrong type."""
    value = item[field]
    if value is None:
        raise MalformedRecord(f"{label}: required field '{field}' is null")
    if expected_type is not None and not isinstance(value, expected_type):
        raise MalformedRecord(f"{label}: field '{field}' should be {expected_type.__name__}, "
                              f"got {type(value).__name__}")
    return value


def normalize_commit(repo, commit):
    """Convert a raw commit into a normalized record."""
    sha = require(commit, "sha", "commit")
    label = f"commit {sha[:7]}"
    git = require(commit, "commit", label) 

    # The Git author and committer are both nullable, fall back to the committer date.
    # Note: Git author data is self-declared by the committer, not verified by GitHub.
    author = git["author"] or {}
    committer = git.get("committer") or {}
    timestamp = author.get("date") or committer.get("date")
    if timestamp is None:
        # Without a timestamp the record can't be placed on the timeline (and would break the sort)
        raise MalformedRecord(f"{label}: no author or committer date")
    if not isinstance(timestamp, str):
        raise MalformedRecord(f"{label}: date should be text, got {type(timestamp).__name__}")

    # Summary: first non-blank line of the message, or "" if there is none
    message = require(git, "message", label)
    summary = next((line for line in message.splitlines() if line.strip()), "")
    # verification is optional in the schema, so it may be missing entirely
    verified = (git.get("verification") or {}).get("verified", "unknown")

    return {
        "timestamp": timestamp,
        "repo": repo,
        "type": "commit",
        "actor": author.get("name") or "unknown",
        "summary": summary,
        "details": f"sha={sha[:7]} verified={verified}",
    }


def normalize_pull(repo, pr):
    """Convert a raw pull request into a normalized record."""
    number = require(pr, "number", "pull")
    label = f"pull #{number}"

    return {
        "timestamp": require(pr, "created_at", label, str),  # Creation time, not merge time
        "repo": repo,
        "type": "pull",
        "actor": (pr["user"] or {}).get("login", "unknown"),  # user is nullable
        "summary": require(pr, "title", label),
        # merged_at is None for pull request that are still open or were closed without merging
        "details": f"#{number} state={require(pr, 'state', label)} merged={pr['merged_at']}",
    }


def normalize_issue(repo, issue):
    """Convert a raw issue into a normalized record."""
    number = require(issue, "number", "issue")
    label = f"issue #{number}"

    return {
        "timestamp": require(issue, "created_at", label, str),
        "repo": repo,
        "type": "issue",
        "actor": (issue["user"] or {}).get("login", "unknown"),  # user is nullable
        "summary": require(issue, "title", label),
        "details": f"#{number} state={require(issue, 'state', label)}",
    }


# Maps each endpoint name to its normalizer, keys must match ENDPOINTS
NORMALIZERS = {
    "commits": normalize_commit,
    "pulls":   normalize_pull,
    "issues":  normalize_issue,
}


# ---------- Core steps ----------

def make_session(token):
    """Create a session that sends the auth and API headers with every request."""
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",  # Pin the API version to avoid silent changes
    })
    return session


def collect_records(session, repos):
    """Fetch all activity types for every repo and return normalized records.

    A failed endpoint or a malformed item is skipped (and logged)
    without affecting the others.
    """
    records = []
    for repo in repos:
        name = repo["full_name"]  # "owner/repo"
        for kind, params in ENDPOINTS.items():
            url = f"{API_URL}/repos/{name}/{kind}"
            items = fetch_all(session, f"{kind} {name}", url, params=params)
            if items is None:
                continue  # Skip only this activity type, e.g. commits of an empty repo (409)

            log.info(f"{kind} {name}: {len(items)} items fetched")
            normalize = NORMALIZERS[kind]  # Pick the matching normalizer function
            for item in items:
                if not isinstance(item, dict):
                    log.warning(f"{kind} {name}: skipping item that is not an object: {type(item).__name__}")
                    continue
                if kind == "issues" and "pull_request" in item:
                    continue  # Skip pull requests hiding in the issues list
                try:
                    records.append(normalize(name, item))
                except (MalformedRecord, KeyError, TypeError, AttributeError) as e:
                    # One broken item must not stop the run, but it must not vanish silently either
                    log.warning(f"{kind} {name}: skipping malformed item: {e!r}")                                
    return records


def excel_safe(value):
    """Prefix formula-like strings with ' so Excel shows them as text (CSV injection)."""
    if isinstance(value, str) and value.startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def write_outputs(records):
    """Write records as JSON Lines (for tools/SIEM) and CSV (for spreadsheets).

    Expects a non-empty list of records that all share the same keys.
    """
    # JSON Lines: one JSON object per line; ensure_ascii=False keeps non-ASCII characters readable
    with open(JSONL_PATH, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # CSV: all records share the same keys, so the first one defines the columns.
    # utf-8-sig adds a marker so Excel displays non-ASCII characters correctly.
    fieldnames = list(records[0].keys())
    with open(CSV_PATH, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        # Neutralize formulas only here: the JSONL above keeps the raw evidence
        writer.writerows({key: excel_safe(value) for key, value in r.items()} for r in records)


def main():
    """Fetch, normalize, sort, and export the activity of all accessible repos."""
    #TODO: implement a log extraction relative to a script time execution
    # Token comes from Key Vault, or from a hidden prompt if no vault is configured
    token = get_token()
    if token is None:
        sys.exit(1)
    session = make_session(token)

    repos = fetch_all(session, "repos", f"{API_URL}/user/repos", params={"per_page": 100})
    if repos is None:
        log.error("Could not fetch repos, stopping")
        sys.exit(1)  # Non-zero exit code signals failure to schedulers and other tools
    log.info(f"Found {len(repos)} repos")

    records = collect_records(session, repos)
    if not records:
        log.info("No records collected, nothing to write")
        return

    # ISO 8601 timestamps sort correctly as plain strings
    records.sort(key=lambda r: r["timestamp"])
    write_outputs(records)
    log.info(f"Wrote {len(records)} records to {JSONL_PATH} and {CSV_PATH}")


# Run main() only when the file is executed directly, not when imported
if __name__ == "__main__":
    main()
