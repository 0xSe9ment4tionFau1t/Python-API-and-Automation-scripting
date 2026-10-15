"""GitHub activity extractor.

Collects commits, pull requests, and issues from all repositories the
token can access, normalizes them into one common record format, and
writes a chronological timeline as JSON Lines and CSV. Runs are
incremental (only new activity is collected), and the records can
optionally be uploaded to Microsoft Sentinel.

The file is organized in these sections:
    Configuration  constants and logging setup
    Input          reading the state file, the Key Vault token, and the GitHub API
    Normalizers    raw API items -> one common record format
    Checkers       validation, rate-limit detection, and deduplication
    Output         files, state file, and Microsoft Sentinel
    Main flow      collecting, running one incremental pass, and the entry point
"""
import csv
import functools
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

# ---------- Configuration ----------

# Files: all are kept in the folder containing this script
BASE_DIR = Path(__file__).parent
LOG_PATH = BASE_DIR / "github_activity.log"
STATE_PATH = BASE_DIR / "github_activity.state.json"
FIELDNAMES = ["id", "timestamp", "repo", "type", "actor", "summary", "details"]
DAY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")  # Day stamp used in output file names
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # UTC timestamps in the state file and run times
EPOCH = "1970-01-01T00:00:00Z"  # Stand-in for "no previous run" after an incomplete first run

# GitHub API
API_URL = "https://api.github.com"  # Base URL of the GitHub REST API
API_HOST = urlparse(API_URL).netloc  # "api.github.com": the only host that may receive the token
MAX_PAGES = 50      # Safety limit: max pages fetched per endpoint
MAX_RETRIES = 3     # Max attempts per request before giving up
BACKOFF = 2         # Initial retry delay in seconds; doubles each attempt (2s, 4s, ...)
MAX_WAIT = 300      # Longest rate-limit wait accepted, in seconds
DEFAULT_WAIT = 60   # Wait used when a rate-limit header can't be parsed

# Activity sources to collect per repository, with their query parameters.
# Keys are GitHub endpoint names and must match the keys in NORMALIZERS.
ENDPOINTS = {
    "commits": {"per_page": 100},
    "pulls":   {"per_page": 100, "state": "all"},   # "all" includes closed PRs
    "issues":  {"per_page": 100, "state": "all"},   # "all" includes closed issues
}
# GitHub filters these endpoints by "since" itself; pulls have no such parameter
SERVER_SIDE_SINCE = {"commits", "issues"}
EMPTY_STATUSES = {"commits": (409,)}   # GitHub answers 409 for an empty repo's commits

# Azure Key Vault
VAULT_URL_ENV = "GH_ACTIVITY_VAULT_URL"
SECRET_NAME = "github-token"
TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")

# Microsoft Sentinel
DCE_URI_ENV = "GH_ACTIVITY_DCE_URI"
DCR_ID_ENV = "GH_ACTIVITY_DCR_ID"
STREAM_NAME = "Custom-GitHubActivity_CL"
INGEST_HOST_SUFFIX = ".ingest.monitor.azure.com"
DCR_ID_RE = re.compile(r"dcr-[0-9a-f]{32}")

# Excel treats cells starting with these characters as formulas
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

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


# =====================================================================
# INPUT: reading data from the state file, Azure Key Vault, and GitHub
# =====================================================================

# ---------- Input: state file ----------

def load_last_run(path):
    """Return the saved last-run timestamp, or None (first run or unusable state)."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as e:
        log.warning("Could not read state file: %s", type(e).__name__)
        return None

    try:
        data = json.loads(text)
    except ValueError:
        log.warning("State file is not valid JSON, ignoring it")
        return None

    value = data.get("last_run") if isinstance(data, dict) else None
    if not isinstance(value, str):
        log.warning("State file has no usable 'last_run', ignoring it")
        return None
    try:
        parsed = datetime.strptime(value, TIME_FORMAT)
    except ValueError:
        log.warning("State file 'last_run' has the wrong format, ignoring it")
        return None

    if parsed.strftime(TIME_FORMAT) != value:
        log.warning("State file 'last_run' has the wrong format, ignoring it")
        return None
    if parsed.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
        log.warning("State file 'last_run' is in the future, ignoring it")
        return None
    return value


def load_seen(path):
    """Return the keys already written since the last clean run.

    Any problem with the file gives an empty set.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return set()
    if not isinstance(data, dict):
        return set()
    seen = data.get("seen", [])
    if not isinstance(seen, list) or not all(isinstance(k, str) for k in seen):
        log.warning("Ignoring unusable 'seen' list in state file")
        return set()
    return set(seen)


# ---------- Input: Azure Key Vault ----------

def fetch_secret_from_vault(vault_url, name):
    """Read one secret from Azure Key Vault using DefaultAzureCredential."""
    # Imported here so the script can run (and be tested) without the Azure packages
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient

    client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
    return client.get_secret(name).value


def get_token():
    """Return the GitHub token from Key Vault, or None (logged) if it is missing or invalid."""
    vault_url = os.environ.get(VAULT_URL_ENV)
    if not vault_url:
        log.error("%s is not set", VAULT_URL_ENV)
        return None
    try:
        secret = fetch_secret_from_vault(vault_url, SECRET_NAME)
    except Exception as e:
        # Log only the type: the message could contain sensitive details
        log.error("Could not read token from Key Vault: %s", type(e).__name__)
        return None

    token = (secret or "").strip()
    if not token:
        log.error("Key Vault returned an empty token")
        return None
    if not is_valid_token(token):
        log.error("Token has unexpected characters")
        return None
    return token


# ---------- Input: GitHub API ----------

def make_session(token):
    """Create a session that sends the auth and API headers with every request."""
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",  # Pin the API version to avoid silent changes
    })
    return session


def backoff_sleep(attempt):
    """Wait before the next attempt, but not after the last one."""
    if attempt < MAX_RETRIES:
        time.sleep(BACKOFF * 2 ** (attempt - 1))


def fetch(session, label, url, ok_statuses=(), **kwargs):
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

        if r.status_code in ok_statuses:
            return r
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


def fetch_all(session, label, url, params=None, empty_on=()):
    """Fetch every page of a paginated GitHub list endpoint.

    Follows the "next" links in the Link response header until there are
    no more pages. If MAX_PAGES is reached first, it logs an error and
    returns None, because a truncated list could look complete.
    params are sent with the first request only, since the next-page URLs
    already contain them.

    empty_on lists HTTP statuses that mean "no data" (e.g. 409 for an empty
    repository): they return an empty list instead of failing.

    Returns a list of all items from all pages (an empty list if the
    endpoint has no data), or None if any page failed: a failed request,
    a body that isn't valid JSON, or JSON that isn't a list.
    """
    items = []
    pages = 0
    while url is not None:
        if pages >= MAX_PAGES:
            log.error(f"{label}: reached {MAX_PAGES} pages, discarding incomplete data")
            return None

        resp = fetch(session, label, url, params=params, ok_statuses=empty_on)
        if resp is None:
            return None  # Partial data could look complete, so discard it

        if resp.status_code in empty_on:
            log.info(f"{label}: empty (HTTP {resp.status_code})")
            return items
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


# =====================================================================
# NORMALIZERS: raw API items -> one common record format
# =====================================================================
# Each normalizer turns one raw API item into a record with the same seven keys
# (id, timestamp, repo, type, actor, summary, details), so all activity types
# can be merged, sorted, deduplicated, and exported together.
#
# Null handling follows GitHub's API schema: fields documented as nullable get
# a safe default, and fields documented as never null raise MalformedRecord, so
# a broken item is reported where it occurs instead of corrupting the output.

def normalize_commit(repo, commit):
    """Convert a raw commit into a normalized record."""
    sha = require(commit, "sha", "commit")
    label = f"commit {sha[:7]}"
    git = require(commit, "commit", label)

    # The Git author and committer are both nullable, so fall back to the committer date.
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
        "id": f"commit:{repo}:{sha}",
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
    created = require(pr, "created_at", label, str)
    state = require(pr, "state", label)

    return {
        "id": f"pull:{repo}#{number}",
        "timestamp": require(pr, "updated_at", label, str),
        "repo": repo,
        "type": "pull",
        "actor": (pr["user"] or {}).get("login", "unknown"),  # user is nullable
        "summary": require(pr, "title", label),
        # merged_at is None for pull requests that are still open or were closed without merging
        "details": f"#{number} state={state} merged={pr['merged_at']} created={created}",
    }


def normalize_issue(repo, issue):
    """Convert a raw issue into a normalized record."""
    number = require(issue, "number", "issue")
    label = f"issue #{number}"
    created = require(issue, "created_at", label, str)
    state = require(issue, "state", label)

    return {
        "id": f"issue:{repo}#{number}",
        "timestamp": require(issue, "updated_at", label, str),
        "repo": repo,
        "type": "issue",
        "actor": (issue["user"] or {}).get("login", "unknown"),  # user is nullable
        "summary": require(issue, "title", label),
        "details": f"#{number} state={state} created={created}",
    }


# Maps each endpoint name to its normalizer; keys must match ENDPOINTS
NORMALIZERS = {
    "commits": normalize_commit,
    "pulls":   normalize_pull,
    "issues":  normalize_issue,
}


# =====================================================================
# CHECKERS: validation, rate-limit detection, and deduplication
# =====================================================================

# ---------- Checkers: validation ----------

def is_valid_token(token):
    """Return True if the token has only characters GitHub tokens use."""
    return TOKEN_RE.fullmatch(token) is not None


def is_trusted_url(url):
    """Return True only for HTTPS URLs on the GitHub API host.

    The session sends the token with every request, so any URL taken from a
    response (like a next-page link) must be checked before following it.
    """
    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.netloc == API_HOST


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


# ---------- Checkers: rate limits ----------

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
    # Primary rate limit: wait until the reset time (Unix timestamp), plus a 1s margin
    if r.headers.get("X-RateLimit-Remaining") == "0":
        try:
            reset = int(r.headers["X-RateLimit-Reset"])
        except (KeyError, ValueError):
            log.warning(f"unparseable X-RateLimit-Reset header, waiting {DEFAULT_WAIT}s")
            return DEFAULT_WAIT
        return max(reset - time.time(), 0) + 1
    return None  # A 403 that isn't a rate limit, e.g. missing permissions


# ---------- Checkers: deduplication ----------

def record_key(record):
    """Return the identity of one version of an item: stable id + timestamp."""
    return f"{record['id']} {record['timestamp']}"


def drop_seen(records, seen):
    """Return the records whose key is not in `seen`, in order and without duplicates."""
    already = set(seen)
    fresh = []
    for r in records:
        key = record_key(r)
        if key in already:
            continue
        already.add(key)
        fresh.append(r)
    return fresh


def prune_seen(seen, cutoff):
    """Keep the keys whose timestamp (the part after the last space) is >= cutoff."""
    return {k for k in seen if k.rsplit(" ", 1)[1] >= cutoff}


# =====================================================================
# OUTPUT: writing to files, the state file, and Microsoft Sentinel
# =====================================================================

# ---------- Output: files ----------

def excel_safe(value):
    """Prefix formula-like strings with ' so Excel shows them as text (CSV injection)."""
    if isinstance(value, str) and value.startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def output_paths(day):
    """Return the (jsonl, csv) paths for one collection day, e.g. '2026-10-14'."""
    if DAY_RE.fullmatch(day) is None:
        raise ValueError("day must look like YYYY-MM-DD")
    return (BASE_DIR / f"github_activity_{day}.jsonl",
            BASE_DIR / f"github_activity_{day}.csv")


def write_outputs(records, jsonl_path, csv_path):
    """Append records to the day's JSON Lines (for tools/SIEM) and CSV (for spreadsheets)."""
    if not records:
        return
    # JSON Lines: one JSON object per line; ensure_ascii=False keeps non-ASCII characters readable
    with open(jsonl_path, "a", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # CSV: columns come from FIELDNAMES so every run writes the same layout.
    # utf-8-sig adds a marker (only at the start of a new file) so Excel
    # displays non-ASCII characters correctly.
    write_header = not csv_path.exists() or csv_path.stat().st_size == 0
    with open(csv_path, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, quoting=csv.QUOTE_ALL)
        if write_header:
            writer.writeheader()
        # Neutralize formulas only here: the JSONL above keeps the raw evidence
        writer.writerows({key: excel_safe(value) for key, value in r.items()} for r in records)


# ---------- Output: state file ----------

def save_last_run(path, timestamp, seen=()):
    """Write the state atomically: the old file survives a crash mid-write."""
    payload = {"last_run": timestamp, "seen": sorted(seen)}
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(tmp, path)


# ---------- Output: Microsoft Sentinel ----------

def sentinel_settings():
    """Return (dce_uri, dcr_id), or None if Sentinel upload is not configured.

    Raises ValueError if the configuration is incomplete or invalid. The
    endpoint is checked because an Azure token is sent to it.
    """
    uri = os.environ.get(DCE_URI_ENV)
    rule_id = os.environ.get(DCR_ID_ENV)
    if not uri and not rule_id:
        return None
    if not uri or not rule_id:
        raise ValueError(f"set both {DCE_URI_ENV} and {DCR_ID_ENV}, or neither")

    parsed = urlparse(uri)
    host = parsed.hostname or ""    # the real host: no port, no user@ part
    if parsed.scheme != "https" or not host.endswith(INGEST_HOST_SUFFIX):
        raise ValueError(f"{DCE_URI_ENV} must be an https URL on {INGEST_HOST_SUFFIX}")
    if DCR_ID_RE.fullmatch(rule_id) is None:
        raise ValueError(f"{DCR_ID_ENV} must look like dcr-<32 hex characters>")
    return uri, rule_id


def make_ingestion_client(dce_uri):
    """Create the Azure client (imported lazily, like the Key Vault code)."""
    from azure.identity import DefaultAzureCredential
    from azure.monitor.ingestion import LogsIngestionClient

    return LogsIngestionClient(endpoint=dce_uri, credential=DefaultAzureCredential())


def send_to_sentinel(client, rule_id, records):
    """Upload records to the custom table. Returns True on success, False on failure."""
    if not records:
        return True
    try:
        client.upload(rule_id=rule_id, stream_name=STREAM_NAME, logs=records)
    except Exception as e:
        log.error("Sentinel upload failed: %s", type(e).__name__)
        return False
    return True


# =====================================================================
# MAIN FLOW: collecting, running one incremental pass, and the entry point
# =====================================================================

def utc_now_iso():
    """Return the current UTC time as YYYY-MM-DDTHH:MM:SSZ."""
    return datetime.now(timezone.utc).strftime(TIME_FORMAT)


def collect_records(session, repos, since=None):
    """Fetch all activity types for every repo and return normalized records.

    If `since` is given, commits and issues are filtered by GitHub and pull
    requests are filtered here by their `updated_at`.

    A malformed item is skipped (and logged) without affecting the others.

    Returns (records, complete). `complete` is False if any endpoint failed
    or hit MAX_PAGES, in which case the caller must not advance its state.
    """
    records = []
    complete = True
    for repo in repos:
        name = repo["full_name"]  # "owner/repo"
        for kind, base_params in ENDPOINTS.items():
            params = dict(base_params)
            if since is not None and kind in SERVER_SIDE_SINCE:
                params["since"] = since
            url = f"{API_URL}/repos/{name}/{kind}"
            items = fetch_all(session, f"{kind} {name}", url, params=params, empty_on=EMPTY_STATUSES.get(kind, ()))
            if items is None:
                complete = False
                continue

            log.info(f"{kind} {name}: {len(items)} items fetched")
            normalize = NORMALIZERS[kind]  # Pick the matching normalizer function
            for item in items:
                if not isinstance(item, dict):
                    log.warning(f"{kind} {name}: skipping item that is not an object: {type(item).__name__}")
                    continue
                if kind == "issues" and "pull_request" in item:
                    continue  # Skip pull requests hiding in the issues list
                try:
                    record = normalize(name, item)
                except (MalformedRecord, KeyError, TypeError, AttributeError) as e:
                    # One broken item must not stop the run, but it must not vanish silently either
                    log.warning(f"{kind} {name}: skipping malformed item: {e!r}")
                    continue
                if kind == "pulls" and since is not None and record["timestamp"] < since:
                    continue
                records.append(record)
    return records, complete


def run_once(session, repos, state_path, run_start, deliver=None):
    """Run one incremental pass. Returns (records_written, complete).

    Collects new activity, uploads it with `deliver` (if given), appends it to
    the day's files, and updates the state file. If the upload fails, nothing
    is written and the state stays unchanged, so the next run retries.
    """
    since = load_last_run(state_path)
    seen = load_seen(state_path)

    records, complete = collect_records(session, repos, since)
    fresh = drop_seen(records, seen)
    fresh.sort(key=lambda r: r["timestamp"])

    if fresh and deliver is not None and not deliver(fresh):
        log.error("Delivery failed: nothing written, state unchanged")
        return 0, False

    jsonl_path, csv_path = output_paths(run_start[:10])
    write_outputs(fresh, jsonl_path, csv_path)

    seen = seen | {record_key(r) for r in fresh}
    if complete:
        save_last_run(state_path, run_start, prune_seen(seen, run_start))
    else:
        log.warning("Run incomplete: state not advanced, next run retries from the old point")
        save_last_run(state_path, since or EPOCH, seen)
    return len(fresh), complete


def main():
    """Run one incremental collection: fetch new activity, append it to today's files, update the state."""
    run_start = utc_now_iso()
    try:
        settings = sentinel_settings()
    except ValueError as e:
        log.error("Invalid Sentinel configuration: %s", e)
        sys.exit(1)

    # Token comes from Key Vault
    token = get_token()
    if token is None:
        sys.exit(1)
    session = make_session(token)

    repos = fetch_all(session, "repos", f"{API_URL}/user/repos", params={"per_page": 100})
    if repos is None:
        log.error("Could not fetch repos, stopping")
        sys.exit(1)  # Non-zero exit code signals failure to schedulers and other tools
    log.info(f"Found {len(repos)} repos")

    deliver = None
    if settings is None:
        log.warning("Sentinel upload is not configured: writing files only")
    else:
        dce_uri, rule_id = settings
        try:
            client = make_ingestion_client(dce_uri)
        except Exception as e:
            log.error("Could not create the Sentinel client: %s", type(e).__name__)
            sys.exit(1)
        deliver = functools.partial(send_to_sentinel, client, rule_id)

    written, complete = run_once(session, repos, STATE_PATH, run_start, deliver)
    log.info("Wrote %d new records", written)
    if not complete:
        log.error("Run was incomplete, state not advanced")
        sys.exit(1)


if __name__ == "__main__":
    main()