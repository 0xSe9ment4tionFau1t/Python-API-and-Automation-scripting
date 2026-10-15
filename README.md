# Python-API-and-Automation-scripting

Tools and scripts I wrote to automate routine tasks. I'll add more over time.

## scripts/github_activity.py

A Python script that extracts GitHub repository activity (commits, pull requests and issues), normalizes it into a single timeline, and exports it as JSON Lines and CSV, and sends the data to Microsoft Sentinel. On each run, checks which records are already present based on last_run and since parameters and exports only fresh data.

### Features
- Daily output files, records are appended to `github_activity_YYYY-MM-DD.jsonl` (raw data, for tools and a SIEM) and `.csv` (for spreadsheets), named by the UTC date the run started
- Reads the GitHub token from Azure Key Vault
- Exports data in the parent scripts folder in format .jsonl and .csv, .log stores the script logs for debugging, github_activity.state.json file for saving last_run time and new records added

### Usage
- Login to azure with powershell via az login
- Make sure you've set up your Azure Key Vault and have your github token in it
- Set $env:GH_ACTIVITY_VAULT_URL = "https://<your-vault>.vault.azure.net/" to get the token
- Set $env:GH_ACTIVITY_DCR_ID = "<your-DCR_ID>" resource ID (optional, for Sentinel)
- Set $env:GH_ACTIVITY_DCE_URI = "<your-DCE_URI>" export logs destination (optional, for Sentinel)
- Run py github_activity.py
- Optionally make a scheduled task to run the script on each 15 min.

### Limitations

- Scope is the repositories visible to the token (`/user/repos`). Organization-wide
  collection (`/orgs/{org}/repos`) is not implemented or tested.
- Pull request activity is filtered client-side, so very large repositories cost
  extra API requests.
- API rate limits: GitHub allows 5,000 requests per hour for a personal access
  token, plus secondary limits such as 100 concurrent requests. The script sends
  requests one at a time and needs at least three per repository per run
  (commits, pull requests, issues), plus one for each extra page of 100 items;
  with a 15-minute schedule, multiply that by four. When GitHub answers 403 or
  429, the script waits as long as `Retry-After` or `X-RateLimit-Reset` says, up
  to 300 seconds. If the wait would be longer, it gives up, the run is marked
  incomplete, the state is not advanced, and the next run retries. A rate-limit
  response without those headers is not retried.
- Page cap: at most 50 pages (5,000 items) are read per endpoint and repository
  per run. If the cap is hit, the data from that endpoint is discarded and the
  run is marked incomplete, so the state is not advanced. A repository with more
  than 5,000 pull requests (all of them are fetched on every run), or more than
  5,000 commits on the first run, can therefore never complete unless
  `MAX_PAGES` is raised.
- Does not feature audit logs, like logins, permission changes or deleted repositories.

**Status:** done.

Built as a learning project to solve a real task. I wrote the code myself, with Claude as a tutor and code reviewer.
