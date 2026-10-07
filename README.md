# Python-API-and-Automation-scripting

Tools and scripts I wrote to automate routine tasks. I'll add more over time.

## scripts/github_activity.py

A Python script that extracts GitHub repository activity (commits, pull requests and issues), normalizes it into a single timeline, and exports it as JSON Lines and CSV.

- Handles retries with exponential backoff, rate limits, and 4xx/5xx errors
- Reads the GitHub token from Azure Key Vault (falls back to a hidden prompt)
- Tested with pytest, including malformed API data and security cases

**Status:** work in progress. Next step: onboarding the output into a SIEM.

Built as a learning project to solve a real task. I wrote the code myself, with Claude as a tutor and code reviewer.