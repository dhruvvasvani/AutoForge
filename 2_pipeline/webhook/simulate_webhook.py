"""
simulate_webhook.py  (v2 - matches the real backend webhook)

Sends a signed fake GitHub "push" event to the backend's
POST /api/webhooks/github, the same way GitHub would.

Backend requirements (1_backend GithubWebhookController):
  - X-Hub-Signature-256: sha256=<HMAC-SHA256 of raw body with the webhook secret>
  - X-GitHub-Event: push
  - payload: repository.full_name  and  "after" (commit sha)
  - the repository must already be connected in AutoForge (else backend returns 404)

Usage (PowerShell):
  $env:WEBHOOK_SECRET = "<same value as autoforge.github.webhook-secret in backend config>"
  python 2_pipeline\\webhook\\simulate_webhook.py
Optional env vars: WEBHOOK_URL, REPO_FULL_NAME, COMMIT_SHA
"""

import hashlib
import hmac
import json
import os
import sys

import requests

SECRET = os.environ.get("WEBHOOK_SECRET")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "http://localhost:8080/api/webhooks/github")
REPO_FULL_NAME = os.environ.get("REPO_FULL_NAME", "dhruvvasvani/AutoForge")
# Use a commit that exists on GitHub (the worker clones from GitHub).
COMMIT_SHA = os.environ.get("COMMIT_SHA", "0" * 40)

if not SECRET:
    sys.exit("Set WEBHOOK_SECRET first (same value as autoforge.github.webhook-secret in the backend).")

payload = {
    "ref": "refs/heads/main",
    "after": COMMIT_SHA,
    "repository": {
        "full_name": REPO_FULL_NAME,
        "clone_url": f"https://github.com/{REPO_FULL_NAME}.git",
    },
    "head_commit": {"id": COMMIT_SHA, "message": "simulated push"},
}

# Sign the exact bytes we send.
body = json.dumps(payload).encode("utf-8")
signature = hmac.new(SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()

headers = {
    "Content-Type": "application/json",
    "X-GitHub-Event": "push",
    "X-Hub-Signature-256": f"sha256={signature}",
}

print(f"POST {WEBHOOK_URL}  repo={REPO_FULL_NAME}  commit={COMMIT_SHA[:10]}")
response = requests.post(WEBHOOK_URL, data=body, headers=headers, timeout=30)
print(f"Status:   {response.status_code}")
print(f"Response: {response.text}")