import hmac
import hashlib
import json
import requests

WEBHOOK_URL = "http://localhost:8089/api/webhooks/github"
WEBHOOK_SECRET = "change-this-in-env-vars"

payload = {
    "ref": "refs/heads/main",
    "before": "0000000000000000000000000000000000000000",
    "after": "abc123commit",
    "repository": {
        "id": 123456,
        "name": "AutoForge",
        "full_name": "sample-owner/sample-repo",
        "clone_url": "https://github.com/dhruvvasvani/AutoForge.git",
        "html_url": "https://github.com/dhruvvasvani/AutoForge"
    },
    "pusher": {
        "name": "dhruvvasvani",
        "email": "dhruv@example.com"
    },
    "head_commit": {
        "id": "abc123commit",
        "message": "test push",
        "timestamp": "2026-09-04T11:40:00Z",
        "added": [],
        "removed": [],
        "modified": ["main.py"]
    },
    "commits": [
        {
            "id": "abc123commit",
            "message": "test push",
            "timestamp": "2026-09-04T11:40:00Z",
            "added": [],
            "removed": [],
            "modified": ["main.py"]
        }
    ]
}

payload_str = json.dumps(payload)
payload_bytes = payload_str.encode('utf-8')
signature = hmac.new(WEBHOOK_SECRET.encode('utf-8'), payload_bytes, hashlib.sha256).hexdigest()

headers = {
    "Content-Type": "application/json",
    "X-GitHub-Event": "push",
    "X-Hub-Signature-256": f"sha256={signature}"
}

print("Sending simulated webhook...")
response = requests.post(WEBHOOK_URL, data=payload_bytes, headers=headers)
print(f"Status: {response.status_code}")
print(f"Response: {response.text}")
