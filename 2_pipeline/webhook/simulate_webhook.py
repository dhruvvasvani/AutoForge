"""
simulate_webhook.py
Fake GitHub push payload banata hai, sahi HMAC-SHA256 signature ke sath,
taaki webhook controller ko local test kar sake bina real GitHub push ke.
"""

import hmac
import hashlib
import json
import requests

SECRET = "test_secret_123"  # application.properties me jo secret daala wahi yahan bhi daalo
WEBHOOK_URL = "http://localhost:8080/api/webhooks/github"  # apna backend port check kar lena

payload = {
    "repository": {
        "full_name": "dhruvvasvani/AutoForge",
        "clone_url": "https://github.com/dhruvvasvani/AutoForge.git"
    },
    "head_commit": {
        "id": "abc123commit",
        "message": "test push for demo"
    },
    "ref": "refs/heads/main"
}

payload_str = json.dumps(payload)

# Sahi HMAC-SHA256 signature banao (jaisa GitHub banata hai)
signature = hmac.new(
    SECRET.encode(),
    payload_str.encode(),
    hashlib.sha256
).hexdigest()

headers = {
    "Content-Type": "application/json",
    "X-Hub-Signature-256": f"sha256={signature}"
}

print("Sending simulated webhook...")
response = requests.post(WEBHOOK_URL, data=payload_str, headers=headers)

print(f"Status: {response.status_code}")
print(f"Response: {response.text}")