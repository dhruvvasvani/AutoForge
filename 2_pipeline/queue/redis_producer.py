"""
redis_producer.py
Scan job Redis queue mein push karta hai — agreed schema ke sath:
{repository_id, commit_sha, scan_id, repo_url}
"""

import redis
import json
import uuid

r = redis.Redis(protocol=2, host="localhost", port=6379, db=0)

QUEUE_NAME = "scan_jobs"


def push_scan_job(repo_full_name, commit_sha, repo_url):
    """
    Naya scan job queue mein daalo — backend ke actual fields ke sath match:
    repoFullName aur commitSha (jaisa ScanService.createScanJobFromPush use karta hai)
    """
    scan_id = str(uuid.uuid4())

    job = {
        "repoFullName": repo_full_name,
        "commitSha": commit_sha,
        "scan_id": scan_id,
        "repo_url": repo_url
    }

    r.rpush(QUEUE_NAME, json.dumps(job))
    print(f"Job pushed: {job}")
    return scan_id


def peek_queue():
    """Queue mein kitne jobs hai, dekhne ke liye"""
    length = r.llen(QUEUE_NAME)
    print(f"Jobs in queue: {length}")
    if length > 0:
        jobs = r.lrange(QUEUE_NAME, 0, -1)
        for j in jobs:
            print(json.loads(j))


if __name__ == "__main__":
    # Test: naye schema ke sath sample job push karo
    push_scan_job(
        repo_full_name="dhruvvasvani/AutoForge",
        commit_sha="abc123commit",
        repo_url="https://github.com/dhruvvasvani/AutoForge.git"
    )
    peek_queue()
