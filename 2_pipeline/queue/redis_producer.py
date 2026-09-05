import redis
import json
import uuid

r = redis.Redis(protocol=2, host="localhost", port=6379, db=0)

QUEUE_NAME = "scan_jobs"


def push_scan_job(repo_name, commit_sha, branch):
    job = {
        "scan_id": str(uuid.uuid4()),
        "repo": repo_name,
        "commit": commit_sha,
        "branch": branch,
        "status": "PENDING"
    }
    r.rpush(QUEUE_NAME, json.dumps(job))
    print(f"Job pushed: {job}")
    return job["scan_id"]


def peek_queue():
    length = r.llen(QUEUE_NAME)
    print(f"Jobs in queue: {length}")
    if length > 0:
        jobs = r.lrange(QUEUE_NAME, 0, -1)
        for j in jobs:
            print(json.loads(j))


if __name__ == "__main__":
    push_scan_job("dhruvvasvani/AutoForge", "abc123commit", "main")
    peek_queue()
