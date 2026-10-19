import hashlib
import hmac
import io
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from redis_producer import ASTScanProducer, SCAN_JOB_QUEUE, SCAN_STATUS_PREFIX
from webhook.listener import WebhookListener
from worker import PipelineWorker


class MemoryRedis:
    def __init__(self):
        self.hashes = {}
        self.queue = []
        self.queues = {}

    def hset(self, key, mapping):
        self.hashes.setdefault(key, {}).update(mapping)

    def rpush(self, key, value):
        self.queue.append(value)
        self.queues.setdefault(key, []).append(value)
        return len(self.queue)

    def blpop(self, key, timeout=0):
        if isinstance(key, list):
            for candidate in key:
                if self.queues.get(candidate):
                    value = self.queues[candidate].pop(0)
                    self.queue.remove(value)
                    return (candidate, value)
            return None
        if self.queues.get(key):
            value = self.queues[key].pop(0)
            self.queue.remove(value)
            return key, value
        return None


class BackendStub:
    def __init__(self):
        self.submitted = []

    def create_scan(self, repo, commit, event):
        return "scan-123"

    def submit_results(self, scan_id, result):
        self.submitted.append((scan_id, result))
        return {"id": scan_id}


def test_producer_worker_runs_python_taint_scan():
    redis = MemoryRedis()
    producer = ASTScanProducer(redis)
    producer.enqueue_scan_request(
        {"full_name": "org/repo"},
        {"app.py": "value = request.getParameter('q')\ndb.execute(value)\n"},
        scan_id="scan-test",
    )
    worker = PipelineWorker(redis, BackendStub())
    result = worker.run_once()
    assert result["status"] == "COMPLETED"
    assert result["vulnerabilities"][0]["rule_id"] == "SQLI_RAW_CONCAT"
    assert redis.hashes[f"{SCAN_STATUS_PREFIX}scan-test"]["status"] == "COMPLETED"
    assert SCAN_JOB_QUEUE == "autoforge:scan_jobs"


def test_priority_jobs_use_priority_queues():
    from redis_producer import SCAN_HIGH_PRIORITY_QUEUE
    redis = MemoryRedis()
    ASTScanProducer(redis).enqueue_scan_request(
        {"full_name": "org/repo"}, {"app.py": "x = input()\n"}, priority="critical"
    )
    assert redis.queues[SCAN_HIGH_PRIORITY_QUEUE]
    assert redis.hashes[next(iter(redis.hashes))]["priority"] == "critical"


def test_worker_prefers_critical_queue_before_normal_queue():
    from redis_producer import SCAN_HIGH_PRIORITY_QUEUE
    redis = MemoryRedis()
    producer = ASTScanProducer(redis)
    producer.enqueue_scan_request(
        {"full_name": "org/repo"}, {"normal.py": "value = 1\n"}, scan_id="normal"
    )
    producer.enqueue_scan_request(
        {"full_name": "org/repo"}, {"critical.py": "value = 1\n"},
        scan_id="critical", priority="critical",
    )
    worker = PipelineWorker(redis, BackendStub())
    result = worker.run_once()
    assert result["scan_id"] == "critical"
    assert redis.queues[SCAN_HIGH_PRIORITY_QUEUE] == []


def test_worker_analyzes_multiple_files_in_parallel():
    results = PipelineWorker._analyze_files({
        "one.py": "value = request.getParameter('q')\ndb.execute(value)\n",
        "two.py": "value = input()\ndb.execute(value)\n",
    })
    assert len(results) == 2
    assert {finding["file"] for finding in results} == {"one.py", "two.py"}


def test_github_webhook_authenticates_and_enqueues():
    redis = MemoryRedis()
    backend = BackendStub()
    listener = WebhookListener(ASTScanProducer(redis), backend, github_secret="secret")
    payload = {
        "repository": {"full_name": "org/repo", "clone_url": "https://github.com/org/repo.git"},
        "after": "abc123",
        "ref": "refs/heads/main",
        "commits": [{"added": [], "modified": ["app.py"], "removed": []}],
        "pusher": {"name": "user"},
    }
    raw = json.dumps(payload).encode()
    signature = "sha256=" + hmac.new(b"secret", raw, hashlib.sha256).hexdigest()
    environ = {
        "PATH_INFO": "/github",
        "REQUEST_METHOD": "POST",
        "CONTENT_LENGTH": str(len(raw)),
        "wsgi.input": io.BytesIO(raw),
        "HTTP_X_HUB_SIGNATURE_256": signature,
        "HTTP_X_GITHUB_EVENT": "push",
    }
    response_meta = {}
    response = listener(environ, lambda status, headers: response_meta.update(status=status))
    assert response_meta["status"] == "202 Accepted"
    assert json.loads(response[0])["scan_id"] == "scan-123"
    assert len(redis.queue) == 1


def test_github_webhook_rejects_invalid_signature():
    listener = WebhookListener(MemoryRedis(), BackendStub(), github_secret="secret")
    raw = b"{}"
    environ = {
        "PATH_INFO": "/github",
        "REQUEST_METHOD": "POST",
        "CONTENT_LENGTH": "2",
        "wsgi.input": io.BytesIO(raw),
        "HTTP_X_HUB_SIGNATURE_256": "sha256=wrong",
        "HTTP_X_GITHUB_EVENT": "push",
    }
    response_meta = {}
    listener(environ, lambda status, headers: response_meta.update(status=status))
    assert response_meta["status"] == "401 Unauthorized"
