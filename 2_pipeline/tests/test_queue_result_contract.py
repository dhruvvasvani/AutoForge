from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load_queue_worker():
    worker_path = Path(__file__).resolve().parents[1] / "queue" / "worker.py"
    spec = importlib.util.spec_from_file_location("autoforge_queue_worker", worker_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load pipeline worker from {worker_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_backend_payload_contains_reachability_tagged_ast_findings(monkeypatch):
    module = _load_queue_worker()
    worker = module.ScanWorker.__new__(module.ScanWorker)
    submitted = {}

    class Response:
        @staticmethod
        def raise_for_status():
            return None

    def post(url, *, json, headers, timeout):
        submitted.update(payload=json, url=url, headers=headers, timeout=timeout)
        return Response()

    monkeypatch.setattr(module, "BACKEND_URL", "http://backend")
    monkeypatch.setattr(module, "INTERNAL_TOKEN", "test-token")
    monkeypatch.setattr(module.requests, "post", post)
    finding = {
        "rule_id": "SQLI_RAW_CONCAT",
        "file": "src/app.py",
        "line": 12,
        "severity": "HIGH",
        "message": "Untrusted input reaches a query",
        "source": "semgrep",
        "reachability": "REACHABLE_CODE",
        "combined_risk_score": 8.5,
        "priority": "P1",
    }

    assert worker.post_to_backend(
        {"repo": "octo/demo", "commit": "a" * 40},
        "42",
        {
            "actionable_findings": [finding],
            "filtered_noise": [],
        },
    )

    payload = submitted["payload"]
    assert payload["tagged_findings"][0]["source"] == "semgrep"
    assert payload["tagged_findings"][0]["extra"]["reachable"] is True
    assert payload["tagged_findings"][0]["extra"]["combined_risk_score"] == 8.5
    assert payload["ast"] == payload["tagged_findings"]
    assert submitted["url"] == "http://backend/api/internal/scans/42/results"


def test_backend_queue_message_uses_repository_url_for_result_name():
    module = _load_queue_worker()
    parsed = module.ScanWorker.parse_job(json.dumps({
        "job_id": "42",
        "scan_id": 42,
        "project_id": 3,
        "repository_id": 3,
        "repo_url": "https://github.com/owner/repo.git",
        "commit_sha": "a" * 40,
        "branch": "main",
        "changed_files": [],
    }))

    assert parsed["scan_id"] == 42
    assert parsed["repo"] == "owner/repo"
    assert parsed["repo_url"] == "https://github.com/owner/repo.git"


def test_failed_scan_is_reported_to_backend(monkeypatch):
    module = _load_queue_worker()
    worker = module.ScanWorker.__new__(module.ScanWorker)
    submitted = {}

    class Response:
        @staticmethod
        def raise_for_status():
            return None

    def post(url, *, json, headers, timeout):
        submitted.update(payload=json, url=url, headers=headers)
        return Response()

    monkeypatch.setattr(module, "BACKEND_URL", "http://backend")
    monkeypatch.setattr(module, "INTERNAL_TOKEN", "test-token")
    monkeypatch.setattr(module.requests, "post", post)

    assert worker.report_failure_to_backend("42", "clone failed")
    assert submitted["url"] == "http://backend/api/internal/scans/42/results"
    assert submitted["payload"] == {"status": "FAILED", "error": "clone failed"}
    assert submitted["headers"] == {"X-AutoForge-Internal-Token": "test-token"}
