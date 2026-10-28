from __future__ import annotations

import importlib.util
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
