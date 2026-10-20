from __future__ import annotations

import anyio
import hashlib
import hmac
import json
import sys
import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src.analysis.taint_engine import TaintEngine
from src.deployment.job_queue import SQLiteJobQueue
from src.deployment.webhook_app import create_webhook_app
from src.deployment.worker import PullRequestWorker
from src.engine.cfg_builder import CFGBuilder
from src.integration.webhook_server import PullRequestEvent
from src.ml.cpg_builder import EDGE_TYPES, build_cpg
from src.ml.cpg_gnn import CPGGNN
from src.monitoring.metrics_collector import MetricsCollector
from src.optimization.batch_processor import CPGBatchProcessor
from src.parser.multi_lang_parser import MultiLangParser
from src.policy.rule_tuning import ProductionPolicyError, RuleTuner, finding_fingerprint
from src.reporting.sarif_generator import SARIFReporter
from src.scoring.vulnerability_scorer import VulnerabilityScorer


def _policy_with_approver(tmp_path: Path, approvers: list[str] | None = None) -> Path:
    source = ANALYZER_ROOT / "src" / "policy" / "production_policy.json"
    policy = json.loads(source.read_text(encoding="utf-8"))
    policy["approved_by"] = approvers or []
    destination = tmp_path / "production_policy.json"
    destination.write_text(json.dumps(policy), encoding="utf-8")
    return destination


def _post(app, path: str, body: bytes, headers: dict[str, str]) -> httpx.Response:
    async def send():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            return await client.post(path, content=body, headers=headers)

    return anyio.run(send)


def _signed_headers(body: bytes, event: str, secret: str = "test-secret") -> dict[str, str]:
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return {
        "X-Hub-Signature-256": f"sha256={signature}",
        "X-GitHub-Event": event,
        "Content-Type": "application/json",
    }


def test_production_policy_schema_and_severity_limits_are_enforced(tmp_path):
    policy_path = _policy_with_approver(tmp_path)
    tuner = RuleTuner(policy_path)
    assert tuner.policy["min_ml_confidence"] == 0.6
    assert tuner.evaluate([{"severity": "CRITICAL"}])["status"] == "FAILED"
    assert tuner.evaluate([{"severity": "HIGH"}])["status"] == "PASSED"

    invalid_policy = json.loads(policy_path.read_text(encoding="utf-8"))
    invalid_policy["severity_thresholds"]["CRITICAL"]["unexpected"] = 1
    policy_path.write_text(json.dumps(invalid_policy), encoding="utf-8")
    with pytest.raises(ProductionPolicyError, match="exactly max_allowed"):
        RuleTuner(policy_path)


def test_production_policy_applies_medium_and_low_thresholds(tmp_path):
    policy_path = _policy_with_approver(tmp_path)
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["severity_thresholds"]["MEDIUM"]["max_allowed"] = 0
    policy["severity_thresholds"]["LOW"]["max_allowed"] = 1
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    tuner = RuleTuner(policy_path)

    assert tuner.evaluate([{"severity": "MEDIUM"}])["status"] == "FAILED"
    assert tuner.evaluate([{"severity": "LOW"}, {"severity": "LOW"}])["status"] == "FAILED"


def test_false_positive_feedback_requires_approval_and_can_be_revoked(tmp_path):
    tuner = RuleTuner(
        _policy_with_approver(tmp_path, ["security-reviewer"]),
        tmp_path / "feedback.jsonl",
    )
    finding = {
        "rule_id": "SQLI_RAW_CONCAT",
        "file": "src/routes.py",
        "line": 42,
        "message": "Untrusted input reaches SQL",
        "code_snippet": "cursor.execute(query)",
        "severity": "CRITICAL",
        "repository": "owner/repo",
    }
    fingerprint = tuner.submit_false_positive(
        finding,
        reason="Query is parameterized by the framework",
        submitted_by="developer",
        repository="owner/repo",
        pull_request=17,
    )
    assert fingerprint == finding_fingerprint(finding, repository="owner/repo")
    assert tuner.evaluate([finding])["status"] == "FAILED"

    with pytest.raises(PermissionError, match="not authorized"):
        tuner.approve_false_positive(
            fingerprint,
            approved_by="developer",
            expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            reason="not a reviewer",
        )
    with pytest.raises(ValueError, match="maximum duration"):
        tuner.approve_false_positive(
            fingerprint,
            approved_by="security-reviewer",
            expires_at=(datetime.now(timezone.utc) + timedelta(days=91)).isoformat(),
            reason="approved",
        )

    tuner.approve_false_positive(
        fingerprint,
        approved_by="security-reviewer",
        expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        reason="verified safe",
    )
    result = tuner.evaluate([finding])
    assert result["status"] == "PASSED"
    assert result["suppressed_false_positives"] == 1
    journal = (tmp_path / "feedback.jsonl").read_text(encoding="utf-8")
    assert "cursor.execute(query)" not in journal

    tuner.revoke_false_positive(
        fingerprint,
        revoked_by="security-reviewer",
        reason="new evidence",
    )
    assert tuner.evaluate([finding])["status"] == "FAILED"


def test_false_positive_approvals_require_submitted_finding(tmp_path):
    tuner = RuleTuner(
        _policy_with_approver(tmp_path, ["reviewer"]),
        tmp_path / "feedback.jsonl",
    )
    with pytest.raises(ValueError, match="was not submitted"):
        tuner.approve_false_positive(
            "a" * 64,
            approved_by="reviewer",
            expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            reason="approval",
        )


def test_sqlite_queue_deduplicates_events_retries_and_completes(tmp_path):
    queue = SQLiteJobQueue(tmp_path / "jobs.sqlite3", max_attempts=2)
    event = PullRequestEvent("opened", "owner/repo", 7, "a" * 40, "https://example.diff")
    assert queue.enqueue(event)
    assert not queue.enqueue(event)

    first = queue.claim()
    assert first is not None and first.attempts == 1 and first.event == event
    queue.fail(first.job_id, "temporary API failure")
    retry = queue.claim()
    assert retry is not None and retry.attempts == 2
    queue.complete(retry.job_id)

    assert queue.claim() is None
    assert queue.counts() == {"pending": 0, "processing": 0, "completed": 1, "failed": 0}
    assert queue.healthcheck()


def test_sqlite_queue_exhausts_retries_and_rejects_invalid_transitions(tmp_path):
    queue = SQLiteJobQueue(tmp_path / "jobs.sqlite3", max_attempts=1)
    queue.enqueue(PullRequestEvent("opened", "owner/repo", 8, "b" * 40, "https://example.diff"))
    job = queue.claim()
    assert job is not None
    queue.fail(job.job_id, "terminal failure")
    assert queue.claim() is None
    with pytest.raises(ValueError, match="not being processed"):
        queue.complete(job.job_id)
    assert queue.enqueue(
        PullRequestEvent("synchronize", "owner/repo", 8, "b" * 40, "https://example.diff")
    )
    assert queue.claim() is not None


def test_sqlite_queue_recovers_jobs_interrupted_by_worker_restart(tmp_path):
    queue = SQLiteJobQueue(tmp_path / "jobs.sqlite3", max_attempts=3)
    event = PullRequestEvent("opened", "owner/repo", 9, "d" * 40, "https://example.diff")
    queue.enqueue(event)
    first = queue.claim()
    assert first is not None

    assert queue.recover_interrupted_jobs() == 1
    recovered = queue.claim()
    assert recovered is not None
    assert recovered.attempts == first.attempts + 1


def test_webhook_queues_events_and_signed_review_comment_submits_feedback(tmp_path):
    secret = "test-secret"
    app = create_webhook_app(
        webhook_secret=secret,
        database_path=str(tmp_path / "jobs.sqlite3"),
        repository="owner/repo",
    )
    app.state.rule_tuner.feedback_path = tmp_path / "feedback.jsonl"
    event_payload = {
        "action": "opened",
        "repository": {"full_name": "owner/repo"},
        "pull_request": {
            "number": 12,
            "head": {"sha": "c" * 40},
            "diff_url": "https://github.com/owner/repo/pull/12.diff",
        },
    }
    body = json.dumps(event_payload).encode()
    response = _post(
        app,
        "/api/v1/github/events",
        body,
        _signed_headers(body, "pull_request", secret),
    )
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    assert app.state.job_queue.claim() is not None

    fingerprint = finding_fingerprint(
        {
            "rule_id": "SQLI_RAW_CONCAT",
            "file": "app.py",
            "line": 8,
            "message": "Untrusted input reaches SQL",
        }
    )
    feedback_payload = {
        "comment": {
            "body": f"/autoforge false-positive {fingerprint} framework query binding",
            "user": {"login": "developer"},
        },
        "repository": {"full_name": "owner/repo"},
        "pull_request": {"number": 12},
    }
    body = json.dumps(feedback_payload).encode()
    response = _post(
        app,
        "/api/v1/github/feedback",
        body,
        _signed_headers(body, "pull_request_review_comment", secret),
    )
    assert response.status_code == 200
    assert response.json()["fingerprint"] == fingerprint
    assert "submitted" in app.state.rule_tuner.feedback_path.read_text(encoding="utf-8")


def test_webhook_rejects_unsigned_false_positive_feedback(tmp_path):
    app = create_webhook_app(
        webhook_secret="test-secret",
        database_path=str(tmp_path / "jobs.sqlite3"),
        repository="owner/repo",
    )
    response = _post(
        app,
        "/api/v1/github/feedback",
        b"{}",
        _signed_headers(b"{}", "pull_request_review_comment", "wrong-secret"),
    )
    assert response.status_code == 401


def test_worker_scans_changed_python_and_reports_unhandled_language_files(tmp_path):
    queue = SQLiteJobQueue(tmp_path / "jobs.sqlite3")
    worker = PullRequestWorker(
        queue,
        token="test-token",
        repository="owner/repo",
        rule_tuner=RuleTuner(
            _policy_with_approver(tmp_path),
            tmp_path / "feedback.jsonl",
        ),
    )
    source = "def handler(request):\n    db.execute(request.getParameter('id'))\n"

    async def handle_request(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/contents/app.py")
        return httpx.Response(
            200,
            json={
                "type": "file",
                "encoding": "base64",
                "content": base64.b64encode(source.encode()).decode(),
            },
        )

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handle_request)) as client:
            return await worker._analyze_changed_python_files(
                client,
                PullRequestEvent("opened", "owner/repo", 12, "e" * 40, ""),
                {"app.py": [1, 2], "app.js": [1]},
                [
                    {"filename": "app.py", "status": "modified"},
                    {"filename": "app.js", "status": "modified"},
                ],
            )

    findings, unsupported_files = anyio.run(run)
    assert findings[0]["rule_id"] == "SQLI_RAW_CONCAT"
    assert findings[0]["repository"] == "owner/repo"
    assert unsupported_files == ["app.js"]


def test_end_to_end_ast_cfg_taint_gnn_policy_and_sarif_pipeline():
    import torch

    source = (
        "def handler(request):\n"
        "    query = request.getParameter('id')\n"
        "    if query:\n"
        "        db.execute(query)\n"
    )
    parsed = MultiLangParser().parse_source(source, "app.py")
    cfg = CFGBuilder().build(source)
    raw_findings = TaintEngine().analyze_cfg(source, file_path="app.py")
    graph = build_cpg(source)
    node_features = torch.ones((len(graph.nodes), 16), dtype=torch.float32)
    edge_index = torch.tensor(
        [[left for left, _, _ in graph.edges], [right for _, right, _ in graph.edges]],
        dtype=torch.long,
    )
    edge_type = torch.tensor(
        [EDGE_TYPES[kind] for _, _, kind in graph.edges],
        dtype=torch.long,
    )
    model = CPGGNN(input_dim=16)
    logits = model(
        node_features,
        edge_index,
        edge_type,
        torch.zeros(len(graph.nodes), dtype=torch.long),
    )
    assert logits.shape == (1,)

    metrics = MetricsCollector()
    metrics.update_memory_usage(1024)
    findings = VulnerabilityScorer.score_findings(
        [
            {
                "rule_id": finding.rule_id,
                "file": "app.py",
                "line": finding.line,
                "message": f"Untrusted input reaches {finding.sink}",
            }
            for finding in raw_findings
        ]
    )
    with metrics.track_scan():
        pass
    metrics.record_findings(findings)
    gate = RuleTuner().evaluate(findings)
    sarif = SARIFReporter.build_report(findings)

    assert parsed.tree["type"] == "Module"
    assert len(cfg.blocks) > 2
    assert raw_findings
    assert findings[0]["severity"] == "CRITICAL"
    assert gate["status"] == "FAILED"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "SQLI_RAW_CONCAT"
    assert "vulnerabilities_detected_total" in metrics.render().decode()


def test_batch_benchmark_stress_preserves_all_graphs_under_memory_budget():
    sources = [
        (
            f"module_{index}.py",
            f"def run_{index}(value):\n    copy = value\n    return copy\n",
        )
        for index in range(250)
    ]
    processor = CPGBatchProcessor(
        batch_size=16,
        max_workers=4,
        memory_limit_bytes=1024 * 1024 * 1024,
    )
    batches = list(processor.iter_batches(sources))

    assert batches
    assert all(0 < len(batch.graphs) <= 16 for batch in batches)
    assert all(batch.workers_used <= 4 for batch in batches)
    assert all(batch.graphs_per_second > 0 for batch in batches)
    assert sum(len(batch.graphs) for batch in batches) == len(sources)
    assert all(graph.nodes for batch in batches for graph in batch.graphs)


def test_deployment_files_define_non_root_api_worker_and_durable_data():
    dockerfile = (ANALYZER_ROOT / "src" / "deployment" / "Dockerfile").read_text(
        encoding="utf-8"
    )
    compose = (ANALYZER_ROOT / "src" / "deployment" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    assert "AS builder" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "src.deployment.webhook_app:app" in dockerfile
    assert "analyzer-data:/data" in compose
    assert "src.deployment.worker" in compose
    assert "no-new-privileges:true" in compose
