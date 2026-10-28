from __future__ import annotations

import sys
from pathlib import Path

import anyio
import httpx

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

import src.dashboard_api as dashboard_api
from src.dashboard_api import app


def _request(method: str, path: str) -> httpx.Response:
    async def send() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            return await client.request(method, path)

    return anyio.run(send)


def test_health_readiness_and_prometheus_metrics(monkeypatch):
    monkeypatch.delenv("CPG_GNN_CHECKPOINT", raising=False)

    health = _request("GET", "/health")
    readiness = _request("GET", "/readyz")
    metrics = _request("GET", "/metrics")

    assert health.status_code == 200
    assert health.json() == {"status": "ready", "service": "ast-analyzer"}
    assert readiness.json()["status"] == "ready"
    assert readiness.json()["cpg_gnn"] == {
        "configured": False,
        "checkpoint_available": None,
    }
    assert metrics.status_code == 200
    assert metrics.headers["content-type"].startswith("text/plain")
    assert 'ast_http_requests_total{method="GET",route="/health",status="200"}' in metrics.text


def test_parser_health_reports_supported_grammars_and_parse_audit():
    dashboard_api._TREE_SITTER_ENGINE.parse_source(
        "function {",
        "javascript",
        file_path="week13-parser-health.js",
    )
    response = _request("GET", "/api/v1/parser-health")

    assert response.status_code == 200
    assert "rust" in response.json()["supported_languages"]
    assert "javascript" in response.json()["supported_languages"]
    assert "cache" in response.json()
    assert response.json()["syntax_error_count_by_language"]["javascript"] > 0


def test_readiness_fails_when_configured_checkpoint_is_missing(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "CPG_GNN_CHECKPOINT",
        str(tmp_path / "missing-checkpoint.pt"),
    )

    response = _request("GET", "/readyz")

    assert response.status_code == 503
    assert response.json()["detail"]["status"] == "not_ready"
    assert response.json()["detail"]["cpg_gnn"]["checkpoint_available"] is False


def test_readiness_passes_when_configured_checkpoint_exists(monkeypatch, tmp_path):
    checkpoint = tmp_path / "checkpoint.pt"
    checkpoint.write_bytes(b"checkpoint")
    monkeypatch.setenv("CPG_GNN_CHECKPOINT", str(checkpoint))

    response = _request("GET", "/readyz")

    assert response.status_code == 200
    assert response.json()["cpg_gnn"]["checkpoint_available"] is True


def test_single_python_scan_reports_optional_cpg_inference(monkeypatch):
    monkeypatch.setenv("CPG_GNN_CHECKPOINT", "/configured/checkpoint.pt")
    monkeypatch.setattr(
        dashboard_api,
        "configured_cpg_predictions",
        lambda sources: (
            {"src/handler.py": 0.73},
            {
                "name": "CPG GNN",
                "available": True,
                "status": "complete",
                "files_scored": len(sources),
            },
        ),
    )

    result = dashboard_api._analyze_source(
        dashboard_api.AnalyzeRequest(
            file_path="src/handler.py",
            source=(
                "def handler():\n"
                "    value = input()\n"
                "    cursor.execute('SELECT * FROM users WHERE name=' + value)\n"
            ),
        ),
        record_metrics=False,
    )

    assert result["model"]["available"] is True
    assert result["findings"][0]["cpg_gnn_file_confidence"] == 0.73


def test_optional_cpg_failure_does_not_fail_ast_scan(monkeypatch):
    monkeypatch.setenv("CPG_GNN_CHECKPOINT", "/missing/checkpoint.pt")

    def fail(_sources):
        raise FileNotFoundError("checkpoint is missing")

    monkeypatch.setattr(dashboard_api, "configured_cpg_predictions", fail)
    result = dashboard_api._analyze_source(
        dashboard_api.AnalyzeRequest(
            file_path="safe.py",
            source="def safe():\n    return 1\n",
        ),
        record_metrics=False,
    )

    assert result["model"]["available"] is False
    assert result["model"]["status"] == "failed"
    assert "checkpoint is missing" in result["model"]["reason"]
    assert result["summary"]["finding_count"] == 0
