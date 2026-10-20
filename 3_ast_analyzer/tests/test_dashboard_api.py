from __future__ import annotations

import sys
from pathlib import Path

import anyio
import httpx
import pytest
from fastapi import HTTPException

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

import src.dashboard_api as dashboard_api
from src.dashboard_api import app


def _post(path: str, payload: dict[str, str]) -> httpx.Response:
    async def send() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            return await client.post(path, json=payload)

    return anyio.run(send)


def test_local_scan_returns_graph_findings_policy_and_sarif():
    response = _post(
        "/api/v1/analyze",
        {
            "file_path": "src/handler.py",
            "source": (
                "def handler():\n"
                "    value = input()\n"
                "    cursor.execute('SELECT * FROM users WHERE name=' + value)\n"
            ),
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["language"] == "python"
    assert result["summary"]["finding_count"] == 1
    assert result["findings"][0]["rule_id"] == "SQLI_RAW_CONCAT"
    assert result["findings"][0]["line"] == 3
    assert "ml_confidence" not in result["findings"][0]
    assert result["model"]["available"] is False
    assert result["model"]["confidence"] is None
    assert result["ast"]["type"] == "Module"
    assert result["cfg"]["blocks"]
    assert result["policy_gate"]["status"] == "FAILED"
    assert result["sarif"]["version"] == "2.1.0"


def test_local_scan_rejects_invalid_python_and_unsafe_file_paths():
    syntax_error = _post(
        "/api/v1/analyze",
        {"file_path": "sample.py", "source": "def invalid(:\n"},
    )
    unsafe_path = _post(
        "/api/v1/analyze",
        {"file_path": "../secret.py", "source": "print('not executed')\n"},
    )

    assert syntax_error.status_code == 422
    assert "could not be parsed safely" in syntax_error.json()["detail"]
    assert unsafe_path.status_code == 422
    assert "repository-relative" in unsafe_path.json()["detail"]


def test_local_scan_enforces_source_size_limit():
    response = _post(
        "/api/v1/analyze",
        {"file_path": "large.py", "source": "é" * 128_001},
    )

    assert response.status_code == 422
    assert "size limit" in response.json()["detail"]


def test_project_scan_combines_ast_reachability_and_static_scanner_results(monkeypatch):
    monkeypatch.setattr(
        dashboard_api,
        "_run_project_scanners",
        lambda _root: (
            {"semgrep": {"status": "complete", "finding_count": 0},
             "checkov": {"status": "complete", "finding_count": 1}},
            [{
                "source": "Checkov",
                "rule_id": "CKV_TEST_1",
                "file": "infra/main.tf",
                "line": 1,
                "severity": "HIGH",
                "message": "Example infrastructure finding",
            }],
        ),
    )
    request = dashboard_api.ProjectAnalyzeRequest(files=[
        dashboard_api.ProjectFile(
            file_path="src/main.py",
            source=(
                "def main():\n"
                "    value = input()\n"
                "    cursor.execute('SELECT * FROM users WHERE name=' + value)\n"
            ),
        ),
        dashboard_api.ProjectFile(file_path="infra/main.tf", source='resource "test" "x" {}'),
    ])

    result = dashboard_api.analyze_project(request)

    assert result["summary"]["files_received"] == 2
    assert result["summary"]["files_analyzed"] == 1
    assert result["summary"]["files_scanner_only"] == 1
    assert result["reachability"]["status"] == "complete"
    ast_finding = next(item for item in result["findings"] if item["source"] == "AST")
    checkov_finding = next(item for item in result["findings"] if item["source"] == "Checkov")
    assert ast_finding["reachability"] == "REACHABLE_CODE"
    assert checkov_finding["reachability"] == "UNKNOWN"
    assert result["model"]["available"] is False


def test_project_scan_rejects_secrets_and_traversal_paths():
    with pytest.raises(HTTPException):
        dashboard_api.analyze_project(dashboard_api.ProjectAnalyzeRequest(files=[
            dashboard_api.ProjectFile(file_path="../outside.py", source="print('x')"),
        ]))
    with pytest.raises(HTTPException):
        dashboard_api.analyze_project(dashboard_api.ProjectAnalyzeRequest(files=[
            dashboard_api.ProjectFile(file_path=".env", source="SECRET=value"),
        ]))


def test_project_scan_accepts_empty_source_files(monkeypatch):
    monkeypatch.setattr(
        dashboard_api,
        "_run_project_scanners",
        lambda _root: (
            {"semgrep": {"status": "complete", "finding_count": 0},
             "checkov": {"status": "complete", "finding_count": 0}},
            [],
        ),
    )

    result = dashboard_api.analyze_project(dashboard_api.ProjectAnalyzeRequest(files=[
        dashboard_api.ProjectFile(file_path="src/empty.py", source=""),
    ]))

    assert result["summary"]["files_received"] == 1
    assert result["summary"]["files_analyzed"] == 1
    assert result["summary"]["files_failed"] == 0
    assert result["files"][0]["result"]["summary"]["finding_count"] == 0
