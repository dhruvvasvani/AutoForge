from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from fastapi import HTTPException

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

import src.dashboard_api as dashboard_api
from src.dashboard_api import app
from src.reporting.scan_metrics import ScanMetricsStore


@pytest.fixture(autouse=True)
def isolate_scan_history(tmp_path, monkeypatch):
    monkeypatch.setattr(
        dashboard_api,
        "_scan_metrics_store",
        ScanMetricsStore(tmp_path / "scan_history.sqlite3"),
    )


def _post(path: str, payload: dict[str, Any]) -> httpx.Response:
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
    assert result["metrics"]["files_received"] == 1
    assert result["metrics"]["files_analyzed"] == 1
    assert result["metrics"]["history_id"] > 0
    assert result["model"]["confidence"] is None
    assert result["ast"]["type"] == "Module"
    assert result["cfg"]["blocks"]
    assert result["policy_gate"]["status"] == "FAILED"
    assert result["sarif"]["version"] == "2.1.0"


def test_project_scan_serializes_python_ellipsis_literals(monkeypatch):
    monkeypatch.setattr(
        dashboard_api,
        "_run_project_scanners",
        lambda _root: (
            {"semgrep": {"status": "complete", "finding_count": 0},
             "checkov": {"status": "complete", "finding_count": 0}},
            [],
        ),
    )
    response = _post(
        "/api/v1/analyze-project",
        {"files": [{
            "file_path": "src/stubs.py",
            "source": "def unavailable():\n    return ...\n",
        }]},
    )

    assert response.status_code == 200
    result = response.json()
    value = result["files"][0]["result"]["ast"]["body"][0]["body"][0]["value"]["value"]
    assert value == "..."


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


def test_mysql_parser_diagnostics_are_not_counted_as_security_findings():
    response = _post(
        "/api/v1/analyze",
        {
            "file_path": "database.sql",
            "source": (
                "-- Database creation\n"
                "CREATE DATABASE IF NOT EXISTS credguard;\n"
                "USE credguard;\n"
                "CREATE TABLE IF NOT EXISTS users (\n"
                "  id INT AUTO_INCREMENT PRIMARY KEY,\n"
                "  name VARCHAR(50) NOT NULL\n"
                ");\n"
            ),
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["findings"] == []
    assert result["summary"]["finding_count"] == 0
    assert result["summary"]["severity_counts"] == {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }
    assert result["diagnostics"]
    assert "not a confirmed security vulnerability" in result["diagnostics"][0]["message"]
    assert result["policy_gate"]["passed"] is True
    assert result["sarif"]["runs"][0]["results"] == []


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
    assert sum(result["summary"]["severity_counts"].values()) == result["summary"]["finding_count"]
    assert result["model"]["available"] is False


def test_project_scan_serializes_large_jsx_ast_and_survives_repeat_scans(monkeypatch):
    monkeypatch.setattr(
        dashboard_api,
        "_run_project_scanners",
        lambda _root: (
            {"semgrep": {"status": "complete", "finding_count": 0},
             "checkov": {"status": "complete", "finding_count": 0}},
            [],
        ),
    )
    sections = "\n".join(
        f"<section key={{{index}}}><h2>Item {index}</h2><p>Details {index}</p></section>"
        for index in range(400)
    )
    source = f"export default function Page() {{ return <main>{sections}</main>; }}"
    payload = {
        "files": [{"file_path": "src/page.jsx", "source": source}],
    }

    first = _post("/api/v1/analyze-project", payload)
    second = _post("/api/v1/analyze-project", payload)

    assert first.status_code == 200
    assert second.status_code == 200
    result = first.json()
    assert result["summary"]["files_analyzed"] == 1
    assert result["summary"]["files_failed"] == 0
    assert result["files"][0]["result"]["language"] == "javascript"
    assert len(result["files"][0]["result"]["ast"]["nodes"]) > 2_000


def test_project_scanner_uses_default_security_rules_and_reports_findings(
    monkeypatch, tmp_path
):
    source_file = tmp_path / "src" / "app.js"
    source_file.parent.mkdir()
    source_file.write_text("export function run(code) { return eval(code); }\n", encoding="utf-8")
    commands = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        if command[0] == "semgrep":
            payload = {
                "results": [{
                    "check_id": "javascript.browser.security.eval-detected.eval-detected",
                    "path": str(source_file),
                    "start": {"line": 1},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Avoid evaluating untrusted code.",
                    },
                }],
                "errors": [],
                "paths": {"scanned": [str(source_file)]},
            }
        else:
            payload = []
        return dashboard_api.subprocess.CompletedProcess(
            command, 0, stdout=json.dumps(payload), stderr=""
        )

    monkeypatch.setattr(dashboard_api.subprocess, "run", fake_run)

    tools, findings = dashboard_api._run_project_scanners(tmp_path)

    assert commands[0][commands[0].index("--config") + 1] == "p/default"
    assert tools["semgrep"] == {
        "status": "complete",
        "finding_count": 1,
        "config": "p/default",
        "files_scanned": 1,
    }
    assert findings == [{
        "source": "Semgrep",
        "rule_id": "javascript.browser.security.eval-detected.eval-detected",
        "file": "src/app.js",
        "line": 1,
        "severity": "CRITICAL",
        "message": "Avoid evaluating untrusted code.",
    }]


def test_semgrep_errors_mark_project_scan_partial(monkeypatch, tmp_path):
    def fake_run(command, **_kwargs):
        payload = {
            "results": [],
            "errors": [{"message": "Could not parse src/broken.js"}],
            "paths": {"scanned": ["src/broken.js"]},
        } if command[0] == "semgrep" else []
        return dashboard_api.subprocess.CompletedProcess(
            command, 0, stdout=json.dumps(payload), stderr=""
        )

    monkeypatch.setattr(dashboard_api.subprocess, "run", fake_run)

    tools, findings = dashboard_api._run_project_scanners(tmp_path)

    assert findings == []
    assert tools["semgrep"]["status"] == "partial"
    assert tools["semgrep"]["files_scanned"] == 1
    assert "Could not parse src/broken.js" in tools["semgrep"]["error"]


def test_project_scan_history_and_executive_report_endpoints(monkeypatch):
    monkeypatch.setattr(
        dashboard_api,
        "_run_project_scanners",
        lambda _root: (
            {"semgrep": {"status": "complete", "finding_count": 0},
             "checkov": {"status": "complete", "finding_count": 0}},
            [],
        ),
    )
    scan = dashboard_api.analyze_project(dashboard_api.ProjectAnalyzeRequest(files=[
        dashboard_api.ProjectFile(
            file_path="app.py",
            source="def main():\n    value = input()\n    cursor.execute(value)\n",
        ),
    ]))

    history_response = _post_get("/api/v1/metrics/history?limit=5")
    html_response = _post(
        "/api/v1/reports",
        {
            "metrics": scan["metrics"],
            "findings": scan["findings"],
            "format": "html",
        },
    )
    pdf_response = _post(
        "/api/v1/reports",
        {
            "metrics": scan["metrics"],
            "findings": scan["findings"],
            "format": "pdf",
        },
    )

    assert history_response.status_code == 200
    assert history_response.json()["count"] == 1
    assert history_response.json()["scans"][0]["id"] == scan["metrics"]["history_id"]
    assert html_response.status_code == 200
    assert html_response.headers["content-type"].startswith("text/html")
    assert "AutoForge Security Scan Summary" in html_response.text
    assert pdf_response.status_code == 200
    assert pdf_response.content.startswith(b"%PDF-")


def _post_get(path: str) -> httpx.Response:
    async def send() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            return await client.get(path)

    return anyio.run(send)


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
