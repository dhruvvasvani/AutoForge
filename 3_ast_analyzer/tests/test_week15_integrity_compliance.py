from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src import dashboard_api
from src.reporting.compliance_evidence import build_compliance_evidence


def test_project_scan_reports_matched_source_digest_and_partial_provenance(monkeypatch):
    monkeypatch.setattr(
        dashboard_api,
        "_run_project_scanners",
        lambda _root: (
            {"semgrep": {"status": "complete", "finding_count": 0},
             "checkov": {"status": "complete", "finding_count": 0}},
            [],
        ),
    )
    source = "def main():\n    return 1\n"
    result = dashboard_api.analyze_project(dashboard_api.ProjectAnalyzeRequest(
        files=[
            dashboard_api.ProjectFile(
                file_path="verified.py",
                source=source,
                expected_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest().upper(),
            ),
            dashboard_api.ProjectFile(file_path="unverified.py", source="def run():\n    pass\n"),
        ],
    ))

    assert result["content_integrity"]["status"] == "partially_verified"
    assert result["content_integrity"]["files"][0]["status"] == "MATCHED"
    assert result["content_integrity"]["files"][0]["sha256"] == hashlib.sha256(
        source.encode("utf-8")
    ).hexdigest()
    assert result["content_integrity"]["files"][1]["status"] == "UNVERIFIED"


def test_project_scan_rejects_mismatched_source_digest():
    with pytest.raises(HTTPException) as error:
        dashboard_api.analyze_project(dashboard_api.ProjectAnalyzeRequest(files=[
            dashboard_api.ProjectFile(
                file_path="app.py",
                source="print('changed')",
                expected_sha256="0" * 64,
            ),
        ]))

    assert error.value.status_code == 422
    assert "does not match" in error.value.detail


def test_project_scan_rejects_malformed_expected_digest():
    with pytest.raises(HTTPException) as error:
        dashboard_api.analyze_project(dashboard_api.ProjectAnalyzeRequest(files=[
            dashboard_api.ProjectFile(
                file_path="app.py",
                source="print('unchanged')",
                expected_sha256="not-a-digest",
            ),
        ]))

    assert error.value.status_code == 422
    assert "64-character hexadecimal" in error.value.detail


def test_compliance_evidence_maps_known_cwe_without_claiming_compliance():
    report = build_compliance_evidence([
        {"file": "app.py", "line": 12, "rule_id": "SQLI", "cwe": "cwe-89"},
        {"file": "other.py", "line": 4, "rule_id": "CUSTOM"},
    ])
    categories = {item["category"]: item for item in report["categories"]}

    assert report["framework"] == "OWASP Top 10:2021"
    assert report["is_compliance_assessment"] is False
    assert categories["A03:2021 Injection"]["evidence_count"] == 1
    assert categories["A03:2021 Injection"]["evidence"][0]["file"] == "app.py"
    assert categories["A04:2021 Insecure Design"]["status"] == "NO_MAPPED_EVIDENCE"
