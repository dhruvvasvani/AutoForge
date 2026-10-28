from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src.policy.security_gate import evaluate_security_gate
from src.reporting.executive_report import build_html_report, build_pdf_report
from src.reporting.pipeline_gate import evaluate_findings
from src.reporting.scan_metrics import ScanMetricsStore, build_scan_metrics


def test_ci_gate_ignores_unreachable_noise_but_fails_reachable_critical():
    result = evaluate_findings(
        [
            {
                "severity": "CRITICAL",
                "combined_risk_score": 9.5,
                "reachability": "UNREACHABLE_NOISE",
            },
            {
                "severity": "CRITICAL",
                "combined_risk_score": 9.5,
                "reachability": "REACHABLE_CODE",
            },
        ]
    )

    assert result["passed"] is False
    assert result["unreachable_ignored"] == 1
    assert len(result["blockers"]) == 1
    assert len(result["blockers"][0]["reasons"]) == 2


def test_ci_gate_treats_reachable_error_as_critical():
    result = evaluate_findings([
        {"severity": "ERROR", "reachability": "REACHABLE_CODE"},
    ])

    assert result["passed"] is False
    assert result["blockers"][0]["reasons"] == ["severity CRITICAL is configured to fail"]


def test_project_gate_does_not_block_on_unreachable_critical():
    result = evaluate_security_gate(
        [
            {
                "severity": "CRITICAL",
                "combined_risk_score": 10,
                "reachability": "UNREACHABLE_NOISE",
            }
        ]
    )

    assert result["passed"] is True
    assert result["counts"]["CRITICAL"] == 0
    assert result["unreachable_ignored"] == 1


def test_metrics_aggregate_coverage_noise_severity_and_file_hotspots():
    metrics = build_scan_metrics(
        [
            {
                "file": "src/a.py",
                "severity": "CRITICAL",
                "combined_risk_score": 9.5,
                "reachability": "REACHABLE_CODE",
            },
            {
                "file": "src/b.py",
                "severity": "HIGH",
                "combined_risk_score": 7.5,
                "reachability": "UNREACHABLE_NOISE",
            },
            {"file": "src/c.py", "severity": "LOW"},
        ],
        files_received=4,
        files_analyzed=3,
        timestamp=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    assert metrics["scan_timestamp"] == "2026-01-02T00:00:00+00:00"
    assert metrics["ast_coverage_pct"] == 75
    assert metrics["noise_reduction_pct"] == pytest.approx(66.67)
    assert metrics["unreachable_noise_pct"] == pytest.approx(33.33)
    assert metrics["reachability"] == {
        "REACHABLE_CODE": 1,
        "UNREACHABLE_NOISE": 1,
        "UNKNOWN": 1,
    }
    assert metrics["severity_counts"]["CRITICAL"] == 1
    assert metrics["file_hotspots"][0]["file"] == "src/a.py"


def test_metrics_history_persists_and_validates_limit(tmp_path):
    store = ScanMetricsStore(tmp_path / "history.sqlite3")
    metrics = build_scan_metrics([], files_received=1, files_analyzed=1)
    record_id = store.record(metrics)

    assert store.history(10) == [{"id": record_id, **metrics}]
    with pytest.raises(ValueError, match="limit"):
        store.history(0)


def test_html_report_escapes_findings_and_includes_metrics():
    report = build_html_report(
        {
            "scan_timestamp": "2026-01-02T00:00:00+00:00",
            "severity_counts": {"CRITICAL": 1},
            "files_received": 1,
            "files_analyzed": 1,
            "ast_coverage_pct": 100,
            "reachable_findings": 1,
            "unreachable_findings": 0,
            "noise_reduction_pct": 0,
        },
        [
            {
                "file": "src/<script>.py",
                "line": 2,
                "severity": "CRITICAL",
                "message": "<script>alert(1)</script>",
            }
        ],
    )

    assert "AST coverage: 100.00%" in report
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report
    assert "<script>alert(1)</script>" not in report


def test_pdf_report_is_a_valid_pdf_with_findings():
    report = build_pdf_report(
        {"severity_counts": {"HIGH": 1}, "files_received": 1, "files_analyzed": 1},
        [{"file": "src/app.py", "line": 4, "severity": "HIGH", "message": "Unsafe query"}],
    )

    assert report.startswith(b"%PDF-")


def test_metrics_reject_non_json_values(tmp_path):
    store = ScanMetricsStore(tmp_path / "history.sqlite3")
    metrics = build_scan_metrics([], files_received=0, files_analyzed=0)
    metrics["bad"] = float("nan")

    with pytest.raises(RuntimeError, match="could not persist"):
        store.record(metrics)
