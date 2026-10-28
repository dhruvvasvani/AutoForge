from __future__ import annotations

import sys
from pathlib import Path

import pytest

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src.analysis.runtime_reachability import apply_runtime_observations
from src import dashboard_api


def test_missing_runtime_observations_do_not_change_static_reachability():
    findings, summary = apply_runtime_observations(
        [{"function": "app.main", "reachability": "REACHABLE_CODE"}],
        None,
    )

    assert findings == [{
        "function": "app.main",
        "reachability": "REACHABLE_CODE",
        "runtime_evidence": "UNAVAILABLE",
    }]
    assert summary == {
        "status": "unavailable",
        "executed_function_count": 0,
        "confirmed_static_reachable_count": 0,
    }


def test_runtime_observation_prioritizes_matching_statically_reachable_function():
    findings, summary = apply_runtime_observations(
        [{
            "function": "app.main",
            "reachability": "REACHABLE_CODE",
            "combined_risk_score": 6.5,
            "severity": "HIGH",
        }],
        [" app.main "],
    )

    assert findings[0]["runtime_evidence"] == "OBSERVED"
    assert findings[0]["runtime_priority"] == "IMMEDIATE"
    assert findings[0]["combined_risk_score"] == 6.5
    assert findings[0]["severity"] == "HIGH"
    assert summary["confirmed_static_reachable_count"] == 1


def test_missing_or_unreachable_runtime_evidence_never_downgrades_findings():
    findings, summary = apply_runtime_observations(
        [
            {"function": "app.main", "reachability": "REACHABLE_CODE"},
            {"function": "app.helper", "reachability": "UNREACHABLE_NOISE"},
        ],
        ["app.helper"],
    )

    assert findings[0]["runtime_evidence"] == "NOT_OBSERVED"
    assert "runtime_priority" not in findings[0]
    assert findings[1]["runtime_evidence"] == "OBSERVED"
    assert "runtime_priority" not in findings[1]
    assert summary["confirmed_static_reachable_count"] == 0


@pytest.mark.parametrize(
    "functions",
    [
        [""],
        ["x" * 513],
        [1],
    ],
)
def test_invalid_runtime_function_observation_is_rejected(functions):
    with pytest.raises(ValueError):
        apply_runtime_observations([], functions)


def test_project_scan_accepts_runtime_function_observations(monkeypatch):
    monkeypatch.setattr(
        dashboard_api,
        "_run_project_scanners",
        lambda _root: (
            {"semgrep": {"status": "complete", "finding_count": 0},
             "checkov": {"status": "complete", "finding_count": 0}},
            [],
        ),
    )
    request = dashboard_api.ProjectAnalyzeRequest(
        files=[
            dashboard_api.ProjectFile(
                file_path="app.py",
                source=(
                    "def main():\n"
                    "    value = input()\n"
                    "    cursor.execute(value)\n"
                ),
            ),
        ],
        runtime_executed_functions=["app.main"],
    )

    result = dashboard_api.analyze_project(request)
    ast_finding = next(item for item in result["findings"] if item["source"] == "AST")

    assert ast_finding["reachability"] == "REACHABLE_CODE"
    assert ast_finding["runtime_evidence"] == "OBSERVED"
    assert ast_finding["runtime_priority"] == "IMMEDIATE"
    assert result["runtime_evidence"]["status"] == "provided"
