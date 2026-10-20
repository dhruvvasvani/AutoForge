from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src.reporting.sarif_generator import SARIFReporter
from src.ml.noise_filter import ASTNoiseFilter, FEATURE_KEYS
from src.scoring.vulnerability_scorer import VulnerabilityScorer


def test_vulnerability_scorer_applies_distance_and_ml_confidence():
    finding = {
        "rule_id": "SQLI_RAW_CONCAT",
        "sink": "sqlite3.execute",
        "sink_distance": 2,
        "ml_confidence": 0.8,
        "file": "src/routes.py",
        "line": 14,
    }

    scored = VulnerabilityScorer.score_finding(finding)

    assert scored["base_score"] == 9.0
    assert scored["distance_factor"] == 0.8
    assert scored["final_score"] == 5.76
    assert scored["combined_risk_score"] == 5.76
    assert scored["severity"] == "MEDIUM"
    assert scored["cwe"] == "CWE-89"
    assert "parameterized queries" in scored["remediation"]
    assert "?" in scored["remediation_example"]
    assert "final_score" not in finding


def test_vulnerability_scorer_uses_floor_and_fail_open_ml_default():
    scored = VulnerabilityScorer.score_finding(
        {"rule_id": "CMD_INJ_EXEC", "sink_distance": 20}
    )

    assert scored["distance_factor"] == 0.4
    assert scored["ml_confidence"] == 1.0
    assert scored["final_score"] == 3.4
    assert scored["severity"] == "LOW"
    assert scored["cwe"] == "CWE-78"


def test_vulnerability_scorer_uses_sink_fallback_and_zero_confidence():
    scored = VulnerabilityScorer.score_finding(
        {
            "rule_id": "UNKNOWN_RULE",
            "sink": "os.system",
            "sink_distance": 0,
            "ml_confidence": 0.0,
        }
    )

    assert scored["base_score"] == 8.5
    assert scored["cwe"] == "CWE-78"
    assert scored["final_score"] == 0.0
    assert scored["severity"] == "LOW"


@pytest.mark.parametrize(
    ("confidence", "expected_score", "expected_severity"),
    [
        (1.0, 9.0, "CRITICAL"),
        (0.8, 7.2, "HIGH"),
        (0.5, 4.5, "MEDIUM"),
        (0.3, 2.7, "LOW"),
    ],
)
def test_vulnerability_scorer_maps_scores_to_risk_levels(
    confidence, expected_score, expected_severity
):
    scored = VulnerabilityScorer.score_finding(
        {"rule_id": "SQLI_RAW_CONCAT", "ml_confidence": confidence}
    )
    assert scored["final_score"] == expected_score
    assert scored["severity"] == expected_severity


def test_noise_filter_uses_week6_random_forest_configuration_and_features():
    noise_filter = ASTNoiseFilter()
    parameters = noise_filter.model.get_params()

    assert parameters["n_estimators"] == 100
    assert parameters["max_depth"] == 12
    assert parameters["criterion"] == "gini"
    assert "sanitizer_present" in FEATURE_KEYS
    assert ASTNoiseFilter.extract_features(
        {
            "cyclomatic_complexity": 4,
            "max_nesting_depth": 2,
            "sink_distance": 1,
            "user_input_tainted": True,
            "sanitizer_present": True,
        }
    ) == [4.0, 2.0, 1.0, 1.0, 1.0]


@pytest.mark.parametrize(
    ("finding", "field"),
    [
        ({"sink_distance": -1}, "sink_distance"),
        ({"sink_distance": 1.5}, "sink_distance"),
        ({"ml_confidence": -0.1}, "ml_confidence"),
        ({"ml_confidence": 1.1}, "ml_confidence"),
        ({"ml_confidence": float("nan")}, "ml_confidence"),
    ],
)
def test_vulnerability_scorer_rejects_invalid_context(finding, field):
    with pytest.raises(ValueError, match=field):
        VulnerabilityScorer.score_finding(finding)


def test_sarif_reporter_generates_sarif_21_with_cwe_and_remediation(tmp_path):
    scored = VulnerabilityScorer.score_finding(
        {
            "rule_id": "SQLI_RAW_CONCAT",
            "message": "Untrusted input reaches a SQL query",
            "file": "src\\routes.py",
            "line": 14,
            "sink_distance": 1,
            "ml_confidence": 0.95,
            "code_snippet": "cursor.execute(query)",
        }
    )
    report_path = SARIFReporter.generate(
        [scored],
        tmp_path / "reports" / "results.sarif",
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["version"] == "2.1.0"
    assert report["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    run = report["runs"][0]
    assert run["tool"]["driver"]["name"] == "AutoForge AST Analyzer"
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == "SQLI_RAW_CONCAT"
    assert "external/cwe/cwe-89" in rule["properties"]["tags"]
    assert rule["properties"]["security-severity"] == "7.70"
    assert "parameterized queries" in rule["help"]["text"]

    result = run["results"][0]
    location = result["locations"][0]["physicalLocation"]
    assert result["level"] == "error"
    assert result["properties"]["cwe"] == "CWE-89"
    assert result["properties"]["combinedRiskScore"] == 7.7
    assert result["properties"]["mlConfidence"] == 0.95
    assert location["artifactLocation"]["uri"] == "src/routes.py"
    assert location["region"]["startLine"] == 14
    assert location["region"]["snippet"]["text"] == "cursor.execute(query)"


def test_sarif_reporter_handles_empty_findings():
    report = SARIFReporter.build_report([])

    assert report["version"] == "2.1.0"
    assert report["runs"][0]["tool"]["driver"]["rules"] == []
    assert report["runs"][0]["results"] == []


def test_sarif_rule_uses_highest_score_when_rule_has_many_results():
    report = SARIFReporter.build_report(
        [
            {
                "rule_id": "SQLI_RAW_CONCAT",
                "file": "src/first.py",
                "line": 1,
                "severity": "LOW",
                "combined_risk_score": 1.2,
            },
            {
                "rule_id": "SQLI_RAW_CONCAT",
                "file": "src/second.py",
                "line": 2,
                "severity": "CRITICAL",
                "combined_risk_score": 9.0,
            },
        ]
    )

    rule = report["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "9.00"
    assert rule["defaultConfiguration"]["level"] == "error"
    assert len(report["runs"][0]["results"]) == 2


@pytest.mark.parametrize(
    "finding",
    [
        {"file": "../outside.py", "line": 1},
        {"file": "C:\\outside.py", "line": 1},
        {"file": "src/main.py", "line": 0},
        {"file": "src/main.py", "line": 1, "severity": "UNKNOWN"},
        {"file": "src/main.py", "line": 1, "combined_risk_score": 11.0},
        {"file": "src/main.py", "line": 1, "ml_confidence": 1.5},
    ],
)
def test_sarif_reporter_rejects_invalid_finding_fields(finding):
    with pytest.raises(ValueError):
        SARIFReporter.build_report([finding])
