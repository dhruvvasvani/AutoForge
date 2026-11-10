from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from noise_filter import ASTNoiseFilter


def test_filter_uses_real_file_and_line_findings_and_keeps_unreachable(tmp_path):
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "app.py").write_text(
        "def main():\n"
        "    helper()\n"
        "\n"
        "def helper():\n"
        "    pass\n"
        "\n"
        "def unused():\n"
        "    pass\n",
        encoding="utf-8",
    )
    findings = [
        {"rule_id": "reachable", "file": "app.py", "line": 5},
        {"rule_id": "not-reached", "file": "app.py", "line": 8},
        {"rule_id": "missing-file", "file": "missing.py", "line": 1},
    ]
    scan_path = tmp_path / "scan.json"
    scan_path.write_text(json.dumps({"results": findings}), encoding="utf-8")

    reachable, review = ASTNoiseFilter(["main"]).process_scan_file(
        scan_path, source_root
    )

    assert [finding["rule_id"] for finding in reachable] == ["reachable"]
    assert reachable[0]["status"] == "REACHABLE_STATIC"
    assert reachable[0]["reachability_evidence"]["call_path"] == ["app.main", "app.helper"]
    assert [finding["status"] for finding in review] == [
        "NOT_REACHED_STATIC",
        "UNVERIFIED_REACHABILITY",
    ]
    assert len(reachable) + len(review) == len(findings)
    assert all(finding["action_required"] for finding in reachable + review)
    assert all("reachability" not in finding for finding in findings)


def test_filter_normalizes_semgrep_fields_and_keeps_non_python_findings(tmp_path):
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "app.py").write_text("def main():\n    pass\n", encoding="utf-8")
    scan_path = tmp_path / "scan.json"
    scan_path.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "semgrep.rule",
                        "path": "app.py",
                        "start": {"line": 1},
                        "extra": {"message": "scanner message", "severity": "ERROR"},
                    },
                    {
                        "check_id": "semgrep.js-rule",
                        "path": "app.js",
                        "start": {"line": 3},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    reachable, review = ASTNoiseFilter(["main"]).process_scan_file(
        scan_path, source_root
    )

    assert len(reachable) == 1
    assert reachable[0]["rule_id"] == "semgrep.rule"
    assert reachable[0]["message"] == "scanner message"
    assert reachable[0]["severity"] == "ERROR"
    assert len(review) == 1
    assert review[0]["check_id"] == "semgrep.js-rule"
    assert review[0]["status"] == "UNVERIFIED_REACHABILITY"
    assert review[0]["reachability"] == "UNKNOWN"


def test_filter_rejects_malformed_scanner_results(tmp_path):
    source_root = tmp_path / "source"
    source_root.mkdir()
    scan_path = tmp_path / "scan.json"
    scan_path.write_text(json.dumps({"results": ["not a finding"]}), encoding="utf-8")

    with pytest.raises(ValueError, match="every scanner result"):
        ASTNoiseFilter(["main"]).process_scan_file(scan_path, source_root)


def test_cli_requires_actual_scan_source_and_entry_points():
    import subprocess

    result = subprocess.run(
        [sys.executable, str(ANALYZER_ROOT / "noise_filter.py"), "--help"],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "--scan SCAN" in result.stdout
    assert "--source-root SOURCE_ROOT" in result.stdout
    assert "--entry-point ENTRY_POINT" in result.stdout
