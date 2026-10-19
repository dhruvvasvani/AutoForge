"""Severity and combined-risk CI gate for scan results."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def evaluate_findings(
    findings: Iterable[Mapping[str, Any]],
    *,
    max_score: float = 8.0,
    fail_on_severity: Iterable[str] = ("CRITICAL",),
) -> dict[str, Any]:
    if isinstance(max_score, bool) or not isinstance(max_score, (int, float)) or not math.isfinite(max_score):
        raise ValueError("max_score must be finite numeric")
    fail_levels = {severity.upper() for severity in fail_on_severity}
    unknown = fail_levels - set(SEVERITY_ORDER)
    if unknown:
        raise ValueError(f"Unknown severity threshold(s): {sorted(unknown)}")
    blockers: list[dict[str, Any]] = []
    inspected = 0
    for index, finding in enumerate(findings):
        if not isinstance(finding, Mapping):
            raise ValueError(f"Finding {index} must be an object")
        inspected += 1
        severity = str(finding.get("severity", "LOW")).upper()
        if severity not in SEVERITY_ORDER:
            raise ValueError(f"Finding {index} has unknown severity {severity!r}")
        score = finding.get("combined_risk_score", finding.get("final_score"))
        reasons: list[str] = []
        if severity in fail_levels:
            reasons.append(f"severity {severity} is configured to fail")
        if score is not None:
            if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
                raise ValueError(f"Finding {index} has invalid risk score")
            if score > max_score:
                reasons.append(f"risk score {score:g} exceeds {max_score:g}")
        if reasons:
            blockers.append({"index": index, "rule_id": finding.get("rule_id"), "reasons": reasons})
    return {
        "passed": not blockers,
        "findings_inspected": inspected,
        "blockers": blockers,
        "max_score": float(max_score),
        "fail_on_severity": sorted(fail_levels, key=lambda item: SEVERITY_ORDER[item], reverse=True),
    }


def _findings_from_report(data: Any) -> list[Mapping[str, Any]]:
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        raise ValueError("Input must be a findings list or report object")
    if isinstance(data.get("findings"), list):
        return data["findings"]
    if isinstance(data.get("vulnerabilities"), list):
        return data["vulnerabilities"]
    if isinstance(data.get("runs"), list):
        findings: list[Mapping[str, Any]] = []
        for run in data["runs"]:
            for result in run.get("results", []):
                properties = result.get("properties") or {}
                findings.append({
                    "rule_id": result.get("ruleId"),
                    "severity": properties.get(
                        "severity",
                        {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(
                            str(result.get("level", "note")).lower(), "LOW"
                        ),
                    ),
                    "combined_risk_score": properties.get("combinedRiskScore"),
                })
        return findings
    raise ValueError("Report contains no findings array")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail CI when findings exceed configured risk limits")
    parser.add_argument("report", type=Path, help="JSON findings or SARIF 2.1.0 report")
    parser.add_argument("--max-score", type=float, default=8.0)
    parser.add_argument("--fail-on", action="append", dest="fail_on", default=["CRITICAL"])
    args = parser.parse_args(argv)
    try:
        findings = _findings_from_report(json.loads(args.report.read_text(encoding="utf-8")))
        result = evaluate_findings(findings, max_score=args.max_score, fail_on_severity=args.fail_on)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Pipeline gate error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
