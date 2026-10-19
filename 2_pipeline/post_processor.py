"""Convert AST findings to the backend result DTO."""

from __future__ import annotations

from typing import Any


def format_scan_results(result: dict[str, Any]) -> dict[str, Any]:
    if result.get("status") != "COMPLETED":
        raise ValueError("Only completed scans can be posted")
    findings = result.get("vulnerabilities", [])
    if not isinstance(findings, list):
        raise ValueError("vulnerabilities must be a list")
    ast_findings = []
    scores = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("each finding must be an object")
        score = finding.get("combined_risk_score")
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            scores.append(float(score))
        ast_findings.append({
            "path": finding.get("file") or finding.get("path"),
            "start": {"line": finding.get("line", 0)},
            "check_id": finding.get("rule_id") or finding.get("rule"),
            "extra": {
                "severity": finding.get("severity", "MEDIUM"),
                "message": finding.get("description") or finding.get("message", ""),
                "combined_risk_score": score,
                "reachable": finding.get("reachable", False),
            },
        })
    return {
        "semgrep": [],
        "checkov": [],
        "ast": ast_findings,
        "combinedRiskScore": max(scores, default=None),
        "commitSha": result.get("commit_sha"),
    }
