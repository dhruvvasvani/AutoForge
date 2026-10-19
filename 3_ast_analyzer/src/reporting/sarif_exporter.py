"""Write normalized findings as SARIF 2.1.0."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import quote

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


class SARIFExporter:
    @staticmethod
    def export_to_sarif(
        findings: Sequence[Mapping[str, Any]], output_path: str | Path
    ) -> Path:
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []
        for finding in findings:
            if not isinstance(finding, Mapping):
                raise TypeError("Each finding must be a mapping")
            rule_id = str(finding.get("rule_id") or "AF-VULN-001")
            message = str(finding.get("message") or finding.get("description") or "Security finding")
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "shortDescription": {"text": message[:512]},
                    "fullDescription": {"text": message},
                },
            )
            try:
                line = max(1, int(finding.get("line_number", finding.get("line", 1))))
            except (TypeError, ValueError):
                line = 1
            score = finding.get("combined_risk_score")
            if score is not None and (
                isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score)
            ):
                raise ValueError(f"Invalid combined_risk_score for {rule_id}")
            severity = str(finding.get("severity", "MEDIUM")).upper()
            level = (
                "error" if (score is not None and score >= 8.5) or severity in {"CRITICAL", "HIGH"}
                else "warning" if (score is not None and score >= 4.0) or severity == "MEDIUM"
                else "note"
            )
            location: dict[str, Any] = {
                "artifactLocation": {
                    "uri": quote(
                        str(finding.get("file") or finding.get("file_path") or "unknown").replace("\\", "/"),
                        safe="/.-_",
                    )
                },
                "region": {"startLine": line},
            }
            snippet = finding.get("code_snippet") or finding.get("snippet")
            if isinstance(snippet, str) and snippet:
                location["region"]["snippet"] = {"text": snippet}
            properties: dict[str, Any] = {"severity": severity}
            if score is not None:
                properties["combinedRiskScore"] = float(score)
            remediation = finding.get("remediation")
            if isinstance(remediation, str) and remediation:
                properties["remediation"] = remediation
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": message},
                    "locations": [{"physicalLocation": location}],
                    "properties": properties,
                }
            )

        report = {
            "$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "AutoForge AST Analyzer", "rules": list(rules.values())}},
                    "results": results,
                }
            ],
        }
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return destination
