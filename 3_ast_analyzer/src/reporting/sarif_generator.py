"""Generate SARIF 2.1.0 reports from enriched vulnerability findings."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import quote

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SEVERITY_LEVELS = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


class SARIFReporter:
    """Build and write SARIF logs suitable for code-scanning consumers."""

    @classmethod
    def build_report(cls, findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []
        for index, finding in enumerate(findings):
            if not isinstance(finding, Mapping):
                raise TypeError(f"finding {index} must be a mapping")
            rule_id = str(finding.get("rule_id") or "AF-VULN-001")
            message = str(
                finding.get("message")
                or finding.get("description")
                or "Security finding"
            )
            severity = str(finding.get("severity", "MEDIUM")).upper()
            if severity not in _SEVERITY_LEVELS:
                raise ValueError(f"finding {index} has unknown severity {severity!r}")

            score = cls._optional_score(
                finding.get("combined_risk_score", finding.get("final_score")),
                index,
            )
            level = _SEVERITY_LEVELS[severity]
            rule_level = cls._score_level(score) if score is not None else level
            cwe = finding.get("cwe")
            remediation = finding.get("remediation")
            remediation_example = finding.get("remediation_example")
            tags = ["security"]
            if isinstance(cwe, str) and cwe:
                tags.append(f"external/cwe/{cwe.lower()}")

            rule: dict[str, Any] = {
                "id": rule_id,
                "shortDescription": {"text": message[:512]},
                "fullDescription": {"text": message},
                "defaultConfiguration": {"level": rule_level},
                "properties": {"tags": tags},
            }
            if score is not None:
                rule["properties"]["security-severity"] = f"{score:.2f}"
            if isinstance(remediation, str) and remediation:
                rule["help"] = {"text": remediation, "markdown": remediation}
            existing_rule = rules.get(rule_id)
            if existing_rule is None:
                rules[rule_id] = rule
            else:
                existing_tags = existing_rule["properties"]["tags"]
                existing_tags.extend(tag for tag in tags if tag not in existing_tags)
                previous_score = existing_rule["properties"].get("security-severity")
                if score is not None and (
                    previous_score is None or score > float(previous_score)
                ):
                    existing_rule["properties"]["security-severity"] = f"{score:.2f}"
                    existing_rule["defaultConfiguration"]["level"] = cls._score_level(score)
                if "help" not in existing_rule and "help" in rule:
                    existing_rule["help"] = rule["help"]

            line = cls._line_number(finding, index)
            file_name = finding.get("file") or finding.get("file_path") or "unknown"
            uri = cls._artifact_uri(file_name, index)
            region: dict[str, Any] = {"startLine": line}
            snippet = finding.get("code_snippet", finding.get("snippet"))
            if isinstance(snippet, str) and snippet:
                region["snippet"] = {"text": snippet}

            properties: dict[str, Any] = {"severity": severity}
            if score is not None:
                properties["combinedRiskScore"] = score
            if isinstance(cwe, str) and cwe:
                properties["cwe"] = cwe
            if isinstance(remediation, str) and remediation:
                properties["remediation"] = remediation
            if isinstance(remediation_example, str) and remediation_example:
                properties["remediationExample"] = remediation_example
            if "ml_confidence" in finding:
                properties["mlConfidence"] = cls._confidence(finding["ml_confidence"], index)
            if "sink_distance" in finding:
                properties["sinkDistance"] = cls._distance(finding["sink_distance"], index)
            reachability = finding.get("reachability")
            if isinstance(reachability, str) and reachability:
                properties["reachability"] = reachability

            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri},
                                "region": region,
                            }
                        }
                    ],
                    "properties": properties,
                }
            )

        return {
            "$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AutoForge AST Analyzer",
                            "informationUri": "https://github.com/dhruvvasvani/AutoForge",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    @classmethod
    def generate(
        cls,
        findings: Sequence[Mapping[str, Any]],
        output_path: str | Path,
    ) -> Path:
        report = cls.build_report(findings)
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return destination

    export_to_sarif = generate

    @staticmethod
    def _line_number(finding: Mapping[str, Any], index: int) -> int:
        value = finding.get("line_number", finding.get("line", 1))
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"finding {index} line number must be a positive integer")
        return value

    @staticmethod
    def _artifact_uri(value: Any, index: int) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"finding {index} file path must be a non-empty string")
        normalized = value.strip().replace("\\", "/")
        if normalized.startswith("/") or PureWindowsPath(value).is_absolute():
            raise ValueError(f"finding {index} file path must be repository-relative")
        parts = normalized.split("/")
        if any(part in {".", ".."} for part in parts):
            raise ValueError(f"finding {index} file path must not traverse directories")
        return quote(normalized, safe="/.-_")

    @staticmethod
    def _optional_score(value: Any, index: int) -> float | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"finding {index} risk score must be numeric")
        if not math.isfinite(value) or not 0.0 <= value <= 10.0:
            raise ValueError(f"finding {index} risk score must be finite and between 0 and 10")
        return float(value)

    @staticmethod
    def _score_level(score: float) -> str:
        if score >= 6.5:
            return "error"
        if score >= 4.0:
            return "warning"
        return "note"

    @staticmethod
    def _confidence(value: Any, index: int) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"finding {index} ML confidence must be numeric")
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise ValueError(f"finding {index} ML confidence must be finite and between 0 and 1")
        return float(value)

    @staticmethod
    def _distance(value: Any, index: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"finding {index} sink distance must be a non-negative integer")
        return value
