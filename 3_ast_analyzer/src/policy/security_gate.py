"""Configurable CI gate for scored security findings."""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_ALIASES = {
    "ERROR": "CRITICAL",
    "FATAL": "CRITICAL",
    "WARNING": "HIGH",
    "NOTE": "LOW",
    "INFO": "LOW",
}


@dataclass(frozen=True)
class SecurityPolicy:
    max_critical_allowed: int = 0
    max_high_allowed: int = 1
    min_severity_score_block: float = 8.5
    require_ml_confidence: float = 0.60
    max_medium_allowed: int | None = None
    max_low_allowed: int | None = None

    def __post_init__(self) -> None:
        for name in ("max_critical_allowed", "max_high_allowed"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        for name in ("max_medium_allowed", "max_low_allowed"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                raise ValueError(f"{name} must be None or a non-negative integer")
        for name in ("min_severity_score_block", "require_ml_confidence"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise ValueError(f"{name} must be finite numeric")
        if self.min_severity_score_block < 0:
            raise ValueError("min_severity_score_block must be non-negative")
        if not 0.0 <= self.require_ml_confidence <= 1.0:
            raise ValueError("require_ml_confidence must be between 0 and 1")


POLICY_RULES = SecurityPolicy()


def evaluate_security_gate(
    findings: Iterable[Mapping[str, Any]],
    policy: SecurityPolicy = POLICY_RULES,
) -> dict[str, Any]:
    """Evaluate high-confidence findings and return a CI-friendly gate result."""
    if not isinstance(policy, SecurityPolicy):
        raise TypeError("policy must be a SecurityPolicy")

    counts = {severity: 0 for severity in SEVERITIES}
    blockers: list[dict[str, Any]] = []
    excluded_low_confidence = 0
    unreachable_ignored = 0
    for index, finding in enumerate(findings):
        if not isinstance(finding, Mapping):
            raise ValueError(f"finding {index} must be an object")
        if finding.get("reachability") == "UNREACHABLE_NOISE":
            unreachable_ignored += 1
            continue
        raw_severity = finding.get("severity", "LOW")
        if not isinstance(raw_severity, str):
            raise ValueError(f"finding {index} has unknown severity {raw_severity!r}")
        severity = SEVERITY_ALIASES.get(raw_severity.upper(), raw_severity.upper())
        if severity not in SEVERITIES:
            raise ValueError(f"finding {index} has unknown severity {raw_severity!r}")
        confidence = finding.get("ml_confidence", 1.0)
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(confidence)
            or not 0.0 <= confidence <= 1.0
        ):
            raise ValueError(f"finding {index} has invalid ML confidence")
        if confidence < policy.require_ml_confidence:
            excluded_low_confidence += 1
            continue

        counts[severity] += 1
        score = finding.get("combined_risk_score", finding.get("final_score"))
        if score is not None and (
            isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not math.isfinite(score)
        ):
            raise ValueError(f"finding {index} has an invalid severity score")
        reasons = []
        if score is not None and score >= policy.min_severity_score_block:
            reasons.append(f"risk score {score:g} meets the blocking threshold")
        if reasons:
            blockers.append({"index": index, "rule_id": finding.get("rule_id"), "reasons": reasons})

    if counts["CRITICAL"] > policy.max_critical_allowed:
        blockers.append(
            {
                "rule": "max_critical_allowed",
                "count": counts["CRITICAL"],
                "limit": policy.max_critical_allowed,
            }
        )
    if counts["HIGH"] > policy.max_high_allowed:
        blockers.append(
            {
                "rule": "max_high_allowed",
                "count": counts["HIGH"],
                "limit": policy.max_high_allowed,
            }
        )
    for severity, limit in (
        ("MEDIUM", policy.max_medium_allowed),
        ("LOW", policy.max_low_allowed),
    ):
        if limit is not None and counts[severity] > limit:
            blockers.append(
                {
                    "rule": f"max_{severity.lower()}_allowed",
                    "count": counts[severity],
                    "limit": limit,
                }
            )

    passed = not blockers
    summary = (
        f"{'PASSED' if passed else 'FAILED'}: "
        f"{counts['CRITICAL']} critical, {counts['HIGH']} high; "
        f"{len(blockers)} blocking condition(s)"
    )
    if excluded_low_confidence:
        summary += f"; {excluded_low_confidence} finding(s) below ML confidence threshold"
    if unreachable_ignored:
        summary += f"; {unreachable_ignored} unreachable finding(s) excluded from the gate"
    return {
        "status": "PASSED" if passed else "FAILED",
        "passed": passed,
        "summary": summary,
        "counts": counts,
        "findings_inspected": sum(counts.values()) + excluded_low_confidence,
        "excluded_low_confidence": excluded_low_confidence,
        "unreachable_ignored": unreachable_ignored,
        "blockers": blockers,
        "policy": {
            "max_critical_allowed": policy.max_critical_allowed,
            "max_high_allowed": policy.max_high_allowed,
            "max_medium_allowed": policy.max_medium_allowed,
            "max_low_allowed": policy.max_low_allowed,
            "min_severity_score_block": policy.min_severity_score_block,
            "require_ml_confidence": policy.require_ml_confidence,
        },
    }
