"""Apply reachability and exposure context to a rule's base risk."""

from __future__ import annotations

import math
from typing import Any

from .rule_weights import get_rule_weight


class RiskAggregator:
    REACHABILITY_MULTIPLIERS = {"direct": 1.0, "interprocedural": 0.85, "unreachable": 0.4}
    SANITIZER_MULTIPLIER = 0.5

    @staticmethod
    def severity(score: float) -> str:
        if score >= 8.5:
            return "CRITICAL"
        if score >= 6.5:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"

    @classmethod
    def aggregate(
        cls,
        rule_id: str,
        *,
        reachability: str = "direct",
        exposure_factor: float = 1.0,
        partial_sanitizer: bool = False,
        base_score: float | None = None,
    ) -> dict[str, Any]:
        if reachability not in cls.REACHABILITY_MULTIPLIERS:
            raise ValueError(f"Unknown reachability category: {reachability}")
        if (
            isinstance(exposure_factor, bool)
            or not isinstance(exposure_factor, (int, float))
            or not math.isfinite(exposure_factor)
            or exposure_factor < 0
        ):
            raise ValueError("exposure_factor must be a finite non-negative number")
        weight = get_rule_weight(rule_id) if base_score is None else base_score
        if isinstance(weight, bool) or not isinstance(weight, (int, float)) or not math.isfinite(weight):
            raise ValueError("base_score must be finite numeric")
        multiplier = cls.REACHABILITY_MULTIPLIERS[reachability]
        if partial_sanitizer:
            multiplier *= cls.SANITIZER_MULTIPLIER
        final_score = round(min(10.0, max(0.0, float(weight) * multiplier * exposure_factor)), 2)
        return {
            "rule_id": rule_id,
            "base_score": float(weight),
            "reachability_multiplier": multiplier,
            "exposure_factor": float(exposure_factor),
            "final_score": final_score,
            "severity": cls.severity(final_score),
        }
