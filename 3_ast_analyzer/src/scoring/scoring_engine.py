"""Combine normalized static and ML risk estimates."""

from __future__ import annotations

import math


class ScoringEngine:
    STATIC_WEIGHT = 0.6
    ML_WEIGHT = 0.4

    @classmethod
    def calculate_score(cls, static_score: float, ml_score: float) -> dict[str, float | str]:
        for name, score in (("static_score", static_score), ("ml_score", ml_score)):
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                raise ValueError(f"{name} must be numeric")
            if not math.isfinite(score) or not 0.0 <= score <= 1.0:
                raise ValueError(f"{name} must be finite and between 0 and 1")
        combined = cls.STATIC_WEIGHT * static_score + cls.ML_WEIGHT * ml_score
        severity = (
            "CRITICAL" if combined >= 0.85
            else "HIGH" if combined >= 0.65
            else "MEDIUM" if combined >= 0.4
            else "LOW"
        )
        return {
            "static_score": float(static_score),
            "ml_score": float(ml_score),
            "combined_risk_score": round(combined, 4),
            "severity": severity,
        }

    @classmethod
    def calculate_hybrid_risk(cls, static_risk_score: float, ml_probability: float | None) -> dict[str, float | str | None]:
        if isinstance(static_risk_score, bool) or not isinstance(static_risk_score, (int, float)):
            raise ValueError("static_risk_score must be numeric")
        if not math.isfinite(static_risk_score) or not 0.0 <= static_risk_score <= 10.0:
            raise ValueError("static_risk_score must be finite and between 0 and 10")
        if ml_probability is None:
            combined = float(static_risk_score)
        else:
            if isinstance(ml_probability, bool) or not isinstance(ml_probability, (int, float)):
                raise ValueError("ml_probability must be numeric or None")
            if not math.isfinite(ml_probability) or not 0.0 <= ml_probability <= 1.0:
                raise ValueError("ml_probability must be finite and between 0 and 1")
            combined = cls.STATIC_WEIGHT * static_risk_score + cls.ML_WEIGHT * (ml_probability * 10.0)
        severity = (
            "CRITICAL" if combined >= 8.5
            else "HIGH" if combined >= 6.5
            else "MEDIUM" if combined >= 4.0
            else "LOW"
        )
        return {
            "static_risk_score": float(static_risk_score),
            "ml_probability": None if ml_probability is None else float(ml_probability),
            "combined_risk_score": round(min(10.0, combined), 2),
            "severity": severity,
        }
