"""Random-forest filter for experiments with AST-derived feature records."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Mapping, Sequence

from sklearn.ensemble import RandomForestClassifier

FEATURE_KEYS = (
    "cyclomatic_complexity",
    "max_nesting_depth",
    "sink_distance",
    "user_input_tainted",
    "sanitizer_present",
)


class ASTNoiseFilter:
    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 12,
        random_state: int = 42,
    ) -> None:
        if isinstance(n_estimators, bool) or not isinstance(n_estimators, int) or n_estimators < 1:
            raise ValueError("n_estimators must be a positive integer")
        if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 1:
            raise ValueError("max_depth must be a positive integer")
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            criterion="gini",
            random_state=random_state,
        )
        self.is_trained = False

    @staticmethod
    def extract_features(sample: Mapping[str, Any]) -> list[float]:
        if not isinstance(sample, Mapping):
            raise TypeError("each sample must be a mapping")
        features: list[float] = []
        for key in FEATURE_KEYS:
            value = sample.get(
                key,
                False if key in {"user_input_tainted", "sanitizer_present"} else None,
            )
            if key in {"user_input_tainted", "sanitizer_present"}:
                if isinstance(value, bool):
                    features.append(float(value))
                elif isinstance(value, (int, float)) and value in (0, 1):
                    features.append(float(value))
                else:
                    raise ValueError(f"{key} must be a boolean or 0/1")
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{key} must be numeric")
            if not math.isfinite(value):
                raise ValueError(f"{key} must be finite")
            features.append(float(value))
        return features

    def train(self, dataset_path: str | Path) -> None:
        path = Path(dataset_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list) or not data:
            raise ValueError("dataset must be a non-empty JSON array")

        features: list[list[float]] = []
        labels: list[int] = []
        for index, row in enumerate(data):
            if not isinstance(row, Mapping):
                raise ValueError(f"dataset row {index} must be an object")
            label = row.get("is_real_vulnerability")
            if isinstance(label, bool) or not isinstance(label, int) or label not in (0, 1):
                raise ValueError(f"dataset row {index} must have a 0/1 vulnerability label")
            features.append(self.extract_features(row))
            labels.append(label)

        self.model.fit(features, labels)
        self.is_trained = True

    def predict_confidence(self, sample: Mapping[str, Any]) -> float:
        if not self.is_trained:
            return 1.0
        features = self.extract_features(sample)
        probabilities = self.model.predict_proba([features])[0]
        positive_index = next(
            (index for index, label in enumerate(self.model.classes_) if label == 1),
            None,
        )
        return round(float(probabilities[positive_index]), 4) if positive_index is not None else 0.0

    def filter_findings(
        self,
        findings: Sequence[Mapping[str, Any]],
        threshold: float = 0.5,
    ) -> list[dict[str, Any]]:
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
            raise ValueError("threshold must be a finite number between 0 and 1")
        if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be a finite number between 0 and 1")

        filtered: list[dict[str, Any]] = []
        for finding in findings:
            if not isinstance(finding, Mapping):
                raise TypeError("each finding must be a mapping")
            confidence = self.predict_confidence(finding)
            if confidence >= threshold:
                filtered.append({**finding, "ml_confidence": confidence})
        return filtered
