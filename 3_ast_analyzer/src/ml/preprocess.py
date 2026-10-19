"""Feature-vector validation and standardization."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence


@dataclass
class FeatureStandardizer:
    means: list[float] | None = None
    scales: list[float] | None = None

    def fit(self, vectors: Sequence[Sequence[float]]) -> "FeatureStandardizer":
        matrix = self._validate(vectors)
        width = len(matrix[0])
        rows = len(matrix)
        means = [sum(row[column] for row in matrix) / rows for column in range(width)]
        variances = [
            sum((row[column] - means[column]) ** 2 for row in matrix) / rows
            for column in range(width)
        ]
        self.means = means
        self.scales = [math.sqrt(variance) or 1.0 for variance in variances]
        return self

    def transform(self, vectors: Sequence[Sequence[float]]) -> list[list[float]]:
        if self.means is None or self.scales is None:
            raise RuntimeError("FeatureStandardizer must be fitted before transform")
        matrix = self._validate(vectors)
        if any(len(row) != len(self.means) for row in matrix):
            raise ValueError("feature width differs from fitted width")
        return [
            [(value - mean) / scale for value, mean, scale in zip(row, self.means, self.scales)]
            for row in matrix
        ]

    def fit_transform(self, vectors: Sequence[Sequence[float]]) -> list[list[float]]:
        return self.fit(vectors).transform(vectors)

    @staticmethod
    def _validate(vectors: Sequence[Sequence[float]]) -> list[list[float]]:
        if not vectors:
            raise ValueError("at least one feature vector is required")
        matrix: list[list[float]] = []
        width: int | None = None
        for vector in vectors:
            row: list[float] = []
            for value in vector:
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                    raise ValueError("features must be finite numeric values")
                row.append(float(value))
            if width is None:
                width = len(row)
                if width == 0:
                    raise ValueError("feature vectors must not be empty")
            elif len(row) != width:
                raise ValueError("feature vectors must have equal width")
            matrix.append(row)
        return matrix
