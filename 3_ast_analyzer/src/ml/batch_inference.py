"""Batch inference using the vulnerability classifier."""

from __future__ import annotations

from collections.abc import Sequence

import torch

from .models import ASTVulnerabilityClassifier


class BatchInference:
    def __init__(self, model: ASTVulnerabilityClassifier) -> None:
        self.model = model.eval()

    def predict(self, feature_vectors: Sequence[Sequence[float]]) -> list[float]:
        if not feature_vectors:
            return []
        tensor = torch.as_tensor(feature_vectors, dtype=torch.float32)
        if tensor.ndim != 2 or not torch.isfinite(tensor).all():
            raise ValueError("feature_vectors must be a finite two-dimensional matrix")
        expected = self.model.layers[0].in_features
        if tensor.shape[1] != expected:
            raise ValueError(f"Expected {expected} features, got {tensor.shape[1]}")
        with torch.no_grad():
            return self.model(tensor).squeeze(1).tolist()
