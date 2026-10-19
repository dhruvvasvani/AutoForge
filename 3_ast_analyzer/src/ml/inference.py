"""Load a trained AST classifier checkpoint and run predictions."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

import torch

from .batch_inference import BatchInference
from .models import ASTVulnerabilityClassifier
from .preprocess import FeatureStandardizer


class ASTInference:
    def __init__(self, model: ASTVulnerabilityClassifier, standardizer: FeatureStandardizer | None = None):
        self.model = model.eval()
        self.standardizer = standardizer
        self.batch = BatchInference(self.model)

    @classmethod
    def from_checkpoint(cls, checkpoint_path: str | Path) -> "ASTInference":
        path = Path(checkpoint_path)
        if not path.is_file():
            raise FileNotFoundError(path)
        checkpoint = torch.load(path, map_location="cpu", weights_only=True)
        if not isinstance(checkpoint, dict) or "state_dict" not in checkpoint or "input_dim" not in checkpoint:
            raise ValueError("checkpoint must contain input_dim and state_dict")
        input_dim = checkpoint["input_dim"]
        if isinstance(input_dim, bool) or not isinstance(input_dim, int) or input_dim <= 0:
            raise ValueError("checkpoint input_dim must be a positive integer")
        model = ASTVulnerabilityClassifier(input_dim)
        model.load_state_dict(checkpoint["state_dict"], strict=True)
        standardizer = None
        if "means" in checkpoint or "scales" in checkpoint:
            means, scales = checkpoint.get("means"), checkpoint.get("scales")
            if not isinstance(means, list) or not isinstance(scales, list):
                raise ValueError("checkpoint means and scales must both be lists")
            if len(means) != input_dim or len(scales) != input_dim:
                raise ValueError("checkpoint scaler dimensions do not match input_dim")
            standardizer = FeatureStandardizer(means, scales)
        return cls(model, standardizer)

    def predict(self, feature_vector: Sequence[float]) -> float:
        return self.predict_batch([feature_vector])[0]

    def predict_batch(self, feature_vectors: Sequence[Sequence[float]]) -> list[float]:
        vectors = list(feature_vectors)
        if self.standardizer is not None and vectors:
            vectors = self.standardizer.transform(vectors)
        return self.batch.predict(vectors)
