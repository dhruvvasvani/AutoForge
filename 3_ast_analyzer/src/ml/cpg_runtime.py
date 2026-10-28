"""Optional production loader for the configured CPG-GNN checkpoint."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from .codebert_encoder import CodeBERTEncoder
from .cpg_inference import predict_file_confidences
from .cpg_training import load_cpg_gnn


@lru_cache(maxsize=2)
def _load_runtime(
    checkpoint_path: str,
    model_name: str,
    device: str | None,
    checkpoint_mtime_ns: int,
    checkpoint_size: int,
) -> tuple[Any, CodeBERTEncoder]:
    del checkpoint_mtime_ns, checkpoint_size
    checkpoint = Path(checkpoint_path).expanduser()
    if not checkpoint.is_file():
        raise FileNotFoundError(f"CPG_GNN_CHECKPOINT does not exist: {checkpoint}")
    model = load_cpg_gnn(checkpoint, device=device)
    encoder = CodeBERTEncoder(model_name=model_name, device=device)
    if encoder.model.config.hidden_size != model.input_projection.in_features:
        raise ValueError(
            "CodeBERT embedding size does not match the configured CPG-GNN checkpoint"
        )
    return model, encoder


def configured_cpg_predictions(
    sources: dict[str, str],
) -> tuple[dict[str, float], dict[str, Any]]:
    """Run local inference only when an explicit checkpoint path is configured."""
    checkpoint = os.getenv("CPG_GNN_CHECKPOINT", "").strip()
    if not checkpoint:
        return {}, {
            "name": "CPG GNN",
            "available": False,
            "status": "not_configured",
            "confidence": None,
            "reason": "Set CPG_GNN_CHECKPOINT to enable local CPG-GNN inference.",
        }
    model_name = os.getenv("CPG_GNN_MODEL_NAME", "microsoft/codebert-base").strip()
    device = os.getenv("CPG_GNN_DEVICE") or None
    checkpoint_file = Path(checkpoint).expanduser()
    if not checkpoint_file.is_file():
        raise FileNotFoundError(f"CPG_GNN_CHECKPOINT does not exist: {checkpoint_file}")
    checkpoint_stat = checkpoint_file.stat()
    model, encoder = _load_runtime(
        str(checkpoint_file),
        model_name,
        device,
        checkpoint_stat.st_mtime_ns,
        checkpoint_stat.st_size,
    )
    predictions = predict_file_confidences(sources, model, encoder)
    return predictions, {
        "name": "CPG GNN",
        "available": True,
        "status": "complete",
        "model_name": model_name,
        "checkpoint": Path(checkpoint).name,
        "files_scored": len(predictions),
        "confidence": None,
        "threshold": 0.5,
        "interpretation": "File-level graph probability; informational, not a finding verdict.",
    }
