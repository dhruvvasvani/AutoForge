"""Threshold-gated, tenant-isolated retraining using the existing CPG trainer."""

from __future__ import annotations

import json
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.ml.cpg_training import load_cpg_dataset
from src.multitenancy.tenant_manager import validate_tenant_id
from .feedback_collector import FeedbackCollector

Trainer = Callable[[str | Path, str | Path], Any]


@dataclass(frozen=True)
class RetrainResult:
    tenant_id: str
    feedback_count: int
    checkpoint_path: Path
    trainer_result: Any


class RetrainTrigger:
    def __init__(
        self,
        feedback_collector: FeedbackCollector,
        model_root: str | Path,
        *,
        baseline_dataset_path: str | Path | None = None,
        min_feedback: int = 100,
        trainer: Trainer,
    ) -> None:
        if isinstance(min_feedback, bool) or not isinstance(min_feedback, int) or min_feedback < 1:
            raise ValueError("min_feedback must be a positive integer")
        if not callable(trainer):
            raise TypeError("trainer must be callable")
        self.feedback_collector = feedback_collector
        self.model_root = Path(model_root).resolve()
        self.baseline_dataset_path = Path(
            baseline_dataset_path
            if baseline_dataset_path is not None
            else Path(__file__).resolve().parents[2] / "data" / "pycode_vul" / "train.csv"
        )
        self.min_feedback = min_feedback
        self.trainer = trainer
        self._lock = threading.Lock()

    def maybe_retrain(self, tenant_id: str) -> RetrainResult | None:
        validate_tenant_id(tenant_id)
        with self._lock:
            feedback = self.feedback_collector.pending_training_examples(
                tenant_id, limit=max(self.min_feedback, 1)
            )
            if len(feedback) < self.min_feedback:
                return None
            if not self.baseline_dataset_path.is_file():
                raise FileNotFoundError(
                    f"baseline training dataset does not exist: {self.baseline_dataset_path}"
                )

            baseline = load_cpg_dataset(self.baseline_dataset_path)
            examples = [
                {"code": item.source, "label": item.label}
                for item in baseline
            ]
            examples.extend(entry.training_example for entry in feedback)
            tenant_model_dir = (self.model_root / tenant_id).resolve()
            if tenant_model_dir.parent != self.model_root:
                raise ValueError("tenant model directory must remain inside the model root")
            tenant_model_dir.mkdir(parents=True, exist_ok=True)
            checkpoint_path = tenant_model_dir / "cpg_gnn.pt"

            with tempfile.TemporaryDirectory(prefix="autoforge-retrain_") as temporary_dir:
                dataset_path = Path(temporary_dir) / "training.json"
                dataset_path.write_text(
                    json.dumps(examples, ensure_ascii=False),
                    encoding="utf-8",
                )
                trainer_result = self.trainer(dataset_path, checkpoint_path)

            self.feedback_collector.mark_trained(
                tenant_id,
                [entry.feedback_id for entry in feedback],
            )
            return RetrainResult(
                tenant_id=tenant_id,
                feedback_count=len(feedback),
                checkpoint_path=checkpoint_path,
                trainer_result=trainer_result,
            )
