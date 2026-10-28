from __future__ import annotations

import argparse
import ast
import json
import math
import os
import sys
from pathlib import Path
from typing import Any

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src.ml.cpg_training import load_cpg_dataset, train_cpg_gnn


_LABELS = {
    "FALSE_POSITIVE": 0,
    "CONFIRMED_VULNERABILITY": 1,
}


def build_training_dataset(
    feedback_path: Path,
    baseline_path: Path,
    output_path: Path,
    *,
    min_feedback: int,
) -> dict[str, Any]:
    try:
        feedback_rows: Any = json.loads(feedback_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"could not read feedback export: {error}") from error
    if not isinstance(feedback_rows, list):
        raise ValueError("feedback export must be a JSON array")

    approved_examples = []
    feedback_ids: list[int] = []
    skipped_invalid = 0
    for index, row in enumerate(feedback_rows):
        if not isinstance(row, dict):
            raise ValueError(f"feedback row {index} must be an object")
        if row.get("reviewStatus") != "APPROVED":
            continue
        feedback_id = row.get("id")
        if isinstance(feedback_id, bool) or not isinstance(feedback_id, int) or feedback_id < 1:
            raise ValueError(f"approved feedback row {index} must have a positive integer id")
        label = _LABELS.get(row.get("label"))
        snippet = row.get("sourceSnippet")
        if label is None or not isinstance(snippet, str) or not snippet.strip():
            raise ValueError(f"approved feedback row {index} has invalid label or source")
        try:
            ast.parse(snippet)
        except SyntaxError:
            skipped_invalid += 1
            continue
        approved_examples.append({"code": snippet, "label": label})
        feedback_ids.append(feedback_id)

    if len(approved_examples) < min_feedback:
        raise ValueError(
            f"only {len(approved_examples)} syntax-valid approved examples; "
            f"at least {min_feedback} are required"
        )
    labels = {row["label"] for row in approved_examples}
    if labels != {0, 1}:
        raise ValueError("approved feedback must include both false-positive and confirmed classes")

    baseline = load_cpg_dataset(baseline_path)
    if not baseline:
        raise ValueError("baseline dataset is empty")
    combined = [
        {"code": example.source, "label": example.label}
        for example in baseline
    ] + approved_examples
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(combined, ensure_ascii=False), encoding="utf-8")
    return {
        "baseline_examples": len(baseline),
        "approved_feedback_examples": len(approved_examples),
        "skipped_invalid_examples": skipped_invalid,
        "combined_examples": len(combined),
        "feedback_ids": feedback_ids,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train a versioned CPG-GNN candidate from approved feedback; do not activate it automatically."
    )
    parser.add_argument("--feedback", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--min-feedback", type=int, default=500)
    parser.add_argument("--model-name", default="microsoft/codebert-base")
    parser.add_argument("--max-epochs", type=int, default=50)
    parser.add_argument("--device", default=None)
    arguments = parser.parse_args()
    if arguments.min_feedback < 1:
        parser.error("--min-feedback must be positive")
    dataset_path = arguments.candidate.with_suffix(".training.json")
    temporary_candidate = arguments.candidate.with_name(
        f".{arguments.candidate.name}.{os.getpid()}.candidate"
    )
    try:
        arguments.candidate.parent.mkdir(parents=True, exist_ok=True)
        counts = build_training_dataset(
            arguments.feedback,
            arguments.baseline,
            dataset_path,
            min_feedback=arguments.min_feedback,
        )
        result = train_cpg_gnn(
            dataset_path,
            temporary_candidate,
            model_name=arguments.model_name,
            max_epochs=arguments.max_epochs,
            device=arguments.device,
        )
        validation_loss = result.get("best_validation_loss")
        if (
            isinstance(validation_loss, bool)
            or not isinstance(validation_loss, (int, float))
            or not math.isfinite(validation_loss)
        ):
            raise ValueError("trainer did not produce a finite best validation loss")
        if not temporary_candidate.is_file() or temporary_candidate.stat().st_size == 0:
            raise ValueError("trainer did not produce a candidate checkpoint")
        os.replace(temporary_candidate, arguments.candidate)
    except (OSError, ValueError, RuntimeError, ImportError) as error:
        parser.error(str(error))
    finally:
        dataset_path.unlink(missing_ok=True)
        temporary_candidate.unlink(missing_ok=True)
    print(json.dumps({"dataset": counts, "training": result}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
