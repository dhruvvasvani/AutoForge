"""Train the AST feature classifier from labeled source-code examples."""

from __future__ import annotations

import argparse
import csv
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.ml.multilingual_features import FEATURE_NAMES, extract_features
from src.ml.preprocess import FeatureStandardizer
from src.parser.multi_lang_parser import MultiLangParser


@dataclass(frozen=True)
class LabeledSource:
    source: str
    label: int
    language: str = "python"
    group_id: str | None = None


def load_ast_dataset(dataset_path: str | Path) -> list[LabeledSource]:
    """Load a JSON array or CSV with source code and binary labels."""
    path = Path(dataset_path)
    if path.suffix.lower() == ".csv":
        try:
            with path.open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream))
        except OSError as error:
            raise ValueError(f"could not read dataset at {path}: {error}") from error
    else:
        try:
            rows = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"could not read dataset at {path}: {error}") from error
    if not isinstance(rows, list) or not rows:
        raise ValueError("dataset must be a non-empty JSON array or CSV")

    examples: list[LabeledSource] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ValueError(f"dataset row {index} must be an object")
        label = _parse_label(row.get("label", row.get("class", row.get("is_vulnerable"))))
        source_column = next(
            (key for key in ("code", "source", "function_code", "vulnerable_function_source") if row.get(key)),
            None,
        )
        if source_column is None:
            raise ValueError(f"dataset row {index} must contain source code")
        source = str(row[source_column]).strip()
        if not source:
            raise ValueError(f"dataset row {index} contains empty source code")
        language = str(row.get("language") or "python").strip().lower()
        group_id = str(row.get("group_id") or f"row:{index}")
        examples.append(LabeledSource(source, label, language, group_id))

        patched_source = row.get("patched_function_source")
        if patched_source and source_column == "vulnerable_function_source":
            examples.append(LabeledSource(str(patched_source).strip(), 0, language, group_id))

    if not examples:
        raise ValueError("dataset contains no usable source examples")
    return examples


def _parse_label(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, str) and value.strip() in {"0", "1"}:
        value = int(value.strip())
    if not isinstance(value, int) or value not in (0, 1):
        raise ValueError("each dataset row must have a 0/1 label")
    return value


def _split_dataset(
    examples: Sequence[LabeledSource], seed: int
) -> tuple[list[LabeledSource], list[LabeledSource], list[LabeledSource]]:
    groups: dict[str, list[LabeledSource]] = {}
    for index, example in enumerate(examples):
        groups.setdefault(example.group_id or f"example:{index}", []).append(example)
    class_groups: dict[int, list[list[LabeledSource]]] = {0: [], 1: []}
    for group in groups.values():
        class_groups[int(any(example.label == 1 for example in group))].append(group)
    if any(len(items) < 3 for items in class_groups.values()):
        raise ValueError("80/10/10 split requires at least 3 independent groups per class")

    rng = random.Random(seed)
    splits: list[list[LabeledSource]] = [[], [], []]
    for items in class_groups.values():
        rng.shuffle(items)
        validation_count = max(1, round(len(items) * 0.1))
        test_count = max(1, round(len(items) * 0.1))
        boundaries = (len(items) - validation_count - test_count, len(items) - test_count)
        for index, group in enumerate(items):
            destination = 0 if index < boundaries[0] else 1 if index < boundaries[1] else 2
            splits[destination].extend(group)
    for name, split in zip(("training", "validation", "test"), splits):
        if {example.label for example in split} != {0, 1}:
            raise ValueError(f"{name} split must contain both labels")
    for split in splits:
        rng.shuffle(split)
    return splits[0], splits[1], splits[2]


def train_ast_classifier(
    dataset_path: str | Path,
    checkpoint_path: str | Path,
    *,
    max_epochs: int = 50,
    patience: int = 7,
    seed: int = 42,
    device: str | None = None,
) -> dict[str, Any]:
    """Train with train-only feature scaling and save an ASTInference checkpoint."""
    if isinstance(max_epochs, bool) or not isinstance(max_epochs, int) or max_epochs < 1:
        raise ValueError("max_epochs must be a positive integer")
    if isinstance(patience, bool) or not isinstance(patience, int) or patience < 1:
        raise ValueError("patience must be a positive integer")

    try:
        import torch
        from src.ml.models import ASTVulnerabilityClassifier
    except ImportError as error:
        raise ImportError("AST training requires PyTorch; install torch") from error

    examples = load_ast_dataset(dataset_path)
    train_examples, validation_examples, test_examples = _split_dataset(examples, seed)
    parser = MultiLangParser()

    def make_features(items: Sequence[LabeledSource]) -> list[list[float]]:
        vectors = []
        for index, example in enumerate(items):
            try:
                parsed = parser.parse_source(
                    example.source,
                    f"sample.{_extension(example.language)}",
                    example.language,
                )
                vectors.append(extract_features(parsed.tree, example.source))
            except (SyntaxError, ValueError, RuntimeError) as error:
                raise ValueError(f"could not parse source example {index}: {error}") from error
        return vectors

    train_vectors = make_features(train_examples)
    validation_vectors = make_features(validation_examples)
    test_vectors = make_features(test_examples)
    standardizer = FeatureStandardizer()
    train_vectors = standardizer.fit_transform(train_vectors)
    validation_vectors = standardizer.transform(validation_vectors)
    test_vectors = standardizer.transform(test_vectors)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    target_device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
    model = ASTVulnerabilityClassifier(len(FEATURE_NAMES)).to(target_device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    train_labels = torch.tensor([item.label for item in train_examples], dtype=torch.float32, device=target_device)
    positive_count = int(train_labels.sum().item())
    negative_count = len(train_labels) - positive_count
    if not positive_count or not negative_count:
        raise ValueError("training split must contain both vulnerability classes")
    sample_weights = torch.where(train_labels > 0, negative_count / positive_count, 1.0)
    criterion = torch.nn.BCELoss(reduction="none")
    x_train = torch.tensor(train_vectors, dtype=torch.float32, device=target_device)
    x_validation = torch.tensor(validation_vectors, dtype=torch.float32, device=target_device)
    y_validation = torch.tensor([item.label for item in validation_examples], dtype=torch.float32, device=target_device)

    destination = Path(checkpoint_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    best_loss = float("inf")
    best_epoch = 0
    stale_epochs = 0
    history: list[dict[str, float]] = []
    batch_size = min(64, len(train_examples))
    for epoch in range(1, max_epochs + 1):
        model.train()
        order = torch.randperm(len(train_examples), device=target_device)
        epoch_losses = []
        for start in range(0, len(train_examples), batch_size):
            indices = order[start : start + batch_size]
            optimizer.zero_grad(set_to_none=True)
            losses = criterion(model(x_train[indices]).squeeze(1), train_labels[indices])
            loss = (losses * sample_weights[indices]).mean()
            loss.backward()
            optimizer.step()
            epoch_losses.append(float(loss.detach().cpu()))
        model.eval()
        with torch.no_grad():
            validation_loss = float(
                criterion(model(x_validation).squeeze(1), y_validation).mean().cpu()
            )
        history.append({
            "epoch": float(epoch),
            "training_loss": sum(epoch_losses) / len(epoch_losses),
            "validation_loss": validation_loss,
        })
        print(f"Epoch {epoch}/{max_epochs}: validation_loss={validation_loss:.4f}", flush=True)
        if validation_loss < best_loss:
            best_loss, best_epoch, stale_epochs = validation_loss, epoch, 0
            torch.save(
                {
                    "state_dict": model.state_dict(),
                    "input_dim": len(FEATURE_NAMES),
                    "feature_names": list(FEATURE_NAMES),
                    "means": standardizer.means,
                    "scales": standardizer.scales,
                    "best_epoch": best_epoch,
                    "best_validation_loss": best_loss,
                },
                destination,
            )
        else:
            stale_epochs += 1
            if stale_epochs >= patience:
                break

    checkpoint = torch.load(destination, map_location=target_device, weights_only=True)
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    x_test = torch.tensor(test_vectors, dtype=torch.float32, device=target_device)
    y_test = torch.tensor([item.label for item in test_examples], dtype=torch.float32, device=target_device)
    with torch.no_grad():
        predictions = model(x_test).squeeze(1) >= 0.5
    true_positive = int((predictions & (y_test >= 0.5)).sum().item())
    true_negative = int((~predictions & (y_test < 0.5)).sum().item())
    false_positive = int((predictions & (y_test < 0.5)).sum().item())
    false_negative = int((~predictions & (y_test >= 0.5)).sum().item())
    precision = true_positive / max(1, true_positive + false_positive)
    recall = true_positive / max(1, true_positive + false_negative)
    metrics = {
        "accuracy": (true_positive + true_negative) / len(test_examples),
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / max(1e-12, precision + recall),
    }
    return {
        "checkpoint": str(destination),
        "best_epoch": best_epoch,
        "best_validation_loss": best_loss,
        "test_metrics": metrics,
        "split_sizes": {
            "train": len(train_examples),
            "validation": len(validation_examples),
            "test": len(test_examples),
        },
        "history": history,
    }


def _extension(language: str) -> str:
    extensions = {
        "python": "py",
        "py": "py",
        "javascript": "js",
        "js": "js",
        "java": "java",
    }
    try:
        return extensions[language]
    except KeyError as error:
        raise ValueError(f"unsupported language: {language}") from error


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the AutoForge AST vulnerability classifier")
    parser.add_argument("--dataset", required=True, help="labeled JSON array or CSV source dataset")
    parser.add_argument("--checkpoint", default="src/ml/ast_classifier.pt")
    parser.add_argument("--max-epochs", type=int, default=50)
    parser.add_argument("--patience", type=int, default=7)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--device", default=None, help="optional torch device, e.g. cpu or cuda")
    arguments = parser.parse_args()
    print(json.dumps(train_ast_classifier(
        arguments.dataset,
        arguments.checkpoint,
        max_epochs=arguments.max_epochs,
        patience=arguments.patience,
        seed=arguments.seed,
        device=arguments.device,
    ), indent=2))


if __name__ == "__main__":
    main()