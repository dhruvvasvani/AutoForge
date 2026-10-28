"""Dataset preparation and early-stopped training for the Week 7 CPG GNN."""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import logging
import random
import sys
import tempfile
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .cpg_builder import EDGE_TYPES, build_cpg

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class LabeledCPG:
    source: str
    label: int
    group_id: str | None = None


@dataclass(frozen=True)
class EncodedCPG:
    node_start: int
    node_count: int
    edge_start: int
    edge_count: int


def load_cpg_dataset(dataset_path: str | Path) -> list[LabeledCPG]:
    path = Path(dataset_path)
    if path.suffix.lower() == ".csv":
        return _load_pycode_vul_csv(path)
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"could not read CPG dataset at {path}: {error}") from error
    if not isinstance(rows, list) or not rows:
        raise ValueError("dataset must be a non-empty JSON array")

    examples = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"dataset row {index} must be an object")
        source = row.get("code", row.get("source"))
        label = row.get("label", row.get("is_vulnerable"))
        if not isinstance(source, str) or not source.strip():
            raise ValueError(f"dataset row {index} must contain non-empty code or source")
        if isinstance(label, bool) or not isinstance(label, int) or label not in (0, 1):
            raise ValueError(f"dataset row {index} must have a 0/1 label")
        try:
            _validate_python(source)
        except SyntaxError as error:
            raise ValueError(f"dataset row {index} contains invalid Python: {error}") from error
        examples.append(LabeledCPG(source, label))
    return examples


def _load_pycode_vul_csv(path: Path) -> list[LabeledCPG]:
    examples: list[LabeledCPG] = []
    empty_sources = 0
    duplicate_sources = 0
    invalid_sources = 0
    try:
        stream = path.open(encoding="utf-8-sig", newline="")
    except OSError as error:
        raise ValueError(f"could not read PyCode-Vul CSV at {path}: {error}") from error

    with stream:
        csv.field_size_limit(sys.maxsize)
        reader = csv.DictReader(stream)
        columns = set(reader.fieldnames or ())
        label_column = "label" if "label" in columns else "class" if "class" in columns else None
        source_column = (
            "vulnerable_function_source"
            if "vulnerable_function_source" in columns
            else "function_code"
            if "function_code" in columns
            else None
        )
        if label_column is None or source_column is None:
            raise ValueError(
                "PyCode-Vul CSV must include label/class and "
                "vulnerable_function_source/function_code columns"
            )
        for row_number, row in enumerate(reader, start=2):
            if row_number % 1000 == 2:
                _LOGGER.info("Parsing %s: CSV row %d", path.name, row_number)
            raw_label = (row.get(label_column) or "").strip()
            if raw_label not in {"0", "1"}:
                raise ValueError(f"PyCode-Vul CSV row {row_number} has an invalid label")
            label = int(raw_label)
            group_id = f"{path.name}:{row_number}"
            sources = [(row.get(source_column) or "", label)]
            if (
                source_column == "vulnerable_function_source"
                and "patched_function_source" in columns
            ):
                sources.append((row.get("patched_function_source") or "", 0))
            seen_sources: set[str] = set()
            for source, source_label in sources:
                normalized_source = source.strip()
                if not normalized_source:
                    empty_sources += 1
                    continue
                if normalized_source in seen_sources:
                    duplicate_sources += 1
                    continue
                seen_sources.add(normalized_source)
                try:
                    _validate_python(normalized_source)
                except SyntaxError:
                    invalid_sources += 1
                    continue
                examples.append(LabeledCPG(normalized_source, source_label, group_id))

    if not examples:
        raise ValueError("PyCode-Vul CSV contains no usable function examples")
    if empty_sources or duplicate_sources or invalid_sources:
        _LOGGER.warning(
            "%s: skipped %d empty code cells, %d duplicate source/patch pairs, "
            "and %d syntax-invalid functions",
            path,
            empty_sources,
            duplicate_sources,
            invalid_sources,
        )
    return examples


def _validate_python(source: str) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        ast.parse(source)


def stratified_split(
    examples: Sequence[LabeledCPG],
    seed: int = 42,
) -> tuple[list[LabeledCPG], list[LabeledCPG], list[LabeledCPG]]:
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    parent: dict[tuple[str, str | int], tuple[str, str | int]] = {}
    source_owner: dict[bytes, tuple[str, str | int]] = {}

    def find(key: tuple[str, str | int]) -> tuple[str, str | int]:
        root = key
        while parent[root] != root:
            root = parent[root]
        while parent[key] != key:
            next_key = parent[key]
            parent[key] = root
            key = next_key
        return root

    def union(left: tuple[str, str | int], right: tuple[str, str | int]) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    example_keys = []
    for index, example in enumerate(examples):
        key = (
            ("group", example.group_id)
            if example.group_id is not None
            else ("example", index)
        )
        parent.setdefault(key, key)
        example_keys.append(key)
        source_digest = hashlib.sha256(example.source.strip().encode("utf-8")).digest()
        previous_key = source_owner.setdefault(source_digest, key)
        union(key, previous_key)

    grouped: dict[tuple[str, str | int], list[LabeledCPG]] = {}
    for key, example in zip(example_keys, examples):
        grouped.setdefault(find(key), []).append(example)

    groups: dict[int, list[list[LabeledCPG]]] = {0: [], 1: []}
    for group in grouped.values():
        group_label = int(any(example.label == 1 for example in group))
        groups[group_label].append(group)
    if any(len(group) < 3 for group in groups.values()):
        raise ValueError("stratified 80/10/10 split requires at least 3 examples per class")

    rng = random.Random(seed)
    train: list[LabeledCPG] = []
    validation: list[LabeledCPG] = []
    test: list[LabeledCPG] = []
    for group in groups.values():
        rng.shuffle(group)
        validation_count = max(1, round(len(group) * 0.1))
        test_count = max(1, round(len(group) * 0.1))
        validation.extend(example for bundle in group[:validation_count] for example in bundle)
        test.extend(
            example
            for bundle in group[validation_count : validation_count + test_count]
            for example in bundle
        )
        train.extend(
            example
            for bundle in group[validation_count + test_count :]
            for example in bundle
        )
    rng.shuffle(train)
    rng.shuffle(validation)
    rng.shuffle(test)
    return train, validation, test


def train_cpg_gnn(
    dataset_path: str | Path,
    checkpoint_path: str | Path,
    *,
    test_dataset_path: str | Path | None = None,
    model_name: str = "microsoft/codebert-base",
    batch_size: int = 32,
    max_epochs: int = 50,
    patience: int = 7,
    seed: int = 42,
    device: str | None = None,
) -> dict[str, Any]:
    """Train and save the best validation-loss checkpoint.

    Input may be a JSON array of Python ``code``/``source`` and binary
    ``label``/``is_vulnerable`` fields, or the PyCode-Vul train CSV. A separate
    held-out CSV can be supplied to preserve its official test split. This
    function does not download or normalize external datasets.
    """
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size != 32:
        raise ValueError("Week 7 training uses a batch size of 32")
    if isinstance(max_epochs, bool) or not isinstance(max_epochs, int) or not 1 <= max_epochs <= 50:
        raise ValueError("max_epochs must be between 1 and 50")
    if isinstance(patience, bool) or not isinstance(patience, int) or patience != 7:
        raise ValueError("Week 7 early stopping uses a patience of 7")

    try:
        import torch
        from .codebert_encoder import CodeBERTEncoder
        from .cpg_gnn import CPGGNN
    except ImportError as error:
        raise ImportError(
            "GNN training requires torch and transformers; install "
            "3_ast_analyzer\\requirements.txt"
        ) from error

    examples = load_cpg_dataset(dataset_path)
    train_examples, validation_examples, test_examples = stratified_split(examples, seed)
    if test_dataset_path is not None:
        train_examples.extend(test_examples)
        test_examples = load_cpg_dataset(test_dataset_path)
        _reject_held_out_overlap(train_examples + validation_examples, test_examples)
    encoder = CodeBERTEncoder(model_name=model_name, batch_size=batch_size, device=device)
    all_examples = train_examples + validation_examples + test_examples
    with tempfile.TemporaryDirectory(prefix="autoforge_cpg_features_") as cache_directory:
        feature_store, edge_store, encoded = _encode_to_cache(
            all_examples,
            encoder,
            Path(cache_directory),
        )
        train_data = [(example, encoded[id(example)]) for example in train_examples]
        validation_data = [
            (example, encoded[id(example)]) for example in validation_examples
        ]
        test_data = [(example, encoded[id(example)]) for example in test_examples]
        try:
            return _fit_gnn(
                torch,
                CPGGNN,
                model_name,
                encoder.model.config.hidden_size,
                train_data,
                validation_data,
                test_data,
                feature_store,
                edge_store,
                Path(checkpoint_path),
                batch_size,
                max_epochs,
                patience,
                seed,
                device,
            )
        finally:
            feature_store._mmap.close()
            if hasattr(edge_store, "_mmap"):
                edge_store._mmap.close()


def _encode_to_cache(
    examples: Sequence[LabeledCPG],
    encoder: Any,
    cache_directory: Path,
) -> tuple[Any, Any, dict[int, EncodedCPG]]:
    import numpy as np

    hidden_size = encoder.model.config.hidden_size
    feature_path = cache_directory / "node_embeddings.float16"
    edge_path = cache_directory / "graph_edges.bin"
    edge_dtype = np.dtype(
        [("source", "<i4"), ("target", "<i4"), ("kind", "u1")],
        align=False,
    )
    encoded: dict[int, EncodedCPG] = {}
    node_offset = 0
    edge_offset = 0
    with feature_path.open("wb") as feature_stream, edge_path.open("wb") as edge_stream:
        for example_offset in range(0, len(examples), 32):
            example_batch = examples[example_offset : example_offset + 32]
            graphs = [build_cpg(example.source, label=example.label) for example in example_batch]
            feature_batch = encoder.encode(graphs)
            if len(feature_batch) != len(example_batch):
                raise ValueError("CodeBERT did not return one feature matrix per graph")
            for example, graph, features in zip(example_batch, graphs, feature_batch):
                node_count = len(graph.nodes)
                if features.shape != (node_count, hidden_size):
                    raise ValueError("CodeBERT output does not match CPG node/feature dimensions")
                features.numpy().astype(np.float16, copy=False).tofile(feature_stream)
                edge_array = np.empty(len(graph.edges), dtype=edge_dtype)
                if graph.edges:
                    edge_array["source"] = [source for source, _, _ in graph.edges]
                    edge_array["target"] = [target for _, target, _ in graph.edges]
                    edge_array["kind"] = [
                        EDGE_TYPES[kind] for _, _, kind in graph.edges
                    ]
                    edge_array.tofile(edge_stream)
                encoded[id(example)] = EncodedCPG(
                    node_start=node_offset,
                    node_count=node_count,
                    edge_start=edge_offset,
                    edge_count=len(graph.edges),
                )
                node_offset += node_count
                edge_offset += len(graph.edges)
            del graphs, feature_batch
            if example_offset % 512 == 0:
                print(
                    f"Encoded CodeBERT features for "
                    f"{min(example_offset + len(example_batch), len(examples))}/{len(examples)} graphs",
                    flush=True,
                )

    if node_offset == 0:
        raise ValueError("dataset graphs contain no nodes")
    feature_store = np.memmap(
        feature_path,
        mode="r",
        dtype=np.float16,
        shape=(node_offset, hidden_size),
    )
    edge_store = (
        np.memmap(edge_path, mode="r", dtype=edge_dtype, shape=(edge_offset,))
        if edge_offset
        else np.empty((0,), dtype=edge_dtype)
    )
    return feature_store, edge_store, encoded


def _fit_gnn(
    torch: Any,
    model_class: Any,
    model_name: str,
    input_dim: int,
    train_data: Sequence[tuple[LabeledCPG, EncodedCPG]],
    validation_data: Sequence[tuple[LabeledCPG, EncodedCPG]],
    test_data: Sequence[tuple[LabeledCPG, EncodedCPG]],
    feature_store: Any,
    edge_store: Any,
    checkpoint: Path,
    batch_size: int,
    max_epochs: int,
    patience: int,
    seed: int,
    device: str | None,
) -> dict[str, Any]:
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    target_device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
    model = model_class(input_dim=input_dim).to(target_device)
    positives = sum(example.label for example, _ in train_data)
    negatives = len(train_data) - positives
    if positives == 0 or negatives == 0:
        raise ValueError("training split must contain both vulnerability classes")
    criterion = torch.nn.BCEWithLogitsLoss(
        pos_weight=torch.tensor([negatives / positives], device=target_device)
    )
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    batcher = lambda batch, target: _batch(batch, target, feature_store, edge_store)

    best_loss = float("inf")
    best_epoch = 0
    stale_epochs = 0
    history: list[dict[str, float]] = []
    for epoch in range(1, max_epochs + 1):
        model.train()
        epoch_losses = []
        shuffled = list(train_data)
        random.Random(seed + epoch).shuffle(shuffled)
        for offset in range(0, len(shuffled), batch_size):
            batch = shuffled[offset : offset + batch_size]
            node_features, edge_index, edge_type, graph_batch, labels = batcher(
                batch, target_device
            )
            optimizer.zero_grad(set_to_none=True)
            logits = model(node_features, edge_index, edge_type, graph_batch)
            loss = criterion(logits, labels)
            loss.backward()
            optimizer.step()
            epoch_losses.append(float(loss.detach().cpu()))

        validation_metrics = _evaluate(
            model, validation_data, criterion, target_device, batcher
        )
        history.append(
            {
                "epoch": float(epoch),
                "training_loss": sum(epoch_losses) / len(epoch_losses),
                "validation_loss": validation_metrics["loss"],
                "validation_accuracy": validation_metrics["accuracy"],
                "validation_precision": validation_metrics["precision"],
                "validation_recall": validation_metrics["recall"],
                "validation_f1": validation_metrics["f1"],
            }
        )
        print(
            f"Epoch {epoch}/{max_epochs}: "
            f"train_loss={history[-1]['training_loss']:.4f} "
            f"validation_loss={validation_metrics['loss']:.4f} "
            f"validation_f1={validation_metrics['f1']:.4f}",
            flush=True,
        )
        if validation_metrics["loss"] < best_loss:
            best_loss = validation_metrics["loss"]
            best_epoch = epoch
            stale_epochs = 0
            torch.save(
                {
                    "state_dict": model.state_dict(),
                    "input_dim": input_dim,
                    "hidden_dim": 128,
                    "layers": 4,
                    "edge_types": tuple(EDGE_TYPES),
                    "model_name": model_name,
                    "best_validation_loss": best_loss,
                    "best_epoch": best_epoch,
                },
                checkpoint,
            )
        else:
            stale_epochs += 1
            if stale_epochs >= patience:
                break

    saved = torch.load(checkpoint, map_location=target_device, weights_only=True)
    model.load_state_dict(saved["state_dict"])
    test_metrics = _evaluate(model, test_data, criterion, target_device, batcher)
    return {
        "checkpoint": str(checkpoint),
        "best_epoch": best_epoch,
        "best_validation_loss": best_loss,
        "test_loss": test_metrics["loss"],
        "test_metrics": test_metrics,
        "history": history,
        "split_sizes": {
            "train": len(train_data),
            "validation": len(validation_data),
            "test": len(test_data),
        },
    }


def _reject_held_out_overlap(
    training_examples: Sequence[LabeledCPG],
    test_examples: Sequence[LabeledCPG],
) -> None:
    training_sources = {
        hashlib.sha256(example.source.strip().encode("utf-8")).digest()
        for example in training_examples
    }
    overlapping_sources = sum(
        hashlib.sha256(example.source.strip().encode("utf-8")).digest()
        in training_sources
        for example in test_examples
    )
    if overlapping_sources:
        raise ValueError(
            "held-out test dataset contains "
            f"{overlapping_sources} source example(s) also present in training or validation data"
        )


def load_cpg_gnn(checkpoint_path: str | Path, device: str | None = None) -> Any:
    """Load a saved Week 7 checkpoint for use by the inference helpers."""
    try:
        import torch
        from .cpg_gnn import CPGGNN
    except ImportError as error:
        raise ImportError("loading a CPG GNN requires PyTorch") from error
    target_device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
    checkpoint = torch.load(
        Path(checkpoint_path),
        map_location=target_device,
        weights_only=True,
    )
    required = {"state_dict", "input_dim", "hidden_dim", "layers"}
    if not isinstance(checkpoint, dict) or not required.issubset(checkpoint):
        raise ValueError("checkpoint is missing required CPG GNN metadata")
    if checkpoint.get("edge_types") != tuple(EDGE_TYPES):
        raise ValueError("checkpoint edge types do not match this CPG GNN")
    model = CPGGNN(
        input_dim=checkpoint["input_dim"],
        hidden_dim=checkpoint["hidden_dim"],
        layers=checkpoint["layers"],
    ).to(target_device)
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    return model


def _batch(
    examples: Sequence[tuple[LabeledCPG, EncodedCPG]],
    device: Any,
    feature_store: Any,
    edge_store: Any,
) -> tuple[Any, Any, Any, Any, Any]:
    import numpy as np
    import torch

    features = []
    edge_indices = []
    edge_types = []
    graph_indices = []
    labels = []
    node_offset = 0
    for graph_index, (example, encoded) in enumerate(examples):
        node_features = torch.from_numpy(
            feature_store[
                encoded.node_start : encoded.node_start + encoded.node_count
            ].astype("float32", copy=True)
        )
        if node_features.shape[0] != encoded.node_count:
            raise ValueError("CodeBERT returned a feature count inconsistent with its graph")
        features.append(node_features)
        graph_indices.append(
            torch.full((encoded.node_count,), graph_index, dtype=torch.long)
        )
        if encoded.edge_count:
            edges = edge_store[
                encoded.edge_start : encoded.edge_start + encoded.edge_count
            ]
            edge_index = np.stack((edges["source"], edges["target"])).astype(
                np.int64,
                copy=False,
            )
            edge_index += node_offset
            edge_indices.append(torch.from_numpy(edge_index))
            edge_types.append(
                torch.from_numpy(edges["kind"].astype(np.int64, copy=True))
            )
        labels.append(float(example.label))
        node_offset += encoded.node_count

    edge_index = (
        torch.cat(edge_indices, dim=1)
        if edge_indices
        else torch.empty((2, 0), dtype=torch.long)
    )
    edge_type = torch.cat(edge_types) if edge_types else torch.empty((0,), dtype=torch.long)
    return (
        torch.cat(features).to(device),
        edge_index.to(device),
        edge_type.to(device),
        torch.cat(graph_indices).to(device),
        torch.tensor(labels, dtype=torch.float32, device=device),
    )


def _evaluate(
    model: Any,
    examples: Sequence,
    criterion: Any,
    device: Any,
    batcher: Any,
) -> dict[str, float]:
    import torch

    model.eval()
    loss_sum = 0.0
    total = true_positive = true_negative = false_positive = false_negative = 0
    with torch.no_grad():
        for offset in range(0, len(examples), 32):
            node_features, edge_index, edge_type, graph_batch, labels = batcher(
                examples[offset : offset + 32], device
            )
            logits = model(node_features, edge_index, edge_type, graph_batch)
            loss_sum += float(criterion(logits, labels).cpu()) * labels.numel()
            predictions = logits >= 0
            actual = labels >= 0.5
            true_positive += int((predictions & actual).sum().item())
            true_negative += int((~predictions & ~actual).sum().item())
            false_positive += int((predictions & ~actual).sum().item())
            false_negative += int((~predictions & actual).sum().item())
            total += labels.numel()
    if total == 0:
        raise ValueError("cannot evaluate an empty dataset split")
    precision = true_positive / max(1, true_positive + false_positive)
    recall = true_positive / max(1, true_positive + false_negative)
    return {
        "loss": loss_sum / total,
        "accuracy": (true_positive + true_negative) / total,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / max(1e-12, precision + recall),
    }


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="Train the AutoForge Week 7 CPG GNN")
    parser.add_argument("--dataset", required=True, help="JSON array of Python code and binary labels")
    parser.add_argument(
        "--test-dataset",
        default=None,
        help="optional held-out JSON or PyCode-Vul CSV test split",
    )
    parser.add_argument(
        "--checkpoint",
        default="src/ml/cpg_gnn_model.pt",
        help="output checkpoint path (default: src/ml/cpg_gnn_model.pt)",
    )
    parser.add_argument("--model-name", default="microsoft/codebert-base")
    parser.add_argument("--max-epochs", type=int, default=50)
    parser.add_argument("--device", default=None, help="optional torch device, e.g. cpu or cuda")
    arguments = parser.parse_args()
    result = train_cpg_gnn(
        arguments.dataset,
        arguments.checkpoint,
        test_dataset_path=arguments.test_dataset,
        model_name=arguments.model_name,
        max_epochs=arguments.max_epochs,
        device=arguments.device,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
