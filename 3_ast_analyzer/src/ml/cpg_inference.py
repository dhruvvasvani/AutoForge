"""Inference helpers for single-file and explicitly linked cross-file CPGs."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
import os
from typing import Any

from .cpg_builder import CPGGraph, build_cpg, merge_cpg_graphs


def predict_cpg_confidence(
    graph: CPGGraph,
    model: Any,
    encoder: Any,
) -> float:
    try:
        import torch
        from .cpg_gnn import predict_graph_confidence
    except ImportError as error:
        raise ImportError("CPG inference requires PyTorch") from error
    features = encoder.encode([graph])[0]
    if features.shape[0] != len(graph.nodes):
        raise ValueError("encoder returned a feature count inconsistent with the graph")
    edge_index, edge_type = _edge_tensors(graph, torch)
    return predict_graph_confidence(model, features, edge_index, edge_type)


def predict_project_confidence(
    sources: Mapping[str, str],
    model: Any,
    encoder: Any,
    cross_file_edges: Iterable[tuple[str, int, str, int]] = (),
) -> float:
    """Score a project graph with explicit cross-file edges from a resolver."""
    file_graphs = {path: build_cpg(source) for path, source in sources.items()}
    graph = merge_cpg_graphs(file_graphs, cross_file_edges)
    return predict_cpg_confidence(graph, model, encoder)


def predict_file_confidences(
    sources: Mapping[str, str],
    model: Any,
    encoder: Any,
    *,
    batch_size: int = 16,
) -> dict[str, float]:
    """Score each source file's CPG graph in bounded encoder batches."""
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
        raise ValueError("batch_size must be a positive integer")
    try:
        import torch
    except ImportError as error:
        raise ImportError("CPG inference requires PyTorch") from error

    source_items = list(sources.items())
    worker_count = min(4, len(source_items), os.cpu_count() or 1)
    if worker_count > 1:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            graphs = executor.map(lambda item: build_cpg(item[1]), source_items)
            items = [(item[0], graph) for item, graph in zip(source_items, graphs)]
    else:
        items = [(path, build_cpg(source)) for path, source in source_items]
    predictions: dict[str, float] = {}
    model.eval()
    device = next(model.parameters()).device
    for offset in range(0, len(items), batch_size):
        batch = items[offset : offset + batch_size]
        graphs = [graph for _, graph in batch]
        features_batch = encoder.encode(graphs)
        if len(features_batch) != len(graphs):
            raise ValueError("encoder returned a different number of feature matrices than graphs")

        feature_parts = []
        edge_indices = []
        edge_types = []
        graph_indices = []
        for graph_index, (graph, features) in enumerate(zip(graphs, features_batch)):
            if features.shape[0] != len(graph.nodes):
                raise ValueError("encoder returned a feature count inconsistent with a graph")
            edge_index, edge_type = _edge_tensors(graph, torch)
            if edge_index.numel():
                edge_indices.append(edge_index + sum(part.shape[0] for part in feature_parts))
                edge_types.append(edge_type)
            feature_parts.append(features)
            graph_indices.append(
                torch.full((len(graph.nodes),), graph_index, dtype=torch.long)
            )

        node_features = torch.cat(feature_parts, dim=0).to(device)
        edge_index = (
            torch.cat(edge_indices, dim=1).to(device)
            if edge_indices
            else torch.empty((2, 0), dtype=torch.long, device=device)
        )
        edge_type = (
            torch.cat(edge_types).to(device)
            if edge_types
            else torch.empty((0,), dtype=torch.long, device=device)
        )
        graph_batch = torch.cat(graph_indices).to(device)
        with torch.no_grad():
            probabilities = torch.sigmoid(
                model(node_features, edge_index, edge_type, graph_batch)
            ).cpu().tolist()
        predictions.update(
            (path, float(probability))
            for (path, _), probability in zip(batch, probabilities)
        )
    return predictions


def _edge_tensors(graph: CPGGraph, torch: Any) -> tuple[Any, Any]:
    from .cpg_builder import EDGE_TYPES

    if graph.edges:
        edge_index = torch.tensor(
            [[source for source, _, _ in graph.edges], [target for _, target, _ in graph.edges]],
            dtype=torch.long,
        )
        edge_type = torch.tensor(
            [EDGE_TYPES[kind] for _, _, kind in graph.edges],
            dtype=torch.long,
        )
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)
        edge_type = torch.empty((0,), dtype=torch.long)
    return edge_index, edge_type
