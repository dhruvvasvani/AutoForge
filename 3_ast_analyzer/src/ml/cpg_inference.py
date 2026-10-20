"""Inference helpers for single-file and explicitly linked cross-file CPGs."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
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
