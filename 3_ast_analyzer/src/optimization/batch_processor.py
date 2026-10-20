"""Memory-aware batching for CPG construction and GNN input collation."""

from __future__ import annotations

import ast
import os
from collections.abc import Iterable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from time import perf_counter
from typing import Any

from src.ml.cpg_builder import CPGGraph, CPGNode, EDGE_TYPES, build_cpg

_BYTES_PER_ESTIMATED_NODE = 4096
_MIN_WORKER_RESERVATION_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class CPGBatch:
    graphs: tuple[CPGGraph, ...]
    estimated_memory_bytes: int
    pruned_graphs: int
    workers_used: int
    duration_seconds: float
    graphs_per_second: float


class CPGBatchProcessor:
    def __init__(
        self,
        *,
        batch_size: int = 32,
        max_workers: int | None = None,
        memory_limit_bytes: int = 1536 * 1024 * 1024,
        max_nodes_per_graph: int | None = None,
    ) -> None:
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
            raise ValueError("batch_size must be a positive integer")
        if max_workers is None:
            max_workers = min(4, os.cpu_count() or 1)
        if isinstance(max_workers, bool) or not isinstance(max_workers, int) or max_workers < 1:
            raise ValueError("max_workers must be a positive integer")
        if (
            isinstance(memory_limit_bytes, bool)
            or not isinstance(memory_limit_bytes, int)
            or memory_limit_bytes < _MIN_WORKER_RESERVATION_BYTES
        ):
            raise ValueError("memory_limit_bytes must be at least 64 MiB")
        if max_nodes_per_graph is not None and (
            isinstance(max_nodes_per_graph, bool)
            or not isinstance(max_nodes_per_graph, int)
            or max_nodes_per_graph < 1
        ):
            raise ValueError("max_nodes_per_graph must be a positive integer when set")
        self.batch_size = batch_size
        self.max_workers = max_workers
        self.memory_limit_bytes = memory_limit_bytes
        self.max_nodes_per_graph = max_nodes_per_graph

    def iter_batches(self, sources: Iterable[tuple[str, str]]) -> Iterator[CPGBatch]:
        iterator = iter(sources)
        pending_item = None
        while True:
            available_budget = self._available_budget()
            source_batch, pending_item = self._next_source_batch(
                iterator,
                available_budget,
                pending_item,
            )
            if not source_batch:
                break
            estimated_bytes = sum(
                self._estimate_graph_memory(source) for _, source in source_batch
            )
            worker_count = max(
                1,
                min(
                    self.max_workers,
                    len(source_batch),
                    max(1, available_budget // _MIN_WORKER_RESERVATION_BYTES),
                ),
            )
            started_at = perf_counter()
            build = self._build_one
            if worker_count == 1:
                built_graphs = [build(item) for item in source_batch]
            else:
                with ThreadPoolExecutor(max_workers=worker_count) as executor:
                    built_graphs = list(executor.map(build, source_batch))
            graphs = []
            pruned_graphs = 0
            for graph in built_graphs:
                if (
                    self.max_nodes_per_graph is not None
                    and len(graph.nodes) > self.max_nodes_per_graph
                ):
                    graph = _prune_graph(graph, self.max_nodes_per_graph)
                    pruned_graphs += 1
                graphs.append(graph)
            duration = max(perf_counter() - started_at, 1e-12)
            yield CPGBatch(
                graphs=tuple(graphs),
                estimated_memory_bytes=estimated_bytes,
                pruned_graphs=pruned_graphs,
                workers_used=worker_count,
                duration_seconds=duration,
                graphs_per_second=len(graphs) / duration,
            )

    def _next_source_batch(
        self,
        sources: Iterator[tuple[str, str]],
        available_budget: int,
        pending_item: tuple[str, str] | None,
    ) -> tuple[list[tuple[str, str]], tuple[str, str] | None]:
        batch: list[tuple[str, str]] = []
        estimated_bytes = 0
        while len(batch) < self.batch_size:
            if pending_item is not None:
                item = pending_item
                pending_item = None
            else:
                try:
                    item = next(sources)
                except StopIteration:
                    break
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not item[0]
                or not isinstance(item[1], str)
            ):
                raise ValueError("each source must be a (non-empty path, source string) tuple")
            estimate = self._estimate_graph_memory(item[1])
            if batch and estimated_bytes + estimate > available_budget:
                pending_item = item
                break
            batch.append(item)
            estimated_bytes += estimate
            if estimated_bytes >= available_budget:
                break
        return batch, pending_item

    def _available_budget(self) -> int:
        try:
            import psutil
        except ImportError as error:
            raise RuntimeError(
                "memory-aware batching requires psutil; install "
                "3_ast_analyzer\\requirements.txt"
            ) from error
        process_rss = psutil.Process().memory_info().rss
        system_available = psutil.virtual_memory().available
        remaining_process_budget = max(1, self.memory_limit_bytes - process_rss)
        return max(1, min(remaining_process_budget, system_available // 2, self.memory_limit_bytes // 2))

    @staticmethod
    def _estimate_graph_memory(source: str) -> int:
        syntax_node_count = sum(1 for _ in ast.walk(ast.parse(source)))
        return max(64 * 1024, syntax_node_count * _BYTES_PER_ESTIMATED_NODE)

    @staticmethod
    def _build_one(item: tuple[str, str]) -> CPGGraph:
        return build_cpg(item[1])


def collate_cpg_graphs(
    graphs: Sequence[CPGGraph],
    node_features: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Concatenate graph edges and optional precomputed node features for a GNN."""
    if not graphs:
        raise ValueError("at least one CPG graph is required")
    try:
        import torch
    except ImportError as error:
        raise RuntimeError("GNN collation requires PyTorch") from error

    feature_tensors = None
    if node_features is not None:
        if len(node_features) != len(graphs):
            raise ValueError("node_features must contain one tensor per graph")
        feature_tensors = []
        for graph_index, (graph, features) in enumerate(zip(graphs, node_features)):
            if not isinstance(features, torch.Tensor) or features.ndim != 2:
                raise ValueError(f"node_features[{graph_index}] must be a rank-2 tensor")
            if features.shape[0] != len(graph.nodes):
                raise ValueError(f"node_features[{graph_index}] must have one row per graph node")
            if not features.is_floating_point():
                raise ValueError(f"node_features[{graph_index}] must use a floating-point dtype")
            feature_tensors.append(features)

    all_edges: list[tuple[int, int, str]] = []
    graph_indices: list[int] = []
    offset = 0
    for graph_index, graph in enumerate(graphs):
        if not graph.nodes:
            raise ValueError(f"graph {graph_index} has no nodes")
        graph_indices.extend([graph_index] * len(graph.nodes))
        for source, target, edge_type in graph.edges:
            if edge_type not in EDGE_TYPES:
                raise ValueError(f"graph {graph_index} has unknown edge type {edge_type!r}")
            all_edges.append((source + offset, target + offset, edge_type))
        offset += len(graph.nodes)

    if all_edges:
        edge_index = torch.tensor(
            [[source for source, _, _ in all_edges], [target for _, target, _ in all_edges]],
            dtype=torch.long,
        )
        edge_type = torch.tensor(
            [EDGE_TYPES[kind] for _, _, kind in all_edges],
            dtype=torch.long,
        )
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)
        edge_type = torch.empty((0,), dtype=torch.long)

    batch: dict[str, Any] = {
        "edge_index": edge_index,
        "edge_type": edge_type,
        "graph_batch": torch.tensor(graph_indices, dtype=torch.long),
    }
    if feature_tensors is not None:
        batch["node_features"] = torch.cat(feature_tensors, dim=0)
    if all(graph.label is not None for graph in graphs):
        batch["labels"] = torch.tensor([graph.label for graph in graphs], dtype=torch.float32)
    return batch


def _prune_graph(graph: CPGGraph, maximum_nodes: int) -> CPGGraph:
    retained_nodes = graph.nodes[:maximum_nodes]
    retained_ids = {node.node_id: new_id for new_id, node in enumerate(retained_nodes)}
    nodes = tuple(
        CPGNode(
            node_id=retained_ids[node.node_id],
            kind=node.kind,
            text=node.text,
            line=node.line,
        )
        for node in retained_nodes
    )
    edges = tuple(
        sorted(
            (retained_ids[source], retained_ids[target], edge_type)
            for source, target, edge_type in graph.edges
            if source in retained_ids and target in retained_ids
        )
    )
    return CPGGraph(nodes, edges, graph.label)
