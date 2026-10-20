"""Relation-aware GINE-style graph classifier implemented with PyTorch."""

from __future__ import annotations

import torch
from torch import nn
from torch.nn import functional as F

from .cpg_builder import EDGE_TYPES


class GINEMessagePassing(nn.Module):
    def __init__(self, hidden_dim: int, edge_type_count: int = len(EDGE_TYPES)) -> None:
        super().__init__()
        self.edge_embedding = nn.Embedding(edge_type_count, hidden_dim)
        self.epsilon = nn.Parameter(torch.zeros(1))
        self.update = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
        )

    def forward(
        self,
        node_features: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor,
    ) -> torch.Tensor:
        aggregate = torch.zeros_like(node_features)
        if edge_index.numel():
            source, destination = edge_index
            messages = F.relu(
                node_features[source] + self.edge_embedding(edge_type)
            )
            aggregate.index_add_(0, destination, messages)
        return self.update((1 + self.epsilon) * node_features + aggregate)


class CPGGNN(nn.Module):
    def __init__(
        self,
        input_dim: int = 768,
        hidden_dim: int = 128,
        layers: int = 4,
        edge_type_count: int = len(EDGE_TYPES),
    ) -> None:
        super().__init__()
        if isinstance(input_dim, bool) or not isinstance(input_dim, int) or input_dim < 1:
            raise ValueError("input_dim must be a positive integer")
        if hidden_dim != 128:
            raise ValueError("the Week 7 model uses a 128-dimensional embedding")
        if layers != 4:
            raise ValueError("the Week 7 model uses exactly four message-passing layers")
        self.input_projection = nn.Linear(input_dim, hidden_dim)
        self.layers = nn.ModuleList(
            GINEMessagePassing(hidden_dim, edge_type_count) for _ in range(layers)
        )
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, 1),
        )

    def forward(
        self,
        node_features: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor,
        graph_batch: torch.Tensor,
    ) -> torch.Tensor:
        if node_features.ndim != 2 or node_features.shape[0] == 0:
            raise ValueError("node_features must contain at least one node")
        if edge_index.ndim != 2 or edge_index.shape[0] != 2:
            raise ValueError("edge_index must have shape [2, edge_count]")
        if edge_type.ndim != 1 or edge_type.shape[0] != edge_index.shape[1]:
            raise ValueError("edge_type must have one entry per edge")
        if graph_batch.ndim != 1 or graph_batch.shape[0] != node_features.shape[0]:
            raise ValueError("graph_batch must have one graph index per node")

        hidden = F.relu(self.input_projection(node_features))
        for layer in self.layers:
            hidden = F.relu(layer(hidden, edge_index, edge_type))

        graph_count = int(graph_batch.max().item()) + 1
        pooled = []
        for graph_id in range(graph_count):
            graph_nodes = hidden[graph_batch == graph_id]
            if graph_nodes.shape[0] == 0:
                raise ValueError("graph_batch indices must be contiguous and non-empty")
            pooled.append(
                torch.cat(
                    (graph_nodes.mean(dim=0), graph_nodes.max(dim=0).values),
                    dim=0,
                )
            )
        return self.classifier(torch.stack(pooled, dim=0)).squeeze(-1)


def predict_graph_confidence(
    model: CPGGNN,
    node_features: torch.Tensor,
    edge_index: torch.Tensor,
    edge_type: torch.Tensor,
) -> float:
    model.eval()
    device = next(model.parameters()).device
    graph_batch = torch.zeros(node_features.shape[0], dtype=torch.long, device=device)
    with torch.no_grad():
        logit = model(
            node_features.to(device),
            edge_index.to(device),
            edge_type.to(device),
            graph_batch,
        )
        return float(torch.sigmoid(logit[0]).item())
