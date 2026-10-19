"""PyTorch MLP used to estimate vulnerability probability."""

from __future__ import annotations

import torch
from torch import nn


class ASTVulnerabilityClassifier(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int = 64, dropout: float = 0.25) -> None:
        super().__init__()
        if input_dim <= 0 or hidden_dim < 2 or not 0.0 <= dropout < 1.0:
            raise ValueError("Invalid model dimensions or dropout")
        self.layers = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 1),
        )

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        return torch.sigmoid(self.layers(features))
