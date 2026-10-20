"""Optional CodeBERT node-text embeddings for CPG graphs."""

from __future__ import annotations

from typing import Sequence

from .cpg_builder import CPGGraph


class CodeBERTEncoder:
    def __init__(
        self,
        model_name: str = "microsoft/codebert-base",
        batch_size: int = 16,
        device: str | None = None,
    ) -> None:
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
            raise ValueError("batch_size must be a positive integer")
        try:
            import torch
            from transformers import AutoModel, AutoTokenizer
        except ImportError as error:
            raise ImportError(
                "CodeBERT embeddings require torch and transformers; install "
                "3_ast_analyzer\\requirements.txt"
            ) from error

        self.torch = torch
        self.batch_size = batch_size
        self.device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name).to(self.device)
        self.model.eval()

    def encode(self, graphs: Sequence[CPGGraph]) -> list:
        torch = self.torch
        texts = [node.text for graph in graphs for node in graph.nodes]
        if not texts:
            raise ValueError("cannot encode graphs without nodes")
        unique_texts = list(dict.fromkeys(texts))
        text_indices = {text: index for index, text in enumerate(unique_texts)}
        node_text_indices = torch.tensor(
            [text_indices[text] for text in texts],
            dtype=torch.long,
        )

        embeddings = []
        with torch.no_grad():
            for offset in range(0, len(unique_texts), self.batch_size):
                tokens = self.tokenizer(
                    unique_texts[offset : offset + self.batch_size],
                    padding=True,
                    truncation=True,
                    max_length=64,
                    return_tensors="pt",
                )
                tokens = {name: value.to(self.device) for name, value in tokens.items()}
                output = self.model(**tokens).last_hidden_state
                mask = tokens["attention_mask"].unsqueeze(-1)
                pooled = (output * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)
                embeddings.append(pooled.cpu())
        node_embeddings = torch.cat(embeddings, dim=0)[node_text_indices]
        return list(node_embeddings.split([len(graph.nodes) for graph in graphs]))

    def iter_encode(
        self,
        graphs: Sequence[CPGGraph],
        graph_batch_size: int = 32,
    ):
        if (
            isinstance(graph_batch_size, bool)
            or not isinstance(graph_batch_size, int)
            or graph_batch_size < 1
        ):
            raise ValueError("graph_batch_size must be a positive integer")
        for offset in range(0, len(graphs), graph_batch_size):
            yield offset, self.encode(graphs[offset : offset + graph_batch_size])
