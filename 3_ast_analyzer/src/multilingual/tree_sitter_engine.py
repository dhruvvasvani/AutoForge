"""Build structural code-property graphs from Tree-sitter syntax trees."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.ml.cpg_builder import CPGGraph, CPGNode, build_cpg

_LANGUAGES = {
    ".cjs": "javascript",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".py": "python",
    ".sql": "sql",
    ".ts": "typescript",
    ".tsx": "tsx",
}


@dataclass(frozen=True)
class TreeSitterResult:
    language: str
    root_type: str
    graph: CPGGraph
    has_errors: bool
    error_count: int


class TreeSitterEngine:
    def __init__(self, *, max_node_text_length: int = 512) -> None:
        if (
            isinstance(max_node_text_length, bool)
            or not isinstance(max_node_text_length, int)
            or max_node_text_length < 1
        ):
            raise ValueError("max_node_text_length must be a positive integer")
        self.max_node_text_length = max_node_text_length

    def parse_file(self, file_path: str | Path) -> TreeSitterResult:
        path = Path(file_path)
        language = _LANGUAGES.get(path.suffix.lower())
        if language is None:
            raise ValueError(f"Unsupported source extension: {path.suffix}")
        return self.parse_source(path.read_text(encoding="utf-8"), language)

    def parse_source(
        self,
        source: str,
        language: str,
    ) -> TreeSitterResult:
        if not isinstance(source, str):
            raise TypeError("source must be a string")
        if not isinstance(language, str):
            raise TypeError("language must be a string")
        normalized_language = language.lower().lstrip(".")
        if normalized_language in {"js", "jsx", "mjs", "cjs"}:
            normalized_language = "javascript"
        if normalized_language not in {
            "python",
            "javascript",
            "typescript",
            "tsx",
            "go",
            "java",
            "sql",
        }:
            raise ValueError(f"Unsupported language: {language}")
        try:
            from tree_sitter_language_pack import get_parser
        except ImportError as error:
            raise RuntimeError(
                "Tree-sitter parsing requires tree-sitter-language-pack; "
                "install 3_ast_analyzer\\requirements.txt"
            ) from error

        source_bytes = source.encode("utf-8")
        root = get_parser(normalized_language).parse(source_bytes).root_node
        if normalized_language == "python":
            return TreeSitterResult(
                language=normalized_language,
                root_type=root.type,
                graph=build_cpg(source),
                has_errors=root.has_error,
                error_count=_count_syntax_errors(root),
            )

        nodes: list[CPGNode] = []
        edges: list[tuple[int, int, str]] = []
        error_count = 0
        pending: list[tuple[Any, int | None]] = [(root, None)]
        while pending:
            syntax_node, parent_id = pending.pop()
            if not syntax_node.is_named:
                continue
            node_id = len(nodes)
            start = syntax_node.start_byte
            end = syntax_node.end_byte
            text = source_bytes[start:end].decode("utf-8", errors="replace")
            nodes.append(
                CPGNode(
                    node_id=node_id,
                    kind=syntax_node.type,
                    text=text[: self.max_node_text_length],
                    line=syntax_node.start_point.row + 1,
                )
            )
            if parent_id is not None:
                edges.append((parent_id, node_id, "ast"))
            if syntax_node.is_error or syntax_node.is_missing:
                error_count += 1
            for child in reversed(syntax_node.children):
                if child.is_named:
                    pending.append((child, node_id))

        graph = CPGGraph(tuple(nodes), tuple(edges))
        return TreeSitterResult(
            language=normalized_language,
            root_type=root.type,
            graph=graph,
            has_errors=root.has_error,
            error_count=error_count,
        )


def _count_syntax_errors(root: Any) -> int:
    count = 0
    pending = [root]
    while pending:
        node = pending.pop()
        if node.is_error or node.is_missing:
            count += 1
        pending.extend(node.children)
    return count
