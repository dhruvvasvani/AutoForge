from __future__ import annotations

import threading
from collections import OrderedDict
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
    ".rs": "rust",
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


@dataclass(frozen=True)
class _CachedTree:
    source: bytes
    tree: Any
    result: TreeSitterResult


class TreeSitterEngine:
    def __init__(
        self,
        *,
        max_node_text_length: int = 512,
        cache_capacity: int = 128,
    ) -> None:
        if (
            isinstance(max_node_text_length, bool)
            or not isinstance(max_node_text_length, int)
            or max_node_text_length < 1
        ):
            raise ValueError("max_node_text_length must be a positive integer")
        if isinstance(cache_capacity, bool) or not isinstance(cache_capacity, int) or cache_capacity < 1:
            raise ValueError("cache_capacity must be a positive integer")
        self.max_node_text_length = max_node_text_length
        self.cache_capacity = cache_capacity
        self._cache: OrderedDict[tuple[str, str], _CachedTree] = OrderedDict()
        self._cache_lock = threading.Lock()
        self._cache_hits = 0
        self._incremental_parses = 0
        self._full_parses = 0
        self._parse_count_by_language: dict[str, int] = {}
        self._syntax_error_count_by_language: dict[str, int] = {}
        self._node_type_count_by_language: dict[str, dict[str, int]] = {}

    def parse_file(self, file_path: str | Path) -> TreeSitterResult:
        path = Path(file_path)
        language = _LANGUAGES.get(path.suffix.lower())
        if language is None:
            raise ValueError(f"Unsupported source extension: {path.suffix}")
        return self.parse_source(
            path.read_text(encoding="utf-8"),
            language,
            file_path=path,
        )

    def parse_source(
        self,
        source: str,
        language: str,
        *,
        file_path: str | Path | None = None,
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
            "rust",
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
        parser = get_parser(normalized_language)
        cache_key = (
            (normalized_language, str(Path(file_path).resolve()))
            if file_path is not None
            else None
        )
        cached = None
        if cache_key is not None:
            with self._cache_lock:
                cached = self._cache.get(cache_key)
                if cached is not None:
                    self._cache.move_to_end(cache_key)
                    if cached.source == source_bytes:
                        self._cache_hits += 1
                        return cached.result

        old_tree = cached.tree.copy() if cached is not None else None
        incremental = old_tree is not None
        if old_tree is not None:
            _edit_tree(old_tree, cached.source, source_bytes)
            tree = parser.parse(source_bytes, old_tree)
        else:
            tree = parser.parse(source_bytes)
        root = tree.root_node
        if normalized_language == "python":
            result = TreeSitterResult(
                language=normalized_language,
                root_type=root.type,
                graph=build_cpg(source),
                has_errors=root.has_error,
                error_count=_count_syntax_errors(root),
            )
        else:
            result = self._tree_sitter_result(root, source_bytes, normalized_language)

        if cache_key is not None:
            with self._cache_lock:
                self._cache[cache_key] = _CachedTree(source_bytes, tree, result)
                self._cache.move_to_end(cache_key)
                while len(self._cache) > self.cache_capacity:
                    self._cache.popitem(last=False)
                if incremental:
                    self._incremental_parses += 1
                else:
                    self._full_parses += 1
        with self._cache_lock:
            self._parse_count_by_language[normalized_language] = (
                self._parse_count_by_language.get(normalized_language, 0) + 1
            )
            if result.error_count:
                self._syntax_error_count_by_language[normalized_language] = (
                    self._syntax_error_count_by_language.get(normalized_language, 0)
                    + result.error_count
                )
            node_counts = self._node_type_count_by_language.setdefault(
                normalized_language, {}
            )
            for node in result.graph.nodes:
                node_counts[node.kind] = node_counts.get(node.kind, 0) + 1

        return result

    def cache_info(self) -> dict[str, int]:
        with self._cache_lock:
            return {
                "entries": len(self._cache),
                "capacity": self.cache_capacity,
                "hits": self._cache_hits,
                "incremental_parses": self._incremental_parses,
                "full_parses": self._full_parses,
            }

    def health_info(self) -> dict[str, Any]:
        with self._cache_lock:
            return {
                "supported_languages": sorted({
                    "python", "javascript", "typescript", "tsx", "go", "java", "sql", "rust"
                }),
                "parse_count_by_language": dict(self._parse_count_by_language),
                "syntax_error_count_by_language": dict(self._syntax_error_count_by_language),
                "observed_node_types_by_language": {
                    language: dict(sorted(counts.items()))
                    for language, counts in self._node_type_count_by_language.items()
                },
                "cache": {
                    "entries": len(self._cache),
                    "capacity": self.cache_capacity,
                    "hits": self._cache_hits,
                },
            }

    def _tree_sitter_result(
        self,
        root: Any,
        source_bytes: bytes,
        language: str,
    ) -> TreeSitterResult:
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
            language=language,
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


def _point(source: bytes, offset: int) -> tuple[int, int]:
    prefix = source[:offset]
    row = prefix.count(b"\n")
    column = len(prefix) - (prefix.rfind(b"\n") + 1)
    return row, column


def _edit_tree(tree: Any, old_source: bytes, new_source: bytes) -> None:
    prefix_length = 0
    shared_length = min(len(old_source), len(new_source))
    while prefix_length < shared_length and old_source[prefix_length] == new_source[prefix_length]:
        prefix_length += 1

    suffix_length = 0
    max_suffix = min(len(old_source) - prefix_length, len(new_source) - prefix_length)
    while (
        suffix_length < max_suffix
        and old_source[len(old_source) - suffix_length - 1]
        == new_source[len(new_source) - suffix_length - 1]
    ):
        suffix_length += 1

    old_end = len(old_source) - suffix_length
    new_end = len(new_source) - suffix_length
    tree.edit(
        start_byte=prefix_length,
        old_end_byte=old_end,
        new_end_byte=new_end,
        start_point=_point(old_source, prefix_length),
        old_end_point=_point(old_source, old_end),
        new_end_point=_point(new_source, new_end),
    )
