"""Thread-pool AST feature extraction for independent source files."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from src.ml.multilingual_features import extract_features
from src.parser.multi_lang_parser import MultiLangParser

_SOURCE_MARKERS = ("getparameter(", "request.args", "request.get(", "input(")
_SINK_MARKERS = ("execute(", "executequery(", "system(", "popen(")
_SANITIZER_MARKERS = ("escape(", "sanitize(", "parameterize(", "quote(")
_BRANCH_TYPES = {
    "if",
    "if_statement",
    "if_expression",
    "conditional_expression",
    "match",
    "match_statement",
    "switch_statement",
    "switch_expression",
}
_LOOP_TYPES = {"for", "asyncfor", "for_statement", "while", "while_statement"}


class ParallelASTBroker:
    def __init__(self, max_workers: int = 4) -> None:
        if isinstance(max_workers, bool) or not isinstance(max_workers, int) or max_workers < 1:
            raise ValueError("max_workers must be a positive integer")
        self.max_workers = max_workers
        self.parser = MultiLangParser()

    def process_file_ast(self, file_data: tuple[str, str]) -> dict[str, Any]:
        if (
            not isinstance(file_data, tuple)
            or len(file_data) != 2
            or not isinstance(file_data[0], str)
            or not file_data[0]
            or not isinstance(file_data[1], str)
        ):
            raise ValueError("file_data must be a (non-empty path, source string) tuple")

        file_path, content = file_data
        parsed = self.parser.parse_source(content, file_path)
        features = extract_features(parsed.tree, content)
        branches, loops = self._count_control_flow(parsed.tree)
        return {
            "file": file_path,
            "status": "PROCESSED",
            "language": parsed.language,
            "nodes_analyzed": int(features[0]),
            "cyclomatic_complexity": 1 + branches + loops,
            "max_nesting_depth": self._max_control_nesting(parsed.tree),
            "sink_distance": self._sink_distance(content),
            "user_input_tainted": self._has_source_marker(content),
            "sanitizer_present": self._has_sanitizer_marker(content),
            "feature_vector": features,
        }

    def run_batch(self, file_batch: Iterable[tuple[str, str]]) -> list[dict[str, Any]]:
        items = list(file_batch)
        if not items:
            return []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            return list(executor.map(self.process_file_ast, items))

    @classmethod
    def _max_control_nesting(cls, tree: Mapping[str, Any]) -> int:
        def visit(value: Any, depth: int) -> int:
            if isinstance(value, Mapping):
                kind = str(value.get("type", "")).lower()
                nested_depth = depth + int(kind in _BRANCH_TYPES or kind in _LOOP_TYPES)
                return max(
                    [nested_depth]
                    + [visit(child, nested_depth) for child in value.values() if child is not value]
                )
            if isinstance(value, (list, tuple)):
                return max((visit(child, depth) for child in value), default=depth)
            return depth

        return visit(tree, 0)

    @classmethod
    def _count_control_flow(cls, tree: Mapping[str, Any]) -> tuple[int, int]:
        branches = 0
        loops = 0

        def visit(value: Any) -> None:
            nonlocal branches, loops
            if isinstance(value, Mapping):
                kind = str(value.get("type", "")).lower()
                branches += int(kind in _BRANCH_TYPES)
                loops += int(kind in _LOOP_TYPES)
                for child in value.values():
                    visit(child)
            elif isinstance(value, (list, tuple)):
                for child in value:
                    visit(child)

        visit(tree)
        return branches, loops

    @staticmethod
    def _has_source_marker(source: str) -> bool:
        lowered = source.lower()
        return any(marker in lowered for marker in _SOURCE_MARKERS)

    @staticmethod
    def _has_sanitizer_marker(source: str) -> bool:
        lowered = source.lower()
        return any(marker in lowered for marker in _SANITIZER_MARKERS)

    @classmethod
    def _sink_distance(cls, source: str) -> int:
        lines = source.lower().splitlines()
        source_lines = [
            number for number, line in enumerate(lines, start=1)
            if any(marker in line for marker in _SOURCE_MARKERS)
        ]
        sink_lines = [
            number for number, line in enumerate(lines, start=1)
            if any(marker in line for marker in _SINK_MARKERS)
        ]
        if not source_lines or not sink_lines:
            return max(1, len(lines))
        return min(abs(source_line - sink_line) for source_line in source_lines for sink_line in sink_lines)
