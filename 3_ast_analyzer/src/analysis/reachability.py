"""Inter-procedural call-graph construction and entry-point reachability."""

from __future__ import annotations

import ast
from collections import deque
from pathlib import Path
from typing import Any, Iterable, Mapping

from src.analysis.cross_file_resolver import CrossFileResolver
from src.ir.symbol_table import SymbolTable


class ReachabilityAnalyzer:
    DEFAULT_ENTRY_POINTS = ("main", "handle_login", "get_user_profile")
    HTTP_ROUTE_DECORATORS = {
        "api_route", "delete", "get", "options", "patch", "post", "put", "route",
        "websocket",
    }

    def __init__(self, entry_points: Iterable[str] | None = None) -> None:
        self.entry_points = tuple(entry_points or self.DEFAULT_ENTRY_POINTS)

    def analyze_project(
        self,
        project_root: str | Path,
        findings: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        resolver = CrossFileResolver(project_root)
        graph = resolver.resolve()
        symbols = resolver.symbols
        call_graph: dict[str, set[str]] = {
            name: set() for name in symbols.functions
        }
        for edge in resolver.call_edges:
            call_graph.setdefault(edge.caller, set()).add(edge.callee)

        matched_entries = {
            name for name in call_graph
            if any(name == entry or name.endswith(f".{entry}") for entry in self.entry_points)
        }
        matched_entries.update(
            name
            for name, symbol in symbols.functions.items()
            if self._is_http_route(symbol.node)
        )
        reachable = set(matched_entries)
        pending = deque(matched_entries)
        while pending:
            caller = pending.popleft()
            for callee in call_graph.get(caller, ()):
                if callee in call_graph and callee not in reachable:
                    reachable.add(callee)
                    pending.append(callee)

        tagged = []
        for finding in findings:
            tagged_finding = dict(finding)
            file_path = (
                tagged_finding.get("file")
                or tagged_finding.get("path")
                or tagged_finding.get("file_path")
            )
            if isinstance(file_path, str) and Path(file_path).suffix.lower() != ".py":
                tagged_finding["function"] = None
                tagged_finding["reachability"] = "UNKNOWN"
                tagged.append(tagged_finding)
                continue
            function = (
                tagged_finding.get("function")
                or tagged_finding.get("function_name")
                or self._function_for_location(symbols, project_root, tagged_finding)
            )
            target = (
                self._resolve_function(call_graph, function)
                if isinstance(function, str) and function.strip()
                else None
            )
            tagged_finding["function"] = function
            if target is None:
                tagged_finding["reachability"] = "UNKNOWN"
            else:
                tagged_finding["reachability"] = (
                    "REACHABLE_CODE" if target in reachable else "UNREACHABLE_NOISE"
                )
            tagged.append(tagged_finding)

        return {
            "call_graph": {name: sorted(callees) for name, callees in call_graph.items()},
            "reachable_functions": sorted(reachable),
            "missing_entry_points": [
                entry for entry in self.entry_points
                if not any(name.endswith(f".{entry}") or name == entry for name in call_graph)
            ],
            "tagged_findings": tagged,
            "imports": graph["imports"],
        }

    @classmethod
    def _is_http_route(cls, function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for decorator in function.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if isinstance(target, ast.Name) and target.id.lower() in cls.HTTP_ROUTE_DECORATORS:
                return True
            if isinstance(target, ast.Attribute) and target.attr.lower() in cls.HTTP_ROUTE_DECORATORS:
                return True
        return False

    @staticmethod
    def _resolve_function(call_graph: Mapping[str, Any], target: str) -> str | None:
        if target in call_graph:
            return target
        matches = [name for name in call_graph if name.endswith(f".{target}")]
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _function_for_location(
        symbols: SymbolTable,
        project_root: str | Path,
        finding: Mapping[str, Any],
    ) -> str | None:
        file_path = finding.get("file") or finding.get("path") or finding.get("file_path")
        line = finding.get("line") or finding.get("line_number")
        if not isinstance(file_path, str) or not isinstance(line, int):
            return None
        candidate = (Path(project_root).resolve() / file_path).resolve()
        matches = [
            symbol for symbol in symbols.functions.values()
            if (
                symbol.file_path.resolve() == candidate
                and symbol.line <= line <= (symbol.node.end_lineno or symbol.line)
            )
        ]
        if not matches:
            return None
        return min(
            matches,
            key=lambda symbol: (
                (symbol.node.end_lineno or symbol.line) - symbol.line,
                -symbol.line,
            ),
        ).qualified_name
