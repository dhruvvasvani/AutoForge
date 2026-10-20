"""Resolve Python imports and calls across a source tree."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.ir.symbol_table import FunctionSymbol, SymbolTable


@dataclass(frozen=True)
class CallEdge:
    caller: str
    callee: str
    arguments: tuple[str, ...]
    parameters: tuple[str, ...]
    line: int
    assigned_to: str | None = None
    call_name: str = ""
    keyword_arguments: tuple[tuple[str, str], ...] = ()

    @property
    def argument_bindings(self) -> dict[str, str]:
        parameters = self.parameters
        if (
            "." in self.call_name
            and parameters
            and parameters[0] in {"self", "cls"}
        ):
            parameters = parameters[1:]
        bindings = dict(zip(parameters, self.arguments))
        bindings.update(self.keyword_arguments)
        return bindings


class CrossFileResolver:
    def __init__(self, project_root: str | Path) -> None:
        self.root = Path(project_root).resolve()
        self.symbols = SymbolTable.from_project(self.root)
        self.imports: dict[str, dict[str, str]] = {}
        self.call_edges: list[CallEdge] = []

    def resolve(self) -> dict[str, Any]:
        self.imports.clear()
        self.call_edges.clear()
        for module, path in self.symbols.modules.items():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            aliases = self._imports(tree, module)
            self.imports[module] = aliases
            self._calls(tree, module, path, aliases)
        return {
            "modules": {name: str(path) for name, path in self.symbols.modules.items()},
            "imports": {module: dict(aliases) for module, aliases in self.imports.items()},
            "call_edges": [
                {
                    "caller": edge.caller,
                    "callee": edge.callee,
                    "arguments": list(edge.arguments),
                    "parameters": list(edge.parameters),
                    "argument_bindings": edge.argument_bindings,
                    "line": edge.line,
                    "assigned_to": edge.assigned_to,
                    "call_name": edge.call_name,
                }
                for edge in self.call_edges
            ],
        }

    def _imports(self, tree: ast.Module, module: str) -> dict[str, str]:
        aliases: dict[str, str] = {}
        package = module.rpartition(".")[0]
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    aliases[item.asname or item.name.split(".")[0]] = (
                        item.name if item.asname else item.name.split(".")[0]
                    )
            elif isinstance(node, ast.ImportFrom):
                target_module = node.module or ""
                if node.level:
                    base_parts = package.split(".") if package else []
                    ascend = max(0, node.level - 1)
                    base_parts = base_parts[: max(0, len(base_parts) - ascend)]
                    target_module = ".".join([*base_parts, target_module]).strip(".")
                for item in node.names:
                    if item.name == "*":
                        continue
                    alias = item.asname or item.name
                    aliases[alias] = f"{target_module}.{item.name}".strip(".")
        return aliases

    def _calls(
        self, tree: ast.Module, module: str, path: Path, aliases: dict[str, str]
    ) -> None:
        scopes: list[str] = [f"{module}::<module>"]
        parent_map = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }

        class Visitor(ast.NodeVisitor):
            def visit_ClassDef(inner_self, node: ast.ClassDef) -> None:
                parent = scopes[-1].removesuffix("::<module>")
                scopes.append(f"{parent}.{node.name}")
                inner_self.generic_visit(node)
                scopes.pop()

            def visit_FunctionDef(inner_self, node: ast.FunctionDef) -> None:
                parent = scopes[-1]
                if parent.endswith("::<module>"):
                    parent = parent.removesuffix("::<module>")
                scopes.append(f"{parent}.{node.name}")
                inner_self.generic_visit(node)
                scopes.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Call(inner_self, node: ast.Call) -> None:
                name = CrossFileResolver._call_name(node.func)
                callee = CrossFileResolver._resolve_name(name, aliases, module)
                symbol = self._find_symbol(callee)
                if symbol is not None:
                    args = tuple(CrossFileResolver._expr_name(arg) for arg in node.args)
                    keywords = tuple(
                        (keyword.arg, CrossFileResolver._expr_name(keyword.value))
                        for keyword in node.keywords
                        if keyword.arg is not None
                    )
                    parent = parent_map.get(node)
                    assigned_to = None
                    if isinstance(parent, ast.Assign) and parent.value is node and parent.targets:
                        assigned_to = CrossFileResolver._expr_name(parent.targets[0])
                    elif isinstance(parent, ast.AnnAssign) and parent.value is node:
                        assigned_to = CrossFileResolver._expr_name(parent.target)
                    self.call_edges.append(CallEdge(
                        scopes[-1], symbol.qualified_name, args, symbol.parameters,
                        node.lineno, assigned_to, name, keywords,
                    ))
                inner_self.generic_visit(node)

        Visitor().visit(tree)

    def analyze_taint(self) -> list[dict[str, Any]]:
        from src.analysis.taint_engine import TaintEngine

        self.resolve()
        function_inputs: dict[str, dict[str, str]] = {name: {} for name in self.symbols.functions}
        findings_by_key: dict[tuple[str, int, str, str], dict[str, Any]] = {}
        summaries: dict[str, bool] = {}
        for _ in range(max(1, len(self.symbols.functions) + 1)):
            changed = False
            for name, symbol in self.symbols.functions.items():
                source = ast.get_source_segment(
                    symbol.file_path.read_text(encoding="utf-8"), symbol.node
                )
                if not source:
                    continue
                engine = TaintEngine()
                tainted_calls = {
                    edge.call_name: "interprocedural return"
                    for edge in self.call_edges
                    if edge.caller == name and summaries.get(edge.callee)
                }
                findings = engine.analyze_cfg(
                    source, str(symbol.file_path), function_inputs[name], tainted_calls
                )
                state = engine.function_taint.get(symbol.node.name, {})
                for finding in findings:
                    absolute_line = finding.line + symbol.line - 1
                    key = (str(symbol.file_path), absolute_line, finding.sink, finding.variable)
                    findings_by_key[key] = {
                        "file": symbol.file_path.relative_to(self.root).as_posix(),
                        "function": name,
                        "line": absolute_line,
                        "rule_id": finding.rule_id,
                        "source": finding.source,
                        "sink": finding.sink,
                        "variable": finding.variable,
                        "has_sanitizer": finding.has_sanitizer,
                        "reachable": True,
                    }
                summaries[name] = self._returns_tainted(symbol.node, state)
                for edge in self.call_edges:
                    if edge.caller != name:
                        continue
                    callee = self.symbols.resolve(edge.callee)
                    if callee is None:
                        continue
                    for parameter, argument in edge.argument_bindings.items():
                        if self._expression_tainted(argument, state):
                            origin = next(
                                (state[var] for var in state if var in argument),
                                "interprocedural input",
                            )
                            if function_inputs[edge.callee].get(parameter) != origin:
                                function_inputs[edge.callee][parameter] = origin
                                changed = True
                    if edge.assigned_to and summaries.get(edge.callee):
                        if function_inputs[edge.caller].get(edge.assigned_to) != "interprocedural return":
                            function_inputs[edge.caller][edge.assigned_to] = "interprocedural return"
                            changed = True
            if not changed:
                break
        return list(findings_by_key.values())

    @staticmethod
    def _expression_tainted(expression: str, state: dict[str, str]) -> bool:
        from src.analysis.taint_engine import TaintEngine

        try:
            node = ast.parse(expression, mode="eval").body
        except SyntaxError:
            return any(name in expression for name in state)
        source_names = TaintEngine.SOURCES
        for item in ast.walk(node):
            if isinstance(item, ast.Name) and item.id in state:
                return True
            if isinstance(item, ast.Call) and CrossFileResolver._call_name(item.func).rsplit(".", 1)[-1] in source_names:
                return True
        return False

    @classmethod
    def _returns_tainted(cls, function: ast.FunctionDef | ast.AsyncFunctionDef, state: dict[str, str]) -> bool:
        return any(
            cls._expression_tainted(ast.unparse(node.value), state)
            for node in ast.walk(function)
            if isinstance(node, ast.Return) and node.value is not None
        )

    def _find_symbol(self, candidate: str) -> FunctionSymbol | None:
        symbol = self.symbols.resolve(candidate)
        if symbol:
            return symbol
        normalized = candidate.replace("::", ".")
        symbol = self.symbols.resolve(normalized)
        if symbol:
            return symbol
        short_name = candidate.rsplit(".", 1)[-1]
        matches = self.symbols.candidates(short_name)
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _resolve_name(name: str, aliases: dict[str, str], module: str) -> str:
        head, dot, tail = name.partition(".")
        if head in aliases:
            return aliases[head] + (dot + tail if dot else "")
        return f"{module}.{name}"

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    @staticmethod
    def _expr_name(node: ast.AST) -> str:
        return ast.unparse(node) if hasattr(ast, "unparse") else type(node).__name__


def resolve_project(project_root: str | Path) -> dict[str, Any]:
    return CrossFileResolver(project_root).resolve()
