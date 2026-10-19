"""Flow-sensitive intra-procedural source-to-sink tracking for Python."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from collections import deque
from typing import Any


@dataclass(frozen=True)
class TaintFinding:
    rule_id: str
    source: str
    sink: str
    line: int
    variable: str
    has_sanitizer: bool = False


class TaintEngine(ast.NodeVisitor):
    SOURCES = {"getParameter", "get_param", "get", "input", "getParameterValues"}
    SINK_RULES = {
        "execute": "SQLI_RAW_CONCAT",
        "executeQuery": "SQLI_RAW_CONCAT",
        "executemany": "SQLI_RAW_CONCAT",
        "system": "CMD_INJ_EXEC",
        "Popen": "CMD_INJ_EXEC",
        "exec": "CMD_INJ_EXEC",
        "write": "XSS_UNSANITIZED_WRITE",
        "send": "XSS_UNSANITIZED_WRITE",
        "render_template_string": "XSS_UNSANITIZED_WRITE",
        "info": "LOG_INJECTION",
        "warning": "LOG_INJECTION",
        "error": "LOG_INJECTION",
        "critical": "LOG_INJECTION",
        "exception": "LOG_INJECTION",
    }
    SANITIZERS = {"escape", "sanitize", "html.escape", "quote", "parameterize"}

    def __init__(self) -> None:
        self.tainted: dict[str, str] = {}
        self.sanitized: set[str] = set()
        self.findings: list[TaintFinding] = []
        self.function_taint: dict[str, dict[str, str]] = {}
        self._initial_tainted: dict[str, str] = {}
        self._tainted_calls: dict[str, str] = {}

    def analyze(
        self,
        source: str,
        file_path: str = "<memory>",
        initial_tainted: dict[str, str] | None = None,
        tainted_calls: dict[str, str] | None = None,
    ) -> list[TaintFinding]:
        tree = ast.parse(source, filename=file_path)
        self.tainted = dict(initial_tainted or {})
        self._initial_tainted = dict(initial_tainted or {})
        self._tainted_calls = dict(tainted_calls or {})
        self.sanitized.clear()
        self.findings.clear()
        self.function_taint.clear()
        self.visit(tree)
        return list(self.findings)

    def analyze_cfg(
        self,
        source: str,
        file_path: str = "<memory>",
        initial_tainted: dict[str, str] | None = None,
        tainted_calls: dict[str, str] | None = None,
    ) -> list[TaintFinding]:
        from src.engine.cfg_builder import CFGBuilder

        tree = ast.parse(source, filename=file_path)
        self._initial_tainted = dict(initial_tainted or {})
        self._tainted_calls = dict(tainted_calls or {})
        self.findings.clear()
        self.function_taint.clear()
        units: list[tuple[str, ast.AST]] = []
        if isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef)):
            units.append((tree.name, tree))
        else:
            units.extend(
                (node.name, node)
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
            module_body = [
                node for node in tree.body
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            ]
            if module_body:
                units.append(("<module>", ast.Module(body=module_body, type_ignores=[])))

        for function_name, unit in units:
            cfg = CFGBuilder().build(unit)
            predecessors: dict[int, set[int]] = {block_id: set() for block_id in cfg.blocks}
            for source_id, block in cfg.blocks.items():
                for target_id in block.successors:
                    predecessors[target_id].add(source_id)
            incoming_taint: dict[int, dict[str, str]] = {cfg.entry: dict(self._initial_tainted)}
            incoming_sanitized: dict[int, set[str]] = {cfg.entry: set()}
            outgoing_taint: dict[int, dict[str, str]] = {}
            outgoing_sanitized: dict[int, set[str]] = {}
            pending = deque([cfg.entry])
            enqueued = {cfg.entry}
            reachable = cfg.reachable_blocks()
            while pending:
                block_id = pending.popleft()
                enqueued.discard(block_id)
                if block_id not in reachable:
                    continue
                self.tainted = dict(incoming_taint.get(block_id, {}))
                self.sanitized = set(incoming_sanitized.get(block_id, set()))
                self._transfer_cfg_block(cfg.blocks[block_id])
                taint_out = dict(self.tainted)
                sanitized_out = set(self.sanitized)
                if (
                    outgoing_taint.get(block_id) == taint_out
                    and outgoing_sanitized.get(block_id) == sanitized_out
                ):
                    continue
                outgoing_taint[block_id] = taint_out
                outgoing_sanitized[block_id] = sanitized_out
                for successor in cfg.blocks[block_id].successors:
                    if successor not in reachable:
                        continue
                    incoming_ids = [
                        predecessor for predecessor in predecessors[successor]
                        if predecessor in outgoing_taint
                    ]
                    merged_taint: dict[str, str] = {}
                    for predecessor in incoming_ids:
                        for variable, origin in outgoing_taint[predecessor].items():
                            merged_taint.setdefault(variable, origin)
                    merged_sanitized = (
                        set.intersection(*(outgoing_sanitized[p] for p in incoming_ids))
                        if incoming_ids else set()
                    )
                    if (
                        incoming_taint.get(successor) != merged_taint
                        or incoming_sanitized.get(successor) != merged_sanitized
                    ):
                        incoming_taint[successor] = merged_taint
                        incoming_sanitized[successor] = merged_sanitized
                        if successor not in enqueued:
                            pending.append(successor)
                            enqueued.add(successor)
            self.function_taint[function_name] = outgoing_taint.get(cfg.exit, {})

        unique: dict[tuple[str, int, str, str], TaintFinding] = {}
        for finding in self.findings:
            unique[(finding.rule_id, finding.line, finding.sink, finding.variable)] = finding
        self.tainted = {}
        self.sanitized = set()
        self.findings = list(unique.values())
        return list(self.findings)

    def _transfer_cfg_block(self, block: Any) -> None:
        for statement in block.statements:
            if isinstance(statement, ast.If):
                self.visit(statement.test)
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                origin = self._taint_origin(statement.iter)
                if origin:
                    for name in self._target_names(statement.target):
                        self.tainted[name] = origin
                else:
                    for name in self._target_names(statement.target):
                        self.tainted.pop(name, None)
                self.visit(statement.iter)
            elif isinstance(statement, ast.While):
                self.visit(statement.test)
            elif isinstance(statement, ast.Try):
                for child in statement.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        continue
                    self.visit(child)
            else:
                self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        outer_tainted, outer_sanitized = self.tainted, self.sanitized
        self.tainted = dict(self._initial_tainted)
        self.sanitized = set()
        for statement in node.body:
            self.visit(statement)
        self.function_taint[node.name] = dict(self.tainted)
        self.tainted, self.sanitized = outer_tainted, outer_sanitized

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        origin = self._taint_origin(node.value)
        is_sanitized = self._is_sanitizer(node.value)
        for target in node.targets:
            for name in self._target_names(target):
                if origin:
                    self.tainted[name] = origin
                    if is_sanitized:
                        self.sanitized.add(name)
                    else:
                        self.sanitized.discard(name)
                else:
                    self.tainted.pop(name, None)
                    self.sanitized.discard(name)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        origin = self._taint_origin(node.value)
        if node.value is not None:
            for name in self._target_names(node.target):
                if origin:
                    self.tainted[name] = origin
                    if self._is_sanitizer(node.value):
                        self.sanitized.add(name)
                    else:
                        self.sanitized.discard(name)
                else:
                    self.tainted.pop(name, None)
                    self.sanitized.discard(name)
            self.visit(node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        origin = self._taint_origin(node.value)
        for name in self._target_names(node.target):
            if origin:
                self.tainted[name] = origin
            else:
                self.tainted.pop(name, None)
        self.visit(node.value)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        before = dict(self.tainted)
        before_sanitized = set(self.sanitized)
        self.tainted = dict(before)
        self.sanitized = set(before_sanitized)
        for statement in node.body:
            self.visit(statement)
        body_tainted, body_sanitized = dict(self.tainted), set(self.sanitized)
        self.tainted = dict(before)
        self.sanitized = set(before_sanitized)
        for statement in node.orelse:
            self.visit(statement)
        else_tainted, else_sanitized = dict(self.tainted), set(self.sanitized)
        merged = dict(before)
        for name in body_tainted.keys() | else_tainted.keys():
            origins = [mapping[name] for mapping in (body_tainted, else_tainted) if name in mapping]
            if origins:
                merged[name] = origins[0]
        self.tainted = merged
        self.sanitized = body_sanitized & else_sanitized

    def visit_Call(self, node: ast.Call) -> None:
        name = self._call_name(node.func)
        sink_name = name.rsplit(".", 1)[-1]
        if sink_name in self.SINK_RULES:
            for argument in (*node.args, *(keyword.value for keyword in node.keywords)):
                origin = self._taint_origin(argument)
                if origin:
                    variable = self._tainted_name(argument) or ast.unparse(argument)
                    sanitized = self._is_sanitizer(argument) or variable in self.sanitized
                    self.findings.append(
                        TaintFinding(
                            self.SINK_RULES[sink_name], origin, name,
                            getattr(node, "lineno", 1), variable, sanitized,
                        )
                    )
        self.generic_visit(node)

    def _taint_origin(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return self.tainted.get(node.id)
        if isinstance(node, ast.Call):
            name = self._call_name(node.func)
            if name.rsplit(".", 1)[-1] in self.SOURCES:
                return name
            if name in self._tainted_calls:
                return self._tainted_calls[name]
        for child in ast.iter_child_nodes(node):
            origin = self._taint_origin(child)
            if origin:
                return origin
        return None

    def _tainted_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name) and node.id in self.tainted:
            return node.id
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.tainted:
                return child.id
        return None

    def _is_sanitizer(self, node: ast.AST | None) -> bool:
        return isinstance(node, ast.Call) and self._call_name(node.func).lower() in self.SANITIZERS

    @staticmethod
    def _target_names(target: ast.AST) -> set[str]:
        if isinstance(target, ast.Name):
            return {target.id}
        return {
            node.id for node in ast.walk(target)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
        }

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))
