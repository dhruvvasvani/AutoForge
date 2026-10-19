"""Build a control-flow graph for Python module or function statements."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class BasicBlock:
    block_id: int
    kind: str
    statements: list[ast.stmt] = field(default_factory=list)
    successors: dict[int, str] = field(default_factory=dict)

    @property
    def start_line(self) -> int | None:
        lines = [getattr(statement, "lineno", None) for statement in self.statements]
        return min((line for line in lines if line is not None), default=None)

    @property
    def end_line(self) -> int | None:
        lines = [getattr(statement, "end_lineno", getattr(statement, "lineno", None))
                 for statement in self.statements]
        return max((line for line in lines if line is not None), default=None)

    @property
    def code(self) -> list[str]:
        return [ast.unparse(statement) for statement in self.statements]


@dataclass
class ControlFlowGraph:
    blocks: dict[int, BasicBlock]
    entry: int
    exit: int

    def reachable_blocks(self) -> set[int]:
        reachable: set[int] = set()
        pending = [self.entry]
        while pending:
            block_id = pending.pop()
            if block_id in reachable:
                continue
            reachable.add(block_id)
            pending.extend(self.blocks[block_id].successors)
        return reachable

    def to_dict(self) -> dict[str, object]:
        return {
            "entry": self.entry,
            "exit": self.exit,
            "blocks": [
                {
                    "id": block.block_id,
                    "kind": block.kind,
                    "start_line": block.start_line,
                    "end_line": block.end_line,
                    "statements": block.code,
                    "successors": [
                        {"block": target, "kind": edge_kind}
                        for target, edge_kind in block.successors.items()
                    ],
                }
                for block in self.blocks.values()
            ],
        }


class CFGBuilder:
    def __init__(self) -> None:
        self._blocks: dict[int, BasicBlock] = {}
        self._next_id = 0
        self._exit_id: int | None = None

    def build(self, source: str | ast.AST) -> ControlFlowGraph:
        tree = ast.parse(source) if isinstance(source, str) else source
        if isinstance(tree, ast.Module):
            functions = [
                node for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            executable = [
                node for node in tree.body
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            ]
            if len(functions) == 1 and not executable:
                tree = functions[0]
        if isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef)):
            statements = tree.body
        elif isinstance(tree, ast.Module):
            statements = [
                statement for statement in tree.body
                if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            ]
        else:
            raise TypeError("CFGBuilder.build expects source, Module, or function AST")
        self._blocks = {}
        self._next_id = 0
        self._exit_id = None
        entry = self._new_block("entry").block_id
        exit_block = self._new_block("exit").block_id
        self._exit_id = exit_block
        body_entry = self._compile_sequence(statements, exit_block, None, None)
        self._edge(entry, body_entry, "flow")
        return ControlFlowGraph(self._blocks, entry, exit_block)

    def _new_block(self, kind: str, statement: ast.stmt | None = None) -> BasicBlock:
        block = BasicBlock(self._next_id, kind)
        self._next_id += 1
        if statement is not None:
            block.statements.append(statement)
        self._blocks[block.block_id] = block
        return block

    def _edge(self, source: int, target: int, kind: str) -> None:
        self._blocks[source].successors[target] = kind

    def _compile_sequence(
        self,
        statements: Iterable[ast.stmt],
        continuation: int,
        break_target: int | None,
        continue_target: int | None,
    ) -> int:
        current = continuation
        for statement in reversed(list(statements)):
            current = self._compile_statement(statement, current, break_target, continue_target)
        return current

    def _compile_statement(
        self,
        statement: ast.stmt,
        continuation: int,
        break_target: int | None,
        continue_target: int | None,
    ) -> int:
        if isinstance(statement, ast.If):
            condition = self._new_block("branch", statement)
            body = self._compile_sequence(statement.body, continuation, break_target, continue_target)
            alternate = self._compile_sequence(statement.orelse, continuation, break_target, continue_target)
            self._edge(condition.block_id, body, "true")
            self._edge(condition.block_id, alternate, "false")
            return condition.block_id

        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            condition = self._new_block("loop", statement)
            after_loop = self._compile_sequence(statement.orelse, continuation, break_target, continue_target)
            body = self._compile_sequence(
                statement.body, condition.block_id, continuation, condition.block_id
            )
            self._edge(condition.block_id, body, "true")
            self._edge(condition.block_id, after_loop, "false")
            return condition.block_id

        if isinstance(statement, (ast.With, ast.AsyncWith)):
            block = self._new_block("statement", statement)
            body = self._compile_sequence(statement.body, continuation, break_target, continue_target)
            self._edge(block.block_id, body, "flow")
            return block.block_id

        if isinstance(statement, ast.Try):
            block = self._new_block("exception", statement)
            final_entry = self._compile_sequence(
                statement.finalbody, continuation, break_target, continue_target
            ) if statement.finalbody else continuation
            normal = self._compile_sequence(statement.body, final_entry, break_target, continue_target)
            self._edge(block.block_id, normal, "normal")
            for handler in statement.handlers:
                handler_entry = self._compile_sequence(
                    handler.body, final_entry, break_target, continue_target
                )
                self._edge(block.block_id, handler_entry, "exception")
            return block.block_id

        block = self._new_block("statement", statement)
        if isinstance(statement, ast.Return):
            self._edge(block.block_id, self._exit_id if self._exit_id is not None else continuation, "return")
        elif isinstance(statement, ast.Raise):
            exit_id = self._exit_id if self._exit_id is not None else continuation
            self._edge(block.block_id, exit_id, "raise")
        elif isinstance(statement, ast.Break):
            if break_target is None:
                raise SyntaxError("'break' outside loop")
            self._edge(block.block_id, break_target, "break")
        elif isinstance(statement, ast.Continue):
            if continue_target is None:
                raise SyntaxError("'continue' outside loop")
            self._edge(block.block_id, continue_target, "continue")
        else:
            self._edge(block.block_id, continuation, "flow")
        return block.block_id
