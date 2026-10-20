"""Bounded AST parsing; source code is parsed but never evaluated or executed."""

from __future__ import annotations

import ast


class ASTSandboxRunner:
    """Parse untrusted Python source within explicit input and AST-size bounds.

    This is not an operating-system process sandbox. It avoids execution of
    submitted code and is intended for syntax-tree inspection only.
    """

    def __init__(self, *, max_source_bytes: int = 256_000, max_ast_nodes: int = 50_000) -> None:
        for name, value in (
            ("max_source_bytes", max_source_bytes),
            ("max_ast_nodes", max_ast_nodes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.max_source_bytes = max_source_bytes
        self.max_ast_nodes = max_ast_nodes

    def parse(self, source: str) -> ast.Module:
        if not isinstance(source, str):
            raise TypeError("source must be a string")
        if len(source.encode("utf-8")) > self.max_source_bytes:
            raise ValueError("source exceeds the AST sandbox size limit")
        try:
            tree = ast.parse(source, mode="exec")
            node_count = sum(1 for _ in ast.walk(tree))
        except (SyntaxError, RecursionError, ValueError) as error:
            raise ValueError(f"source could not be parsed safely: {error}") from error
        if node_count > self.max_ast_nodes:
            raise ValueError("source exceeds the AST sandbox node limit")
        return tree
