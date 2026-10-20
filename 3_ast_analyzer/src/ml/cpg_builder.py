"""Build lightweight Python code-property graphs from the standard AST."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from collections.abc import Iterable, Mapping

EDGE_TYPES = {"ast": 0, "cfg": 1, "dfg": 2}


@dataclass(frozen=True)
class CPGNode:
    node_id: int
    kind: str
    text: str
    line: int


@dataclass(frozen=True)
class CPGGraph:
    nodes: tuple[CPGNode, ...]
    edges: tuple[tuple[int, int, str], ...]
    label: int | None = None

    def edges_of_type(self, edge_type: str) -> tuple[tuple[int, int, str], ...]:
        if edge_type not in EDGE_TYPES:
            raise ValueError(f"unsupported CPG edge type: {edge_type}")
        return tuple(edge for edge in self.edges if edge[2] == edge_type)


def build_cpg(source: str, label: int | None = None) -> CPGGraph:
    """Build AST, approximate CFG, and lexical DFG edges for Python source."""
    if not isinstance(source, str):
        raise TypeError("source must be a string")
    if label is not None and (
        isinstance(label, bool) or not isinstance(label, int) or label not in (0, 1)
    ):
        raise ValueError("label must be 0, 1, or None")

    tree = ast.parse(source)
    ast_nodes = list(ast.walk(tree))
    node_ids = {id(node): index for index, node in enumerate(ast_nodes)}
    nodes = tuple(
        CPGNode(
            node_id=index,
            kind=type(node).__name__,
            text=_node_text(node, source),
            line=getattr(node, "lineno", 1),
        )
        for index, node in enumerate(ast_nodes)
    )
    edges: set[tuple[int, int, str]] = set()

    for parent in ast_nodes:
        for child in ast.iter_child_nodes(parent):
            edges.add((node_ids[id(parent)], node_ids[id(child)], "ast"))

    _add_cfg_edges(tree, node_ids, edges)
    _add_dfg_edges(tree, node_ids, edges)
    return CPGGraph(nodes, tuple(sorted(edges)), label)


def merge_cpg_graphs(
    graphs: Mapping[str, CPGGraph],
    cross_file_edges: Iterable[tuple[str, int, str, int]] = (),
) -> CPGGraph:
    """Merge file graphs and add explicit (source file/node, target file/node) DFG edges."""
    if not graphs:
        raise ValueError("at least one file graph is required")
    nodes: list[CPGNode] = []
    edges: set[tuple[int, int, str]] = set()
    offsets: dict[str, int] = {}
    for path, graph in graphs.items():
        if not isinstance(path, str) or not path:
            raise ValueError("graph paths must be non-empty strings")
        offsets[path] = len(nodes)
        offset = offsets[path]
        nodes.extend(
            CPGNode(
                node_id=offset + index,
                kind=node.kind,
                text=node.text,
                line=node.line,
            )
            for index, node in enumerate(graph.nodes)
        )
        edges.update(
            (source + offsets[path], target + offsets[path], edge_type)
            for source, target, edge_type in graph.edges
        )

    for source_path, source_node, target_path, target_node in cross_file_edges:
        if source_path not in graphs or target_path not in graphs:
            raise ValueError("cross-file edge references an unknown file")
        if (
            isinstance(source_node, bool)
            or not isinstance(source_node, int)
            or not 0 <= source_node < len(graphs[source_path].nodes)
            or isinstance(target_node, bool)
            or not isinstance(target_node, int)
            or not 0 <= target_node < len(graphs[target_path].nodes)
        ):
            raise ValueError("cross-file edge contains an invalid node id")
        edges.add(
            (
                offsets[source_path] + source_node,
                offsets[target_path] + target_node,
                "dfg",
            )
        )

    return CPGGraph(tuple(nodes), tuple(sorted(edges)))


def _node_text(node: ast.AST, source: str) -> str:
    text = ast.get_source_segment(source, node)
    if text is None:
        text = ast.unparse(node)
    return text[:512]


def _add_cfg_edges(
    tree: ast.Module,
    node_ids: dict[int, int],
    edges: set[tuple[int, int, str]],
) -> None:
    def connect_sequence(statements: list[ast.stmt]) -> None:
        for current, following in zip(statements, statements[1:]):
            edges.add((node_ids[id(current)], node_ids[id(following)], "cfg"))

        for statement in statements:
            if isinstance(statement, (ast.If, ast.For, ast.AsyncFor, ast.While)):
                for body in (statement.body, statement.orelse):
                    if body:
                        edges.add((node_ids[id(statement)], node_ids[id(body[0])], "cfg"))
                    connect_sequence(body)
            elif isinstance(statement, (ast.With, ast.AsyncWith, ast.Try)):
                body = statement.body
                if body:
                    edges.add((node_ids[id(statement)], node_ids[id(body[0])], "cfg"))
                connect_sequence(body)
                for handler in getattr(statement, "handlers", ()):
                    if handler.body:
                        edges.add((node_ids[id(statement)], node_ids[id(handler.body[0])], "cfg"))
                    connect_sequence(handler.body)
                connect_sequence(getattr(statement, "finalbody", []))
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                connect_sequence(statement.body)

    connect_sequence(tree.body)


def _add_dfg_edges(
    tree: ast.Module,
    node_ids: dict[int, int],
    edges: set[tuple[int, int, str]],
) -> None:
    definitions: dict[str, int] = {}

    class DataFlowVisitor(ast.NodeVisitor):
        def visit_arg(self, node: ast.arg) -> None:
            definitions[node.arg] = node_ids[id(node)]

        def visit_Assign(self, node: ast.Assign) -> None:
            self.visit(node.value)
            for target in node.targets:
                self._visit_store_target(target)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if node.value is not None:
                self.visit(node.value)
            self.visit(node.annotation)
            self._visit_store_target(node.target)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            self._visit_load_target(node.target)
            self.visit(node.value)
            self._visit_store_target(node.target)

        def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
            self.visit(node.value)
            self._visit_store_target(node.target)

        def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
            self.visit(node.iter)
            self._visit_store_target(node.target)
            for statement in (*node.body, *node.orelse):
                self.visit(statement)

        def _visit_store_target(self, target: ast.AST) -> None:
            self.visit(target)

        def _visit_load_target(self, target: ast.AST) -> None:
            for child in ast.walk(target):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                    self.visit(child)

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, ast.Load):
                definition = definitions.get(node.id)
                if definition is not None:
                    edges.add((definition, node_ids[id(node)], "dfg"))
            elif isinstance(node.ctx, (ast.Store, ast.Param)):
                definitions[node.id] = node_ids[id(node)]

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_scoped(node)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Lambda(self, node: ast.Lambda) -> None:
            self._visit_scoped(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            for decorator in node.decorator_list:
                self.visit(decorator)
            for base in node.bases:
                self.visit(base)
            for keyword in node.keywords:
                self.visit(keyword.value)
            self._visit_scoped(node)

        def _visit_scoped(self, node: ast.AST) -> None:
            previous = definitions.copy()
            definitions.clear()
            for child in ast.iter_child_nodes(node):
                self.visit(child)
            definitions.clear()
            definitions.update(previous)

    DataFlowVisitor().visit(tree)
