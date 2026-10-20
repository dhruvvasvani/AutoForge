"""Python module and function symbol collection for cross-file analysis."""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class VariableSymbol:
    name: str
    scope: str
    kind: str
    line: int


@dataclass
class ScopeSymbol:
    qualified_name: str
    kind: str
    parent: str | None
    variables: dict[str, VariableSymbol] = field(default_factory=dict)


@dataclass(frozen=True)
class FunctionSymbol:
    qualified_name: str
    module: str
    name: str
    file_path: Path
    parameters: tuple[str, ...]
    line: int
    node: ast.FunctionDef | ast.AsyncFunctionDef = field(compare=False, repr=False)


class SymbolTable:
    _EXCLUDED_DIRECTORIES = {
        ".git", ".venv", "venv", "__pycache__", ".pytest_cache",
        "node_modules", "vendor", "build", "dist", "target",
    }

    def __init__(self) -> None:
        self.modules: dict[str, Path] = {}
        self.functions: dict[str, FunctionSymbol] = {}
        self.functions_by_short_name: dict[str, list[FunctionSymbol]] = {}
        self.scopes: dict[str, ScopeSymbol] = {}
        self.imports: dict[str, dict[str, str]] = {}

    @classmethod
    def from_project(cls, project_root: str | Path) -> "SymbolTable":
        root = Path(project_root).resolve()
        if not root.is_dir():
            raise NotADirectoryError(root)
        table = cls()
        for directory, child_directories, filenames in os.walk(root):
            child_directories[:] = sorted(
                name for name in child_directories
                if name.lower() not in cls._EXCLUDED_DIRECTORIES
            )
            current_directory = Path(directory)
            for filename in sorted(filenames):
                path = current_directory / filename
                if path.suffix.lower() != ".py":
                    continue
                relative = path.relative_to(root)
                module = ".".join(relative.with_suffix("").parts)
                if module.endswith(".__init__"):
                    module = module[: -len(".__init__")]
                table.modules[module] = path
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                table._collect_scopes(tree, module, path)
                table._collect_functions(tree, module, path)
        return table

    def _collect_scopes(self, tree: ast.Module, module: str, path: Path) -> None:
        module_scope = ScopeSymbol(module, "module", None)
        self.scopes[module] = module_scope
        imports: dict[str, str] = {}

        class Collector(ast.NodeVisitor):
            def __init__(collector_self) -> None:
                collector_self.scope_stack = [module]

            def visit_ClassDef(collector_self, node: ast.ClassDef) -> None:
                parent = collector_self.scope_stack[-1]
                qualified = f"{parent}.{node.name}"
                self.scopes[qualified] = ScopeSymbol(qualified, "class", parent)
                collector_self.scope_stack.append(qualified)
                for decorator in node.decorator_list:
                    collector_self.visit(decorator)
                for base in node.bases:
                    collector_self.visit(base)
                for child in node.body:
                    collector_self.visit(child)
                collector_self.scope_stack.pop()

            def visit_FunctionDef(collector_self, node: ast.FunctionDef) -> None:
                parent = collector_self.scope_stack[-1]
                qualified = f"{parent}.{node.name}"
                self.scopes[qualified] = ScopeSymbol(qualified, "function", parent)
                collector_self.scope_stack.append(qualified)
                arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
                for argument in arguments:
                    self._add_variable(
                        qualified, argument.arg, "parameter", argument.lineno, path
                    )
                for child in node.body:
                    collector_self.visit(child)
                collector_self.scope_stack.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Import(collector_self, node: ast.Import) -> None:
                for item in node.names:
                    imports[item.asname or item.name.split(".")[0]] = (
                        item.name if item.asname else item.name.split(".")[0]
                    )
                    self._add_variable(
                        collector_self.scope_stack[-1],
                        item.asname or item.name.split(".")[0],
                        "import",
                        node.lineno,
                        path,
                    )

            def visit_ImportFrom(collector_self, node: ast.ImportFrom) -> None:
                for item in node.names:
                    if item.name == "*":
                        continue
                    imports[item.asname or item.name] = ".".join(
                        part for part in (node.module, item.name) if part
                    )
                    self._add_variable(
                        collector_self.scope_stack[-1],
                        item.asname or item.name,
                        "import",
                        node.lineno,
                        path,
                    )

            def visit_Name(collector_self, node: ast.Name) -> None:
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    self._add_variable(
                        collector_self.scope_stack[-1], node.id, "variable", node.lineno, path
                    )

        Collector().visit(tree)
        self.imports[module] = imports

    def _add_variable(
        self, scope_name: str, name: str, kind: str, line: int, path: Path
    ) -> None:
        scope = self.scopes.get(scope_name)
        if scope is None:
            return
        scope.variables[name] = VariableSymbol(name, scope_name, kind, line)

    def _collect_functions(self, tree: ast.Module, module: str, path: Path) -> None:
        def collect(nodes: Iterable[ast.stmt], prefix: str = "") -> None:
            for node in nodes:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    local_name = f"{prefix}.{node.name}" if prefix else node.name
                    args = node.args
                    parameters = tuple(
                        arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)
                    )
                    symbol = FunctionSymbol(
                        f"{module}.{local_name}" if module else local_name,
                        module,
                        local_name,
                        path,
                        parameters,
                        node.lineno,
                        node,
                    )
                    self.functions[symbol.qualified_name] = symbol
                    self.functions_by_short_name.setdefault(node.name, []).append(symbol)
                    collect(node.body, local_name)
                elif isinstance(node, ast.ClassDef):
                    collect(node.body, f"{prefix}.{node.name}" if prefix else node.name)

        collect(tree.body)

    def resolve(self, qualified_name: str) -> FunctionSymbol | None:
        return self.functions.get(qualified_name)

    def candidates(self, short_name: str) -> tuple[FunctionSymbol, ...]:
        return tuple(self.functions_by_short_name.get(short_name, ()))
