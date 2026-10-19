"""Normalized multi-language parser facade."""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ParsedUnit:
    language: str
    file_path: str
    source: str
    tree: dict[str, Any]


class MultiLangParser:
    _EXTENSIONS = {
        ".py": "python",
        ".java": "java",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
    }

    def parse_file(self, file_path: str | Path) -> ParsedUnit:
        path = Path(file_path)
        language = self._EXTENSIONS.get(path.suffix.lower())
        if language is None:
            raise ValueError(f"Unsupported source extension: {path.suffix}")
        return self.parse_source(path.read_text(encoding="utf-8"), str(path), language)

    def parse_source(
        self, source: str, file_path: str = "<memory>", language: str | None = None
    ) -> ParsedUnit:
        if not isinstance(source, str):
            raise TypeError("source must be a string")
        resolved_language = (language or self._EXTENSIONS.get(Path(file_path).suffix, "")).lower()
        if resolved_language in {"py", "python"}:
            tree = ast.parse(source, filename=file_path)
            normalized = self._python_node(tree)
            resolved_language = "python"
        elif resolved_language in {"java", "javascript", "js"}:
            resolved_language = "javascript" if resolved_language == "js" else resolved_language
            normalized = self._tree_sitter_tree(source, resolved_language)
        else:
            raise ValueError(f"Unsupported language: {resolved_language or '<unknown>'}")
        return ParsedUnit(resolved_language, file_path, source, normalized)

    @classmethod
    def _python_node(cls, node: ast.AST) -> dict[str, Any]:
        result: dict[str, Any] = {"type": type(node).__name__}
        for field_name, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                result[field_name] = cls._python_node(value)
            elif isinstance(value, list):
                result[field_name] = [
                    cls._python_node(item) if isinstance(item, ast.AST) else item
                    for item in value
                ]
            else:
                result[field_name] = value
        if hasattr(node, "lineno"):
            result["line"] = node.lineno
        return result

    @staticmethod
    def _tree_sitter_tree(source: str, language: str) -> dict[str, Any]:
        try:
            from tree_sitter_language_pack import get_parser
        except ImportError as exc:
            raise RuntimeError(
                "Java and JavaScript parsing requires tree-sitter-language-pack; "
                "install 3_ast_analyzer/requirements.txt"
            ) from exc
        parser = get_parser(language)
        root = parser.parse(source.encode("utf-8")).root_node

        def normalize(node: Any) -> dict[str, Any]:
            result: dict[str, Any] = {
                "type": node.type,
                "start": {"line": node.start_point.row + 1, "column": node.start_point.column},
                "end": {"line": node.end_point.row + 1, "column": node.end_point.column},
            }
            if node.child_count:
                result["children"] = [normalize(child) for child in node.children]
            else:
                result["text"] = node.text.decode("utf-8", errors="replace")
            if node.has_error:
                result["hasError"] = True
            return result

        return normalize(root)


def ast_to_json(parsed: ParsedUnit) -> str:
    return json.dumps(
        {
            "language": parsed.language,
            "file": parsed.file_path,
            "ast": parsed.tree,
        },
        ensure_ascii=False,
    )
