"""Fixed-width, language-neutral structural features for normalized ASTs."""

from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

FEATURE_NAMES = (
    "node_count", "max_depth", "average_depth", "function_nodes", "call_nodes",
    "identifier_nodes", "literal_nodes", "branch_nodes", "loop_nodes",
    "assignment_nodes", "return_nodes", "import_nodes", "binary_nodes",
    "string_literal_nodes", "taint_source_markers", "sink_markers",
)


def extract_features(tree: Mapping[str, Any], source: str = "") -> list[float]:
    counts: Counter[str] = Counter()
    depths: list[int] = []

    def walk(node: Any, depth: int) -> None:
        if isinstance(node, Mapping):
            kind = str(node.get("type", "")).lower()
            if kind:
                counts[kind] += 1
                depths.append(depth)
            for key, value in node.items():
                if key not in {"type", "line", "start", "end"}:
                    walk(value, depth + 1)
        elif isinstance(node, (list, tuple)):
            for value in node:
                walk(value, depth)

    walk(tree, 0)
    total = len(depths)

    def matching(*fragments: str) -> int:
        return sum(count for kind, count in counts.items() if any(part in kind for part in fragments))

    lowered_source = source.lower()
    return [
        float(total),
        float(max(depths, default=0)),
        (sum(depths) / total) if total else 0.0,
        float(matching("function", "methoddeclaration", "method_definition")),
        float(matching("call", "invocation")),
        float(matching("identifier", "name")),
        float(matching("literal", "constant")),
        float(matching("if", "conditional", "switch")),
        float(matching("for", "while", "loop")),
        float(matching("assign", "variabledeclaration")),
        float(matching("return")),
        float(matching("import")),
        float(matching("binary", "infix")),
        float(matching("string")),
        float(sum(lowered_source.count(marker) for marker in (
            "getparameter(", "request.args", "request.get(", "input("
        ))),
        float(sum(lowered_source.count(marker) for marker in (
            "execute(", "executequery(", "system(", "popen("
        ))),
    ]
