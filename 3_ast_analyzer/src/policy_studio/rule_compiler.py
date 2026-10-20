"""Compile safe JSON/YAML rule documents into Python AST matchers."""

from __future__ import annotations

import ast
import regex
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_POLICY_BYTES = 256_000
REGEX_TIMEOUT_SECONDS = 0.05
SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_ROOT_KEYS = frozenset({"rules"})
_RULE_KEYS = frozenset(
    {
        "id",
        "node_type",
        "severity",
        "message",
        "call_names",
        "call_name_regex",
        "names",
        "name_regex",
        "attributes",
        "attribute_regex",
    }
)


class PolicyCompileError(ValueError):
    """Raised when a policy document is malformed or uses unsupported selectors."""


@dataclass(frozen=True)
class CompiledRule:
    rule_id: str
    node_class: type[ast.AST]
    severity: str
    message: str
    call_names: frozenset[str]
    call_name_regex: regex.Pattern[str] | None
    names: frozenset[str]
    name_regex: regex.Pattern[str] | None
    attributes: frozenset[str]
    attribute_regex: regex.Pattern[str] | None


def compile_rules(source: str | Path | Mapping[str, Any]) -> tuple[CompiledRule, ...]:
    """Load and validate a JSON/YAML document or an already-decoded mapping.

    Supported selectors are exact Python AST node types, call names, variable
    names, and attribute names. Regular expressions run with a strict timeout;
    policy data is never evaluated as code.
    """
    document = _load_document(source)
    if not isinstance(document, Mapping) or set(document) != _ROOT_KEYS:
        raise PolicyCompileError("policy root must contain exactly a 'rules' list")
    raw_rules = document["rules"]
    if not isinstance(raw_rules, list) or not raw_rules:
        raise PolicyCompileError("policy 'rules' must be a non-empty list")

    compiled: list[CompiledRule] = []
    seen_ids: set[str] = set()
    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, Mapping):
            raise PolicyCompileError(f"rule {index} must be an object")
        if any(not isinstance(key, str) for key in raw_rule):
            raise PolicyCompileError(f"rule {index} field names must be strings")
        unknown = set(raw_rule) - _RULE_KEYS
        if unknown:
            raise PolicyCompileError(f"rule {index} has unsupported fields: {sorted(unknown)}")
        rule_id = raw_rule.get("id")
        node_type = raw_rule.get("node_type")
        severity = raw_rule.get("severity")
        message = raw_rule.get("message")
        if not isinstance(rule_id, str) or not rule_id.strip() or len(rule_id) > 128:
            raise PolicyCompileError(f"rule {index} must have a non-empty id up to 128 characters")
        if rule_id in seen_ids:
            raise PolicyCompileError(f"duplicate rule id {rule_id!r}")
        seen_ids.add(rule_id)
        if not isinstance(node_type, str):
            raise PolicyCompileError(f"rule {rule_id!r} must specify node_type")
        node_class = getattr(ast, node_type, None)
        if not isinstance(node_class, type) or not issubclass(node_class, ast.AST):
            raise PolicyCompileError(f"rule {rule_id!r} has unsupported AST node_type {node_type!r}")
        if not isinstance(severity, str) or severity.upper() not in SEVERITIES:
            raise PolicyCompileError(f"rule {rule_id!r} has an invalid severity")
        if not isinstance(message, str) or not message.strip() or len(message) > 1_000:
            raise PolicyCompileError(f"rule {rule_id!r} must have a message up to 1000 characters")

        call_names = _string_set(raw_rule.get("call_names", []), rule_id, "call_names")
        call_name_regex = _compile_regex(raw_rule.get("call_name_regex"), rule_id, "call_name_regex")
        names = _string_set(raw_rule.get("names", []), rule_id, "names")
        name_regex = _compile_regex(raw_rule.get("name_regex"), rule_id, "name_regex")
        attributes = _string_set(raw_rule.get("attributes", []), rule_id, "attributes")
        attribute_regex = _compile_regex(
            raw_rule.get("attribute_regex"), rule_id, "attribute_regex"
        )
        if (call_names or call_name_regex is not None) and node_class is not ast.Call:
            raise PolicyCompileError(f"rule {rule_id!r}: call_names requires node_type 'Call'")
        if (names or name_regex is not None) and node_class is not ast.Name:
            raise PolicyCompileError(f"rule {rule_id!r}: names requires node_type 'Name'")
        if (attributes or attribute_regex is not None) and node_class is not ast.Attribute:
            raise PolicyCompileError(f"rule {rule_id!r}: attributes requires node_type 'Attribute'")
        if not (
            call_names
            or call_name_regex is not None
            or names
            or name_regex is not None
            or attributes
            or attribute_regex is not None
        ) and node_class in {
            ast.Call,
            ast.Name,
            ast.Attribute,
        }:
            raise PolicyCompileError(f"rule {rule_id!r} requires a selector for {node_type}")
        compiled.append(
            CompiledRule(
                rule_id=rule_id,
                node_class=node_class,
                severity=severity.upper(),
                message=message,
                call_names=call_names,
                call_name_regex=call_name_regex,
                names=names,
                name_regex=name_regex,
                attributes=attributes,
                attribute_regex=attribute_regex,
            )
        )
    return tuple(compiled)


def _load_document(source: str | Path | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(source, Mapping):
        return source
    if isinstance(source, Path):
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as error:
            raise PolicyCompileError(f"could not read policy file {source}: {error}") from error
    elif isinstance(source, str):
        candidate = Path(source)
        if "\n" not in source and len(source) < 4_096 and candidate.is_file():
            try:
                text = candidate.read_text(encoding="utf-8")
            except OSError as error:
                raise PolicyCompileError(f"could not read policy file {candidate}: {error}") from error
        else:
            text = source
    else:
        raise PolicyCompileError("policy source must be a path, text, or mapping")
    if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
        raise PolicyCompileError("policy document exceeds the size limit")
    try:
        import yaml
    except ImportError as error:
        raise ImportError("YAML policy support requires PyYAML; install analyzer requirements") from error
    try:
        document = yaml.safe_load(text)
    except (yaml.YAMLError, UnicodeError) as error:
        raise PolicyCompileError(f"could not parse policy document: {error}") from error
    if not isinstance(document, Mapping):
        raise PolicyCompileError("policy document must be an object")
    return document


def _string_set(value: Any, rule_id: str, field: str) -> frozenset[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item or len(item) > 256 for item in value
    ):
        raise PolicyCompileError(f"rule {rule_id!r} field {field!r} must be a list of strings")
    if len(set(value)) != len(value):
        raise PolicyCompileError(f"rule {rule_id!r} field {field!r} contains duplicates")
    return frozenset(value)


def _compile_regex(value: Any, rule_id: str, field: str) -> regex.Pattern[str] | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 256:
        raise PolicyCompileError(f"rule {rule_id!r} field {field!r} must be a regex up to 256 characters")
    try:
        return regex.compile(value)
    except regex.error as error:
        raise PolicyCompileError(f"rule {rule_id!r} has an invalid {field}: {error}") from error


def _regex_matches(pattern: regex.Pattern[str] | None, value: str) -> bool:
    return pattern is not None and pattern.search(value, timeout=REGEX_TIMEOUT_SECONDS) is not None


def called_function_name(node: ast.Call) -> str | None:
    parts: list[str] = []
    current: ast.expr = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def rule_matches(rule: CompiledRule, node: ast.AST) -> bool:
    if not isinstance(node, rule.node_class):
        return False
    if rule.call_names or rule.call_name_regex is not None:
        if not isinstance(node, ast.Call):
            return False
        name = called_function_name(node)
        return name is not None and (
            name in rule.call_names or _regex_matches(rule.call_name_regex, name)
        )
    if rule.names or rule.name_regex is not None:
        if not isinstance(node, ast.Name):
            return False
        return node.id in rule.names or _regex_matches(rule.name_regex, node.id)
    if rule.attributes or rule.attribute_regex is not None:
        if not isinstance(node, ast.Attribute):
            return False
        return node.attr in rule.attributes or _regex_matches(rule.attribute_regex, node.attr)
    return True
