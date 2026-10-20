"""Evaluate tenant-specific compiled policies against bounded Python ASTs."""

from __future__ import annotations

import ast
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from src.multitenancy.sandbox_runner import ASTSandboxRunner
from src.multitenancy.tenant_manager import validate_tenant_id
from .rule_compiler import CompiledRule, compile_rules, rule_matches


class PolicyEvaluator:
    def __init__(self, sandbox_runner: ASTSandboxRunner | None = None) -> None:
        self._sandbox = sandbox_runner or ASTSandboxRunner()
        self._tenant_rules: dict[str, tuple[CompiledRule, ...]] = {}
        self._lock = threading.RLock()

    def set_policy(self, tenant_id: str, policy: str | Path | Mapping[str, Any]) -> None:
        validate_tenant_id(tenant_id)
        compiled = compile_rules(policy)
        with self._lock:
            self._tenant_rules[tenant_id] = compiled

    def evaluate(self, tenant_id: str, source: str) -> list[dict[str, Any]]:
        validate_tenant_id(tenant_id)
        with self._lock:
            rules = self._tenant_rules.get(tenant_id)
        if rules is None:
            raise LookupError(f"no security policy is configured for tenant {tenant_id!r}")
        tree = self._sandbox.parse(source)
        findings: list[dict[str, Any]] = []
        for node in ast.walk(tree):
            for rule in rules:
                try:
                    matches = rule_matches(rule, node)
                except TimeoutError as error:
                    raise RuntimeError(
                        f"regular expression timed out for policy rule {rule.rule_id!r}"
                    ) from error
                if matches:
                    findings.append(
                        {
                            "rule_id": rule.rule_id,
                            "severity": rule.severity,
                            "message": rule.message,
                            "line": getattr(node, "lineno", 1),
                            "column": getattr(node, "col_offset", 0),
                            "node_type": type(node).__name__,
                        }
                    )
        return findings
