"""Combine static reachability with caller-supplied runtime observations."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


MAX_RUNTIME_FUNCTIONS = 10_000
MAX_FUNCTION_NAME_LENGTH = 512


def apply_runtime_observations(
    findings: Iterable[Mapping[str, Any]],
    executed_functions: Iterable[str] | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if executed_functions is None:
        return (
            [
                {**finding, "runtime_evidence": "UNAVAILABLE"}
                for finding in findings
            ],
            {
                "status": "unavailable",
                "executed_function_count": 0,
                "confirmed_static_reachable_count": 0,
            },
        )

    functions = list(executed_functions)
    if len(functions) > MAX_RUNTIME_FUNCTIONS:
        raise ValueError(f"at most {MAX_RUNTIME_FUNCTIONS} runtime functions are allowed")

    normalized_functions: set[str] = set()
    for function in functions:
        if not isinstance(function, str):
            raise ValueError("runtime function names must be strings")
        name = function.strip()
        if not name or len(name) > MAX_FUNCTION_NAME_LENGTH:
            raise ValueError(
                f"runtime function names must contain 1 to {MAX_FUNCTION_NAME_LENGTH} characters"
            )
        normalized_functions.add(name)

    enriched: list[dict[str, Any]] = []
    confirmed_count = 0
    for finding in findings:
        item = dict(finding)
        function = item.get("function")
        observed = isinstance(function, str) and function in normalized_functions
        is_static_reachable = item.get("reachability") == "REACHABLE_CODE"
        item["runtime_evidence"] = "OBSERVED" if observed else "NOT_OBSERVED"
        if observed and is_static_reachable:
            item["runtime_priority"] = "IMMEDIATE"
            confirmed_count += 1
        enriched.append(item)

    return enriched, {
        "status": "provided",
        "executed_function_count": len(normalized_functions),
        "confirmed_static_reachable_count": confirmed_count,
    }
