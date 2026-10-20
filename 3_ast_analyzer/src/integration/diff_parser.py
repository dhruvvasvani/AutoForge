"""Parse unified Git diffs and restrict findings to added lines."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

_FILE_HEADER = re.compile(r"^\+\+\+ b/(.+)$")
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_unified_diff(diff_text: str) -> dict[str, list[int]]:
    """Return added line numbers for each file in a unified diff."""
    if not isinstance(diff_text, str):
        raise TypeError("diff_text must be a string")

    changed: dict[str, set[int]] = {}
    current_file: str | None = None
    new_line: int | None = None
    in_hunk = False

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            current_file = None
            in_hunk = False
            continue
        if line.startswith("+++ ") and not in_hunk:
            file_header = _FILE_HEADER.match(line)
            current_file = file_header.group(1) if file_header else None
            if current_file is not None:
                changed.setdefault(current_file, set())
            continue
        if line.startswith("@@"):
            hunk = _HUNK_HEADER.match(line)
            if hunk is None or (current_file is None and hunk.group(2) != "0"):
                raise ValueError(f"invalid or unexpected diff hunk header: {line!r}")
            new_line = int(hunk.group(1))
            in_hunk = True
            continue
        if not in_hunk or current_file is None:
            continue
        if line.startswith("+"):
            if new_line is None:
                raise ValueError("added line appears in a zero-length new-file hunk")
            changed[current_file].add(new_line)
            new_line += 1
        elif line.startswith(" "):
            new_line += 1
        elif line.startswith("-") or line.startswith("\\"):
            continue
        else:
            raise ValueError(f"invalid unified diff line: {line!r}")

    return {path: sorted(lines) for path, lines in changed.items()}


def filter_findings_to_changed_lines(
    findings: Iterable[Mapping[str, Any]],
    changed_lines: Mapping[str, Iterable[int]],
) -> list[Mapping[str, Any]]:
    """Keep findings whose file and line occur among the diff's added lines."""
    changed = {path: set(lines) for path, lines in changed_lines.items()}
    filtered: list[Mapping[str, Any]] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, Mapping):
            raise ValueError(f"finding {index} must be an object")
        path = finding.get("file", finding.get("path"))
        line = finding.get("line", finding.get("start_line"))
        if not isinstance(path, str) or isinstance(line, bool) or not isinstance(line, int):
            raise ValueError(f"finding {index} must include a file path and integer line")
        if line in changed.get(path.replace("\\", "/"), set()):
            filtered.append(finding)
    return filtered
