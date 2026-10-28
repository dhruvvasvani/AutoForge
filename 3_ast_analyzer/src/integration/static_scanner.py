"""Run Semgrep and Checkov against an isolated set of changed source files."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

_LOGGER = logging.getLogger(__name__)
_MAX_SOURCE_BYTES = 1_000_000
_IAC_SUFFIXES = {".tf", ".yaml", ".yml", ".json"}


def scan_sources(
    sources: Mapping[str, str],
    *,
    timeout_seconds: int = 180,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Return normalized findings and explicit per-scanner statuses."""
    if not isinstance(sources, Mapping):
        raise TypeError("sources must be a mapping of relative paths to source text")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds < 1:
        raise ValueError("timeout_seconds must be a positive integer")

    statuses = {"semgrep": "skipped", "checkov": "skipped"}
    if not sources:
        return [], statuses

    findings: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="autoforge-pr-scan-") as directory:
        root = Path(directory).resolve()
        relative_paths: list[str] = []
        for relative, source in sources.items():
            path = PurePosixPath(relative)
            if (
                not isinstance(relative, str)
                or not relative
                or path.is_absolute()
                or ".." in path.parts
                or not isinstance(source, str)
            ):
                raise ValueError("sources must contain safe relative paths and string contents")
            if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
                raise ValueError(f"changed source file exceeds {_MAX_SOURCE_BYTES} bytes: {relative}")
            destination = (root / Path(*path.parts)).resolve()
            if root not in destination.parents:
                raise ValueError(f"changed source path escapes its scan directory: {relative}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(source, encoding="utf-8")
            relative_paths.append(path.as_posix())

        environment = os.environ.copy()
        environment["PYTHONUTF8"] = "1"
        environment["PYTHONIOENCODING"] = "utf-8"

        try:
            semgrep = subprocess.run(
                ["semgrep", "--config", "auto", "--json", str(root)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                env=environment,
                check=False,
            )
            if semgrep.returncode not in (0, 1):
                statuses["semgrep"] = "failed"
                _LOGGER.error("Semgrep exited with code %d: %s", semgrep.returncode, semgrep.stderr[-1000:])
            else:
                result = json.loads(semgrep.stdout)
                if not isinstance(result, dict) or not isinstance(result.get("results"), list):
                    raise ValueError("Semgrep returned malformed JSON")
                findings.extend(_semgrep_findings(result["results"], root))
                statuses["semgrep"] = "ok"
        except FileNotFoundError:
            statuses["semgrep"] = "unavailable"
            _LOGGER.error("Semgrep executable is not installed")
        except (subprocess.TimeoutExpired, json.JSONDecodeError, ValueError) as error:
            statuses["semgrep"] = "failed"
            _LOGGER.error("Semgrep scan failed: %s", error)

        iac_paths = [
            relative
            for relative in relative_paths
            if Path(relative).suffix.lower() in _IAC_SUFFIXES
        ]
        if not iac_paths:
            statuses["checkov"] = "skipped"
        else:
            try:
                checkov = subprocess.run(
                    [
                        "checkov",
                        "-d",
                        str(root),
                        "-o",
                        "json",
                        "--skip-download",
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout_seconds,
                    env=environment,
                    check=False,
                )
                if checkov.returncode not in (0, 1):
                    statuses["checkov"] = "failed"
                    _LOGGER.error("Checkov exited with code %d: %s", checkov.returncode, checkov.stderr[-1000:])
                else:
                    document = json.loads(checkov.stdout)
                    entries = document if isinstance(document, list) else [document]
                    findings.extend(_checkov_findings(entries, root))
                    statuses["checkov"] = "ok"
            except FileNotFoundError:
                statuses["checkov"] = "unavailable"
                _LOGGER.error("Checkov executable is not installed")
            except (subprocess.TimeoutExpired, json.JSONDecodeError, ValueError) as error:
                statuses["checkov"] = "failed"
                _LOGGER.error("Checkov scan failed: %s", error)

    return findings, statuses


def _relative_path(path: Any, root: Path) -> str | None:
    if not isinstance(path, str) or not path:
        return None
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(root)
        except ValueError:
            return None
    normalized = candidate.as_posix()
    if ".." in PurePosixPath(normalized).parts:
        return None
    return normalized


def _semgrep_findings(results: list[Any], root: Path) -> list[dict[str, Any]]:
    findings = []
    for result in results:
        if not isinstance(result, dict):
            continue
        extra = result.get("extra")
        start = result.get("start")
        if not isinstance(extra, dict) or not isinstance(start, dict):
            continue
        path = _relative_path(result.get("path"), root)
        line = start.get("line")
        if path is None or isinstance(line, bool) or not isinstance(line, int) or line < 1:
            continue
        findings.append(
            {
                "source": "semgrep",
                "rule_id": result.get("check_id") or "SEMGREP_FINDING",
                "file": path,
                "line": line,
                "severity": extra.get("severity", "WARNING"),
                "message": extra.get("message", "Semgrep finding"),
            }
        )
    return findings


def _checkov_findings(entries: list[Any], root: Path) -> list[dict[str, Any]]:
    findings = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        results = entry.get("results")
        failed_checks = results.get("failed_checks", []) if isinstance(results, dict) else []
        if not isinstance(failed_checks, list):
            continue
        for check in failed_checks:
            if not isinstance(check, dict):
                continue
            path = _relative_path(check.get("file_path"), root)
            line_range = check.get("file_line_range")
            line = line_range[0] if isinstance(line_range, list) and line_range else None
            if path is None or isinstance(line, bool) or not isinstance(line, int) or line < 1:
                continue
            findings.append(
                {
                    "source": "checkov",
                    "rule_id": check.get("check_id") or "CHECKOV_FINDING",
                    "file": path,
                    "line": line,
                    "severity": check.get("severity") or "MEDIUM",
                    "message": check.get("check_name") or "Checkov finding",
                }
            )
    return findings
