"""Aggregate scan outcomes and persist a bounded local scan history."""

from __future__ import annotations

import json
import os
import sqlite3
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def build_scan_metrics(
    findings: Sequence[Mapping[str, Any]],
    *,
    files_received: int,
    files_analyzed: int,
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    if isinstance(files_received, bool) or not isinstance(files_received, int) or files_received < 0:
        raise ValueError("files_received must be a non-negative integer")
    if isinstance(files_analyzed, bool) or not isinstance(files_analyzed, int) or not 0 <= files_analyzed <= files_received:
        raise ValueError("files_analyzed must be between 0 and files_received")

    counts = {severity: 0 for severity in _SEVERITIES}
    reachability = {"REACHABLE_CODE": 0, "UNREACHABLE_NOISE": 0, "UNKNOWN": 0}
    by_file: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "finding_count": 0,
            "reachable": 0,
            "unreachable": 0,
            "unknown": 0,
            "max_risk_score": 0.0,
            "severity_counts": {severity: 0 for severity in _SEVERITIES},
        }
    )
    for index, finding in enumerate(findings):
        if not isinstance(finding, Mapping):
            raise ValueError(f"finding {index} must be an object")
        severity = str(finding.get("severity", "")).upper()
        if severity in counts:
            counts[severity] += 1
        state = finding.get("reachability")
        state = state if state in {"REACHABLE_CODE", "UNREACHABLE_NOISE"} else "UNKNOWN"
        reachability[state] += 1
        file_name = finding.get("file") or finding.get("file_path") or "unknown"
        if not isinstance(file_name, str):
            file_name = "unknown"
        file_metrics = by_file[file_name]
        file_metrics["finding_count"] += 1
        file_metrics[{"REACHABLE_CODE": "reachable", "UNREACHABLE_NOISE": "unreachable", "UNKNOWN": "unknown"}[state]] += 1
        if severity in counts:
            file_metrics["severity_counts"][severity] += 1
        score = finding.get("combined_risk_score", finding.get("final_score", 0))
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            file_metrics["max_risk_score"] = max(file_metrics["max_risk_score"], float(score))

    total = len(findings)
    reachable = reachability["REACHABLE_CODE"]
    analyzed_coverage = files_analyzed / files_received * 100 if files_received else 100.0
    noise_reduction = (total - reachable) / total * 100 if total else 0.0
    unreachable_rate = reachability["UNREACHABLE_NOISE"] / total * 100 if total else 0.0
    scan_time = timestamp or datetime.now(timezone.utc)
    if scan_time.tzinfo is None:
        scan_time = scan_time.replace(tzinfo=timezone.utc)

    hotspots = [
        {"file": file_name, **metrics}
        for file_name, metrics in by_file.items()
    ]
    hotspots.sort(
        key=lambda item: (
            item["max_risk_score"],
            item["reachable"],
            item["finding_count"],
            item["file"],
        ),
        reverse=True,
    )
    return {
        "scan_timestamp": scan_time.astimezone(timezone.utc).isoformat(),
        "files_received": files_received,
        "files_analyzed": files_analyzed,
        "ast_coverage_pct": round(analyzed_coverage, 2),
        "total_findings": total,
        "severity_counts": counts,
        "reachable_findings": reachable,
        "unreachable_findings": reachability["UNREACHABLE_NOISE"],
        "unverified_findings": reachability["UNKNOWN"],
        "reachability": reachability,
        "noise_reduction_pct": round(noise_reduction, 2),
        "unreachable_noise_pct": round(unreachable_rate, 2),
        "file_hotspots": hotspots,
    }


class ScanMetricsStore:
    """SQLite history for the local analyzer's dashboard and report trends."""

    def __init__(self, database_path: str | Path | None = None) -> None:
        configured_path = database_path or os.getenv("AST_SCAN_HISTORY_DB")
        self.database_path = (
            Path(configured_path)
            if configured_path
            else Path.home() / ".autoforge" / "scan_history.sqlite3"
        )
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_metrics (
                    id INTEGER PRIMARY KEY,
                    scan_timestamp TEXT NOT NULL,
                    metrics_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS scan_metrics_timestamp "
                "ON scan_metrics(scan_timestamp DESC)"
            )

    def record(self, metrics: Mapping[str, Any]) -> int:
        if not isinstance(metrics, Mapping) or not isinstance(metrics.get("scan_timestamp"), str):
            raise ValueError("metrics must include a scan_timestamp")
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    "INSERT INTO scan_metrics(scan_timestamp, metrics_json) VALUES (?, ?)",
                    (
                        metrics["scan_timestamp"],
                        json.dumps(dict(metrics), separators=(",", ":"), allow_nan=False),
                    ),
                )
                return int(cursor.lastrowid)
        except (OSError, sqlite3.Error, TypeError, ValueError) as error:
            raise RuntimeError(f"could not persist scan metrics: {error}") from error

    def history(self, limit: int = 30) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer between 1 and 100")
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT id, metrics_json FROM scan_metrics "
                    "ORDER BY scan_timestamp DESC, id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [
                {"id": row_id, **json.loads(document)}
                for row_id, document in rows
            ]
        except (OSError, sqlite3.Error, json.JSONDecodeError, TypeError) as error:
            raise RuntimeError(f"could not read scan metrics history: {error}") from error

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10.0)
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection
