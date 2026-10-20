"""Persist tenant-isolated feedback and explicitly labeled training examples."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.multitenancy.tenant_manager import validate_tenant_id

_FEEDBACK_TYPES = {"false_positive": 0, "true_positive": 1}


@dataclass(frozen=True)
class FeedbackEntry:
    feedback_id: int
    tenant_id: str
    finding_id: str
    feedback: str
    reason: str
    submitted_by: str
    training_example: dict[str, Any]


class FeedbackCollector:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS developer_feedback (
                        id INTEGER PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        finding_id TEXT NOT NULL,
                        feedback TEXT NOT NULL CHECK (
                            feedback IN ('false_positive', 'true_positive')
                        ),
                        reason TEXT NOT NULL,
                        submitted_by TEXT NOT NULL,
                        training_example_json TEXT,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        trained_at TEXT,
                        UNIQUE (tenant_id, finding_id, feedback)
                    )
                    """
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS developer_feedback_pending "
                    "ON developer_feedback(tenant_id, trained_at, id)"
                )
        except sqlite3.Error as error:
            raise RuntimeError(f"could not initialize feedback database: {error}") from error

    def record_feedback(
        self,
        tenant_id: str,
        finding_id: str,
        feedback: str,
        *,
        reason: str = "",
        submitted_by: str = "",
        training_example: Mapping[str, Any] | None = None,
    ) -> int:
        validate_tenant_id(tenant_id)
        if not isinstance(finding_id, str) or not finding_id.strip() or len(finding_id) > 256:
            raise ValueError("finding_id must be a non-empty string up to 256 characters")
        if not isinstance(feedback, str) or feedback not in _FEEDBACK_TYPES:
            raise ValueError("feedback must be 'false_positive' or 'true_positive'")
        if not isinstance(reason, str) or len(reason) > 2_000:
            raise ValueError("reason must be a string up to 2000 characters")
        if not isinstance(submitted_by, str) or len(submitted_by) > 256:
            raise ValueError("submitted_by must be a string up to 256 characters")

        example_json = None
        if training_example is not None:
            if not isinstance(training_example, Mapping):
                raise ValueError("training_example must be an object")
            code = training_example.get("code", training_example.get("source"))
            label = training_example.get("label")
            if not isinstance(code, str) or not code.strip():
                raise ValueError("training_example must contain non-empty code")
            if isinstance(label, bool) or not isinstance(label, int) or label not in (0, 1):
                raise ValueError("training_example label must be 0 or 1")
            if label != _FEEDBACK_TYPES[feedback]:
                raise ValueError("training_example label must agree with feedback type")
            example_json = json.dumps({"code": code, "label": label}, ensure_ascii=False)

        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO developer_feedback
                        (tenant_id, finding_id, feedback, reason, submitted_by, training_example_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (tenant_id, finding_id, feedback, reason, submitted_by, example_json),
                )
                feedback_id = cursor.lastrowid
                if feedback_id is None:
                    raise RuntimeError("feedback insert did not return a database ID")
                return feedback_id
        except sqlite3.IntegrityError as error:
            raise ValueError("feedback for this finding and label was already recorded") from error
        except sqlite3.Error as error:
            raise RuntimeError(f"could not record developer feedback: {error}") from error

    def pending_training_examples(
        self, tenant_id: str, *, limit: int = 1_000
    ) -> list[FeedbackEntry]:
        validate_tenant_id(tenant_id)
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT id, tenant_id, finding_id, feedback, reason, submitted_by,
                           training_example_json
                    FROM developer_feedback
                    WHERE tenant_id = ? AND trained_at IS NULL
                      AND training_example_json IS NOT NULL
                    ORDER BY id
                    LIMIT ?
                    """,
                    (tenant_id, limit),
                ).fetchall()
        except sqlite3.Error as error:
            raise RuntimeError(f"could not load pending feedback: {error}") from error
        return [
            FeedbackEntry(
                feedback_id=row[0],
                tenant_id=row[1],
                finding_id=row[2],
                feedback=row[3],
                reason=row[4],
                submitted_by=row[5],
                training_example=json.loads(row[6]),
            )
            for row in rows
        ]

    def mark_trained(self, tenant_id: str, feedback_ids: Sequence[int]) -> None:
        validate_tenant_id(tenant_id)
        if not isinstance(feedback_ids, Sequence) or isinstance(feedback_ids, (str, bytes)):
            raise ValueError("feedback_ids must be a sequence of positive integers")
        ids = list(feedback_ids)
        if not ids:
            return
        if any(isinstance(item, bool) or not isinstance(item, int) or item < 1 for item in ids):
            raise ValueError("feedback_ids must contain positive integers")
        if len(set(ids)) != len(ids):
            raise ValueError("feedback_ids must not contain duplicates")
        placeholders = ",".join("?" for _ in ids)
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    f"""
                    UPDATE developer_feedback SET trained_at = CURRENT_TIMESTAMP
                    WHERE tenant_id = ? AND trained_at IS NULL
                      AND training_example_json IS NOT NULL AND id IN ({placeholders})
                    """,
                    (tenant_id, *ids),
                )
                if cursor.rowcount != len(ids):
                    raise ValueError("one or more feedback IDs are not pending for this tenant")
        except sqlite3.Error as error:
            raise RuntimeError(f"could not mark feedback as trained: {error}") from error

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10.0)
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection
