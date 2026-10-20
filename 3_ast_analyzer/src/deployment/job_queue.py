"""Small durable SQLite queue shared by the webhook API and worker service."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from src.integration.webhook_server import PullRequestEvent


@dataclass(frozen=True)
class QueuedJob:
    job_id: int
    event: PullRequestEvent
    attempts: int


class SQLiteJobQueue:
    def __init__(self, database_path: str | Path, *, max_attempts: int = 3) -> None:
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer")
        self.database_path = Path(database_path)
        self.max_attempts = max_attempts
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS pull_request_jobs (
                    id INTEGER PRIMARY KEY,
                    job_key TEXT NOT NULL UNIQUE,
                    event_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('pending', 'processing', 'completed', 'failed')
                    ),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    error TEXT
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS pull_request_jobs_ready "
                "ON pull_request_jobs(status, attempts, id)"
            )

    def enqueue(self, event: PullRequestEvent) -> bool:
        if not isinstance(event, PullRequestEvent):
            raise TypeError("event must be a PullRequestEvent")
        event_data = asdict(event)
        job_key = f"{event.repository}:{event.pull_request_number}:{event.head_sha}"
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO pull_request_jobs (job_key, event_json, status)
                    VALUES (?, ?, 'pending')
                    ON CONFLICT(job_key) DO UPDATE SET
                        event_json = excluded.event_json,
                        status = 'pending',
                        attempts = 0,
                        updated_at = CURRENT_TIMESTAMP,
                        error = NULL
                    WHERE pull_request_jobs.status = 'failed'
                    """,
                    (job_key, json.dumps(event_data, sort_keys=True)),
                )
                return cursor.rowcount == 1
        except (OSError, sqlite3.Error, TypeError, ValueError) as error:
            raise RuntimeError(f"could not enqueue pull-request event: {error}") from error

    def claim(self) -> QueuedJob | None:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT id, event_json, attempts
                    FROM pull_request_jobs
                    WHERE status = 'pending'
                       OR (status = 'failed' AND attempts < ?)
                    ORDER BY id
                    LIMIT 1
                    """,
                    (self.max_attempts,),
                ).fetchone()
                if row is None:
                    connection.commit()
                    return None
                job_id, event_json, attempts = row
                next_attempt = attempts + 1
                connection.execute(
                    """
                    UPDATE pull_request_jobs
                    SET status = 'processing', attempts = ?,
                        updated_at = CURRENT_TIMESTAMP, error = NULL
                    WHERE id = ?
                    """,
                    (next_attempt, job_id),
                )
                connection.commit()
            event = PullRequestEvent(**json.loads(event_json))
            return QueuedJob(job_id, event, next_attempt)
        except (OSError, sqlite3.Error, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError(f"could not claim pull-request job: {error}") from error

    def recover_interrupted_jobs(self) -> int:
        """Requeue jobs left in processing state by a stopped single worker."""
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """
                    UPDATE pull_request_jobs
                    SET status = CASE
                            WHEN attempts < ? THEN 'pending'
                            ELSE 'failed'
                        END,
                        updated_at = CURRENT_TIMESTAMP,
                        error = CASE
                            WHEN attempts < ? THEN 'Recovered after worker restart'
                            ELSE COALESCE(error, 'Worker stopped before completing the final attempt')
                        END
                    WHERE status = 'processing'
                    """,
                    (self.max_attempts, self.max_attempts),
                )
                return cursor.rowcount
        except sqlite3.Error as error:
            raise RuntimeError(f"could not recover interrupted jobs: {error}") from error

    def complete(self, job_id: int) -> None:
        self._update_job(job_id, "completed")

    def fail(self, job_id: int, error: str) -> None:
        if not isinstance(error, str) or not error.strip():
            raise ValueError("error must be a non-empty string")
        self._update_job(job_id, "failed", error[:2000])

    def healthcheck(self) -> bool:
        try:
            with self._connect() as connection:
                connection.execute("SELECT 1 FROM pull_request_jobs LIMIT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    def counts(self) -> dict[str, int]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT status, COUNT(*) FROM pull_request_jobs GROUP BY status"
            ).fetchall()
        counts = {"pending": 0, "processing": 0, "completed": 0, "failed": 0}
        counts.update({status: count for status, count in rows})
        return counts

    def _update_job(self, job_id: int, status: str, error: str | None = None) -> None:
        if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id < 1:
            raise ValueError("job_id must be a positive integer")
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """
                    UPDATE pull_request_jobs
                    SET status = ?, error = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND status = 'processing'
                    """,
                    (status, error, job_id),
                )
                if cursor.rowcount != 1:
                    raise ValueError(f"pull-request job {job_id} is not being processed")
        except sqlite3.Error as database_error:
            raise RuntimeError(f"could not update pull-request job {job_id}: {database_error}") from database_error

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10.0)
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection
