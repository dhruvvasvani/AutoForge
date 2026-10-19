"""Redis producer for uploaded-source and webhook scan requests."""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)
SCAN_JOB_QUEUE = "autoforge:scan_jobs"
SCAN_HIGH_PRIORITY_QUEUE = "autoforge:scan_jobs:high"
SCAN_LOW_PRIORITY_QUEUE = "autoforge:scan_jobs:low"
SCAN_QUEUE_ORDER = (SCAN_HIGH_PRIORITY_QUEUE, SCAN_JOB_QUEUE, SCAN_LOW_PRIORITY_QUEUE)
SCAN_STATUS_PREFIX = "autoforge:scan_status:"


class ASTScanProducer:
    def __init__(self, redis_client: Any | None = None) -> None:
        if redis_client is None:
            import redis

            redis_client = redis.Redis(
                host=os.environ.get("REDIS_HOST", "localhost"),
                port=int(os.environ.get("REDIS_PORT", "6379")),
                db=int(os.environ.get("REDIS_DB", "0")),
                decode_responses=True,
                socket_connect_timeout=5,
            )
        self.redis_client = redis_client

    def enqueue_scan_request(
        self,
        repository: dict[str, Any],
        files: dict[str, str],
        scan_id: str | None = None,
        priority: str = "normal",
    ) -> dict[str, Any]:
        if not isinstance(repository, dict) or not isinstance(files, dict) or not files:
            raise ValueError("repository metadata and non-empty source files are required")
        if any(not isinstance(path, str) or not path for path in files):
            raise ValueError("source paths must be non-empty strings")
        if any(not isinstance(source, str) for source in files.values()):
            raise ValueError("source contents must be strings")
        return self._enqueue({
            "scan_id": (scan_id or str(uuid.uuid4())).strip(),
            "repository": repository,
            "files": files,
            "priority": priority,
        })

    def enqueue_webhook_scan(
        self,
        repository: dict[str, Any],
        commit_sha: str,
        branch: str,
        changed_files: list[str],
        event_type: str,
        scan_id: str,
        author: str = "",
        priority: str = "normal",
    ) -> dict[str, Any]:
        if not isinstance(repository, dict) or not repository.get("clone_url"):
            raise ValueError("repository requires clone_url")
        if not commit_sha or not scan_id:
            raise ValueError("commit_sha and scan_id are required")
        return self._enqueue({
            "scan_id": scan_id.strip(),
            "repository": repository,
            "commit_sha": commit_sha,
            "branch": branch,
            "changed_files": changed_files,
            "event_type": event_type,
            "author": author,
            "post_results_to_backend": True,
            "priority": priority,
        })

    def _enqueue(self, job: dict[str, Any]) -> dict[str, Any]:
        if not job["scan_id"]:
            raise ValueError("scan_id must not be empty")
        priority = str(job.get("priority", "normal")).lower()
        queue_name = {
            "critical": SCAN_HIGH_PRIORITY_QUEUE,
            "high": SCAN_HIGH_PRIORITY_QUEUE,
            "normal": SCAN_JOB_QUEUE,
            "low": SCAN_LOW_PRIORITY_QUEUE,
        }.get(priority)
        if queue_name is None:
            raise ValueError("priority must be critical, high, normal, or low")
        job["status"] = "QUEUED"
        job["priority"] = priority
        job["created_at"] = datetime.now(timezone.utc).isoformat()
        self.redis_client.hset(
            f"{SCAN_STATUS_PREFIX}{job['scan_id']}",
            mapping={"scan_id": job["scan_id"], "status": "QUEUED", "priority": priority},
        )
        queued = self.redis_client.rpush(queue_name, json.dumps(job))
        if queued is None:
            raise RuntimeError("Redis did not confirm job queueing")
        logger.info("Queued scan %s", job["scan_id"])
        return job
