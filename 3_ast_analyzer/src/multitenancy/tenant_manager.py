"""Tenant authentication, workspace isolation, and in-memory scan limits."""

from __future__ import annotations

import hmac
import re
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

_TENANT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def validate_tenant_id(tenant_id: str) -> str:
    if not isinstance(tenant_id, str) or _TENANT_ID.fullmatch(tenant_id) is None:
        raise ValueError("tenant_id must be 1-64 safe ASCII letters, digits, '.', '_' or '-'")
    return tenant_id


@dataclass(frozen=True)
class TenantJob:
    tenant_id: str
    job_id: str
    workspace: Path


class TenantManager:
    """Manage authenticated tenant workspaces and per-process scan limits.

    API keys are provided by the caller and are never persisted. Rate and
    concurrency limits are process-local; deployments with multiple workers
    should enforce shared limits at their queue or API gateway as well.
    """

    def __init__(
        self,
        workspace_root: str | Path,
        api_keys: Mapping[str, str],
        *,
        max_jobs_per_window: int = 60,
        window_seconds: float = 60.0,
        max_concurrent_jobs: int = 5,
    ) -> None:
        for name, value in (
            ("max_jobs_per_window", max_jobs_per_window),
            ("max_concurrent_jobs", max_concurrent_jobs),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or window_seconds <= 0
        ):
            raise ValueError("window_seconds must be positive")
        if not isinstance(api_keys, Mapping) or not api_keys:
            raise ValueError("api_keys must contain at least one tenant key")

        validated_keys: dict[str, str] = {}
        for tenant_id, api_key in api_keys.items():
            validate_tenant_id(tenant_id)
            if not isinstance(api_key, str) or not api_key:
                raise ValueError(f"API key for tenant {tenant_id!r} must be non-empty")
            validated_keys[tenant_id] = api_key

        self.workspace_root = Path(workspace_root).resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self._api_keys = validated_keys
        self.max_jobs_per_window = max_jobs_per_window
        self.window_seconds = float(window_seconds)
        self.max_concurrent_jobs = max_concurrent_jobs
        self._requests: dict[str, deque[float]] = {}
        self._active_jobs: dict[str, set[str]] = {}
        self._lock = threading.Lock()

    def authenticate(self, tenant_id: str, api_key: str) -> None:
        validate_tenant_id(tenant_id)
        expected = self._api_keys.get(tenant_id)
        if (
            expected is None
            or not isinstance(api_key, str)
            or not hmac.compare_digest(expected, api_key)
        ):
            raise PermissionError("invalid tenant credentials")

    def workspace_for(self, tenant_id: str, api_key: str) -> Path:
        self.authenticate(tenant_id, api_key)
        workspace = (self.workspace_root / tenant_id).resolve()
        if workspace.parent != self.workspace_root:
            raise ValueError("tenant workspace must remain inside the workspace root")
        workspace.mkdir(parents=True, exist_ok=True)
        return workspace

    def start_scan(self, tenant_id: str, api_key: str) -> TenantJob:
        workspace = self.workspace_for(tenant_id, api_key)
        now = time.monotonic()
        with self._lock:
            requests = self._requests.setdefault(tenant_id, deque())
            while requests and now - requests[0] >= self.window_seconds:
                requests.popleft()
            jobs = self._active_jobs.setdefault(tenant_id, set())
            if len(requests) >= self.max_jobs_per_window:
                raise RuntimeError("tenant scan rate limit exceeded")
            if len(jobs) >= self.max_concurrent_jobs:
                raise RuntimeError("tenant concurrent scan limit exceeded")

            job_id = uuid.uuid4().hex
            requests.append(now)
            jobs.add(job_id)
        return TenantJob(tenant_id=tenant_id, job_id=job_id, workspace=workspace)

    def finish_scan(self, tenant_id: str, api_key: str, job_id: str) -> None:
        self.authenticate(tenant_id, api_key)
        if not isinstance(job_id, str) or not job_id:
            raise ValueError("job_id must be non-empty")
        with self._lock:
            jobs = self._active_jobs.get(tenant_id, set())
            if job_id not in jobs:
                raise ValueError("scan job does not belong to this tenant or is already finished")
            jobs.remove(job_id)
