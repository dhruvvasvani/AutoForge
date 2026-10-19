"""Client for AutoForge's internal scan result API."""

from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from post_processor import format_scan_results


class BackendClient:
    def __init__(
        self, base_url: str, timeout_seconds: float = 15, internal_token: str | None = None
    ) -> None:
        if not base_url.strip() or timeout_seconds <= 0:
            raise ValueError("base_url must be non-empty and timeout must be positive")
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.internal_token = internal_token

    @classmethod
    def from_environment(cls) -> "BackendClient":
        return cls(
            os.environ.get("AUTOFORGE_BACKEND_URL", "http://localhost:8082"),
            float(os.environ.get("AUTOFORGE_BACKEND_TIMEOUT", "15")),
            os.environ.get("AUTOFORGE_INTERNAL_SCAN_TOKEN"),
        )

    def create_scan(self, repo_full_name: str, commit_sha: str, event_type: str = "push") -> str:
        response = self._request(
            "/api/internal/scans",
            {"repoFullName": repo_full_name, "commitSha": commit_sha, "eventType": event_type},
        )
        if response.get("id") is None:
            raise RuntimeError("Backend create-scan response has no id")
        return str(response["id"])

    def submit_results(self, scan_id: str, result: dict[str, Any]) -> dict[str, Any]:
        return self._request(f"/api/internal/scans/{scan_id}/results", format_scan_results(result))

    def _request(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.internal_token:
            headers["X-AutoForge-Internal-Token"] = self.internal_token
        request = Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                data = json.loads(response.read())
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Backend returned HTTP {exc.code}: {detail}") from exc
        except (URLError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Backend request failed for {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise RuntimeError("Backend response must be a JSON object")
        return data
