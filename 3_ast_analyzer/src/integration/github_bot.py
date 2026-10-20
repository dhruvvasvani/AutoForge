"""Async GitHub REST API client for pull-request reviews, statuses, and SARIF."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

import httpx

from src.policy.rule_tuning import finding_fingerprint

_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class GitHubBot:
    def __init__(
        self,
        repository: str,
        token: str,
        *,
        client: httpx.AsyncClient | None = None,
        api_url: str = "https://api.github.com",
    ) -> None:
        if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
            raise ValueError("repository must be an owner/repository name")
        if not isinstance(token, str) or not token.strip():
            raise ValueError("GitHub token must not be empty")
        if not isinstance(api_url, str) or not api_url.startswith("https://"):
            raise ValueError("api_url must use HTTPS")
        self.repository = repository
        self._base_url = f"{api_url.rstrip('/')}/repos/{repository}"
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=20.0,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> GitHubBot:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        await self.aclose()

    async def post_review(
        self,
        pull_request_number: int,
        findings: Sequence[Mapping[str, Any]],
        *,
        summary: str,
    ) -> dict[str, Any] | None:
        self._validate_pull_request_number(pull_request_number)
        comments = []
        for index, finding in enumerate(findings):
            if not isinstance(finding, Mapping):
                raise ValueError(f"finding {index} must be an object")
            path = finding.get("file", finding.get("path"))
            line = finding.get("line", finding.get("start_line"))
            severity = finding.get("severity", "LOW")
            if (
                not isinstance(path, str)
                or not path
                or path.startswith(("/", "\\"))
                or ".." in path.replace("\\", "/").split("/")
            ):
                raise ValueError(f"finding {index} has an invalid relative file path")
            if isinstance(line, bool) or not isinstance(line, int) or line < 1:
                raise ValueError(f"finding {index} has an invalid line number")
            if not isinstance(severity, str) or severity.upper() not in _SEVERITIES:
                raise ValueError(f"finding {index} has an invalid severity")
            message = finding.get("message", "Security finding detected")
            remediation = finding.get("remediation")
            if not isinstance(message, str) or not message:
                raise ValueError(f"finding {index} has an invalid message")
            body = f"**{severity.upper()}**: {message}"
            if remediation is not None:
                if not isinstance(remediation, str):
                    raise ValueError(f"finding {index} has an invalid remediation")
                body += f"\n\n**Remediation:** {remediation}"
            fingerprint = finding_fingerprint(finding)
            body += (
                f"\n\nAutoForge finding fingerprint: `{fingerprint}`"
                "\nTo report a false positive, add a review comment:"
                f" `/autoforge false-positive {fingerprint} <reason>`."
            )
            comments.append(
                {"path": path.replace("\\", "/"), "line": line, "side": "RIGHT", "body": body}
            )
        if not comments:
            return None
        response = await self._client.post(
            f"{self._base_url}/pulls/{pull_request_number}/reviews",
            json={"body": summary, "event": "COMMENT", "comments": comments},
        )
        response.raise_for_status()
        return response.json()

    async def fetch_pull_request_diff(self, pull_request_number: int) -> str:
        self._validate_pull_request_number(pull_request_number)
        response = await self._client.get(
            f"{self._base_url}/pulls/{pull_request_number}",
            headers={"Accept": "application/vnd.github.diff"},
        )
        response.raise_for_status()
        return response.text

    async def post_commit_status(
        self,
        commit_sha: str,
        *,
        passed: bool,
        description: str,
        context: str = "autoforge/security-gate",
    ) -> dict[str, Any]:
        self._validate_sha(commit_sha)
        if not isinstance(passed, bool):
            raise ValueError("passed must be a boolean")
        if not isinstance(description, str) or not description.strip():
            raise ValueError("description must not be empty")
        if not isinstance(context, str) or not context.strip():
            raise ValueError("context must not be empty")
        response = await self._client.post(
            f"{self._base_url}/statuses/{commit_sha}",
            json={
                "state": "success" if passed else "failure",
                "description": description[:140],
                "context": context,
            },
        )
        response.raise_for_status()
        return response.json()

    async def upload_sarif(
        self,
        sarif: str | bytes | Mapping[str, Any],
        *,
        commit_sha: str,
        ref: str,
        tool_name: str = "AutoForge AST Analyzer",
        category: str | None = None,
    ) -> dict[str, Any]:
        self._validate_sha(commit_sha)
        if not isinstance(ref, str) or not ref.startswith("refs/") or any(c.isspace() for c in ref):
            raise ValueError("ref must be a Git reference beginning with 'refs/'")
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("tool_name must not be empty")
        if category is not None and (not isinstance(category, str) or not category.strip()):
            raise ValueError("category must be non-empty when provided")
        if isinstance(sarif, Mapping):
            sarif_bytes = json.dumps(sarif, ensure_ascii=False).encode("utf-8")
        elif isinstance(sarif, str):
            sarif_bytes = sarif.encode("utf-8")
        elif isinstance(sarif, bytes):
            sarif_bytes = sarif
        else:
            raise TypeError("sarif must be a JSON object, string, or bytes")
        try:
            sarif_document = json.loads(sarif_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("sarif must contain valid JSON") from error
        if (
            not isinstance(sarif_document, Mapping)
            or sarif_document.get("version") != "2.1.0"
            or not isinstance(sarif_document.get("runs"), list)
        ):
            raise ValueError("sarif must be a SARIF 2.1.0 report with a runs array")
        payload: dict[str, Any] = {
            "commit_sha": commit_sha,
            "ref": ref,
            "sarif": base64.b64encode(sarif_bytes).decode("ascii"),
            "tool_name": tool_name,
        }
        if category is not None:
            payload["analysis_category"] = category
        response = await self._client.post(
            f"{self._base_url}/code-scanning/sarifs",
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _validate_sha(commit_sha: str) -> None:
        if not isinstance(commit_sha, str) or not _SHA.fullmatch(commit_sha):
            raise ValueError("commit_sha must be a 40-character hexadecimal SHA")

    @staticmethod
    def _validate_pull_request_number(pull_request_number: int) -> None:
        if (
            isinstance(pull_request_number, bool)
            or not isinstance(pull_request_number, int)
            or pull_request_number < 1
        ):
            raise ValueError("pull_request_number must be a positive integer")
