"""HMAC-authenticated GitHub pull-request webhook receiver."""

from __future__ import annotations

import hashlib
import hmac
import inspect
import os
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, HTTPException, Request

_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
SUPPORTED_ACTIONS = frozenset({"opened", "synchronize", "reopened"})


@dataclass(frozen=True)
class PullRequestEvent:
    action: str
    repository: str
    pull_request_number: int
    head_sha: str
    diff_url: str


EventHandler = Callable[[PullRequestEvent], Awaitable[Any]]


def _pull_request_event(payload: Mapping[str, Any]) -> PullRequestEvent | None:
    action = payload.get("action")
    if action not in SUPPORTED_ACTIONS:
        return None
    pull_request = payload.get("pull_request")
    repository = payload.get("repository")
    if not isinstance(pull_request, dict) or not isinstance(repository, dict):
        raise HTTPException(status_code=400, detail="Malformed pull_request webhook payload")
    number = pull_request.get("number")
    head = pull_request.get("head")
    full_name = repository.get("full_name")
    diff_url = pull_request.get("diff_url")
    sha = head.get("sha") if isinstance(head, dict) else None
    if (
        isinstance(number, bool)
        or not isinstance(number, int)
        or number < 1
        or not isinstance(full_name, str)
        or not _REPOSITORY.fullmatch(full_name)
        or not isinstance(sha, str)
        or not _SHA.fullmatch(sha)
        or not isinstance(diff_url, str)
        or not diff_url
    ):
        raise HTTPException(status_code=400, detail="Malformed pull_request webhook fields")
    return PullRequestEvent(action, full_name, number, sha, diff_url)


def create_app(
    *,
    webhook_secret: str | None = None,
    event_handler: EventHandler | None = None,
) -> FastAPI:
    app = FastAPI(title="AutoForge GitHub Webhook", docs_url=None, redoc_url=None)
    app.state.webhook_secret = webhook_secret
    app.state.event_handler = event_handler

    @app.post("/api/v1/github/events")
    async def receive_github_event(request: Request) -> dict[str, Any]:
        secret = request.app.state.webhook_secret or os.getenv("WEBHOOK_SECRET")
        if not secret:
            raise HTTPException(status_code=503, detail="WEBHOOK_SECRET is not configured")
        supplied_signature = request.headers.get("X-Hub-Signature-256", "")
        body = await request.body()
        expected_signature = "sha256=" + hmac.new(
            secret.encode("utf-8"),
            body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected_signature, supplied_signature):
            raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature")

        if request.headers.get("X-GitHub-Event") != "pull_request":
            return {"status": "ignored", "reason": "unsupported event"}
        try:
            payload = await request.json()
        except ValueError as error:
            raise HTTPException(status_code=400, detail="Webhook body must be valid JSON") from error
        if not isinstance(payload, Mapping):
            raise HTTPException(status_code=400, detail="Webhook payload must be an object")
        event = _pull_request_event(payload)
        if event is None:
            return {"status": "ignored", "reason": "unsupported pull_request action"}

        handler = request.app.state.event_handler
        if handler is None:
            raise HTTPException(
                status_code=503,
                detail="No pull-request analysis handler is configured",
            )
        result = handler(event)
        if not inspect.isawaitable(result):
            raise TypeError("event_handler must return an awaitable")
        await result
        return {
            "status": "accepted",
            "repository": event.repository,
            "pull_request": event.pull_request_number,
            "head_sha": event.head_sha,
        }

    return app


app = create_app()
