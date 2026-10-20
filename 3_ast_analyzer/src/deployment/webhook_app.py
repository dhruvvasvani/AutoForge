"""Production webhook app that queues verified events for the worker service."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re

from fastapi import FastAPI, HTTPException, Request, Response

from src.integration.webhook_server import PullRequestEvent, create_app
from src.monitoring.logger import get_security_logger, log_security_event
from src.monitoring.metrics_collector import MetricsCollector
from src.policy.rule_tuning import RuleTuner
from .job_queue import SQLiteJobQueue


def create_webhook_app(
    *,
    webhook_secret: str | None = None,
    database_path: str | None = None,
    repository: str | None = None,
) -> FastAPI:
    secret = webhook_secret if webhook_secret is not None else os.getenv("WEBHOOK_SECRET")
    queue_path = database_path or os.getenv("JOB_DB_PATH", "/data/jobs.sqlite3")
    configured_repository = repository or os.getenv("GITHUB_REPOSITORY")
    queue = SQLiteJobQueue(queue_path)
    metrics = MetricsCollector()
    rule_tuner = RuleTuner(
        feedback_path=os.getenv(
            "FEEDBACK_PATH",
            "/data/false_positive_feedback.jsonl",
        )
    )

    async def enqueue_event(event: PullRequestEvent) -> None:
        if not configured_repository:
            raise HTTPException(status_code=503, detail="GITHUB_REPOSITORY is not configured")
        if event.repository.casefold() != configured_repository.casefold():
            raise HTTPException(status_code=403, detail="Webhook repository is not configured")
        queue.enqueue(event)

    app = create_app(webhook_secret=secret, event_handler=enqueue_event)
    app.state.job_queue = queue
    app.state.metrics = metrics
    app.state.rule_tuner = rule_tuner

    @app.post("/api/v1/github/feedback")
    async def submit_feedback(request: Request) -> dict[str, str]:
        secret = request.app.state.webhook_secret or os.getenv("WEBHOOK_SECRET")
        if not secret:
            raise HTTPException(status_code=503, detail="WEBHOOK_SECRET is not configured")
        body = await request.body()
        supplied_signature = request.headers.get("X-Hub-Signature-256", "")
        expected_signature = "sha256=" + hmac.new(
            secret.encode("utf-8"),
            body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected_signature, supplied_signature):
            raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature")
        if request.headers.get("X-GitHub-Event") != "pull_request_review_comment":
            raise HTTPException(status_code=400, detail="Expected pull_request_review_comment event")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as error:
            raise HTTPException(status_code=400, detail="Webhook body must be valid JSON") from error
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="Webhook payload must be an object")
        comment = payload.get("comment")
        repository = payload.get("repository")
        pull_request = payload.get("pull_request")
        author = comment.get("user") if isinstance(comment, dict) else None
        author = author.get("login") if isinstance(author, dict) else None
        body_text = comment.get("body") if isinstance(comment, dict) else None
        full_name = repository.get("full_name") if isinstance(repository, dict) else None
        number = pull_request.get("number") if isinstance(pull_request, dict) else None
        if (
            not isinstance(author, str)
            or not isinstance(body_text, str)
            or not isinstance(full_name, str)
            or isinstance(number, bool)
            or not isinstance(number, int)
            or number < 1
        ):
            raise HTTPException(status_code=400, detail="Malformed review-comment payload")
        if (
            not configured_repository
            or full_name.casefold() != configured_repository.casefold()
        ):
            raise HTTPException(status_code=403, detail="Feedback repository is not configured")
        command = re.fullmatch(
            r"\s*/autoforge\s+false-positive\s+([0-9a-f]{64})\s+(.+?)\s*",
            body_text,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if command is None:
            return {"status": "ignored", "reason": "no false-positive command"}
        fingerprint, reason = command.groups()
        try:
            request.app.state.rule_tuner.submit_false_positive_fingerprint(
                fingerprint.lower(),
                reason=reason,
                submitted_by=author,
                repository=full_name,
                pull_request=number,
            )
        except (TypeError, ValueError) as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        log_security_event(
            "false_positive.feedback",
            outcome="submitted",
            logger=get_security_logger(),
            repository=full_name,
            pull_request=number,
            submitted_by=author,
            fingerprint=fingerprint.lower(),
        )
        return {"status": "submitted", "fingerprint": fingerprint.lower()}

    @app.get("/healthz")
    async def healthcheck() -> dict[str, str]:
        if not app.state.webhook_secret:
            raise HTTPException(status_code=503, detail="WEBHOOK_SECRET is not configured")
        if not configured_repository:
            raise HTTPException(status_code=503, detail="GITHUB_REPOSITORY is not configured")
        if not queue.healthcheck():
            raise HTTPException(status_code=503, detail="Job queue is unavailable")
        return {"status": "ready"}

    @app.get("/metrics")
    async def metrics_endpoint() -> Response:
        return Response(
            content=metrics.render(),
            media_type=metrics.content_type,
        )

    return app


app = create_webhook_app()
