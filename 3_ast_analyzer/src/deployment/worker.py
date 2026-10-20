"""Durable asynchronous GitHub pull-request analysis worker."""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import signal
from collections.abc import Mapping
from urllib.parse import quote
from typing import Any

import httpx

from src.analysis.taint_engine import TaintEngine
from src.integration.diff_parser import filter_findings_to_changed_lines, parse_unified_diff
from src.integration.github_bot import GitHubBot
from src.integration.webhook_server import PullRequestEvent
from src.monitoring.logger import get_security_logger, log_security_event
from src.monitoring.metrics_collector import MetricsCollector
from src.policy.rule_tuning import RuleTuner
from src.reporting.sarif_generator import SARIFReporter
from src.scoring.vulnerability_scorer import VulnerabilityScorer

from .job_queue import QueuedJob, SQLiteJobQueue

_LOGGER = logging.getLogger(__name__)
_GITHUB_API = "https://api.github.com"
_MAX_PR_FILES = 500
_MAX_PARALLEL_CONTENT_REQUESTS = 8


class PullRequestWorker:
    def __init__(
        self,
        queue: SQLiteJobQueue,
        *,
        token: str,
        metrics: MetricsCollector | None = None,
        rule_tuner: RuleTuner | None = None,
        repository: str | None = None,
    ) -> None:
        if not isinstance(token, str) or not token.strip():
            raise ValueError("GITHUB_TOKEN must be configured for the worker")
        self.queue = queue
        self.token = token
        self.metrics = metrics or MetricsCollector()
        configured_repository = repository or os.getenv("GITHUB_REPOSITORY")
        if not configured_repository:
            raise ValueError("GITHUB_REPOSITORY must be configured for the worker")
        self.repository = configured_repository
        self.rule_tuner = rule_tuner or RuleTuner(
            feedback_path=os.getenv(
                "FEEDBACK_PATH",
                "/data/false_positive_feedback.jsonl",
            )
        )

    async def run_once(self) -> bool:
        job = await asyncio.to_thread(self.queue.claim)
        if job is None:
            return False
        try:
            await self.process(job)
        except Exception as error:
            _LOGGER.exception("Pull-request analysis job %s failed", job.job_id)
            await asyncio.to_thread(self.queue.fail, job.job_id, str(error))
            log_security_event(
                "pull_request.analysis",
                outcome="failed",
                logger=get_security_logger(),
                repository=job.event.repository,
                pull_request=job.event.pull_request_number,
                attempt=job.attempts,
                error_type=type(error).__name__,
            )
        else:
            await asyncio.to_thread(self.queue.complete, job.job_id)
        return True

    async def process(self, job: QueuedJob) -> None:
        event = job.event
        if event.repository.casefold() != self.repository.casefold():
            raise ValueError("queued webhook repository does not match configured repository")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        async with httpx.AsyncClient(headers=headers, timeout=30.0) as client:
            async with GitHubBot(event.repository, self.token, client=client) as bot:
                diff_text = await bot.fetch_pull_request_diff(event.pull_request_number)
                changed_lines = parse_unified_diff(diff_text)
                files = await self._fetch_pull_request_files(client, event)
                with self.metrics.track_scan():
                    findings, unsupported_files = await self._analyze_changed_python_files(
                        client,
                        event,
                        changed_lines,
                        files,
                    )
                changed_findings = filter_findings_to_changed_lines(findings, changed_lines)
                scored_findings = VulnerabilityScorer.score_findings(changed_findings)
                gate = self.rule_tuner.evaluate(scored_findings)
                self.metrics.record_findings(scored_findings)
                self.metrics.update_memory_usage()

                if unsupported_files:
                    gate["passed"] = False
                    gate["status"] = "FAILED"
                    gate["blockers"].append(
                        {
                            "rule": "unsupported_languages",
                            "files": unsupported_files[:20],
                            "count": len(unsupported_files),
                        }
                    )
                    gate["summary"] += (
                        f"; FAILED: {len(unsupported_files)} changed non-Python file(s) "
                        "were not taint-analyzed"
                    )

                await bot.post_review(
                    event.pull_request_number,
                    scored_findings,
                    summary=gate["summary"],
                )
                await bot.post_commit_status(
                    event.head_sha,
                    passed=gate["passed"],
                    description=f"AutoForge Security Gate: {gate['summary']}",
                )
                await bot.upload_sarif(
                    SARIFReporter.build_report(scored_findings),
                    commit_sha=event.head_sha,
                    ref=f"refs/pull/{event.pull_request_number}/head",
                )
                log_security_event(
                    "pull_request.analysis",
                    outcome=gate["status"].lower(),
                    logger=get_security_logger(),
                    repository=event.repository,
                    pull_request=event.pull_request_number,
                    changed_files=len(changed_lines),
                    scanned_python_files=len(files),
                    findings=len(scored_findings),
                    suppressed_false_positives=gate["suppressed_false_positives"],
                    unsupported_language_files=len(unsupported_files),
                )

    async def _fetch_pull_request_files(
        self,
        client: httpx.AsyncClient,
        event: PullRequestEvent,
    ) -> list[Mapping[str, Any]]:
        files: list[Mapping[str, Any]] = []
        for page in range(1, 7):
            response = await client.get(
                f"{_GITHUB_API}/repos/{event.repository}/pulls/{event.pull_request_number}/files",
                params={"per_page": 100, "page": page},
            )
            response.raise_for_status()
            page_files = response.json()
            if not isinstance(page_files, list) or any(
                not isinstance(item, Mapping) for item in page_files
            ):
                raise ValueError("GitHub pull-request files response is malformed")
            files.extend(page_files)
            if len(files) > _MAX_PR_FILES:
                raise ValueError(
                    f"pull request modifies more than the supported {_MAX_PR_FILES} files"
                )
            if len(page_files) < 100:
                return files
        raise ValueError("pull request exceeds the supported 500 changed files")

    async def _analyze_changed_python_files(
        self,
        client: httpx.AsyncClient,
        event: PullRequestEvent,
        changed_lines: Mapping[str, list[int]],
        files: list[Mapping[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[str]]:
        changed_files = {
            str(item.get("filename"))
            for item in files
            if isinstance(item.get("filename"), str)
            and item.get("status") != "removed"
            and item.get("filename") in changed_lines
            and changed_lines[str(item.get("filename"))]
        }
        python_files = sorted(path for path in changed_files if path.lower().endswith(".py"))
        unsupported_files = sorted(changed_files - set(python_files))
        semaphore = asyncio.Semaphore(_MAX_PARALLEL_CONTENT_REQUESTS)

        async def fetch_source(path: str) -> tuple[str, str]:
            async with semaphore:
                encoded_path = quote(path, safe="/")
                response = await client.get(
                    f"{_GITHUB_API}/repos/{event.repository}/contents/{encoded_path}",
                    params={"ref": event.head_sha},
                )
            response.raise_for_status()
            document = response.json()
            if (
                not isinstance(document, dict)
                or document.get("type") != "file"
                or document.get("encoding") != "base64"
                or not isinstance(document.get("content"), str)
            ):
                raise ValueError(f"GitHub did not return base64 file content for {path}")
            try:
                content = base64.b64decode(document["content"], validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError) as error:
                raise ValueError(f"could not decode source file {path}") from error
            return path, content

        sources = await asyncio.gather(*(fetch_source(path) for path in python_files))
        findings: list[dict[str, Any]] = []
        for path, source in sources:
            for finding in TaintEngine().analyze(source, file_path=path):
                findings.append(
                    {
                        "rule_id": finding.rule_id,
                        "file": path,
                        "line": finding.line,
                        "sink": finding.sink,
                        "message": f"Untrusted data from {finding.source} reaches {finding.sink}.",
                        "repository": event.repository,
                    }
                )
        return findings, unsupported_files


async def run_worker() -> None:
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN must be configured for the production worker")
    queue = SQLiteJobQueue(os.getenv("JOB_DB_PATH", "/data/jobs.sqlite3"))
    recovered_jobs = await asyncio.to_thread(queue.recover_interrupted_jobs)
    if recovered_jobs:
        _LOGGER.warning("Recovered %d interrupted pull-request job(s)", recovered_jobs)
    metrics = MetricsCollector()
    metrics.start_server(port=int(os.getenv("METRICS_PORT", "8001")), addr="0.0.0.0")
    worker = PullRequestWorker(queue, token=token, metrics=metrics)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signal_number in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signal_number, stop.set)
    _LOGGER.info("Pull-request worker started")
    try:
        while not stop.is_set():
            processed = await worker.run_once()
            if not processed:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=1.0)
                except TimeoutError:
                    continue
    finally:
        metrics.stop_server()
        _LOGGER.info("Pull-request worker stopped")


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
