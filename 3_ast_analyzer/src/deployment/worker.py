"""Durable asynchronous GitHub pull-request analysis worker."""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import signal
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import quote
from typing import Any

import httpx

from src.analysis.taint_engine import TaintEngine
from src.integration.diff_parser import filter_findings_to_changed_lines, parse_unified_diff
from src.integration.github_bot import GitHubBot
from src.integration.static_scanner import scan_sources
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
_MAX_PR_SOURCE_BYTES = 1_000_000


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
        self.static_scanners_required = (
            os.getenv("STATIC_SCANNERS_REQUIRED", "true").strip().lower() == "true"
        )
        self.ai_fix_url = os.getenv("AI_FIX_URL", "").rstrip("/")
        self.ai_fix_enabled = os.getenv("AI_FIX_ENABLED", "false").strip().lower() == "true"
        self.max_ai_fixes = int(os.getenv("MAX_AI_FIXES", "3"))
        if self.max_ai_fixes < 0:
            raise ValueError("MAX_AI_FIXES must not be negative")
        if self.ai_fix_enabled and not self.ai_fix_url:
            raise ValueError("AI_FIX_URL must be configured when AI_FIX_ENABLED is true")

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
                    findings, unsupported_files, scanner_status = await self._analyze_changed_python_files(
                        client,
                        event,
                        changed_lines,
                        files,
                    )
                changed_findings = filter_findings_to_changed_lines(findings, changed_lines)
                scored_findings = VulnerabilityScorer.score_findings(changed_findings)
                scanner_risk_floor = {
                    "CRITICAL": 9.0,
                    "ERROR": 9.0,
                    "HIGH": 7.0,
                    "WARNING": 7.0,
                    "MEDIUM": 5.0,
                    "LOW": 2.0,
                    "INFO": 2.0,
                }
                scanner_severity = {
                    "ERROR": "CRITICAL",
                    "WARNING": "HIGH",
                    "INFO": "LOW",
                }
                for finding in scored_findings:
                    raw_severity = finding.get("scanner_severity")
                    if isinstance(raw_severity, str):
                        severity = raw_severity.upper()
                        normalized_severity = scanner_severity.get(severity, severity)
                        if normalized_severity in scanner_risk_floor:
                            finding["severity"] = normalized_severity
                            finding["combined_risk_score"] = max(
                                finding["combined_risk_score"],
                                scanner_risk_floor[severity],
                            )
                gate = self.rule_tuner.evaluate(scored_findings)
                self.metrics.record_findings(scored_findings)
                self.metrics.update_memory_usage()

                failed_scanners = {
                    scanner: status
                    for scanner, status in scanner_status.items()
                    if status in {"failed", "unavailable"}
                }
                if self.static_scanners_required and failed_scanners:
                    gate["passed"] = False
                    gate["status"] = "FAILED"
                    gate["blockers"].append(
                        {"rule": "static_scanners", "scanners": failed_scanners}
                    )
                    gate["summary"] += (
                        "; FAILED: required static scanner(s) did not complete "
                        f"({', '.join(sorted(failed_scanners))})"
                    )

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

                if self.ai_fix_enabled and self.ai_fix_url:
                    await self._attach_ai_suggestions(
                        scored_findings,
                        findings,
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
                    static_scanners=scanner_status,
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
    ) -> tuple[list[dict[str, Any]], list[str], dict[str, str]]:
        changed_files = {
            str(item.get("filename"))
            for item in files
            if isinstance(item.get("filename"), str)
            and item.get("status") != "removed"
            and item.get("filename") in changed_lines
            and changed_lines[str(item.get("filename"))]
        }
        python_files = sorted(path for path in changed_files if path.lower().endswith(".py"))
        supported_extensions = {
            ".py", ".java", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php",
            ".cs", ".c", ".cpp", ".tf", ".yaml", ".yml", ".json",
        }
        scan_files = sorted(
            path
            for path in changed_files
            if Path(path).suffix.lower() in supported_extensions
            or Path(path).name.lower() == "dockerfile"
        )
        unsupported_files = sorted(changed_files - set(python_files))
        semaphore = asyncio.Semaphore(_MAX_PARALLEL_CONTENT_REQUESTS)

        async def fetch_source(path: str) -> tuple[str, str] | None:
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
                _LOGGER.warning("GitHub did not return base64 file content for %s", path)
                return None
            try:
                encoded_content = document["content"]
                if len(encoded_content) > ((_MAX_PR_SOURCE_BYTES + 2) // 3) * 4:
                    _LOGGER.warning("Skipping oversized changed file %s", path)
                    return None
                content_bytes = base64.b64decode(encoded_content, validate=True)
                if len(content_bytes) > _MAX_PR_SOURCE_BYTES:
                    _LOGGER.warning("Skipping oversized changed file %s", path)
                    return None
                content = content_bytes.decode("utf-8")
            except (ValueError, UnicodeDecodeError) as error:
                raise ValueError(f"could not decode source file {path}") from error
            return path, content

        fetched_sources = await asyncio.gather(*(fetch_source(path) for path in scan_files))
        sources = {
            path: source
            for fetched in fetched_sources
            if fetched is not None
            for path, source in [fetched]
        }
        findings: list[dict[str, Any]] = []
        for path in python_files:
            source = sources.get(path)
            if source is None:
                continue
            for finding in TaintEngine().analyze(source, file_path=path):
                source_lines = source.splitlines()
                line_start = max(0, finding.line - 16)
                line_end = min(len(source_lines), finding.line + 15)
                findings.append(
                    {
                        "rule_id": finding.rule_id,
                        "file": path,
                        "line": finding.line,
                        "sink": finding.sink,
                        "message": f"Untrusted data from {finding.source} reaches {finding.sink}.",
                        "repository": event.repository,
                        "code_snippet": "\n".join(source_lines[line_start:line_end])[:4000],
                    }
                )
        scanner_findings, scanner_status = await asyncio.to_thread(scan_sources, sources)
        for finding in scanner_findings:
            source = sources.get(finding["file"])
            source_lines = source.splitlines() if source is not None else []
            line = finding["line"]
            finding["code_snippet"] = "\n".join(
                source_lines[max(0, line - 16):min(len(source_lines), line + 15)]
            )[:4000]
            finding["scanner_severity"] = finding.get("severity")
            finding["repository"] = event.repository
            findings.append(finding)
        return findings, unsupported_files, scanner_status

    async def _attach_ai_suggestions(
        self,
        findings: list[dict[str, Any]],
        raw_findings: list[dict[str, Any]],
    ) -> None:
        if not self.ai_fix_url or self.max_ai_fixes == 0:
            return
        raw_by_location = {
            (finding.get("file"), finding.get("line")): finding
            for finding in raw_findings
            if finding.get("scanner_severity") is None
        }
        candidates = [
            finding
            for finding in findings
            if finding.get("severity") in {"CRITICAL", "HIGH"}
            and (finding.get("file"), finding.get("line")) in raw_by_location
        ][: self.max_ai_fixes]
        async with httpx.AsyncClient(timeout=90.0) as ai_client:
            for finding in candidates:
                raw = raw_by_location[(finding["file"], finding["line"])]
                try:
                    response = await ai_client.post(
                        f"{self.ai_fix_url}/api/fix",
                        json={
                            "code": raw.get("code_snippet", ""),
                            "language": "python",
                            "vulnerability": (
                                f"{finding.get('rule_id')}: {finding.get('message')}"
                            ),
                        },
                    )
                    response.raise_for_status()
                    result = response.json()
                    suggestion = result.get("result") if isinstance(result, dict) else None
                    if (
                        isinstance(result, dict)
                        and result.get("success") is True
                        and isinstance(suggestion, str)
                        and suggestion.strip()
                    ):
                        finding["remediation"] = (
                            f"{finding.get('remediation', '')}\n\n"
                            "AI-generated suggestion (review before applying):\n"
                            f"```\n{suggestion[:4000]}\n```"
                        ).strip()
                    else:
                        _LOGGER.warning(
                            "AI fix service returned no suggestion for %s:%s",
                            finding.get("file"),
                            finding.get("line"),
                        )
                except (httpx.HTTPError, ValueError) as error:
                    _LOGGER.warning(
                        "AI fix request failed for %s:%s: %s",
                        finding.get("file"),
                        finding.get("line"),
                        error,
                    )


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
