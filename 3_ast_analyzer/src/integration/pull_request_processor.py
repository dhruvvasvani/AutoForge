"""Compose diff filtering, finding scoring, policy evaluation, and GitHub publishing."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any

from src.reporting.sarif_generator import SARIFReporter
from src.scoring.vulnerability_scorer import VulnerabilityScorer

from .diff_parser import filter_findings_to_changed_lines, parse_unified_diff
from .github_bot import GitHubBot
from .webhook_server import PullRequestEvent
from ..policy.security_gate import POLICY_RULES, SecurityPolicy, evaluate_security_gate

FindingAnalyzer = Callable[
    [PullRequestEvent, Mapping[str, list[int]]],
    Awaitable[Sequence[Mapping[str, Any]]],
]


class PullRequestProcessor:
    """Run the configured analyzer only against added lines and publish its results."""

    def __init__(
        self,
        github_bot: GitHubBot,
        analyze: FindingAnalyzer,
        *,
        policy: SecurityPolicy = POLICY_RULES,
    ) -> None:
        if not isinstance(github_bot, GitHubBot):
            raise TypeError("github_bot must be a GitHubBot")
        if not callable(analyze):
            raise TypeError("analyze must be callable")
        self.github_bot = github_bot
        self.analyze = analyze
        self.policy = policy

    async def __call__(self, event: PullRequestEvent) -> dict[str, Any]:
        if event.repository != self.github_bot.repository:
            raise ValueError("webhook repository does not match the configured GitHub bot")
        diff_text = await self.github_bot.fetch_pull_request_diff(event.pull_request_number)
        changed_lines = parse_unified_diff(diff_text)
        findings = self.analyze(event, changed_lines)
        if not inspect.isawaitable(findings):
            raise TypeError("analyzer must return an awaitable")
        findings = await findings
        if not isinstance(findings, Sequence) or isinstance(findings, (str, bytes)):
            raise ValueError("analyzer must return a sequence of findings")

        changed_findings = filter_findings_to_changed_lines(findings, changed_lines)
        scored_findings = VulnerabilityScorer.score_findings(changed_findings)
        gate = evaluate_security_gate(scored_findings, self.policy)
        sarif = SARIFReporter.build_report(scored_findings)

        await self.github_bot.post_review(
            event.pull_request_number,
            scored_findings,
            summary=gate["summary"],
        )
        await self.github_bot.post_commit_status(
            event.head_sha,
            passed=gate["passed"],
            description=f"AutoForge Security Gate: {gate['summary']}",
        )
        await self.github_bot.upload_sarif(
            sarif,
            commit_sha=event.head_sha,
            ref=f"refs/pull/{event.pull_request_number}/head",
        )
        return {
            "changed_files": len(changed_lines),
            "changed_lines": sum(len(lines) for lines in changed_lines.values()),
            "findings": len(scored_findings),
            "gate": gate,
        }
