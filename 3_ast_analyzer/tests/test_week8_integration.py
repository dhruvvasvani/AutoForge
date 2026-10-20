from __future__ import annotations

import anyio
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

ANALYZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_ROOT))

from src.integration.diff_parser import (
    filter_findings_to_changed_lines,
    parse_unified_diff,
)
from src.integration.github_bot import GitHubBot
from src.integration.pull_request_processor import PullRequestProcessor
from src.integration.webhook_server import PullRequestEvent, create_app
from src.policy.security_gate import SecurityPolicy, evaluate_security_gate


def _post_webhook(
    app: FastAPI,
    body: bytes,
    headers: dict[str, str],
) -> httpx.Response:
    async def send():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            return await client.post(
                "/api/v1/github/events",
                content=body,
                headers=headers,
            )

    return anyio.run(send)


def _signed_headers(body: bytes, secret: str = "test-secret") -> dict[str, str]:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return {
        "X-Hub-Signature-256": f"sha256={digest}",
        "X-GitHub-Event": "pull_request",
        "Content-Type": "application/json",
    }


def _payload(action: str = "opened") -> dict[str, Any]:
    return {
        "action": action,
        "repository": {"full_name": "owner/repo"},
        "pull_request": {
            "number": 12,
            "head": {"sha": "a" * 40},
            "diff_url": "https://github.com/owner/repo/pull/12.diff",
        },
    }


def test_webhook_authenticates_payload_and_dispatches_pull_request():
    received: list[PullRequestEvent] = []

    async def handler(event: PullRequestEvent) -> None:
        received.append(event)

    body = json.dumps(_payload()).encode()
    response = _post_webhook(
        create_app(webhook_secret="test-secret", event_handler=handler),
        body,
        _signed_headers(body),
    )

    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    assert received == [
        PullRequestEvent(
            "opened",
            "owner/repo",
            12,
            "a" * 40,
            "https://github.com/owner/repo/pull/12.diff",
        )
    ]


def test_webhook_rejects_invalid_signature():
    body = json.dumps(_payload()).encode()
    response = _post_webhook(
        create_app(webhook_secret="test-secret"),
        body,
        {**_signed_headers(body), "X-Hub-Signature-256": "sha256=invalid"},
    )

    assert response.status_code == 401


def test_webhook_fails_closed_when_secret_or_handler_is_missing():
    body = json.dumps(_payload()).encode()
    missing_secret = _post_webhook(
        create_app(),
        body,
        _signed_headers(body),
    )
    missing_handler = _post_webhook(
        create_app(webhook_secret="test-secret"),
        body,
        _signed_headers(body),
    )

    assert missing_secret.status_code == 503
    assert missing_handler.status_code == 503


@pytest.mark.parametrize(
    ("payload", "expected_status"),
    [
        ({**_payload(), "repository": {"full_name": "owner/../repo"}}, 400),
        ({**_payload(), "pull_request": {"number": True}}, 400),
    ],
)
def test_webhook_rejects_malformed_pull_request_fields(payload, expected_status):
    body = json.dumps(payload).encode()
    response = _post_webhook(
        create_app(webhook_secret="test-secret"),
        body,
        _signed_headers(body),
    )
    assert response.status_code == expected_status


def test_webhook_ignores_unsupported_pull_request_actions():
    body = json.dumps(_payload("closed")).encode()
    response = _post_webhook(
        create_app(webhook_secret="test-secret"),
        body,
        _signed_headers(body),
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"


def test_diff_parser_tracks_added_lines_across_files_and_hunks():
    diff_text = (
        "diff --git a/src/one.py b/src/one.py\n"
        "--- a/src/one.py\n"
        "+++ b/src/one.py\n"
        "@@ -1,3 +1,4 @@\n"
        " context\n"
        "-old\n"
        "+new\n"
        "+another\n"
        "@@ -8 +9,2 @@\n"
        "+third\n"
        " context\n"
        "diff --git a/src/old.py b/src/old.py\n"
        "--- a/src/old.py\n"
        "+++ /dev/null\n"
        "@@ -1 +0,0 @@\n"
        "-removed\n"
        "diff --git a/src/new.py b/src/new.py\n"
        "--- /dev/null\n"
        "+++ b/src/new.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+first\n"
        "+second\n"
    )

    assert parse_unified_diff(diff_text) == {
        "src/one.py": [2, 3, 9],
        "src/new.py": [1, 2],
    }


def test_diff_parser_rejects_malformed_hunks():
    with pytest.raises(ValueError, match="hunk header"):
        parse_unified_diff(
            "diff --git a/src/app.py b/src/app.py\n"
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ malformed @@\n"
        )


def test_findings_are_filtered_to_added_lines_only():
    findings = [
        {"file": "src/app.py", "line": 12},
        {"file": "src/app.py", "line": 20},
        {"file": "src/other.py", "line": 12},
    ]
    assert filter_findings_to_changed_lines(
        findings,
        {"src/app.py": [12]},
    ) == [findings[0]]


def test_security_gate_enforces_critical_high_score_and_confidence_rules():
    result = evaluate_security_gate(
        [
            {"severity": "CRITICAL", "ml_confidence": 0.8},
            {"severity": "HIGH", "ml_confidence": 0.9},
            {"severity": "HIGH", "ml_confidence": 0.9},
            {"severity": "CRITICAL", "ml_confidence": 0.2},
            {"severity": "MEDIUM", "combined_risk_score": 8.5},
        ]
    )

    assert result["status"] == "FAILED"
    assert result["counts"] == {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 1}
    assert result["excluded_low_confidence"] == 1
    assert len(result["blockers"]) == 3


def test_security_gate_passes_within_limits_and_reports_excluded_confidence():
    result = evaluate_security_gate(
        [
            {"severity": "HIGH", "ml_confidence": 0.6},
            {"severity": "CRITICAL", "ml_confidence": 0.59},
        ]
    )

    assert result["status"] == "PASSED"
    assert result["excluded_low_confidence"] == 1
    assert "below ML confidence threshold" in result["summary"]


def test_security_gate_policy_is_configurable_and_validated():
    policy = SecurityPolicy(
        max_critical_allowed=1,
        max_high_allowed=3,
        min_severity_score_block=9.5,
        require_ml_confidence=0.9,
    )
    result = evaluate_security_gate(
        [{"severity": "CRITICAL", "ml_confidence": 0.9}],
        policy,
    )
    assert result["status"] == "PASSED"
    with pytest.raises(ValueError, match="require_ml_confidence"):
        SecurityPolicy(require_ml_confidence=1.1)


@pytest.mark.parametrize(
    "finding",
    [
        {"severity": "URGENT"},
        {"severity": "HIGH", "ml_confidence": float("nan")},
        {"severity": "HIGH", "combined_risk_score": float("inf")},
    ],
)
def test_security_gate_rejects_invalid_findings(finding):
    with pytest.raises(ValueError):
        evaluate_security_gate([finding])


def test_github_bot_posts_inline_review_comments():
    requests = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"id": 123})

    async def run_test():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            bot = GitHubBot("owner/repo", "test-token", client=client)
            return await bot.post_review(
                12,
                [
                    {
                        "file": "src/app.py",
                        "line": 8,
                        "severity": "HIGH",
                        "message": "Untrusted input reaches the query",
                        "remediation": "Use a parameterized query.",
                    }
                ],
                summary="AutoForge found one issue.",
            )

    result = anyio.run(run_test)

    assert result == {"id": 123}
    assert requests[0].url.path == "/repos/owner/repo/pulls/12/reviews"
    comment = json.loads(requests[0].content)["comments"][0]
    assert comment["side"] == "RIGHT"
    assert comment["line"] == 8
    assert "parameterized query" in comment["body"]


def test_github_bot_posts_status_and_uploads_sarif():
    requests = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(202, json={"id": "upload"})

    async def run_test():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            bot = GitHubBot("owner/repo", "test-token", client=client)
            await bot.post_commit_status(
                "b" * 40,
                passed=False,
                description="AutoForge Security Gate: FAILED",
            )
            await bot.upload_sarif(
                {"version": "2.1.0", "runs": []},
                commit_sha="b" * 40,
                ref="refs/pull/12/head",
                category="autoforge",
            )

    anyio.run(run_test)

    status = json.loads(requests[0].content)
    assert status["state"] == "failure"
    upload = json.loads(requests[1].content)
    assert upload["analysis_category"] == "autoforge"
    assert json.loads(base64.b64decode(upload["sarif"])) == {
        "version": "2.1.0",
        "runs": [],
    }
    assert requests[1].url.path == "/repos/owner/repo/code-scanning/sarifs"


def test_pull_request_processor_runs_incremental_analysis_and_publishes_results():
    requests = []
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1 +1,2 @@\n"
        " existing()\n"
        "+db.execute(query)\n"
    )
    analyzed: list[dict[str, list[int]]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, text=diff)
        if request.url.path.endswith("/reviews"):
            return httpx.Response(200, json={"id": 456})
        if request.url.path.endswith("/code-scanning/sarifs"):
            return httpx.Response(202, json={"id": "sarif"})
        return httpx.Response(201, json={"state": "success"})

    async def analyze(event, changed_lines):
        analyzed.append(dict(changed_lines))
        return [
            {
                "rule_id": "SQLI_RAW_CONCAT",
                "file": "src/app.py",
                "line": 2,
                "message": "Untrusted input reaches SQL",
                "ml_confidence": 0.8,
            },
            {
                "rule_id": "SQLI_RAW_CONCAT",
                "file": "src/app.py",
                "line": 1,
                "message": "Legacy finding",
            },
        ]

    async def run_test():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            bot = GitHubBot("owner/repo", "test-token", client=client)
            processor = PullRequestProcessor(bot, analyze)
            return await processor(
                PullRequestEvent(
                    "opened",
                    "owner/repo",
                    12,
                    "a" * 40,
                    "https://github.com/owner/repo/pull/12.diff",
                )
            )

    result = anyio.run(run_test)

    assert analyzed == [{"src/app.py": [2]}]
    assert result["findings"] == 1
    assert result["gate"]["passed"] is True
    assert [request.method for request in requests] == ["GET", "POST", "POST", "POST"]
    assert requests[1].url.path.endswith("/reviews")
    assert len(json.loads(requests[1].content)["comments"]) == 1
    assert json.loads(requests[2].content)["state"] == "success"
    upload = json.loads(requests[3].content)
    report = json.loads(base64.b64decode(upload["sarif"]))
    assert len(report["runs"][0]["results"]) == 1
    assert report["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "region"
    ]["startLine"] == 2


def test_github_bot_surfaces_api_errors_and_skips_empty_reviews():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "forbidden"})

    async def run_test():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            bot = GitHubBot("owner/repo", "test-token", client=client)
            assert await bot.post_review(1, [], summary="No findings") is None
            with pytest.raises(httpx.HTTPStatusError):
                await bot.post_commit_status(
                    "c" * 40,
                    passed=True,
                    description="Gate passed",
                )

    anyio.run(run_test)


def test_github_bot_validates_input_without_network_calls():
    with pytest.raises(ValueError, match="repository"):
        GitHubBot("owner/../repo", "test-token")
