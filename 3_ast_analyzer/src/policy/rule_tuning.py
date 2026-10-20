"""Validated production policy loading and auditable false-positive feedback."""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .security_gate import SecurityPolicy, evaluate_security_gate

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_POLICY_KEYS = {
    "schema_version",
    "severity_thresholds",
    "risk_score_block_threshold",
    "min_ml_confidence",
    "approved_suppression_max_days",
    "approved_by",
}
_THRESHOLD_KEYS = {"max_allowed"}
_ACTOR = re.compile(r"^[A-Za-z0-9_.@-]{1,100}$")
_JOURNAL_LOCK = threading.Lock()
DEFAULT_POLICY_PATH = Path(__file__).with_name("production_policy.json")


class ProductionPolicyError(ValueError):
    """The production policy file is malformed or uses unsupported fields."""


def _parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("expiry must be a non-empty ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("expiry must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError("expiry timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def finding_fingerprint(
    finding: Mapping[str, Any],
    *,
    repository: str | None = None,
) -> str:
    scope = repository if repository is not None else finding.get("repository", "")
    normalized = {
        "repository": str(scope).lower(),
        "rule_id": str(finding.get("rule_id", "")),
        "file": str(finding.get("file", finding.get("file_path", ""))).replace("\\", "/"),
        "line": finding.get("line", finding.get("line_number")),
        "code_snippet": str(finding.get("code_snippet", finding.get("snippet", ""))),
        "message": str(finding.get("message", finding.get("description", ""))),
    }
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class RuleTuner:
    def __init__(
        self,
        policy_path: str | Path = DEFAULT_POLICY_PATH,
        feedback_path: str | Path | None = None,
    ) -> None:
        self.policy_path = Path(policy_path)
        self.feedback_path = (
            Path(feedback_path)
            if feedback_path is not None
            else self.policy_path.with_name("false_positive_feedback.jsonl")
        )
        self.policy = self._load_policy(self.policy_path)

    @staticmethod
    def _load_policy(path: Path) -> dict[str, Any]:
        try:
            policy = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ProductionPolicyError(f"could not load production policy at {path}: {error}") from error
        if not isinstance(policy, dict):
            raise ProductionPolicyError("production policy must be a JSON object")
        unknown_keys = set(policy) - _POLICY_KEYS
        missing_keys = _POLICY_KEYS - set(policy)
        if unknown_keys or missing_keys:
            raise ProductionPolicyError(
                f"production policy keys mismatch; missing={sorted(missing_keys)}, "
                f"unknown={sorted(unknown_keys)}"
            )
        if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
            raise ProductionPolicyError("schema_version must be integer 1")

        thresholds = policy["severity_thresholds"]
        if not isinstance(thresholds, dict) or set(thresholds) != set(_SEVERITIES):
            raise ProductionPolicyError(
                f"severity_thresholds must define exactly {', '.join(_SEVERITIES)}"
            )
        for severity, threshold in thresholds.items():
            if not isinstance(threshold, dict) or set(threshold) != _THRESHOLD_KEYS:
                raise ProductionPolicyError(
                    f"{severity} threshold must contain exactly max_allowed"
                )
            limit = threshold["max_allowed"]
            if limit is not None and (
                isinstance(limit, bool) or not isinstance(limit, int) or limit < 0
            ):
                raise ProductionPolicyError(f"{severity}.max_allowed must be null or non-negative")
            if severity in {"CRITICAL", "HIGH"} and limit is None:
                raise ProductionPolicyError(f"{severity}.max_allowed must be an integer")
        for key in ("risk_score_block_threshold", "min_ml_confidence"):
            value = policy[key]
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise ProductionPolicyError(f"{key} must be finite numeric")
        if not 0 <= policy["risk_score_block_threshold"] <= 10:
            raise ProductionPolicyError("risk_score_block_threshold must be between 0 and 10")
        if not 0 <= policy["min_ml_confidence"] <= 1:
            raise ProductionPolicyError("min_ml_confidence must be between 0 and 1")
        maximum_days = policy["approved_suppression_max_days"]
        if isinstance(maximum_days, bool) or not isinstance(maximum_days, int) or maximum_days < 1:
            raise ProductionPolicyError("approved_suppression_max_days must be a positive integer")
        approvers = policy["approved_by"]
        if (
            not isinstance(approvers, list)
            or any(not isinstance(actor, str) or not _ACTOR.fullmatch(actor) for actor in approvers)
        ):
            raise ProductionPolicyError("approved_by must be a list of valid reviewer identifiers")
        policy["approved_by"] = sorted(set(approvers))
        return policy

    def submit_false_positive(
        self,
        finding: Mapping[str, Any],
        *,
        reason: str,
        submitted_by: str,
        repository: str | None = None,
        pull_request: int | None = None,
    ) -> str:
        if not isinstance(finding, Mapping):
            raise TypeError("finding must be a mapping")
        fingerprint = finding_fingerprint(finding, repository=repository)
        audit_finding = {
            key: finding[key]
            for key in ("rule_id", "file", "file_path", "line", "line_number")
            if key in finding and isinstance(finding[key], (str, int, float, type(None)))
        }
        self.submit_false_positive_fingerprint(
            fingerprint,
            reason=reason,
            submitted_by=submitted_by,
            repository=repository,
            pull_request=pull_request,
            finding=audit_finding,
        )
        return fingerprint

    def submit_false_positive_fingerprint(
        self,
        fingerprint: str,
        *,
        reason: str,
        submitted_by: str,
        repository: str | None = None,
        pull_request: int | None = None,
        finding: Mapping[str, Any] | None = None,
    ) -> None:
        self._validate_fingerprint(fingerprint)
        if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 1000:
            raise ValueError("reason must contain between 1 and 1000 characters")
        self._validate_actor(submitted_by, "submitted_by")
        if finding is not None and not isinstance(finding, Mapping):
            raise TypeError("finding metadata must be a mapping")
        if repository is not None and (
            not isinstance(repository, str) or not re.fullmatch(r"[^/\s]+/[^/\s]+", repository)
        ):
            raise ValueError("repository must be an owner/repository name")
        if pull_request is not None and (
            isinstance(pull_request, bool) or not isinstance(pull_request, int) or pull_request < 1
        ):
            raise ValueError("pull_request must be a positive integer")
        self._append_event(
            {
                "action": "submitted",
                "fingerprint": fingerprint,
                "reason": reason.strip(),
                "submitted_by": submitted_by,
                "repository": repository,
                "pull_request": pull_request,
                "finding": dict(finding or {}),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

    def approve_false_positive(
        self,
        fingerprint: str,
        *,
        approved_by: str,
        expires_at: str,
        reason: str,
    ) -> None:
        self._validate_fingerprint(fingerprint)
        self._validate_actor(approved_by, "approved_by")
        if approved_by not in self.policy["approved_by"]:
            raise PermissionError("reviewer is not authorized to approve false-positive suppressions")
        if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 1000:
            raise ValueError("approval reason must contain between 1 and 1000 characters")
        expiry = _parse_utc(expires_at)
        now = datetime.now(timezone.utc)
        if expiry <= now:
            raise ValueError("suppression expiry must be in the future")
        if expiry > now + timedelta(days=self.policy["approved_suppression_max_days"]):
            raise ValueError("suppression expiry exceeds the configured maximum duration")
        if not any(
            event["fingerprint"] == fingerprint and event["action"] == "submitted"
            for event in self._read_events()
        ):
            raise ValueError("cannot approve a false-positive report that was not submitted")
        self._append_event(
            {
                "action": "approved",
                "fingerprint": fingerprint,
                "approved_by": approved_by,
                "reason": reason.strip(),
                "expires_at": expiry.isoformat(),
                "created_at": now.isoformat(),
            }
        )

    def revoke_false_positive(
        self,
        fingerprint: str,
        *,
        revoked_by: str,
        reason: str,
    ) -> None:
        self._validate_fingerprint(fingerprint)
        self._validate_actor(revoked_by, "revoked_by")
        if revoked_by not in self.policy["approved_by"]:
            raise PermissionError("reviewer is not authorized to revoke false-positive suppressions")
        if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 1000:
            raise ValueError("revocation reason must contain between 1 and 1000 characters")
        if fingerprint not in self._active_suppressions():
            raise ValueError("no active approved suppression exists for this finding")
        self._append_event(
            {
                "action": "revoked",
                "fingerprint": fingerprint,
                "revoked_by": revoked_by,
                "reason": reason.strip(),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

    def filter_approved_suppressions(
        self,
        findings: Iterable[Mapping[str, Any]],
    ) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]:
        suppressions = self._active_suppressions()
        kept = []
        suppressed = []
        for finding in findings:
            if not isinstance(finding, Mapping):
                raise ValueError("findings must contain only mappings")
            if finding_fingerprint(finding) in suppressions:
                suppressed.append(finding)
            else:
                kept.append(finding)
        return kept, suppressed

    def evaluate(self, findings: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
        kept, suppressed = self.filter_approved_suppressions(findings)
        thresholds = self.policy["severity_thresholds"]
        gate_policy = SecurityPolicy(
            max_critical_allowed=thresholds["CRITICAL"]["max_allowed"],
            max_high_allowed=thresholds["HIGH"]["max_allowed"],
            min_severity_score_block=self.policy["risk_score_block_threshold"],
            require_ml_confidence=self.policy["min_ml_confidence"],
            max_medium_allowed=thresholds["MEDIUM"]["max_allowed"],
            max_low_allowed=thresholds["LOW"]["max_allowed"],
        )
        gate = evaluate_security_gate(kept, gate_policy)
        gate["suppressed_false_positives"] = len(suppressed)
        gate["findings_before_suppression"] = len(kept) + len(suppressed)
        return gate

    def _active_suppressions(self) -> dict[str, datetime]:
        events = self._read_events()
        latest: dict[str, dict[str, Any]] = {}
        submitted = set()
        for event in events:
            action = event["action"]
            fingerprint = event["fingerprint"]
            if action == "submitted":
                submitted.add(fingerprint)
            elif action in {"approved", "revoked"}:
                if fingerprint not in submitted:
                    raise ProductionPolicyError(
                        f"{action} event references an unsubmitted finding: {fingerprint}"
                    )
                latest[fingerprint] = event
        now = datetime.now(timezone.utc)
        active = {}
        for fingerprint, event in latest.items():
            if event["action"] != "approved":
                continue
            expiry = _parse_utc(event["expires_at"])
            if expiry > now:
                active[fingerprint] = expiry
        return active

    def _read_events(self) -> list[dict[str, Any]]:
        try:
            contents = self.feedback_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        except OSError as error:
            raise ProductionPolicyError(f"could not read feedback journal: {error}") from error
        events = []
        for line_number, line in enumerate(contents.splitlines(), start=1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ProductionPolicyError(
                    f"invalid feedback journal JSON at line {line_number}"
                ) from error
            if (
                not isinstance(event, dict)
                or event.get("action") not in {"submitted", "approved", "revoked"}
                or not isinstance(event.get("fingerprint"), str)
            ):
                raise ProductionPolicyError(
                    f"invalid feedback journal event at line {line_number}"
                )
            self._validate_fingerprint(event["fingerprint"])
            events.append(event)
        return events

    def _append_event(self, event: Mapping[str, Any]) -> None:
        self.feedback_path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(event, sort_keys=True, ensure_ascii=True, allow_nan=False)
        try:
            with _JOURNAL_LOCK, self.feedback_path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(serialized + "\n")
                stream.flush()
        except (OSError, TypeError, ValueError) as error:
            raise ProductionPolicyError(f"could not write feedback journal: {error}") from error

    @staticmethod
    def _validate_fingerprint(fingerprint: str) -> None:
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("fingerprint must be a SHA-256 hex digest")

    @staticmethod
    def _validate_actor(actor: str, name: str) -> None:
        if not isinstance(actor, str) or not _ACTOR.fullmatch(actor):
            raise ValueError(f"{name} must be a valid reviewer identifier")
