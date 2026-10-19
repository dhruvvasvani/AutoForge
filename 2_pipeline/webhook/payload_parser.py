"""Parse supported GitHub and GitLab events into scan metadata."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class UnsupportedWebhookEvent(ValueError):
    pass


@dataclass(frozen=True)
class WebhookScanRequest:
    repository: dict[str, str]
    commit_sha: str
    branch: str
    author: str
    changed_files: list[str]
    event_type: str


def _paths(commits: Any) -> list[str]:
    paths: set[str] = set()
    if isinstance(commits, list):
        for commit in commits:
            if isinstance(commit, dict):
                for key in ("added", "modified", "removed"):
                    values = commit.get(key, [])
                    if isinstance(values, list):
                        paths.update(path for path in values if isinstance(path, str) and path)
    elif isinstance(commits, dict):
        paths.update(path for path in commits if isinstance(path, str))
    return sorted(paths)


def parse_webhook_payload(provider: str, event_name: str, payload: dict[str, Any]) -> WebhookScanRequest:
    if provider.lower() == "github":
        repo = payload.get("repository") or {}
        if event_name == "push":
            commit = payload.get("after")
            ref = payload.get("ref", "")
            pusher = payload.get("pusher") or {}
            author = pusher.get("name", "") if isinstance(pusher, dict) else ""
            paths = _paths(payload.get("commits"))
            event_type = "push"
            clone_url = repo.get("clone_url")
        elif event_name == "pull_request":
            pr = payload.get("pull_request") or {}
            head = pr.get("head") or {}
            head_repo = head.get("repo") or {}
            commit = head.get("sha")
            ref = head.get("ref", "")
            sender = payload.get("sender") or pr.get("user") or {}
            author = sender.get("login", "") if isinstance(sender, dict) else ""
            paths = []
            event_type = "pull_request"
            clone_url = head_repo.get("clone_url") or repo.get("clone_url")
        else:
            raise UnsupportedWebhookEvent(f"Ignored GitHub event {event_name}")
        full_name = repo.get("full_name")
        provider_name = "github"
    elif provider.lower() == "gitlab":
        project = payload.get("project") or {}
        if event_name == "Push Hook":
            commit = payload.get("after")
            ref = payload.get("ref", "")
            paths = _paths(payload.get("commits"))
            event_type = "push"
            author = payload.get("user_name", "")
            clone_url = project.get("git_http_url")
        elif event_name == "Merge Request Hook":
            attrs = payload.get("object_attributes") or {}
            last_commit = attrs.get("last_commit") or {}
            commit = last_commit.get("id")
            ref = attrs.get("source_branch", "")
            paths = _paths((payload.get("changes") or {}).get("paths", {}))
            event_type = "pull_request"
            user = payload.get("user") or {}
            author = user.get("name", "") if isinstance(user, dict) else ""
            source = payload.get("source") or {}
            clone_url = source.get("git_http_url") or project.get("git_http_url")
        else:
            raise UnsupportedWebhookEvent(f"Ignored GitLab event {event_name}")
        full_name = project.get("path_with_namespace")
        provider_name = "gitlab"
    else:
        raise ValueError(f"Unsupported provider {provider}")
    if not isinstance(full_name, str) or not isinstance(clone_url, str):
        raise ValueError("Webhook payload has no repository name or clone URL")
    if not isinstance(commit, str) or not commit or set(commit) == {"0"}:
        raise UnsupportedWebhookEvent("Event has no commit to scan")
    return WebhookScanRequest(
        {"full_name": full_name, "clone_url": clone_url, "provider": provider_name},
        commit,
        str(ref).removeprefix("refs/heads/"),
        str(author),
        paths,
        event_type,
    )
