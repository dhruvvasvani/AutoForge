"""WSGI webhook listener with GitHub HMAC and GitLab token validation."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from typing import Any, Callable
from wsgiref.simple_server import make_server

from client import BackendClient
from redis_producer import ASTScanProducer
from webhook.payload_parser import UnsupportedWebhookEvent, parse_webhook_payload

logger = logging.getLogger(__name__)


class WebhookListener:
    def __init__(
        self,
        producer: Any | None = None,
        backend_client: Any | None = None,
        github_secret: str | None = None,
        gitlab_secret: str | None = None,
    ) -> None:
        self.producer = producer or ASTScanProducer()
        self.backend = backend_client or BackendClient.from_environment()
        self.github_secret = github_secret if github_secret is not None else os.getenv("GITHUB_WEBHOOK_SECRET", "")
        self.gitlab_secret = gitlab_secret if gitlab_secret is not None else os.getenv("GITLAB_WEBHOOK_SECRET", "")

    def __call__(self, environ: dict[str, Any], start_response: Callable[..., Any]) -> list[bytes]:
        provider = environ.get("PATH_INFO", "").strip("/").lower()
        if environ.get("REQUEST_METHOD") != "POST" or provider not in {"github", "gitlab"}:
            return self._respond(start_response, "404 Not Found", {"error": "Not found"})
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
            if not 0 < length <= 2 * 1024 * 1024:
                raise ValueError("Invalid webhook body size")
            raw = environ["wsgi.input"].read(length)
            if not self._authenticate(provider, environ, raw):
                return self._respond(start_response, "401 Unauthorized", {"error": "Invalid signature"})
            payload = json.loads(raw)
            event_header = "HTTP_X_GITHUB_EVENT" if provider == "github" else "HTTP_X_GITLAB_EVENT"
            request = parse_webhook_payload(provider, environ.get(event_header, ""), payload)
        except UnsupportedWebhookEvent as exc:
            return self._respond(start_response, "202 Accepted", {"status": "ignored", "reason": str(exc)})
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return self._respond(start_response, "400 Bad Request", {"error": str(exc)})
        try:
            scan_id = self.backend.create_scan(
                request.repository["full_name"], request.commit_sha, request.event_type
            )
            self.producer.enqueue_webhook_scan(
                request.repository, request.commit_sha, request.branch,
                request.changed_files, request.event_type, scan_id, author=request.author,
            )
        except Exception:
            logger.exception("Webhook registration or queueing failed")
            return self._respond(start_response, "502 Bad Gateway", {"error": "Could not queue scan"})
        return self._respond(start_response, "202 Accepted", {"scan_id": scan_id, "status": "queued"})

    def _authenticate(self, provider: str, environ: dict[str, Any], body: bytes) -> bool:
        if provider == "github":
            signature = environ.get("HTTP_X_HUB_SIGNATURE_256", "")
            if not self.github_secret or not signature.startswith("sha256="):
                return False
            digest = hmac.new(self.github_secret.encode(), body, hashlib.sha256).hexdigest()
            return hmac.compare_digest("sha256=" + digest, signature)
        received = environ.get("HTTP_X_GITLAB_TOKEN", "")
        return bool(self.gitlab_secret) and hmac.compare_digest(self.gitlab_secret, received)

    @staticmethod
    def _respond(start_response: Callable[..., Any], status: str, payload: dict[str, Any]) -> list[bytes]:
        body = json.dumps(payload).encode("utf-8")
        start_response(status, [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
        return [body]


def main() -> None:
    host = os.getenv("WEBHOOK_HOST", "127.0.0.1")
    port = int(os.getenv("WEBHOOK_PORT", "8089"))
    with make_server(host, port, WebhookListener()) as server:
        logger.info("Webhook listener at http://%s:%d", host, port)
        server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
