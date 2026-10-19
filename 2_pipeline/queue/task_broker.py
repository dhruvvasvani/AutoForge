"""Compatibility facade for the shared Redis producer."""

from __future__ import annotations

from typing import Any

from redis_producer import ASTScanProducer


class TaskBroker:
    def __init__(self, producer: ASTScanProducer | None = None) -> None:
        self.producer = producer or ASTScanProducer()

    def enqueue_scan_request(
        self,
        repository: dict[str, Any],
        files: dict[str, str],
        scan_id: str | None = None,
        priority: str = "normal",
    ) -> dict[str, Any]:
        return self.producer.enqueue_scan_request(repository, files, scan_id, priority)

    def enqueue_webhook_scan(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.producer.enqueue_webhook_scan(*args, **kwargs)
