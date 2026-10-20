"""Prometheus metrics for analyzer scans, detections, inference, and memory."""

from __future__ import annotations

from collections.abc import Generator, Mapping, Sequence
from contextlib import contextmanager
from typing import Any

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from prometheus_client.exposition import start_http_server

_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM"})
_MODEL_LABELS = frozenset({"cpg_gnn", "noise_filter"})


class MetricsCollector:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.scan_duration = Histogram(
            "ast_scan_duration_seconds",
            "Time spent analyzing source files and code property graphs.",
            registry=self.registry,
        )
        self.vulnerabilities_detected = Counter(
            "vulnerabilities_detected",
            "Security findings produced by the analyzer.",
            labelnames=("severity",),
            registry=self.registry,
        )
        self.inference_latency = Histogram(
            "ml_inference_latency_seconds",
            "Time spent in ML inference.",
            labelnames=("model",),
            registry=self.registry,
        )
        self.memory_usage = Gauge(
            "memory_usage_bytes",
            "Resident memory used by the analyzer process.",
            registry=self.registry,
        )
        self._metrics_server: Any = None

    @contextmanager
    def track_scan(self) -> Generator[None, None, None]:
        with self.scan_duration.time():
            yield

    @contextmanager
    def track_inference(self, model: str) -> Generator[None, None, None]:
        if not isinstance(model, str) or model not in _MODEL_LABELS:
            raise ValueError(f"model must be one of {sorted(_MODEL_LABELS)}")
        with self.inference_latency.labels(model=model).time():
            yield

    def record_findings(
        self,
        findings: int | Sequence[Mapping[str, Any]],
        *,
        severity: str = "MEDIUM",
    ) -> None:
        counts: dict[str, int] = {}
        if isinstance(findings, bool):
            raise ValueError("findings must be a non-negative count or findings list")
        if isinstance(findings, int):
            if findings < 0:
                raise ValueError("findings count must be non-negative")
            if not isinstance(severity, str) or severity.upper() not in _SEVERITIES:
                raise ValueError(f"unsupported severity {severity!r}")
            counts[severity.upper()] = findings
        elif isinstance(findings, Sequence) and not isinstance(findings, (str, bytes)):
            for index, finding in enumerate(findings):
                if not isinstance(finding, Mapping):
                    raise ValueError(f"finding {index} must be an object")
                severity = finding.get("severity", "MEDIUM")
                if not isinstance(severity, str) or severity.upper() not in _SEVERITIES:
                    raise ValueError(f"finding {index} has unsupported severity {severity!r}")
                severity = severity.upper()
                counts[severity] = counts.get(severity, 0) + 1
        else:
            raise ValueError("findings must be a non-negative count or findings list")
        for severity, count in counts.items():
            self.vulnerabilities_detected.labels(severity=severity).inc(count)

    def update_memory_usage(self, rss_bytes: int | None = None) -> int:
        if rss_bytes is None:
            try:
                import psutil
            except ImportError as error:
                raise RuntimeError(
                    "memory metrics require psutil; install 3_ast_analyzer\\requirements.txt"
                ) from error
            rss_bytes = psutil.Process().memory_info().rss
        if isinstance(rss_bytes, bool) or not isinstance(rss_bytes, int) or rss_bytes < 0:
            raise ValueError("rss_bytes must be a non-negative integer")
        self.memory_usage.set(rss_bytes)
        return rss_bytes

    def render(self) -> bytes:
        return generate_latest(self.registry)

    @property
    def content_type(self) -> str:
        return CONTENT_TYPE_LATEST

    def start_server(self, port: int = 8000, addr: str = "127.0.0.1") -> Any:
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
            raise ValueError("port must be an integer between 1 and 65535")
        if not isinstance(addr, str) or not addr:
            raise ValueError("addr must be a non-empty string")
        if self._metrics_server is not None:
            raise RuntimeError("metrics server is already running")
        self._metrics_server, thread = start_http_server(
            port,
            addr=addr,
            registry=self.registry,
        )
        return thread

    def stop_server(self) -> None:
        if self._metrics_server is None:
            return
        self._metrics_server.shutdown()
        self._metrics_server.server_close()
        self._metrics_server = None
