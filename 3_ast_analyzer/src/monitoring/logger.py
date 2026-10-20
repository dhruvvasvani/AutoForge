"""Structured JSON logging for security audit events."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

_SENSITIVE_KEY = re.compile(r"(?:authorization|password|secret|token|credential|api[_-]?key)", re.I)


def _redact(value: Any, key: str = "") -> Any:
    if _SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(name): _redact(item, str(name)) for name, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        fields = getattr(record, "audit_fields", {})
        if fields:
            if not isinstance(fields, dict):
                raise TypeError("audit_fields must be a dictionary")
            event.update(_redact(fields))
        if record.exc_info:
            event["exception"] = self.formatException(record.exc_info)
        return json.dumps(event, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def get_security_logger(
    name: str = "autoforge.security",
    *,
    level: int = logging.INFO,
) -> logging.Logger:
    if not isinstance(name, str) or not name.strip():
        raise ValueError("logger name must be a non-empty string")
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False
    if not any(isinstance(handler.formatter, JSONFormatter) for handler in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
    return logger


def log_security_event(
    event: str,
    *,
    outcome: str,
    logger: logging.Logger | None = None,
    **fields: Any,
) -> None:
    if not isinstance(event, str) or not event.strip():
        raise ValueError("event must be a non-empty string")
    if not isinstance(outcome, str) or not outcome.strip():
        raise ValueError("outcome must be a non-empty string")
    audit_logger = logger or get_security_logger()
    audit_logger.info(
        event,
        extra={"audit_fields": {"event": event, "outcome": outcome, **fields}},
    )
