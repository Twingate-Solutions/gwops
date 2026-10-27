"""structlog configuration for gwops: JSON lines to stdout, secrets redacted."""

import logging
import re
import sys
from typing import Any

import structlog

_SECRET_KEY_RE = re.compile(
    r"token|key|secret|password|passphrase|auth|credential|bearer|cookie|signature",
    re.IGNORECASE,
)
_REDACTED = "[REDACTED]"

# Keys structlog itself owns; their values are messages, not secrets.
_EXEMPT_KEYS = frozenset({"event", "level", "timestamp", "logger"})


def looks_secret(key: str) -> bool:
    """True if `key` names something secret-like that must never be logged or served.

    Shared by the structlog redaction processor and the admin API's state redaction.
    """
    return _SECRET_KEY_RE.search(key) is not None


def _redact_value(key: str, value: Any) -> Any:
    # Taint propagation: once a key matches the secret pattern, redact its ENTIRE
    # value — scalar, list, or dict — before descending, so a secret nested under a
    # secret-named key (e.g. {"api_key": {"value": ...}}) cannot leak.
    if _SECRET_KEY_RE.search(key):
        return _REDACTED
    if isinstance(value, dict):
        return {k: _redact_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(key, item) for item in value]
    return value


def redact_secrets(
    logger: structlog.types.WrappedLogger | None,
    method_name: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    """Redact values whose key looks secret (recursive, with taint propagation).

    A key matching :data:`_SECRET_KEY_RE` redacts its entire value — including nested
    dicts and lists — so a secret cannot hide one level below a secret-named key.
    """
    return {
        k: (v if k in _EXEMPT_KEYS else _redact_value(k, v)) for k, v in event_dict.items()
    }


def configure_logging(level: int = logging.INFO) -> None:
    """Configure structlog to emit JSON lines to stdout with secret redaction."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            redact_secrets,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(sys.stdout),
        cache_logger_on_first_use=False,
    )
