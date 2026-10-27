"""Allowlist classifier for gateway stderr lines: keep audit and session data, drop the rest."""

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class DropReason(StrEnum):
    """Why a line was not shipped; values are the counter keys."""

    NOT_JSON = "not_json"
    NOT_ALLOWLISTED = "not_allowlisted"
    TOO_LONG = "too_long"
    SPOOL_FAILED = "spool_failed"


@dataclass(frozen=True, slots=True)
class Verdict:
    """Classification of one line; ``obj`` is the parsed object when the line is kept."""

    keep: bool
    reason: DropReason | None = None
    obj: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        """Refuse a drop without a reason, so no line is dropped uncounted."""
        if not self.keep and self.reason is None:
            raise ValueError("a dropped line needs a reason")


_NOT_JSON = Verdict(keep=False, reason=DropReason.NOT_JSON)
_NOT_ALLOWLISTED = Verdict(keep=False, reason=DropReason.NOT_ALLOWLISTED)

# Gateway logger names; only lines from these loggers are shipped.
_SYSTEM_LOGGER = "system"
_AUDIT_LOGGER = "audit"
_RECORDING_LOGGER = "session_recording"
_HTTP_AUDIT_MESSAGES = frozenset({"API request completed", "API request failed"})
_AUTHENTICATED = "Authenticated connection"


def _allowlisted(obj: dict[str, Any]) -> bool:
    """Return True if the parsed object is one of the shippable shapes.

    A recording line (a segment or the final line of an SSH or Kubernetes session) is any
    `session_recording` line whose `asciicast` is a string; the message is not consulted.
    """
    logger = obj.get("logger")
    message = obj.get("message")
    if logger == _RECORDING_LOGGER:
        return isinstance(obj.get("asciicast"), str)
    if logger == _AUDIT_LOGGER:
        return (
            "asciicast" not in obj and isinstance(message, str) and message in _HTTP_AUDIT_MESSAGES
        )
    return logger == _SYSTEM_LOGGER and message == _AUTHENTICATED


def classify(line: bytes) -> Verdict:
    """Classify one line (no trailing newline); never raises."""
    if line[:1] != b"{":
        return _NOT_JSON
    try:
        obj = json.loads(line.decode("utf-8"))
    except (ValueError, RecursionError):  # ValueError covers UnicodeDecodeError
        return _NOT_JSON
    if not isinstance(obj, dict):
        return _NOT_JSON
    if not _allowlisted(obj):
        return _NOT_ALLOWLISTED
    return Verdict(keep=True, obj=obj)


def system_fields(line: bytes) -> dict[str, Any] | None:
    """Return the parsed fields of a gateway `system` log line, or None for anything else.

    Fail closed: only a JSON object whose `logger` is exactly ``system`` and that has no
    `asciicast` key qualifies. Non-JSON, malformed, non-UTF-8, `audit`, `session_recording`
    and unnamed lines all return None, as does a line that claims to be a system line while
    carrying a recording payload. Never raises. Used for the operator-visible relay only; it
    does not affect what is spooled or shipped.
    """
    if line[:1] != b"{":
        return None
    try:
        obj = json.loads(line.decode("utf-8"))
    except (ValueError, RecursionError):
        return None
    if not isinstance(obj, dict) or obj.get("logger") != _SYSTEM_LOGGER:
        return None
    if "asciicast" in obj:
        return None
    return obj
