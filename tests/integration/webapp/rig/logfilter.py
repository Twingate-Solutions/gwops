"""Filters and scrubbers for container logs before they go to run.log."""

import json
import re
from typing import Any

GWOPS_EVENT_PREFIXES = ("gateway.line", "supervisor.", "reconcile.")
_NOISY_LEVELS = frozenset({"warning", "warn", "error", "err", "critical", "fatal"})
_CLIENT_RE = re.compile(r"error|authorize_flow|failed|denied|fatal", re.IGNORECASE)
_SAFE_HEADER_RE = re.compile(
    r"accept|user-agent|content-type|content-length|x-rig-.*|x-twingate-.*|x_twingate.*"
    r"|x-forwarded-.*",
    re.IGNORECASE,
)
REDACTED_HEADER = ["[redacted]"]


def _scrub_headers(headers: dict[str, Any]) -> dict[str, Any]:
    return {
        name: value if _SAFE_HEADER_RE.fullmatch(name) else list(REDACTED_HEADER)
        for name, value in headers.items()
    }


def _scrub_url(url: str) -> str:
    path, sep, query = url.partition("?")
    return f"{path}?[redacted]" if sep and query else url


def scrub_gateway_line(text: str) -> str:
    """Redact header values (except a safe list) and query strings in a gateway audit JSON line.

    Text that is not a JSON object is returned unchanged for the regular redactor.
    """
    try:
        payload = json.loads(text)
    except ValueError:
        return text
    if not isinstance(payload, dict):
        return text
    for side in ("request", "response"):
        part = payload.get(side)
        if isinstance(part, dict):
            if isinstance(part.get("headers"), dict):
                part["headers"] = _scrub_headers(part["headers"])
            if isinstance(part.get("url"), str):
                part["url"] = _scrub_url(part["url"])
    if isinstance(payload.get("url"), str):
        payload["url"] = _scrub_url(payload["url"])
    return json.dumps(payload)


def scrub_gwops_line(raw: str) -> str:
    """Scrub the embedded gateway audit line of a gwops `gateway.line` event; others unchanged."""
    try:
        document = json.loads(raw)
    except ValueError:
        return raw
    if not isinstance(document, dict) or document.get("event") != "gateway.line":
        return raw
    if isinstance(document.get("line"), str):
        document["line"] = scrub_gateway_line(document["line"])
    return json.dumps(document)


def scrub_gwops_log(text: str) -> str:
    """`scrub_gwops_line` over every line of a gwops log."""
    return "\n".join(scrub_gwops_line(line) for line in text.splitlines())


def filter_gwops_log(text: str) -> str:
    """Scrubbed gateway, supervisor and reconcile events plus warnings and errors.

    Lines that are not JSON (tracebacks, raw output) are kept.
    """
    kept: list[str] = []
    for line in text.splitlines():
        try:
            document = json.loads(line)
        except ValueError:
            kept.append(line)
            continue
        if not isinstance(document, dict):
            kept.append(line)
            continue
        event = str(document.get("event", ""))
        level = str(document.get("level", "")).lower()
        if event.startswith(GWOPS_EVENT_PREFIXES) or level in _NOISY_LEVELS:
            kept.append(scrub_gwops_line(line))
    return "\n".join(kept)


def filter_client_log(text: str) -> str:
    """Twingate client log lines that mention an error, a failure, a denial or authorize_flow."""
    return "\n".join(line for line in text.splitlines() if _CLIENT_RE.search(line))
