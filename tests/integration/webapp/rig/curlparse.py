"""Parsing of `curl -i` output and of the echo/verifier JSON bodies; pure functions."""

import json
import re
from dataclasses import dataclass, field
from typing import Any

_STATUS_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})")


@dataclass(frozen=True)
class CurlResult:
    """One curl invocation: exit code, HTTP status (None when no response), headers, body."""

    exit_code: int
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    stderr: str = ""

    def json(self) -> dict[str, Any] | None:
        """The body as a JSON object, or None."""
        try:
            value = json.loads(self.body)
        except ValueError:
            return None
        return value if isinstance(value, dict) else None

    def seen_headers(self) -> dict[str, list[str]]:
        """Request headers an echo or verifier reported, by lowercase name (all values)."""
        document = self.json() or {}
        reported = document.get("headers")
        pairs: list[tuple[str, str]] = []
        if isinstance(reported, list):
            pairs = [
                (str(p[0]), str(p[1])) for p in reported if isinstance(p, list) and len(p) == 2
            ]
        elif isinstance(reported, dict):
            pairs = [(str(k), str(v)) for k, v in reported.items()]
        seen: dict[str, list[str]] = {}
        for name, value in pairs:
            seen.setdefault(name.lower(), []).append(value)
        return seen

    def line(self) -> str:
        """A one-line description for logs: exit code and status, never the body."""
        return f"exit={self.exit_code} status={self.status}"


def parse_curl_output(exit_code: int, stdout: str, stderr: str = "") -> CurlResult:
    """Split `curl -i` stdout into the final response's status, headers and body."""
    text = stdout.replace("\r\n", "\n")
    status: int | None = None
    headers: dict[str, str] = {}
    body = text
    while True:
        head, sep, rest = body.partition("\n\n")
        match = _STATUS_RE.match(head)
        if match is None or not sep:
            if match is not None and not sep:
                status, headers, body = int(match.group(1)), _headers(head), ""
            break
        status, headers, body = int(match.group(1)), _headers(head), rest
        if not 100 <= status < 200:
            break
    if status is None:
        body = text
    return CurlResult(exit_code, status, headers, body, stderr)


def _headers(head: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in head.split("\n")[1:]:
        name, sep, value = line.partition(":")
        if sep:
            parsed[name.strip().lower()] = value.strip()
    return parsed
