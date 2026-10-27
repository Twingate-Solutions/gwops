"""Redaction for the rig's run log: known secret values plus credential-shaped patterns."""

import json
import os
import re
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REDACTED = "[redacted]"
MIN_SECRET_LENGTH = 6
BLOCK_MAX_CHARS = 200_000

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
        "[redacted-private-key]",
    ),
    (
        re.compile(
            r'(?i)("(?:authorization|proxy-authorization|x-api-key|cookie|set-cookie)"\s*:\s*)'
            r'"(?:[^"\\]|\\.)*"'
        ),
        rf'\1"{REDACTED}"',
    ),
    (
        re.compile(
            r'(?i)("[a-z_]*(?:token|secret|password|private_?key|api_?key)[a-z_]*"\s*:\s*)'
            r'"(?:[^"\\]|\\.)*"'
        ),
        rf'\1"{REDACTED}"',
    ),
    (
        re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization|x-api-key)\s*:\s*)[^\r\n]+"),
        rf"\1{REDACTED}",
    ),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"), f"Bearer {REDACTED}"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        "[redacted-jwt]",
    ),
    (
        re.compile(
            r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|SERVICE_KEY|PRIVATE_KEY)"
            r"[A-Z0-9_]*)\s*=\s*\S+"
        ),
        rf"\1={REDACTED}",
    ),
)


class Redactor:
    """Replaces registered secret values and credential-shaped text with a fixed marker."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        """Start with `secrets`; values shorter than MIN_SECRET_LENGTH are ignored."""
        self._secrets: set[str] = set()
        self._lock = threading.Lock()
        for secret in secrets:
            self.add(secret)

    def add(self, secret: str) -> None:
        """Register one more secret value (and each non-trivial line of a multi-line one)."""
        for piece in (secret, *secret.splitlines()):
            piece = piece.strip()
            if len(piece) >= MIN_SECRET_LENGTH:
                with self._lock:
                    self._secrets.add(piece)

    def redact(self, text: str) -> str:
        """Return `text` with every known secret and credential-shaped span replaced."""
        with self._lock:
            known = sorted(self._secrets, key=len, reverse=True)
        for secret in known:
            text = text.replace(secret, REDACTED)
        for pattern, replacement in _PATTERNS:
            text = pattern.sub(replacement, text)
        return text


def _string_leaves(value: Any) -> list[str]:
    """Every string in a decoded JSON value, keys excluded."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [leaf for item in value.values() for leaf in _string_leaves(item)]
    if isinstance(value, list):
        return [leaf for item in value for leaf in _string_leaves(item)]
    return []


def secret_values_from_env_text(text: str, *, exclude: Iterable[str] = ()) -> list[str]:
    """Values of `NAME=value` lines, plus every JSON string leaf of a JSON value.

    `exclude` lists public values (such as the tenant name) that must stay readable in the log.
    """
    skipped = set(exclude)
    found: list[str] = []
    for line in text.splitlines():
        _name, sep, raw = line.partition("=")
        value = raw.strip().strip("'\"")
        if not sep or not value:
            continue
        found.append(value)
        try:
            decoded = json.loads(value)
        except ValueError:
            continue
        found.extend(leaf for leaf in _string_leaves(decoded) if len(leaf) >= MIN_SECRET_LENGTH)
    return [value for value in found if value not in skipped]


class RunLog:
    """Append-only run log that redacts every line on write; console output is redacted too."""

    def __init__(self, path: Path, redactor: Redactor, *, echo: bool = True) -> None:
        """Open `path` for appending; `echo` also prints each redacted line."""
        self._path = path
        self._redactor = redactor
        self._echo = echo
        self._lock = threading.Lock()
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600))

    @property
    def redactor(self) -> Redactor:
        """The redactor applied to every write."""
        return self._redactor

    def add_secret(self, secret: str) -> None:
        """Register a secret value for redaction from now on."""
        self._redactor.add(secret)

    def _append(self, lines: list[str], echo: bool | None) -> None:
        stamp = datetime.now(UTC).strftime("%H:%M:%S")
        text = "".join(f"{stamp} {line}\n" for line in lines)
        with self._lock:
            with self._path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
            if self._echo if echo is None else echo:
                print(text, end="", flush=True)

    def write(self, line: str, *, echo: bool | None = None) -> None:
        """Append one redacted line, timestamped; `echo` overrides the console setting."""
        self._append([self._redactor.redact(line).rstrip("\n")], echo)

    def event(self, event: str, /, **fields: Any) -> None:
        """Append `event key=value ...`; fields may be named `name` or `event`."""
        parts = [event, *(f"{key}={value}" for key, value in fields.items())]
        self.write(" ".join(parts))

    def block(
        self, title: str, text: str, *, max_chars: int = BLOCK_MAX_CHARS, echo: bool = True
    ) -> None:
        """Append a titled multi-line excerpt, truncated to its tail; `echo` shows it on screen."""
        safe = self._redactor.redact(text)
        if len(safe) > max_chars:
            safe = "...[truncated]\n" + safe[-max_chars:]
        header = f"--- {self._redactor.redact(title)} ---"
        self._append([header, *(f"  {line}" for line in safe.splitlines())], echo)
