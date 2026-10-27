"""Rig ingest tap: forwards POST /ingest to Gatorcast and logs per-line metadata.

Env: TAP_LISTEN_PORT, TAP_UPSTREAM (http://host:port), TAP_LOG (JSONL file path).
Each shipped line becomes one `line` record, each POST one `post` record. A record holds sizes,
a sha256, the logger, message, ids, resource address, the recording's sequence number and the
rig's own session-end marker; never recording content, request headers or credentials. The one
exception is a line the gwops allowlist should have dropped: it is marked `allowed: false` with
a short excerpt (at most 100 characters) so the failure can be diagnosed.
"""

import hashlib
import http.client
import json
import os
import re
import sys
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

AUDIT_MESSAGES = frozenset({"API request completed", "API request failed"})
SESSION_MARKER = re.compile(r"RIG-SSH-DONE-[0-9a-f]{12}")
FORWARD_HEADERS = ("Authorization", "Content-Type")
EXCERPT_CHARS = 100
UPSTREAM_TIMEOUT = 120.0


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def describe_line(raw: bytes) -> dict[str, Any]:
    """Metadata of one shipped line, with the allowlist re-implemented independently of gwops."""
    record: dict[str, Any] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {**record, "kind": "invalid_utf8", "allowed": False, "excerpt": repr(raw[:60])}
    document: Any = None
    if text.startswith("{"):
        try:
            document = json.loads(text)
        except ValueError:
            document = None
    if not isinstance(document, dict):
        return {**record, "kind": "text", "allowed": False, "excerpt": text[:EXCERPT_CHARS]}
    logger, message = _text(document.get("logger")), _text(document.get("message"))
    asciicast = document.get("asciicast")
    allowed = (
        (logger == "session_recording" and isinstance(asciicast, str))
        or (logger == "audit" and "asciicast" not in document and message in AUDIT_MESSAGES)
        or (logger == "system" and message == "Authenticated connection")
    )
    record.update(
        kind="json",
        allowed=allowed,
        logger=logger,
        message=message,
        conn_id=_text(document.get("conn_id")),
        resource_type=_text(document.get("resource_type")),
        resource_address=_text(document.get("resource_address")),
    )
    if isinstance(asciicast, str):
        record["asciicast_len"] = len(asciicast)
        sequence = document.get("asciicast_sequence_num")
        record["asciicast_sequence_num"] = sequence if type(sequence) is int else None
        record["markers"] = sorted(set(SESSION_MARKER.findall(asciicast)))
    if isinstance(document.get("gwops"), dict):
        record["gwops"] = document["gwops"]
    if not allowed:
        record["excerpt"] = f"{logger}: {message}"[:EXCERPT_CHARS]
    return record


def split_body(body: bytes) -> list[bytes]:
    """The non-empty newline-separated lines of an ingest body."""
    return [line for line in body.split(b"\n") if line]


class Tap(BaseHTTPRequestHandler):
    """Proxies to the upstream and appends to the log; credentials are forwarded, never logged."""

    protocol_version = "HTTP/1.1"
    upstream = urlsplit("http://gatorcast:8080")
    log_path = "/tap/ingest.jsonl"
    lock = threading.Lock()
    posts = 0

    def _forward(self, method: str, body: bytes | None) -> int:
        headers = {n: v for n in FORWARD_HEADERS if (v := self.headers.get(n)) is not None}
        try:
            conn = http.client.HTTPConnection(
                self.upstream.hostname or "", self.upstream.port or 80, timeout=UPSTREAM_TIMEOUT
            )
            conn.request(method, self.path, body=body, headers=headers)
            response = conn.getresponse()
            response.read()
            conn.close()
            return response.status
        except (OSError, http.client.HTTPException):
            return 502

    def _reply(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _append(self, records: list[dict[str, Any]]) -> None:
        stamp = datetime.now(UTC).isoformat()
        with self.lock, open(self.log_path, "a", encoding="utf-8", newline="\n") as handle:
            handle.writelines(json.dumps({"at": stamp, **r}) + "\n" for r in records)

    def do_GET(self) -> None:  # noqa: N802
        """Relay GET (health probes)."""
        self._reply(self._forward("GET", None))

    def do_POST(self) -> None:  # noqa: N802
        """Relay a POST, then log one `post` record and one `line` record per shipped line."""
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        status = self._forward("POST", body)
        with self.lock:
            type(self).posts += 1
            number = self.posts
        lines = split_body(body)
        records = [
            {
                "rec": "post",
                "post": number,
                "status": status,
                "lines": len(lines),
                "bytes": len(body),
            }
        ]
        records += [
            {"rec": "line", "post": number, "status": status, **describe_line(x)} for x in lines
        ]
        self._append(records)
        self._reply(status)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Request lines only; never a header or body."""
        print("tap:", self.address_string(), format % args, flush=True)


def main() -> int:
    """Serve until killed."""
    Tap.upstream = urlsplit(os.environ.get("TAP_UPSTREAM", "http://gatorcast:8080"))
    Tap.log_path = os.environ.get("TAP_LOG", "/tap/ingest.jsonl")
    port = int(os.environ.get("TAP_LISTEN_PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Tap).serve_forever()  # noqa: S104
    return 0


if __name__ == "__main__":
    sys.exit(main())
