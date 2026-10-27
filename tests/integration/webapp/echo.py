"""Rig echo upstream: returns the request line and received headers as JSON, over HTTP or TLS 1.3.

Env: ECHO_HTTP_PORT and/or ECHO_HTTPS_PORT, plus ECHO_CERT and ECHO_KEY for HTTPS. Credential
headers are reported as present but never echoed back.
"""

import json
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

REDACTED_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie"})


class Echo(BaseHTTPRequestHandler):
    """Answers every method with a JSON description of the request."""

    protocol_version = "HTTP/1.1"

    def _reply(self) -> None:
        tls = isinstance(self.connection, ssl.SSLSocket)
        headers = [
            [name, "[redacted]" if name.lower() in REDACTED_HEADERS else value]
            for name, value in self.headers.items()
        ]
        body = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "scheme": "https" if tls else "http",
                "tls_version": self.connection.version()
                if isinstance(self.connection, ssl.SSLSocket)
                else None,
                "headers": headers,
            },
            indent=2,
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _reply

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Log the request line, never a header."""
        print("echo:", self.address_string(), format % args, flush=True)


class TLSEchoServer(ThreadingHTTPServer):
    """Handshakes in the per-connection thread so a stalled client cannot block accept."""

    def __init__(self, address: tuple[str, int], context: ssl.SSLContext) -> None:
        """Bind `address`; `context` is applied to each accepted connection."""
        super().__init__(address, Echo)
        self._context = context

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        """Wrap the connection in TLS, then handle it; a failed handshake drops the client."""
        request.settimeout(10)
        try:
            wrapped = self._context.wrap_socket(request, server_side=True)
        except (TimeoutError, ssl.SSLError, OSError):
            self.shutdown_request(request)
            return
        wrapped.settimeout(None)
        super().process_request_thread(wrapped, client_address)


def tls13_context(cert: str, key: str) -> ssl.SSLContext:
    """A server context that accepts TLS 1.3 only."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert, key)
    return context


def main() -> None:
    """Serve the configured ports until killed."""
    http_port = os.environ.get("ECHO_HTTP_PORT")
    https_port = os.environ.get("ECHO_HTTPS_PORT")
    if not http_port and not https_port:
        sys.exit("set ECHO_HTTP_PORT and/or ECHO_HTTPS_PORT")
    servers: list[ThreadingHTTPServer] = []
    if https_port:
        cert, key = os.environ.get("ECHO_CERT"), os.environ.get("ECHO_KEY")
        if not cert or not key:
            sys.exit("ECHO_HTTPS_PORT needs ECHO_CERT and ECHO_KEY")
        servers.append(TLSEchoServer(("0.0.0.0", int(https_port)), tls13_context(cert, key)))
    if http_port:
        servers.append(ThreadingHTTPServer(("0.0.0.0", int(http_port)), Echo))
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
