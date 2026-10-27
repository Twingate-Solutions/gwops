"""Failure diagnostics: repeat a failed request verbosely and capture logs; never raises."""

import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from . import logfilter
from .redact import RunLog

SINCE_MARGIN = timedelta(seconds=5)
DIAGNOSTIC_MAX_CHARS = 100_000
_AUTH_LINE_RE = re.compile(r"authorization|bearer\s", re.IGNORECASE)


def since_arg(moment: datetime) -> str:
    """`docker logs --since` value for `moment`, backed off to absorb engine clock skew."""
    return (moment.astimezone(UTC) - SINCE_MARGIN).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def scrub_verbose(text: str) -> str:
    """Drop every line that mentions an Authorization header or a bearer token."""
    return "\n".join(line for line in text.splitlines() if not _AUTH_LINE_RE.search(line))


async def _repeat_request(
    docker: Any, http: Any, log: RunLog, number: str, mono_start: float
) -> None:
    last = http.last
    if last is None or last.at < mono_start:
        return
    result = await docker.curl(
        last.url,
        cacert=last.cacert,
        headers=last.headers,
        max_time=last.max_time,
        verbose=True,
    )
    log.block(
        f"diagnostic {number}: curl -v {last.url} ({result.line()})",
        scrub_verbose(f"{result.stderr}\n{result.body}"),
        max_chars=DIAGNOSTIC_MAX_CHARS,
        echo=False,
    )


async def _capture_logs(docker: Any, log: RunLog, number: str, wall_start: datetime) -> None:
    since = since_arg(wall_start)
    for service in ("gwops", "client"):
        text = await docker.logs(docker.container(service), since=since)
        if service == "gwops":
            text = logfilter.scrub_gwops_log(text)
        log.block(
            f"diagnostic {number}: {service} logs since {since}",
            text,
            max_chars=DIAGNOSTIC_MAX_CHARS,
            echo=False,
        )


async def diagnose_failure(
    docker: Any,
    http: Any,
    log: RunLog,
    number: str,
    *,
    wall_start: datetime,
    mono_start: float,
) -> None:
    """Re-run the last request with `curl -v` and log gwops/client logs; each step alone."""
    steps: list[Callable[[], Awaitable[None]]] = [
        lambda: _repeat_request(docker, http, log, number, mono_start),
        lambda: _capture_logs(docker, log, number, wall_start),
    ]
    for step in steps:
        try:
            await step()
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"[:200]
            log.event("diagnostic-failed", assertion=number, error=error)
