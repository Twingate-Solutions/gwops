"""Async GraphQL client for the Twingate admin API.

One :class:`TGClient` owns one persistent ``httpx.AsyncClient``. Every call goes
through :meth:`TGClient.execute`, which retries transient failures (429, 5xx,
transport errors) and raises a typed :class:`~gwops.tgapi.errors.TGAPIError` for
anything else. 5xx and transport errors back off exponentially with jitter; a 429
waits for the server's own throttle hint (``Retry-After``, else the "Expected
available in N seconds" body text), capped at :data:`_THROTTLE_WAIT_CAP_SECONDS`,
plus jitter. Every call is logged with the GraphQL operation name, HTTP status, and
duration — never the API key.

A pass-wide budget (:data:`_PASS_THROTTLE_BUDGET_SECONDS`) bounds the total time the
client sleeps on 429s between two :meth:`TGClient.begin_pass` calls; a wait that would
exceed what is left raises :class:`~gwops.tgapi.errors.TGRateLimited` at once instead of
sleeping, so a throttled tenant cannot hold a reconcile pass for minutes per call.

The client counts throttled mutations (:attr:`TGClient.write_throttle_count`) so a
caller that batches writes can stop once the tenant has throttled one.

Every request carries an attribution ``User-Agent`` built by :func:`build_user_agent`.
The client-level default carries the config dimensions; :meth:`TGClient.execute`
overrides it per call.
"""

import asyncio
import contextlib
import json
import math
import random
import re
import time
from collections.abc import Iterable, Iterator
from contextvars import ContextVar
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Literal

import httpx
import structlog

from gwops._version import __version__
from gwops.tgapi.errors import TGAPIError, TGAuthError, TGGraphQLError, TGRateLimited

logger = structlog.get_logger(__name__)

PRODUCT = "twingate-gwops-gateway"
_UA_VALUE_RE = re.compile(r"[a-z0-9,._-]*")
# Same rule the image build applies to the GWOPS_VERSION build arg.
_UA_VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,63}")

# What triggered the current TG calls; read by TGClient.execute for the UA's ``via`` key.
_attribution_via: ContextVar[str | None] = ContextVar("gwops_attribution_via", default=None)

_MAX_ATTEMPTS = 6
_BACKOFF_BASE_SECONDS = 1.0
_BACKOFF_CAP_SECONDS = 30.0
_REQUEST_TIMEOUT_SECONDS = 30.0

# A server-hinted 429 wait is capped here, then up to _THROTTLE_JITTER_MAX_SECONDS of
# jitter is added so concurrent callers released by the same hint do not stampede.
_THROTTLE_WAIT_CAP_SECONDS = 60.0
_THROTTLE_JITTER_MAX_SECONDS = 1.0

# Cumulative 429-sleep allowance per reconcile pass (see TGClient.begin_pass). Without it
# each call can sleep 5 x ~61 s, and a pass makes many calls.
_PASS_THROTTLE_BUDGET_SECONDS = 90.0

# A GraphQL document may open with `#` comment lines before the operation keyword.
_LEADING_BLANK_AND_COMMENTS = r"^\s*(?:#[^\n]*\n\s*)*"
_OPERATION_NAME_RE = re.compile(
    _LEADING_BLANK_AND_COMMENTS + r"(?:query|mutation)\s+([A-Za-z_]\w*)"
)
_MUTATION_RE = re.compile(_LEADING_BLANK_AND_COMMENTS + r"mutation\b")
# Delta-seconds is bounded to 9 digits: a longer value is nonsense, and `int()` of
# thousands of digits raises ValueError (the int string-conversion limit).
_RETRY_AFTER_SECONDS_RE = re.compile(r"\d{1,9}", re.ASCII)
_BODY_HINT_RE = re.compile(r"Expected available in (\d+(?:\.\d+)?) seconds?", re.IGNORECASE)


def _ua_set(values: Iterable[str]) -> str:
    """Render a set-valued UA key: sorted, de-duplicated, comma-joined; empty is ``none``."""
    return ",".join(sorted(set(values))) or "none"


def build_user_agent(
    *,
    version: str = __version__,
    kinds: Iterable[str] | None = None,
    tls: Iterable[str] | None = None,
    op: str | None = None,
    via: str | None = None,
) -> str:
    """Build the attribution User-Agent string.

    Format: ``twingate-gwops-gateway/<version> (k=v; k=v) python-httpx/<httpx version>``.

    The key order is fixed: ``kinds``, ``tls``, ``op``, ``via``. It must never change, and
    a key must never be reused for a different meaning; downstream log extraction is
    positional. A key passed as ``None`` is omitted without disturbing the order of the
    rest; when no key is present the parenthesised comment is omitted entirely.

    ``kinds`` and ``tls`` are sorted, de-duplicated and comma-joined; an empty set renders
    ``none``. ``tls`` is computed by the caller: an empty set means no ``public_tls`` block
    (private-CA mode), otherwise the set of certificate sources (``file``, ``acme``).

    :raises ValueError: `version` does not match the build's version rule, or a rendered
        comment value contains a character outside ``[a-z0-9,._-]``.
    """
    if not _UA_VERSION_RE.fullmatch(version):
        raise ValueError("User-Agent version has characters outside [0-9A-Za-z._-]")
    pairs: list[tuple[str, str]] = []
    if kinds is not None:
        pairs.append(("kinds", _ua_set(kinds)))
    if tls is not None:
        pairs.append(("tls", _ua_set(tls)))
    if op is not None:
        pairs.append(("op", op))
    if via is not None:
        pairs.append(("via", via))

    for key, value in pairs:
        if not _UA_VALUE_RE.fullmatch(value):
            raise ValueError(f"User-Agent value for {key!r} has characters outside [a-z0-9,._-]")

    comment = f" ({'; '.join(f'{k}={v}' for k, v in pairs)})" if pairs else ""
    return f"{PRODUCT}/{version}{comment} python-httpx/{httpx.__version__}"


@contextlib.contextmanager
def attribution_via(via: Literal["reconcile", "admin_api"]) -> Iterator[None]:
    """Mark TG calls made inside the block as triggered by `via` (the UA's ``via`` key).

    asyncio tasks created inside the block copy the context and keep `via` for their whole
    life, after the block exits. A long-lived task that will call TG must not be started
    from inside one.
    """
    token = _attribution_via.set(via)
    try:
        yield
    finally:
        _attribution_via.reset(token)


def _operation_name(query: str) -> str:
    """Best-effort extraction of the named GraphQL operation, for logging.

    Falls back to ``"anonymous"`` for unnamed operations (e.g. ``query { ... }``).
    """
    match = _OPERATION_NAME_RE.match(query)
    return match.group(1) if match else "anonymous"


def _backoff_delay(attempt: int) -> float:
    """Full-jitter exponential backoff delay (seconds) for a failed `attempt`.

    ``attempt`` is 1-indexed (the attempt that just failed). Grows as
    ``base * 2**(attempt-1)``, capped at ``_BACKOFF_CAP_SECONDS``, then a
    uniform random value in ``[0, ceiling]`` is returned so concurrent callers
    don't retry in lockstep.
    """
    ceiling = min(_BACKOFF_CAP_SECONDS, _BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)))
    return random.uniform(0, ceiling)


def _utcnow() -> datetime:
    """Current UTC time; a seam so tests can pin the clock for HTTP-date parsing."""
    return datetime.now(UTC)


def _is_mutation(query: str) -> bool:
    """True when `query` is a GraphQL mutation (a TG write)."""
    return _MUTATION_RE.match(query) is not None


def _parse_retry_after(value: str, now: datetime) -> float | None:
    """Seconds to wait per a ``Retry-After`` header value, or None if unparseable.

    Accepts delta-seconds (``"30"``) or an HTTP-date (``"Wed, 21 Oct 2026 07:28:00
    GMT"``, converted relative to `now`; a date in the past yields ``0.0``).
    """
    value = value.strip()
    if _RETRY_AFTER_SECONDS_RE.fullmatch(value):
        return float(int(value))
    try:
        when = parsedate_to_datetime(value)
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        seconds = max(0.0, (when - now).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None
    return seconds if math.isfinite(seconds) else None


def _parse_body_hint(body: str) -> float | None:
    """Seconds from a body hint like ``"Expected available in 12 seconds"``, or None."""
    match = _BODY_HINT_RE.search(body)
    if match is None:
        return None
    try:
        seconds = float(match.group(1))
    except (TypeError, ValueError, OverflowError):
        return None
    # An absurdly long digit run parses to inf, which would also be logged as non-JSON.
    return seconds if math.isfinite(seconds) else None


def _throttle_wait(response: httpx.Response, attempt: int) -> tuple[float, str, float | None]:
    """How long to wait after a 429, and why.

    Returns ``(wait_seconds, source, server_hint_seconds)``. The server hint comes from
    ``Retry-After`` if it parses, else the body's "Expected available in N seconds"
    text; it is capped at :data:`_THROTTLE_WAIT_CAP_SECONDS` and then up to
    :data:`_THROTTLE_JITTER_MAX_SECONDS` of jitter is added. With no usable hint the
    wait falls back to the exponential :func:`_backoff_delay` (already jittered) and
    `server_hint_seconds` is None.
    """
    header = response.headers.get("Retry-After")
    try:
        hint: float | None = None
        source = "retry-after"
        if header is not None:
            hint = _parse_retry_after(header, _utcnow())
            if hint is None:
                logger.warning("tgapi.retry_after_unparseable", retry_after=header[:64])
        if hint is None:
            hint = _parse_body_hint(response.text)
            source = "body-hint"
        if hint is None:
            return _backoff_delay(attempt), "backoff", None
        wait = min(hint, _THROTTLE_WAIT_CAP_SECONDS) + random.uniform(
            0, _THROTTLE_JITTER_MAX_SECONDS
        )
    except Exception:
        # A server-supplied header/body value must never escape execute() as anything but
        # a TGAPIError: treat any failure deriving the hint as "no hint".
        logger.warning(
            "tgapi.retry_after_unparseable",
            retry_after=(header or "")[:64],
            reason="hint derivation failed",
        )
        return _backoff_delay(attempt), "backoff", None
    return wait, source, hint


class TGClient:
    """Thin async GraphQL client for ``https://<network>.<host>/api/graphql/``."""

    def __init__(
        self,
        network: str,
        api_key: str,
        host: str = "twingate.com",
        *,
        version: str = __version__,
    ) -> None:
        """Build a client for the tenant `network` under `host`, authenticated by `api_key`.

        `version` is the build identity reported in the attribution User-Agent.
        """
        self._url = f"https://{network}.{host}/api/graphql/"
        self._version = version
        self._attr_kinds: tuple[str, ...] | None = None
        self._attr_tls: tuple[str, ...] | None = None
        self._client = httpx.AsyncClient(
            headers={
                "X-API-KEY": api_key,
                "Content-Type": "application/json",
                "User-Agent": build_user_agent(version=version),
            },
            timeout=httpx.Timeout(_REQUEST_TIMEOUT_SECONDS),
        )
        self._write_throttle_count = 0
        self._throttle_budget_remaining = _PASS_THROTTLE_BUDGET_SECONDS

    def set_attribution(self, kinds: Iterable[str], tls: Iterable[str]) -> None:
        """Record the configured resource kinds and TLS certificate sources for the UA.

        Called by the reconciler after each successful effective-state load. Updates the
        client's default ``User-Agent`` to the config-level string (no ``op``/``via``).
        """
        self._attr_kinds = tuple(kinds)
        self._attr_tls = tuple(tls)
        self._client.headers["User-Agent"] = build_user_agent(
            version=self._version, kinds=self._attr_kinds, tls=self._attr_tls
        )

    def begin_pass(self) -> None:
        """Start a new reconcile pass: restore the full 429-sleep budget.

        The budget (:data:`_PASS_THROTTLE_BUDGET_SECONDS`) is the total time this client
        may sleep on 429s between two calls to this method. Calls made outside a pass
        draw from the same pool until the next reset.
        """
        self._throttle_budget_remaining = _PASS_THROTTLE_BUDGET_SECONDS

    @property
    def throttle_budget_remaining(self) -> float:
        """Seconds of 429 sleeping left in the current pass's budget."""
        return self._throttle_budget_remaining

    @property
    def write_throttle_count(self) -> int:
        """How many HTTP 429 responses mutations have received over this client's life.

        Monotonic. A caller snapshots it before a batch of writes and compares after
        each write: a higher value means the tenant throttled a write (even if the
        retry then succeeded), so the caller should stop issuing further writes.
        Reads never move it.
        """
        return self._write_throttle_count

    async def aclose(self) -> None:
        """Close the underlying HTTP client. Call once when done with this TGClient."""
        await self._client.aclose()

    async def execute(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        """Execute one GraphQL operation and return its ``data`` payload.

        Retries on HTTP 429, 5xx, and transport-level errors (up to
        :data:`_MAX_ATTEMPTS` attempts total). 5xx and transport errors use
        exponential backoff with jitter. A 429 waits for ``Retry-After`` (seconds or
        HTTP-date), else the body's "Expected available in N seconds" hint, capped at
        :data:`_THROTTLE_WAIT_CAP_SECONDS` plus jitter; with neither it falls back to
        the exponential backoff. A throttled mutation also increments
        :attr:`write_throttle_count`. The sleep is drawn from the per-pass budget (see
        :meth:`begin_pass`); a wait that would exceed what is left raises
        :class:`~gwops.tgapi.errors.TGRateLimited` immediately. Any
        other 4xx response raises immediately without retrying. A 200 response
        whose body carries a GraphQL ``errors[]`` array raises immediately
        (never retried — it's a query/mutation defect, not a transient fault).

        :raises TGAuthError: HTTP 401 or 403.
        :raises TGRateLimited: HTTP 429 after retries are exhausted, or the pass's 429-sleep
            budget cannot cover the next wait.
        :raises TGGraphQLError: 200 OK with a GraphQL ``errors[]`` array.
        :raises TGAPIError: any other non-2xx status, a transport failure after
            retries (if applicable) are exhausted, or a 200 OK response whose body
            is not valid JSON or is valid JSON but not a top-level object.
        """
        op_name = _operation_name(query)
        is_write = _is_mutation(query)
        payload = {"query": query, "variables": variables}
        headers = {
            "User-Agent": build_user_agent(
                version=self._version,
                kinds=self._attr_kinds,
                tls=self._attr_tls,
                op="write" if is_write else "read",
                via=_attribution_via.get(),
            )
        }

        for attempt in range(1, _MAX_ATTEMPTS + 1):
            start = time.monotonic()
            try:
                response = await self._client.post(self._url, json=payload, headers=headers)
            except httpx.TransportError as exc:
                duration = time.monotonic() - start
                logger.warning(
                    "tgapi.transport_error",
                    query_name=op_name,
                    attempt=attempt,
                    duration=duration,
                    error=str(exc),
                )
                if attempt == _MAX_ATTEMPTS:
                    raise TGAPIError(
                        f"{op_name} failed: transport error: {exc}",
                        status=None,
                        query_name=op_name,
                        body=str(exc),
                    ) from exc
                await asyncio.sleep(_backoff_delay(attempt))
                continue

            duration = time.monotonic() - start
            status = response.status_code
            logger.info(
                "tgapi.request",
                query_name=op_name,
                status=status,
                duration=duration,
                attempt=attempt,
            )

            if status in (401, 403):
                raise TGAuthError(
                    f"{op_name} failed: HTTP {status}",
                    status=status,
                    query_name=op_name,
                    body=response.text,
                )

            if status == 429:
                if is_write:
                    self._write_throttle_count += 1
                if attempt == _MAX_ATTEMPTS:
                    raise TGRateLimited(
                        f"{op_name} rate-limited after {attempt} attempts",
                        status=status,
                        query_name=op_name,
                        body=response.text,
                    )
                wait, source, hint = _throttle_wait(response, attempt)
                if wait > self._throttle_budget_remaining:
                    logger.warning(
                        "tgapi.throttle_budget_exhausted",
                        query_name=op_name,
                        is_write=is_write,
                        attempt=attempt,
                        wait_seconds=round(wait, 3),
                        budget_remaining_seconds=round(self._throttle_budget_remaining, 3),
                    )
                    raise TGRateLimited(
                        f"{op_name} rate-limited: the pass's {_PASS_THROTTLE_BUDGET_SECONDS:g} s "
                        "throttle-wait budget is exhausted",
                        status=status,
                        query_name=op_name,
                        body=response.text,
                    )
                self._throttle_budget_remaining -= wait
                logger.warning(
                    "tgapi.throttled",
                    query_name=op_name,
                    is_write=is_write,
                    attempt=attempt,
                    wait_seconds=round(wait, 3),
                    wait_source=source,
                    server_hint_seconds=hint,
                    capped=hint is not None and hint > _THROTTLE_WAIT_CAP_SECONDS,
                )
                await asyncio.sleep(wait)
                continue

            if 500 <= status < 600:
                if attempt == _MAX_ATTEMPTS:
                    raise TGAPIError(
                        f"{op_name} failed: HTTP {status} after {attempt} attempts",
                        status=status,
                        query_name=op_name,
                        body=response.text,
                    )
                await asyncio.sleep(_backoff_delay(attempt))
                continue

            if status >= 400:
                raise TGAPIError(
                    f"{op_name} failed: HTTP {status}",
                    status=status,
                    query_name=op_name,
                    body=response.text,
                )

            try:
                body = response.json()
            except json.JSONDecodeError as exc:
                raise TGAPIError(
                    f"{op_name} returned a non-JSON 200 response: {exc}",
                    status=status,
                    query_name=op_name,
                    body=response.text,
                ) from exc

            if not isinstance(body, dict):
                raise TGAPIError(
                    f"{op_name} returned a non-object JSON 200 response",
                    status=status,
                    query_name=op_name,
                    body=response.text,
                )

            if body.get("errors"):
                raise TGGraphQLError(
                    f"{op_name} returned GraphQL errors",
                    status=status,
                    query_name=op_name,
                    body=response.text,
                    errors=body["errors"],
                )

            data: dict[str, Any] = body.get("data") or {}
            return data

        raise AssertionError("unreachable: retry loop must return or raise")
