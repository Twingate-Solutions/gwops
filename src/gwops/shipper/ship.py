"""`Shipper`: batch-POST spooled recording lines to the configured sink's ``/ingest``.

The run loop reads a batch from the spool's committed cursor (at most 500 lines and
16 MiB per POST, or one larger line alone), POSTs it as ``application/x-ndjson`` with the
``GWOPS_RECORDING_TOKEN`` bearer, and commits the cursor only on success. Any failure (non-2xx,
connect error, timeout) backs off exponentially with jitter (1 s doubling to a 30 s cap)
and retries the same batch, so uncommitted lines are never dropped. Redelivery relies on
the sink deduplicating on ``conn_id`` + ``seq``. Lines are filtered before they reach the
spool, so nothing is filtered here.

An empty spool parks the loop on an ``asyncio.Event`` that the spool's ``append`` sets.
``lag`` exposes the pending line/byte counts and last-success timestamp for ``GET /status``.
"""

import asyncio
import random
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
import structlog

from gwops.shipper.limits import BATCH_MAX_BYTES
from gwops.shipper.spool import Spool

logger = structlog.get_logger(__name__)

_DEFAULT_BATCH_MAX_LINES = 500
_DEFAULT_BACKOFF_START = 1.0
_DEFAULT_BACKOFF_CAP = 30.0
_DEFAULT_REQUEST_TIMEOUT = 30.0


@dataclass(frozen=True)
class ShipperLag:
    """Delivery lag for `/status`: what is still on disk and when we last succeeded."""

    pending_lines: int
    pending_bytes: int
    last_success_at: datetime | None


class Shipper:
    """Owns delivery from one :class:`Spool` to one ingest endpoint."""

    def __init__(
        self,
        spool: Spool,
        url: str,
        token: str,
        *,
        batch_max_lines: int = _DEFAULT_BATCH_MAX_LINES,
        batch_max_bytes: int = BATCH_MAX_BYTES,
        backoff_start: float = _DEFAULT_BACKOFF_START,
        backoff_cap: float = _DEFAULT_BACKOFF_CAP,
        request_timeout: float = _DEFAULT_REQUEST_TIMEOUT,
        on_backoff: Callable[[float], None] | None = None,
    ) -> None:
        """Bind to `spool` and the sink's base `url` (``/ingest`` is appended here).

        `token` goes into the bearer header and must never be logged. `on_backoff`, if
        given, is called with each computed backoff delay.
        """
        self._spool = spool
        self._ingest_url = url.rstrip("/") + "/ingest"
        self._token = token
        if not self._ingest_url.lower().startswith("https://"):
            logger.warning(
                "shipper.insecure_transport",
                url=self._ingest_url,
                reason=(
                    "recording.receiver_url is not https; the GWOPS_RECORDING_TOKEN and recorded "
                    "session content will traverse the network in cleartext. Use "
                    "https:// unless the path to the recording receiver is a trusted local network."
                ),
            )
        self._batch_max_lines = batch_max_lines
        self._batch_max_bytes = batch_max_bytes
        self._backoff_start = backoff_start
        self._backoff_cap = backoff_cap
        self._request_timeout = request_timeout
        self._on_backoff = on_backoff
        self._last_success_at: datetime | None = None
        self._wake = asyncio.Event()
        spool.on_append = self._wake.set

    @property
    def lag(self) -> ShipperLag:
        """Current delivery lag (pending lines/bytes, last successful POST)."""
        return ShipperLag(
            pending_lines=self._spool.pending_lines,
            pending_bytes=self._spool.pending_bytes,
            last_success_at=self._last_success_at,
        )

    async def run(self) -> None:
        """The delivery loop; runs until cancelled (supervisor shutdown)."""
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/x-ndjson",
        }
        backoff = self._backoff_start
        async with httpx.AsyncClient(timeout=self._request_timeout) as client:
            while True:
                # Clear before reading so an append racing the read re-sets the event.
                self._wake.clear()
                batch, cursor = self._spool.read_batch(
                    self._batch_max_lines, self._batch_max_bytes
                )
                if not batch:
                    await self._wake.wait()
                    continue
                if await self._post(client, batch, headers):
                    self._spool.commit(cursor)
                    self._last_success_at = datetime.now(UTC)
                    backoff = self._backoff_start
                    continue
                delay = random.uniform(backoff / 2, backoff)  # noqa: S311 - jitter
                backoff = min(backoff * 2, self._backoff_cap)
                if self._on_backoff is not None:
                    self._on_backoff(delay)
                await asyncio.sleep(delay)

    async def _post(
        self, client: httpx.AsyncClient, batch: list[str], headers: dict[str, str]
    ) -> bool:
        """POST one batch; True on a 2xx ack. Never logs the token."""
        body = ("\n".join(batch) + "\n").encode("utf-8")
        try:
            response = await client.post(self._ingest_url, content=body, headers=headers)
        except httpx.HTTPError as exc:
            logger.error(
                "shipper.post_failed",
                url=self._ingest_url,
                lines=len(batch),
                error=str(exc),
            )
            return False
        if response.is_success:
            return True
        logger.error(
            "shipper.post_rejected",
            url=self._ingest_url,
            lines=len(batch),
            status_code=response.status_code,
            body=response.text[:200],
        )
        return False
