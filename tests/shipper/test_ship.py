"""Shipper tests against a respx-mocked Gatorcast: commit-on-204, backoff+jitter
retrying the *same* batch, event-driven wake-up, and token hygiene (header yes,
logs never)."""

import asyncio
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import httpx
import pytest
import respx
import structlog.testing

from gwops.shipper.ship import Shipper
from gwops.shipper.spool import Spool

TOKEN = "gc-secret-token-do-not-log"  # noqa: S105 - a test fixture, not a credential
BASE_URL = "http://gatorcast.test:8000"
INGEST_URL = f"{BASE_URL}/ingest"


def make_spool(tmp_path: Path) -> Spool:
    return Spool(tmp_path / "spool", max_bytes=1024 * 1024)


def make_shipper(
    spool: Spool, *, on_backoff: Callable[[float], None] | None = None
) -> Shipper:
    return Shipper(
        spool,
        BASE_URL,
        TOKEN,
        backoff_start=0.01,
        backoff_cap=0.05,
        on_backoff=on_backoff,
    )


async def drain(spool: Spool, timeout: float = 5.0) -> None:
    """Wait until every spooled line has been committed."""
    async with asyncio.timeout(timeout):
        while spool.pending_lines > 0:
            await asyncio.sleep(0.01)


@pytest.fixture
async def run_shipper() -> AsyncIterator[Callable[[Shipper], asyncio.Task[None]]]:
    tasks: list[asyncio.Task[None]] = []

    def _start(shipper: Shipper) -> asyncio.Task[None]:
        task = asyncio.create_task(shipper.run())
        tasks.append(task)
        return task

    yield _start
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


@respx.mock
async def test_204_commits_and_updates_lag(
    tmp_path: Path, run_shipper: Callable[[Shipper], asyncio.Task[None]]
) -> None:
    route = respx.post(INGEST_URL).mock(return_value=httpx.Response(204))
    spool = make_spool(tmp_path)
    shipper = make_shipper(spool)
    lines = ['{"a":1}', '{"b":2}', '{"c":3}']
    for line in lines:
        spool.append(line.encode())

    run_shipper(shipper)
    await drain(spool)

    assert route.called
    request = route.calls[0].request
    assert request.content == ("\n".join(lines) + "\n").encode()
    assert request.headers["authorization"] == f"Bearer {TOKEN}"
    assert request.headers["content-type"] == "application/x-ndjson"
    assert shipper.lag.pending_lines == 0
    assert shipper.lag.last_success_at is not None


@respx.mock
async def test_each_post_stays_within_the_byte_cap(
    tmp_path: Path, run_shipper: Callable[[Shipper], asyncio.Task[None]]
) -> None:
    route = respx.post(INGEST_URL).mock(return_value=httpx.Response(204))
    spool = make_spool(tmp_path)
    shipper = Shipper(spool, BASE_URL, TOKEN, batch_max_bytes=250)
    lines = ["x" * 99 for _ in range(5)]  # 100 B each in a body
    for line in lines:
        spool.append(line.encode())

    run_shipper(shipper)
    await drain(spool)

    bodies = [call.request.content for call in route.calls]
    assert [len(body) for body in bodies] == [200, 200, 100]
    assert b"".join(bodies) == ("\n".join(lines) + "\n").encode()


@respx.mock
async def test_line_over_the_byte_cap_ships_alone(
    tmp_path: Path, run_shipper: Callable[[Shipper], asyncio.Task[None]]
) -> None:
    route = respx.post(INGEST_URL).mock(return_value=httpx.Response(204))
    spool = make_spool(tmp_path)
    shipper = Shipper(spool, BASE_URL, TOKEN, batch_max_bytes=100)
    big = "z" * 500
    for line in ("a", big, "b"):
        spool.append(line.encode())

    run_shipper(shipper)
    await drain(spool)

    assert [call.request.content for call in route.calls] == [
        b"a\n",
        big.encode() + b"\n",
        b"b\n",
    ]


@respx.mock
async def test_failure_backs_off_with_jitter_and_retries_same_batch(
    tmp_path: Path, run_shipper: Callable[[Shipper], asyncio.Task[None]]
) -> None:
    route = respx.post(INGEST_URL).mock(
        side_effect=[
            httpx.Response(500, text="boom"),
            httpx.Response(503, text="still boom"),
            httpx.Response(204),
        ]
    )
    delays: list[float] = []
    spool = make_spool(tmp_path)
    shipper = make_shipper(spool, on_backoff=delays.append)
    spool.append(b'{"seq":1}')
    spool.append(b'{"seq":2}')

    run_shipper(shipper)
    await drain(spool)

    assert route.call_count == 3
    bodies = {call.request.content for call in route.calls}
    assert len(bodies) == 1, "failed batches must be retried verbatim, never dropped"
    # Exponential backoff with jitter: attempt N sleeps in (delay/2, delay] where
    # delay doubles from backoff_start (0.01) to backoff_cap (0.05).
    assert len(delays) == 2
    assert 0.005 <= delays[0] <= 0.01
    assert 0.01 <= delays[1] <= 0.02
    assert shipper.lag.last_success_at is not None


@respx.mock
async def test_connect_error_retries_until_delivery(
    tmp_path: Path, run_shipper: Callable[[Shipper], asyncio.Task[None]]
) -> None:
    route = respx.post(INGEST_URL).mock(
        side_effect=[httpx.ConnectError("refused"), httpx.Response(204)]
    )
    spool = make_spool(tmp_path)
    shipper = make_shipper(spool)
    spool.append(b'{"x":1}')

    run_shipper(shipper)
    await drain(spool)
    assert route.call_count == 2


@respx.mock
async def test_empty_spool_waits_for_append(
    tmp_path: Path, run_shipper: Callable[[Shipper], asyncio.Task[None]]
) -> None:
    route = respx.post(INGEST_URL).mock(return_value=httpx.Response(204))
    spool = make_spool(tmp_path)
    shipper = make_shipper(spool)

    run_shipper(shipper)
    await asyncio.sleep(0.05)
    assert not route.called, "an empty spool must wait, not poll Gatorcast"

    spool.append(b'{"late":1}')
    await drain(spool)
    assert route.call_count == 1


@respx.mock
async def test_token_never_appears_in_logs(
    tmp_path: Path, run_shipper: Callable[[Shipper], asyncio.Task[None]]
) -> None:
    respx.post(INGEST_URL).mock(
        side_effect=[httpx.Response(500, text="denied"), httpx.Response(204)]
    )
    spool = make_spool(tmp_path)
    shipper = make_shipper(spool)
    spool.append(b'{"x":1}')

    with structlog.testing.capture_logs() as logs:
        run_shipper(shipper)
        await drain(spool)

    assert logs, "failures must be logged"
    assert TOKEN not in repr(logs)


@respx.mock
async def test_other_2xx_still_commits(
    tmp_path: Path, run_shipper: Callable[[Shipper], asyncio.Task[None]]
) -> None:
    """The contract says 204 always, but any 2xx ack must not spin the retry loop."""
    respx.post(INGEST_URL).mock(return_value=httpx.Response(200))
    spool = make_spool(tmp_path)
    shipper = make_shipper(spool)
    spool.append(b'{"x":1}')

    run_shipper(shipper)
    await drain(spool)
    assert spool.pending_lines == 0
