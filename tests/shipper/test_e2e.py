"""End-to-end recording path over Gatorcast's own wire samples:

fake-gateway stderr -> GatewayProcess pump -> Spool -> Shipper -> respx'd /ingest.

The one property everything downstream depends on: lines arrive byte-identical and in
order (Gatorcast's classifier keys off exact JSON shapes, and dedup off conn_id+seq).

The first test hands lines straight to the spool (transport fidelity only, no filter). The
POSIX-only second test runs the real ``bootstrap`` wiring, so only filtered, enriched lines ship.
"""

import asyncio
import json
import sys
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
import respx

from gwops.shipper.filter import classify
from gwops.shipper.ship import Shipper
from gwops.shipper.spool import Spool
from gwops.supervisor.main import bootstrap
from gwops.supervisor.process import GatewayProcess
from tests.drops_support import expected_drops
from tests.on_demand_support import make_settings

BASE_URL = "http://gatorcast.test:8000"
FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample_log_lines.ndjson"
WEBAPP_FIXTURE = Path(__file__).parent.parent / "fixtures" / "webapp_gateway_lines.ndjson"

_SEED = """\
twingate:
  network: acme
  gateway_id: g-1
ssh_upstreams:
  - name: host1
    address: 10.0.0.5:22
recording:
  enabled: true
  receiver_url: http://gatorcast.test:8000
"""


@respx.mock
async def test_fixture_replay_arrives_byte_identical_in_order(
    tmp_path: Path, fake_gateway: Callable[..., Path]
) -> None:
    originals = [line for line in FIXTURE.read_bytes().splitlines() if line]
    route = respx.post(f"{BASE_URL}/ingest").mock(return_value=httpx.Response(204))

    spool = Spool(tmp_path / "spool", max_bytes=1024 * 1024)
    shipper = Shipper(spool, BASE_URL, "tok")
    # The fake replays the fixture on stderr at boot, then exits on its own
    # (crash_after=1). A self-exiting child is the only portable teardown: on Windows
    # terminate() would kill the .cmd shim and orphan the python underneath, leaving
    # the pipe readers waiting forever. backoff_start=60 keeps GatewayProcess from
    # respawning it (and re-replaying the fixture) before the test finishes.
    binary = fake_gateway(crash_after=1, stderr_file=FIXTURE)
    config_path = tmp_path / "config.yaml"
    config_path.write_text("", encoding="utf-8")
    process = GatewayProcess(
        binary,
        config_path,
        lambda _line: None,
        spool.append,
        backoff_start=60.0,
    )

    ship_task = asyncio.create_task(shipper.run())
    await process.start()
    try:
        async with asyncio.timeout(10.0):
            while _received(route) < len(originals):
                await asyncio.sleep(0.02)
    finally:
        ship_task.cancel()
        await asyncio.gather(ship_task, return_exceptions=True)
        await process.stop(timeout=5.0)

    received: list[bytes] = []
    for call in route.calls:
        assert call.request.headers["content-type"] == "application/x-ndjson"
        received.extend(line for line in call.request.content.splitlines() if line)
    assert received[: len(originals)] == originals, (
        "fixture lines must reach Gatorcast byte-identical and in order"
    )


@pytest.mark.skipif(sys.platform == "win32", reason="requires POSIX signal semantics")
@respx.mock
async def test_gateway_stderr_ships_only_the_filtered_lines_in_order(
    tmp_path: Path, fake_gateway: Callable[..., Path]
) -> None:
    originals = WEBAPP_FIXTURE.read_bytes().splitlines()
    kept = [line for line in originals if classify(line).keep]
    route = respx.post(f"{BASE_URL}/ingest").mock(return_value=httpx.Response(204))

    binary = fake_gateway(stderr_file=WEBAPP_FIXTURE, stderr_ticks=False)
    result = await bootstrap(make_settings(tmp_path, binary, _SEED))
    assert result.shipper is None  # no GWOPS_RECORDING_TOKEN in make_settings
    assert result.spool is not None
    shipper = Shipper(result.spool, BASE_URL, "tok")
    ship_task = asyncio.create_task(shipper.run())
    try:
        async with asyncio.timeout(10.0):
            while _received(route) < len(kept):
                await asyncio.sleep(0.02)
    finally:
        ship_task.cancel()
        await asyncio.gather(ship_task, return_exceptions=True)
        await result.process.stop(timeout=5.0)

    received = [
        line for call in route.calls for line in call.request.content.splitlines() if line
    ]
    # Exactly the kept lines, in order: no service line and no plain-text line was shipped.
    assert len(received) == len(kept) == 113
    for got, original in zip(received, kept, strict=True):
        obj = json.loads(original)
        if obj["message"] == "Authenticated connection":
            assert got.startswith(original[:-1] + b',"gwops":{"schema":1,')
        else:
            assert got == original
    # The fixture's usage block holds seven non-JSON lines; the pump skips the blank one.
    assert result.drops.snapshot() == expected_drops(not_json=6, not_allowlisted=38)


def _received(route: respx.Route) -> int:
    return sum(len(call.request.content.splitlines()) for call in route.calls)


@pytest.mark.integration
async def test_contract_smoke_against_real_gatorcast(tmp_path: Path) -> None:
    """Optional contract smoke test against a *real* local Gatorcast.

    Run manually (not in the default suite):

    1. Start Gatorcast locally, e.g.
       ``docker compose up`` with its INGEST_TOKEN set.
    2. ``GWOPS_SMOKE_RECEIVER_URL=http://localhost:8000 \\
        GWOPS_SMOKE_RECORDING_TOKEN=<token> pytest -m integration``
    3. Verify in Gatorcast that the fixture session
       (conn_id 9114cb20-7e00-4bfd-b50b-aa6f7440127a) was classified and sealed.
    """
    import os

    url = os.environ.get("GWOPS_SMOKE_RECEIVER_URL")
    token = os.environ.get("GWOPS_SMOKE_RECORDING_TOKEN")
    if not url or not token:
        pytest.skip("set GWOPS_SMOKE_RECEIVER_URL and GWOPS_SMOKE_RECORDING_TOKEN")

    spool = Spool(tmp_path / "spool", max_bytes=1024 * 1024)
    shipper = Shipper(spool, url, token)
    for line in FIXTURE.read_text(encoding="utf-8").splitlines():
        if line:
            spool.append(line.encode())

    ship_task = asyncio.create_task(shipper.run())
    try:
        async with asyncio.timeout(30.0):
            while spool.pending_lines > 0:
                await asyncio.sleep(0.05)
    finally:
        ship_task.cancel()
        await asyncio.gather(ship_task, return_exceptions=True)
    assert shipper.lag.last_success_at is not None
