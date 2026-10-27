"""The on-demand restart after ``rotate-ca complete`` waits for an in-flight reconcile pass."""

import asyncio
from pathlib import Path

import httpx

from gwops.api.app import create_app

from .conftest import ADMIN_TOKEN, SEED, make_deps

_ON_SEED = SEED + "ca:\n  x509:\n    on_demand_issuance: true\n"


async def test_the_restart_does_not_run_while_a_pass_holds_the_reconciler_lock(
    tmp_path: Path,
) -> None:
    """drain_restart waits for the pass, then runs exactly once."""
    bundle = make_deps(tmp_path, seed=_ON_SEED)
    pass_lock = asyncio.Lock()
    bundle.reconciler.lock = pass_lock  # type: ignore[attr-defined]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(bundle.deps)),
        base_url="http://gwops",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    ) as client:
        stage = await client.post("/certs/rotate-ca", json={"phase": "stage"})
        assert stage.status_code == 200

        async with pass_lock:
            complete = asyncio.create_task(
                client.post("/certs/rotate-ca", json={"phase": "complete"})
            )
            await asyncio.sleep(0.3)
            assert not complete.done()
            assert "drain_restart" not in bundle.process.calls

        response = await asyncio.wait_for(complete, 10)

    assert response.status_code == 200
    assert bundle.process.calls.count("drain_restart") == 1
    assert not pass_lock.locked()
    assert not bundle.deps.mutation_lock.locked()


async def test_a_reconciler_without_a_lock_still_restarts(tmp_path: Path) -> None:
    """A reconciler that exposes no lock (a stub) does not block the restart."""
    bundle = make_deps(tmp_path, seed=_ON_SEED)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(bundle.deps)),
        base_url="http://gwops",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    ) as client:
        await client.post("/certs/rotate-ca", json={"phase": "stage"})
        response = await client.post("/certs/rotate-ca", json={"phase": "complete"})

    assert response.status_code == 200
    assert bundle.process.calls.count("drain_restart") == 1
