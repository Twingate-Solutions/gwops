"""Pass facts the admin API reads: ``tg_attempted`` on the result, the public pass ``lock``."""

import asyncio
from collections.abc import Callable
from pathlib import Path

from gwops.renderer.capabilities import Capabilities
from tests.on_demand_support import SSH_UPSTREAM_SEED

from .test_core import Env


def _env(tmp_path: Path, binary: Path, seed: str = SSH_UPSTREAM_SEED) -> Env:
    return Env(tmp_path, seed, binary, Capabilities(), None)


async def test_a_pass_that_reaches_tg_sync_is_marked_attempted(
    tmp_path: Path, gateway_binary: Callable[..., Path]
) -> None:
    """Even with no API key the pass reached the sync step and recorded why it did nothing."""
    env = _env(tmp_path, gateway_binary())

    result = await env.reconciler.reconcile("startup")

    assert result.tg_attempted is True


async def test_a_pass_that_ends_before_tg_sync_is_not_marked_attempted(
    tmp_path: Path, gateway_binary: Callable[..., Path]
) -> None:
    """A seed that fails to load ends the pass at step 0."""
    env = _env(tmp_path, gateway_binary(), "not: [valid")

    result = await env.reconciler.reconcile("startup")

    assert result.local_ok is False
    assert result.tg_attempted is False


async def test_the_pass_lock_is_public_and_held_for_the_whole_pass(
    tmp_path: Path, gateway_binary: Callable[..., Path]
) -> None:
    """``Reconciler.lock`` is the lock `_run` holds; a pass waits for whoever holds it."""
    env = _env(tmp_path, gateway_binary())
    lock = env.reconciler.lock
    assert isinstance(lock, asyncio.Lock)

    async with lock:
        task = asyncio.create_task(env.reconciler.reconcile("tick"))
        await asyncio.sleep(0.2)
        assert not task.done()
    result = await asyncio.wait_for(task, 30)

    assert result.trigger == "tick"
    assert not lock.locked()
