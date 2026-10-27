"""Tests for gwops.reconciler.watch: the three level-trigger sources.

The watchers only need something with an async ``reconcile(trigger)`` — a recording
stub keeps these tests independent of the full Reconciler. Timings are kept tiny;
each test bounds its waits so a broken watcher fails fast instead of hanging.
"""

import asyncio
import contextlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gwops.reconciler.core import ReconcileResult
from gwops.reconciler.watch import (
    SeedFingerprint,
    api_trigger,
    periodic_tick,
    poll_seed,
    run_triggers,
    watch_seed,
)


class RecordingReconciler:
    """Records every trigger and lets tests await the next call."""

    def __init__(self) -> None:
        self.triggers: list[str] = []
        self._called = asyncio.Event()

    async def reconcile(self, trigger: str) -> ReconcileResult:
        self.triggers.append(trigger)
        self._called.set()
        return ReconcileResult(
            ok=True, trigger=trigger, started_at=datetime.now(UTC), actions=[], errors=[]
        )

    async def wait_for_call(self, timeout: float = 5.0) -> None:
        await asyncio.wait_for(self._called.wait(), timeout=timeout)
        self._called.clear()


async def _cancel(task: asyncio.Task[None]) -> None:
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


class TestPeriodicTick:
    async def test_fires_repeatedly_with_trigger_tick(self) -> None:
        stub = RecordingReconciler()
        task = asyncio.create_task(periodic_tick(stub, interval_seconds=0.01))
        try:
            await stub.wait_for_call()
            await stub.wait_for_call()
        finally:
            await _cancel(task)
        assert len(stub.triggers) >= 2
        assert set(stub.triggers) == {"tick"}


class TestApiTrigger:
    async def test_each_event_set_fires_one_reconcile(self) -> None:
        stub = RecordingReconciler()
        event = asyncio.Event()
        task = asyncio.create_task(api_trigger(stub, event))
        try:
            event.set()
            await stub.wait_for_call()
            event.set()
            await stub.wait_for_call()
        finally:
            await _cancel(task)
        assert stub.triggers == ["api", "api"]


class TestSeedWatch:
    async def test_seed_write_fires_seed_change(self, tmp_path: Path) -> None:
        seed = tmp_path / "seed.yaml"
        seed.write_text("a: 0\n", encoding="utf-8")
        stub = RecordingReconciler()
        task = asyncio.create_task(watch_seed(stub, seed, debounce_ms=50))
        try:
            # The OS watcher arms asynchronously (observed >0.5 s on Linux/notify), so
            # a single write can race it and be lost forever — keep mutating until the
            # trigger lands, bounded so a broken watcher still fails fast.
            for attempt in range(1, 51):
                seed.write_text(f"a: {attempt}\n", encoding="utf-8")
                await asyncio.sleep(0.2)
                if stub.triggers:
                    break
        finally:
            await _cancel(task)
        assert "seed-change" in stub.triggers


class TestSeedFingerprint:
    def test_changed_reports_each_new_content_once(self, tmp_path: Path) -> None:
        seed = tmp_path / "seed.yaml"
        seed.write_text("a: 0\n", encoding="utf-8")
        fp = SeedFingerprint(seed)
        assert not fp.changed()
        seed.write_text("a: 1\n", encoding="utf-8")
        assert fp.changed()
        assert not fp.changed()

    def test_rewriting_identical_content_is_not_a_change(self, tmp_path: Path) -> None:
        seed = tmp_path / "seed.yaml"
        seed.write_text("a: 0\n", encoding="utf-8")
        fp = SeedFingerprint(seed)
        seed.write_text("a: 0\n", encoding="utf-8")
        assert not fp.changed()

    def test_refresh_absorbs_a_change(self, tmp_path: Path) -> None:
        seed = tmp_path / "seed.yaml"
        seed.write_text("a: 0\n", encoding="utf-8")
        fp = SeedFingerprint(seed)
        seed.write_text("a: 1\n", encoding="utf-8")
        fp.refresh()
        assert not fp.changed()

    def test_a_missing_seed_and_its_return_are_changes(self, tmp_path: Path) -> None:
        seed = tmp_path / "seed.yaml"
        seed.write_text("a: 0\n", encoding="utf-8")
        fp = SeedFingerprint(seed)
        seed.unlink()
        assert fp.changed()
        assert not fp.changed()
        seed.write_text("a: 0\n", encoding="utf-8")
        assert fp.changed()


class TestSeedPoll:
    async def test_in_place_edit_fires_seed_change_once(self, tmp_path: Path) -> None:
        seed = tmp_path / "seed.yaml"
        seed.write_text("a: 0\n", encoding="utf-8")
        stub = RecordingReconciler()
        fp = SeedFingerprint(seed)
        task = asyncio.create_task(poll_seed(stub, fp, interval_seconds=0.01, settle_seconds=0.01))
        try:
            with seed.open("r+", encoding="utf-8") as f:  # in place, same inode, like nano
                f.write("a: 1\n")
            await stub.wait_for_call()
            await asyncio.sleep(0.1)  # many more polls; the same content must not refire
        finally:
            await _cancel(task)
        assert stub.triggers == ["seed-change"]

    async def test_unchanged_seed_never_fires(self, tmp_path: Path) -> None:
        seed = tmp_path / "seed.yaml"
        seed.write_text("a: 0\n", encoding="utf-8")
        stub = RecordingReconciler()
        task = asyncio.create_task(
            poll_seed(stub, SeedFingerprint(seed), interval_seconds=0.01, settle_seconds=0.01)
        )
        try:
            await asyncio.sleep(0.1)
        finally:
            await _cancel(task)
        assert stub.triggers == []

    async def test_waits_for_a_write_in_progress_to_settle(self, tmp_path: Path) -> None:
        seed = tmp_path / "seed.yaml"
        seed.write_text("a: 0\n", encoding="utf-8")
        stub = RecordingReconciler()
        task = asyncio.create_task(
            poll_seed(stub, SeedFingerprint(seed), interval_seconds=0.01, settle_seconds=0.05)
        )
        try:
            # Keep the content moving faster than the settle interval: no pass may start.
            for attempt in range(1, 11):
                seed.write_text(f"a: {attempt}\n", encoding="utf-8")
                await asyncio.sleep(0.01)
            assert stub.triggers == []
            await stub.wait_for_call()
        finally:
            await _cancel(task)
        assert stub.triggers == ["seed-change"]


class TestRunTriggers:
    async def test_runs_all_three_sources_until_cancelled(self, tmp_path: Path) -> None:
        seed = tmp_path / "seed.yaml"
        seed.write_text("a: 1\n", encoding="utf-8")
        stub = RecordingReconciler()
        api_event = asyncio.Event()
        task = asyncio.create_task(
            run_triggers(
                stub,
                seed_path=seed,
                tick_seconds=0.01,
                api_event=api_event,
            )
        )
        try:
            await stub.wait_for_call()  # a tick proves the group is live
            api_event.set()
            await asyncio.wait_for(_wait_for_trigger(stub, "api"), timeout=5.0)
        finally:
            await _cancel(task)
        assert "tick" in stub.triggers
        assert "api" in stub.triggers

    async def test_polls_the_seed(self, tmp_path: Path) -> None:
        seed = tmp_path / "seed.yaml"
        seed.write_text("a: 1\n", encoding="utf-8")
        stub = RecordingReconciler()
        task = asyncio.create_task(
            run_triggers(
                stub,
                seed_path=seed,
                tick_seconds=3600,
                api_event=asyncio.Event(),
                seed_poll_seconds=0.01,
            )
        )
        try:
            await asyncio.sleep(0.05)  # the fingerprint is taken before the edit
            with seed.open("r+", encoding="utf-8") as f:
                f.write("a: 2\n")
            await asyncio.wait_for(_wait_for_trigger(stub, "seed-change"), timeout=5.0)
        finally:
            await _cancel(task)


async def _wait_for_trigger(stub: RecordingReconciler, trigger: str) -> None:
    while trigger not in stub.triggers:
        await asyncio.sleep(0.005)


class TestReconcileErrorsDoNotKillTheLoop:
    async def test_a_raising_reconcile_is_logged_and_the_tick_continues(self) -> None:
        class ExplodingReconciler(RecordingReconciler):
            async def reconcile(self, trigger: str) -> ReconcileResult:
                await super().reconcile(trigger)
                raise RuntimeError("boom")

        stub = ExplodingReconciler()
        task = asyncio.create_task(periodic_tick(stub, interval_seconds=0.01))
        try:
            await stub.wait_for_call()
            await stub.wait_for_call()  # still ticking after the first raise
        finally:
            await _cancel(task)
        assert len(stub.triggers) >= 2


class TestProtocolShape:
    def test_recording_stub_satisfies_the_watcher_protocol(self) -> None:
        # The watchers accept anything with an async reconcile(trigger) — this stub
        # standing in for the Reconciler is itself the contract check.
        stub = RecordingReconciler()
        assert callable(stub.reconcile)

    @pytest.mark.parametrize("name", ["watch_seed", "poll_seed", "periodic_tick", "api_trigger"])
    def test_module_exports(self, name: str) -> None:
        import gwops.reconciler.watch as watch

        assert callable(getattr(watch, name))
