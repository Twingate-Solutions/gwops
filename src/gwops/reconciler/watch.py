"""Level-trigger sources feeding :meth:`~gwops.reconciler.core.Reconciler.reconcile`.

Four sources, all long-running coroutines the supervisor owns as tasks:

- :func:`watch_seed` — filesystem watch on the seed file (``watchfiles``), debounced
  (default 2 s) so editor save storms fire once;
- :func:`poll_seed` — a content-hash poll of the seed (default every 5 s). A single-file
  bind mount (``./seed.yaml:/config/seed.yaml``) never delivers inotify events to the
  watched ``/config`` directory, so this is what notices an in-place edit there;
- :func:`periodic_tick` — the slow level-triggered safety net (default 10 min via
  ``GWOPS_RECONCILE_TICK_SECONDS``) that heals anything event delivery missed;
- :func:`api_trigger` — an :class:`asyncio.Event` the admin API sets after a mutation.

:func:`run_triggers` bundles all four until cancelled. A reconcile pass that raises is
logged and the source keeps running. Trigger names are ``"seed-change"`` (watch and
poll), ``"tick"``, and ``"api"``; ``"startup"`` and ``"sighup"`` are fired directly by
the supervisor.
"""

import asyncio
import hashlib
from pathlib import Path
from typing import Protocol

import structlog
import watchfiles

from gwops.reconciler.core import ReconcileResult

logger = structlog.get_logger(__name__)

_DEFAULT_DEBOUNCE_MS = 2000
_DEFAULT_SEED_POLL_SECONDS = 5.0
_DEFAULT_SEED_SETTLE_SECONDS = 0.5


class SupportsReconcile(Protocol):
    """Anything with the Reconciler's ``reconcile`` coroutine (tests use stubs)."""

    async def reconcile(self, trigger: str) -> ReconcileResult: ...


class SeedFingerprint:
    """SHA-256 of the seed's bytes as last acted on, shared by the watch and the poll.

    The watch refreshes it when it fires, so the poll does not fire a second pass for the
    same edit. An unreadable seed fingerprints as ``None``; the pass that follows reports
    the read error itself.
    """

    def __init__(self, seed_path: Path) -> None:
        self.seed_path = seed_path
        self._digest = self._read()

    def _read(self) -> bytes | None:
        try:
            return hashlib.sha256(self.seed_path.read_bytes()).digest()
        except OSError:
            return None

    def refresh(self) -> None:
        """Record the seed's current content as acted on."""
        self._digest = self._read()

    def changed(self) -> bool:
        """Whether the content differs from the last recorded; records the new content."""
        digest = self._read()
        if digest == self._digest:
            return False
        self._digest = digest
        return True


async def _fire(reconciler: SupportsReconcile, trigger: str) -> None:
    """Run one reconcile pass, containing any unexpected exception."""
    try:
        await reconciler.reconcile(trigger)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("watch.reconcile_raised", trigger=trigger)


async def watch_seed(
    reconciler: SupportsReconcile,
    seed_path: Path,
    *,
    debounce_ms: int = _DEFAULT_DEBOUNCE_MS,
    fingerprint: SeedFingerprint | None = None,
) -> None:
    """Fire ``reconcile("seed-change")`` whenever the seed file changes, debounced.

    Watches the parent directory rather than the file itself so a rename-over or
    delete-then-recreate of the seed file (the usual editor save) keeps being observed.
    Only events naming `seed_path` itself fire. A directory-mounted Kubernetes ConfigMap
    updates by swapping the ``..data`` symlink, which produces no event for ``seed.yaml``,
    so that update is caught only by :func:`poll_seed`'s content-hash poll. Refreshes
    `fingerprint`, when given, before each pass so :func:`poll_seed` skips the same edit.
    Runs until cancelled.
    """
    parent = seed_path.parent
    async for changes in watchfiles.awatch(parent, debounce=debounce_ms, recursive=False):
        if any(Path(changed) == seed_path for _kind, changed in changes):
            logger.info("watch.seed_changed", seed_path=str(seed_path), source="watch")
            if fingerprint is not None:
                fingerprint.refresh()
            await _fire(reconciler, "seed-change")


async def poll_seed(
    reconciler: SupportsReconcile,
    fingerprint: SeedFingerprint,
    *,
    interval_seconds: float = _DEFAULT_SEED_POLL_SECONDS,
    settle_seconds: float = _DEFAULT_SEED_SETTLE_SECONDS,
) -> None:
    """Fire ``reconcile("seed-change")`` when the seed's content hash changes.

    Covers what the watch cannot see: an in-place edit (nano, ``>``) of a single-file bind
    mount, the ``..data`` symlink swap of a directory-mounted ConfigMap, and filesystems
    that deliver no events (Docker Desktop shares). On a change it
    re-reads every `settle_seconds` until two reads agree, so a write still in progress is
    not reconciled half-written. A rename-over save on the host is not visible through a
    single-file bind mount at all (the mount keeps the old inode); only a recreate shows it.
    Runs until cancelled.
    """
    while True:
        await asyncio.sleep(interval_seconds)
        if not fingerprint.changed():
            continue
        while True:
            await asyncio.sleep(settle_seconds)
            if not fingerprint.changed():
                break
        logger.info("watch.seed_changed", seed_path=str(fingerprint.seed_path), source="poll")
        await _fire(reconciler, "seed-change")


async def periodic_tick(reconciler: SupportsReconcile, interval_seconds: float) -> None:
    """Fire ``reconcile("tick")`` every `interval_seconds`, forever (until cancelled).

    The interval elapses between passes (not fixed-rate), so a slow reconcile never
    stacks ticks — coalescing in the reconciler makes overlap harmless anyway.
    """
    while True:
        await asyncio.sleep(interval_seconds)
        await _fire(reconciler, "tick")


async def api_trigger(reconciler: SupportsReconcile, event: asyncio.Event) -> None:
    """Fire ``reconcile("api")`` each time `event` is set; clears it before running.

    The admin API sets the event after persisting an overlay; clearing before the
    pass means a set() arriving *during* the pass is not lost — it fires again.
    """
    while True:
        await event.wait()
        event.clear()
        await _fire(reconciler, "api")


async def run_triggers(
    reconciler: SupportsReconcile,
    *,
    seed_path: Path,
    tick_seconds: float,
    api_event: asyncio.Event,
    seed_debounce_ms: int = _DEFAULT_DEBOUNCE_MS,
    seed_poll_seconds: float = _DEFAULT_SEED_POLL_SECONDS,
) -> None:
    """Run all four trigger sources concurrently until cancelled.

    If any single source exits with an unexpected error, the failure is propagated
    (and the remaining sources cancelled) so the supervisor notices instead of
    running silently trigger-less.
    """
    fingerprint = SeedFingerprint(seed_path)
    async with asyncio.TaskGroup() as group:
        group.create_task(
            watch_seed(reconciler, seed_path, debounce_ms=seed_debounce_ms, fingerprint=fingerprint)
        )
        group.create_task(poll_seed(reconciler, fingerprint, interval_seconds=seed_poll_seconds))
        group.create_task(periodic_tick(reconciler, tick_seconds))
        group.create_task(api_trigger(reconciler, api_event))
