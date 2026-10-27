"""Helpers for the AcmeRunner tests: a manual clock, polling and process checks.

Nothing here knows the runner's internals. The runner is driven through its public API
(``configure``, ``start``, ``wake``, ``request_issue``, ``aclose``) and observed through
``snapshot()``, ``state.json`` (read with a fresh :class:`AcmeStateStore`) and the fake lego's
invocation log. Sleeping is limited to short polling intervals; time that matters to the runner
(backoff, check interval, retry-after) comes from :class:`Clock`.
"""

import asyncio
import json
import os
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from cryptography import x509

from gwops.acme.runner import AcmeRunner
from gwops.acme.state import AcmeStateStore, CertAcmeState
from gwops.settings import GwopsSettings
from tests.acme.fake_lego_support import FakeLego, Step
from tests.public_chain_support import fingerprint

__all__ = [
    "CERT",
    "Clock",
    "RunnerFactory",
    "child_pid",
    "entry",
    "events",
    "fingerprint_of",
    "leaf_of",
    "process_alive",
    "serial_of",
    "started_pids",
    "wait_attempts",
    "wait_until",
]

CERT = "wildcard"

type RunnerFactory = Callable[..., AcmeRunner]
"""``new_runner(settings=..., environ=..., on_installed=...)`` from ``conftest.py``."""


class Clock:
    """A settable UTC clock; the runner calls it for every timestamp it records."""

    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> datetime:
        """Move the clock forward and return the new time."""
        self.now += delta
        return self.now


async def wait_until(
    predicate: Callable[[], bool],
    *,
    timeout: float = 30.0,
    interval: float = 0.02,
    what: str = "the condition",
) -> None:
    """Poll `predicate` until it is true; fail the test with `what` after `timeout` seconds."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out after {timeout:g}s waiting for {what}")
        await asyncio.sleep(interval)


def entry(settings: GwopsSettings, name: str = CERT) -> CertAcmeState:
    """The persisted state of `name`, read from ``state.json`` with a fresh store."""
    return AcmeStateStore(settings.acme_dir).get(name)


async def wait_attempts(
    settings: GwopsSettings,
    runner: AcmeRunner,
    count: int,
    name: str = CERT,
    *,
    timeout: float = 30.0,
) -> CertAcmeState:
    """Wait until `count` attempts of `name` have started and the runner is idle again.

    ``attempts`` is persisted before lego is spawned and ``running`` is reset only after the
    outcome (state, install, callback) is complete, so both together mean "attempt `count` is
    finished".
    """
    await wait_until(
        lambda: entry(settings, name).attempts >= count and runner.running is None,
        timeout=timeout,
        what=f"attempt {count} of {name!r} to finish",
    )
    return entry(settings, name)


def events(logs: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    """The captured structlog events called `name`."""
    return [e for e in logs if e["event"] == name]


def leaf_of(step: Step) -> x509.Certificate:
    """The leaf certificate a fake-lego ``success`` step writes."""
    return x509.load_pem_x509_certificate(step["crt"].encode())


def serial_of(step: Step) -> str:
    """Lowercase hex serial of the step's leaf, the form the runner records."""
    return format(leaf_of(step).serial_number, "x")


def fingerprint_of(step: Step) -> str:
    """Lowercase hex SHA-256 of the step's leaf."""
    return fingerprint(leaf_of(step))


def started_pids(fake: FakeLego) -> list[int]:
    """Process ids of every fake-lego start recorded so far."""
    if not fake.invocations_path.exists():
        return []
    records: list[dict[str, Any]] = [
        json.loads(line) for line in fake.invocations_path.read_text().splitlines() if line
    ]
    return [r["pid"] for r in records if r["event"] == "start"]


def child_pid(fake: FakeLego) -> int | None:
    """Process id of the grandchild a ``hang(spawn_child=True)`` run started, if any."""
    path = fake.binary.with_name("fake_lego.child.pid")
    try:
        return int(path.read_text())
    except (OSError, ValueError):  # absent, or caught mid-write
        return None


def process_alive(pid: int) -> bool:
    """Whether a process with this id is running (a reaped process or a zombie is not)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        with open(f"/proc/{pid}/stat") as handle:
            # "<pid> (<comm>) <state> ...": the state follows the last closing parenthesis.
            return handle.read().rpartition(")")[2].split()[0] != "Z"
    except (OSError, IndexError):
        return True
