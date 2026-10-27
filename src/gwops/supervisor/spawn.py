"""Bounded-spawn validation primitive: run ``gateway start --config <path>`` and observe it.

The gateway has no ``config validate`` subcommand, so the only way to check a config is to
spawn ``start`` with it. A good config never exits on its own (it binds :8443 and runs until
killed), so still being up after ``timeout_seconds`` is the success signal. A bad config makes
``start`` exit non-zero quickly with a ``failed to validate config``-shaped stderr line.

Used by :meth:`gwops.reconciler.core.Reconciler._render_and_write`,
:mod:`gwops.supervisor.process` (which shares the timeout constant) and the CI preflight.
"""

import asyncio
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import structlog

from gwops.supervisor.childenv import child_env

logger = structlog.get_logger(__name__)

# How long a spawned `start` must stay up before it is trusted as healthy. Also the window a
# live start must survive before its config is promoted to the last-good sidecar.
_VALIDATE_TIMEOUT_SECONDS = 5.0


class SpawnVerdict(StrEnum):
    """The bounded spawn's outcome."""

    REJECTED = "rejected"
    """Exited non-zero before the timeout: the binary refused this config."""

    HEALTHY = "healthy"
    """Still running at the timeout (the expected outcome for a good config)."""

    EXITED_ZERO_EARLY = "exited-zero-early"
    """Exited 0 before the timeout — unexpected for `start`; never a routine success."""


@dataclass(frozen=True)
class SpawnOutcome:
    """One bounded-spawn's outcome, with the child's stderr text for actionable errors."""

    verdict: SpawnVerdict
    stderr_text: str = ""


async def _kill(proc: asyncio.subprocess.Process) -> None:
    """Kill `proc` and, on Windows, its full descendant tree.

    The real gateway binary has no descendants, so `Process.kill()` suffices elsewhere.
    On Windows, `.cmd`-wrapped launchers re-exec through a further child that `kill()`
    does not reach; `taskkill /T` does.
    """
    if sys.platform == "win32":
        killer = await asyncio.create_subprocess_exec(
            "taskkill", "/F", "/T", "/PID", str(proc.pid),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await killer.wait()
    else:
        proc.kill()


async def validate_config_by_spawn(
    binary: Path,
    config_path: Path,
    *,
    timeout_seconds: float = _VALIDATE_TIMEOUT_SECONDS,
) -> SpawnOutcome:
    """Spawn ``<binary> start --config <config_path>`` and wait up to `timeout_seconds`.

    Uses the same argv as :meth:`gwops.supervisor.process.GatewayProcess.start`. Outcomes:
    **rejected** (non-zero exit before the timeout; the stderr text is returned),
    **healthy** (still running at the timeout; the child is killed), or
    **exited-zero-early** (exit 0 before the timeout, which `start` should not do).
    """
    argv = [str(binary), "start", "--config", str(config_path)]
    proc = await asyncio.create_subprocess_exec(
        *argv,
        # stdout is discarded: an undrained PIPE would let a chatty child block on a full buffer.
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
        env=child_env(),
    )
    # Poll instead of `asyncio.wait_for(proc.wait(), ...)`: cancelling a subprocess wait
    # while the child is alive can hang on Windows' ProactorEventLoop.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    poll_interval = min(0.05, timeout_seconds)
    while proc.returncode is None and loop.time() < deadline:
        await asyncio.sleep(poll_interval)

    if proc.returncode is None:
        # The verdict is already HEALTHY; bound the reap so a slow-to-exit process cannot block.
        await _kill(proc)
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except TimeoutError:
            logger.warning("spawn.validate_healthy_reap_timeout", binary=str(binary))
        logger.info("spawn.validate_healthy", binary=str(binary), timeout=timeout_seconds)
        return SpawnOutcome(verdict=SpawnVerdict.HEALTHY)

    assert proc.stderr is not None
    stderr_text = (await proc.stderr.read()).decode("utf-8", errors="replace")
    if proc.returncode != 0:
        logger.warning(
            "spawn.validate_rejected",
            binary=str(binary),
            returncode=proc.returncode,
            stderr=stderr_text.strip(),
        )
        return SpawnOutcome(verdict=SpawnVerdict.REJECTED, stderr_text=stderr_text)
    logger.warning(
        "spawn.validate_exited_zero_early", binary=str(binary), stderr=stderr_text.strip()
    )
    return SpawnOutcome(verdict=SpawnVerdict.EXITED_ZERO_EARLY, stderr_text=stderr_text)


# --- outcome classification ----------------------------------------------------------
#
# A failed spawn is not necessarily a bad config. The gateway's startup has three steps:
#
#   1. `config.Load`   -> "failed to load config"      (YAML parse / unmarshal / ByteSize)
#   2. `cfg.Validate()`-> "failed to validate config"  (structural rules)
#   3. `proxy.NewProxy`-> "failed to create proxy" / an OS open/parse/bind error
#
# Only steps 1-2 mean the config is broken. A step-3 failure is environmental: cert/key
# files absent on a CI runner, or :8443/:9090 still held by the running gateway
# (EADDRINUSE) during the reconciler's live pre-flight.

# Stderr shapes of steps 1-2, which mean the config itself is unusable.
SCHEMA_BREAK_MARKERS: tuple[str, ...] = (
    "failed to load config",
    "failed to validate config",
)


class Classification(StrEnum):
    """How a (healthy or non-healthy) spawn outcome is judged against the config schema."""

    HEALTHY = "healthy"
    """Still running at the validation window: the config is valid."""

    EXPECTED_STARTUP_FAILURE = "expected-startup-failure"
    """Rejected/early-exited without a schema marker — a step-3 runtime failure (missing
    runtime files, or a port already held by the live gateway). The config is not broken."""

    SCHEMA_BREAK = "schema-break"
    """Rejected/early-exited with a step-1/step-2 marker: the config itself is broken
    against this binary. The one outcome the reconciler's live pre-flight must reject."""

    UNRECOGNIZED_FAILURE = "unrecognized-failure"
    """Not healthy, no schema marker, and no positive step-3 marker either: the binary
    may never have reached config loading (usage error, panic, wrong architecture, exited
    0). Produced only by the CI preflight (:func:`gwops.ci.preflight.classify_ci_outcome`);
    :func:`classify_outcome` never returns it."""


@dataclass(frozen=True)
class PreflightVerdict:
    """The schema judgment of one :class:`SpawnOutcome`."""

    classification: Classification
    passed: bool
    note: str


def classify_outcome(outcome: SpawnOutcome) -> PreflightVerdict:
    """Classify one spawn outcome per the three-step startup model above.

    Pure function with no I/O, shared by the reconciler's pre-flight and the CI preflight.
    """
    if outcome.verdict is SpawnVerdict.HEALTHY:
        return PreflightVerdict(
            classification=Classification.HEALTHY,
            passed=True,
            note="still running at the validation window",
        )

    marker = next((m for m in SCHEMA_BREAK_MARKERS if m in outcome.stderr_text), None)
    if marker is not None:
        return PreflightVerdict(
            classification=Classification.SCHEMA_BREAK,
            passed=False,
            note=f"stderr matched schema-break marker {marker!r}",
        )

    verdict_note = (
        "exited 0 before the validation window with no schema-break marker in stderr"
        if outcome.verdict is SpawnVerdict.EXITED_ZERO_EARLY
        else (
            "rejected without a schema-break marker in stderr — a runtime startup "
            "failure (missing runtime files, or a port already held by the live gateway)"
        )
    )
    return PreflightVerdict(
        classification=Classification.EXPECTED_STARTUP_FAILURE,
        passed=True,
        note=verdict_note,
    )
