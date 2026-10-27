"""CI real-binary config preflight: spawn a golden config against a real gateway binary.

The gateway has no ``config validate`` subcommand (see :mod:`gwops.supervisor.spawn`), so
the only way to check a rendered config against a gateway release is to spawn ``start``
with it and read the outcome. This module wraps
:func:`gwops.supervisor.spawn.validate_config_by_spawn` and classifies a non-healthy
outcome as a config-schema break or an expected startup failure.

The golden configs reference runtime paths (for example ``/data/pki/leaf/fullchain.pem``)
that exist only inside a running container, so even a valid config fails to start on a CI
runner, just not at config parsing. The gateway's startup has three steps:

1. ``config.Load``: YAML parse, unmarshal, bad ByteSize. On failure, stderr contains
   ``"failed to load config"``.
2. ``cfg.Validate()``: structural validation (for example ``maxSize`` out of range or a
   missing TLS source). On failure, stderr contains ``"failed to validate config"``.
3. ``proxy.NewProxy``: where cert and key files are opened. On failure, stderr contains
   ``"failed to create proxy"`` or an OS-level open/parse/bind error.

Only steps 1 and 2 mean the config itself is broken; :data:`SCHEMA_BREAK_MARKERS` names
them.

This preflight is stricter than the reconciler's live check
(:func:`gwops.supervisor.spawn.classify_outcome`), which treats any non-schema rejection as
benign because EADDRINUSE is expected while the live gateway holds the ports. In CI, "no
schema marker" is also what a wrong binary, a usage error or an early panic looks like.
:func:`classify_ci_outcome` therefore passes only on a healthy spawn or on a rejection
carrying a positive step-3 marker (:data:`STEP3_REACHED_MARKERS`,
:data:`STEP3_RUNTIME_PATH_RE`); everything else fails with its stderr logged.

Entrypoint: ``python -m gwops.ci.preflight <binary> <config> [<config> ...]``.
"""

import argparse
import asyncio
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import structlog

from gwops.logging import configure_logging
from gwops.supervisor.spawn import (
    _VALIDATE_TIMEOUT_SECONDS,
    SCHEMA_BREAK_MARKERS,
    Classification,
    PreflightVerdict,
    SpawnOutcome,
    SpawnVerdict,
    classify_outcome,
    validate_config_by_spawn,
)

logger = structlog.get_logger(__name__)

# `SCHEMA_BREAK_MARKERS`, `Classification`, `PreflightVerdict` and `classify_outcome` are
# defined in `gwops.supervisor.spawn` and re-exported here.
__all__ = [
    "Classification",
    "ConfigPreflightResult",
    "PreflightVerdict",
    "SCHEMA_BREAK_MARKERS",
    "STEP3_REACHED_MARKERS",
    "STEP3_RUNTIME_PATH_RE",
    "classify_ci_outcome",
    "classify_outcome",
    "main",
    "preflight_config",
    "run",
    "run_preflight",
]


# Positive evidence the gateway got past config load and validate (steps 1-2) to proxy
# creation (step 3). `failed to create proxy` wraps any step-3 error.
STEP3_REACHED_MARKERS: tuple[str, ...] = ("failed to create proxy",)

# A missing file under a runtime-only directory (`/data/` or `/run/`): the config named a
# path that exists only inside a running container. Same evidence.
STEP3_RUNTIME_PATH_RE = re.compile(
    r"(?:/data/|/run/)[^\s:]*:\s*no such file or directory", re.IGNORECASE
)


def _check_markers(expect_failure: Sequence[str]) -> None:
    """Refuse an empty marker list or a blank marker: either would pass any rejection.

    Raises:
        ValueError: `expect_failure` is empty or holds an empty or whitespace-only string.
    """
    if not expect_failure:
        raise ValueError("expect_failure needs at least one marker")
    if any(not marker.strip() for marker in expect_failure):
        raise ValueError("expect_failure markers must not be blank")


def _marker_arg(value: str) -> str:
    try:
        _check_markers([value])
    except ValueError:
        raise argparse.ArgumentTypeError("the marker must not be empty or whitespace") from None
    return value


def classify_ci_outcome(
    outcome: SpawnOutcome,
    *,
    expect_failure: list[str] | None = None,
) -> PreflightVerdict:
    """Strictly classify one spawn outcome for CI: pass only on positive evidence.

    Passes (``passed=True``) on a still-running spawn, or on a rejection whose stderr
    carries a step-3 marker (:data:`STEP3_REACHED_MARKERS` or
    :data:`STEP3_RUNTIME_PATH_RE`) and no schema-break marker. Fails on a schema-break
    marker (:attr:`Classification.SCHEMA_BREAK`) and on everything else
    (:attr:`Classification.UNRECOGNIZED_FAILURE`): an exit 0 before the window, a usage or
    unknown-flag error, a panic before config load, an exec-format error, any rejection
    with no recognized marker. Pure function, no I/O.

    With `expect_failure`, passes only on a rejection whose stderr contains every
    substring and carries no schema-break marker; the step-3 marker check is skipped.

    Raises:
        ValueError: `expect_failure` is empty or holds a blank marker.
    """
    if expect_failure is not None:
        _check_markers(expect_failure)
        if outcome.verdict is not SpawnVerdict.REJECTED:
            markers = ", ".join(repr(m) for m in expect_failure)
            return PreflightVerdict(
                classification=Classification.UNRECOGNIZED_FAILURE,
                passed=False,
                note=(
                    f"expected a rejection containing [{markers}], but got "
                    f"{outcome.verdict.value}"
                ),
            )
        schema_break = classify_outcome(outcome)
        if schema_break.classification is Classification.SCHEMA_BREAK:
            return schema_break
        missing = [m for m in expect_failure if m not in outcome.stderr_text]
        if not missing:
            markers = ", ".join(repr(m) for m in expect_failure)
            return PreflightVerdict(
                classification=Classification.EXPECTED_STARTUP_FAILURE,
                passed=True,
                note=f"rejection matched all expected markers: [{markers}]",
            )
        missing_str = ", ".join(repr(m) for m in missing)
        return PreflightVerdict(
            classification=Classification.UNRECOGNIZED_FAILURE,
            passed=False,
            note=f"rejection missing expected marker(s): [{missing_str}]",
        )

    base = classify_outcome(outcome)
    if base.classification in (Classification.HEALTHY, Classification.SCHEMA_BREAK):
        return base

    if outcome.verdict is SpawnVerdict.EXITED_ZERO_EARLY:
        return PreflightVerdict(
            classification=Classification.UNRECOGNIZED_FAILURE,
            passed=False,
            note="exited 0 before the validation window: not a gateway that reached `start`",
        )

    stderr = outcome.stderr_text
    marker = next((m for m in STEP3_REACHED_MARKERS if m in stderr), None)
    if marker is None:
        path_match = STEP3_RUNTIME_PATH_RE.search(stderr)
        marker = path_match.group(0) if path_match else None
    if marker is None:
        return PreflightVerdict(
            classification=Classification.UNRECOGNIZED_FAILURE,
            passed=False,
            note=(
                "rejected with no step-3 marker in stderr: the binary may not have reached "
                "config loading (usage error, panic, wrong binary or architecture)"
            ),
        )
    return PreflightVerdict(
        classification=Classification.EXPECTED_STARTUP_FAILURE,
        passed=True,
        note=f"past config load/validate; step-3 runtime failure matched {marker!r}",
    )


@dataclass(frozen=True)
class ConfigPreflightResult:
    """One config's full preflight result: the raw spawn outcome plus its verdict."""

    config_path: Path
    outcome: SpawnOutcome
    verdict: PreflightVerdict


async def preflight_config(
    binary: Path,
    config_path: Path,
    *,
    timeout_seconds: float = _VALIDATE_TIMEOUT_SECONDS,
    expect_failure: list[str] | None = None,
) -> ConfigPreflightResult:
    """Spawn `binary` against `config_path` and classify the result, logging either way.

    Logs the binary, config, raw spawn verdict and classification on every call; a failing
    classification also logs the full stderr. Uses :func:`classify_ci_outcome`, which also
    applies `expect_failure`.

    Raises:
        ValueError: `expect_failure` is empty or holds a blank marker (checked before spawning).
    """
    if expect_failure is not None:
        _check_markers(expect_failure)
    try:
        outcome = await validate_config_by_spawn(
            binary, config_path, timeout_seconds=timeout_seconds
        )
    except OSError as exc:
        # The binary could not be exec'd; treat it like any run that never reached config loading.
        outcome = SpawnOutcome(
            verdict=SpawnVerdict.REJECTED, stderr_text=f"could not execute {binary}: {exc}"
        )
        verdict = PreflightVerdict(
            classification=Classification.UNRECOGNIZED_FAILURE,
            passed=False,
            note="the binary could not be executed (missing, not executable, wrong architecture)",
        )
    else:
        verdict = classify_ci_outcome(outcome, expect_failure=expect_failure)

    log_fields: dict[str, str | int] = {
        "binary": str(binary),
        "config": str(config_path),
        "spawn_verdict": outcome.verdict.value,
        "classification": verdict.classification.value,
    }
    if expect_failure is not None:
        log_fields["expect_failure_count"] = len(expect_failure)
    if verdict.classification is Classification.SCHEMA_BREAK:
        logger.error("ci.preflight_schema_break", stderr=outcome.stderr_text.strip(), **log_fields)
    elif verdict.classification is Classification.UNRECOGNIZED_FAILURE:
        logger.error(
            "ci.preflight_unrecognized_failure",
            note=verdict.note,
            stderr=outcome.stderr_text.strip(),
            **log_fields,
        )
    elif verdict.classification is Classification.EXPECTED_STARTUP_FAILURE:
        logger.info("ci.preflight_expected_startup_failure", note=verdict.note, **log_fields)
    else:
        logger.info("ci.preflight_healthy", **log_fields)

    return ConfigPreflightResult(config_path=config_path, outcome=outcome, verdict=verdict)


async def run_preflight(
    binary: Path,
    config_paths: Sequence[Path],
    *,
    timeout_seconds: float = _VALIDATE_TIMEOUT_SECONDS,
    expect_failure: list[str] | None = None,
) -> list[ConfigPreflightResult]:
    """Preflight every config in `config_paths` against `binary` and return all results.

    Runs sequentially: a healthy spawn binds :8443 for the full `timeout_seconds` window,
    so concurrent runs against the same binary would race for the port.
    """
    return [
        await preflight_config(
            binary, config_path, timeout_seconds=timeout_seconds, expect_failure=expect_failure
        )
        for config_path in config_paths
    ]


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m gwops.ci.preflight",
        description=(
            "Spawn a real gateway binary against one or more rendered golden configs "
            "and fail (non-zero exit) unless each is healthy or fails only at proxy "
            "creation (runtime files absent)."
        ),
    )
    parser.add_argument(
        "binary",
        type=Path,
        help="path to the gateway binary to validate against (e.g. a downloaded release)",
    )
    parser.add_argument(
        "configs",
        type=Path,
        nargs="+",
        help="one or more rendered golden config YAML files to preflight",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=_VALIDATE_TIMEOUT_SECONDS,
        help="how long a config must stay up to be considered healthy (default: %(default)s)",
    )
    parser.add_argument(
        "--expect-failure",
        type=_marker_arg,
        action="append",
        dest="expect_failure",
        help="pass only when stderr contains this substring (repeatable)",
    )
    return parser.parse_args(argv)


async def main(argv: Sequence[str] | None = None) -> int:
    """Run the preflight CLI: parse args, preflight every config, return the exit code.

    Exit code is non-zero if any config fails the strict classification (a schema break
    or an unrecognized failure), zero when every config is healthy or was rejected only at
    step 3 (proxy creation, the expected outcome when runtime files are absent).

    With ``--expect-failure``, every config must instead reject with every marker in stderr.
    """
    args = _parse_args(argv)
    results = await run_preflight(
        args.binary, args.configs, timeout_seconds=args.timeout_seconds,
        expect_failure=args.expect_failure,
    )
    failures = [r for r in results if not r.verdict.passed]
    if failures:
        logger.error(
            "ci.preflight_failed",
            binary=str(args.binary),
            failed_configs=[str(r.config_path) for r in failures],
            classifications=[r.verdict.classification.value for r in failures],
            total_configs=len(results),
        )
        return 1
    logger.info(
        "ci.preflight_passed", binary=str(args.binary), total_configs=len(results)
    )
    return 0


def run() -> None:
    """Synchronous console entrypoint: `python -m gwops.ci.preflight ...`."""
    configure_logging()
    sys.exit(asyncio.run(main()))


if __name__ == "__main__":
    run()
