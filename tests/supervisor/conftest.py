"""Shared helpers for supervisor tests: launching the fake gateway binary.

The fake gateway is a Python script (``tests/fakes/fake_gateway.py``). Just like the
reconciler's pre-flight tests, it is wrapped so ``asyncio.create_subprocess_exec`` can
launch it as if it were a native binary: a ``.cmd`` shim on Windows, an executable ``sh``
script on POSIX. ``GatewayProcess``/``validate_config_by_spawn`` own the argv
(``start --config <path>``), so the fake's behavior is injected through environment
variables baked into the wrapper. Because the wrapper exports them *after* the supervisor has
spawned it, they are unaffected by the supervisor's ``env=`` allowlist (``child_env``): the
allowlist never needs a test-only widening. ``env_dump=<path>`` makes the fake write its
inherited environment there and exit, for the env-scrub tests.
"""

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

_FAKE_GATEWAY = Path(__file__).parent.parent / "fakes" / "fake_gateway.py"


def _fake_env(
    *,
    interval: float,
    reject_config: bool,
    early_exit_after: float,
    early_exit_code: int,
    crash_after: int,
    ignore_sigterm: bool,
    bigline_bytes: int,
    boot_counter: Path | None,
    stderr_file: Path | None,
    stderr_ticks: bool,
    env_dump: Path | None,
) -> dict[str, str]:
    env = {
        "FAKE_GW_INTERVAL": str(interval),
        "FAKE_GW_REJECT_CONFIG": "1" if reject_config else "0",
        "FAKE_GW_EARLY_EXIT_AFTER": str(early_exit_after),
        "FAKE_GW_EARLY_EXIT_CODE": str(early_exit_code),
        "FAKE_GW_CRASH_AFTER": str(crash_after),
        "FAKE_GW_IGNORE_SIGTERM": "1" if ignore_sigterm else "0",
        "FAKE_GW_BIGLINE_BYTES": str(bigline_bytes),
        "FAKE_GW_STDERR_TICKS": "1" if stderr_ticks else "0",
    }
    if boot_counter is not None:
        env["FAKE_GW_BOOT_COUNTER"] = str(boot_counter)
    if stderr_file is not None:
        env["FAKE_GW_STDERR_FILE"] = str(stderr_file)
    if env_dump is not None:
        env["FAKE_GW_ENV_DUMP"] = str(env_dump)
    return env


def _write_launcher(tmp_path: Path, name: str, env: dict[str, str]) -> Path:
    if sys.platform == "win32":
        launcher = tmp_path / f"{name}.cmd"
        lines = [f"@set {key}={value}" for key, value in env.items()]
        lines.append(f'@"{sys.executable}" "{_FAKE_GATEWAY}" %*')
        launcher.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")
    else:
        launcher = tmp_path / name
        lines = ["#!/bin/sh"]
        lines += [f"export {key}='{value}'" for key, value in env.items()]
        lines.append(f'exec "{sys.executable}" "{_FAKE_GATEWAY}" "$@"')
        launcher.write_text("\n".join(lines) + "\n", encoding="utf-8")
        launcher.chmod(launcher.stat().st_mode | 0o111)
    return launcher


@pytest.fixture
def fake_gateway(tmp_path: Path) -> Callable[..., Path]:
    """Return a factory that writes a launchable fake-gateway binary into ``tmp_path``."""

    counter = [0]

    def _make(
        *,
        interval: float = 0.05,
        reject_config: bool = False,
        early_exit_after: float = 0.0,
        early_exit_code: int = 1,
        crash_after: int = 0,
        ignore_sigterm: bool = False,
        bigline_bytes: int = 0,
        boot_counter: Path | None = None,
        stderr_file: Path | None = None,
        stderr_ticks: bool = True,
        env_dump: Path | None = None,
    ) -> Path:
        counter[0] += 1
        env = _fake_env(
            interval=interval,
            reject_config=reject_config,
            early_exit_after=early_exit_after,
            early_exit_code=early_exit_code,
            crash_after=crash_after,
            ignore_sigterm=ignore_sigterm,
            bigline_bytes=bigline_bytes,
            boot_counter=boot_counter,
            stderr_file=stderr_file,
            stderr_ticks=stderr_ticks,
            env_dump=env_dump,
        )
        return _write_launcher(tmp_path, f"fake-gateway-{counter[0]}", env)

    return _make
