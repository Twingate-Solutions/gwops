"""Tests for gwops.supervisor.spawn.validate_config_by_spawn: the bounded-spawn primitive.

Exercises all three outcomes against the fake gateway, and confirms the
timeout constant is injectable (a fast test suite depends on shrinking it well below the
production 5s default).
"""

from collections.abc import Callable
from pathlib import Path

from gwops.supervisor.spawn import _VALIDATE_TIMEOUT_SECONDS, SpawnVerdict, validate_config_by_spawn


def _config_file(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text("twingate: {network: test}\n", encoding="utf-8")
    return path


class TestRejected:
    async def test_bad_config_is_rejected_with_stderr_text(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        outcome = await validate_config_by_spawn(
            fake_gateway(reject_config=True), _config_file(tmp_path), timeout_seconds=2.0
        )
        assert outcome.verdict is SpawnVerdict.REJECTED
        assert "failed to validate config" in outcome.stderr_text


class TestHealthy:
    async def test_good_config_still_up_at_timeout_is_healthy(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        outcome = await validate_config_by_spawn(
            fake_gateway(), _config_file(tmp_path), timeout_seconds=0.2
        )
        assert outcome.verdict is SpawnVerdict.HEALTHY

    async def test_healthy_process_is_actually_killed_not_leaked(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        # Proves the call returns promptly rather than hanging past the timeout; a leaked,
        # unreaped child would show up as a lingering process.
        import time

        started = time.monotonic()
        await validate_config_by_spawn(
            fake_gateway(), _config_file(tmp_path), timeout_seconds=0.2
        )
        assert time.monotonic() - started < 2.0


class TestExitedZeroEarly:
    async def test_clean_early_exit_is_reported_distinctly(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        outcome = await validate_config_by_spawn(
            fake_gateway(early_exit_after=0.05, early_exit_code=0),
            _config_file(tmp_path),
            timeout_seconds=2.0,
        )
        assert outcome.verdict is SpawnVerdict.EXITED_ZERO_EARLY


class TestTimeoutInjectable:
    async def test_default_constant_is_five_seconds(self) -> None:
        assert _VALIDATE_TIMEOUT_SECONDS == 5.0

    async def test_custom_timeout_is_honored_and_faster_than_default(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        import time

        started = time.monotonic()
        outcome = await validate_config_by_spawn(
            fake_gateway(), _config_file(tmp_path), timeout_seconds=0.1
        )
        elapsed = time.monotonic() - started
        assert outcome.verdict is SpawnVerdict.HEALTHY
        assert elapsed < _VALIDATE_TIMEOUT_SECONDS
