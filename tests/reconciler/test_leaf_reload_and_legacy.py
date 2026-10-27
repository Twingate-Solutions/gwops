"""Private-mode leaf: a failed delete of the previous generation, and the legacy leaf files.

The gateway reloads the leaf only when the previous generation's files are unlinked, so a
mint whose delete failed, or a sweep that cannot delete, is a local error (not a quiet warning)
and the delete is retried on every pass. The pre-store ``leaf.crt`` / ``leaf.key`` survive a
mint (a ``.last-good`` config may still name them) and are removed after a successful pass only
when neither ``config.yaml`` nor ``.last-good`` references them.
"""

import dataclasses
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from gwops.certs.store import StoreError
from gwops.reconciler.core import ReconcileResult
from gwops.renderer.capabilities import Capabilities
from gwops.supervisor.process import last_good_path
from tests.store_support import generation_dirs, leaf_dir

from .test_core import _SSH_SEED, Env

_NOT_RELOADED_AFTER_MINT = (
    "leaf certificate: installed but previous generation not removed; gateway has not reloaded"
)
_NOT_RELOADED = "leaf certificate: previous generation not removed; gateway has not reloaded"

_needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32",
    reason="creating symlinks needs elevation on Windows (WinError 1314)",
)


@pytest.fixture
def env(tmp_path: Path, gateway_binary: Callable[..., Path]) -> Env:
    return Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), None)


def _local_errors(result: ReconcileResult) -> list[str]:
    return [e for e in result.errors if e.startswith("leaf certificate")]


class TestFailedDeleteAtMint:
    async def test_a_mint_that_could_not_delete_the_previous_generation_is_a_local_error(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real_install = env.certs._store.install

        def _install(name: str, cert_pem: bytes, key_pem: bytes) -> object:
            return dataclasses.replace(real_install(name, cert_pem, key_pem), reload_pending=True)

        monkeypatch.setattr(env.certs._store, "install", _install)

        result = await env.reconciler.reconcile("test")

        assert _local_errors(result) == [_NOT_RELOADED_AFTER_MINT]
        assert result.local_ok is False
        [minted] = [a for a in result.actions if a.startswith("minted TLS leaf")]
        assert minted.endswith("(previous generation not removed; gateway has not reloaded)")
        assert not any("hot-reloads" in a for a in result.actions)
        assert env.process.calls == []  # a local failure applies nothing

    async def test_a_clean_mint_is_not_an_error(self, env: Env) -> None:
        result = await env.reconciler.reconcile("test")

        assert _local_errors(result) == []
        assert result.local_ok is True


class TestSweepRetriedEveryPass:
    async def test_a_sweep_that_cannot_delete_is_a_local_error_until_it_can(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.reconciler.reconcile("first")

        with monkeypatch.context() as patch:
            def _fail() -> list[str]:
                raise StoreError("cannot collect store garbage: permission denied")

            patch.setattr(env.certs, "collect_leaf_generations", _fail)
            failed = await env.reconciler.reconcile("second")
        recovered = await env.reconciler.reconcile("third")

        assert _local_errors(failed) == [_NOT_RELOADED]
        assert failed.local_ok is False
        assert _local_errors(recovered) == []
        assert recovered.local_ok is True

    @_needs_symlinks
    async def test_a_stale_leaf_generation_is_removed_on_the_next_pass(self, env: Env) -> None:
        await env.reconciler.reconcile("first")
        directory = leaf_dir(env.paths.pki_dir)
        stale = directory / "..0123456789ab"
        stale.mkdir()
        (stale / "fullchain.pem").write_text("old", encoding="utf-8")
        assert len(generation_dirs(directory)) == 2

        result = await env.reconciler.reconcile("second")

        assert not stale.exists()
        assert len(generation_dirs(directory)) == 1
        assert "removed 1 stale leaf generation(s); gateway reloads the leaf" in result.actions


class TestLegacyLeafFiles:
    @staticmethod
    def _plant(env: Env) -> tuple[Path, Path]:
        legacy_cert, legacy_key = env.certs.legacy_leaf_paths
        legacy_cert.write_bytes(b"old cert")
        legacy_key.write_bytes(b"old key")
        return legacy_cert, legacy_key

    async def test_they_survive_the_mint_and_are_removed_after_a_clean_pass(
        self, env: Env
    ) -> None:
        legacy_cert, legacy_key = self._plant(env)

        result = await env.reconciler.reconcile("test")

        assert result.local_ok is True
        assert not legacy_cert.exists() and not legacy_key.exists()
        assert f"removed legacy leaf file {legacy_cert.as_posix()}" in result.actions
        assert f"removed legacy leaf file {legacy_key.as_posix()}" in result.actions
        assert result.housekeeping_errors == []

    async def test_a_last_good_config_that_still_names_them_keeps_them(self, env: Env) -> None:
        legacy_cert, legacy_key = self._plant(env)
        await env.reconciler.reconcile("first")
        legacy_cert.write_bytes(b"old cert")
        legacy_key.write_bytes(b"old key")
        last_good_path(env.config_path).write_text(
            "tls:\n  certificates:\n    files:\n"
            f"      - certificateFile: {legacy_cert.as_posix()}\n"
            f"        keyFile: {legacy_key.as_posix()}\n",
            encoding="utf-8",
        )

        result = await env.reconciler.reconcile("second")

        assert legacy_cert.read_bytes() == b"old cert"
        assert legacy_key.read_bytes() == b"old key"
        assert not any("legacy leaf file" in a for a in result.actions)

    async def test_a_config_naming_one_of_them_keeps_only_that_one(self, env: Env) -> None:
        legacy_cert, legacy_key = self._plant(env)
        await env.reconciler.reconcile("first")
        legacy_cert.write_bytes(b"old cert")
        legacy_key.write_bytes(b"old key")
        last_good_path(env.config_path).write_text(
            f"certificateFile: {legacy_cert.as_posix()}\n", encoding="utf-8"
        )

        await env.reconciler.reconcile("second")

        assert legacy_cert.exists()
        assert not legacy_key.exists()

    async def test_an_unreadable_config_removes_nothing(self, env: Env) -> None:
        legacy_cert, legacy_key = self._plant(env)
        await env.reconciler.reconcile("first")
        legacy_cert.write_bytes(b"old cert")
        legacy_key.write_bytes(b"old key")
        last_good_path(env.config_path).mkdir()  # reading a directory fails

        result = await env.reconciler.reconcile("second")

        assert legacy_cert.exists() and legacy_key.exists()
        assert any(
            e.startswith("legacy leaf files kept: a gateway config could not be read")
            for e in result.housekeeping_errors
        )
        assert result.local_ok is True

    async def test_a_failed_removal_is_a_housekeeping_error_that_never_fails_the_pass(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        legacy_cert, _legacy_key = self._plant(env)
        real_unlink = Path.unlink

        def _unlink(self: Path, *args: object, **kwargs: object) -> None:
            if self == legacy_cert:
                raise PermissionError("secret detail")
            real_unlink(self, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(Path, "unlink", _unlink)

        result = await env.reconciler.reconcile("test")

        assert result.local_ok is True
        assert legacy_cert.exists()
        [error] = [e for e in result.housekeeping_errors if "legacy leaf file" in e]
        assert error.endswith("failed (PermissionError)")
        assert "secret detail" not in error
