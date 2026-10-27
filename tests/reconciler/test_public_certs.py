"""The public-mode certificate step of the reconciler.

Drives full passes of ``Reconciler`` over tmp dirs with real generated certificate material
and no tenant client. The store is ``PlainFileStore`` on Windows (``tests/conftest.py``) and
the real ``MaterialStore`` elsewhere; the real store's atomicity is covered in
``test_public_certs_store.py``.

All-or-nothing: any invalid certificate means nothing is installed and the last good
config and generations keep serving.
"""

import asyncio
import dataclasses
import inspect
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
import structlog.testing
import yaml

from gwops.certs.public import RegisteredRootError
from gwops.certs.store import StoreError
from gwops.reconciler import core
from gwops.reconciler.core import PublicCertStatus, ReconcileResult
from gwops.renderer.capabilities import Capabilities
from gwops.supervisor.process import ProcState, last_good_path
from gwops.tgapi.client import TGClient
from tests.public_chain_support import Issued, ec_key, key_pem_of, pem_bodies, rsa_hierarchy
from tests.public_tls_support import ZONE
from tests.store_support import generation_id

from .conftest import FakeTGServer
from .public_certs_support import DAY, ROOT, PublicEnv, host, issue, other_cert_errors
from .test_core import _SSH_SEED, Env

HELD_DOWN = "gateway held down until every public certificate is installed"


@pytest.fixture(autouse=True)
def _pin_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate against the generated test root, never the host's trust store."""
    monkeypatch.setattr(core, "resolve_registered_root", lambda name: ROOT)


@pytest.fixture
def make_env(
    tmp_path: Path, gateway_binary: Callable[..., Path]
) -> Callable[..., PublicEnv]:
    def _make(certs: dict[str, list[str]] | None = None) -> PublicEnv:
        return PublicEnv(tmp_path, gateway_binary(), certs)

    return _make


TWO = {"alpha": [host("alpha")], "beta": [host("beta")]}


def _installed_actions(actions: list[str]) -> list[str]:
    return [a for a in actions if a.startswith("installed public certificate")]


def _status(result: object, name: str) -> PublicCertStatus:
    [found] = [s for s in result.public_certs or [] if s.name == name]  # type: ignore[attr-defined]
    return found


class TestFirstInstall:
    async def test_every_certificate_is_installed_rendered_and_the_gateway_started(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write_all()

        result = await pub.run()

        assert pub.public_errors(result) == []
        assert other_cert_errors(result) == []
        assert result.local_ok is True
        for name in TWO:
            issued = pub.written[name]
            assert pub.served(name) == (issued.cert_pem, issued.key_pem)
            gen = generation_id(issued.cert_pem, issued.key_pem)
            assert (
                f"installed public certificate '{name}' generation {gen} (gateway hot-reloads)"
                in result.actions
            )
        assert pub.env.process.calls == ["start"]

    async def test_the_rendered_entries_are_sorted_by_name_at_the_stable_paths(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env({"zeta": [host("zeta")], "alpha": [host("alpha")]})
        pub.write_all()

        await pub.run()

        doc = yaml.safe_load(pub.env.config_path.read_text(encoding="utf-8"))
        files = doc["tls"]["certificates"]["files"]
        assert [f["certificateFile"] for f in files] == [
            pub.env.paths.public_cert_files(n)[0].as_posix() for n in ("alpha", "zeta")
        ]
        assert "automation" not in doc["tls"]

    async def test_the_status_lists_every_certificate_in_seed_order(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env({"zeta": [host("zeta")], "alpha": [host("alpha")]})
        pub.write_all()

        result = await pub.run()

        assert result.public_certs is not None
        assert [s.name for s in result.public_certs] == ["zeta", "alpha"]
        zeta = _status(result, "zeta")
        issued = pub.written["zeta"]
        assert zeta == PublicCertStatus(
            name="zeta",
            names=(host("zeta"),),
            not_after=issued.cert.not_valid_after_utc,
            state="ok",
            last_error=None,
            generation=generation_id(issued.cert_pem, issued.key_pem),
        )

    async def test_an_unchanged_pass_has_no_install_action_and_no_new_generation(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write_all()
        first = await pub.run()

        second = await pub.run()

        assert _installed_actions(second.actions) == []
        assert [s.generation for s in second.public_certs or []] == [
            s.generation for s in first.public_certs or []
        ]
        assert pub.env.process.calls == ["start"]

    async def test_private_mode_has_no_public_status(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), None)

        result = await env.reconciler.reconcile("test")

        assert result.public_certs is None


class TestAllOrNothing:
    async def test_one_invalid_certificate_installs_nothing_and_keeps_the_last_good(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write_all()
        first = await pub.run()
        old_alpha, old_beta = pub.served("alpha"), pub.served("beta")
        old_config = pub.env.config_path.read_text(encoding="utf-8")
        # alpha has a valid renewal waiting; beta's key no longer matches its certificate.
        pub.write("alpha")
        beta = pub.written["beta"]
        pub.source_root.joinpath("beta", "privkey.pem").write_bytes(key_pem_of(ec_key()))

        result = await pub.run()

        [error] = pub.public_errors(result)
        assert error.startswith("public certificate 'beta':")
        assert "key_file" in error
        assert result.local_ok is False
        assert pub.served("alpha") == old_alpha  # the valid renewal was not installed
        assert pub.served("beta") == old_beta
        assert pub.env.config_path.read_text(encoding="utf-8") == old_config
        assert pub.env.process.calls == ["start"]
        assert _installed_actions(result.actions) == []
        assert "kept previous gateway config (local step failed)" in result.actions
        beta_status = _status(result, "beta")
        assert beta_status.state == "invalid"
        assert beta_status.last_error == error
        assert beta_status.generation == _status(first, "beta").generation
        assert beta_status.not_after == beta.cert.not_valid_after_utc
        # alpha validated but was not installed: it is pending and keeps what is served.
        alpha_status = _status(result, "alpha")
        assert alpha_status.state == "pending"
        assert alpha_status.last_error == "not installed: another certificate failed validation"
        assert alpha_status.generation == _status(first, "alpha").generation
        assert alpha_status.not_after == _status(first, "alpha").not_after

    async def test_a_valid_certificate_that_was_never_installed_is_pending_without_a_generation(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write("alpha")
        pub.write("beta")
        pub.source_root.joinpath("beta", "privkey.pem").write_bytes(key_pem_of(ec_key()))

        result = await pub.run()

        alpha = _status(result, "alpha")
        assert alpha == PublicCertStatus(
            name="alpha",
            names=(host("alpha"),),
            not_after=None,
            state="pending",
            last_error="not installed: another certificate failed validation",
            generation=None,
        )
        assert _status(result, "beta").state == "invalid"
        assert not pub.env.paths.public_cert_files("alpha")[0].exists()

    async def test_the_pending_certificate_is_ok_again_once_the_failure_is_fixed(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write_all()
        good_key = pub.source_root.joinpath("beta", "privkey.pem").read_bytes()
        pub.source_root.joinpath("beta", "privkey.pem").write_bytes(key_pem_of(ec_key()))
        failed = await pub.run()
        assert _status(failed, "alpha").state == "pending"
        pub.source_root.joinpath("beta", "privkey.pem").write_bytes(good_key)

        result = await pub.run()

        assert [_status(result, n).state for n in TWO] == ["ok", "ok"]
        assert _status(result, "alpha").generation is not None
        assert _status(result, "alpha").last_error is None

    async def test_every_failure_is_collected_in_seed_order(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write_all()
        await pub.run()
        pub.source_root.joinpath("alpha", "privkey.pem").write_bytes(key_pem_of(ec_key()))
        pub.source_root.joinpath("beta", "fullchain.pem").unlink()

        result = await pub.run()

        errors = pub.public_errors(result)
        assert [e.split(":")[0] for e in errors] == [
            "public certificate 'alpha'",
            "public certificate 'beta'",
        ]
        assert "key_file" in errors[0] and "cert_file" in errors[1]
        assert _status(result, "alpha").state == "invalid"
        assert _status(result, "beta").state == "invalid"

    async def test_an_expired_renewal_is_refused_and_the_last_good_stays_served(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env()
        pub.write_all()
        first = await pub.run()
        served = pub.served("alpha")
        pub.write("alpha", issue("alpha", lifetime_days=90, remaining_days=-1))

        result = await pub.run()

        [error] = pub.public_errors(result)
        assert "notAfter" in error
        assert pub.served("alpha") == served
        status = _status(result, "alpha")
        assert status.state == "invalid"
        assert status.generation == _status(first, "alpha").generation

    async def test_errors_and_status_never_carry_key_or_certificate_contents(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env()
        pub.write_all()
        await pub.run()
        bad_key = key_pem_of(ec_key())
        pub.source_root.joinpath("alpha", "privkey.pem").write_bytes(bad_key)

        result = await pub.run()

        text = " ".join(result.errors) + repr(result.public_certs)
        issued = pub.written["alpha"]
        for body in pem_bodies(issued.cert_pem, issued.key_pem, bad_key):
            assert body not in text

    async def test_a_fixed_certificate_is_installed_on_the_next_pass_and_the_error_clears(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write_all()
        await pub.run()
        good_key = pub.source_root.joinpath("beta", "privkey.pem").read_bytes()
        pub.source_root.joinpath("beta", "privkey.pem").write_bytes(key_pem_of(ec_key()))
        failed = await pub.run()
        assert _status(failed, "beta").state == "invalid"
        pub.write("alpha")  # a renewal that the failed pass held back
        pub.source_root.joinpath("beta", "privkey.pem").write_bytes(good_key)

        result = await pub.run()

        assert pub.public_errors(result) == []
        assert result.local_ok is True
        assert pub.served("alpha") == (pub.written["alpha"].cert_pem, pub.written["alpha"].key_pem)
        assert [_status(result, n).state for n in TWO] == ["ok", "ok"]
        assert _status(result, "beta").last_error is None
        assert len(_installed_actions(result.actions)) == 1  # only alpha changed

    async def test_a_store_error_partway_is_a_local_error_and_nothing_is_rendered(
        self, make_env: Callable[..., PublicEnv], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pub = make_env(TWO)
        pub.write_all()
        store = pub.env.reconciler._public_store
        real_install = store.install

        def _install(name: str, cert_pem: bytes, key_pem: bytes) -> object:
            if name == "beta":
                raise StoreError("cannot install material for 'beta': no space left on device")
            return real_install(name, cert_pem, key_pem)

        monkeypatch.setattr(store, "install", _install)

        result = await pub.run()

        [error] = pub.public_errors(result)
        assert error.startswith("public certificate 'beta': install failed")
        assert result.local_ok is False
        assert any(a.startswith("installed public certificate 'alpha'") for a in result.actions)
        assert pub.served("alpha") == (pub.written["alpha"].cert_pem, pub.written["alpha"].key_pem)
        assert not pub.env.config_path.exists()  # nothing rendered this pass
        assert _status(result, "alpha").state == "ok"
        assert _status(result, "beta").state == "invalid"
        assert _status(result, "beta").generation is None

    async def test_a_pass_that_never_reaches_the_step_keeps_the_previous_status(
        self, make_env: Callable[..., PublicEnv], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pub = make_env()
        pub.write_all()
        first = await pub.run()

        def _refuse(name: str) -> object:
            raise RegisteredRootError("trust store unreadable")

        monkeypatch.setattr(core, "resolve_registered_root", _refuse)
        result = await pub.run()

        assert result.local_ok is False
        assert result.public_certs == first.public_certs


class TestExpiringState:
    @pytest.mark.parametrize(
        ("remaining_days", "state"),
        [(31, "ok"), (29, "expiring"), (1, "expiring")],
    )
    async def test_less_than_a_third_of_the_lifetime_left_is_expiring(
        self, make_env: Callable[..., PublicEnv], remaining_days: int, state: str
    ) -> None:
        pub = make_env()
        pub.write("alpha", issue("alpha", lifetime_days=90, remaining_days=remaining_days))

        result = await pub.run()

        assert result.local_ok is True  # expiring is still served, never refused
        assert pub.public_errors(result) == []
        status = _status(result, "alpha")
        assert status.state == state
        assert status.generation is not None
        assert status.last_error is None
        assert pub.served("alpha")[0] == pub.written["alpha"].cert_pem


class TestApply:
    async def test_a_content_change_at_the_stable_paths_does_not_restart_the_gateway(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write_all()
        first = await pub.run()
        config = pub.env.config_path.read_text(encoding="utf-8")
        renewed = pub.write("alpha")

        result = await pub.run()

        gen = generation_id(renewed.cert_pem, renewed.key_pem)
        assert _installed_actions(result.actions) == [
            f"installed public certificate 'alpha' generation {gen} (gateway hot-reloads)"
        ]
        assert _status(result, "alpha").generation == gen != _status(first, "alpha").generation
        assert pub.env.config_path.read_text(encoding="utf-8") == config
        assert pub.env.process.calls == ["start"]
        assert not any(
            "drain-restarted" in a or "wrote gateway config" in a for a in result.actions
        )

    async def test_an_entry_set_change_drain_restarts_the_gateway(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env()
        pub.write_all()
        await pub.run()
        pub.declare(TWO)
        pub.write("beta")

        result = await pub.run()

        assert pub.public_errors(result) == []
        assert pub.env.process.calls == ["start", "drain_restart"]
        assert (
            "drain-restarted gateway (restart-required: TLS certificate set changed)"
            in result.actions
        )
        doc = yaml.safe_load(pub.env.config_path.read_text(encoding="utf-8"))
        assert len(doc["tls"]["certificates"]["files"]) == 2


class TestHoldDown:
    async def test_no_installed_certificate_holds_the_gateway_down(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env()  # nothing written: the files do not exist

        result = await pub.run()

        [error] = pub.public_errors(result)
        assert error.startswith("public certificate 'alpha':")
        assert HELD_DOWN in result.actions
        assert not pub.env.config_path.exists()
        assert pub.env.process.calls == []
        assert pub.env.process.state is ProcState.STOPPED

    async def test_a_newly_declared_certificate_without_an_install_holds_a_running_gateway(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        """Driven through the real certificate step: beta is declared but its files are missing,
        so nothing is installed for it, the pass fails locally and render and apply are skipped."""
        pub = make_env()
        pub.write_all()
        await pub.run()
        config = pub.env.config_path.read_text(encoding="utf-8")
        pub.declare(TWO)  # beta has no source files

        result = await pub.run()

        [error] = pub.public_errors(result)
        assert error.startswith("public certificate 'beta':") and "cert_file" in error
        assert result.local_ok is False
        assert HELD_DOWN in result.actions
        assert "kept previous gateway config (local step failed)" in result.actions
        assert not pub.env.paths.public_cert_files("beta")[0].exists()
        assert pub.env.config_path.read_text(encoding="utf-8") == config
        assert pub.env.process.calls == ["start"]  # the running gateway is left alone
        assert _status(result, "beta").generation is None

    async def test_one_missing_install_among_several_holds_the_gateway_down(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write("alpha")  # beta has no files

        result = await pub.run()

        assert HELD_DOWN in result.actions
        # All-or-nothing: alpha's valid material is not installed either.
        assert not pub.env.paths.public_cert_files("alpha")[0].exists()
        assert pub.env.process.calls == []

    async def test_no_hold_down_once_everything_is_installed(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write_all()

        result = await pub.run()

        assert HELD_DOWN not in result.actions


class TestGarbageCollection:
    async def _two_then_one(self, pub: PublicEnv) -> Path:
        pub.write_all()
        await pub.run()
        beta_dir = pub.env.paths.public_tls_dir / "beta"
        assert beta_dir.is_dir()
        pub.declare({"alpha": [host("alpha")]})
        return beta_dir

    async def test_the_directory_of_a_no_longer_declared_certificate_is_removed(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        beta_dir = await self._two_then_one(pub)

        result = await pub.run()

        assert not beta_dir.exists()
        assert (pub.env.paths.public_tls_dir / "alpha").is_dir()
        assert "removed material of undeclared public certificate 'beta'" in result.actions
        assert result.housekeeping_errors == []
        assert [s.name for s in result.public_certs or []] == ["alpha"]

    async def test_a_directory_the_last_good_config_still_names_is_kept(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        beta_dir = await self._two_then_one(pub)
        cert_file = pub.env.paths.public_cert_files("beta")[0]
        last_good_path(pub.env.config_path).write_text(
            f"tls:\n  certificates:\n    files:\n      - certificateFile: {cert_file.as_posix()}\n",
            encoding="utf-8",
        )

        result = await pub.run()

        assert beta_dir.is_dir()
        assert not any("undeclared public certificate" in a for a in result.actions)
        assert result.housekeeping_errors == []

    async def test_an_unreadable_config_removes_nothing(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        beta_dir = await self._two_then_one(pub)
        last_good_path(pub.env.config_path).mkdir()  # reading a directory fails

        result = await pub.run()

        assert beta_dir.is_dir()
        assert not any("undeclared public certificate" in a for a in result.actions)
        assert any(
            e.startswith("public certificate directories kept: a gateway config could not")
            for e in result.housekeeping_errors
        )
        assert result.local_ok is True

    async def test_a_removal_failure_is_a_housekeeping_error_that_never_fails_the_pass(
        self, make_env: Callable[..., PublicEnv], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pub = make_env(TWO)
        beta_dir = await self._two_then_one(pub)

        def _boom(path: object, *args: object, **kwargs: object) -> None:
            raise PermissionError(f"secret detail about {path}")

        monkeypatch.setattr(core.shutil, "rmtree", _boom)

        result = await pub.run()

        assert beta_dir.is_dir()
        assert result.local_ok is True
        [error] = [e for e in result.housekeeping_errors if "undeclared" in e]
        assert error.endswith("failed (PermissionError)")
        assert "secret detail" not in error

    async def test_a_store_collection_failure_is_a_housekeeping_error(
        self, make_env: Callable[..., PublicEnv], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pub = make_env()
        pub.write_all()
        await pub.run()

        def _gc(name: str | None = None) -> list[str]:
            raise StoreError("cannot collect store garbage: disk detail")

        monkeypatch.setattr(pub.env.reconciler._public_store, "gc", _gc)

        result = await pub.run()

        assert result.local_ok is True
        assert result.housekeeping_errors == [
            "garbage collection of the public certificate store failed (StoreError)"
        ]

    async def test_the_store_collection_runs_off_the_event_loop_thread(
        self, make_env: Callable[..., PublicEnv], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It takes the store lock and does file I/O, so it must not block the loop (item 10)."""
        pub = make_env()
        pub.write_all()
        await pub.run()
        loop_thread = threading.get_ident()
        seen: list[int] = []

        def _gc(name: str | None = None) -> list[str]:
            seen.append(threading.get_ident())
            return []

        monkeypatch.setattr(pub.env.reconciler._public_store, "gc", _gc)

        result = await pub.run()

        assert result.housekeeping_ran is True
        assert len(seen) == 1
        assert seen[0] != loop_thread

    async def test_the_collection_helpers_are_coroutines(self) -> None:
        reconciler = core.Reconciler
        assert inspect.iscoroutinefunction(reconciler._collect_garbage)
        assert inspect.iscoroutinefunction(reconciler._collect_public_garbage)

    async def test_the_event_loop_keeps_running_while_the_store_collection_blocks(
        self, make_env: Callable[..., PublicEnv], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pub = make_env()
        pub.write_all()
        await pub.run()
        entered = threading.Event()
        release = threading.Event()

        def _slow_gc(name: str | None = None) -> list[str]:
            entered.set()
            assert release.wait(10), "the loop never got to run the ticker"
            return []

        monkeypatch.setattr(pub.env.reconciler._public_store, "gc", _slow_gc)

        async def _ticker() -> None:
            while not entered.is_set():
                await asyncio.sleep(0.005)
            await asyncio.sleep(0.01)  # the loop is alive while gc is blocked in its thread
            release.set()

        ticker = asyncio.create_task(_ticker())
        result = await asyncio.wait_for(pub.run(), timeout=30)
        await ticker

        assert result.local_ok is True
        assert result.housekeeping_errors == []

    async def test_declared_certificates_and_stray_files_are_never_removed(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write_all()
        await pub.run()
        stray = pub.env.paths.public_tls_dir / "README"
        stray.write_text("keep", encoding="utf-8")

        result = await pub.run()

        assert stray.read_text(encoding="utf-8") == "keep"
        for name in TWO:
            assert pub.env.paths.public_cert_files(name)[0].is_file()
        assert not any("undeclared" in a for a in result.actions)


def _issue_for(*dns: str) -> Issued:
    """A leaf valid now whose SANs are exactly `dns` (so it can carry more than it declares)."""
    now = datetime.now(UTC)
    return rsa_hierarchy().issue(list(dns), not_before=now - 10 * DAY, not_after=now + 80 * DAY)


class TestSanOverlap:
    """Overlap is judged on the leaf SANs: a served name matched by two certificates is refused."""

    @staticmethod
    def _overlap_errors(result: ReconcileResult) -> list[str]:
        return [e for e in result.errors if e.startswith("served name")]

    async def test_a_leaf_with_an_extra_san_that_another_certificate_covers_installs_nothing(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write("alpha")
        # beta declares only its own name but its leaf also carries alpha's.
        pub.write("beta", _issue_for(host("beta"), host("alpha")))

        result = await pub.run()

        [error] = self._overlap_errors(result)
        assert error == (
            f"served name {host('alpha')!r} is covered by certificate 'alpha' but the leaf of "
            "certificate 'beta' also matches it; each served name must match exactly one "
            "certificate"
        )
        assert result.local_ok is False
        assert not pub.env.paths.public_cert_files("alpha")[0].exists()  # nothing installed
        assert not pub.env.paths.public_cert_files("beta")[0].exists()
        assert not pub.env.config_path.exists()
        assert _status(result, "alpha").state == "invalid"
        assert _status(result, "beta").state == "invalid"
        assert _status(result, "beta").last_error == error

    async def test_an_extra_wildcard_san_is_matched_by_the_served_names_it_covers(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write("alpha")
        pub.write("beta", _issue_for(host("beta"), f"*.{ZONE}"))

        result = await pub.run()

        errors = self._overlap_errors(result)
        assert len(errors) == 1  # only alpha's name; beta's own is covered by beta alone
        assert f"served name {host('alpha')!r}" in errors[0]

    async def test_disjoint_leaves_are_installed_as_before(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write_all()

        result = await pub.run()

        assert self._overlap_errors(result) == []
        assert result.local_ok is True

    async def test_an_overlap_over_the_last_good_keeps_the_last_good_serving(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write_all()
        first = await pub.run()
        served = pub.served("beta")
        pub.write("beta", _issue_for(host("beta"), host("alpha")))

        result = await pub.run()

        assert len(self._overlap_errors(result)) == 1
        assert pub.served("beta") == served
        assert _status(result, "beta").generation == _status(first, "beta").generation

    async def test_a_certificate_that_failed_validation_is_not_also_reported_as_an_overlap(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write("alpha")
        pub.write("beta", _issue_for(host("beta"), host("alpha")))
        pub.source_root.joinpath("beta", "privkey.pem").write_bytes(key_pem_of(ec_key()))

        result = await pub.run()

        assert self._overlap_errors(result) == []  # beta's refusal is reported on its own


class TestReloadPending:
    """A previous generation that could not be removed is a local error."""

    async def test_a_pending_reload_is_a_local_error_with_no_hot_reload_claim(
        self, make_env: Callable[..., PublicEnv], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pub = make_env()
        pub.write_all()
        first = await pub.run()
        store = pub.env.reconciler._public_store
        real_install = store.install

        def _install(name: str, cert_pem: bytes, key_pem: bytes) -> object:
            return dataclasses.replace(real_install(name, cert_pem, key_pem), reload_pending=True)

        monkeypatch.setattr(store, "install", _install)
        renewed = pub.write("alpha")

        result = await pub.run()

        gen = generation_id(renewed.cert_pem, renewed.key_pem)
        assert pub.public_errors(result) == [
            "public certificate 'alpha': installed but previous generation not removed; "
            "gateway has not reloaded"
        ]
        assert result.local_ok is False
        assert (
            f"installed public certificate 'alpha' generation {gen} (previous generation not "
            "removed; gateway has not reloaded)"
        ) in result.actions
        assert not any("(gateway hot-reloads)" in a for a in result.actions)
        status = _status(result, "alpha")
        assert status.state == "invalid"
        assert status.generation == _status(first, "alpha").generation

    async def test_a_clean_install_still_claims_the_hot_reload(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env()
        pub.write_all()

        result = await pub.run()

        assert any(a.endswith("(gateway hot-reloads)") for a in result.actions)
        assert pub.public_errors(result) == []


class TestReadinessLogSeesPublicStates:
    """M3: the mid-pass readiness log is built after the certificate step sets its states."""

    async def test_the_readiness_log_carries_public_cert_invalid(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
    ) -> None:
        pub = PublicEnv(tmp_path, gateway_binary(), {"alpha": [host("alpha")]})
        pub.write_all()
        pub.source_root.joinpath("alpha", "privkey.pem").write_bytes(key_pem_of(ec_key()))
        pub.env.reconciler._tg = TGClient(network="acme", api_key="test-key")
        pub.env.registry.record("ca", "ssh", "ca-s-known")
        tg_server.add_web_app("app", host("alpha"), "g-1")

        with structlog.testing.capture_logs() as logs:
            result = await pub.run()

        assert _status(result, "alpha").state == "invalid"
        [event] = [e for e in logs if e["event"] == "reconcile.webapp_readiness"]
        [app] = event["apps"]
        assert "public_cert_invalid:alpha" in app["reasons"]
        assert app["state"] == "action_required"
        # Public mode has no leaf, so the pass must not log it as unreadable.
        assert not [e for e in logs if e["event"] == "certs.leaf_sans_unreadable"]


class TestFileOnlySeedHasNoAcmeState:
    """A seed with no ``source: acme`` certificate keeps the full hold-down and no ACME output."""

    async def test_a_missing_file_certificate_is_held_down_with_nothing_pending(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write("alpha")  # beta has nothing installed

        result = await pub.run()

        assert HELD_DOWN in result.actions
        assert "pending ACME issuance" not in " ".join(result.actions)
        assert result.acme_pending == []
        assert result.acme_errors == []
        assert result.acme_hold is False  # startup must not wait for ACME on a file hold-down
        assert pub.env.process.calls == []

    async def test_installed_file_certificates_report_no_acme_state(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        pub = make_env(TWO)
        pub.write_all()

        result = await pub.run()

        assert result.acme_pending == []
        assert result.acme_errors == []
        assert result.acme_hold is False
        assert {s.source for s in result.public_certs or []} == {"file"}
        assert pub.env.process.calls == ["start"]

    async def test_a_file_only_seed_never_reports_a_missing_runner(
        self, make_env: Callable[..., PublicEnv]
    ) -> None:
        """No ``source: acme`` certificate, no runner: nothing to be unavailable for."""
        pub = make_env(TWO)
        pub.write_all()

        with structlog.testing.capture_logs() as logs:
            result = await pub.run()

        assert result.acme_errors == []
        assert not [e for e in logs if e["event"] == "reconcile.acme_runner_unavailable"]
