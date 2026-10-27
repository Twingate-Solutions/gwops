"""The reconciler's ACME integration.

A ``source: acme`` certificate is issued by the runner outside the pass. The pass judges it by
what the store holds under ``/data/public-tls/<name>/``: nothing valid there means ``pending``
(skipped from the render, never an error), and the gateway is held down only while no
certificate at all can render. ``source: file`` keeps the full hold-down. ACME problems
go to ``ReconcileResult.acme_errors`` and never touch ``errors`` or ``local_ok``.

Most tests drive the pass with a recording stand-in for the runner and land material by
installing into the store directly. One POSIX-only test runs the real ``AcmeRunner`` against
the fake lego.
"""

import asyncio
import dataclasses
import shutil
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import structlog.testing
import yaml

from gwops.acme.runner import AcmeCertState, AcmeConfig, AcmeRunner, AcmeSnapshot, CertSnapshot
from gwops.acme.state import AcmeErrorClass
from gwops.configmodel.schema import AcmePublicCertificate
from gwops.reconciler import core
from gwops.reconciler.core import AcmeError, Reconciler, ReconcileResult
from gwops.renderer.capabilities import Capabilities
from tests.public_chain_support import Issued, ec_key, other_hierarchy, rsa_hierarchy
from tests.public_tls_support import ZONE, public_cert, public_seed, ssh, tls_block
from tests.store_support import generation_id

from .public_certs_support import DAY, ROOT, host
from .test_core import Env

HELD_DOWN = core._PUBLIC_HELD_DOWN
NONE_RENDERABLE = core._PUBLIC_NONE_RENDERABLE
NONE_RENDERABLE_STAGING = core._PUBLIC_NONE_RENDERABLE_STAGING
# Production unless a test is about staging: only production installs and serves.
ACME_BLOCK = {"email": "ops@example.com", "accept_tos": True, "directory": "production"}
STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"


# --- fixtures ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _pin_root_and_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate against the generated root; treat the DNS token file as present."""
    monkeypatch.setattr(core, "resolve_registered_root", lambda name: ROOT)
    monkeypatch.setattr(core, "token_file_problem", lambda settings: None)


class FakeRunner:
    """Records what the pass hands the runner; ``snapshot`` returns what the test sets."""

    def __init__(self) -> None:
        self.configured: list[AcmeConfig | None] = []
        self.wakes = 0
        self.snapshot_value = AcmeSnapshot(
            configured=True,
            directory=None,
            staging=True,
            running=None,
            state_error=None,
            certificates=(),
        )
        self.raise_on_snapshot: Exception | None = None
        self.marked: list[str] = []
        self.raise_on_mark: Exception | None = None

    def configure(self, config: AcmeConfig | None) -> None:
        self.configured.append(config)

    def wake(self) -> None:
        self.wakes += 1

    def mark_store_invalid(self, name: str) -> None:
        if self.raise_on_mark is not None:
            raise self.raise_on_mark
        self.marked.append(name)

    def snapshot(self) -> AcmeSnapshot:
        if self.raise_on_snapshot is not None:
            raise self.raise_on_snapshot
        return self.snapshot_value

    def fail(
        self, name: str, code: AcmeErrorClass, excerpt: str = "lego said no"
    ) -> None:
        self.snapshot_value = dataclasses_replace_snapshot(
            self.snapshot_value, (cert_snapshot(name, code, excerpt),)
        )


def dataclasses_replace_snapshot(
    snapshot: AcmeSnapshot, certificates: tuple[CertSnapshot, ...]
) -> AcmeSnapshot:
    return snapshot.model_copy(update={"certificates": certificates})


def cert_snapshot(
    name: str, code: AcmeErrorClass | None = None, excerpt: str | None = None
) -> CertSnapshot:
    return CertSnapshot(
        name=name,
        names=(host(name),),
        directory="https://acme-staging-v02.api.letsencrypt.org/directory",
        staging=True,
        state=AcmeCertState.BACKOFF if code is not None else AcmeCertState.IDLE,
        installed=False,
        installed_at=None,
        installed_serial=None,
        last_attempt_at=None,
        last_success_at=None,
        next_attempt_at=None,
        error_code=code,
        error_excerpt=excerpt,
        renewal_reason=None,
        consecutive_failures=1 if code is not None else 0,
        in_backoff=code is not None,
        retry_after=None,
    )


def leaf_for(
    names: list[str] | None = None, *, remaining_days: int = 80, new_key: bool = False
) -> Issued:
    """A leaf valid now (the reconciler validates at the real clock); a distinct serial per call."""
    now = datetime.now(UTC)
    return rsa_hierarchy().issue(
        names if names is not None else [f"*.{ZONE}"],
        key=ec_key() if new_key else None,
        not_before=now - (90 - remaining_days) * DAY,
        not_after=now + remaining_days * DAY,
    )


def acme_entry(name: str, names: list[str] | None = None) -> dict[str, Any]:
    return {"name": name, "names": names if names is not None else [host(name)], "source": "acme"}


class AcmeEnv:
    """A public-mode reconciler over tmp dirs wired to a runner and a shared public store.

    ``acme`` and ``files`` map a certificate name to its names; the seed declares one SSH
    upstream per served name so the gateway has something to render.
    """

    def __init__(
        self,
        tmp_path: Path,
        binary: Path,
        *,
        acme: dict[str, list[str]] | None = None,
        files: dict[str, list[str]] | None = None,
        runner: Any = None,
        acme_unavailable: str | None = None,
    ) -> None:
        self.source_root = tmp_path / "public-tls-src"
        self.acme = acme if acme is not None else {"alpha": [host("alpha")]}
        self.files = files if files is not None else {}
        self.runner = runner
        self.env = Env(tmp_path, self.seed_text(), binary, Capabilities(), None)
        self.paths = dataclasses.replace(self.env.paths, public_tls_root=self.source_root)
        self.env.paths = self.paths
        self.store = core.MaterialStore(self.paths.public_tls_dir)
        self.reconciler = Reconciler(
            settings=self.env.settings,
            store=self.env.store,
            tg=None,
            certs=self.env.certs,
            process=self.env.process,  # type: ignore[arg-type]
            registry=self.env.registry,
            caps=Capabilities(),
            validate_timeout_seconds=0.2,
            paths=self.paths,
            acme=runner,
            public_store=self.store,
            acme_unavailable=acme_unavailable,
        )
        self.process = self.env.process
        self.config_path = self.env.config_path

    def seed_dict(self) -> dict[str, Any]:
        entries: list[dict[str, Any]] = [
            public_cert(
                name,
                names,
                cert_file=str(self.source_root / name / "fullchain.pem"),
                key_file=str(self.source_root / name / "privkey.pem"),
            )
            for name, names in self.files.items()
        ] + [acme_entry(name, names) for name, names in self.acme.items()]
        served = sorted({n for names in (*self.acme.values(), *self.files.values()) for n in names})
        hosts = [f"web{n[1:]}" if n.startswith("*.") else n for n in served]
        block = tls_block(certificates=entries)
        if self.acme:
            block["acme"] = dict(ACME_BLOCK)
        upstreams = [ssh(f"h{i}", f"{h}:22") for i, h in enumerate(hosts)]
        return public_seed(block, ssh_upstreams=upstreams)

    def seed_text(self) -> str:
        return yaml.safe_dump(self.seed_dict(), sort_keys=False)

    def rewrite_seed(self, mutate: Callable[[dict[str, Any]], None] | None = None) -> None:
        seed = self.seed_dict()
        if mutate is not None:
            mutate(seed)
        self.env.seed_path.write_text(yaml.safe_dump(seed, sort_keys=False), encoding="utf-8")

    def land(self, name: str, issued: Issued | None = None) -> Issued:
        """Install material for an ACME certificate, as the runner does after validating it."""
        issued = issued if issued is not None else leaf_for(self.acme[name])
        self.store.install(name, issued.cert_pem, issued.key_pem)
        return issued

    def write_file_cert(self, name: str, issued: Issued | None = None) -> Issued:
        issued = issued if issued is not None else leaf_for(self.files[name])
        directory = self.source_root / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "fullchain.pem").write_bytes(issued.cert_pem)
        (directory / "privkey.pem").write_bytes(issued.key_pem)
        return issued

    async def run(self, trigger: str = "test") -> ReconcileResult:
        return await self.reconciler.reconcile(trigger)

    def rendered_files(self) -> list[str]:
        doc = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        return [f["certificateFile"] for f in doc["tls"]["certificates"]["files"]]

    def stable_cert(self, name: str) -> str:
        return self.paths.public_cert_files(name)[0].as_posix()


@pytest.fixture
def make_env(
    tmp_path: Path, gateway_binary: Callable[..., Path]
) -> Callable[..., AcmeEnv]:
    def _make(**kwargs: Any) -> AcmeEnv:
        kwargs.setdefault("runner", FakeRunner())
        return AcmeEnv(tmp_path, gateway_binary(), **kwargs)

    return _make


def _status(result: ReconcileResult, name: str) -> core.PublicCertStatus:
    [found] = [s for s in result.public_certs or [] if s.name == name]
    return found


def _non_tg_errors(result: ReconcileResult) -> list[str]:
    return [e for e in result.errors if not e.startswith("TG sync")]


# --- startup with nothing issued ----------------------------------------------------------


class TestAcmeOnlySeedStartsPending:
    async def test_the_gateway_is_held_down_as_none_renderable_and_local_ok_stays_true(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()

        result = await acme.run("startup")

        assert result.local_ok is True
        assert _non_tg_errors(result) == []
        assert NONE_RENDERABLE in result.actions
        assert HELD_DOWN not in result.actions
        assert acme.process.calls == []
        assert not acme.config_path.exists()
        assert result.acme_pending == ["alpha"]
        assert result.acme_errors == []

    async def test_the_pending_status_names_the_source_and_has_no_generation(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()

        result = await acme.run()

        status = _status(result, "alpha")
        assert status.state == "pending"
        assert status.source == "acme"
        assert status.generation is None
        assert status.not_after is None
        assert status.last_error is None  # not issued yet is not an error

    async def test_tg_sync_is_not_gated_by_the_pending_certificate(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()

        result = await acme.run()

        assert result.tg_attempted is True

    async def test_a_landed_certificate_is_rendered_and_the_gateway_started_next_pass(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()
        await acme.run("startup")
        issued = acme.land("alpha")

        result = await acme.run("api")

        assert result.local_ok is True
        assert _non_tg_errors(result) == []
        assert result.acme_pending == []
        assert acme.process.calls == ["start"]
        assert acme.rendered_files() == [acme.stable_cert("alpha")]
        status = _status(result, "alpha")
        assert status.state == "ok"
        assert status.source == "acme"
        if sys.platform != "win32":  # the plain-file stand-in has no generations
            assert status.generation == generation_id(issued.cert_pem, issued.key_pem)
        assert status.not_after == issued.cert.not_valid_after_utc

    async def test_an_acme_certificate_landing_beside_a_running_one_drain_restarts(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(acme={"beta": [host("beta")]}, files={"alpha": [host("alpha")]})
        acme.write_file_cert("alpha")
        first = await acme.run("startup")
        assert acme.rendered_files() == [acme.paths.public_cert_files("alpha")[0].as_posix()]
        assert acme.process.calls == ["start"]
        assert first.acme_pending == ["beta"]

        acme.land("beta")
        result = await acme.run("api")

        assert acme.process.calls == ["start", "drain_restart"]
        assert acme.rendered_files() == [
            acme.stable_cert("alpha"),
            acme.stable_cert("beta"),
        ]
        assert result.acme_pending == []

    async def test_the_real_clock_is_used_for_the_installed_material_check(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()
        now = datetime.now(UTC)
        expired = rsa_hierarchy().issue(
            [host("alpha")], not_before=now - 100 * DAY, not_after=now - 10 * DAY
        )
        acme.land("alpha", expired)

        result = await acme.run()

        assert result.acme_pending == ["alpha"]
        assert [e.code for e in result.acme_errors] == ["invalid_output"]
        assert result.local_ok is True


# --- mixed and file seeds ---------------------------------------------------------------


class TestMixedFileAndAcme:
    async def test_the_file_certificate_renders_while_the_acme_one_is_pending(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(acme={"beta": [host("beta")]}, files={"alpha": [host("alpha")]})
        acme.write_file_cert("alpha")

        result = await acme.run("startup")

        assert result.local_ok is True
        assert _non_tg_errors(result) == []
        assert HELD_DOWN not in result.actions
        assert NONE_RENDERABLE not in result.actions
        assert acme.process.calls == ["start"]
        assert acme.rendered_files() == [acme.paths.public_cert_files("alpha")[0].as_posix()]
        assert result.acme_pending == ["beta"]
        assert _status(result, "alpha").state == "ok"
        assert _status(result, "alpha").source == "file"
        assert _status(result, "beta").state == "pending"
        assert [s.name for s in result.public_certs or []] == ["alpha", "beta"]

    async def test_a_missing_file_certificate_keeps_the_full_hold_down(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(acme={"beta": [host("beta")]}, files={"alpha": [host("alpha")]})
        acme.land("beta")  # the ACME side is renderable; the file side has nothing

        result = await acme.run("startup")

        assert HELD_DOWN in result.actions
        assert NONE_RENDERABLE not in result.actions
        assert acme.process.calls == []
        assert result.local_ok is False
        assert any(e.startswith("public certificate 'alpha'") for e in result.errors)

    async def test_a_file_only_installed_certificate_is_not_held_by_a_pending_acme_one(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(acme={"beta": [host("beta")]}, files={"alpha": [host("alpha")]})
        acme.write_file_cert("alpha")
        await acme.run("startup")

        result = await acme.run("tick")

        assert acme.process.calls == ["start"]  # nothing to restart
        assert HELD_DOWN not in result.actions


# --- refused installed material -----------------------------------------------------------


class TestRefusedInstalledMaterial:
    def _land_refused(self, acme: AcmeEnv, name: str = "alpha") -> Issued:
        """Material the validator refuses: a leaf chained to another hierarchy."""
        now = datetime.now(UTC)
        bad = other_hierarchy().issue(
            [host(name)], not_before=now - 10 * DAY, not_after=now + 80 * DAY
        )
        return acme.land(name, bad)

    async def test_it_is_invalid_not_rendered_with_an_invalid_output_error_and_local_ok_holds(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()
        self._land_refused(acme)

        result = await acme.run("startup")

        assert result.local_ok is True
        assert _non_tg_errors(result) == []
        assert result.acme_pending == ["alpha"]
        [error] = result.acme_errors
        assert error.certificate == "alpha"
        assert error.code == "invalid_output"
        assert "alpha" in error.detail
        assert acme.process.calls == []
        status = _status(result, "alpha")
        assert status.state == "invalid"  # readiness: public_cert_invalid, not pending
        assert status.last_error == error.detail
        assert status.generation is None
        assert status.not_after is None
        assert status.source == "acme"

    async def test_it_is_skipped_from_the_render_beside_a_valid_file_certificate(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(acme={"beta": [host("beta")]}, files={"alpha": [host("alpha")]})
        acme.write_file_cert("alpha")
        self._land_refused(acme, "beta")

        result = await acme.run("startup")

        assert acme.process.calls == ["start"]
        assert acme.rendered_files() == [acme.paths.public_cert_files("alpha")[0].as_posix()]
        assert result.local_ok is True
        assert [e.certificate for e in result.acme_errors] == ["beta"]

    async def test_the_error_is_logged_once_and_reported_on_every_pass(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()
        self._land_refused(acme)

        with structlog.testing.capture_logs() as logs:
            first = await acme.run("startup")
            second = await acme.run("tick")

        refused = [e for e in logs if e["event"] == "reconcile.acme_installed_material_refused"]
        assert len(refused) == 1
        assert refused[0]["log_level"] == "error"
        assert refused[0]["certificate"] == "alpha"
        assert [e.code for e in first.acme_errors] == ["invalid_output"]
        assert [e.code for e in second.acme_errors] == ["invalid_output"]

    async def test_a_valid_replacement_clears_the_pending_state_and_the_error(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()
        self._land_refused(acme)
        await acme.run("startup")
        acme.land("alpha")

        result = await acme.run("api")

        assert result.acme_pending == []
        assert result.acme_errors == []
        assert acme.process.calls == ["start"]

    async def test_the_detail_carries_no_key_or_certificate_contents(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()
        bad = self._land_refused(acme)

        result = await acme.run()

        [error] = result.acme_errors
        assert "BEGIN" not in error.detail and "PRIVATE KEY" not in error.detail
        assert bad.key_pem.decode().splitlines()[1] not in error.detail


# --- renewal at stable paths --------------------------------------------------------------


class TestRenewal:
    async def test_a_renewal_changes_the_served_generation_but_not_the_config_or_the_gateway(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()
        first_issue = acme.land("alpha")
        first = await acme.run("startup")
        config_before = acme.config_path.read_text(encoding="utf-8")
        generation_before = _status(first, "alpha").generation

        renewed = leaf_for(acme.acme["alpha"], new_key=True)
        acme.land("alpha", renewed)
        second = await acme.run("api")

        assert acme.config_path.read_text(encoding="utf-8") == config_before
        assert acme.process.calls == ["start"]  # no reload, no restart from gwops
        assert second.local_ok is True
        assert _non_tg_errors(second) == []
        assert not any("restart" in a or "applied" in a for a in second.actions)
        status = _status(second, "alpha")
        assert status.state == "ok"
        assert status.not_after == renewed.cert.not_valid_after_utc
        assert renewed.cert_pem != first_issue.cert_pem
        if sys.platform != "win32":  # the plain-file stand-in has no generations
            assert status.generation == generation_id(renewed.cert_pem, renewed.key_pem)
            assert status.generation != generation_before

    async def test_a_certificate_that_vanishes_from_the_store_is_pending_again(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(acme={"beta": [host("beta")]}, files={"alpha": [host("alpha")]})
        acme.write_file_cert("alpha")
        acme.land("beta")
        first = await acme.run("startup")
        assert first.acme_pending == []
        # The runner and the pass judge the generation behind the store's ``..data`` link, so a
        # vanished certificate means the whole directory (not just the stable links) is gone.
        shutil.rmtree(acme.paths.public_tls_dir / "beta")

        second = await acme.run("tick")

        assert second.acme_pending == ["beta"]
        assert second.local_ok is True
        assert acme.rendered_files() == [acme.stable_cert("alpha")]
        assert acme.process.calls == ["start", "drain_restart"]


# --- what the pass hands the runner -------------------------------------------------------


class TestRunnerWiring:
    async def test_the_first_pass_configures_the_runner_with_the_seeds_acme_configuration(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner, acme={"alpha": [host("alpha")], "beta": [host("beta")]})

        await acme.run("startup")

        [config] = runner.configured
        assert config is not None
        assert config.settings.email == "ops@example.com"
        assert [c.name for c in config.certificates] == ["alpha", "beta"]
        assert all(isinstance(c, AcmePublicCertificate) for c in config.certificates)
        assert config.zones == (ZONE,)
        assert config.root is ROOT

    async def test_an_unchanged_configuration_is_not_handed_over_again(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)
        await acme.run("startup")

        await acme.run("tick")
        await acme.run("tick")

        assert len(runner.configured) == 1

    async def test_an_unchanged_pending_set_does_not_wake_the_runner(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)
        await acme.run("startup")

        await acme.run("tick")
        await acme.run("tick")

        assert runner.wakes == 0

    async def test_a_changed_pending_set_wakes_the_runner_once(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)
        await acme.run("startup")
        acme.land("alpha")

        await acme.run("api")
        await acme.run("tick")

        assert runner.wakes == 1
        assert len(runner.configured) == 1

    async def test_a_certificate_vanishing_wakes_the_runner_without_reconfiguring(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        acme = make_env(
            runner=runner, acme={"beta": [host("beta")]}, files={"alpha": [host("alpha")]}
        )
        acme.write_file_cert("alpha")
        acme.land("beta")
        await acme.run("startup")
        # The runner and the pass judge the generation behind the store's ``..data`` link, so a
        # vanished certificate means the whole directory (not just the stable links) is gone.
        shutil.rmtree(acme.paths.public_tls_dir / "beta")

        await acme.run("tick")

        assert runner.wakes == 1
        assert len(runner.configured) == 1

    async def test_a_changed_acme_block_configures_the_runner_again(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)
        await acme.run("startup")

        acme.rewrite_seed(lambda seed: seed["public_tls"]["acme"].update(email="new@example.com"))
        await acme.run("tick")

        assert len(runner.configured) == 2
        assert runner.configured[1] is not None
        assert runner.configured[1].settings.email == "new@example.com"

    async def test_a_changed_certificate_set_configures_the_runner_again(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)
        await acme.run("startup")

        acme.acme = {"alpha": [host("alpha")], "beta": [host("beta")]}
        acme.rewrite_seed()
        await acme.run("tick")

        assert len(runner.configured) == 2
        assert runner.configured[1] is not None
        assert [c.name for c in runner.configured[1].certificates] == ["alpha", "beta"]

    async def test_a_seed_that_drops_every_acme_certificate_configures_the_runner_with_none(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        acme = make_env(
            runner=runner, acme={"alpha": [host("alpha")]}, files={"beta": [host("beta")]}
        )
        acme.write_file_cert("beta")
        await acme.run("startup")

        acme.acme = {}
        acme.rewrite_seed()
        result = await acme.run("tick")

        assert runner.configured[-1] is None
        assert result.acme_pending == []

    async def test_a_runner_state_error_is_an_internal_acme_error_and_never_fails_the_pass(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        runner.snapshot_value = runner.snapshot_value.model_copy(
            update={"state_error": "state.json is not valid JSON"}
        )
        acme = make_env(runner=runner)

        result = await acme.run("startup")

        assert AcmeError(None, "internal", "state.json is not valid JSON") in result.acme_errors
        assert result.local_ok is True
        assert _non_tg_errors(result) == []

    async def test_a_recorded_runner_failure_is_reported_per_certificate(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        runner.fail("alpha", AcmeErrorClass.RATE_LIMITED, "too many certificates")
        acme = make_env(runner=runner)

        result = await acme.run("startup")

        assert result.acme_errors == [AcmeError("alpha", "rate_limited", "too many certificates")]
        assert result.local_ok is True
        assert _non_tg_errors(result) == []
        assert result.acme_pending == ["alpha"]

    async def test_a_runner_that_raises_never_fails_the_pass(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        runner.raise_on_snapshot = RuntimeError("boom")
        acme = make_env(runner=runner)
        acme.land("alpha")

        result = await acme.run("startup")

        assert [(e.certificate, e.code) for e in result.acme_errors] == [(None, "internal")]
        assert "boom" not in result.acme_errors[0].detail  # the class name only
        assert result.local_ok is True
        assert acme.process.calls == ["start"]

    async def test_a_pass_without_a_runner_still_judges_the_store(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(runner=None)

        result = await acme.run("startup")

        assert result.acme_pending == ["alpha"]
        assert result.local_ok is True
        assert NONE_RENDERABLE in result.actions


# --- the DNS token file -------------------------------------------------------------------


class TestTokenFile:
    @pytest.fixture
    def token_problem(self, monkeypatch: pytest.MonkeyPatch) -> str:
        problem = "ACME DNS token file /config/acme/cloudflare-token does not exist"
        monkeypatch.setattr(core, "token_file_problem", lambda settings: problem)
        return problem

    async def test_an_unusable_token_file_is_a_config_error_and_never_fails_the_pass(
        self, make_env: Callable[..., AcmeEnv], token_problem: str
    ) -> None:
        acme = make_env()
        acme.land("alpha")

        result = await acme.run("startup")

        assert AcmeError(None, "config", token_problem) in result.acme_errors
        assert result.local_ok is True
        assert _non_tg_errors(result) == []
        assert acme.process.calls == ["start"]  # material already installed still serves

    async def test_the_runner_is_not_handed_a_configuration_while_the_token_is_unusable(
        self, make_env: Callable[..., AcmeEnv], token_problem: str
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)

        result = await acme.run("startup")

        assert [c for c in runner.configured if c is not None] == []
        assert [e.code for e in result.acme_errors if e.certificate is None] == ["config"]
        assert result.local_ok is True
        assert result.acme_pending == ["alpha"]

    async def test_the_problem_is_logged_once_and_reported_every_pass(
        self, make_env: Callable[..., AcmeEnv], token_problem: str
    ) -> None:
        acme = make_env()

        with structlog.testing.capture_logs() as logs:
            first = await acme.run("startup")
            second = await acme.run("tick")

        unusable = [e for e in logs if e["event"] == "reconcile.acme_token_file_unusable"]
        assert len(unusable) == 1
        assert unusable[0]["problem"] == token_problem
        assert any(e.code == "config" for e in first.acme_errors)
        assert any(e.code == "config" for e in second.acme_errors)

    async def test_a_usable_token_file_reports_no_config_error(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()

        result = await acme.run("startup")

        assert [e for e in result.acme_errors if e.code == "config"] == []


# --- SAN overlap --------------------------------------------------------------------------


class TestSanOverlap:
    async def test_old_acme_material_with_extra_sans_never_fails_local_ok_and_is_not_an_overlap(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        """Leaf SANs that differ from the declared names are an ACME problem
        (awaiting reissue), never a local error that holds back a valid file certificate."""
        acme = make_env(acme={"alpha": [host("alpha")]}, files={"beta": [host("beta")]})
        acme.write_file_cert("beta")
        acme.land("alpha", leaf_for([host("alpha"), host("beta")]))

        result = await acme.run("startup")

        assert result.local_ok is True
        assert _non_tg_errors(result) == []
        assert not any("also matches it" in e for e in result.errors)
        assert result.acme_pending == ["alpha"]
        assert acme.process.calls == ["start"]  # beta's file certificate is served meanwhile
        assert acme.rendered_files() == [acme.paths.public_cert_files("beta")[0].as_posix()]
        status = _status(result, "alpha")
        assert status.state == "pending"
        assert status.last_error == "awaiting reissue for changed names"
        assert _status(result, "beta").state == "ok"

    async def test_a_file_leaf_with_extra_sans_over_an_acme_name_is_still_an_overlap(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        """The overlap check still runs on matching ACME material: the other leaf is at fault."""
        acme = make_env(acme={"alpha": [host("alpha")]}, files={"beta": [host("beta")]})
        acme.write_file_cert("beta", leaf_for([host("beta"), host("alpha")]))
        acme.land("alpha")

        result = await acme.run("startup")

        assert result.local_ok is False
        assert any(
            f"served name '{host('alpha')}' is covered by certificate 'alpha' but the leaf of "
            "certificate 'beta' also matches it" in e
            for e in result.errors
        )
        assert acme.process.calls == []

    async def test_acme_material_for_its_own_names_only_is_not_an_overlap(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(acme={"alpha": [host("alpha")]}, files={"beta": [host("beta")]})
        acme.write_file_cert("beta")
        acme.land("alpha")

        result = await acme.run("startup")

        assert result.local_ok is True
        assert not any("also matches it" in e for e in result.errors)
        assert acme.process.calls == ["start"]


# --- staging hold, acme_hold, unavailable runner, config problems ---------------------------


def _use_directory(acme: AcmeEnv, directory: str) -> None:
    acme.rewrite_seed(lambda seed: seed["public_tls"]["acme"].update(directory=directory))


class TestStagingHold:
    """A staging directory is a dry run: nothing is ever installed, so the hold says so."""

    async def test_a_staging_seed_holds_with_the_staging_text_and_the_hint(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()
        _use_directory(acme, "staging")

        result = await acme.run("startup")

        assert NONE_RENDERABLE_STAGING in result.actions
        assert NONE_RENDERABLE not in result.actions
        assert "set public_tls.acme.directory: production to serve" in NONE_RENDERABLE_STAGING
        assert "staging" in NONE_RENDERABLE_STAGING and "dry run" in NONE_RENDERABLE_STAGING
        assert result.acme_hold is True
        assert result.local_ok is True
        assert acme.process.calls == []

    async def test_a_production_seed_holds_with_the_plain_text(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()

        result = await acme.run("startup")

        assert NONE_RENDERABLE in result.actions
        assert NONE_RENDERABLE_STAGING not in result.actions
        assert "staging" not in NONE_RENDERABLE
        assert result.acme_hold is True

    async def test_the_staging_url_spelled_out_is_still_staging(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()
        _use_directory(acme, STAGING_URL)

        result = await acme.run("startup")

        assert NONE_RENDERABLE_STAGING in result.actions

    async def test_the_production_url_spelled_out_is_not_staging(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()
        _use_directory(acme, "https://acme-v02.api.letsencrypt.org/directory")

        result = await acme.run("startup")

        assert NONE_RENDERABLE in result.actions

    async def test_material_installed_earlier_still_serves_under_a_staging_seed(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        """Staging never installs and never removes: a production-era certificate keeps serving."""
        acme = make_env()
        _use_directory(acme, "staging")
        acme.land("alpha")

        result = await acme.run("startup")

        assert result.acme_hold is False
        assert NONE_RENDERABLE_STAGING not in result.actions
        assert acme.process.calls == ["start"]

    async def test_a_renderable_certificate_beside_a_pending_one_is_not_held_under_staging(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(acme={"beta": [host("beta")]}, files={"alpha": [host("alpha")]})
        _use_directory(acme, "staging")
        acme.write_file_cert("alpha")

        result = await acme.run("startup")

        assert result.acme_hold is False
        assert acme.process.calls == ["start"]
        assert not any("pending ACME issuance" in a for a in result.actions)


class TestAcmeHold:
    """``ReconcileResult.acme_hold``: only the none-renderable ACME hold sets it."""

    def test_it_defaults_to_false(self) -> None:
        result = ReconcileResult(ok=True, trigger="t", started_at=datetime.now(UTC))

        assert result.acme_hold is False

    async def test_it_is_false_once_a_certificate_renders(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()
        acme.land("alpha")

        result = await acme.run("startup")

        assert result.acme_hold is False
        assert acme.process.calls == ["start"]

    async def test_it_is_false_for_the_file_certificate_full_hold_down(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(acme={"beta": [host("beta")]}, files={"alpha": [host("alpha")]})
        acme.land("beta")  # the file side has nothing installed

        result = await acme.run("startup")

        assert HELD_DOWN in result.actions
        assert result.acme_hold is False

    async def test_it_is_false_when_there_are_no_upstreams_to_serve(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()
        acme.land("alpha")
        acme.rewrite_seed(lambda seed: seed.pop("ssh_upstreams"))

        result = await acme.run("startup")

        assert result.acme_hold is False
        assert any("no upstreams configured" in a for a in result.actions)

    async def test_it_stays_true_beside_a_local_failure_so_startup_can_tell_them_apart(
        self, make_env: Callable[..., AcmeEnv], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The supervisor waits for ACME only when ``acme_hold and local_ok``."""
        acme = make_env()

        def _broken(*args: object, **kwargs: object) -> None:
            raise OSError("the SSH CA key is unreadable")

        monkeypatch.setattr(acme.reconciler._certs, "ensure_ssh_ca", _broken)

        result = await acme.run("startup")

        assert result.local_ok is False
        assert result.acme_hold is True
        assert any("CA material is unusable" in e for e in result.errors)

    async def test_it_is_recomputed_every_pass(self, make_env: Callable[..., AcmeEnv]) -> None:
        acme = make_env()
        first = await acme.run("startup")
        acme.land("alpha")
        second = await acme.run("api")

        assert (first.acme_hold, second.acme_hold) == (True, False)


class TestRunnerUnavailable:
    """Constructing the runner failed (or it never started): declared ACME certificates say so."""

    REASON = "OSError: cannot create /data/acme"
    DETAIL = f"ACME runner unavailable: {REASON}"

    async def test_the_pass_records_why_as_a_certificate_less_internal_error(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(runner=None, acme_unavailable=self.REASON)

        result = await acme.run("startup")

        assert result.acme_errors == [AcmeError(None, "internal", self.DETAIL)]
        assert result.local_ok is True
        assert _non_tg_errors(result) == []
        assert result.acme_pending == ["alpha"]

    async def test_a_runner_that_was_never_started_has_its_own_wording(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(runner=None)

        result = await acme.run("startup")

        assert result.acme_errors == [
            AcmeError(None, "internal", "ACME runner unavailable: it was not started")
        ]

    async def test_it_is_logged_once_at_error_level_and_reported_every_pass(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(runner=None, acme_unavailable=self.REASON)

        with structlog.testing.capture_logs() as logs:
            first = await acme.run("startup")
            second = await acme.run("tick")

        [logged] = [e for e in logs if e["event"] == "reconcile.acme_runner_unavailable"]
        assert logged["log_level"] == "error"
        assert logged["detail"] == self.DETAIL
        assert [e.code for e in first.acme_errors] == ["internal"]
        assert [e.code for e in second.acme_errors] == ["internal"]

    async def test_it_is_logged_again_after_the_certificates_were_dropped_and_redeclared(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(
            runner=None,
            acme_unavailable=self.REASON,
            acme={"alpha": [host("alpha")]},
            files={"beta": [host("beta")]},
        )
        acme.write_file_cert("beta")

        with structlog.testing.capture_logs() as logs:
            await acme.run("startup")
            acme.acme = {}
            acme.rewrite_seed()
            quiet = await acme.run("tick")
            acme.acme = {"alpha": [host("alpha")]}
            acme.rewrite_seed()
            await acme.run("tick")

        assert quiet.acme_errors == []
        assert len([e for e in logs if e["event"] == "reconcile.acme_runner_unavailable"]) == 2

    async def test_a_seed_without_acme_certificates_reports_nothing(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(
            runner=None,
            acme_unavailable=self.REASON,
            acme={},
            files={"alpha": [host("alpha")]},
        )
        acme.write_file_cert("alpha")

        with structlog.testing.capture_logs() as logs:
            result = await acme.run("startup")

        assert result.acme_errors == []
        assert not [e for e in logs if e["event"] == "reconcile.acme_runner_unavailable"]
        assert result.local_ok is True

    async def test_a_runner_that_exists_makes_the_unavailable_reason_irrelevant(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(runner=FakeRunner(), acme_unavailable="stale reason")

        result = await acme.run("startup")

        assert result.acme_errors == []

    async def test_material_already_installed_still_serves_without_a_runner(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(runner=None, acme_unavailable=self.REASON)
        acme.land("alpha")

        result = await acme.run("startup")

        assert acme.process.calls == ["start"]
        assert result.local_ok is True
        assert result.acme_pending == []
        assert result.acme_errors == [AcmeError(None, "internal", self.DETAIL)]

    async def test_the_detail_is_the_text_status_and_readiness_use(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        from gwops import webapp_readiness
        from gwops.configmodel.loader import load_effective_state

        acme = make_env(runner=None, acme_unavailable=self.REASON)
        result = await acme.run("startup")
        state, _provenance = load_effective_state(acme.env.seed_path, acme.env.store)

        public = webapp_readiness.public_input(state, result)

        assert public is not None
        assert public.acme_internal_error is True
        assert public.acme_config_error is False


class TestAcmeConfigurationProblem:
    """``AcmeConfig.from_public_tls`` raising ValueError: logged once, reported, runner idled."""

    PROBLEM = "production ACME needs the registered root to validate against"

    @staticmethod
    def _raise(problem: str) -> Any:
        def _from_public_tls(cls: type, public: object, root: object) -> None:
            raise ValueError(problem)

        return classmethod(_from_public_tls)

    async def test_it_is_a_config_error_and_the_runner_is_configured_with_none(
        self, make_env: Callable[..., AcmeEnv], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)
        monkeypatch.setattr(core.AcmeConfig, "from_public_tls", self._raise(self.PROBLEM))

        result = await acme.run("startup")

        assert AcmeError(None, "config", self.PROBLEM) in result.acme_errors
        assert runner.configured == [None]
        assert result.local_ok is True
        assert _non_tg_errors(result) == []
        assert result.acme_pending == ["alpha"]

    async def test_it_is_logged_once_with_its_traceback_and_reported_every_pass(
        self, make_env: Callable[..., AcmeEnv], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)
        monkeypatch.setattr(core.AcmeConfig, "from_public_tls", self._raise(self.PROBLEM))

        with structlog.testing.capture_logs() as logs:
            first = await acme.run("startup")
            second = await acme.run("tick")
            third = await acme.run("tick")

        [logged] = [e for e in logs if e["event"] == "reconcile.acme_config_invalid"]
        assert logged["log_level"] == "error"
        assert logged["error"] == self.PROBLEM
        assert logged["exc_info"] is True
        for result in (first, second, third):
            assert AcmeError(None, "config", self.PROBLEM) in result.acme_errors
        assert runner.configured == [None]  # not re-handed while nothing changed

    async def test_a_different_problem_is_logged_again(
        self, make_env: Callable[..., AcmeEnv], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        acme = make_env(runner=FakeRunner())

        with structlog.testing.capture_logs() as logs:
            monkeypatch.setattr(core.AcmeConfig, "from_public_tls", self._raise("problem one"))
            await acme.run("startup")
            await acme.run("tick")
            monkeypatch.setattr(core.AcmeConfig, "from_public_tls", self._raise("problem two"))
            await acme.run("tick")
            await acme.run("tick")

        logged = [e["error"] for e in logs if e["event"] == "reconcile.acme_config_invalid"]
        assert logged == ["problem one", "problem two"]

    async def test_the_runner_recovers_when_the_problem_goes_away(
        self, make_env: Callable[..., AcmeEnv], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)
        await acme.run("startup")
        with monkeypatch.context() as patched:
            patched.setattr(core.AcmeConfig, "from_public_tls", self._raise(self.PROBLEM))
            broken = await acme.run("tick")

        fixed = await acme.run("tick")

        assert runner.configured[1] is None
        assert runner.configured[2] == runner.configured[0] is not None
        assert len(runner.configured) == 3
        assert AcmeError(None, "config", self.PROBLEM) in broken.acme_errors
        assert [e for e in fixed.acme_errors if e.code == "config"] == []

    async def test_a_recovered_problem_that_returns_is_logged_again(
        self, make_env: Callable[..., AcmeEnv], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        acme = make_env(runner=FakeRunner())

        with structlog.testing.capture_logs() as logs:
            with monkeypatch.context() as patched:
                patched.setattr(core.AcmeConfig, "from_public_tls", self._raise(self.PROBLEM))
                await acme.run("startup")
            await acme.run("tick")  # fine again
            with monkeypatch.context() as patched:
                patched.setattr(core.AcmeConfig, "from_public_tls", self._raise(self.PROBLEM))
                await acme.run("tick")

        assert len([e for e in logs if e["event"] == "reconcile.acme_config_invalid"]) == 2

    async def test_the_readiness_input_sees_it_as_the_config_error(
        self, make_env: Callable[..., AcmeEnv], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from gwops import webapp_readiness
        from gwops.configmodel.loader import load_effective_state

        acme = make_env(runner=FakeRunner())
        monkeypatch.setattr(core.AcmeConfig, "from_public_tls", self._raise(self.PROBLEM))
        result = await acme.run("startup")
        state, _provenance = load_effective_state(acme.env.seed_path, acme.env.store)

        public = webapp_readiness.public_input(state, result)

        assert public is not None
        assert public.acme_config_error is True
        assert public.acme_internal_error is False


class TestStoreMarkedInvalid:
    """Refused, unreadable and SAN-mismatched installed material tells the runner every pass."""

    def _land_refused(self, acme: AcmeEnv, name: str = "alpha") -> Issued:
        now = datetime.now(UTC)
        bad = other_hierarchy().issue(
            [host(name)], not_before=now - 10 * DAY, not_after=now + 80 * DAY
        )
        return acme.land(name, bad)

    async def test_refused_material_marks_the_runner_on_every_pass(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)
        self._land_refused(acme)

        await acme.run("startup")
        await acme.run("tick")

        assert runner.marked == ["alpha", "alpha"]

    async def test_nothing_installed_marks_nothing(self, make_env: Callable[..., AcmeEnv]) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)

        await acme.run("startup")
        await acme.run("tick")

        assert runner.marked == []

    async def test_valid_material_marks_nothing(self, make_env: Callable[..., AcmeEnv]) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)
        acme.land("alpha")

        await acme.run("startup")

        assert runner.marked == []

    async def test_only_the_bad_certificate_is_marked(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner, acme={"alpha": [host("alpha")], "beta": [host("beta")]})
        acme.land("alpha")
        self._land_refused(acme, "beta")

        result = await acme.run("startup")

        assert runner.marked == ["beta"]
        assert result.acme_pending == ["beta"]

    async def test_a_replacement_stops_the_marking(self, make_env: Callable[..., AcmeEnv]) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)
        self._land_refused(acme)
        await acme.run("startup")
        acme.land("alpha")

        await acme.run("api")

        assert runner.marked == ["alpha"]  # only the first pass

    async def test_material_for_changed_names_marks_the_runner_every_pass(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)
        acme.land("alpha", leaf_for([host("alpha"), host("gamma")]))

        first = await acme.run("startup")
        await acme.run("tick")

        assert _status(first, "alpha").last_error == "awaiting reissue for changed names"
        assert runner.marked == ["alpha", "alpha"]

    async def test_unreadable_material_is_invalid_and_marks_the_runner(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)
        acme.land("alpha")

        def _denied(name: str) -> None:
            raise PermissionError(13, "Permission denied", "/data/public-tls/alpha")

        acme.store.read_current = _denied  # type: ignore[method-assign]

        result = await acme.run("startup")

        assert result.local_ok is True
        assert result.acme_pending == ["alpha"]
        [error] = result.acme_errors
        assert (error.certificate, error.code) == ("alpha", "invalid_output")
        assert "the store cannot be read (PermissionError)" in error.detail
        assert "/data/public-tls" not in error.detail
        status = _status(result, "alpha")
        assert (status.state, status.generation) == ("invalid", None)
        assert runner.marked == ["alpha"]

    async def test_an_unexpected_exception_is_internal_invalid_and_logged_with_its_traceback(
        self, make_env: Callable[..., AcmeEnv], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)
        acme.land("alpha")

        def _boom(*args: object, **kwargs: object) -> None:
            raise RuntimeError("secret-looking detail")

        monkeypatch.setattr(core, "read_installed_public_material", _boom)

        with structlog.testing.capture_logs() as logs:
            first = await acme.run("startup")
            second = await acme.run("tick")

        for result in (first, second):
            assert result.local_ok is True
            assert result.acme_pending == ["alpha"]
            [error] = result.acme_errors
            assert (error.certificate, error.code) == ("alpha", "internal")
            assert error.detail == (
                "public certificate 'alpha': unexpected RuntimeError while validating the "
                "installed material"
            )
            assert _status(result, "alpha").state == "invalid"
        [logged] = [e for e in logs if e["event"] == "reconcile.acme_installed_material_refused"]
        assert isinstance(logged["exc_info"], RuntimeError)
        assert "secret-looking" not in str([e.detail for e in first.acme_errors])
        assert runner.marked == ["alpha", "alpha"]

    async def test_a_refusal_has_no_traceback_in_its_log(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()
        self._land_refused(acme)

        with structlog.testing.capture_logs() as logs:
            await acme.run("startup")

        [logged] = [e for e in logs if e["event"] == "reconcile.acme_installed_material_refused"]
        assert logged["exc_info"] is None

    async def test_a_runner_that_cannot_be_marked_never_fails_the_pass(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        runner.raise_on_mark = RuntimeError("runner is broken")
        acme = make_env(runner=runner)
        self._land_refused(acme)

        with structlog.testing.capture_logs() as logs:
            result = await acme.run("startup")

        assert result.local_ok is True
        assert [e.code for e in result.acme_errors] == ["invalid_output"]
        [failed] = [e for e in logs if e["event"] == "reconcile.acme_mark_store_invalid_failed"]
        assert failed["log_level"] == "error"
        assert failed["certificate"] == "alpha"

    async def test_without_a_runner_a_refusal_is_still_judged_and_nothing_raises(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(runner=None)
        self._land_refused(acme)

        result = await acme.run("startup")

        assert result.local_ok is True
        assert result.acme_pending == ["alpha"]
        assert ("alpha", "invalid_output") in {(e.certificate, e.code) for e in result.acme_errors}

    async def test_the_real_runner_ends_up_with_the_mark(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        """The first pass reads the store before the runner is configured; the next one lands."""
        acme = make_env(runner=None)
        runner = AcmeRunner(acme.env.settings, store=acme.store)
        acme.reconciler._acme = runner
        self._land_refused(acme)

        await acme.run("startup")
        await acme.run("tick")

        assert "alpha" in runner._store_invalid  # type: ignore[attr-defined]


class TestChangedNames:
    """Installed material that validates but whose leaf SANs differ from the declared names.

    That is a leaf carrying names the seed no longer declares (the seed dropped a name): it
    awaits reissue. A declared name the leaf lacks is not this case: the validator refuses it
    first (``san_missing_name``), see ``test_a_newly_declared_name_the_leaf_lacks_is_refused``.
    """

    async def test_it_is_pending_with_the_reissue_note_and_never_an_error(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()
        acme.land("alpha", leaf_for([host("alpha"), host("gamma")]))

        with structlog.testing.capture_logs() as logs:
            result = await acme.run("startup")

        status = _status(result, "alpha")
        assert status.state == "pending"
        assert status.last_error == "awaiting reissue for changed names"
        assert status.generation is None
        assert status.not_after is None
        assert result.acme_pending == ["alpha"]
        assert result.acme_errors == []
        assert result.local_ok is True
        assert _non_tg_errors(result) == []
        assert NONE_RENDERABLE in result.actions
        assert acme.process.calls == []
        assert not [e for e in logs if e["event"] == "reconcile.acme_installed_material_refused"]

    async def test_a_leaf_with_a_wildcard_san_for_a_concrete_declared_name_is_the_same_case(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        """The SAN sets differ (``*.zone`` vs ``alpha.zone``) though the validator accepts it."""
        acme = make_env()
        acme.land("alpha", leaf_for([f"*.{ZONE}"]))

        result = await acme.run("startup")

        status = _status(result, "alpha")
        assert (status.state, status.last_error) == (
            "pending",
            "awaiting reissue for changed names",
        )
        assert result.acme_errors == []
        assert result.local_ok is True

    async def test_a_newly_declared_name_the_leaf_lacks_is_refused_not_a_reissue_note(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        acme = make_env(runner=runner)
        acme.land("alpha")
        acme.acme = {"alpha": [host("alpha"), host("gamma")]}
        acme.rewrite_seed()

        result = await acme.run("startup")

        status = _status(result, "alpha")
        assert status.state == "invalid"
        assert status.last_error is not None and "gamma" in status.last_error
        [error] = result.acme_errors
        assert (error.certificate, error.code) == ("alpha", "invalid_output")
        assert runner.marked == ["alpha"]
        assert result.local_ok is True

    async def test_the_old_material_is_not_rendered_beside_a_valid_certificate(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(acme={"beta": [host("beta")]}, files={"alpha": [host("alpha")]})
        acme.write_file_cert("alpha")
        acme.land("beta", leaf_for([host("beta"), host("gamma")]))

        result = await acme.run("startup")

        assert acme.rendered_files() == [acme.stable_cert("alpha")]
        assert result.acme_pending == ["beta"]
        assert result.local_ok is True

    async def test_a_reissue_for_the_declared_names_is_rendered_and_clears_the_note(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env()
        acme.land("alpha", leaf_for([host("alpha"), host("gamma")]))
        await acme.run("startup")

        acme.land("alpha", leaf_for([host("alpha")]))
        result = await acme.run("api")

        status = _status(result, "alpha")
        assert (status.state, status.last_error) == ("ok", None)
        assert result.acme_pending == []
        assert acme.process.calls == ["start"]

    async def test_the_san_order_does_not_matter(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        acme = make_env(acme={"alpha": [host("alpha"), host("gamma")]})
        acme.land("alpha", leaf_for([host("gamma"), host("alpha")]))

        result = await acme.run("startup")

        assert _status(result, "alpha").state == "ok"
        assert result.acme_pending == []


class TestRunnerTaskDead:
    async def test_a_dead_task_is_a_certificate_less_internal_error(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        runner.snapshot_value = runner.snapshot_value.model_copy(update={"task_dead": True})
        acme = make_env(runner=runner)

        result = await acme.run("startup")

        assert AcmeError(None, "internal", "the ACME runner task is not running") in (
            result.acme_errors
        )
        assert result.local_ok is True
        assert _non_tg_errors(result) == []

    async def test_a_dead_task_is_listed_after_the_per_certificate_failures(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        runner.fail("alpha", AcmeErrorClass.RATE_LIMITED, "too many certificates")
        runner.snapshot_value = runner.snapshot_value.model_copy(update={"task_dead": True})
        acme = make_env(runner=runner)

        result = await acme.run("startup")

        assert result.acme_errors == [
            AcmeError("alpha", "rate_limited", "too many certificates"),
            AcmeError(None, "internal", "the ACME runner task is not running"),
        ]

    async def test_a_live_task_reports_nothing(self, make_env: Callable[..., AcmeEnv]) -> None:
        acme = make_env()

        result = await acme.run("startup")

        assert result.acme_errors == []

    async def test_a_dead_task_never_stops_installed_material_from_serving(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        runner = FakeRunner()
        runner.snapshot_value = runner.snapshot_value.model_copy(update={"task_dead": True})
        acme = make_env(runner=runner)
        acme.land("alpha")

        result = await acme.run("startup")

        assert acme.process.calls == ["start"]
        assert result.local_ok is True


class TestReadinessLogWithAFailingSnapshot:
    async def test_the_readiness_log_degrades_to_one_internal_reason(
        self, make_env: Callable[..., AcmeEnv]
    ) -> None:
        from gwops.configmodel.loader import load_effective_state

        runner = FakeRunner()
        acme = make_env(runner=runner)
        acme.land("alpha")
        result = await acme.run("startup")
        runner.raise_on_snapshot = RuntimeError("secret-looking detail")
        result.remote_web_apps = [
            core.RemoteWebApp(
                id="r-1",
                name="alpha-app",
                gateway_id="g-1",
                address=host("alpha"),
                upstream_port=443,
                alias=None,
                upstream_tls="verify_full",
                downstream_tls="tls13",
                downstream_port=443,
                header_rewrite_names=(),
                managed=True,
            )
        ]
        state, _provenance = load_effective_state(acme.env.seed_path, acme.env.store)

        with structlog.testing.capture_logs() as logs:
            acme.reconciler._log_webapp_readiness(state, result, "g-1")

        [event] = [e for e in logs if e["event"] == "reconcile.webapp_readiness"]
        [app] = event["apps"]
        assert "acme_failed:internal" in app["reasons"]
        assert app["state"] == "action_required"
        assert not [e for e in logs if e["event"] == "reconcile.webapp_readiness_failed"]
        [failed] = [e for e in logs if e["event"] == "webapp_readiness.acme_snapshot_failed"]
        assert failed["log_level"] == "error"
        assert "secret-looking" not in str(event)


# --- the real runner and the fake lego (POSIX) --------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="requires a POSIX executable script (shebang)")
class TestWithTheFakeLego:
    async def test_a_certificate_the_runner_lands_is_rendered_by_the_next_pass(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from gwops.acme import token as token_module
        from tests.acme.fake_lego_support import install_fake_lego, success, write_token_file

        fake = install_fake_lego(tmp_path / "bin")
        token = write_token_file(tmp_path)
        # The runner requires the token file to resolve under the ACME mount root.
        monkeypatch.setattr(token_module, "ACME_ROOT", token.path.parent)
        fake.configure(success(leaf_for([f"*.{ZONE}"])))
        installed = asyncio.Event()
        acme = AcmeEnv(
            tmp_path, gateway_binary(), acme={"alpha": [f"*.{ZONE}"]}, runner=None
        )
        acme.rewrite_seed(
            lambda seed: seed["public_tls"]["acme"].update(directory="production")
        )
        settings = acme.env.settings.model_copy(update={"lego_binary": fake.binary})
        settings.acme_dir.mkdir(parents=True, mode=0o700)

        class TokenAtTmpRunner(AcmeRunner):
            """The seed confines ``token_file`` to /config/acme/; point lego at the tmp copy."""

            def configure(self, config: AcmeConfig | None) -> None:
                if config is not None:
                    moved = config.settings.model_copy(update={"token_file": str(token.path)})
                    config = dataclasses.replace(config, settings=moved)
                super().configure(config)

        runner = TokenAtTmpRunner(
            settings, store=acme.store, on_installed=lambda _name: installed.set()
        )
        acme.reconciler = Reconciler(
            settings=acme.env.settings,
            store=acme.env.store,
            tg=None,
            certs=acme.env.certs,
            process=acme.process,  # type: ignore[arg-type]
            registry=acme.env.registry,
            caps=Capabilities(),
            validate_timeout_seconds=0.2,
            paths=acme.paths,
            acme=runner,
            public_store=acme.store,
        )
        try:
            first = await acme.run("startup")
            assert first.acme_pending == ["alpha"]
            assert acme.process.calls == []
            runner.start()
            await asyncio.wait_for(installed.wait(), timeout=60)

            second = await acme.run("api")
        finally:
            await runner.aclose()

        assert second.acme_pending == []
        assert second.local_ok is True
        assert acme.process.calls == ["start"]
        assert acme.rendered_files() == [acme.stable_cert("alpha")]
        assert len(fake.invocations()) == 1
        assert _status(second, "alpha").state == "ok"


def test_the_clock_helper_stays_ahead_of_now() -> None:
    """Guards the helper the tests above rely on: leaves are valid at the real clock."""
    issued = leaf_for()
    assert issued.cert.not_valid_before_utc < datetime.now(UTC) < issued.cert.not_valid_after_utc
    assert issued.cert.not_valid_after_utc - datetime.now(UTC) > timedelta(days=70)
