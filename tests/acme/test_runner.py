"""Tests for ``gwops.acme.runner.AcmeRunner`` against the fake lego.

The runner is driven through its public API and observed through ``snapshot()``, ``state.json``
and the fake's invocation log. Time comes from the injected clock; real sleeping is limited to
polling and to the (small) ``lego_timeout_seconds`` of the timeout tests. Everything that spawns
the fake needs a POSIX shebang and skips on Windows through the ``fake_lego`` fixture.
"""

import asyncio
import contextlib
import dataclasses
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import structlog

from gwops.acme import runner as runner_module
from gwops.acme.runner import (
    FORCE_WINDOW,
    RELOAD_PENDING_EXCERPT,
    REQUEST_FLOOR,
    STILL_DUE_EXCERPT,
    AcmeCertState,
    AcmeConfig,
    AcmeRunner,
    IssueStatus,
)
from gwops.acme.state import (
    INITIAL_BACKOFF,
    PRUNE_RETENTION,
    STATE_FILENAME,
    AcmeErrorClass,
    AcmeStateStore,
    backoff_delay,
    names_hash,
)
from gwops.certs.store import MaterialStore, StoreError
from gwops.configmodel.schema import AcmePublicCertificate, AcmeSettings, PublicTlsSettings
from gwops.settings import GwopsSettings
from tests.acme.fake_lego_support import (
    TOKEN_SENTINEL,
    FakeLego,
    Step,
    TokenFile,
    failure,
    hang,
    rate_limit_hang,
    signal_death,
    success,
)
from tests.acme.runner_support import (
    CERT,
    Clock,
    RunnerFactory,
    child_pid,
    entry,
    events,
    fingerprint_of,
    process_alive,
    serial_of,
    started_pids,
    wait_attempts,
    wait_until,
)
from tests.public_chain_support import (
    NOW,
    ZONE,
    ZONES,
    key_pem_of,
    other_hierarchy,
    pem_of,
    rsa_hierarchy,
    rsa_key,
)
from tests.public_tls_support import public_cert, tls_block

WILDCARD = f"*.{ZONE}"
PRODUCTION_URL = "https://acme-v02.api.letsencrypt.org/directory"
STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
OTHER_URL = "https://acme.example.test/directory"
SAME_HOST_URL = "https://acme-v02.api.letsencrypt.org/other-directory"
HOUR = timedelta(hours=1)


def fast(settings: GwopsSettings, seconds: float) -> GwopsSettings:
    """`settings` with a short lego timeout."""
    return settings.model_copy(update={"lego_timeout_seconds": seconds})


def installed_pair(store: MaterialStore, name: str = CERT) -> tuple[bytes, bytes]:
    cert_path, key_path = store.stable_paths(name)
    return cert_path.read_bytes(), key_path.read_bytes()


def store_has(store: MaterialStore, name: str = CERT) -> bool:
    cert_path, key_path = store.stable_paths(name)
    return cert_path.is_file() and key_path.is_file()


async def first_install(
    runner: AcmeRunner,
    config: AcmeConfig,
    fake: FakeLego,
    settings: GwopsSettings,
) -> Step:
    """Configure a successful fake, start the runner and wait for the first attempt."""
    step = fake.succeed()
    runner.configure(config)
    runner.start()
    await wait_attempts(settings, runner, 1)
    return step


# --- AcmeConfig -------------------------------------------------------------------------------


class TestAcmeConfig:
    def test_production_without_a_registered_root_is_refused(
        self, production_settings: AcmeSettings, acme_cert: AcmePublicCertificate
    ) -> None:
        with pytest.raises(ValueError, match="registered root"):
            AcmeConfig(production_settings, (acme_cert,), ZONES, None)

    def test_staging_needs_no_root(
        self, acme_settings: AcmeSettings, acme_cert: AcmePublicCertificate
    ) -> None:
        config = AcmeConfig(acme_settings, (acme_cert,), ZONES, None)

        assert config.root is None

    def test_the_configuration_is_frozen(self, staging_config: AcmeConfig) -> None:
        with pytest.raises(dataclasses.FrozenInstanceError):
            staging_config.zones = ()  # type: ignore[misc]

    def public(self, certificates: list[dict[str, object]], **tls: object) -> PublicTlsSettings:
        return PublicTlsSettings.model_validate(tls_block(certificates=certificates, **tls))

    ACME_BLOCK = {"email": "ops@example.com", "accept_tos": True}
    ACME_CERT = {"name": CERT, "names": [WILDCARD], "source": "acme"}

    def test_from_public_tls_collects_only_the_acme_certificates(self) -> None:
        public = self.public(
            [public_cert(name="from-file", names=[ZONE]), self.ACME_CERT],
            acme=self.ACME_BLOCK,
        )

        config = AcmeConfig.from_public_tls(public, None)

        assert config is not None
        assert [c.name for c in config.certificates] == [CERT]
        assert config.zones == (ZONE,)
        assert config.settings.email == "ops@example.com"
        assert config.settings.is_staging

    def test_from_public_tls_passes_the_root_through(self) -> None:
        public = self.public([self.ACME_CERT], acme={**self.ACME_BLOCK, "directory": "production"})
        root = rsa_hierarchy().root

        config = AcmeConfig.from_public_tls(public, root)

        assert config is not None
        assert config.root is root

    def test_from_public_tls_is_none_without_acme_certificates(self) -> None:
        public = self.public([public_cert()], acme=self.ACME_BLOCK)

        assert AcmeConfig.from_public_tls(public, None) is None

    def test_from_public_tls_is_none_without_an_acme_block(self) -> None:
        public = self.public([public_cert()])

        assert AcmeConfig.from_public_tls(public, None) is None

    def test_from_public_tls_in_production_without_a_root_is_refused(self) -> None:
        public = self.public([self.ACME_CERT], acme={**self.ACME_BLOCK, "directory": "production"})

        with pytest.raises(ValueError, match="registered root"):
            AcmeConfig.from_public_tls(public, None)


# --- first issuance and landing ---------------------------------------------------------------


class TestProductionInstall:
    async def test_first_issuance_installs_through_the_store_and_calls_back_once(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
        installed_calls: list[str],
    ) -> None:
        runner = new_runner()

        step = await first_install(runner, production_config, fake_lego, lego_settings)

        assert installed_pair(public_store) == (step["crt"].encode(), step["key"].encode())
        assert installed_calls == [CERT]
        recorded = entry(lego_settings)
        assert recorded.installed_serial == serial_of(step)
        assert recorded.installed_fingerprint == fingerprint_of(step)
        assert recorded.installed_at == NOW
        assert recorded.issued_names_hash == names_hash([WILDCARD])
        assert recorded.directory == PRODUCTION_URL
        assert recorded.renewal_reason == "missing"
        assert recorded.error_code is None
        assert recorded.consecutive_failures == 0
        assert len(fake_lego.invocations()) == 1

    async def test_the_snapshot_reports_an_installed_idle_certificate(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        step = await first_install(runner, production_config, fake_lego, lego_settings)

        snap = runner.snapshot().get(CERT)

        assert snap is not None
        assert snap.state is AcmeCertState.IDLE
        assert snap.installed is True
        assert snap.installed_serial == serial_of(step)
        assert snap.installed_at == NOW
        assert snap.error_code is None
        assert snap.in_backoff is False
        assert snap.readiness_codes == ()

    async def test_the_runner_hands_lego_the_declared_names_and_the_production_directory(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        await first_install(runner, production_config, fake_lego, lego_settings)

        (call,) = fake_lego.invocations()

        assert call.value("--server") == PRODUCTION_URL
        assert call.value("--domains") == WILDCARD
        assert call.value("--cert.name") == CERT
        assert not call.has("--renew-force")

    async def test_a_run_that_is_not_due_records_no_install_and_no_callback(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
        installed_calls: list[str],
        clock: Clock,
    ) -> None:
        runner = new_runner()
        await first_install(runner, production_config, fake_lego, lego_settings)
        generation = os.readlink(public_store.stable_paths(CERT)[0].parent / "..data")
        installed_at = entry(lego_settings).installed_at
        fake_lego.succeed()  # lego itself decides "not due": exit 0, writes nothing

        clock.advance(timedelta(hours=14))
        runner.wake()
        await wait_attempts(lego_settings, runner, 2)

        recorded = entry(lego_settings)
        assert len(fake_lego.invocations()) == 2
        assert installed_calls == [CERT]
        assert recorded.installed_at == installed_at
        assert recorded.last_success_at == NOW + timedelta(hours=14)
        assert recorded.renewal_reason == "check_interval"
        assert recorded.error_code is None
        assert os.readlink(public_store.stable_paths(CERT)[0].parent / "..data") == generation
        assert not fake_lego.invocations()[1].has("--renew-force")

    async def test_the_next_check_is_scheduled_twelve_hours_out_with_one_hour_of_jitter(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        await first_install(runner, production_config, fake_lego, lego_settings)

        next_at = entry(lego_settings).next_attempt_at

        assert next_at is not None
        assert NOW + timedelta(hours=11) <= next_at <= NOW + timedelta(hours=13)

    async def test_a_renewal_with_new_material_installs_it_and_calls_back_again(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
        installed_calls: list[str],
        clock: Clock,
    ) -> None:
        runner = new_runner()
        first = await first_install(runner, production_config, fake_lego, lego_settings)
        renewed = fake_lego.succeed(renewal_due=True)

        clock.advance(timedelta(hours=14))
        runner.wake()
        await wait_attempts(lego_settings, runner, 2)

        assert installed_pair(public_store) == (renewed["crt"].encode(), renewed["key"].encode())
        assert installed_calls == [CERT, CERT]
        assert entry(lego_settings).installed_serial == serial_of(renewed)
        assert serial_of(renewed) != serial_of(first)

    async def test_the_same_material_returned_again_is_not_a_new_install(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        installed_calls: list[str],
        clock: Clock,
    ) -> None:
        """A forced lego run that rewrites identical files is recognised by serial and hash."""
        runner = new_runner()
        step = await first_install(runner, production_config, fake_lego, lego_settings)
        fake_lego.configure({**step, "renewal_due": True})

        clock.advance(timedelta(hours=14))
        runner.wake()
        await wait_attempts(lego_settings, runner, 2)

        assert installed_calls == [CERT]
        assert entry(lego_settings).installed_serial == serial_of(step)


class TestValidatorRefusal:
    async def test_material_from_the_wrong_root_installs_nothing_and_records_invalid_output(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
        installed_calls: list[str],
    ) -> None:
        runner = new_runner()
        fake_lego.succeed(other_hierarchy().issue((WILDCARD,)))
        runner.configure(production_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.error_code is AcmeErrorClass.INVALID_OUTPUT
        assert recorded.installed_serial is None
        assert recorded.consecutive_failures == 1
        assert recorded.next_attempt_at == NOW + INITIAL_BACKOFF
        assert "chain" in (recorded.error_excerpt or "")
        assert not store_has(public_store)
        assert installed_calls == []
        assert len(fake_lego.invocations()) == 1

    async def test_a_production_refusal_removes_lego_certificate_files_but_not_its_account(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        fake_lego.succeed(other_hierarchy().issue((WILDCARD,)))
        runner.configure(production_config)

        with structlog.testing.capture_logs() as logs:
            runner.start()
            await wait_attempts(lego_settings, runner, 1)

        storage = lego_settings.lego_storage_dir(PRODUCTION_URL)
        assert list((storage / "certificates").glob(f"{CERT}.*")) == []
        assert (storage / "accounts" / "acme-v02.api.letsencrypt.org").is_dir()
        (reset,) = events(logs, "acme.runner.lego_material_reset")
        assert reset["reason"] == "refused"
        assert reset["removed"] == [".crt", ".key", ".issuer.crt", ".json"]

    async def test_the_next_run_after_a_production_refusal_is_a_fresh_order(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
        installed_calls: list[str],
        clock: Clock,
    ) -> None:
        """Without the reset lego would call the bad files "not due" and write nothing."""
        runner = new_runner()
        good = success()
        fake_lego.configure(success(other_hierarchy().issue((WILDCARD,))), good)
        runner.configure(production_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)

        clock.advance(INITIAL_BACKOFF)
        runner.wake()
        recorded = await wait_attempts(lego_settings, runner, 2)

        assert recorded.error_code is None
        assert recorded.installed_serial == serial_of(good)
        assert installed_pair(public_store)[0] == good["crt"].encode()
        assert installed_calls == [CERT]

    async def test_a_staging_refusal_leaves_lego_files_in_place(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        fake_lego.succeed(other_hierarchy().issue((f"other.{ZONE}",)))
        runner.configure(staging_config)

        with structlog.testing.capture_logs() as logs:
            runner.start()
            recorded = await wait_attempts(lego_settings, runner, 1)

        certs = lego_settings.lego_storage_dir(STAGING_URL) / "certificates"
        assert recorded.error_code is AcmeErrorClass.INVALID_OUTPUT
        assert sorted(p.name for p in certs.glob(f"{CERT}.*")) == [
            f"{CERT}.crt",
            f"{CERT}.issuer.crt",
            f"{CERT}.json",
            f"{CERT}.key",
        ]
        assert events(logs, "acme.runner.lego_material_reset") == []

    async def test_an_unreadable_issuer_file_is_logged_and_named_in_the_refusal(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
    ) -> None:
        """A leaf-only ``.crt`` needs lego's issuer file; without it the chain is incomplete."""
        leaf = rsa_hierarchy().issue((WILDCARD,))
        step = {**success(leaf), "crt": pem_of(leaf.cert).decode()}
        step.pop("issuer")
        fake_lego.configure(step)
        runner = new_runner()
        runner.configure(production_config)

        with structlog.testing.capture_logs() as logs:
            runner.start()
            recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.error_code is AcmeErrorClass.INVALID_OUTPUT
        assert f"the issuer file {CERT}.issuer.crt is unreadable" in (recorded.error_excerpt or "")
        (warning,) = events(logs, "acme.runner.issuer_unreadable")
        assert warning["certificate"] == CERT
        assert warning["file"] == f"{CERT}.issuer.crt"
        assert not store_has(public_store)

    async def test_an_unreadable_issuer_file_does_not_block_a_complete_bundle(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
    ) -> None:
        step = success()
        step.pop("issuer")  # the bundle in .crt already carries the intermediates
        fake_lego.configure(step)
        runner = new_runner()
        runner.configure(production_config)

        with structlog.testing.capture_logs() as logs:
            runner.start()
            recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.error_code is None
        assert store_has(public_store)
        assert len(events(logs, "acme.runner.issuer_unreadable")) == 1

    async def test_an_installed_pair_that_is_not_the_one_lego_holds_is_not_taken_for_current(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
        installed_calls: list[str],
        clock: Clock,
    ) -> None:
        """lego says "not due" and writes nothing; its files are compared with the store."""
        runner = new_runner()
        step = await first_install(runner, production_config, fake_lego, lego_settings)
        stray = rsa_hierarchy().issue((WILDCARD,))
        public_store.install(CERT, stray.cert_pem, stray.key_pem)
        fake_lego.succeed()

        clock.advance(timedelta(hours=14))
        runner.wake()
        recorded = await wait_attempts(lego_settings, runner, 2)

        assert recorded.error_code is None
        assert installed_pair(public_store) == (step["crt"].encode(), step["key"].encode())
        assert installed_calls == [CERT, CERT]

    async def test_a_key_that_differs_from_the_installed_one_is_not_taken_for_current(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
        installed_calls: list[str],
        clock: Clock,
    ) -> None:
        """Same leaf, different key in the store: only the pair together counts as current."""
        runner = new_runner()
        step = await first_install(runner, production_config, fake_lego, lego_settings)
        public_store.install(CERT, step["crt"].encode(), key_pem_of(rsa_key()))
        fake_lego.succeed()

        clock.advance(timedelta(hours=14))
        runner.wake()
        await wait_attempts(lego_settings, runner, 2)

        assert installed_pair(public_store) == (step["crt"].encode(), step["key"].encode())
        assert installed_calls == [CERT, CERT]

    async def test_the_refusal_excerpt_carries_no_pem_text(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        step = fake_lego.succeed(other_hierarchy().issue((WILDCARD,)))
        runner.configure(production_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        body_line = step["key"].splitlines()[1]
        assert body_line not in (recorded.error_excerpt or "")
        assert "BEGIN" not in (recorded.error_excerpt or "")

    async def test_the_snapshot_after_a_refusal_shows_pending_failed_and_backoff(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        fake_lego.succeed(other_hierarchy().issue((WILDCARD,)))
        runner.configure(production_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)

        snap = runner.snapshot().get(CERT)

        assert snap is not None
        assert snap.state is AcmeCertState.BACKOFF
        assert snap.installed is False
        assert snap.error_code is AcmeErrorClass.INVALID_OUTPUT
        assert snap.in_backoff is True
        assert snap.next_attempt_at == NOW + INITIAL_BACKOFF
        assert snap.readiness_codes == (
            f"public_cert_pending:{CERT}",
            "acme_failed:invalid_output",
            "acme_backoff",
        )

    async def test_a_refusal_after_a_good_install_keeps_serving_the_installed_pair(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
        installed_calls: list[str],
        clock: Clock,
    ) -> None:
        runner = new_runner()
        step = await first_install(runner, production_config, fake_lego, lego_settings)
        fake_lego.succeed(other_hierarchy().issue((WILDCARD,)), renewal_due=True)

        clock.advance(timedelta(hours=14))
        runner.wake()
        await wait_attempts(lego_settings, runner, 2)

        recorded = entry(lego_settings)
        assert recorded.error_code is AcmeErrorClass.INVALID_OUTPUT
        assert recorded.installed_serial == serial_of(step)
        assert installed_pair(public_store) == (step["crt"].encode(), step["key"].encode())
        assert installed_calls == [CERT]
        snap = runner.snapshot().get(CERT)
        assert snap is not None
        assert snap.installed is True
        assert snap.readiness_codes == ("acme_failed:invalid_output", "acme_backoff")

    async def test_a_missing_key_file_is_invalid_output(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
    ) -> None:
        runner = new_runner()
        fake_lego.succeed(key=False)
        runner.configure(production_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.error_code is AcmeErrorClass.INVALID_OUTPUT
        assert "cannot be read" in (recorded.error_excerpt or "")
        assert not store_has(public_store)

    async def test_a_certificate_file_without_a_certificate_is_invalid_output(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
    ) -> None:
        runner = new_runner()
        fake_lego.configure({**success(), "crt": "this is not a certificate\n"})
        runner.configure(production_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.error_code is AcmeErrorClass.INVALID_OUTPUT
        assert "no parseable certificate" in (recorded.error_excerpt or "")
        assert not store_has(public_store)

    async def test_names_the_certificate_does_not_cover_are_invalid_output(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
    ) -> None:
        runner = new_runner()
        fake_lego.succeed(rsa_hierarchy().issue((f"other.{ZONE}",)))
        runner.configure(production_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.error_code is AcmeErrorClass.INVALID_OUTPUT
        assert WILDCARD in (recorded.error_excerpt or "")
        assert not store_has(public_store)

    async def test_a_store_that_cannot_install_records_internal_and_calls_nothing(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
        installed_calls: list[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def refuse(name: str, cert_pem: bytes, key_pem: bytes) -> object:
            raise StoreError("disk full")

        monkeypatch.setattr(public_store, "install", refuse)
        runner = new_runner()
        fake_lego.succeed()
        runner.configure(production_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.error_code is AcmeErrorClass.INTERNAL
        assert "disk full" in (recorded.error_excerpt or "")
        assert recorded.installed_serial is None
        assert installed_calls == []


class TestStagingDryRun:
    async def test_a_dry_run_never_installs_and_never_calls_back(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        public_store: MaterialStore,
        installed_calls: list[str],
    ) -> None:
        runner = new_runner()

        await first_install(runner, staging_config, fake_lego, lego_settings)

        recorded = entry(lego_settings)
        assert not store_has(public_store)
        assert not public_store.stable_paths(CERT)[0].parent.exists()
        assert installed_calls == []
        assert recorded.last_success_at == NOW
        assert recorded.installed_serial is None
        assert recorded.installed_at is None
        assert recorded.issued_names_hash is None
        assert recorded.directory == STAGING_URL

    async def test_the_snapshot_reports_dry_run_ok_and_pending(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        await first_install(runner, staging_config, fake_lego, lego_settings)

        snap = runner.snapshot().get(CERT)

        assert snap is not None
        assert snap.staging is True
        assert snap.state is AcmeCertState.DRY_RUN_OK
        assert snap.installed is False
        assert snap.readiness_codes == (f"public_cert_pending:{CERT}",)

    async def test_staging_material_from_an_unregistered_root_passes_the_root_less_check(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        fake_lego.succeed(other_hierarchy().issue((WILDCARD,)))
        runner.configure(staging_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.error_code is None
        assert recorded.last_success_at == NOW

    async def test_staging_material_with_a_bad_profile_is_still_refused(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        fake_lego.succeed(other_hierarchy().issue((f"other.{ZONE}",)))
        runner.configure(staging_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.error_code is AcmeErrorClass.INVALID_OUTPUT
        assert recorded.last_success_at is None

    async def test_a_changed_name_set_starts_a_new_dry_run(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        acme_cert: AcmePublicCertificate,
        installed_calls: list[str],
    ) -> None:
        runner = new_runner()
        await first_install(runner, staging_config, fake_lego, lego_settings)
        fake_lego.succeed(rsa_hierarchy().issue((WILDCARD, ZONE)))
        changed = acme_cert.model_copy(update={"names": [WILDCARD, ZONE]})

        runner.configure(dataclasses.replace(staging_config, certificates=(changed,)))
        recorded = await wait_attempts(lego_settings, runner, 2)

        assert recorded.renewal_reason == "names_changed"
        assert recorded.names == [WILDCARD, ZONE]
        assert installed_calls == []

    async def test_a_dry_run_does_not_repeat_until_the_next_check(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        await first_install(runner, staging_config, fake_lego, lego_settings)

        runner.wake()
        await asyncio.sleep(0.2)

        assert len(fake_lego.invocations()) == 1
        assert runner.running is None


# --- reissue triggers -------------------------------------------------------------------------


class TestReissue:
    async def test_a_changed_name_set_reissues_and_installs_the_new_material(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        acme_cert: AcmePublicCertificate,
        public_store: MaterialStore,
        installed_calls: list[str],
    ) -> None:
        runner = new_runner()
        await first_install(runner, production_config, fake_lego, lego_settings)
        widened = fake_lego.succeed(rsa_hierarchy().issue((WILDCARD, ZONE)))
        changed = acme_cert.model_copy(update={"names": [WILDCARD, ZONE]})

        runner.configure(dataclasses.replace(production_config, certificates=(changed,)))
        recorded = await wait_attempts(lego_settings, runner, 2)

        second = fake_lego.invocations()[1]
        assert second.value("--domains") == f"{WILDCARD},{ZONE}"
        assert recorded.renewal_reason == "names_changed"
        assert recorded.names == [WILDCARD, ZONE]
        assert recorded.issued_names_hash == names_hash([WILDCARD, ZONE])
        assert recorded.installed_serial == serial_of(widened)
        assert installed_pair(public_store)[0] == widened["crt"].encode()
        assert installed_calls == [CERT, CERT]

    async def test_a_directory_change_on_the_same_host_resets_lego_material_and_reissues(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        production_settings: AcmeSettings,
        public_store: MaterialStore,
        installed_calls: list[str],
    ) -> None:
        """Both URLs map to one lego ``--path``, so the old order's files must go."""
        runner = new_runner()
        await first_install(runner, production_config, fake_lego, lego_settings)
        storage = lego_settings.lego_storage_dir(PRODUCTION_URL)
        assert lego_settings.lego_storage_dir(SAME_HOST_URL) == storage
        certs = storage / "certificates"
        assert (certs / f"{CERT}.json").is_file()
        old_account = storage / "accounts" / "acme-v02.api.letsencrypt.org"
        assert old_account.is_dir()
        other = fake_lego.succeed()
        moved = dataclasses.replace(
            production_config,
            settings=production_settings.model_copy(update={"directory": SAME_HOST_URL}),
        )

        with structlog.testing.capture_logs() as logs:
            runner.configure(moved)
            recorded = await wait_attempts(lego_settings, runner, 2)

        (reset,) = events(logs, "acme.runner.lego_material_reset")
        assert reset["removed"] == [".crt", ".key", ".issuer.crt", ".json"]
        assert reset["reason"] == "directory_changed"
        assert reset["previous_directory"] == PRODUCTION_URL
        assert reset["directory"] == SAME_HOST_URL
        assert fake_lego.invocations()[1].value("--server") == SAME_HOST_URL
        assert recorded.renewal_reason == "directory_changed"
        assert recorded.directory == SAME_HOST_URL
        assert recorded.installed_serial == serial_of(other)
        assert installed_pair(public_store)[0] == other["crt"].encode()
        assert installed_calls == [CERT, CERT]
        assert old_account.is_dir(), "only the certificate files are reset, not accounts"

    async def test_a_directory_change_to_another_host_uses_a_new_path_and_resets_nothing(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        production_settings: AcmeSettings,
        public_store: MaterialStore,
        installed_calls: list[str],
    ) -> None:
        runner = new_runner()
        await first_install(runner, production_config, fake_lego, lego_settings)
        old_storage = lego_settings.lego_storage_dir(PRODUCTION_URL)
        new_storage = lego_settings.lego_storage_dir(OTHER_URL)
        assert new_storage != old_storage
        other = fake_lego.succeed()
        moved = dataclasses.replace(
            production_config,
            settings=production_settings.model_copy(update={"directory": OTHER_URL}),
        )

        with structlog.testing.capture_logs() as logs:
            runner.configure(moved)
            recorded = await wait_attempts(lego_settings, runner, 2)

        assert events(logs, "acme.runner.lego_material_reset") == []
        second = fake_lego.invocations()[1]
        assert second.value("--server") == OTHER_URL
        assert second.value("--path") == new_storage.as_posix()
        assert recorded.renewal_reason == "directory_changed"
        assert recorded.directory == OTHER_URL
        assert recorded.installed_serial == serial_of(other)
        assert installed_pair(public_store)[0] == other["crt"].encode()
        assert installed_calls == [CERT, CERT]
        assert (old_storage / "certificates" / f"{CERT}.json").is_file(), "left untouched"
        assert (new_storage / "certificates" / f"{CERT}.json").is_file()

    async def test_a_directory_change_leaves_the_installed_pair_serving_if_the_new_run_fails(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        production_settings: AcmeSettings,
        public_store: MaterialStore,
    ) -> None:
        runner = new_runner()
        step = await first_install(runner, production_config, fake_lego, lego_settings)
        fake_lego.fail("dns_auth")
        moved = dataclasses.replace(
            production_config,
            settings=production_settings.model_copy(update={"directory": OTHER_URL}),
        )

        runner.configure(moved)
        recorded = await wait_attempts(lego_settings, runner, 2)

        assert recorded.error_code is AcmeErrorClass.DNS_AUTH
        assert installed_pair(public_store)[0] == step["crt"].encode()

    async def test_each_certificate_gets_its_own_run_and_the_runs_never_overlap(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        acme_cert: AcmePublicCertificate,
        public_store: MaterialStore,
        installed_calls: list[str],
    ) -> None:
        api = AcmePublicCertificate.model_validate(
            {"name": "api-host", "names": [f"api.{ZONE}"], "source": "acme"}
        )
        wild_step = success(rsa_hierarchy().issue((WILDCARD,)), delay=0.5)
        api_step = success(rsa_hierarchy().issue((f"api.{ZONE}",)), delay=0.5)
        fake_lego.configure(wild_step, api_step)
        runner = new_runner()
        runner.configure(dataclasses.replace(production_config, certificates=(acme_cert, api)))
        runner.start()

        await wait_until(lambda: runner.running == CERT, what="the first run to start")
        during = runner.snapshot()
        await wait_attempts(lego_settings, runner, 1, CERT)
        await wait_attempts(lego_settings, runner, 1, "api-host")

        first, second = fake_lego.invocations()
        assert first.value("--cert.name") == CERT
        assert second.value("--cert.name") == "api-host"
        assert first.ended_at is not None
        assert first.ended_at <= second.started_at
        assert during.running == CERT
        assert during.get(CERT).state is AcmeCertState.ISSUING  # type: ignore[union-attr]
        assert during.get("api-host").state is AcmeCertState.SCHEDULED  # type: ignore[union-attr]
        assert installed_calls == [CERT, "api-host"]
        assert store_has(public_store, "api-host")


# --- request_issue ----------------------------------------------------------------------------


class TestRequestIssue:
    async def test_an_unconfigured_runner_reports_an_unknown_certificate(
        self, new_runner: RunnerFactory
    ) -> None:
        outcome = new_runner().request_issue(CERT)

        assert outcome.status is IssueStatus.UNKNOWN_CERTIFICATE
        assert outcome.accepted is False
        assert CERT in outcome.detail

    async def test_a_name_that_is_not_configured_is_unknown(
        self, new_runner: RunnerFactory, staging_config: AcmeConfig
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)

        outcome = runner.request_issue("not-declared")

        assert outcome.status is IssueStatus.UNKNOWN_CERTIFICATE
        assert outcome.retry_after_seconds is None

    async def test_a_configured_certificate_is_accepted_and_runs_as_requested(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        installed_calls: list[str],
    ) -> None:
        """After a success ``next_attempt_at`` is the scheduled check, which is not a backoff."""
        runner = new_runner()
        await first_install(runner, production_config, fake_lego, lego_settings)
        scheduled = entry(lego_settings)
        assert scheduled.next_attempt_at is not None
        assert scheduled.next_attempt_at > NOW
        assert scheduled.consecutive_failures == 0
        assert scheduled.error_code is None
        fake_lego.succeed()

        outcome = runner.request_issue(CERT)
        recorded = await wait_attempts(lego_settings, runner, 2)

        assert outcome.status is IssueStatus.ACCEPTED
        assert outcome.accepted is True
        assert outcome.reason is None
        assert outcome.retry_after_seconds is None
        assert recorded.renewal_reason == "requested"
        assert not fake_lego.invocations()[1].has("--renew-force")
        assert installed_calls == [CERT]

    async def test_force_adds_renew_force_and_installs_the_renewed_material(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
        installed_calls: list[str],
        clock: Clock,
    ) -> None:
        runner = new_runner()
        await first_install(runner, production_config, fake_lego, lego_settings)
        renewed = fake_lego.succeed()
        clock.advance(FORCE_WINDOW)  # a production force is refused inside 24 h of the install

        outcome = runner.request_issue(CERT, force=True)
        recorded = await wait_attempts(lego_settings, runner, 2)

        assert outcome.status is IssueStatus.ACCEPTED
        assert fake_lego.invocations()[1].has("--renew-force")
        assert recorded.renewal_reason == "forced"
        assert installed_pair(public_store)[0] == renewed["crt"].encode()
        assert installed_calls == [CERT, CERT]

    @pytest.mark.parametrize(
        "order", [(False, True), (True, False)], ids=["upgrade", "no-downgrade"]
    )
    async def test_a_forced_request_is_never_downgraded_by_a_plain_one(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
        order: tuple[bool, bool],
    ) -> None:
        runner = new_runner()
        fake_lego.succeed()
        runner.configure(staging_config)
        for force in order:
            assert runner.request_issue(CERT, force=force).status is IssueStatus.ACCEPTED
            clock.advance(REQUEST_FLOOR + timedelta(seconds=1))  # one request per 60 s

        runner.start()
        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.renewal_reason == "forced"
        assert fake_lego.invocations()[0].has("--renew-force")
        assert len(fake_lego.invocations()) == 1

    async def test_a_request_while_lego_runs_for_that_certificate_is_already_running(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        fake_lego.configure(success(delay=0.6))
        runner.configure(staging_config)
        runner.start()
        await wait_until(lambda: runner.running == CERT, what="lego to start")

        outcome = runner.request_issue(CERT, force=True)

        assert outcome.status is IssueStatus.ALREADY_RUNNING
        assert CERT in outcome.detail
        await wait_attempts(lego_settings, runner, 1)
        assert len(fake_lego.invocations()) == 1

    async def test_a_request_for_another_certificate_waits_its_turn(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        acme_cert: AcmePublicCertificate,
    ) -> None:
        api = AcmePublicCertificate.model_validate(
            {"name": "api-host", "names": [f"api.{ZONE}"], "source": "acme"}
        )
        fake_lego.configure(
            success(delay=0.5),
            success(rsa_hierarchy().issue((f"api.{ZONE}",))),
        )
        runner = new_runner()
        runner.configure(dataclasses.replace(staging_config, certificates=(acme_cert, api)))
        runner.start()
        await wait_until(lambda: runner.running == CERT, what="lego to start")

        outcome = runner.request_issue("api-host")

        assert outcome.status is IssueStatus.ACCEPTED
        await wait_attempts(lego_settings, runner, 1, "api-host")
        assert [i.value("--cert.name") for i in fake_lego.invocations()] == [CERT, "api-host"]

    async def test_a_certificate_in_backoff_reports_the_seconds_left_and_force_does_not_help(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        runner = new_runner()
        fake_lego.fail("internal")
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)

        plain = runner.request_issue(CERT)
        forced = runner.request_issue(CERT, force=True)
        clock.advance(timedelta(minutes=14, seconds=59))
        almost = runner.request_issue(CERT)

        assert plain.status is IssueStatus.IN_BACKOFF
        assert plain.retry_after_seconds == 900
        assert plain.reason == "backoff"
        assert plain.error_code == "internal"
        assert CERT in plain.detail
        assert forced.status is IssueStatus.IN_BACKOFF
        assert forced.retry_after_seconds == 900
        assert forced.reason == "backoff"
        assert almost.status is IssueStatus.IN_BACKOFF
        assert almost.retry_after_seconds == 1
        assert entry(lego_settings).last_request_at is None, "a refused request leaves no stamp"
        await asyncio.sleep(0.2)
        assert len(fake_lego.invocations()) == 1

    async def test_the_request_is_accepted_when_the_backoff_has_elapsed(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        runner = new_runner()
        fake_lego.configure(failure("internal"), success())
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)
        clock.advance(INITIAL_BACKOFF)

        outcome = runner.request_issue(CERT)
        recorded = await wait_attempts(lego_settings, runner, 2)

        assert outcome.status is IssueStatus.ACCEPTED
        assert recorded.renewal_reason == "requested"
        assert recorded.error_code is None
        assert recorded.consecutive_failures == 0

    async def test_a_rate_limited_certificate_reports_the_retry_after_in_seconds(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        fake_lego.fail("rate_limited", retry_after="2026-10-21 10:00:00 UTC")
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)

        outcome = runner.request_issue(CERT)

        expected = datetime(2026, 10, 21, 10, 0, tzinfo=UTC) - NOW
        assert outcome.status is IssueStatus.IN_BACKOFF
        assert outcome.retry_after_seconds == int(expected.total_seconds())
        assert outcome.reason == "backoff"
        assert outcome.error_code == "rate_limited"

    async def test_an_unusable_state_file_makes_issuance_unavailable(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        state_path = lego_settings.acme_dir / STATE_FILENAME
        state_path.write_text("{ not json")
        runner = new_runner()
        runner.configure(staging_config)

        outcome = runner.request_issue(CERT)

        assert outcome.status is IssueStatus.UNAVAILABLE
        assert "state file" in outcome.detail
        assert state_path.read_text() == "{ not json"

    async def test_a_closed_runner_is_unavailable(
        self, new_runner: RunnerFactory, staging_config: AcmeConfig
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)
        await runner.aclose()

        outcome = runner.request_issue(CERT)

        assert outcome.status is IssueStatus.UNAVAILABLE
        assert "shut down" in outcome.detail


# --- timeouts and kills -----------------------------------------------------------------------


class TestTimeouts:
    @pytest.fixture
    def signals(self, monkeypatch: pytest.MonkeyPatch) -> list[bool]:
        """Records ``kill`` of every signal the runner sends to lego's process group."""
        calls: list[bool] = []
        real = runner_module._signal_group

        def spy(proc: asyncio.subprocess.Process, *, kill: bool) -> None:
            calls.append(kill)
            real(proc, kill=kill)

        monkeypatch.setattr(runner_module, "_signal_group", spy)
        return calls

    async def test_a_hung_lego_is_terminated_and_recorded_as_a_timeout(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        signals: list[bool],
    ) -> None:
        fake_lego.configure(hang())
        runner = new_runner(settings=fast(lego_settings, 1.0))
        runner.configure(staging_config)

        with structlog.testing.capture_logs() as logs:
            runner.start()
            recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.error_code is AcmeErrorClass.TIMEOUT
        assert (recorded.error_excerpt or "").startswith("killed after 1s without finishing;")
        assert recorded.consecutive_failures == 1
        assert recorded.next_attempt_at == NOW + INITIAL_BACKOFF
        assert signals == [False], "SIGTERM was enough; no SIGKILL"
        (call,) = fake_lego.invocations()
        assert call.exit_code is None
        assert not process_alive(started_pids(fake_lego)[0])
        assert any(e["event"] == "acme.runner.lego_timeout" for e in logs)

    async def test_a_lego_that_ignores_sigterm_is_killed(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        signals: list[bool],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(runner_module, "KILL_GRACE_SECONDS", 0.5)
        fake_lego.configure(hang(ignore_sigterm=True))
        runner = new_runner(settings=fast(lego_settings, 2.0))
        runner.configure(staging_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.error_code is AcmeErrorClass.TIMEOUT
        assert signals == [False, True], "SIGTERM first, SIGKILL after the grace period"
        assert not process_alive(started_pids(fake_lego)[0])

    async def test_a_timeout_after_a_rate_limit_warning_is_rate_limited(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        """lego sleeps out Retry-After without a cap, so the runner's kill fires first."""
        fake_lego.configure(rate_limit_hang())
        runner = new_runner(settings=fast(lego_settings, 1.5))
        runner.configure(staging_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        expected = datetime(2026, 10, 21, 10, 0, tzinfo=UTC)
        assert recorded.error_code is AcmeErrorClass.RATE_LIMITED
        assert recorded.retry_after == expected
        assert recorded.next_attempt_at == expected
        assert "rateLimited" in (recorded.error_excerpt or "")
        assert (recorded.error_excerpt or "").startswith("killed after 1.5s")

    async def test_a_rate_limit_with_a_short_retry_after_waits_the_one_hour_floor(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        fake_lego.fail("rate_limited", retry_after="2026-10-19 12:20:00 UTC")
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.error_code is AcmeErrorClass.RATE_LIMITED
        assert recorded.next_attempt_at == NOW + HOUR

    async def test_a_rate_limit_without_a_retry_after_waits_the_one_hour_floor(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        fake_lego.fail("rate_limited", retry_after=None)
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.next_attempt_at == NOW + HOUR
        assert recorded.retry_after == NOW + HOUR

    async def test_a_retry_after_beyond_a_week_is_capped(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        fake_lego.fail("rate_limited", retry_after="2027-03-01 00:00:00 UTC")
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.next_attempt_at == NOW + timedelta(days=7)


# --- failures that never reach the validator --------------------------------------------------


class TestFailureRecording:
    @pytest.mark.parametrize(
        ("kind", "options", "expected"),
        [
            ("rate_limited", {}, AcmeErrorClass.RATE_LIMITED),
            ("dns_auth", {}, AcmeErrorClass.DNS_AUTH),
            ("dns_auth", {"status": 400}, AcmeErrorClass.DNS_AUTH),
            ("dns_propagation", {}, AcmeErrorClass.DNS_PROPAGATION),
            ("unauthorized", {}, AcmeErrorClass.UNAUTHORIZED),
            ("acme_unreachable", {}, AcmeErrorClass.ACME_UNREACHABLE),
            ("dns_zone", {}, AcmeErrorClass.DNS_ZONE),
            ("config", {}, AcmeErrorClass.CONFIG),
            ("internal", {}, AcmeErrorClass.INTERNAL),
            ("acme_problem", {"variant": "invalidContact"}, AcmeErrorClass.CONFIG),
            ("acme_problem", {"variant": "rejectedIdentifier"}, AcmeErrorClass.CONFIG),
            ("acme_problem", {"variant": "malformed"}, AcmeErrorClass.CONFIG),
            ("acme_problem", {"variant": "accountDoesNotExist"}, AcmeErrorClass.CONFIG),
            ("acme_problem", {"variant": "userActionRequired"}, AcmeErrorClass.CONFIG),
            (
                "acme_problem",
                {"variant": "malformed", "wrapped": True},
                AcmeErrorClass.CONFIG,
            ),
            ("acme_problem", {"variant": "badNonce"}, AcmeErrorClass.ACME_UNREACHABLE),
            ("acme_problem", {"variant": "serverInternal"}, AcmeErrorClass.ACME_UNREACHABLE),
            (
                "acme_problem",
                {"variant": "badNonce", "wrapped": True},
                AcmeErrorClass.ACME_UNREACHABLE,
            ),
            ("cloudflare_transient", {"variant": "rate"}, AcmeErrorClass.ACME_UNREACHABLE),
            ("cloudflare_transient", {"variant": "5xx"}, AcmeErrorClass.ACME_UNREACHABLE),
            ("cloudflare_transient", {"variant": "network"}, AcmeErrorClass.ACME_UNREACHABLE),
        ],
        ids=lambda value: value if isinstance(value, str) else None,
    )
    async def test_each_failure_class_is_recorded_and_backs_off(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        public_store: MaterialStore,
        installed_calls: list[str],
        kind: str,
        options: dict[str, Any],
        expected: AcmeErrorClass,
    ) -> None:
        fake_lego.fail(kind, **options)
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.error_code is expected
        assert recorded.consecutive_failures == 1
        assert recorded.next_attempt_at is not None
        assert recorded.next_attempt_at >= NOW + INITIAL_BACKOFF
        assert recorded.error_excerpt
        assert len(recorded.error_excerpt) <= 512
        assert recorded.last_success_at is None
        assert not store_has(public_store)
        assert installed_calls == []

    async def test_the_backoff_doubles_with_each_failure(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        fake_lego.fail("internal")
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        delays: list[timedelta] = []

        for attempt in range(1, 5):
            recorded = await wait_attempts(lego_settings, runner, attempt)
            assert recorded.next_attempt_at is not None
            delays.append(recorded.next_attempt_at - clock.now)
            if attempt < 4:
                clock.advance(delays[-1])
                runner.wake()

        assert delays == [timedelta(minutes=15), timedelta(minutes=30), HOUR, 2 * HOUR]

    async def test_a_failing_run_is_retried_by_the_loop_once_the_backoff_elapses(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        fake_lego.configure(failure("internal"), success())
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)
        runner.wake()
        await asyncio.sleep(0.2)
        assert len(fake_lego.invocations()) == 1, "no retry before the backoff has elapsed"

        clock.advance(INITIAL_BACKOFF)
        runner.wake()
        recorded = await wait_attempts(lego_settings, runner, 2)

        assert recorded.error_code is None
        assert recorded.consecutive_failures == 0
        assert recorded.renewal_reason == "missing"

    async def test_the_snapshot_walks_backoff_then_failed_as_the_clock_passes(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        fake_lego.fail("dns_auth")
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)

        during = runner.snapshot().get(CERT)
        clock.advance(INITIAL_BACKOFF)
        after = runner.snapshot().get(CERT)

        assert during is not None and after is not None
        assert during.state is AcmeCertState.BACKOFF
        assert during.in_backoff is True
        assert during.error_code is AcmeErrorClass.DNS_AUTH
        assert during.consecutive_failures == 1
        assert during.readiness_codes == (
            f"public_cert_pending:{CERT}",
            "acme_failed:dns_auth",
            "acme_backoff",
        )
        assert after.state is AcmeCertState.FAILED
        assert after.in_backoff is False
        assert after.readiness_codes == (f"public_cert_pending:{CERT}", "acme_failed:dns_auth")

    async def test_a_rate_limit_shows_its_retry_after_until_it_has_passed(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        fake_lego.fail("rate_limited", retry_after=None)
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)

        before = runner.snapshot().get(CERT)
        clock.advance(HOUR + timedelta(seconds=1))
        after = runner.snapshot().get(CERT)

        assert before is not None and after is not None
        assert before.retry_after == NOW + HOUR
        assert after.retry_after is None

    async def test_a_lego_binary_that_does_not_exist_is_a_config_failure(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        tmp_path: Path,
    ) -> None:
        missing = lego_settings.model_copy(update={"lego_binary": tmp_path / "no-such-lego"})
        runner = new_runner(settings=missing)
        runner.configure(staging_config)
        runner.start()

        recorded = await wait_attempts(missing, runner, 1)

        assert recorded.error_code is AcmeErrorClass.CONFIG
        assert "cannot start lego" in (recorded.error_excerpt or "")
        assert "FileNotFoundError" in (recorded.error_excerpt or "")
        assert recorded.next_attempt_at == NOW + INITIAL_BACKOFF
        assert runner.running is None

    async def test_a_lego_binary_that_is_not_executable_is_a_config_failure(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        tmp_path: Path,
    ) -> None:
        plain = tmp_path / "lego-not-executable"
        plain.write_text("#!/bin/sh\nexit 0\n")
        plain.chmod(0o644)
        broken = lego_settings.model_copy(update={"lego_binary": plain})
        runner = new_runner(settings=broken)
        runner.configure(staging_config)
        runner.start()

        recorded = await wait_attempts(broken, runner, 1)

        assert recorded.error_code is AcmeErrorClass.CONFIG
        assert "PermissionError" in (recorded.error_excerpt or "")

    async def test_a_crash_while_preparing_an_attempt_leaves_the_runner_alive_and_backed_off(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def kaput(*args: object, **kwargs: object) -> object:
            raise RuntimeError("kaput")

        monkeypatch.setattr(runner_module, "build_argv", kaput)
        runner = new_runner()
        runner.configure(staging_config)

        with structlog.testing.capture_logs() as logs:
            task = runner.start()
            await wait_attempts(lego_settings, runner, 1)
            snap = runner.snapshot().get(CERT)

        assert not task.done()
        assert runner.running is None
        assert fake_lego.invocations() == []
        assert any(e["event"] == "acme.runner.attempt_crashed" for e in logs)
        assert snap is not None
        assert snap.state is AcmeCertState.BACKOFF
        assert snap.in_backoff is True
        assert snap.last_crash == "RuntimeError: kaput"

    async def test_a_callback_that_raises_does_not_undo_the_install(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def explode(name: str) -> None:
            raise RuntimeError("callback bug")

        runner = new_runner(on_installed=explode)
        woken: list[bool] = []
        real_wake = runner.wake
        monkeypatch.setattr(runner, "wake", lambda: (woken.append(True), real_wake())[1])

        with structlog.testing.capture_logs() as logs:
            step = await first_install(runner, production_config, fake_lego, lego_settings)

        assert store_has(public_store)
        assert entry(lego_settings).installed_serial == serial_of(step)
        assert entry(lego_settings).error_code is None
        (event,) = [e for e in logs if e["event"] == "acme.runner.install_callback_failed"]
        assert event["certificate"] == CERT
        assert event["error_type"] == "RuntimeError"
        assert event["exc_info"] is True, "the traceback is logged"
        assert woken == [True], "the loop is woken so the reconciler is not left waiting"


# --- restart and state file -------------------------------------------------------------------


class TestResume:
    async def test_a_new_runner_resumes_the_failure_backoff_from_state_json(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        installed_calls: list[str],
        public_store: MaterialStore,
        clock: Clock,
    ) -> None:
        fake_lego.configure(failure("internal"), success())
        first = new_runner()
        first.configure(production_config)
        first.start()
        await wait_attempts(lego_settings, first, 1)
        await first.aclose()

        second = new_runner()
        second.configure(production_config)
        second.start()
        held = second.request_issue(CERT)
        await asyncio.sleep(0.2)
        snap = second.snapshot().get(CERT)

        assert held.status is IssueStatus.IN_BACKOFF
        assert held.retry_after_seconds == 900
        assert len(fake_lego.invocations()) == 1, "the restart did not hammer lego"
        assert snap is not None
        assert snap.consecutive_failures == 1
        assert snap.error_code is AcmeErrorClass.INTERNAL

        clock.advance(INITIAL_BACKOFF)
        second.wake()
        recorded = await wait_attempts(lego_settings, second, 2)

        assert recorded.error_code is None
        assert recorded.consecutive_failures == 0
        assert recorded.attempts == 2
        assert store_has(public_store)
        assert installed_calls == [CERT]

    async def test_a_new_runner_does_not_reissue_a_certificate_that_is_installed(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        installed_calls: list[str],
    ) -> None:
        first = new_runner()
        await first_install(first, production_config, fake_lego, lego_settings)
        await first.aclose()

        second = new_runner()
        second.configure(production_config)
        second.start()
        await asyncio.sleep(0.3)

        assert len(fake_lego.invocations()) == 1
        assert installed_calls == [CERT]
        snap = second.snapshot().get(CERT)
        assert snap is not None
        assert snap.state is AcmeCertState.IDLE
        assert snap.installed is True

    async def test_a_crash_during_a_run_makes_the_next_process_wait(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        """``record_attempt_start`` is persisted first; an attempt with no outcome is held."""
        AcmeStateStore(lego_settings.acme_dir).record_attempt_start(
            CERT, now=NOW, names=[WILDCARD], directory=STAGING_URL, reason="missing"
        )
        fake_lego.succeed()
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await asyncio.sleep(0.2)

        assert fake_lego.invocations() == []
        assert runner.request_issue(CERT).status is IssueStatus.IN_BACKOFF

        clock.advance(INITIAL_BACKOFF)
        runner.wake()
        await wait_attempts(lego_settings, runner, 2)

        assert len(fake_lego.invocations()) == 1

    async def test_configure_retires_state_for_certificates_no_longer_declared(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        seeded = AcmeStateStore(lego_settings.acme_dir)
        for name in ("gone", CERT):
            seeded.record_attempt_start(
                name, now=NOW, names=[WILDCARD], directory=STAGING_URL, reason="missing"
            )
        runner = new_runner()

        runner.configure(staging_config)

        reloaded = AcmeStateStore(lego_settings.acme_dir)
        assert reloaded.certificate_names() == [CERT]
        assert reloaded.get("gone").pruned_at == NOW, "marked, not deleted"
        assert reloaded.get("gone").attempts == 1

    async def test_configuring_none_stops_scheduling_without_touching_state(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        await first_install(runner, staging_config, fake_lego, lego_settings)
        before = (lego_settings.acme_dir / STATE_FILENAME).read_bytes()

        runner.configure(None)
        runner.wake()
        await asyncio.sleep(0.2)

        snap = runner.snapshot()
        assert snap.configured is False
        assert snap.certificates == ()
        assert snap.directory is None
        assert runner.request_issue(CERT).status is IssueStatus.UNKNOWN_CERTIFICATE
        assert (lego_settings.acme_dir / STATE_FILENAME).read_bytes() == before


class TestStateError:
    async def test_an_unusable_state_file_is_reported_and_never_overwritten(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        state_path = lego_settings.acme_dir / STATE_FILENAME
        state_path.write_text('{"version": 7, "certificates": {}}')

        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await asyncio.sleep(0.2)

        assert runner.state_error is not None
        assert "unknown version 7" in runner.state_error
        assert state_path.read_text() == '{"version": 7, "certificates": {}}'
        assert fake_lego.invocations() == []
        snap = runner.snapshot()
        assert snap.state_error == runner.state_error
        cert = snap.get(CERT)
        assert cert is not None
        assert cert.state is AcmeCertState.FAILED
        assert cert.error_code is AcmeErrorClass.INTERNAL
        assert "unknown version 7" in (cert.error_excerpt or "")
        assert cert.readiness_codes == (f"public_cert_pending:{CERT}", "acme_failed:internal")

    async def test_a_repaired_file_recovers_without_a_restart(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        state_path = lego_settings.acme_dir / STATE_FILENAME
        state_path.write_text("garbage")
        fake_lego.succeed()

        with structlog.testing.capture_logs() as logs:
            runner = new_runner()
            runner.configure(staging_config)
            runner.start()
            await asyncio.sleep(0.1)
            runner.wake()
            assert runner.request_issue(CERT).status is IssueStatus.UNAVAILABLE
            runner.wake()
            await asyncio.sleep(0.1)
            assert fake_lego.invocations() == []

            state_path.write_text(json.dumps({"version": 1, "certificates": {}}))
            runner.wake()
            await wait_until(lambda: runner.state_error is None, what="the state to recover")
            recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.last_success_at == NOW
        assert len(fake_lego.invocations()) == 1
        assert runner.snapshot().state_error is None
        assert len([e for e in logs if e["event"] == "acme.runner.state_unusable"]) == 1
        assert any(e["event"] == "acme.runner.state_recovered" for e in logs)


# --- shutdown ---------------------------------------------------------------------------------


class TestShutdown:
    async def test_aclose_terminates_a_running_lego(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        fake_lego.configure(hang())
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_until(
            lambda: runner.running == CERT and bool(started_pids(fake_lego)),
            what="lego to be running",
        )
        (pid,) = started_pids(fake_lego)
        assert process_alive(pid)

        await runner.aclose()

        assert runner.running is None
        assert not process_alive(pid)

    async def test_aclose_kills_a_lego_that_ignores_sigterm(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(runner_module, "KILL_GRACE_SECONDS", 0.5)
        fake_lego.configure(hang(ignore_sigterm=True))
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_until(
            lambda: runner.running == CERT and bool(started_pids(fake_lego)),
            what="lego to be running",
        )
        await asyncio.sleep(0.5)  # let the fake install its SIGTERM handler
        (pid,) = started_pids(fake_lego)

        await runner.aclose()

        assert not process_alive(pid)

    async def test_aclose_is_idempotent_and_leaves_no_attempt_outcome(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        fake_lego.configure(hang())
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_until(lambda: runner.running == CERT, what="lego to start")

        await runner.aclose()
        await runner.aclose()

        recorded = entry(lego_settings)
        assert recorded.attempts == 1
        assert recorded.error_code is None, "a shutdown is not a failed attempt"
        assert recorded.last_success_at is None

    async def test_aclose_without_start_is_a_no_op(
        self, new_runner: RunnerFactory, staging_config: AcmeConfig
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)

        await runner.aclose()

        assert runner.running is None

    async def test_start_is_idempotent(
        self, new_runner: RunnerFactory, staging_config: AcmeConfig
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)

        first = runner.start()
        second = runner.start()

        assert first is second


# --- lego path permissions --------------------------------------------------------------------


class TestPermissions:
    async def test_the_lego_tree_is_made_owner_only_after_a_run_and_links_are_left_alone(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        tmp_path: Path,
    ) -> None:
        loose_dir = lego_settings.lego_path_dir / "accounts" / "stale"
        loose_dir.mkdir(parents=True)
        for directory in (lego_settings.lego_path_dir, loose_dir.parent, loose_dir):
            directory.chmod(0o755)
        loose_file = loose_dir / "account.json"
        loose_file.write_text("{}")
        loose_file.chmod(0o644)
        target = tmp_path / "outside-target"
        target.write_text("not lego's")
        target.chmod(0o644)
        link = lego_settings.lego_path_dir / "link-to-outside"
        link.symlink_to(target)
        runner = new_runner()

        with structlog.testing.capture_logs() as logs:
            await first_install(runner, staging_config, fake_lego, lego_settings)

        modes = {}
        for root, dirs, files in os.walk(lego_settings.lego_path_dir):
            for name in [*dirs, *files]:
                path = Path(root) / name
                if not path.is_symlink():
                    modes[path] = stat.S_IMODE(path.stat().st_mode)
        assert modes
        for path, mode in modes.items():
            assert mode == (0o700 if path.is_dir() else 0o600), path
        assert stat.S_IMODE(lego_settings.lego_path_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(lego_settings.acme_dir.stat().st_mode) == 0o700
        assert link.is_symlink()
        assert stat.S_IMODE(target.stat().st_mode) == 0o644
        assert any(e["event"] == "acme.runner.permissions_tightened" for e in logs)

    async def test_state_json_is_private(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        await first_install(runner, staging_config, fake_lego, lego_settings)

        assert stat.S_IMODE((lego_settings.acme_dir / STATE_FILENAME).stat().st_mode) == 0o600


# --- snapshot ---------------------------------------------------------------------------------


class TestSnapshot:
    async def test_an_unconfigured_runner_has_an_empty_snapshot(
        self, new_runner: RunnerFactory
    ) -> None:
        snap = new_runner().snapshot()

        assert snap.configured is False
        assert snap.directory is None
        assert snap.staging is None
        assert snap.running is None
        assert snap.state_error is None
        assert snap.certificates == ()
        assert snap.get(CERT) is None

    async def test_a_configured_runner_reports_a_scheduled_pending_certificate(
        self, new_runner: RunnerFactory, staging_config: AcmeConfig
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)

        snap = runner.snapshot()
        cert = snap.get(CERT)

        assert snap.configured is True
        assert snap.directory == STAGING_URL
        assert snap.staging is True
        assert cert is not None
        assert cert.name == CERT
        assert cert.names == (WILDCARD,)
        assert cert.directory == STAGING_URL
        assert cert.staging is True
        assert cert.state is AcmeCertState.SCHEDULED
        assert cert.installed is False
        assert cert.installed_serial is None
        assert cert.last_attempt_at is None
        assert cert.last_success_at is None
        assert cert.error_code is None
        assert cert.consecutive_failures == 0
        assert cert.in_backoff is False
        assert cert.next_attempt_at == NOW
        assert cert.last_crash is None
        assert cert.permissions_problem is None
        assert snap.task_dead is False
        assert cert.readiness_codes == (f"public_cert_pending:{CERT}",)

    async def test_a_production_configuration_reports_the_production_directory(
        self, new_runner: RunnerFactory, production_config: AcmeConfig
    ) -> None:
        runner = new_runner()
        runner.configure(production_config)

        snap = runner.snapshot()

        assert snap.directory == PRODUCTION_URL
        assert snap.staging is False

    async def test_the_snapshot_names_the_running_certificate_and_its_state(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        fake_lego.configure(success(delay=0.5))
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_until(lambda: runner.running == CERT, what="lego to start")

        snap = runner.snapshot()

        assert snap.running == CERT
        cert = snap.get(CERT)
        assert cert is not None
        assert cert.state is AcmeCertState.ISSUING
        assert cert.last_attempt_at == NOW
        await wait_attempts(lego_settings, runner, 1)
        assert runner.snapshot().running is None

    async def test_a_queued_request_shows_as_scheduled(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        seeded = AcmeStateStore(lego_settings.acme_dir)
        seeded.record_attempt_start(
            CERT, now=NOW, names=[WILDCARD], directory=STAGING_URL, reason="missing"
        )
        seeded.record_success(CERT, now=NOW, next_attempt_at=NOW + 12 * HOUR, installed=False)
        runner = new_runner()
        runner.configure(staging_config)
        before = runner.snapshot().get(CERT)

        runner.request_issue(CERT)
        after = runner.snapshot().get(CERT)

        assert before is not None and after is not None
        assert before.state is AcmeCertState.DRY_RUN_OK
        assert after.state is AcmeCertState.SCHEDULED

    async def test_the_snapshot_is_immutable(
        self, new_runner: RunnerFactory, staging_config: AcmeConfig
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)
        snap = runner.snapshot()

        with pytest.raises(ValueError, match="frozen"):
            snap.configured = False  # type: ignore[misc]
        cert = snap.get(CERT)
        assert cert is not None
        with pytest.raises(ValueError, match="frozen"):
            cert.installed = True  # type: ignore[misc]


# --- additional runner cases ----------------------------------------------------------------------


class Switch:
    """A flag a monkeypatched seam reads; flip ``on`` in the middle of a test."""

    def __init__(self, on: bool = True) -> None:
        self.on = on


@pytest.fixture
def crash_switch(monkeypatch: pytest.MonkeyPatch) -> Switch:
    """``build_argv`` raises ``RuntimeError("kaput")`` while ``switch.on``, else is the real one."""
    switch = Switch()
    real = runner_module.build_argv

    def maybe(*args: Any, **kwargs: Any) -> Any:
        if switch.on:
            raise RuntimeError("kaput")
        return real(*args, **kwargs)

    monkeypatch.setattr(runner_module, "build_argv", maybe)
    return switch


@pytest.fixture
def signal_spy(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Records ``kill`` of every signal sent to lego's process group (False: SIGTERM)."""
    calls: list[bool] = []
    real = runner_module._signal_group

    def spy(proc: asyncio.subprocess.Process, *, kill: bool) -> None:
        calls.append(kill)
        real(proc, kill=kill)

    monkeypatch.setattr(runner_module, "_signal_group", spy)
    return calls


async def close_quietly(runner: AcmeRunner) -> None:
    """``aclose`` a runner whose loop task died with an exception (``aclose`` re-raises it)."""
    with contextlib.suppress(Exception):
        await runner.aclose()


def api_certificate() -> AcmePublicCertificate:
    """A second ``source: acme`` certificate, ``api-host``."""
    return AcmePublicCertificate.model_validate(
        {"name": "api-host", "names": [f"api.{ZONE}"], "source": "acme"}
    )


class TestCrashHandling:
    """An unexpected exception in an attempt is a crash: logged, shown, backed off, never fatal."""

    async def test_a_crash_is_shown_as_an_internal_error_carrying_its_text(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        crash_switch: Switch,
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)

        snap = runner.snapshot().get(CERT)

        assert snap is not None
        assert snap.last_crash == "RuntimeError: kaput"
        assert snap.error_code is AcmeErrorClass.INTERNAL
        assert snap.error_excerpt == "RuntimeError: kaput"
        assert snap.state is AcmeCertState.BACKOFF
        assert snap.readiness_codes == (
            f"public_cert_pending:{CERT}",
            "acme_failed:internal",
            "acme_backoff",
        )
        assert entry(lego_settings).error_code is None, "a crash is in memory, not a failure record"

    async def test_the_cooldown_grows_with_each_consecutive_crash(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        crash_switch: Switch,
        clock: Clock,
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)

        with structlog.testing.capture_logs() as logs:
            runner.start()
            delays = [timedelta(minutes=15), timedelta(minutes=30), HOUR, 2 * HOUR]
            for crashes, delay in enumerate(delays, start=1):
                await wait_attempts(lego_settings, runner, crashes)
                snap = runner.snapshot().get(CERT)
                assert snap is not None
                assert snap.next_attempt_at == clock.now + delay, f"crash {crashes}"
                assert snap.in_backoff is True
                if crashes < len(delays):
                    clock.advance(delay)
                    runner.wake()

        assert delays == [backoff_delay(n) for n in (1, 2, 3, 4)]
        crashed = events(logs, "acme.runner.attempt_crashed")
        assert [e["consecutive_crashes"] for e in crashed] == [1, 2, 3, 4]
        assert {e["error_type"] for e in crashed} == {"RuntimeError"}

    async def test_a_crashing_certificate_is_not_retried_before_its_cooldown(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        crash_switch: Switch,
        clock: Clock,
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)

        clock.advance(INITIAL_BACKOFF - timedelta(seconds=1))
        runner.wake()
        await asyncio.sleep(0.2)

        assert entry(lego_settings).attempts == 1
        assert fake_lego.invocations() == []

    async def test_a_success_resets_the_crash_count_and_clears_the_note(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        crash_switch: Switch,
        clock: Clock,
    ) -> None:
        fake_lego.succeed()
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)
        clock.advance(backoff_delay(1))
        runner.wake()
        await wait_attempts(lego_settings, runner, 2)
        clock.advance(backoff_delay(2))
        crash_switch.on = False
        runner.wake()
        await wait_attempts(lego_settings, runner, 3)

        healed = runner.snapshot().get(CERT)

        assert healed is not None
        assert healed.last_crash is None
        assert healed.error_code is None
        assert healed.state is AcmeCertState.DRY_RUN_OK
        crash_switch.on = True
        assert runner.request_issue(CERT).accepted
        await wait_attempts(lego_settings, runner, 4)
        again = runner.snapshot().get(CERT)
        assert again is not None
        assert again.last_crash == "RuntimeError: kaput"
        assert again.next_attempt_at == clock.now + backoff_delay(1), "the count started over"

    async def test_the_crash_note_is_redacted_and_bounded(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def kaput(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError(f"bad token={TOKEN_SENTINEL} " + "x" * 2000)

        monkeypatch.setattr(runner_module, "build_argv", kaput)
        runner = new_runner()
        runner.configure(staging_config)

        with structlog.testing.capture_logs() as logs:
            runner.start()
            await wait_attempts(lego_settings, runner, 1)
            snap = runner.snapshot().get(CERT)

        assert snap is not None
        assert snap.last_crash is not None
        assert len(snap.last_crash) <= 512
        assert "[redacted]" in snap.last_crash
        assert TOKEN_SENTINEL not in snap.model_dump_json()
        assert TOKEN_SENTINEL not in json.dumps(logs, default=str)

    async def test_a_crash_for_one_certificate_does_not_stop_the_others(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        acme_cert: AcmePublicCertificate,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        real = runner_module.build_argv

        def selective(settings: AcmeSettings, cert: AcmePublicCertificate, **kwargs: Any) -> Any:
            if cert.name == CERT:
                raise RuntimeError("kaput")
            return real(settings, cert, **kwargs)

        monkeypatch.setattr(runner_module, "build_argv", selective)
        fake_lego.succeed(rsa_hierarchy().issue((f"api.{ZONE}",)))
        runner = new_runner()
        runner.configure(
            dataclasses.replace(staging_config, certificates=(acme_cert, api_certificate()))
        )
        runner.start()

        await wait_attempts(lego_settings, runner, 1, "api-host")

        crashed = runner.snapshot().get(CERT)
        done = runner.snapshot().get("api-host")
        assert crashed is not None and done is not None
        assert crashed.last_crash == "RuntimeError: kaput"
        assert done.state is AcmeCertState.DRY_RUN_OK
        assert done.last_crash is None

    async def test_the_loop_survives_a_crash(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        crash_switch: Switch,
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)

        task = runner.start()
        await wait_attempts(lego_settings, runner, 1)

        assert not task.done()
        assert runner.snapshot().task_dead is False

    async def test_a_crash_leaves_requests_unaccepted_while_the_cooldown_runs(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        crash_switch: Switch,
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)

        outcome = runner.request_issue(CERT)

        assert outcome.status is IssueStatus.IN_BACKOFF
        assert outcome.reason == "backoff"
        assert outcome.error_code == "internal"
        assert outcome.retry_after_seconds == 900


class TestInstallResilience:
    async def test_a_state_write_that_fails_after_the_install_still_notifies_and_recovers(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
        installed_calls: list[str],
        clock: Clock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fail = Switch()
        real = AcmeStateStore.record_success

        def flaky(self: AcmeStateStore, name: str, **kwargs: Any) -> Any:
            if fail.on and kwargs.get("installed"):
                raise OSError("disk full")
            return real(self, name, **kwargs)

        monkeypatch.setattr(AcmeStateStore, "record_success", flaky)
        step = fake_lego.succeed()
        runner = new_runner()
        runner.configure(production_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)

        crashed = runner.snapshot().get(CERT)

        assert installed_calls == [CERT], "the store already serves the pair; the pass must hear"
        assert installed_pair(public_store) == (step["crt"].encode(), step["key"].encode())
        assert entry(lego_settings).installed_serial is None, "the record never landed"
        assert crashed is not None
        assert "OSError: disk full" in (crashed.last_crash or "")
        assert crashed.error_code is AcmeErrorClass.INTERNAL

        fail.on = False
        clock.advance(backoff_delay(1))
        runner.wake()
        recorded = await wait_attempts(lego_settings, runner, 2)

        assert recorded.installed_serial == serial_of(step)
        assert installed_calls == [CERT, CERT], "the record was missing: told of the install again"
        healed = runner.snapshot().get(CERT)
        assert healed is not None
        assert healed.last_crash is None
        assert healed.error_code is None


class TestReloadPending:
    """A store that could not delete the previous generation: noted in memory, swept each step."""

    @pytest.fixture
    def pending_store(
        self, public_store: MaterialStore, monkeypatch: pytest.MonkeyPatch
    ) -> dict[str, Any]:
        control: dict[str, Any] = {"pending": True, "gc_failures": 1, "gc_calls": []}
        real_install = public_store.install
        real_gc = public_store.gc

        def install(name: str, cert_pem: bytes, key_pem: bytes) -> Any:
            result = real_install(name, cert_pem, key_pem)
            return dataclasses.replace(result, reload_pending=control["pending"])

        def gc(name: str | None = None) -> list[str]:
            control["gc_calls"].append(name)
            if len(control["gc_calls"]) <= control["gc_failures"]:
                raise StoreError("cannot delete the previous generation")
            return real_gc(name)

        monkeypatch.setattr(public_store, "install", install)
        monkeypatch.setattr(public_store, "gc", gc)
        return control

    async def test_an_install_awaiting_the_gateway_is_an_internal_note_not_a_failure_record(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        pending_store: dict[str, Any],
    ) -> None:
        pending_store["gc_failures"] = 10**6
        runner = new_runner()
        await first_install(runner, production_config, fake_lego, lego_settings)

        snap = runner.snapshot().get(CERT)
        forced = runner.request_issue(CERT, force=True)

        assert snap is not None
        assert snap.error_code is AcmeErrorClass.INTERNAL
        assert snap.error_excerpt == RELOAD_PENDING_EXCERPT == "installed; gateway has not reloaded"
        assert snap.readiness_codes == ("acme_failed:internal",)
        assert entry(lego_settings).error_code is None, "nothing is persisted"
        assert forced.status is IssueStatus.IN_BACKOFF
        assert forced.error_code == "internal"

    async def test_the_store_is_swept_again_on_every_loop_step_until_it_succeeds(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        pending_store: dict[str, Any],
    ) -> None:
        pending_store["gc_failures"] = 3
        runner = new_runner()

        with structlog.testing.capture_logs() as logs:
            await first_install(runner, production_config, fake_lego, lego_settings)
            for expected in (1, 2, 3):
                await wait_until(
                    lambda expected=expected: len(pending_store["gc_calls"]) >= expected,
                    what=f"sweep {expected}",
                )
                pending = runner.snapshot().get(CERT)
                assert pending is not None
                assert pending.error_code is AcmeErrorClass.INTERNAL
                runner.wake()
            await wait_until(
                lambda: (c := runner.snapshot().get(CERT)) is not None and c.error_code is None,
                what="the sweep to succeed",
            )

        assert set(pending_store["gc_calls"]) == {CERT}, "only this certificate's directory"
        assert len(pending_store["gc_calls"]) == 4
        failed = events(logs, "acme.runner.store_gc_failed")
        assert len(failed) == 3
        assert {e["error_type"] for e in failed} == {"StoreError"}
        assert len(events(logs, "acme.runner.store_gc_cleared")) == 1

    async def test_the_loop_retries_on_its_own_while_a_sweep_is_pending(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        pending_store: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The sleep is capped at ``RELOAD_RETRY_SECONDS`` instead of the 12 h check."""
        monkeypatch.setattr(runner_module, "RELOAD_RETRY_SECONDS", 0.05)
        pending_store["gc_failures"] = 2
        runner = new_runner()

        await first_install(runner, production_config, fake_lego, lego_settings)

        await wait_until(
            lambda: (c := runner.snapshot().get(CERT)) is not None and c.error_code is None,
            what="the loop to sweep without being woken",
        )
        assert len(pending_store["gc_calls"]) == 3

    async def test_a_new_runner_does_not_inherit_the_note(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        pending_store: dict[str, Any],
    ) -> None:
        pending_store["gc_failures"] = 10**6
        first = new_runner()
        await first_install(first, production_config, fake_lego, lego_settings)
        await first.aclose()

        second = new_runner()
        second.configure(production_config)

        snap = second.snapshot().get(CERT)
        assert snap is not None
        assert snap.error_code is None


class TestStoreInvalid:
    async def test_marking_the_store_invalid_forces_a_reinstall_when_lego_has_nothing_new(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
        installed_calls: list[str],
    ) -> None:
        runner = new_runner()
        step = await first_install(runner, production_config, fake_lego, lego_settings)
        fake_lego.succeed()  # lego says "not due" and writes nothing

        runner.mark_store_invalid(CERT)
        recorded = await wait_attempts(lego_settings, runner, 2)

        assert recorded.renewal_reason == "missing"
        assert installed_pair(public_store)[0] == step["crt"].encode()
        assert installed_calls == [CERT, CERT], "the reconciler is told to render it again"
        idle = runner.snapshot().get(CERT)
        assert idle is not None
        assert idle.state is AcmeCertState.IDLE

    async def test_marking_is_idempotent_and_ignores_unknown_names(
        self, new_runner: RunnerFactory, production_config: AcmeConfig
    ) -> None:
        runner = new_runner()
        runner.mark_store_invalid(CERT)  # before configuration: ignored
        runner.configure(production_config)

        with structlog.testing.capture_logs() as logs:
            runner.mark_store_invalid("not-declared")
            runner.mark_store_invalid(CERT)
            runner.mark_store_invalid(CERT)

        (event,) = events(logs, "acme.runner.store_marked_invalid")
        assert event["certificate"] == CERT

    async def test_a_certificate_that_left_the_configuration_is_forgotten(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        acme_cert: AcmePublicCertificate,
        installed_calls: list[str],
    ) -> None:
        """Declaring it again later must not carry a stale "invalid" mark."""
        runner = new_runner()
        await first_install(runner, production_config, fake_lego, lego_settings)
        runner.mark_store_invalid(CERT)
        await wait_attempts(lego_settings, runner, 2)  # the reinstall consumed the mark
        fake_lego.succeed()
        runner.mark_store_invalid(CERT)
        runner.configure(dataclasses.replace(production_config, certificates=()))
        runner.configure(production_config)

        await asyncio.sleep(0.3)

        assert entry(lego_settings).attempts == 2, "the mark was dropped with the declaration"


class TestConfigChangedDuringRun:
    @pytest.mark.parametrize("how", ["none", "emptied"])
    async def test_a_certificate_that_left_the_configuration_mid_run_is_not_landed(
        self,
        how: str,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
        installed_calls: list[str],
    ) -> None:
        fake_lego.configure(success(delay=0.6))
        runner = new_runner()
        runner.configure(production_config)
        runner.start()
        await wait_until(lambda: runner.running == CERT, what="lego to start")

        runner.configure(
            None if how == "none" else dataclasses.replace(production_config, certificates=())
        )
        with structlog.testing.capture_logs() as logs:
            recorded = await wait_attempts(lego_settings, runner, 1)

        assert events(logs, "acme.runner.config_changed_during_run")
        assert not store_has(public_store)
        assert installed_calls == []
        assert recorded.last_success_at is None
        assert recorded.error_code is None, "neither a success nor a failure was recorded"
        assert recorded.installed_serial is None

    async def test_a_certificate_still_declared_after_a_config_change_is_landed(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        production_settings: AcmeSettings,
        public_store: MaterialStore,
    ) -> None:
        fake_lego.configure(success(delay=0.6))
        runner = new_runner()
        runner.configure(production_config)
        runner.start()
        await wait_until(lambda: runner.running == CERT, what="lego to start")

        runner.configure(
            dataclasses.replace(
                production_config,
                settings=production_settings.model_copy(update={"propagation": "authoritative"}),
            )
        )
        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.installed_serial is not None
        assert store_has(public_store)


class TestUnknownProvenance:
    """lego files with no recorded directory (state lost or never written) are not trusted."""

    @staticmethod
    def plant(settings: GwopsSettings, url: str, suffixes: tuple[str, ...]) -> Path:
        certs = settings.lego_storage_dir(url) / "certificates"
        certs.mkdir(parents=True)
        for suffix in suffixes:
            (certs / f"{CERT}{suffix}").write_text("planted, not lego's\n")
        return certs

    async def test_planted_files_are_removed_before_the_first_attempt(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        certs = self.plant(lego_settings, STAGING_URL, (".crt", ".key", ".json"))
        fake_lego.succeed()
        runner = new_runner()
        runner.configure(staging_config)

        with structlog.testing.capture_logs() as logs:
            runner.start()
            recorded = await wait_attempts(lego_settings, runner, 1)

        (reset,) = events(logs, "acme.runner.lego_material_reset")
        assert reset["reason"] == "unknown_provenance"
        assert reset["removed"] == [".crt", ".key", ".json"]
        assert recorded.error_code is None
        assert "planted" not in (certs / f"{CERT}.crt").read_text(), "lego wrote a fresh order"

    async def test_in_production_a_planted_pair_is_never_installed(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        public_store: MaterialStore,
    ) -> None:
        self.plant(lego_settings, PRODUCTION_URL, (".crt", ".key", ".json", ".issuer.crt"))
        step = fake_lego.succeed()
        runner = new_runner()
        runner.configure(production_config)
        runner.start()

        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.installed_serial == serial_of(step)
        assert installed_pair(public_store)[0] == step["crt"].encode()

    async def test_nothing_is_logged_when_there_is_nothing_to_remove(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        fake_lego.succeed()
        runner = new_runner()
        runner.configure(staging_config)

        with structlog.testing.capture_logs() as logs:
            runner.start()
            await wait_attempts(lego_settings, runner, 1)

        assert events(logs, "acme.runner.lego_material_reset") == []

    async def test_files_are_kept_when_the_recorded_directory_is_the_same_path(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        """A second attempt has a recorded directory: lego's own files are not reset."""
        fake_lego.succeed()
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)
        certs = lego_settings.lego_storage_dir(STAGING_URL) / "certificates"
        before = (certs / f"{CERT}.crt").read_bytes()

        with structlog.testing.capture_logs() as logs:
            runner.request_issue(CERT)
            await wait_attempts(lego_settings, runner, 2)

        assert events(logs, "acme.runner.lego_material_reset") == []
        assert (certs / f"{CERT}.crt").read_bytes() == before


class TestStillDue:
    async def test_a_clean_run_that_leaves_the_certificate_still_due_backs_off(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        original = AcmeRunner._immediate_reason

        def due_after_success(self: AcmeRunner, cfg: Any, cert: Any, recorded: Any) -> str | None:
            if recorded.last_success_at is not None:
                return "missing"  # as if the success had not satisfied the plan
            return original(self, cfg, cert, recorded)

        monkeypatch.setattr(AcmeRunner, "_immediate_reason", due_after_success)
        fake_lego.succeed()
        runner = new_runner()
        runner.configure(staging_config)

        with structlog.testing.capture_logs() as logs:
            runner.start()
            recorded = await wait_attempts(lego_settings, runner, 1)
            runner.wake()
            await asyncio.sleep(0.2)

        assert STILL_DUE_EXCERPT == "lego exited 0 but the certificate is still due"
        assert recorded.error_code is AcmeErrorClass.INTERNAL
        assert recorded.error_excerpt == STILL_DUE_EXCERPT
        assert recorded.consecutive_failures == 1
        assert recorded.last_success_at == NOW, "the clean exit itself was recorded"
        assert recorded.next_attempt_at == NOW + INITIAL_BACKOFF
        assert events(logs, "acme.runner.still_due_after_success")
        assert len(fake_lego.invocations()) == 1, "no tight loop on lego"
        snap = runner.snapshot().get(CERT)
        assert snap is not None
        assert snap.state is AcmeCertState.BACKOFF
        assert snap.error_code is AcmeErrorClass.INTERNAL


class TestTaskDeath:
    async def test_a_loop_that_raises_marks_the_runner_dead_and_logs_the_error(
        self,
        new_runner: RunnerFactory,
        staging_config: AcmeConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def explode(self: AcmeRunner) -> None:
            raise RuntimeError("loop exploded")

        monkeypatch.setattr(AcmeRunner, "run", explode)
        runner = new_runner()
        runner.configure(staging_config)

        with structlog.testing.capture_logs() as logs:
            task = runner.start()
            await wait_until(task.done, what="the loop to die")
            await asyncio.sleep(0)

        assert runner.snapshot().task_dead is True
        (event,) = events(logs, "acme.runner.task_died")
        assert event["error_type"] == "RuntimeError"
        assert event["error"] == "loop exploded"
        assert event["log_level"] == "error"
        await close_quietly(runner)

    async def test_a_loop_that_simply_returns_is_dead_too(
        self,
        new_runner: RunnerFactory,
        staging_config: AcmeConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def returns(self: AcmeRunner) -> None:
            return None

        monkeypatch.setattr(AcmeRunner, "run", returns)
        runner = new_runner()
        runner.configure(staging_config)

        with structlog.testing.capture_logs() as logs:
            task = runner.start()
            await wait_until(task.done, what="the loop to return")
            await asyncio.sleep(0)

        assert runner.snapshot().task_dead is True
        (event,) = events(logs, "acme.runner.task_died")
        assert event["error_type"] is None
        assert event["error"] == "loop returned"
        await close_quietly(runner)

    async def test_an_unconfigured_runner_reports_it_too(
        self, new_runner: RunnerFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def explode(self: AcmeRunner) -> None:
            raise RuntimeError("loop exploded")

        monkeypatch.setattr(AcmeRunner, "run", explode)
        runner = new_runner()

        task = runner.start()
        await wait_until(task.done, what="the loop to die")
        await asyncio.sleep(0)

        snap = runner.snapshot()
        assert snap.configured is False
        assert snap.task_dead is True
        await close_quietly(runner)

    async def test_the_error_text_is_redacted_and_bounded(
        self,
        new_runner: RunnerFactory,
        staging_config: AcmeConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def explode(self: AcmeRunner) -> None:
            raise RuntimeError(f"bad token={TOKEN_SENTINEL} " + "y" * 3000)

        monkeypatch.setattr(AcmeRunner, "run", explode)
        runner = new_runner()
        runner.configure(staging_config)

        with structlog.testing.capture_logs() as logs:
            task = runner.start()
            await wait_until(task.done, what="the loop to die")
            await asyncio.sleep(0)

        (event,) = events(logs, "acme.runner.task_died")
        assert TOKEN_SENTINEL not in json.dumps(logs, default=str)
        assert len(event["error"]) <= 512
        await close_quietly(runner)

    async def test_a_cancelled_loop_is_a_shutdown_not_a_death(
        self,
        new_runner: RunnerFactory,
        staging_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()

        with structlog.testing.capture_logs() as logs:
            await runner.aclose()
            await asyncio.sleep(0)

        assert runner.snapshot().task_dead is False
        assert events(logs, "acme.runner.task_died") == []

    async def test_starting_again_after_a_death_replaces_the_task_and_clears_the_flag(
        self,
        new_runner: RunnerFactory,
        staging_config: AcmeConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        real_run = AcmeRunner.run
        calls: list[int] = []

        async def die_once(self: AcmeRunner) -> None:
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("loop exploded")
            await real_run(self)

        monkeypatch.setattr(AcmeRunner, "run", die_once)
        runner = new_runner()
        runner.configure(staging_config)
        first = runner.start()
        await wait_until(first.done, what="the first loop to die")
        await asyncio.sleep(0)
        assert runner.snapshot().task_dead is True

        second = runner.start()

        assert second is not first
        assert runner.snapshot().task_dead is False
        await asyncio.sleep(0.1)
        assert not second.done()


class TestSpawnCancellation:
    async def test_cancelling_during_the_spawn_kills_the_process_it_creates(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        signal_spy: list[bool],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake_lego.configure(hang(ignore_sigterm=True))
        real_spawn = asyncio.create_subprocess_exec

        async def slow_spawn(*args: Any, **kwargs: Any) -> Any:
            proc = await real_spawn(*args, **kwargs)
            await asyncio.sleep(1.5)  # the runner is cancelled while this is pending
            return proc

        monkeypatch.setattr(asyncio, "create_subprocess_exec", slow_spawn)
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_until(
            lambda: runner.running == CERT and bool(started_pids(fake_lego)),
            what="lego to be spawned",
        )
        (pid,) = started_pids(fake_lego)

        await runner.aclose()

        assert runner.running is None
        await wait_until(
            lambda: not process_alive(pid), timeout=15.0, what="the orphaned lego to be killed"
        )
        assert signal_spy == [True], "SIGKILL to the group, with no grace period"
        recorded = entry(lego_settings)
        assert recorded.attempts == 1
        assert recorded.error_code is None, "a shutdown is not a failed attempt"


class TestGroupKill:
    async def test_a_timeout_stops_lego_and_the_processes_it_started(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        fake_lego.configure(hang(spawn_child=True))
        runner = new_runner(settings=fast(lego_settings, 2.0))
        runner.configure(staging_config)
        runner.start()
        await wait_until(lambda: child_pid(fake_lego) is not None, what="lego's child to start")
        pid = child_pid(fake_lego)
        assert pid is not None
        assert process_alive(pid)

        recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.error_code is AcmeErrorClass.TIMEOUT
        await wait_until(lambda: not process_alive(pid), what="lego's child to stop")

    async def test_shutdown_stops_the_whole_group_even_if_lego_ignores_sigterm(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(runner_module, "KILL_GRACE_SECONDS", 0.5)
        fake_lego.configure(hang(spawn_child=True, ignore_sigterm=True))
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_until(
            lambda: child_pid(fake_lego) is not None and runner.running == CERT,
            what="lego's child to start",
        )
        await asyncio.sleep(0.5)  # let the fake install its SIGTERM handler
        pid = child_pid(fake_lego)
        assert pid is not None

        await runner.aclose()

        await wait_until(lambda: not process_alive(pid), what="lego's child to stop")


class TestSignalDeath:
    @pytest.mark.parametrize("number", [9, 15])
    async def test_a_lego_killed_by_a_signal_is_internal_and_names_the_signal(
        self,
        number: int,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        fake_lego.configure(signal_death(number))
        runner = new_runner()
        runner.configure(staging_config)

        with structlog.testing.capture_logs() as logs:
            runner.start()
            recorded = await wait_attempts(lego_settings, runner, 1)

        assert recorded.error_code is AcmeErrorClass.INTERNAL
        assert (recorded.error_excerpt or "").startswith(f"terminated by signal {number}: ")
        assert recorded.consecutive_failures == 1
        assert recorded.next_attempt_at == NOW + INITIAL_BACKOFF
        (call,) = fake_lego.invocations()
        assert call.exit_code is None
        (exited,) = events(logs, "acme.runner.lego_exited")
        assert exited["exit_code"] == -number
        assert exited["timed_out"] is False


class TestPruneRetention:
    @staticmethod
    def seed(settings: GwopsSettings, *names: str) -> None:
        seeded = AcmeStateStore(settings.acme_dir)
        for name in names:
            seeded.record_attempt_start(
                name, now=NOW, names=[WILDCARD], directory=STAGING_URL, reason="missing"
            )

    async def test_a_dropped_certificate_is_kept_for_a_week_then_deleted(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        self.seed(lego_settings, "gone", CERT)
        runner = new_runner()
        runner.configure(staging_config)
        assert AcmeStateStore(lego_settings.acme_dir).get("gone").pruned_at == NOW

        clock.advance(PRUNE_RETENTION - timedelta(seconds=1))
        runner.configure(staging_config)
        assert AcmeStateStore(lego_settings.acme_dir).get("gone").attempts == 1, "still kept"

        clock.advance(timedelta(seconds=1))
        runner.configure(staging_config)
        document = json.loads((lego_settings.acme_dir / STATE_FILENAME).read_text())
        assert sorted(document["certificates"]) == [CERT]

    async def test_redeclaring_it_inside_the_week_restores_its_history(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        self.seed(lego_settings, "gone", CERT)
        gone = AcmePublicCertificate.model_validate(
            {"name": "gone", "names": [WILDCARD], "source": "acme"}
        )
        runner = new_runner()
        runner.configure(staging_config)
        clock.advance(timedelta(days=3))

        runner.configure(
            dataclasses.replace(
                staging_config, certificates=(*staging_config.certificates, gone)
            )
        )

        restored = AcmeStateStore(lego_settings.acme_dir)
        assert restored.get("gone").pruned_at is None
        assert restored.get("gone").attempts == 1
        assert restored.certificate_names() == [CERT, "gone"]

    async def test_a_queued_request_does_not_survive_a_retirement(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        seeded = AcmeStateStore(lego_settings.acme_dir)
        seeded.record_attempt_start(
            CERT, now=NOW, names=[WILDCARD], directory=STAGING_URL, reason="missing"
        )
        seeded.record_success(CERT, now=NOW, next_attempt_at=NOW + 12 * HOUR, installed=False)
        runner = new_runner()
        runner.configure(staging_config)
        clock.advance(REQUEST_FLOOR)
        assert runner.request_issue(CERT).accepted
        scheduled = runner.snapshot().get(CERT)
        assert scheduled is not None and scheduled.state is AcmeCertState.SCHEDULED

        runner.configure(dataclasses.replace(staging_config, certificates=()))
        assert runner.request_issue(CERT).status is IssueStatus.UNKNOWN_CERTIFICATE
        runner.configure(staging_config)

        back = runner.snapshot().get(CERT)
        assert back is not None
        assert back.state is AcmeCertState.DRY_RUN_OK, "the request was dropped with the entry"

    async def test_a_failed_prune_is_logged_and_does_not_break_configuration(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        self.seed(lego_settings, "gone", CERT)

        def boom(self: AcmeStateStore, declared: Any, *, now: datetime) -> list[str]:
            raise OSError("read-only file system")

        monkeypatch.setattr(AcmeStateStore, "prune", boom)
        runner = new_runner()

        with structlog.testing.capture_logs() as logs:
            runner.configure(staging_config)

        (event,) = events(logs, "acme.runner.prune_failed")
        assert event["error_type"] == "OSError"
        assert runner.snapshot().configured is True


class TestFixedBackoff:
    """Operator-fixable failures stop waiting when the configuration or the token changes."""

    @staticmethod
    async def fail_first(
        new_runner: RunnerFactory,
        fake: FakeLego,
        settings: GwopsSettings,
        config: AcmeConfig,
        kind: str,
        **options: Any,
    ) -> AcmeRunner:
        fake.configure(failure(kind, **options), success())
        runner = new_runner()
        runner.configure(config)
        runner.start()
        await wait_attempts(settings, runner, 1)
        return runner

    @pytest.mark.parametrize("kind", ["dns_auth", "dns_zone", "config"])
    async def test_a_replaced_token_file_ends_the_backoff_at_once(
        self,
        kind: str,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        lego_token: TokenFile,
        staging_config: AcmeConfig,
    ) -> None:
        with structlog.testing.capture_logs() as logs:
            runner = await self.fail_first(
                new_runner, fake_lego, lego_settings, staging_config, kind
            )
            assert runner.request_issue(CERT).status is IssueStatus.IN_BACKOFF

            lego_token.path.write_text("a-replacement-token-that-is-a-different-size\n")
            runner.wake()
            recorded = await wait_attempts(lego_settings, runner, 2)

        assert recorded.error_code is None
        assert recorded.consecutive_failures == 0
        (cleared,) = events(logs, "acme.runner.backoff_cleared")
        assert cleared["certificate"] == CERT
        assert cleared["reason"] == "token_file_changed"

    @pytest.mark.parametrize("kind", ["dns_zone", "config"])
    async def test_a_changed_configuration_ends_the_backoff_at_once(
        self,
        kind: str,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        with structlog.testing.capture_logs() as logs:
            runner = await self.fail_first(
                new_runner, fake_lego, lego_settings, staging_config, kind
            )
            changed = dataclasses.replace(
                staging_config,
                settings=staging_config.settings.model_copy(
                    update={"propagation": "authoritative"}
                ),
            )

            runner.configure(changed)
            recorded = await wait_attempts(lego_settings, runner, 2)

        assert recorded.error_code is None
        assert fake_lego.invocations()[1].has("--dns.propagation.disable-ans") is False
        (cleared,) = events(logs, "acme.runner.backoff_cleared")
        assert cleared["reason"] == "config_changed"

    async def test_a_changed_certificate_declaration_ends_the_backoff(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        acme_cert: AcmePublicCertificate,
    ) -> None:
        runner = await self.fail_first(
            new_runner, fake_lego, lego_settings, staging_config, "dns_zone"
        )
        widened = acme_cert.model_copy(update={"names": [WILDCARD, ZONE]})
        fake_lego.succeed(rsa_hierarchy().issue((WILDCARD, ZONE)))

        runner.configure(dataclasses.replace(staging_config, certificates=(widened,)))
        recorded = await wait_attempts(lego_settings, runner, 2)

        assert recorded.error_code is None
        assert recorded.names == [WILDCARD, ZONE]

    @pytest.mark.parametrize(
        "kind", ["internal", "unauthorized", "rate_limited", "acme_unreachable", "dns_propagation"]
    )
    async def test_other_failures_keep_waiting_when_the_token_changes(
        self,
        kind: str,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        lego_token: TokenFile,
        staging_config: AcmeConfig,
    ) -> None:
        runner = await self.fail_first(new_runner, fake_lego, lego_settings, staging_config, kind)

        lego_token.path.write_text("a-replacement-token-that-is-a-different-size\n")
        runner.wake()
        await asyncio.sleep(0.3)

        assert len(fake_lego.invocations()) == 1
        assert entry(lego_settings).consecutive_failures == 1

    @pytest.mark.parametrize("kind", ["internal", "unauthorized", "rate_limited"])
    async def test_other_failures_keep_waiting_when_the_configuration_changes(
        self,
        kind: str,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        runner = await self.fail_first(new_runner, fake_lego, lego_settings, staging_config, kind)
        changed = dataclasses.replace(
            staging_config,
            settings=staging_config.settings.model_copy(update={"propagation": "authoritative"}),
        )

        runner.configure(changed)
        await asyncio.sleep(0.3)

        assert len(fake_lego.invocations()) == 1
        assert entry(lego_settings).consecutive_failures == 1

    async def test_configuring_the_same_thing_again_changes_nothing(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        runner = await self.fail_first(
            new_runner, fake_lego, lego_settings, staging_config, "dns_auth"
        )

        runner.configure(dataclasses.replace(staging_config))
        runner.wake()
        await asyncio.sleep(0.3)

        assert len(fake_lego.invocations()) == 1
        assert runner.request_issue(CERT).status is IssueStatus.IN_BACKOFF

    async def test_a_change_to_another_certificate_does_not_clear_this_ones_backoff(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        acme_cert: AcmePublicCertificate,
    ) -> None:
        api = api_certificate()
        both = dataclasses.replace(staging_config, certificates=(acme_cert, api))
        fake_lego.configure(failure("dns_auth"), success(rsa_hierarchy().issue((f"api.{ZONE}",))))
        runner = new_runner()
        runner.configure(both)
        runner.start()
        await wait_attempts(lego_settings, runner, 1, CERT)
        await wait_attempts(lego_settings, runner, 1, "api-host")
        widened = api.model_copy(update={"names": [f"api.{ZONE}", f"www.{ZONE}"]})

        runner.configure(dataclasses.replace(staging_config, certificates=(acme_cert, widened)))
        await asyncio.sleep(0.3)

        assert runner.request_issue(CERT).status is IssueStatus.IN_BACKOFF
        assert entry(lego_settings).consecutive_failures == 1

    async def test_a_token_replaced_while_gwops_was_down_is_not_noticed(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        lego_token: TokenFile,
        staging_config: AcmeConfig,
    ) -> None:
        """The comparison baseline is in memory: a restart takes the current token as the base."""
        first = await self.fail_first(
            new_runner, fake_lego, lego_settings, staging_config, "dns_auth"
        )
        await first.aclose()
        lego_token.path.write_text("a-replacement-token-that-is-a-different-size\n")

        second = new_runner()
        second.configure(staging_config)
        second.start()
        await asyncio.sleep(0.3)

        assert len(fake_lego.invocations()) == 1
        assert second.request_issue(CERT).status is IssueStatus.IN_BACKOFF

    async def test_a_cleared_backoff_still_leaves_force_unable_to_skip_a_new_failure(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        lego_token: TokenFile,
        staging_config: AcmeConfig,
    ) -> None:
        fake_lego.fail("dns_auth")
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)

        lego_token.path.write_text("a-replacement-token-that-is-a-different-size\n")
        runner.wake()
        await wait_attempts(lego_settings, runner, 2)

        again = runner.request_issue(CERT, force=True)
        assert again.status is IssueStatus.IN_BACKOFF, "the second failure has its own backoff"
        assert again.reason == "backoff"
        assert entry(lego_settings).consecutive_failures == 1

    async def test_a_failed_clear_is_logged_and_the_loop_goes_on(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        lego_token: TokenFile,
        staging_config: AcmeConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = await self.fail_first(
            new_runner, fake_lego, lego_settings, staging_config, "dns_auth"
        )

        def boom(self: AcmeStateStore, name: str) -> bool:
            raise OSError("read-only file system")

        monkeypatch.setattr(AcmeStateStore, "clear_backoff", boom)
        lego_token.path.write_text("a-replacement-token-that-is-a-different-size\n")

        with structlog.testing.capture_logs() as logs:
            runner.wake()
            await asyncio.sleep(0.3)

        (event,) = events(logs, "acme.runner.backoff_clear_failed")
        assert event["certificate"] == CERT
        assert event["error_type"] == "OSError"
        assert len(fake_lego.invocations()) == 1


class TestRequestLimits:
    """The 24 h force window, the 60 s request floor and what a refusal reports."""

    async def test_a_forced_production_issue_is_refused_for_a_day_after_an_install(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        runner = new_runner()
        await first_install(runner, production_config, fake_lego, lego_settings)

        refused = runner.request_issue(CERT, force=True)
        clock.advance(FORCE_WINDOW - timedelta(seconds=1))
        almost = runner.request_issue(CERT, force=True)

        assert refused.status is IssueStatus.IN_BACKOFF
        assert refused.reason == "force_window"
        assert refused.retry_after_seconds == int(FORCE_WINDOW.total_seconds())
        assert "24 h" in refused.detail
        assert "plain request is accepted" in refused.detail
        assert almost.status is IssueStatus.IN_BACKOFF
        assert almost.retry_after_seconds == 1
        assert entry(lego_settings).last_request_at is None
        assert len(fake_lego.invocations()) == 1

    async def test_a_forced_issue_is_accepted_once_the_day_has_passed(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        runner = new_runner()
        await first_install(runner, production_config, fake_lego, lego_settings)
        fake_lego.succeed()
        clock.advance(FORCE_WINDOW)

        outcome = runner.request_issue(CERT, force=True)
        await wait_attempts(lego_settings, runner, 2)

        assert outcome.accepted
        assert fake_lego.invocations()[1].has("--renew-force")

    async def test_a_plain_request_is_not_held_by_the_force_window(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        await first_install(runner, production_config, fake_lego, lego_settings)

        assert runner.request_issue(CERT).accepted

    async def test_the_force_window_is_for_production_only(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        seeded = AcmeStateStore(lego_settings.acme_dir)
        seeded.record_attempt_start(
            CERT, now=NOW, names=[WILDCARD], directory=STAGING_URL, reason="missing"
        )
        seeded.record_success(
            CERT, now=NOW, next_attempt_at=None, installed=True, serial="ab", fingerprint="cd"
        )
        runner = new_runner()
        runner.configure(staging_config)

        outcome = runner.request_issue(CERT, force=True)

        assert outcome.accepted

    async def test_a_second_request_inside_sixty_seconds_is_refused_with_the_seconds_left(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)

        first = runner.request_issue(CERT)
        second = runner.request_issue(CERT)
        clock.advance(timedelta(seconds=59))
        third = runner.request_issue(CERT)
        clock.advance(timedelta(seconds=1))
        fourth = runner.request_issue(CERT)

        assert first.accepted
        assert second.status is IssueStatus.IN_BACKOFF
        assert second.reason == "request_floor"
        assert second.retry_after_seconds == int(REQUEST_FLOOR.total_seconds()) == 60
        assert "60 s" in second.detail
        assert third.reason == "request_floor"
        assert third.retry_after_seconds == 1
        assert fourth.accepted

    async def test_the_floor_applies_to_forced_requests_and_to_staging(
        self,
        new_runner: RunnerFactory,
        staging_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)
        assert runner.request_issue(CERT).accepted

        outcome = runner.request_issue(CERT, force=True)

        assert outcome.status is IssueStatus.IN_BACKOFF
        assert outcome.reason == "request_floor"

    async def test_the_accepted_request_is_stamped_in_state_json(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)

        runner.request_issue(CERT)

        assert entry(lego_settings).last_request_at == NOW

    async def test_the_floor_survives_a_restart(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        first = new_runner()
        first.configure(staging_config)
        assert first.request_issue(CERT).accepted

        second = new_runner()
        second.configure(staging_config)

        outcome = second.request_issue(CERT)
        assert outcome.status is IssueStatus.IN_BACKOFF
        assert outcome.reason == "request_floor"

    async def test_the_floor_outlives_the_attempt_the_request_started(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        fake_lego.succeed()
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)
        assert runner.request_issue(CERT).accepted
        await wait_attempts(lego_settings, runner, 2)

        outcome = runner.request_issue(CERT)

        assert outcome.reason == "request_floor"

    async def test_the_latest_applicable_hold_is_the_one_reported(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        production_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        runner = new_runner()
        await first_install(runner, production_config, fake_lego, lego_settings)
        assert runner.request_issue(CERT).accepted
        await wait_attempts(lego_settings, runner, 2)
        clock.advance(timedelta(seconds=10))

        outcome = runner.request_issue(CERT, force=True)

        assert outcome.reason == "force_window", "24 h outlasts the 60 s floor"
        assert outcome.retry_after_seconds == int(FORCE_WINDOW.total_seconds()) - 10

    async def test_a_failure_backoff_outlasts_the_floor_in_the_report(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        fake_lego.fail("internal")
        runner = new_runner()
        runner.configure(staging_config)
        assert runner.request_issue(CERT).accepted
        runner.start()
        await wait_attempts(lego_settings, runner, 1)
        clock.advance(timedelta(seconds=30))

        outcome = runner.request_issue(CERT)

        assert outcome.reason == "backoff"
        assert outcome.retry_after_seconds == 900 - 30
        assert outcome.error_code == "internal"

    async def test_the_outcome_carries_the_current_error_class_even_when_accepted(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        fake_lego.fail("dns_auth")
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)
        clock.advance(INITIAL_BACKOFF)

        outcome = runner.request_issue(CERT)

        assert outcome.accepted
        assert outcome.error_code == "dns_auth"

    async def test_an_outcome_for_a_healthy_certificate_has_no_error_code(
        self,
        new_runner: RunnerFactory,
        staging_config: AcmeConfig,
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)

        assert runner.request_issue(CERT).error_code is None

    async def test_a_running_certificate_reports_the_error_class_of_its_last_failure(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        clock: Clock,
    ) -> None:
        fake_lego.configure(failure("unauthorized"), success(delay=0.6))
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)
        clock.advance(INITIAL_BACKOFF)
        runner.wake()
        await wait_until(lambda: runner.running == CERT, what="the retry to start")

        outcome = runner.request_issue(CERT)

        assert outcome.status is IssueStatus.ALREADY_RUNNING
        assert outcome.error_code == "unauthorized"
        await wait_attempts(lego_settings, runner, 2)

    async def test_a_state_file_that_cannot_be_written_refuses_and_queues_nothing(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def boom(self: AcmeStateStore, name: str, *, now: datetime) -> None:
            raise OSError("read-only file system")

        monkeypatch.setattr(AcmeStateStore, "record_request", boom)
        fake_lego.succeed()
        runner = new_runner()
        runner.configure(staging_config)

        with structlog.testing.capture_logs() as logs:
            outcome = runner.request_issue(CERT, force=True)

        assert outcome.status is IssueStatus.UNAVAILABLE
        assert "cannot be written" in outcome.detail
        (event,) = events(logs, "acme.runner.request_not_persisted")
        assert event["error_type"] == "OSError"
        runner.start()
        recorded = await wait_attempts(lego_settings, runner, 1)
        assert recorded.renewal_reason == "missing", "the refused request was never queued"
        assert not fake_lego.invocations()[0].has("--renew-force")

    async def test_a_crash_cooldown_is_reported_as_a_backoff(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        crash_switch: Switch,
    ) -> None:
        runner = new_runner()
        runner.configure(staging_config)
        runner.start()
        await wait_attempts(lego_settings, runner, 1)

        outcome = runner.request_issue(CERT, force=True)

        assert outcome.reason == "backoff"
        assert outcome.error_code == "internal"


class TestQueuedRequestState:
    async def test_a_queued_request_shows_as_scheduled_even_after_a_failure(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
    ) -> None:
        seeded = AcmeStateStore(lego_settings.acme_dir)
        seeded.record_attempt_start(
            CERT, now=NOW - 2 * HOUR, names=[WILDCARD], directory=STAGING_URL, reason="missing"
        )
        seeded.record_failure(
            CERT, now=NOW - 2 * HOUR, error_class=AcmeErrorClass.DNS_AUTH, excerpt="403"
        )
        runner = new_runner()
        runner.configure(staging_config)
        before = runner.snapshot().get(CERT)

        assert runner.request_issue(CERT).accepted
        after = runner.snapshot().get(CERT)

        assert before is not None and after is not None
        assert before.state is AcmeCertState.FAILED
        assert after.state is AcmeCertState.SCHEDULED, "the queued request outranks the old error"
        assert after.error_code is AcmeErrorClass.DNS_AUTH, "the error stays visible"


class TestStartupLog:
    async def test_the_start_event_says_whether_the_lego_binary_exists(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        fake_lego: FakeLego,
    ) -> None:
        with structlog.testing.capture_logs() as logs:
            present = new_runner()
            present.start()
            await wait_until(
                lambda: bool(events(logs, "acme.runner.started")), what="the start event"
            )
        (event,) = events(logs, "acme.runner.started")
        assert event["lego_binary"] == fake_lego.binary.as_posix()
        assert event["lego_binary_exists"] is True

    async def test_a_missing_binary_is_reported_but_does_not_stop_the_loop(
        self,
        new_runner: RunnerFactory,
        lego_settings: GwopsSettings,
        tmp_path: Path,
    ) -> None:
        missing = lego_settings.model_copy(update={"lego_binary": tmp_path / "no-such-lego"})

        with structlog.testing.capture_logs() as logs:
            runner = new_runner(settings=missing)
            task = runner.start()
            await wait_until(
                lambda: bool(events(logs, "acme.runner.started")), what="the start event"
            )

        (event,) = events(logs, "acme.runner.started")
        assert event["lego_binary_exists"] is False
        assert not task.done()


class TestPermissionsProblem:
    @pytest.fixture
    def chmod_fails(self, monkeypatch: pytest.MonkeyPatch) -> set[str]:
        """``os.chmod`` raises ``PermissionError`` for every path (``os.fspath``) in the set."""
        blocked: set[str] = set()
        real = os.chmod

        def selective(path: Any, mode: int, **kwargs: Any) -> None:
            if os.fspath(path) in blocked:
                raise PermissionError(1, "operation not permitted", str(path))
            real(path, mode, **kwargs)

        monkeypatch.setattr(runner_module.os, "chmod", selective)
        return blocked

    async def test_a_directory_that_cannot_be_restricted_is_reported_and_logged(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        chmod_fails: set[str],
    ) -> None:
        storage = lego_settings.lego_storage_dir(STAGING_URL)
        chmod_fails.add(os.fspath(storage))
        runner = new_runner()

        with structlog.testing.capture_logs() as logs:
            await first_install(runner, staging_config, fake_lego, lego_settings)

        snap = runner.snapshot().get(CERT)
        assert snap is not None
        assert snap.permissions_problem is not None
        assert f"cannot restrict permissions of {storage}" in snap.permissions_problem
        unfixable = events(logs, "acme.runner.permissions_unfixable")
        assert unfixable
        assert {e["path"] for e in unfixable} == {os.fspath(storage)}
        assert {e["error_type"] for e in unfixable} == {"PermissionError"}
        assert {e["log_level"] for e in unfixable} == {"error"}

    async def test_the_problem_clears_on_the_next_attempt_once_it_is_fixed(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        chmod_fails: set[str],
        clock: Clock,
    ) -> None:
        chmod_fails.add(os.fspath(lego_settings.lego_storage_dir(STAGING_URL)))
        runner = new_runner()
        await first_install(runner, staging_config, fake_lego, lego_settings)
        broken = runner.snapshot().get(CERT)
        assert broken is not None and broken.permissions_problem is not None

        chmod_fails.clear()
        clock.advance(REQUEST_FLOOR)
        assert runner.request_issue(CERT).accepted
        await wait_attempts(lego_settings, runner, 2)

        fixed = runner.snapshot().get(CERT)
        assert fixed is not None
        assert fixed.permissions_problem is None

    async def test_unfixable_files_are_counted_and_only_the_first_few_are_logged(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        chmod_fails: set[str],
    ) -> None:
        loose = lego_settings.lego_storage_dir(STAGING_URL) / "accounts" / "old"
        loose.mkdir(parents=True)
        for number in range(8):
            path = loose / f"loose-{number}.json"
            path.write_text("{}")
            path.chmod(0o644)
            chmod_fails.add(os.fspath(path))
        runner = new_runner()

        with structlog.testing.capture_logs() as logs:
            await first_install(runner, staging_config, fake_lego, lego_settings)

        snap = runner.snapshot().get(CERT)
        assert snap is not None
        assert snap.permissions_problem is not None
        assert snap.permissions_problem.startswith("cannot restrict permissions of ")
        assert snap.permissions_problem.endswith(" and 7 more")
        assert "loose-" in snap.permissions_problem
        unfixable = events(logs, "acme.runner.permissions_unfixable")
        assert len(unfixable) == 5, "the log is limited; the snapshot carries the count"

    async def test_one_unfixable_file_is_named_without_a_count(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        chmod_fails: set[str],
    ) -> None:
        loose = lego_settings.lego_storage_dir(STAGING_URL) / "accounts" / "old" / "loose.json"
        loose.parent.mkdir(parents=True)
        loose.write_text("{}")
        loose.chmod(0o644)
        chmod_fails.add(os.fspath(loose))
        runner = new_runner()

        await first_install(runner, staging_config, fake_lego, lego_settings)

        snap = runner.snapshot().get(CERT)
        assert snap is not None
        assert snap.permissions_problem == f"cannot restrict permissions of {loose}"

    async def test_the_problem_is_runner_wide_and_never_carries_the_token(
        self,
        new_runner: RunnerFactory,
        fake_lego: FakeLego,
        lego_settings: GwopsSettings,
        staging_config: AcmeConfig,
        acme_cert: AcmePublicCertificate,
        chmod_fails: set[str],
    ) -> None:
        chmod_fails.add(os.fspath(lego_settings.lego_storage_dir(STAGING_URL)))
        fake_lego.succeed()
        runner = new_runner()
        runner.configure(
            dataclasses.replace(staging_config, certificates=(acme_cert, api_certificate()))
        )
        runner.start()
        await wait_attempts(lego_settings, runner, 1)

        snapshot = runner.snapshot()

        problems = {c.permissions_problem for c in snapshot.certificates}
        assert len(problems) == 1 and None not in problems
        assert TOKEN_SENTINEL not in snapshot.model_dump_json()
