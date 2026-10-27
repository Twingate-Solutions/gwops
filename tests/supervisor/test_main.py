"""Tests for gwops.supervisor.main.bootstrap: the PID-1 startup gate.

``bootstrap`` performs the fail-loud startup sequence (probe -> load -> rotation
recovery -> ensure CAs -> first ``reconcile("startup")``), with a degraded start for an
upstream-less seed and X.509 rotation crash recovery before the CA is ensured. The
populated-seed path (TG sync, leaf, render, start) is the reconciler's first pass rather
than inline bootstrap code. The full signal-driven ``main()`` loop is not covered here.
"""

import asyncio
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import structlog.testing

import gwops.supervisor.main as main_module
from gwops.certs.manager import CertManager
from gwops.certs.public import RegisteredRootError
from gwops.configmodel.loader import ConfigLoadError
from gwops.jwks import JwksMonitor, JwksStatus
from gwops.reconciler.core import Reconciler
from gwops.settings import GwopsSettings
from gwops.shipper.counters import DropCounters, FailureLog
from gwops.shipper.filter import DropReason
from gwops.shipper.spool import Spool
from gwops.supervisor.main import BootstrapResult, bootstrap, run_drop_log, run_jwks_checks
from gwops.supervisor.process import ProcState
from tests.drops_support import expected_drops
from tests.spool_support import make_flaky
from tests.store_support import leaf_cert_path

_posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="requires POSIX signal semantics"
)

_POPULATED_SEED = """\
twingate:
  network: acme
  gateway_id: g-1
ssh_upstreams:
  - name: host1
    address: 10.0.0.5:22
"""

_EMPTY_SEED = """\
twingate:
  network: acme
  gateway_id: g-1
"""

_RECORDING_SECTION = """\
recording:
  enabled: true
  receiver_url: http://gatorcast.test:8000
"""


_SSH_RECORDING = (
    b'{"levelname":"info","logger":"session_recording","message":"session recording",'
    b'"conn_id":"c1",'
    b'"seq":1,"asciicast":"[0.1,\\"o\\",\\"ok\\"]"}'
)

# Odd spacing and raw UTF-8 survive: kept lines ship as the gateway's bytes.
_KEPT_LINES = [
    _SSH_RECORDING,
    b'{ "logger": "session_recording",  "asciicast": "caf\xc3\xa9" }',
    b'{"logger":"audit","message":"API request completed","method":"GET"}',
    b'{"logger":"audit","message":"API request failed","status":502}',
    b'{"logger":"system","message":"Authenticated connection","resource_type":"SSH"}',
]

_WEB_APP_AUTH = (
    b'{"logger":"system","message":"Authenticated connection","resource_type":"WEB_APP",'
    b'"resource_address":"wiki.corp.internal"}'
)


async def _recording_bootstrap(
    fake_gateway: Callable[..., Path], tmp_path: Path, *, token: str | None = "tok"
) -> tuple[BootstrapResult, Spool]:
    """Bootstrap with recording on and the gateway held down; stderr is fed by the tests."""
    settings = _settings(
        tmp_path,
        fake_gateway(stderr_ticks=False),
        _EMPTY_SEED + _RECORDING_SECTION,
        recording_token=token,
    )
    result = await bootstrap(settings)
    assert not result.gateway_started  # nothing but the tests writes to stderr
    assert result.spool is not None
    return result, result.spool


def _settings(
    tmp_path: Path, binary: Path, seed_text: str, *, recording_token: str | None = None
) -> GwopsSettings:
    seed = tmp_path / "seed.yaml"
    seed.write_text(seed_text, encoding="utf-8")
    return GwopsSettings(
        seed_path=seed,
        data_dir=tmp_path / "data",
        runtime_dir=tmp_path / "run",
        gateway_binary=binary,
        # Never let an ambient TWINGATE_API_KEY leak real HTTP calls into tests:
        # with no key the reconciler records a TG-sync error and stays local.
        # (The secrets are declared by alias, so the overrides must use the alias.)
        **{  # type: ignore[arg-type]
            "TWINGATE_API_KEY": None,
            "GWOPS_ADMIN_TOKEN": None,
            "GWOPS_RECORDING_TOKEN": recording_token,
        },
    )


class TestDegradedStart:
    async def test_empty_seed_does_not_start_gateway_or_mint_leaf(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _EMPTY_SEED)
        result = await bootstrap(settings)
        assert result.gateway_started is False
        assert result.process.state == ProcState.STOPPED
        # No leaf is mintable with an empty SAN set — and none was minted.
        assert not leaf_cert_path(settings.data_dir / "pki").exists()
        # But the CA material was still ensured, ready for the first upstream.
        assert (settings.data_dir / "pki" / "x509-ca.crt").exists()


class TestFailLoud:
    async def test_invalid_seed_raises_config_load_error(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), "twingate: {network: acme}\n")
        # Missing required gateway_id -> load fails loud rather than degrading.
        with pytest.raises(ConfigLoadError):
            await bootstrap(settings)

    async def test_web_app_policy_violations_abort_listing_every_one(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        seed = _POPULATED_SEED + (
            "web_apps:\n"
            "  - name: wiki\n"
            "    address: wiki.corp.internal\n"
            "    request_headers:\n"
            "      Cookie: cookie-value-that-must-not-be-logged\n"
            "  - name: legacy\n"
            "    address: legacy.corp.internal\n"
            "    upstream_tls: insecure\n"
        )
        settings = _settings(tmp_path, fake_gateway(), seed)

        with pytest.raises(ValueError, match="web-app policy refused") as excinfo:
            await bootstrap(settings)

        message = str(excinfo.value)
        assert "'wiki'" in message and "request_headers" in message
        assert "'legacy'" in message and "upstream_tls" in message
        assert "cookie-value-that-must-not-be-logged" not in message
        # Aborted before anything was written or started.
        assert not (settings.data_dir / "pki").exists()
        assert not (settings.runtime_dir / "config.yaml").exists()

    @_posix_only
    async def test_warnings_alone_do_not_abort(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        seed = _POPULATED_SEED + (
            "web_apps:\n"
            "  - name: grafana\n"
            "    address: grafana.corp.internal\n"
            "    upstream_tls: verify_ca\n"
        )
        settings = _settings(tmp_path, fake_gateway(), seed)

        result = await bootstrap(settings)

        assert result.gateway_started is True
        await result.process.stop(timeout=5.0)


class TestStartupFailureExit:
    async def test_missing_registered_root_logs_startup_failed_and_exits_1(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A public-mode seed whose registered root is absent from the trust store makes
        # bootstrap raise RegisteredRootError; main() must log it and exit 1, not traceback.
        async def failing_bootstrap(settings: GwopsSettings) -> BootstrapResult:
            raise RegisteredRootError("registered root 'isrg_root_x1' is not in the trust store")

        monkeypatch.setattr(main_module, "configure_logging", lambda: None)
        monkeypatch.setattr(main_module, "bootstrap", failing_bootstrap)

        with structlog.testing.capture_logs() as logs, pytest.raises(SystemExit) as excinfo:
            await main_module.main()

        assert excinfo.value.code == 1
        failed = [entry for entry in logs if entry["event"] == "supervisor.startup_failed"]
        assert len(failed) == 1
        assert "isrg_root_x1" in failed[0]["error"]

    async def test_registered_root_error_is_a_startup_error(self) -> None:
        assert RegisteredRootError in main_module._STARTUP_ERRORS


class TestRotationRecovery:
    async def test_recovers_interrupted_rotation_before_ensuring_ca(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        # Simulate a crash mid-completion with real CA material: a staged CA and its
        # rotation marker exist, but the default CA was already removed. Recovery must
        # promote the staged CA rather than generate a third one over the top.
        pki = tmp_path / "data" / "pki"
        mgr = CertManager(pki)
        mgr.ensure_x509_ca(generate=True)
        staged = mgr.stage_x509_rotation()
        staged_cert_pem = Path(staged.cert_path).read_text(encoding="utf-8")
        (pki / "staged" / ".rotation-stamp").write_text("20260722T000000Z", encoding="utf-8")
        (pki / "x509-ca.crt").unlink()
        (pki / "x509-ca.key").unlink()

        settings = _settings(tmp_path, fake_gateway(), _EMPTY_SEED)
        await bootstrap(settings)

        # The staged material was promoted to the default location by recovery, and
        # ensure_x509_ca then loaded it (did not generate a fresh CA over the top).
        assert (pki / "x509-ca.crt").read_text(encoding="utf-8") == staged_cert_pem
        assert not (pki / "staged" / "x509-ca.crt").exists()


class TestNormalStart:
    @_posix_only
    async def test_populated_seed_starts_gateway_mints_leaf_and_writes_config(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _POPULATED_SEED)
        result = await bootstrap(settings)
        try:
            assert result.gateway_started is True
            assert result.process.state == ProcState.RUNNING
            assert leaf_cert_path(settings.data_dir / "pki").exists()
            assert result.config_path.exists()
            # The rendered config carries the base identity; the leaf covers the SAN.
            assert "network: acme" in result.config_path.read_text(encoding="utf-8")
            leaf = leaf_cert_path(settings.data_dir / "pki").read_text(encoding="utf-8")
            assert "BEGIN CERTIFICATE" in leaf
        finally:
            await result.process.stop(timeout=5.0)


class TestReconcilerWiring:
    async def test_bootstrap_exposes_the_wired_reconciler_and_api_event(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _EMPTY_SEED)
        result = await bootstrap(settings)
        assert isinstance(result.reconciler, Reconciler)
        assert isinstance(result.api_event, asyncio.Event)
        # The startup pass already ran and left its outcome inspectable.
        assert result.reconciler.last_result is not None
        assert result.reconciler.last_result.trigger == "startup"

    @_posix_only
    async def test_degraded_start_self_heals_when_an_upstream_arrives(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        # The first upstream arriving after a degraded start mints the leaf and starts the
        # child.
        settings = _settings(tmp_path, fake_gateway(), _EMPTY_SEED)
        result = await bootstrap(settings)
        assert result.gateway_started is False
        try:
            settings.seed_path.write_text(_POPULATED_SEED, encoding="utf-8")
            outcome = await result.reconciler.reconcile("seed-change")
            assert result.process.state is ProcState.RUNNING
            assert any("started gateway" in a for a in outcome.actions)
        finally:
            await result.process.stop(timeout=5.0)

    async def test_bootstrap_builds_the_admin_app_wired_to_the_control_plane(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        # bootstrap constructs the FastAPI admin app (served by main());
        # its mutations must land in THIS bootstrap's store and set THIS api_event.
        import httpx

        settings = _settings(tmp_path, fake_gateway(), _EMPTY_SEED)
        result = await bootstrap(settings)
        assert result.admin_app is not None
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=result.admin_app), base_url="http://gwops"
        ) as client:
            # Degraded start: gateway held down -> composite health is 503.
            health = await client.get("/healthz")
            assert health.status_code == 503
            # No GWOPS_ADMIN_TOKEN in test env -> protected routes are locked.
            assert (await client.get("/state")).status_code == 401

    async def test_startup_gate_raises_when_local_steps_cannot_start_gateway(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        # A populated seed whose cluster credentials are missing is a local failure:
        # no config can be produced, so the fail-loud gate must abort, not degrade.
        seed = f"""\
twingate:
  network: acme
  gateway_id: g-1
k8s_clusters:
  - name: prod
    address: prod.k8s.internal
    port: 6443
    bearer_token_file: {(tmp_path / "missing.token").as_posix()}
    ca_file: {(tmp_path / "missing-ca.crt").as_posix()}
"""
        settings = _settings(tmp_path, fake_gateway(), seed)
        with pytest.raises(RuntimeError, match="missing.token"):
            await bootstrap(settings)


class TestRecordingWiring:
    """Recording routes stderr into the spool when recording is enabled."""

    async def test_recording_disabled_builds_neither_spool_nor_shipper(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _EMPTY_SEED, recording_token="tok")
        result = await bootstrap(settings)
        assert result.spool is None
        assert result.shipper is None
        assert result.admin_app.state.deps.spool is None

    async def test_stderr_content_echo_suppressed_even_when_recording_disabled(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        # The gateway emits recordings on stderr unconditionally, so gwops must
        # never mirror stderr content to its own stdout log — regardless of whether the
        # seed enables recording spooling/shipping.
        for seed in (_EMPTY_SEED, _EMPTY_SEED + _RECORDING_SECTION):
            settings = _settings(tmp_path, fake_gateway(), seed, recording_token="tok")
            result = await bootstrap(settings)
            assert result.process._echo_stderr_content is False

    async def test_recording_enabled_builds_spool_and_shipper(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        seed = _EMPTY_SEED + _RECORDING_SECTION
        settings = _settings(tmp_path, fake_gateway(), seed, recording_token="tok")
        result = await bootstrap(settings)
        assert result.spool is not None
        assert result.shipper is not None
        assert (settings.data_dir / "spool").is_dir()
        # The same objects are wired into the admin app for /status lag reporting.
        assert result.admin_app.state.deps.spool is result.spool
        assert result.admin_app.state.deps.shipper is result.shipper

    async def test_missing_recording_token_spools_but_does_not_ship(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        seed = _EMPTY_SEED + _RECORDING_SECTION
        settings = _settings(tmp_path, fake_gateway(), seed, recording_token=None)
        result = await bootstrap(settings)
        assert result.spool is not None
        assert result.shipper is None

    @_posix_only
    async def test_only_kept_lines_land_in_the_spool_and_the_rest_are_counted(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        replay = tmp_path / "stderr.ndjson"
        replay.write_text(_SSH_RECORDING.decode() + "\n" + "http: proxy error: boom\n", "utf-8")
        seed = _POPULATED_SEED + _RECORDING_SECTION
        binary = fake_gateway(stderr_file=replay, stderr_ticks=False)
        result = await bootstrap(_settings(tmp_path, binary, seed, recording_token="tok"))
        assert result.spool is not None
        try:
            async with asyncio.timeout(5.0):
                while result.drops.snapshot()["not_json"] < 1:
                    await asyncio.sleep(0.02)
        finally:
            await result.process.stop(timeout=5.0)
        batch, _ = result.spool.read_batch()
        assert batch == [_SSH_RECORDING.decode()]
        assert result.drops.snapshot() == expected_drops(not_json=1)

    @_posix_only
    async def test_real_shaped_fake_gateway_ticks_are_filtered_and_web_app_lines_enriched(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        seed = _POPULATED_SEED + _RECORDING_SECTION
        settings = _settings(tmp_path, fake_gateway(), seed, recording_token="tok")
        result = await bootstrap(settings)
        assert result.spool is not None
        try:
            async with asyncio.timeout(5.0):
                while result.drops.snapshot()["not_json"] < 2:
                    await asyncio.sleep(0.02)
        finally:
            await result.process.stop(timeout=5.0)
        batch, _ = result.spool.read_batch()
        objs = [json.loads(line) for line in batch]  # every spooled line is JSON
        kinds = {(o["logger"], o.get("message", "asciicast")) for o in objs}
        assert kinds == {
            ("system", "Authenticated connection"),
            ("audit", "API request completed"),
            ("session_recording", "session recording"),
        }
        auth = [o for o in objs if o.get("message") == "Authenticated connection"]
        assert auth
        assert all(o["gwops"]["match"] == "none" for o in auth)
        counts = result.drops.snapshot()
        assert counts["not_json"] >= 2
        assert counts["not_allowlisted"] >= 2
        assert counts["too_long"] == 0

    async def test_kept_lines_land_as_the_original_bytes(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result, spool = await _recording_bootstrap(fake_gateway, tmp_path)
        for line in _KEPT_LINES:
            result.process._on_stderr_line(line)
        batch, _ = spool.read_batch()
        assert [b.encode() for b in batch] == _KEPT_LINES
        assert result.drops.snapshot() == expected_drops()

    async def test_dropped_lines_are_counted_by_reason_and_never_spooled(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result, spool = await _recording_bootstrap(fake_gateway, tmp_path)
        for line in (
            b"http: proxy error: connection refused",
            b"\xff\xfe not utf-8",
            b'{"logger":"system","message":"Starting connect proxy"}',
            b'{"logger":"audit","message":"SSH connection established"}',
            b'{"logger":"audit","message":"API request completed","method":"GET"}'[:-1],
        ):
            result.process._on_stderr_line(line)
        result.process._count_stderr_too_long()
        assert spool.pending_lines == 0
        assert result.drops.snapshot() == expected_drops(not_json=3, not_allowlisted=2, too_long=1)

    async def test_web_app_lines_are_enriched_when_delivery_is_configured(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        # Enrichment needs receiver_url, not GWOPS_RECORDING_TOKEN.
        result, spool = await _recording_bootstrap(fake_gateway, tmp_path, token=None)
        assert result.shipper is None
        result.process._on_stderr_line(_WEB_APP_AUTH)
        [line] = spool.read_batch()[0]
        obj = json.loads(line)
        assert obj["gwops"] == {"schema": 1, "gateway_id": "g-1", "match": "none"}
        assert line.encode().startswith(_WEB_APP_AUTH[:-1])

    async def test_other_kept_lines_are_not_enriched(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result, spool = await _recording_bootstrap(fake_gateway, tmp_path)
        line = _WEB_APP_AUTH.replace(b"WEB_APP", b"SSH")
        result.process._on_stderr_line(line)
        assert spool.read_batch()[0] == [line.decode()]

    async def test_with_recording_disabled_nothing_is_filtered_or_counted(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        echoed: list[str] = []
        settings = _settings(tmp_path, fake_gateway(), _EMPTY_SEED, recording_token="tok")
        result = await bootstrap(settings, on_stderr_line=echoed.append)
        result.process._on_stderr_line(b"not json")
        result.process._on_stderr_line(_WEB_APP_AUTH)
        assert result.spool is None
        assert result.drops.snapshot() == expected_drops()
        assert echoed == ["not json", _WEB_APP_AUTH.decode()]

    async def test_the_stderr_callback_sees_every_line_whatever_the_filter_did(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        echoed: list[str] = []
        seed = _EMPTY_SEED + _RECORDING_SECTION
        settings = _settings(tmp_path, fake_gateway(), seed, recording_token="tok")
        result = await bootstrap(settings, on_stderr_line=echoed.append)
        for line in (b"plain text\r", _KEPT_LINES[0], b"\xffbad"):
            result.process._on_stderr_line(line)
        assert echoed == ["plain text", _KEPT_LINES[0].decode(), "�bad"]

    async def test_a_spool_failure_does_not_stop_the_stderr_callback(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        echoed: list[str] = []
        seed = _EMPTY_SEED + _RECORDING_SECTION
        settings = _settings(tmp_path, fake_gateway(), seed, recording_token="tok")
        result = await bootstrap(settings, on_stderr_line=echoed.append)
        assert result.spool is not None

        def full(_line: bytes) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(result.spool, "append", full)
        result.process._on_stderr_line(_KEPT_LINES[0])
        assert echoed == [_KEPT_LINES[0].decode()]

    @pytest.mark.parametrize("error", [OSError("disk full"), ValueError("closed file")])
    async def test_a_failed_spool_append_is_counted_and_logged_without_content(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        error: Exception,
    ) -> None:
        result, spool = await _recording_bootstrap(fake_gateway, tmp_path)

        def failing(_line: bytes) -> None:
            raise error

        monkeypatch.setattr(spool, "append", failing)
        with structlog.testing.capture_logs() as logs:
            for line in _KEPT_LINES[:3]:
                result.process._on_stderr_line(line)

        assert result.drops.snapshot() == expected_drops(spool_failed=3)
        [entry] = [e for e in logs if e["event"] == "shipper.spool_append_failed"]
        assert entry["log_level"] == "error"
        assert entry["error_type"] == type(error).__name__
        assert "asciicast" not in repr(entry) and str(error) not in repr(entry)

    async def test_spool_failures_are_logged_once_then_at_most_once_a_minute(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        now = [1000.0]
        monkeypatch.setattr(
            main_module,
            "FailureLog",
            lambda event: FailureLog(event, clock=lambda: now[0]),
        )
        result, spool = await _recording_bootstrap(fake_gateway, tmp_path)

        def failing(_line: bytes) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(spool, "append", failing)
        with structlog.testing.capture_logs() as logs:
            for at in (0.0, 10.0, 20.0, 61.0):
                now[0] = 1000.0 + at
                result.process._on_stderr_line(_KEPT_LINES[0])

        entries = [e for e in logs if e["event"] == "shipper.spool_append_failed"]
        assert [e.get("suppressed") for e in entries] == [None, 2]
        assert result.drops.snapshot()["spool_failed"] == 4

    async def test_a_write_failure_counts_the_buffered_lines_and_the_failing_one(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result, spool = await _recording_bootstrap(fake_gateway, tmp_path)
        for line in _KEPT_LINES[:3]:
            result.process._on_stderr_line(line)  # buffered, not flushed
        make_flaky(spool).fail_write = True

        result.process._on_stderr_line(_KEPT_LINES[3])

        assert result.drops.snapshot() == expected_drops(spool_failed=4)
        assert spool.pending_lines == 0

    async def test_a_flush_failure_counts_every_line_lost_with_it(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result, spool = await _recording_bootstrap(fake_gateway, tmp_path)
        spool._flush_every = 4
        for line in _KEPT_LINES[:2]:
            result.process._on_stderr_line(line)
        make_flaky(spool).fail_flush = True

        result.process._on_stderr_line(_KEPT_LINES[2])  # 3rd buffered, below the flush interval
        assert result.drops.snapshot() == expected_drops()
        result.process._on_stderr_line(_KEPT_LINES[3])  # 4th triggers the failing flush

        assert result.drops.snapshot() == expected_drops(spool_failed=4)
        assert spool.pending_lines == 0

    async def test_a_failed_flush_in_the_shipper_path_counts_the_lost_lines(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result, spool = await _recording_bootstrap(fake_gateway, tmp_path)
        for line in _KEPT_LINES[:3]:
            result.process._on_stderr_line(line)
        make_flaky(spool).fail_flush = True

        spool.flush()  # what read_batch does before reading

        assert result.drops.snapshot() == expected_drops(spool_failed=3)

    async def test_the_echo_decode_is_skipped_for_the_default_sink_only(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        decodes: list[int] = []

        class Spy(bytes):
            def decode(self, *args: Any, **kwargs: Any) -> str:
                decodes.append(1)
                return super().decode(*args, **kwargs)

        binary = fake_gateway(stderr_ticks=False)
        result = await bootstrap(_settings(tmp_path, binary, _EMPTY_SEED))
        result.process._on_stderr_line(Spy(b"plain text"))
        assert decodes == []

        echoed: list[str] = []
        result = await bootstrap(
            _settings(tmp_path, binary, _EMPTY_SEED), on_stderr_line=echoed.append
        )
        result.process._on_stderr_line(Spy(b"plain text"))
        assert decodes == [1]
        assert echoed == ["plain text"]

    async def test_the_reconciler_and_deps_share_the_bootstrap_index_and_counters(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result, _spool = await _recording_bootstrap(fake_gateway, tmp_path)
        assert result.reconciler._webapp_index is result.webapp_index
        assert result.admin_app.state.deps.drops is result.drops


class TestDropLog:
    """The periodic ``shipper.lines_dropped`` log: counts by reason, only on change."""

    async def _run_for(self, drops: DropCounters, seconds: float) -> list[dict[str, Any]]:
        with structlog.testing.capture_logs() as logs:
            task = asyncio.get_running_loop().create_task(run_drop_log(drops, 0.02))
            await asyncio.sleep(seconds)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            assert task.cancelled()
        return [e for e in logs if e["event"] == "shipper.lines_dropped"]

    async def test_logs_nothing_while_no_count_changed(self) -> None:
        assert await self._run_for(DropCounters(), 0.15) == []

    async def test_logs_the_counts_once_per_change_and_nothing_else(self) -> None:
        drops = DropCounters()
        drops.count(DropReason.NOT_JSON)
        drops.count(DropReason.NOT_JSON)
        drops.count(DropReason.TOO_LONG)
        entries = await self._run_for(drops, 0.15)
        assert entries == [
            {
                "event": "shipper.lines_dropped",
                "log_level": "info",
                "not_json": 2,
                "not_allowlisted": 0,
                "too_long": 1,
                "spool_failed": 0,
                "enrich_failed": 0,
            }
        ]

    async def test_logs_again_after_a_further_drop(self) -> None:
        drops = DropCounters()
        drops.count(DropReason.NOT_ALLOWLISTED)
        task = asyncio.get_running_loop().create_task(run_drop_log(drops, 0.02))
        with structlog.testing.capture_logs() as logs:
            await asyncio.sleep(0.1)
            drops.count(DropReason.NOT_ALLOWLISTED)
            await asyncio.sleep(0.1)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        counts = [e["not_allowlisted"] for e in logs if e["event"] == "shipper.lines_dropped"]
        assert counts == [1, 2]

    async def test_the_default_period_is_300_seconds(self) -> None:
        assert main_module._DROP_LOG_INTERVAL_SECONDS == 300.0

    async def test_enrichment_failures_are_in_the_log(self) -> None:
        drops = DropCounters()
        drops.count_enrich_failed()
        [entry] = await self._run_for(drops, 0.15)
        assert entry["enrich_failed"] == 1

    async def test_a_failing_pass_is_logged_and_the_loop_keeps_going(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        drops = DropCounters()
        drops.count(DropReason.NOT_JSON)
        real = main_module._log_drops
        calls: list[int] = []

        def flaky(counters: DropCounters) -> None:
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("log pipeline broke")
            real(counters)

        monkeypatch.setattr(main_module, "_log_drops", flaky)
        with structlog.testing.capture_logs() as logs:
            task = asyncio.get_running_loop().create_task(run_drop_log(drops, 0.02))
            await asyncio.sleep(0.2)
            assert not task.done()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        events = [e["event"] for e in logs]
        assert events.count("shipper.drop_log_failed") == 1
        assert events.count("shipper.lines_dropped") == 1
        assert task.cancelled()


class TestDropLogFinalFlush:
    async def test_teardown_logs_counts_that_changed_since_the_last_periodic_log(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result, _spool = await _recording_bootstrap(fake_gateway, tmp_path)
        result.drops.count(DropReason.NOT_JSON)
        result.drops.count(DropReason.SPOOL_FAILED)

        with structlog.testing.capture_logs() as logs:
            await main_module._teardown(result, admin=None)

        [entry] = [e for e in logs if e["event"] == "shipper.lines_dropped"]
        assert entry["not_json"] == 1 and entry["spool_failed"] == 1

    async def test_teardown_logs_nothing_when_nothing_changed(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result, _spool = await _recording_bootstrap(fake_gateway, tmp_path)
        result.drops.count(DropReason.NOT_JSON)
        assert result.drops.take_changed() is not None  # the periodic log already reported it

        with structlog.testing.capture_logs() as logs:
            await main_module._teardown(result, admin=None)

        assert [e for e in logs if e["event"] == "shipper.lines_dropped"] == []

    async def test_the_flush_comes_after_the_child_is_stopped(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result, _spool = await _recording_bootstrap(fake_gateway, tmp_path)

        async def stop() -> None:  # a line the child still emitted while draining
            result.drops.count(DropReason.TOO_LONG)
            result.process._state = ProcState.STOPPED

        result.process._state = ProcState.RUNNING
        result.process.stop = stop  # type: ignore[method-assign,assignment]

        with structlog.testing.capture_logs() as logs:
            await main_module._teardown(result, admin=None)

        [entry] = [e for e in logs if e["event"] == "shipper.lines_dropped"]
        assert entry["too_long"] == 1

    async def test_lines_lost_in_the_final_spool_flush_are_in_the_last_log(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result, spool = await _recording_bootstrap(fake_gateway, tmp_path)
        for line in _KEPT_LINES[:2]:
            result.process._on_stderr_line(line)  # buffered
        make_flaky(spool).fail_flush = True

        with structlog.testing.capture_logs() as logs:
            await main_module._teardown(result, admin=None)

        [entry] = [e for e in logs if e["event"] == "shipper.lines_dropped"]
        assert entry["spool_failed"] == 2

    async def test_the_drop_log_is_written_even_when_closing_the_spool_raises(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        result, spool = await _recording_bootstrap(fake_gateway, tmp_path)
        result.drops.count(DropReason.NOT_JSON)

        def failing_close() -> None:
            raise OSError("fsync failed")

        monkeypatch.setattr(spool, "close", failing_close)

        with structlog.testing.capture_logs() as logs, pytest.raises(OSError, match="fsync"):
            await main_module._teardown(result, admin=None)

        [entry] = [e for e in logs if e["event"] == "shipper.lines_dropped"]
        assert entry["not_json"] == 1


class TestShutdownSignal:
    async def test_teardown_flags_the_deps_before_anything_else_stops(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _EMPTY_SEED)
        result = await bootstrap(settings)
        assert result.deps is result.admin_app.state.deps
        assert result.deps is not None and not result.deps.shutting_down.is_set()

        await main_module._teardown(result, admin=None)

        assert result.deps.shutting_down.is_set()


class _StubMonitor:
    """Stands in for JwksMonitor: counts calls, then raises or hangs on demand."""

    def __init__(self, behaviour: str) -> None:
        self.behaviour = behaviour
        self.calls = 0
        self.running = 0
        self.max_running = 0
        self.marks: list[tuple[str, str]] = []

    def mark(self, error_class: str, reason: str) -> None:
        self.marks.append((error_class, reason))

    async def check(self) -> JwksStatus:
        self.calls += 1
        self.running += 1
        self.max_running = max(self.max_running, self.running)
        try:
            if self.behaviour == "raise":
                raise RuntimeError("probe exploded")
            if self.behaviour == "hang":
                await asyncio.Event().wait()
            await asyncio.sleep(0.05)
            raise RuntimeError("slow probe finished")
        finally:
            self.running -= 1


class TestJwksWiring:
    async def test_bootstrap_wires_a_monitor_for_the_tenant_url(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _EMPTY_SEED)
        result = await bootstrap(settings)
        try:
            assert isinstance(result.jwks, JwksMonitor)
            assert result.jwks._url == "https://acme.twingate.com/api/v1/jwk/ec"
            assert result.jwks.status is None  # main() schedules the first check
        finally:
            assert result.jwks_client is not None
            await result.jwks_client.aclose()

    async def test_a_failing_client_factory_leaves_jwks_unwired_and_never_aborts(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def broken() -> httpx.AsyncClient:
            raise OSError("no trust store at /secret/path")

        monkeypatch.setattr(main_module, "make_client", broken)
        settings = _settings(tmp_path, fake_gateway(), _EMPTY_SEED)
        with structlog.testing.capture_logs() as logs:
            result = await bootstrap(settings)
        assert result.jwks is None
        assert result.jwks_client is None
        assert result.admin_app.state.deps.jwks is None
        [entry] = [e for e in logs if e["event"] == "jwks.client_unavailable"]
        assert entry["error_type"] == "OSError"
        assert "/secret/path" not in repr(entry)

    async def test_a_raising_probe_neither_propagates_nor_stops_the_loop(self) -> None:
        monitor = _StubMonitor("raise")
        task = asyncio.get_running_loop().create_task(
            run_jwks_checks(monitor, 0.01)  # type: ignore[arg-type]
        )
        try:
            async with asyncio.timeout(5.0):
                while monitor.calls < 3:
                    await asyncio.sleep(0.01)
            assert not task.done()
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_a_hung_probe_is_cancelled_and_never_blocks_the_loop(self) -> None:
        monitor = _StubMonitor("hang")
        task = asyncio.get_running_loop().create_task(
            run_jwks_checks(monitor, 0.01, check_timeout=0.05)  # type: ignore[arg-type]
        )
        try:
            # The caller stays responsive while the probe hangs, and later checks still run.
            await asyncio.sleep(0)
            assert not task.done()
            async with asyncio.timeout(5.0):
                while monitor.calls < 2:
                    await asyncio.sleep(0.01)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        assert monitor.max_running == 1

    async def test_a_hung_probe_is_marked_degraded_with_a_check_timeout_reason(self) -> None:
        monitor = _StubMonitor("hang")
        task = asyncio.get_running_loop().create_task(
            run_jwks_checks(monitor, 0.01, check_timeout=0.05)  # type: ignore[arg-type]
        )
        try:
            async with asyncio.timeout(5.0):
                while not monitor.marks:
                    await asyncio.sleep(0.01)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        assert monitor.marks[0] == ("degraded", "check_timeout")

    async def test_a_raising_probe_is_not_marked(self) -> None:
        monitor = _StubMonitor("raise")
        task = asyncio.get_running_loop().create_task(
            run_jwks_checks(monitor, 0.01)  # type: ignore[arg-type]
        )
        try:
            async with asyncio.timeout(5.0):
                while monitor.calls < 2:
                    await asyncio.sleep(0.01)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        assert monitor.marks == []

    async def test_a_timeout_replaces_a_stale_ok_status_on_a_real_monitor(self) -> None:
        async def hang(_request: httpx.Request) -> httpx.Response:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        async with httpx.AsyncClient(transport=httpx.MockTransport(hang)) as client:
            monitor = JwksMonitor(client, "https://acme.twingate.com/api/v1/jwk/ec")
            stale = JwksStatus(ok=True, checked_at=datetime.now(UTC), error_class=None)
            monitor._status = stale
            task = asyncio.get_running_loop().create_task(
                run_jwks_checks(monitor, 60.0, check_timeout=0.05)
            )
            try:
                async with asyncio.timeout(5.0):
                    while monitor.status is stale:
                        await asyncio.sleep(0.01)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        assert monitor.status is not None
        assert (monitor.status.ok, monitor.status.error_class, monitor.status.reason) == (
            False, "degraded", "check_timeout",
        )

    async def test_checks_never_stack_and_cancel_cleanly(self) -> None:
        monitor = _StubMonitor("slow")
        task = asyncio.get_running_loop().create_task(
            run_jwks_checks(monitor, 0.0)  # type: ignore[arg-type]
        )
        await asyncio.sleep(0.2)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert task.cancelled()
        assert monitor.max_running == 1
        assert monitor.running == 0


_SYSTEM_AUTH_FULL = (
    b'{"levelname":"info","ts":"2026-10-27T10:00:00.000Z","logger":"system",'
    b'"caller":"frontend/conn.go:226","message":"Authenticated connection","version":"2.0.0",'
    b'"user":{"id":"u1","username":"u1","groups":["g1"]},"conn_id":"c1",'
    b'"resource_type":"WEB_APP","resource_address":"wiki.corp.internal"}'
)
_NEVER_RELAYED = [
    pytest.param(_SSH_RECORDING, id="session-recording"),
    pytest.param(b'{"logger":"audit","message":"API request completed"}', id="audit-http"),
    pytest.param(b'{"logger":"audit","message":"SSH connection established"}', id="audit-ssh"),
    pytest.param(
        b'{"logger":"system","message":"x","asciicast":"[0.1,\\"o\\",\\"secret\\"]"}',
        id="system-claiming-asciicast",
    ),
    pytest.param(b"plain text panic: boom", id="plain-text"),
    pytest.param(b'{"logger":"system","message":', id="truncated-json"),
    pytest.param(b"\xff\xfe{", id="invalid-utf8"),
    pytest.param(b'["logger","system"]', id="json-not-object"),
    pytest.param(b'{"message":"no logger"}', id="no-logger"),
]


class TestSystemLogRelay:
    """The gateway's `system` stderr lines reach gwops' stdout log; nothing else does."""

    @staticmethod
    def _relayed(logs: list[dict[str, object]]) -> list[dict[str, object]]:
        return [e for e in logs if e["event"] == "gateway.system"]

    async def test_a_system_line_is_relayed_with_every_gateway_field(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result, _ = await _recording_bootstrap(fake_gateway, tmp_path)
        with structlog.testing.capture_logs() as logs:
            result.process._on_stderr_line(_SYSTEM_AUTH_FULL)
        [entry] = self._relayed(logs)
        assert entry["log_level"] == "info"
        for key, value in json.loads(_SYSTEM_AUTH_FULL).items():
            assert entry[key] == value
        assert entry["user"] == {"id": "u1", "username": "u1", "groups": ["g1"]}

    async def test_the_relay_works_with_recording_disabled(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _EMPTY_SEED)
        result = await bootstrap(settings)
        assert result.spool is None
        with structlog.testing.capture_logs() as logs:
            result.process._on_stderr_line(_SYSTEM_AUTH_FULL)
        assert len(self._relayed(logs)) == 1

    async def test_a_gateway_field_cannot_overwrite_structlogs_own_keys(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result, _ = await _recording_bootstrap(fake_gateway, tmp_path)
        line = (
            b'{"logger":"system","levelname":"error","message":"m","event":"spoof",'
            b'"level":"spoof","timestamp":"spoof","exc_info":"spoof"}'
        )
        with structlog.testing.capture_logs() as logs:
            result.process._on_stderr_line(line)
        [entry] = self._relayed(logs)
        assert entry["event"] == "gateway.system"
        assert entry["log_level"] == "error"
        assert entry["gateway_event"] == "spoof"
        assert entry["gateway_level"] == "spoof"
        assert entry["gateway_timestamp"] == "spoof"
        assert entry["gateway_exc_info"] == "spoof"
        assert "exc_info" not in entry

    @pytest.mark.parametrize("line", _NEVER_RELAYED)
    async def test_other_lines_are_never_relayed(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, line: bytes
    ) -> None:
        result, _ = await _recording_bootstrap(fake_gateway, tmp_path)
        with structlog.testing.capture_logs() as logs:
            result.process._on_stderr_line(line)
        assert self._relayed(logs) == []
        text = line.decode("utf-8", errors="replace")
        assert all(text not in repr(e) for e in logs if e["event"] != "gateway.line")

    async def test_shipper_input_is_unchanged_by_the_relay(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result, spool = await _recording_bootstrap(fake_gateway, tmp_path)
        lines = [_SYSTEM_AUTH_FULL, b'{"logger":"system","message":"Starting HTTP proxy"}']
        lines += _KEPT_LINES
        with structlog.testing.capture_logs() as logs:
            for line in lines:
                result.process._on_stderr_line(line)
        assert len(self._relayed(logs)) == 3  # both system lines and the SSH auth line
        batch, _ = spool.read_batch()
        # Same kept set as without the relay; the full web-app auth line is enriched in place.
        assert len(batch) == len(_KEPT_LINES) + 1
        assert batch[1:] == [line.decode() for line in _KEPT_LINES]
        assert json.loads(batch[0])["gwops"]["match"] == "none"
        assert result.drops.snapshot() == expected_drops(not_allowlisted=1)

    async def test_a_relay_failure_does_not_stop_the_spool_or_callback(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        echoed: list[str] = []
        seed = _EMPTY_SEED + _RECORDING_SECTION
        settings = _settings(tmp_path, fake_gateway(), seed, recording_token="tok")
        result = await bootstrap(settings, on_stderr_line=echoed.append)
        assert result.spool is not None

        def boom(_raw: bytes) -> dict[str, object]:
            raise RuntimeError("parse bug")

        monkeypatch.setattr("gwops.supervisor.main.system_fields", boom)
        result.process._on_stderr_line(_SYSTEM_AUTH_FULL)
        assert echoed == [_SYSTEM_AUTH_FULL.decode()]
        assert result.spool.pending_lines == 1
