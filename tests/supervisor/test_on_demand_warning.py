"""The `tls.on_demand_issuance_active` startup warning of `ca.x509.on_demand_issuance`."""

import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import structlog.testing

from gwops.certs.on_demand import (
    ON_DEMAND_BROWSER_TRUST_WARNING,
    ON_DEMAND_BYO_TRUST_WARNING,
    ON_DEMAND_WARNING,
)
from gwops.supervisor.main import bootstrap
from tests.on_demand_support import (
    BASE_SEED,
    SSH_UPSTREAM_SEED,
    build_ca,
    ca_section,
    make_settings,
)

_EVENT = "tls.on_demand_issuance_active"

_posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="requires POSIX signal semantics"
)


def _active(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [entry for entry in logs if entry["event"] == _EVENT]


def _text(entry: dict[str, Any]) -> str:
    """Every value of the entry except the event name and level, joined."""
    return " ".join(str(v) for k, v in entry.items() if k not in ("event", "log_level"))


class TestModeOn:
    async def test_startup_logs_exactly_one_warning_event(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        """One tls.on_demand_issuance_active warning per startup, at warning level."""
        settings = make_settings(tmp_path, fake_gateway(), BASE_SEED + ca_section(on_demand=True))

        with structlog.testing.capture_logs() as logs:
            await bootstrap(settings)

        [entry] = _active(logs)
        assert entry["log_level"] == "warning"

    async def test_a_later_reconcile_pass_does_not_log_it_again(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        """The warning is a startup event, not a per-pass one."""
        settings = make_settings(tmp_path, fake_gateway(), BASE_SEED + ca_section(on_demand=True))

        with structlog.testing.capture_logs() as logs:
            result = await bootstrap(settings)
            await result.reconciler.reconcile("tick")
            await result.reconciler.reconcile("api")

        assert len(_active(logs)) == 1

    async def test_every_startup_logs_one(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        """A second bootstrap over the same data directory logs its own single warning."""
        settings = make_settings(tmp_path, fake_gateway(), BASE_SEED + ca_section(on_demand=True))

        with structlog.testing.capture_logs() as first:
            await bootstrap(settings)
        with structlog.testing.capture_logs() as second:
            await bootstrap(settings)

        assert len(_active(first)) == 1
        assert len(_active(second)) == 1

    @_posix_only
    async def test_a_startup_that_runs_the_gateway_still_logs_exactly_one(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        """A populated seed (first reconcile renders and starts the child) logs one warning."""
        settings = make_settings(
            tmp_path, fake_gateway(), SSH_UPSTREAM_SEED + ca_section(on_demand=True)
        )

        with structlog.testing.capture_logs() as logs:
            result = await bootstrap(settings)
        try:
            assert result.gateway_started is True
            assert len(_active(logs)) == 1
        finally:
            await result.process.stop(timeout=5.0)

    async def test_the_message_states_the_exposure(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        """The text says the gateway signs under the gwops X.509 CA for any SNI before auth."""
        settings = make_settings(tmp_path, fake_gateway(), BASE_SEED + ca_section(on_demand=True))

        with structlog.testing.capture_logs() as logs:
            await bootstrap(settings)

        text = _text(_active(logs)[0])
        assert re.search(r"X\.509 CA", text)
        assert re.search(r"any SNI", text, re.IGNORECASE)
        assert "8443" in text
        assert re.search(r"before .*authenticat", text, re.IGNORECASE | re.DOTALL)

    async def test_a_byo_ca_logs_the_escalated_text_status_shows(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        """A bring-your-own CA appends the trust-store escalation to the startup warning."""
        byo = build_ca(tmp_path / "byo")
        seed = BASE_SEED + ca_section(on_demand=True, byo=byo)
        settings = make_settings(tmp_path, fake_gateway(), seed)

        with structlog.testing.capture_logs() as logs:
            await bootstrap(settings)

        [entry] = _active(logs)
        assert entry["reason"] == ON_DEMAND_WARNING + ON_DEMAND_BYO_TRUST_WARNING

    async def test_a_generated_ca_with_a_tls13_web_app_logs_the_escalated_text(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        """A generated CA plus a tls13 web app appends the browser-trust escalation."""
        web_app = "web_apps:\n  - name: grafana\n    address: grafana.corp.internal\n"
        settings = make_settings(
            tmp_path, fake_gateway(), BASE_SEED + web_app + ca_section(on_demand=True)
        )

        with structlog.testing.capture_logs() as logs:
            await bootstrap(settings)

        [entry] = _active(logs)
        assert entry["reason"] == ON_DEMAND_WARNING + ON_DEMAND_BROWSER_TRUST_WARNING

    async def test_a_plain_generated_ca_logs_the_base_text(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        """Without either escalation the log is the base warning."""
        settings = make_settings(tmp_path, fake_gateway(), BASE_SEED + ca_section(on_demand=True))

        with structlog.testing.capture_logs() as logs:
            await bootstrap(settings)

        [entry] = _active(logs)
        assert entry["reason"] == ON_DEMAND_WARNING

    async def test_the_entry_carries_no_pem_or_secret_content(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        """Neither certificate text, key text nor the CA body appears in the entry."""
        settings = make_settings(tmp_path, fake_gateway(), BASE_SEED + ca_section(on_demand=True))

        with structlog.testing.capture_logs() as logs:
            await bootstrap(settings)

        text = _text(_active(logs)[0])
        ca_pem = (settings.data_dir / "pki" / "x509-ca.crt").read_text(encoding="ascii")
        body_line = ca_pem.splitlines()[1]
        assert "BEGIN" not in text and "PRIVATE KEY" not in text
        assert body_line not in text


class TestModeOff:
    @pytest.mark.parametrize("ca_block", ["", ca_section(on_demand=False)])
    async def test_no_warning_event_is_logged(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, ca_block: str
    ) -> None:
        """Absent or explicit-false mode logs no tls.on_demand_issuance_active event."""
        settings = make_settings(tmp_path, fake_gateway(), BASE_SEED + ca_block)

        with structlog.testing.capture_logs() as logs:
            result = await bootstrap(settings)
            await result.reconciler.reconcile("tick")

        assert _active(logs) == []
