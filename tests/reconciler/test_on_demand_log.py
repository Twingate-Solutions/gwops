"""A change of ``ca.x509.on_demand_issuance`` between passes is logged once, at the change."""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import structlog

from gwops.certs.on_demand import (
    ON_DEMAND_BROWSER_TRUST_WARNING,
    ON_DEMAND_BYO_TRUST_WARNING,
    ON_DEMAND_WARNING,
)
from gwops.renderer.capabilities import Capabilities
from tests.on_demand_support import SSH_UPSTREAM_SEED, CAFiles, build_ca, ca_section

from .test_core import Env

_ACTIVE = "tls.on_demand_issuance_active"
_DISABLED = "tls.on_demand_issuance_disabled"


def _seed(on_demand: bool) -> str:
    return SSH_UPSTREAM_SEED + ca_section(on_demand=on_demand, byo=None)


def _env(tmp_path: Path, binary: Path, on_demand: bool) -> Env:
    return Env(tmp_path, _seed(on_demand), binary, Capabilities(), None)


def _mode_logs(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in logs if e["event"] in {_ACTIVE, _DISABLED}]


async def test_enabling_the_mode_logs_the_warning_once(
    tmp_path: Path, gateway_binary: Callable[..., Path]
) -> None:
    """Off to on: one warning carrying the warning text; later passes are silent."""
    env = _env(tmp_path, gateway_binary(), False)
    await env.reconciler.reconcile("startup")

    env.seed_path.write_text(_seed(True), encoding="utf-8")
    with structlog.testing.capture_logs() as logs:
        await env.reconciler.reconcile("seed-change")
        await env.reconciler.reconcile("tick")

    [event] = _mode_logs(logs)
    assert event["event"] == _ACTIVE
    assert event["log_level"] == "warning"
    assert event["reason"] == ON_DEMAND_WARNING


_WEB_APP = "web_apps:\n  - name: grafana\n    address: grafana.corp.internal\n"


async def _enable_and_capture(
    tmp_path: Path, binary: Path, seed_off: str, seed_on: str
) -> dict[str, Any]:
    env = Env(tmp_path, seed_off, binary, Capabilities(gateway_version="2.0.0"), None)
    await env.reconciler.reconcile("startup")
    env.seed_path.write_text(seed_on, encoding="utf-8")
    with structlog.testing.capture_logs() as logs:
        await env.reconciler.reconcile("seed-change")
    [event] = _mode_logs(logs)
    return event


async def test_enabling_with_a_byo_ca_logs_the_escalated_warning(
    tmp_path: Path, gateway_binary: Callable[..., Path]
) -> None:
    """The log carries the text /status shows: the BYO-CA trust escalation is appended."""
    byo: CAFiles = build_ca(tmp_path / "byo")
    event = await _enable_and_capture(
        tmp_path,
        gateway_binary(),
        SSH_UPSTREAM_SEED + ca_section(on_demand=False, byo=byo),
        SSH_UPSTREAM_SEED + ca_section(on_demand=True, byo=byo),
    )

    assert event["reason"] == ON_DEMAND_WARNING + ON_DEMAND_BYO_TRUST_WARNING


async def test_enabling_with_a_generated_ca_and_a_tls13_web_app_logs_the_escalated_warning(
    tmp_path: Path, gateway_binary: Callable[..., Path]
) -> None:
    """A generated CA plus a tls13 web app adds the browser-trust escalation."""
    event = await _enable_and_capture(
        tmp_path,
        gateway_binary(),
        SSH_UPSTREAM_SEED + _WEB_APP + ca_section(on_demand=False),
        SSH_UPSTREAM_SEED + _WEB_APP + ca_section(on_demand=True),
    )

    assert event["reason"] == ON_DEMAND_WARNING + ON_DEMAND_BROWSER_TRUST_WARNING


async def test_disabling_the_mode_logs_info_once(
    tmp_path: Path, gateway_binary: Callable[..., Path]
) -> None:
    """On to off: one info line; later passes are silent."""
    env = _env(tmp_path, gateway_binary(), True)
    await env.reconciler.reconcile("startup")

    env.seed_path.write_text(_seed(False), encoding="utf-8")
    with structlog.testing.capture_logs() as logs:
        await env.reconciler.reconcile("seed-change")
        await env.reconciler.reconcile("tick")

    [event] = _mode_logs(logs)
    assert event["event"] == _DISABLED
    assert event["log_level"] == "info"


async def test_the_first_pass_logs_no_change(
    tmp_path: Path, gateway_binary: Callable[..., Path]
) -> None:
    """With no previous pass there is no change to report (startup logs its own warning)."""
    env = _env(tmp_path, gateway_binary(), True)

    with structlog.testing.capture_logs() as logs:
        await env.reconciler.reconcile("startup")

    assert _mode_logs(logs) == []
