"""`public_cert_unused` is logged by the reconciler, once per certificate per distinct set.

Validation runs on every `load_effective_state` (the API loads several times per request),
so the warning lives where the effective state is re-established: the startup pass and each
later pass that sees a changed set.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import structlog.testing
import yaml

from gwops.renderer.capabilities import Capabilities
from tests.public_tls_support import ZONE, public_cert, public_seed, ssh, tls_block

from .test_core import Env

_EVENT = "public_cert_unused"


def _seed(*certs: tuple[str, str]) -> str:
    """Public seed serving `host1`, covered by the certificate named `host`."""
    tls = tls_block(
        certificates=[public_cert("host", [f"host1.{ZONE}"])]
        + [public_cert(name, [pattern]) for name, pattern in certs]
    )
    upstreams = [ssh("host1", f"host1.{ZONE}:22")]
    return yaml.safe_dump(public_seed(tls, ssh_upstreams=upstreams), sort_keys=False)


def _unused(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [log for log in logs if log["event"] == _EVENT]


async def _reconcile(env: Env, trigger: str) -> None:
    """One pass; the state must load, or a silent log would prove nothing."""
    result = await env.reconciler.reconcile(trigger)
    assert not [e for e in result.errors if "effective state" in e], result.errors


def _env(tmp_path: Path, binary: Path, seed: str) -> Env:
    return Env(tmp_path, seed, binary, Capabilities(), None)


async def test_the_startup_pass_warns_once_per_unused_certificate(
    tmp_path: Path, gateway_binary: Callable[..., Path]
) -> None:
    seed = _seed(("one", f"one.{ZONE}"), ("two", f"two.{ZONE}"))
    env = _env(tmp_path, gateway_binary(), seed)

    with structlog.testing.capture_logs() as logs:
        await _reconcile(env, "startup")

    events = _unused(logs)
    assert sorted(e["certificate"] for e in events) == ["one", "two"]
    assert {e["log_level"] for e in events} == {"warning"}


async def test_later_passes_with_the_same_set_are_silent(
    tmp_path: Path, gateway_binary: Callable[..., Path]
) -> None:
    env = _env(tmp_path, gateway_binary(), _seed(("one", f"one.{ZONE}")))
    await _reconcile(env, "startup")

    with structlog.testing.capture_logs() as logs:
        await _reconcile(env, "tick")
        await _reconcile(env, "tick")

    assert _unused(logs) == []


async def test_a_newly_unused_certificate_is_warned_when_the_set_changes(
    tmp_path: Path, gateway_binary: Callable[..., Path]
) -> None:
    """One unused certificate at startup; a second one appears: only the new one is logged."""
    env = _env(tmp_path, gateway_binary(), _seed(("one", f"one.{ZONE}")))
    await _reconcile(env, "startup")

    env.seed_path.write_text(
        _seed(("one", f"one.{ZONE}"), ("two", f"two.{ZONE}")),
        encoding="utf-8",
    )
    with structlog.testing.capture_logs() as logs:
        await _reconcile(env, "seed-change")

    [event] = _unused(logs)
    assert event["certificate"] == "two"


async def test_an_overlay_that_uses_the_certificate_clears_it_and_removing_it_warns_again(
    tmp_path: Path, gateway_binary: Callable[..., Path]
) -> None:
    env = _env(tmp_path, gateway_binary(), _seed(("one", f"one.{ZONE}")))
    with structlog.testing.capture_logs() as startup_logs:
        await _reconcile(env, "startup")
    assert [e["certificate"] for e in _unused(startup_logs)] == ["one"]

    env.store.add({"ssh_upstreams": [ssh("one", f"one.{ZONE}")]}, comment="use it")
    with structlog.testing.capture_logs() as used_logs:
        await _reconcile(env, "overlay")
    assert _unused(used_logs) == []

    [overlay] = env.store.list()
    env.store.delete(overlay.id)
    with structlog.testing.capture_logs() as unused_logs:
        await _reconcile(env, "overlay")
    assert [e["certificate"] for e in _unused(unused_logs)] == ["one"]


async def test_no_warning_without_public_mode(
    tmp_path: Path, gateway_binary: Callable[..., Path]
) -> None:
    seed = (
        "twingate:\n  network: acme\n  gateway_id: g-1\n"
        "ssh_upstreams:\n  - name: h\n    address: 10.0.0.5\n"
    )
    env = _env(tmp_path, gateway_binary(), seed)

    with structlog.testing.capture_logs() as logs:
        await _reconcile(env, "startup")

    assert _unused(logs) == []
