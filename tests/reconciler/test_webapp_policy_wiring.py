"""The web-app policy at load: violations refuse the pass, warnings are logged once per set."""

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import structlog
import yaml

from gwops.renderer.capabilities import Capabilities
from gwops.tgapi.client import TGClient

from .conftest import FakeTGServer
from .test_core import Env

_COOKIE_VALUE = "cookie-value-that-must-not-be-logged"
_HEADER_VALUE = "header-value-that-must-not-be-logged"


@pytest.fixture
def tg_client() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="test-key")


def _seed(*web_apps: dict[str, Any]) -> str:
    doc: dict[str, Any] = {
        "twingate": {"network": "acme", "gateway_id": "g-1"},
        "web_apps": list(web_apps),
    }
    return yaml.safe_dump(doc, sort_keys=False)


_GOOD = {"name": "grafana", "address": "grafana.corp.internal"}
_BAD_HEADER = {
    "name": "wiki",
    "address": "wiki.corp.internal",
    "request_headers": {"Cookie": _COOKIE_VALUE},
}
_BAD_TLS = {"name": "legacy", "address": "legacy.corp.internal", "upstream_tls": "insecure"}


@pytest.fixture
def make_env(
    tmp_path: Path, gateway_binary: Callable[..., Path], tg_client: TGClient
) -> Callable[[str], Env]:
    def _make(seed_text: str) -> Env:
        return Env(
            tmp_path, seed_text, gateway_binary(), Capabilities(gateway_version="2.0.0"), tg_client
        )

    return _make


class TestViolationsRefuseThePass:
    async def test_a_refused_state_syncs_nothing_and_keeps_the_last_good_config(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(_GOOD))
        await env.reconciler.reconcile("startup")
        old_config = env.config_path.read_text(encoding="utf-8")
        seen = len(tg_server.calls)
        env.seed_path.write_text(_seed(_GOOD, _BAD_HEADER, _BAD_TLS), encoding="utf-8")

        result = await env.reconciler.reconcile("tick")

        assert result.local_ok is False
        assert result.ok is False
        # Every violation, each naming its entry and field.
        policy_errors = [e for e in result.errors if e.startswith("web-app policy: ")]
        assert any("'wiki'" in e and "request_headers" in e for e in policy_errors)
        assert any("'legacy'" in e and "upstream_tls" in e for e in policy_errors)
        assert len(policy_errors) == len(result.errors)
        assert _COOKIE_VALUE not in " ".join(result.errors + result.actions)
        # Nothing reached the tenant, nothing was rendered or applied.
        assert tg_server.calls[seen:] == []
        assert "webapp/wiki" not in env.registry.managed_ids()
        assert env.config_path.read_text(encoding="utf-8") == old_config
        assert env.process.calls == ["start"]
        assert any("kept previous gateway config" in a for a in result.actions)

    async def test_a_refused_startup_pass_never_starts_the_gateway(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(_BAD_HEADER))

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        assert tg_server.calls == []
        assert not env.config_path.exists()
        assert env.process.calls == []

    async def test_an_overlay_that_breaks_the_policy_is_refused_too(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(_GOOD))
        await env.reconciler.reconcile("startup")
        env.store.add({"web_apps": [_BAD_TLS]}, comment="add legacy")

        result = await env.reconciler.reconcile("api")

        assert result.local_ok is False
        assert any("'legacy'" in e and "upstream_tls" in e for e in result.errors)
        assert "webapp/legacy" not in env.registry.managed_ids()

    async def test_fixing_the_state_recovers_on_the_next_pass(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(_GOOD))
        await env.reconciler.reconcile("startup")
        env.seed_path.write_text(_seed(_GOOD, _BAD_TLS), encoding="utf-8")
        assert (await env.reconciler.reconcile("tick")).local_ok is False

        env.seed_path.write_text(_seed(_GOOD, {**_BAD_TLS, "upstream_tls": "verify_full"}),
                                 encoding="utf-8")
        result = await env.reconciler.reconcile("tick")

        assert result.local_ok is True
        assert result.errors == []
        assert "webapp/legacy" in env.registry.managed_ids()
        assert any("created webapp resource 'legacy'" in a for a in result.actions)

    async def test_a_clean_state_adds_no_policy_error(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(_GOOD))

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []


class TestWarningsAreLoggedOncePerSet:
    @staticmethod
    def _warnings(logs: list[dict[str, Any]]) -> list[list[str]]:
        return [e["warnings"] for e in logs if e["event"] == "reconcile.webapp_policy_warnings"]

    async def test_logged_on_the_first_pass_and_not_again_while_unchanged(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed({**_GOOD, "upstream_tls": "verify_ca"}))

        with structlog.testing.capture_logs() as logs:
            for trigger in ("startup", "tick", "tick"):
                result = await env.reconciler.reconcile(trigger)
                assert result.local_ok is True

        [warned] = self._warnings(logs)
        assert len(warned) == 1
        assert "'grafana'" in warned[0] and "upstream_tls" in warned[0]
        assert [e["log_level"] for e in logs if e["event"] == "reconcile.webapp_policy_warnings"] \
            == ["warning"]

    async def test_a_changed_set_is_logged_again_and_values_never_appear(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        weak = {**_GOOD, "upstream_tls": "verify_ca",
                "request_headers": {"X-Env": _HEADER_VALUE}}
        env = make_env(_seed(weak))
        with structlog.testing.capture_logs() as first:
            await env.reconciler.reconcile("startup")
        env.seed_path.write_text(
            _seed({**weak, "downstream": {"tls": "none"}}), encoding="utf-8"
        )

        with structlog.testing.capture_logs() as second:
            await env.reconciler.reconcile("tick")
            await env.reconciler.reconcile("tick")

        [after] = self._warnings(second)
        assert len(after) == 2 and len(self._warnings(first)[0]) == 1
        assert any("downstream.tls" in w for w in after)
        assert _HEADER_VALUE not in repr(first) + repr(second)

    async def test_the_same_set_after_a_clean_stretch_is_logged_again(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        weak = _seed({**_GOOD, "upstream_tls": "verify_ca"})
        env = make_env(weak)
        with structlog.testing.capture_logs() as logs:
            await env.reconciler.reconcile("startup")
            env.seed_path.write_text(_seed(_GOOD), encoding="utf-8")
            await env.reconciler.reconcile("tick")
            env.seed_path.write_text(weak, encoding="utf-8")
            await env.reconciler.reconcile("tick")

        assert len(self._warnings(logs)) == 2

    async def test_a_state_without_warnings_logs_none(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(_GOOD))

        with structlog.testing.capture_logs() as logs:
            await env.reconciler.reconcile("startup")
            await env.reconciler.reconcile("tick")

        assert self._warnings(logs) == []
