"""Web apps through the reconciler: create, merged drift update, gateway reassignment, delete.

SSH and Kubernetes resources on another gateway are recorded, never reassigned.
"""

import types
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
import structlog
import yaml

from gwops.reconciler.core import DEFERRED_RATE_LIMITED, GatewayMismatch
from gwops.renderer.capabilities import Capabilities
from gwops.tgapi.client import TGClient

from .conftest import FakeTGServer
from .test_core import Env

_HEADER_VALUE = "internal-marker-value"
_WRITE_PREFIXES = ("Create", "Update", "Delete")


@pytest.fixture
def tg_client() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="test-key")


@pytest.fixture(autouse=True)
def client_sleep(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Instant, recorded 429 waits (only the TG client's sleep is replaced)."""
    fake_sleep = AsyncMock()
    monkeypatch.setattr("gwops.tgapi.client.asyncio", types.SimpleNamespace(sleep=fake_sleep))
    return fake_sleep


def _seed(
    *,
    web_apps: list[dict[str, Any]] | None = None,
    ssh: bool = False,
    extra: dict[str, Any] | None = None,
) -> str:
    doc: dict[str, Any] = {"twingate": {"network": "acme", "gateway_id": "g-1"}}
    if ssh:
        doc["ssh_upstreams"] = [{"name": "web-1", "address": "10.0.0.5:22"}]
    doc["web_apps"] = [] if web_apps is None else web_apps
    doc.update(extra or {})
    return yaml.safe_dump(doc, sort_keys=False)


def _grafana(**fields: Any) -> dict[str, Any]:
    return {"name": "grafana", "address": "grafana.corp.internal", **fields}


@pytest.fixture
def make_env(
    tmp_path: Path, gateway_binary: Callable[..., Path], tg_client: TGClient
) -> Callable[[str], Env]:
    def _make(seed_text: str) -> Env:
        return Env(
            tmp_path,
            seed_text,
            gateway_binary(),
            Capabilities(gateway_version="2.0.0"),
            tg_client,
        )

    return _make


def _writes(server: FakeTGServer, since: int = 0) -> list[str]:
    return [c for c in server.calls[since:] if c.startswith(_WRITE_PREFIXES)]


def _only_resource(server: FakeTGServer, kind: str) -> Any:
    [resource] = [r for r in server.resources.values() if r.kind == kind]
    return resource


class TestCreate:
    async def test_a_web_app_is_created_with_every_setting_and_recorded(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        tg_server.add_group("App Users")
        env = make_env(
            _seed(
                web_apps=[
                    _grafana(
                        alias="grafana.alt.internal",
                        upstream_tls="verify_ca",
                        downstream={"tls": "none", "port": 8080},
                        request_headers={"X-Env": _HEADER_VALUE},
                        access={"groups": ["App Users"]},
                    )
                ]
            )
        )

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []
        assert "webapp/grafana" in result.tg_synced
        web = _only_resource(tg_server, "webapp")
        assert web.gateway_id == "g-1"
        assert web.address == "grafana.corp.internal"
        assert web.web["alias"] == "grafana.alt.internal"
        assert web.web["upstream_tls"] == "VERIFY_CA"
        assert web.web["downstream"] == {"port": 8080, "tlsMode": "NONE"}
        assert web.web["rewrites"] == [{"key": "x-env", "value": _HEADER_VALUE}]
        assert web.groups == {"g-1"}
        assert env.registry.managed_ids()["webapp/grafana"] == web.id
        assert tg_server.webapp_updates == []
        assert result.gateway_mismatches == {}


class TestNoOpPass:
    async def test_a_pass_without_drift_sends_no_write(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        tg_server.add_group("App Users")
        env = make_env(
            _seed(
                web_apps=[
                    _grafana(
                        alias="grafana.alt.internal",
                        request_headers={"X-Env": _HEADER_VALUE},
                        access={"groups": ["App Users"]},
                    )
                ],
                ssh=True,
            )
        )
        await env.reconciler.reconcile("startup")
        env.add_k8s_cluster_overlay()
        await env.reconciler.reconcile("add-cluster")
        seen = len(tg_server.calls)

        result = await env.reconciler.reconcile("tick")

        assert _writes(tg_server, seen) == []
        assert result.errors == []
        assert result.actions == []
        assert {"webapp/grafana", "ssh/web-1", "kubernetes/prod"} <= result.tg_synced
        assert tg_server.generic_updates_on_web_apps == []


class TestMergedDriftUpdate:
    """Each drift is one webAppResourceUpdate holding only the drifted fields."""

    async def _converged(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer, app: dict[str, Any]
    ) -> Env:
        env = make_env(_seed(web_apps=[app]))
        result = await env.reconciler.reconcile("startup")
        assert result.errors == []
        return env

    async def _drift_once(
        self, env: Env, tg_server: FakeTGServer, expected_keys: set[str]
    ) -> None:
        seen = len(tg_server.calls)

        result = await env.reconciler.reconcile("tick")

        assert result.errors == []
        assert _writes(tg_server, seen) == ["UpdateWebAppResource"]
        [update] = tg_server.webapp_updates
        assert set(update) == {"id"} | expected_keys
        assert tg_server.generic_updates_on_web_apps == []
        assert "webapp/grafana" in result.tg_synced
        # Converged: the next pass writes nothing.
        seen = len(tg_server.calls)
        again = await env.reconciler.reconcile("tick")
        assert _writes(tg_server, seen) == []
        assert again.actions == []

    async def test_address_drift(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = await self._converged(make_env, tg_server, _grafana())
        env.seed_path.write_text(
            _seed(web_apps=[{"name": "grafana", "address": "grafana2.corp.internal"}]),
            encoding="utf-8",
        )

        await self._drift_once(env, tg_server, {"address"})

        assert _only_resource(tg_server, "webapp").address == "grafana2.corp.internal"

    async def test_alias_set_then_cleared(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = await self._converged(make_env, tg_server, _grafana())
        env.seed_path.write_text(
            _seed(web_apps=[_grafana(alias="alt.corp.internal")]), encoding="utf-8"
        )
        await self._drift_once(env, tg_server, {"alias"})
        assert _only_resource(tg_server, "webapp").web["alias"] == "alt.corp.internal"

        tg_server.webapp_updates.clear()
        env.seed_path.write_text(_seed(web_apps=[_grafana()]), encoding="utf-8")
        seen = len(tg_server.calls)
        result = await env.reconciler.reconcile("tick")

        assert result.errors == []
        assert _writes(tg_server, seen) == ["UpdateWebAppResource"]
        # A key sent as null clears the alias; absent would have left it.
        assert tg_server.webapp_updates == [
            {"id": _only_resource(tg_server, "webapp").id, "alias": None}
        ]
        assert _only_resource(tg_server, "webapp").web["alias"] is None

    async def test_upstream_mode_and_port(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = await self._converged(make_env, tg_server, _grafana())
        env.seed_path.write_text(
            _seed(web_apps=[_grafana(address="grafana.corp.internal:8443",
                                     upstream_tls="verify_ca")]),
            encoding="utf-8",
        )

        await self._drift_once(env, tg_server, {"upstream"})

        web = _only_resource(tg_server, "webapp")
        assert (web.upstream_port, web.web["upstream_tls"]) == (8443, "VERIFY_CA")

    async def test_downstream_port(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = await self._converged(make_env, tg_server, _grafana())
        env.seed_path.write_text(
            _seed(web_apps=[_grafana(downstream={"port": 9443})]), encoding="utf-8"
        )

        await self._drift_once(env, tg_server, {"downstream"})

        assert _only_resource(tg_server, "webapp").web["downstream"] == {
            "port": 9443, "tlsMode": "TLS13",
        }

    async def test_request_headers(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = await self._converged(
            make_env, tg_server, _grafana(request_headers={"X-Env": "staging"})
        )
        env.seed_path.write_text(
            _seed(web_apps=[_grafana(request_headers={"X-Env": "prod", "X-Tier": "gold"})]),
            encoding="utf-8",
        )

        await self._drift_once(env, tg_server, {"requestHeaderRewrites"})

        assert _only_resource(tg_server, "webapp").web["rewrites"] == [
            {"key": "x-env", "value": "prod"},
            {"key": "x-tier", "value": "gold"},
        ]

    async def test_groups_and_policy(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        tg_server.add_group("App Users")
        tg_server.add_group("Admins")
        tg_server.add_policy("MFA")
        env = await self._converged(
            make_env, tg_server, _grafana(access={"groups": ["App Users"]})
        )
        env.seed_path.write_text(
            _seed(
                web_apps=[
                    _grafana(access={"groups": ["App Users", "Admins"], "security_policy": "MFA"})
                ]
            ),
            encoding="utf-8",
        )

        await self._drift_once(
            env, tg_server, {"addedGroupIds", "securityPolicyId"}
        )

        web = _only_resource(tg_server, "webapp")
        assert web.groups == {"g-1", "g-2"}
        assert web.security_policy == "p-1"
        assert tg_server.access_updates == []

    async def test_removing_a_group_sends_only_the_removal(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        tg_server.add_group("App Users")
        tg_server.add_group("Admins")
        env = await self._converged(
            make_env, tg_server, _grafana(access={"groups": ["App Users", "Admins"]})
        )
        env.seed_path.write_text(
            _seed(web_apps=[_grafana(access={"groups": ["App Users"]})]), encoding="utf-8"
        )

        await self._drift_once(env, tg_server, {"removedGroupIds"})

        assert _only_resource(tg_server, "webapp").groups == {"g-1"}

    async def test_every_drift_at_once_is_still_one_mutation(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        tg_server.add_group("App Users")
        tg_server.add_group("Admins")
        env = await self._converged(make_env, tg_server, _grafana())
        env.seed_path.write_text(
            _seed(
                web_apps=[
                    {
                        "name": "grafana",
                        "address": "g2.corp.internal:8443",
                        "alias": "g.alt.internal",
                        "upstream_tls": "verify_ca",
                        "downstream": {"port": 9443},
                        "request_headers": {"X-Env": "prod"},
                        "access": {"groups": ["App Users", "Admins"]},
                    }
                ]
            ),
            encoding="utf-8",
        )
        web = _only_resource(tg_server, "webapp")
        web.gateway_id = "g-other"

        await self._drift_once(
            env,
            tg_server,
            {
                "address", "alias", "upstream", "downstream", "requestHeaderRewrites",
                "addedGroupIds", "gatewayId",
            },
        )

        assert (web.address, web.gateway_id) == ("g2.corp.internal", "g-1")
        assert web.groups == {"g-1", "g-2"}

    async def test_the_action_line_names_fields_and_header_names_never_values(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = await self._converged(
            make_env, tg_server, _grafana(request_headers={"X-Env": "staging"})
        )
        env.seed_path.write_text(
            _seed(
                web_apps=[
                    _grafana(
                        alias="alt.corp.internal",
                        request_headers={"X-Env": _HEADER_VALUE, "X-Tier": "gold"},
                    )
                ]
            ),
            encoding="utf-8",
        )

        with structlog.testing.capture_logs() as logs:
            result = await env.reconciler.reconcile("tick")

        [action] = [a for a in result.actions if a.startswith("updated webapp")]
        assert "grafana" in action
        assert "alias" in action
        assert "request headers [x-env, x-tier]" in action
        assert "re-issues access tokens" in action
        everything = repr(logs) + " ".join(result.actions + result.errors)
        for secret in (_HEADER_VALUE, "gold", "staging"):
            assert secret not in everything
        # The alias is a certificate SAN (logged by the cert step), never in the update line.
        assert "alt.corp.internal" not in action


class TestNeverTheGenericMutation:
    async def test_no_pass_sends_a_generic_resource_update_for_a_web_app(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        tg_server.add_group("App Users")
        env = make_env(_seed(web_apps=[_grafana(access={"groups": ["App Users"]})]))
        await env.reconciler.reconcile("startup")
        env.seed_path.write_text(
            _seed(web_apps=[{"name": "grafana", "address": "other.corp.internal",
                             "access": {"groups": []}}]),
            encoding="utf-8",
        )

        result = await env.reconciler.reconcile("tick")

        assert result.errors == []
        assert tg_server.generic_updates_on_web_apps == []
        assert "UpdateResourceAddress" not in tg_server.calls
        assert "UpdateResourceAccess" not in tg_server.calls
        assert not any(c.startswith("UpdateWebAppResource") and c != "UpdateWebAppResource"
                       for c in tg_server.calls)


class TestWriteBudget:
    async def test_one_merged_mutation_is_one_budget_unit(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(
            _seed(
                web_apps=[
                    {"name": "one", "address": "one.corp.internal"},
                    {"name": "two", "address": "two.corp.internal"},
                ]
            )
        )
        await env.reconciler.reconcile("startup")
        env.seed_path.write_text(
            _seed(
                web_apps=[
                    {"name": "one", "address": "one2.corp.internal", "alias": "a.internal"},
                    {"name": "two", "address": "two2.corp.internal", "alias": "b.internal"},
                ]
            ),
            encoding="utf-8",
        )
        tg_server.throttle_ops = {"UpdateWebAppResource": 1}

        result = await env.reconciler.reconcile("tick")

        # `one` needed address and alias in a single mutation: throttled once, waited out,
        # applied. `two` is never attempted once a write was throttled.
        assert tg_server.calls.count("UpdateWebAppResource") == 2
        assert len(tg_server.webapp_updates) == 1
        assert result.resource_errors == {"webapp/two": [DEFERRED_RATE_LIMITED]}
        assert result.tg_synced == {"webapp/one"}

        third = await env.reconciler.reconcile("tick")

        assert third.errors == []
        assert len(tg_server.webapp_updates) == 2
        assert third.tg_synced == {"webapp/one", "webapp/two"}

    async def test_a_rejected_update_is_a_per_resource_error_and_is_retried(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(web_apps=[_grafana()]))
        await env.reconciler.reconcile("startup")
        env.seed_path.write_text(_seed(web_apps=[_grafana(alias="a.internal")]), encoding="utf-8")
        tg_server.fail_ops = {"UpdateWebAppResource"}

        failed = await env.reconciler.reconcile("tick")

        assert "webapp/grafana" in failed.resource_errors
        assert failed.local_ok is True
        assert "webapp/grafana" not in failed.tg_synced

        tg_server.fail_ops = set()
        fixed = await env.reconciler.reconcile("tick")

        assert fixed.errors == []
        assert _only_resource(tg_server, "webapp").web["alias"] == "a.internal"

    async def test_access_is_recorded_only_after_the_merged_update_succeeds(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        tg_server.add_group("App Users")
        env = make_env(_seed(web_apps=[_grafana()]))
        await env.reconciler.reconcile("startup")
        env.seed_path.write_text(
            _seed(web_apps=[_grafana(access={"groups": ["App Users"]})]), encoding="utf-8"
        )
        tg_server.fail_ops = {"UpdateWebAppResource"}
        await env.reconciler.reconcile("tick")
        assert env.registry.last_access("webapp/grafana").groups == frozenset()

        tg_server.fail_ops = set()
        await env.reconciler.reconcile("tick")

        assert env.registry.last_access("webapp/grafana").groups == frozenset({"g-1"})


class TestGatewayReassignment:
    async def test_a_web_app_on_another_gateway_is_corrected_in_the_merged_update(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(web_apps=[_grafana()]))
        await env.reconciler.reconcile("startup")
        web = _only_resource(tg_server, "webapp")
        web.gateway_id = "g-other"

        result = await env.reconciler.reconcile("tick")

        assert result.errors == []
        assert tg_server.webapp_updates == [{"id": web.id, "gatewayId": "g-1"}]
        assert web.gateway_id == "g-1"
        assert result.gateway_mismatches == {
            "webapp/grafana": GatewayMismatch(remote_gateway_id="g-other", corrected=True)
        }
        assert "webapp/grafana" in result.tg_synced
        [action] = [a for a in result.actions if a.startswith("updated webapp")]
        assert "gateway g-other -> g-1" in action

        after = await env.reconciler.reconcile("tick")

        assert after.gateway_mismatches == {}
        assert after.actions == []

    async def test_a_failed_correction_is_recorded_as_not_corrected(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(web_apps=[_grafana()]))
        await env.reconciler.reconcile("startup")
        _only_resource(tg_server, "webapp").gateway_id = "g-other"
        tg_server.fail_ops = {"UpdateWebAppResource"}

        result = await env.reconciler.reconcile("tick")

        assert result.gateway_mismatches == {
            "webapp/grafana": GatewayMismatch(remote_gateway_id="g-other", corrected=False)
        }
        assert "webapp/grafana" in result.resource_errors

    async def test_ssh_and_kubernetes_are_recorded_and_never_corrected(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(web_apps=[_grafana()], ssh=True))
        env.add_k8s_cluster_overlay()
        await env.reconciler.reconcile("startup")
        ssh = _only_resource(tg_server, "ssh")
        k8s = _only_resource(tg_server, "kubernetes")
        web = _only_resource(tg_server, "webapp")
        ssh.gateway_id = k8s.gateway_id = web.gateway_id = "g-other"
        seen = len(tg_server.calls)

        result = await env.reconciler.reconcile("tick")

        assert result.gateway_mismatches == {
            "ssh/web-1": GatewayMismatch("g-other", corrected=False),
            "kubernetes/prod": GatewayMismatch("g-other", corrected=False),
            "webapp/grafana": GatewayMismatch("g-other", corrected=True),
        }
        # The only mutation is the web app's merged update.
        assert _writes(tg_server, seen) == ["UpdateWebAppResource"]
        assert (ssh.gateway_id, k8s.gateway_id) == ("g-other", "g-other")
        assert web.gateway_id == "g-1"
        assert result.errors == []

        again = await env.reconciler.reconcile("tick")

        # Recorded on every pass for as long as the mismatch lasts.
        assert set(again.gateway_mismatches) == {"ssh/web-1", "kubernetes/prod"}
        assert all(not m.corrected for m in again.gateway_mismatches.values())
        assert _writes(tg_server, seen) == ["UpdateWebAppResource"]

    async def test_the_gateways_own_id_is_the_resolved_one_in_remote_network_mode(
        self, tmp_path: Path, gateway_binary: Callable[..., Path], tg_client: TGClient,
        tg_server: FakeTGServer,
    ) -> None:
        gateway = tg_server.add_gateway("203.0.113.10:8443", "gw-real")
        seed = yaml.safe_dump(
            {
                "twingate": {
                    "network": "acme",
                    "remote_network_id": "rn-1",
                    "gateway_address": "203.0.113.10:8443",
                },
                "web_apps": [_grafana()],
            },
            sort_keys=False,
        )
        env = Env(tmp_path, seed, gateway_binary(), Capabilities(gateway_version="2.0.0"),
                  tg_client)
        await env.reconciler.reconcile("startup")
        web = _only_resource(tg_server, "webapp")
        assert web.gateway_id == gateway
        web.gateway_id = "gw-elsewhere"

        result = await env.reconciler.reconcile("tick")

        assert result.gateway_mismatches == {
            "webapp/grafana": GatewayMismatch("gw-elsewhere", corrected=True)
        }
        assert web.gateway_id == gateway

    async def test_an_unmanaged_resource_on_another_gateway_is_not_a_mismatch(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        tg_server.add_resource("ssh", "stranger", "10.9.9.9", "g-other")
        tg_server.add_web_app("stranger-web", "stranger.corp.internal", "g-other")
        env = make_env(_seed(web_apps=[_grafana()]))

        result = await env.reconciler.reconcile("startup")

        assert result.gateway_mismatches == {}

    async def test_no_tenant_listing_means_no_mismatch_claim(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(web_apps=[_grafana()]))
        await env.reconciler.reconcile("startup")
        tg_server.fail = True

        result = await env.reconciler.reconcile("tick")

        assert result.tg_unavailable is True
        assert result.gateway_mismatches == {}


class TestGatewayMismatchLogging:
    @staticmethod
    def _mismatch_logs(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [e for e in logs if e["event"].startswith("reconcile.gateway_mismatches")]

    async def test_logged_once_per_distinct_set_then_cleared_once(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(web_apps=[], ssh=True))
        await env.reconciler.reconcile("startup")
        ssh = _only_resource(tg_server, "ssh")
        ssh.gateway_id = "g-other"

        with structlog.testing.capture_logs() as logs:
            for _ in range(3):
                await env.reconciler.reconcile("tick")

        [entry] = self._mismatch_logs(logs)
        assert entry["event"] == "reconcile.gateway_mismatches"
        assert entry["log_level"] == "warning"
        assert entry["mismatches"] == [
            {"resource": "ssh/web-1", "remote_gateway_id": "g-other", "corrected": False}
        ]

        ssh.gateway_id = "g-1"
        with structlog.testing.capture_logs() as logs:
            await env.reconciler.reconcile("tick")
            await env.reconciler.reconcile("tick")

        [cleared] = self._mismatch_logs(logs)
        assert cleared["event"] == "reconcile.gateway_mismatches_cleared"

        ssh.gateway_id = "g-other"
        with structlog.testing.capture_logs() as logs:
            await env.reconciler.reconcile("tick")

        assert len(self._mismatch_logs(logs)) == 1

    async def test_a_changed_set_is_logged_again(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(web_apps=[_grafana()], ssh=True))
        await env.reconciler.reconcile("startup")
        _only_resource(tg_server, "ssh").gateway_id = "g-other"
        with structlog.testing.capture_logs() as logs:
            await env.reconciler.reconcile("tick")
        assert len(self._mismatch_logs(logs)) == 1

        _only_resource(tg_server, "webapp").gateway_id = "g-other"
        with structlog.testing.capture_logs() as logs:
            await env.reconciler.reconcile("tick")

        [entry] = self._mismatch_logs(logs)
        assert {m["resource"]: m["corrected"] for m in entry["mismatches"]} == {
            "ssh/web-1": False,
            "webapp/grafana": True,
        }

    async def test_a_tenant_outage_neither_logs_nor_clears(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(web_apps=[], ssh=True))
        await env.reconciler.reconcile("startup")
        _only_resource(tg_server, "ssh").gateway_id = "g-other"
        await env.reconciler.reconcile("tick")

        with structlog.testing.capture_logs() as logs:
            tg_server.fail = True
            await env.reconciler.reconcile("tick")
            tg_server.fail = False
            await env.reconciler.reconcile("tick")

        assert self._mismatch_logs(logs) == []

    async def test_ids_only_never_header_values(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(web_apps=[_grafana(request_headers={"X-Env": _HEADER_VALUE})]))
        await env.reconciler.reconcile("startup")
        _only_resource(tg_server, "webapp").gateway_id = "g-other"

        with structlog.testing.capture_logs() as logs:
            await env.reconciler.reconcile("tick")

        assert _HEADER_VALUE not in repr(logs)


class TestDelete:
    async def test_a_removed_web_app_is_deleted_with_the_generic_mutation_only(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(web_apps=[_grafana()], ssh=True))
        await env.reconciler.reconcile("startup")
        web_id = _only_resource(tg_server, "webapp").id
        env.seed_path.write_text(_seed(web_apps=[], ssh=True), encoding="utf-8")

        result = await env.reconciler.reconcile("tick")

        assert result.errors == []
        assert web_id not in tg_server.resources
        assert "webapp/grafana" not in env.registry.managed_ids()
        assert "webapp/grafana" in result.tg_synced
        assert any("deleted webapp resource 'grafana'" in a for a in result.actions)
        assert tg_server.webapp_updates == []


class TestRecreate:
    async def test_a_resource_deleted_in_the_tenant_is_created_again(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        env = make_env(_seed(web_apps=[_grafana(alias="a.internal")]))
        await env.reconciler.reconcile("startup")
        del tg_server.resources[_only_resource(tg_server, "webapp").id]

        result = await env.reconciler.reconcile("tick")

        assert result.errors == []
        assert any(a.startswith("recreated webapp resource") for a in result.actions)
        assert _only_resource(tg_server, "webapp").web["alias"] == "a.internal"
