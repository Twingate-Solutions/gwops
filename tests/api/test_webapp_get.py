"""GET /upstreams/{segment}/{name}: web-app settings, warnings, gateway mismatch, policy drift."""

import dataclasses
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import yaml
from pydantic import SecretStr

from gwops.access.webapp_policy import warnings
from gwops.api.app import create_app
from gwops.configmodel.loader import load_effective_state
from gwops.reconciler.core import GatewayMismatch
from gwops.tgapi.client import TGClient

from .conftest import make_deps, ok_result
from .test_automation_webapp import Env, Tenant

_ADMIN = "admin-token"
_AUTO = "automation-token"
_TG_URL = "https://acme.twingate.com/api/graphql/"
_NAME_NOT_ALLOWED = "header name not in admin_api.automation.web_apps.request_header_names"
_NOT_VERIFY_FULL = "only verify_full is allowed for the automation token"

_EXISTING_KEYS = {
    "kind", "name", "origin", "address", "declared_access", "effective_access",
    "tg_resource_id", "applied_access", "last_reconcile_at", "errors",
}
_WEBAPP_ONLY_KEYS = {
    "alias", "upstream_tls", "downstream", "request_headers", "warnings",
    "automation_policy_violations",
}

_SEED_WEB_APPS: list[dict[str, Any]] = [
    {
        "name": "seed-plain",
        "address": "seed-plain.apps.example.com",
        "alias": "seed-alias.corp.example.com",
        "request_headers": {"X-Team": "{{username}}", "X-Env": "Region {{clientGeoRegion}}"},
    },
    {"name": "seed-ca", "address": "seed-ca.apps.example.com", "upstream_tls": "verify_ca"},
    {"name": "seed-insecure", "address": "10.20.0.7", "upstream_tls": "insecure"},
    {
        "name": "seed-none",
        "address": "10.20.0.8",
        "upstream_tls": "none",
        "downstream": {"tls": "none"},
    },
    {
        "name": "seed-port",
        "address": "seed-port.apps.example.com",
        "downstream": {"tls": "tls13", "port": 8443},
    },
    {"name": "seed-empty", "address": "seed-empty.apps.example.com", "request_headers": {}},
]


def _seed(names: list[str] | None = None) -> str:
    doc: dict[str, Any] = {
        "twingate": {
            "network": "acme",
            "gateway_id": "g-1",
            "address_allowlist": {
                "cidrs": ["10.20.0.0/16"],
                "dns_suffixes": ["apps.example.com", "corp.example.com"],
            },
            "access_allowlist": {"groups": ["App Users"], "security_policies": []},
        },
        "ssh_upstreams": [{"name": "seed-ssh", "address": "seed-ssh.apps.example.com"}],
        "k8s_clusters": [
            {
                "name": "seed-k8s",
                "address": "seed-k8s.apps.example.com",
                "bearer_token_file": "/config/k8s-creds/t",
                "ca_file": "/config/k8s-creds/c",
            }
        ],
        "web_apps": _SEED_WEB_APPS,
        "web_app_proxy": {"plaintext_upstreams": {"cidrs": ["10.20.0.0/16"]}},
        "admin_api": {
            "automation": {
                "name_prefix": "auto-",
                "web_apps": {
                    "enabled": True,
                    "request_header_names": ["X-Team", "x-env"] if names is None else names,
                },
            }
        },
    }
    return yaml.safe_dump(doc, sort_keys=False)


@pytest.fixture
async def genv(tmp_path: Path) -> AsyncIterator[Env]:
    bundle = make_deps(tmp_path, seed=_seed(), admin_token=_ADMIN)
    tg = TGClient(network="acme", api_key="test-key")
    settings = bundle.deps.settings.model_copy(
        update={"gwops_automation_token": SecretStr(_AUTO)}
    )
    bundle.deps = dataclasses.replace(bundle.deps, settings=settings, tg=tg)
    transport = httpx.ASGITransport(app=create_app(bundle.deps))
    tenant = Tenant()
    with respx.mock(assert_all_called=False) as router:
        router.post(_TG_URL).mock(side_effect=tenant.handler)
        async with (
            httpx.AsyncClient(
                transport=transport, base_url="http://gwops",
                headers={"Authorization": f"Bearer {_ADMIN}"},
            ) as admin,
            httpx.AsyncClient(
                transport=transport, base_url="http://gwops",
                headers={"Authorization": f"Bearer {_AUTO}"},
            ) as auto,
        ):
            yield Env(bundle, tenant, admin, auto)
    await tg.aclose()


def _app(**fields: Any) -> dict[str, Any]:
    return {"address": "app.apps.example.com", **fields}


def _set_mismatches(env: Env, mismatches: dict[str, GatewayMismatch]) -> None:
    result = ok_result()
    result.gateway_mismatches = mismatches
    env.bundle.reconciler.last_result = result


class TestWebAppFields:
    async def test_returns_the_current_fields_and_the_web_app_settings(self, genv: Env) -> None:
        genv.bundle.deps.registry.record("webapp", "seed-plain", "res-1")
        response = await genv.admin.get("/upstreams/webapp/seed-plain")
        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) >= _EXISTING_KEYS
        assert (body["kind"], body["name"], body["origin"]) == ("webapp", "seed-plain", "seed")
        assert body["address"] == "seed-plain.apps.example.com"
        assert body["tg_resource_id"] == "res-1"
        assert body["alias"] == "seed-alias.corp.example.com"
        assert body["upstream_tls"] == "verify_full"
        assert body["downstream"] == {"tls": "tls13", "port": 443}
        assert body["request_headers"] == {
            "X-Team": "{{username}}", "X-Env": "Region {{clientGeoRegion}}"
        }
        assert body["warnings"] == []
        assert body["gateway_mismatch"] is None

    @pytest.mark.parametrize(
        ("name", "downstream"),
        [
            ("seed-plain", {"tls": "tls13", "port": 443}),
            ("seed-none", {"tls": "none", "port": 80}),
            ("seed-port", {"tls": "tls13", "port": 8443}),
        ],
    )
    async def test_downstream_reports_the_tls_mode_and_the_effective_port(
        self, genv: Env, name: str, downstream: dict[str, Any]
    ) -> None:
        body = (await genv.admin.get(f"/upstreams/webapp/{name}")).json()
        assert body["downstream"] == downstream

    @pytest.mark.parametrize(
        ("name", "alias", "upstream_tls"),
        [
            ("seed-ca", None, "verify_ca"),
            ("seed-insecure", None, "insecure"),
            ("seed-none", None, "none"),
        ],
    )
    async def test_alias_and_upstream_tls_are_reported(
        self, genv: Env, name: str, alias: str | None, upstream_tls: str
    ) -> None:
        body = (await genv.admin.get(f"/upstreams/webapp/{name}")).json()
        assert (body["alias"], body["upstream_tls"]) == (alias, upstream_tls)

    @pytest.mark.parametrize(
        ("name", "expected"), [("seed-ca", None), ("seed-empty", {}), ("seed-port", None)]
    )
    async def test_unmanaged_and_empty_request_headers_are_distinguished(
        self, genv: Env, name: str, expected: dict[str, str] | None
    ) -> None:
        body = (await genv.admin.get(f"/upstreams/webapp/{name}")).json()
        assert body["request_headers"] == expected

    async def test_the_automation_token_gets_the_same_fields_for_its_own_entry(
        self, genv: Env
    ) -> None:
        put = await genv.auto.put(
            "/upstreams/webapp/auto-a",
            json=_app(
                alias="wiki.corp.example.com",
                downstream={"tls": "none"},
                request_headers={"X-Team": "{{groups}}"},
            ),
        )
        assert put.status_code == 200, put.text
        body = (await genv.auto.get("/upstreams/webapp/auto-a")).json()
        assert body["alias"] == "wiki.corp.example.com"
        assert body["upstream_tls"] == "verify_full"
        assert body["downstream"] == {"tls": "none", "port": 80}
        assert body["request_headers"] == {"X-Team": "{{groups}}"}


class TestWarnings:
    @pytest.mark.parametrize(
        ("name", "needles"),
        [
            ("seed-plain", []),
            ("seed-empty", []),
            ("seed-ca", ["verify_ca"]),
            ("seed-insecure", ["insecure"]),
            ("seed-none", ["upstream_tls", "downstream.tls"]),
        ],
    )
    async def test_an_entry_reports_its_own_weakening_settings(
        self, genv: Env, name: str, needles: list[str]
    ) -> None:
        body = (await genv.admin.get(f"/upstreams/webapp/{name}")).json()
        assert len(body["warnings"]) == len(needles)
        for needle, warning in zip(needles, body["warnings"], strict=True):
            assert needle in warning
        assert all(f"'{name}'" in w for w in body["warnings"])

    @pytest.mark.parametrize("name", [e["name"] for e in _SEED_WEB_APPS])
    async def test_warnings_equal_the_policy_warnings_for_that_entry(
        self, genv: Env, name: str
    ) -> None:
        state, _provenance = load_effective_state(genv.bundle.seed_path, genv.bundle.store)
        expected = [w for w in warnings(state) if w.startswith(f"web_apps entry {name!r}:")]
        body = (await genv.admin.get(f"/upstreams/webapp/{name}")).json()
        assert body["warnings"] == expected

    async def test_an_entry_never_carries_another_entrys_warnings(self, genv: Env) -> None:
        body = (await genv.admin.get("/upstreams/webapp/seed-plain")).json()
        assert body["warnings"] == []


class TestGatewayMismatch:
    @pytest.mark.parametrize("corrected", [False, True])
    @pytest.mark.parametrize(
        ("segment", "name", "key"),
        [
            ("webapp", "seed-plain", "webapp/seed-plain"),
            ("ssh", "seed-ssh", "ssh/seed-ssh"),
            ("k8s", "seed-k8s", "kubernetes/seed-k8s"),
        ],
    )
    async def test_the_last_pass_mismatch_is_reported(
        self, genv: Env, segment: str, name: str, key: str, corrected: bool
    ) -> None:
        _set_mismatches(genv, {key: GatewayMismatch("gw-other", corrected=corrected)})
        body = (await genv.admin.get(f"/upstreams/{segment}/{name}")).json()
        assert body["gateway_mismatch"] == {"remote_gateway_id": "gw-other", "corrected": corrected}

    @pytest.mark.parametrize(
        ("segment", "name"), [("webapp", "seed-plain"), ("ssh", "seed-ssh"), ("k8s", "seed-k8s")]
    )
    async def test_it_is_null_when_the_entry_has_no_mismatch(
        self, genv: Env, segment: str, name: str
    ) -> None:
        _set_mismatches(genv, {"webapp/seed-ca": GatewayMismatch("gw-other", corrected=False)})
        body = (await genv.admin.get(f"/upstreams/{segment}/{name}")).json()
        assert "gateway_mismatch" in body
        assert body["gateway_mismatch"] is None

    async def test_it_is_null_before_any_pass_has_completed(self, genv: Env) -> None:
        genv.bundle.reconciler.last_result = None
        body = (await genv.admin.get("/upstreams/webapp/seed-plain")).json()
        assert body["gateway_mismatch"] is None

    async def test_the_automation_token_sees_the_mismatch_of_its_own_entries(
        self, genv: Env
    ) -> None:
        assert (await genv.auto.put("/upstreams/ssh/auto-ssh", json={
            "address": "ssh1.apps.example.com"})).status_code == 200
        _set_mismatches(genv, {"ssh/auto-ssh": GatewayMismatch("gw-other", corrected=True)})
        body = (await genv.auto.get("/upstreams/ssh/auto-ssh")).json()
        assert body["gateway_mismatch"] == {"remote_gateway_id": "gw-other", "corrected": True}


class TestSshAndKubernetesShape:
    @pytest.mark.parametrize(
        ("segment", "name", "kind", "address"),
        [
            ("ssh", "seed-ssh", "ssh", "seed-ssh.apps.example.com"),
            ("k8s", "seed-k8s", "kubernetes", "seed-k8s.apps.example.com"),
        ],
    )
    async def test_only_gateway_mismatch_is_added(
        self, genv: Env, segment: str, name: str, kind: str, address: str
    ) -> None:
        response = await genv.admin.get(f"/upstreams/{segment}/{name}")
        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == _EXISTING_KEYS | {"gateway_mismatch"}
        assert set(body) & _WEBAPP_ONLY_KEYS == set()
        assert (body["kind"], body["name"], body["origin"]) == (kind, name, "seed")
        assert body["address"] == address
        assert body["gateway_mismatch"] is None

    async def test_an_automation_owned_ssh_entry_has_no_policy_field(self, genv: Env) -> None:
        put = await genv.auto.put("/upstreams/ssh/auto-ssh", json={
            "address": "ssh1.apps.example.com"})
        assert put.status_code == 200, put.text
        for client in (genv.auto, genv.admin):
            body = (await client.get("/upstreams/ssh/auto-ssh")).json()
            assert set(body) == _EXISTING_KEYS | {"gateway_mismatch"}
            assert body["origin"] == "automation"


class TestAutomationPolicyViolations:
    async def _create(self, env: Env, name: str = "auto-a") -> None:
        put = await env.auto.put(
            f"/upstreams/webapp/{name}",
            json=_app(request_headers={"X-Team": "{{username}}", "x-env": "{{groups}}"}),
        )
        assert put.status_code == 200, put.text

    @pytest.mark.parametrize("who", ["admin", "auto"])
    async def test_an_entry_within_policy_reports_an_empty_list(self, genv: Env, who: str) -> None:
        await self._create(genv)
        client = genv.admin if who == "admin" else genv.auto
        body = (await client.get("/upstreams/webapp/auto-a")).json()
        assert body["origin"] == "automation"
        assert body["automation_policy_violations"] == []

    @pytest.mark.parametrize("who", ["admin", "auto"])
    async def test_narrowing_the_seed_makes_an_entry_off_policy(self, genv: Env, who: str) -> None:
        await self._create(genv)
        genv.bundle.seed_path.write_text(_seed(names=["X-Team"]), encoding="utf-8")
        client = genv.admin if who == "admin" else genv.auto
        response = await client.get("/upstreams/webapp/auto-a")
        assert response.status_code == 200, response.text
        assert response.json()["automation_policy_violations"] == [
            {"field": "request_headers.x-env", "reason": _NAME_NOT_ALLOWED}
        ]

    async def test_every_off_policy_header_is_listed_in_order(self, genv: Env) -> None:
        await self._create(genv)
        genv.bundle.seed_path.write_text(_seed(names=[]), encoding="utf-8")
        body = (await genv.auto.get("/upstreams/webapp/auto-a")).json()
        assert body["automation_policy_violations"] == [
            {"field": "request_headers.X-Team", "reason": _NAME_NOT_ALLOWED},
            {"field": "request_headers.x-env", "reason": _NAME_NOT_ALLOWED},
        ]

    async def test_the_report_changes_nothing(self, genv: Env) -> None:
        await self._create(genv)
        genv.bundle.seed_path.write_text(_seed(names=[]), encoding="utf-8")
        before = [o.patch for o in genv.bundle.store.list()]
        triggers = list(genv.bundle.reconciler.triggers)
        genv.tenant.operations.clear()
        for client in (genv.auto, genv.admin):
            assert (await client.get("/upstreams/webapp/auto-a")).status_code == 200
        assert [o.patch for o in genv.bundle.store.list()] == before
        assert genv.bundle.reconciler.triggers == triggers
        assert genv.tenant.operations == []

    async def test_an_off_policy_upstream_tls_is_reported(self, genv: Env) -> None:
        genv.bundle.store.add(
            {"web_apps": [{"name": "auto-legacy", **_app(upstream_tls="verify_ca")}]},
            "created before the policy tightened",
            "automation",
        )
        body = (await genv.admin.get("/upstreams/webapp/auto-legacy")).json()
        assert body["origin"] == "automation"
        assert body["automation_policy_violations"] == [
            {"field": "upstream_tls", "reason": _NOT_VERIFY_FULL}
        ]

    @pytest.mark.parametrize("name", ["seed-plain", "seed-ca", "seed-none"])
    async def test_a_seed_entry_omits_the_field(self, genv: Env, name: str) -> None:
        body = (await genv.admin.get(f"/upstreams/webapp/{name}")).json()
        assert body["origin"] == "seed"
        assert "automation_policy_violations" not in body

    async def test_an_admin_entry_omits_the_field(self, genv: Env) -> None:
        put = await genv.admin.put(
            "/upstreams/webapp/ops-app", json=_app(upstream_tls="verify_ca")
        )
        assert put.status_code == 200, put.text
        body = (await genv.admin.get("/upstreams/webapp/ops-app")).json()
        assert body["origin"] == "admin"
        assert "automation_policy_violations" not in body

    async def test_an_entry_the_admin_took_over_omits_the_field(self, genv: Env) -> None:
        await self._create(genv)
        took_over = await genv.admin.put(
            "/upstreams/webapp/auto-a", json={"upstream_tls": "verify_ca"}
        )
        assert took_over.status_code == 200, took_over.text
        body = (await genv.admin.get("/upstreams/webapp/auto-a")).json()
        assert body["origin"] == "admin"
        assert "automation_policy_violations" not in body
