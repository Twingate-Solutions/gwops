"""The automation token's web-app rules: opt-in, field policy and address exclusivity."""

import dataclasses
import json
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import structlog.testing
from fastapi import HTTPException
from pydantic import SecretStr

from gwops.api.app import create_app
from gwops.api.routes_actions import _candidate_entry, _check_exclusivity, _check_field_policy
from gwops.configmodel.loader import load_effective_state
from gwops.kinds import SSH
from gwops.tgapi.client import TGClient

from .conftest import DepsBundle, make_deps

_ADMIN = "admin-token"
_AUTO = "automation-token"
_TG_URL = "https://acme.twingate.com/api/graphql/"
_OFF_MESSAGE = "the automation token may not manage web_apps entries"
_CONFLICT = "conflicts with an existing resource address or alias"


def _seed(opt_in: str = "enabled: true\n      request_header_names: [X-Team, x-env]") -> str:
    web_apps = f"    web_apps:\n      {opt_in}\n" if opt_in else ""
    return f"""\
twingate:
  network: acme
  gateway_id: g-1
  address_allowlist:
    cidrs: ["10.20.0.0/16", "127.0.0.0/8"]
    dns_suffixes: ["apps.example.com", "corp.example.com"]
  access_allowlist:
    groups: ["App Users"]
    security_policies: []
ssh_upstreams:
  - name: seed-ssh
    address: seed-ssh.apps.example.com
k8s_clusters:
  - name: seed-k8s
    address: seed-k8s.apps.example.com
    bearer_token_file: /config/k8s-creds/t
    ca_file: /config/k8s-creds/c
web_apps:
  - name: seed-web
    address: seed-web.apps.example.com
    alias: seed-alias.corp.example.com
web_app_proxy:
  plaintext_upstreams:
    cidrs: ["127.0.0.0/8"]
    dns_suffixes: ["apps.example.com"]
admin_api:
  automation:
    name_prefix: auto-
{web_apps}"""


@dataclass
class Tenant:
    """A fake tenant answering the all-resources listing and group-by-name lookups."""

    resources: list[dict[str, Any]] = field(default_factory=list)
    groups: dict[str, str] = field(
        default_factory=lambda: {"g-app": "App Users", "g-other": "Other Team"}
    )
    page_size: int = 100
    listing_status: int | None = None
    fail_on_page: int | None = None
    cursorless: bool = False
    operations: list[str] = field(default_factory=list)

    def add(self, resource_id: str, address: str, alias: str | None = None) -> None:
        self.resources.append(
            {"id": resource_id, "address": {"value": address}, "alias": alias}
        )

    @property
    def listings(self) -> int:
        return self.operations.count("ListAllResourceAddresses")

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        match = re.search(r"(?:query|mutation)\s+(\w+)", body["query"])
        assert match is not None
        operation = match.group(1)
        self.operations.append(operation)
        variables = body.get("variables") or {}
        if operation == "FindGroupsByName":
            wanted = variables["filter"]["name"]["eq"]
            nodes = [{"node": {"id": i, "name": n}} for i, n in self.groups.items() if n == wanted]
            page_info = {"hasNextPage": False, "endCursor": None}
            return httpx.Response(
                200, json={"data": {"groups": {"pageInfo": page_info, "edges": nodes}}}
            )
        assert operation == "ListAllResourceAddresses", operation
        page_number = self.operations.count(operation)
        if self.listing_status is not None or page_number == self.fail_on_page:
            return httpx.Response(self.listing_status or 400, text="down")
        offset = int(variables["after"] or 0)
        page = self.resources[offset : offset + self.page_size]
        more = offset + self.page_size < len(self.resources)
        cursor = None if self.cursorless else str(offset + self.page_size)
        return httpx.Response(
            200,
            json={
                "data": {
                    "resources": {
                        "pageInfo": {"hasNextPage": more, "endCursor": cursor if more else None},
                        "edges": [{"node": node} for node in page],
                    }
                }
            },
        )


@dataclass
class Env:
    bundle: DepsBundle
    tenant: Tenant
    admin: httpx.AsyncClient
    auto: httpx.AsyncClient

    def assert_nothing_persisted(self) -> None:
        assert self.bundle.store.list() == []
        assert self.bundle.reconciler.triggers == []


@pytest.fixture
async def env(tmp_path: Path) -> AsyncIterator[Env]:
    bundle = make_deps(tmp_path, seed=_seed(), admin_token=_ADMIN)
    tg = TGClient(network="acme", api_key="test-key")
    settings = bundle.deps.settings.model_copy(
        update={"gwops_automation_token": SecretStr(_AUTO)}
    )
    bundle.deps = dataclasses.replace(bundle.deps, settings=settings, tg=tg)
    app = create_app(bundle.deps)
    tenant = Tenant()
    transport = httpx.ASGITransport(app=app)
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


def _fields(response: httpx.Response) -> list[str]:
    return [v["field"] for v in response.json()["violations"]]


class TestOptIn:
    @pytest.mark.parametrize("opt_in", ["", "enabled: false"])
    async def test_off_is_403_on_put_get_and_delete(self, env: Env, opt_in: str) -> None:
        env.bundle.seed_path.write_text(_seed(opt_in), encoding="utf-8")
        responses = [
            await env.auto.put("/upstreams/webapp/auto-app", json=_app()),
            await env.auto.get("/upstreams/webapp/auto-app"),
            await env.auto.delete("/upstreams/webapp/auto-app"),
            await env.auto.delete("/upstreams/webapp/auto-never-existed"),
        ]
        assert [r.status_code for r in responses] == [403] * 4
        assert {r.json()["detail"] for r in responses} == {_OFF_MESSAGE}
        env.assert_nothing_persisted()
        assert env.tenant.operations == []

    async def test_admin_is_unaffected_when_off(self, env: Env) -> None:
        env.bundle.seed_path.write_text(_seed(""), encoding="utf-8")
        assert (await env.admin.put("/upstreams/webapp/ops-app", json=_app())).status_code == 200
        assert (await env.admin.get("/upstreams/webapp/ops-app")).status_code == 200
        assert (await env.admin.delete("/upstreams/webapp/ops-app")).status_code == 200

    async def test_ssh_is_unaffected_when_web_apps_are_off(self, env: Env) -> None:
        env.bundle.seed_path.write_text(_seed(""), encoding="utf-8")
        response = await env.auto.put(
            "/upstreams/ssh/auto-ssh", json={"address": "ssh1.apps.example.com"}
        )
        assert response.status_code == 200

    async def test_on_allows_the_kind(self, env: Env) -> None:
        response = await env.auto.put("/upstreams/webapp/auto-app", json=_app())
        assert response.status_code == 200, response.text
        assert (await env.auto.get("/upstreams/webapp/auto-app")).status_code == 200
        assert (await env.auto.delete("/upstreams/webapp/auto-app")).status_code == 200


class TestFieldTable:
    async def test_name_prefix(self, env: Env) -> None:
        refused = await env.auto.put("/upstreams/webapp/other", json=_app())
        assert refused.status_code == 403
        assert "must start with 'auto-'" in refused.json()["detail"]
        assert (await env.auto.put("/upstreams/webapp/auto-ok", json=_app())).status_code == 200

    async def test_address_allowlist(self, env: Env) -> None:
        refused = await env.auto.put("/upstreams/webapp/auto-a", json=_app(address="x.evil.test"))
        assert refused.status_code == 403
        assert "address allowlist" in refused.json()["detail"]
        ok = await env.auto.put("/upstreams/webapp/auto-a", json=_app(address="10.20.1.5"))
        assert ok.status_code == 200

    async def test_alias_allowed_null_and_allowlisted(self, env: Env) -> None:
        with_alias = _app(alias="wiki.corp.example.com")
        assert (await env.auto.put("/upstreams/webapp/auto-a", json=with_alias)).status_code == 200
        cleared = await env.auto.put("/upstreams/webapp/auto-a", json=_app(alias=None))
        assert cleared.status_code == 200

    async def test_alias_outside_the_allowlist_is_403(self, env: Env) -> None:
        response = await env.auto.put(
            "/upstreams/webapp/auto-a", json=_app(alias="wiki.evil.test")
        )
        assert response.status_code == 403
        assert "address allowlist" in response.json()["detail"]
        env.assert_nothing_persisted()

    async def test_upstream_tls_verify_full_only(self, env: Env) -> None:
        explicit = _app(upstream_tls="verify_full")
        assert (await env.auto.put("/upstreams/webapp/auto-a", json=explicit)).status_code == 200
        default = await env.auto.put(
            "/upstreams/webapp/auto-b", json=_app(address="b.apps.example.com")
        )
        assert default.status_code == 200
        for mode in ("verify_ca", "insecure", "none"):
            refused = await env.auto.put(
                "/upstreams/webapp/auto-c", json=_app(upstream_tls=mode)
            )
            assert refused.status_code == 403, mode
            assert _fields(refused) == ["upstream_tls"]
        assert len(env.bundle.store.list()) == 2

    @pytest.mark.parametrize("downstream", [{"tls": "tls13"}, {"tls": "none"}, {"port": 8443}])
    async def test_downstream_is_unrestricted(self, env: Env, downstream: dict[str, Any]) -> None:
        response = await env.auto.put(
            "/upstreams/webapp/auto-a", json=_app(downstream=downstream)
        )
        assert response.status_code == 200, response.text

    @pytest.mark.parametrize("headers", [None, {}])
    async def test_headers_absent_null_or_empty_are_allowed(
        self, env: Env, headers: dict[str, str] | None
    ) -> None:
        body = _app() if headers is None else _app(request_headers=headers)
        assert (await env.auto.put("/upstreams/webapp/auto-a", json=body)).status_code == 200
        null = await env.auto.put(
            "/upstreams/webapp/auto-b",
            json=_app(address="b.apps.example.com", request_headers=None),
        )
        assert null.status_code == 200

    @pytest.mark.parametrize("name", ["X-Team", "x-team", "X-TEAM", "X-Env"])
    async def test_allowlisted_header_names_match_case_insensitively(
        self, env: Env, name: str
    ) -> None:
        response = await env.auto.put(
            "/upstreams/webapp/auto-a", json=_app(request_headers={name: "{{username}}"})
        )
        assert response.status_code == 200, response.text

    async def test_a_header_name_outside_the_allowlist_is_403(self, env: Env) -> None:
        response = await env.auto.put(
            "/upstreams/webapp/auto-a", json=_app(request_headers={"X-Debug": "1"})
        )
        assert response.status_code == 403
        assert _fields(response) == ["request_headers.X-Debug"]

    async def test_the_jwt_key_is_refused_even_for_an_allowlisted_name(self, env: Env) -> None:
        response = await env.auto.put(
            "/upstreams/webapp/auto-a", json=_app(request_headers={"X-Team": "Bearer {{jwt}}"})
        )
        assert response.status_code == 403
        assert _fields(response) == ["request_headers.X-Team"]

    async def test_access_follows_the_access_allowlist(self, env: Env) -> None:
        ok = await env.auto.put(
            "/upstreams/webapp/auto-a", json=_app(access={"groups": ["App Users"]})
        )
        assert ok.status_code == 200, ok.text
        refused = await env.auto.put(
            "/upstreams/webapp/auto-b",
            json=_app(address="b.apps.example.com", access={"groups": ["Other Team"]}),
        )
        assert refused.status_code == 403
        assert "access allowlist" in refused.json()["detail"]

    async def test_web_app_proxy_is_unreachable(self, env: Env) -> None:
        in_entry = await env.auto.put(
            "/upstreams/webapp/auto-a", json=_app(web_app_proxy={"request_headers": {"X-A": "a"}})
        )
        assert in_entry.status_code == 422
        overlay = await env.auto.post(
            "/overlays", json={"patch": {"web_app_proxy": {"request_headers": {"X-A": "a"}}}}
        )
        assert overlay.status_code == 403
        env.assert_nothing_persisted()


class TestRefusalBody:
    _BAD = {
        "upstream_tls": "insecure",
        "request_headers": {"X-Team": "tok-{{jwt}}-zzz", "X-Debug": "leak-me-not-123"},
    }

    def _bad(self) -> dict[str, Any]:
        """Loopback keeps the body web-app-policy-valid, so only the field policy refuses it."""
        return _app(address="127.0.0.1", **self._BAD)

    async def test_lists_every_violation_and_echoes_no_value(self, env: Env) -> None:
        response = await env.auto.put("/upstreams/webapp/auto-grafana", json=self._bad())
        assert response.status_code == 403
        body = response.json()
        assert set(body) == {"detail", "violations"}
        assert body["detail"] == "automation policy refused web_apps entry 'auto-grafana'"
        assert body["violations"] == [
            {
                "field": "upstream_tls",
                "reason": "only verify_full is allowed for the automation token",
            },
            {
                "field": "request_headers.X-Team",
                "reason": "the jwt template key is not allowed for the automation token",
            },
            {
                "field": "request_headers.X-Debug",
                "reason": "header name not in admin_api.automation.web_apps.request_header_names",
            },
        ]
        for value in ("insecure", "tok-", "leak-me-not-123", "127.0.0.1"):
            assert value not in response.text

    async def test_persists_nothing_calls_no_tenant_and_audits_once(self, env: Env) -> None:
        with structlog.testing.capture_logs() as logs:
            response = await env.auto.put("/upstreams/webapp/auto-grafana", json=self._bad())
        assert response.status_code == 403
        env.assert_nothing_persisted()
        assert env.tenant.operations == []
        [audit] = [e for e in logs if e["event"] == "api.audit"]
        assert (audit["status"], audit["principal"], audit["method"]) == (403, "automation", "PUT")
        assert "leak-me-not-123" not in repr(logs)

    async def test_the_policy_runs_on_the_effective_candidate(self, env: Env) -> None:
        created = await env.auto.put(
            "/upstreams/webapp/auto-a", json=_app(request_headers={"X-Team": "{{username}}"})
        )
        assert created.status_code == 200
        env.bundle.seed_path.write_text(
            _seed("enabled: true\n      request_header_names: []"), encoding="utf-8"
        )
        again = await env.auto.put("/upstreams/webapp/auto-a", json=_app())
        assert again.status_code == 403
        assert _fields(again) == ["request_headers.X-Team"]
        assert len(env.bundle.store.list()) == 1


class TestSeedNarrowing:
    async def test_narrowing_leaves_existing_entries_untouched(self, env: Env) -> None:
        created = await env.auto.put(
            "/upstreams/webapp/auto-a", json=_app(request_headers={"X-Team": "{{username}}"})
        )
        assert created.status_code == 200
        before = [o.patch for o in env.bundle.store.list()]
        env.bundle.seed_path.write_text(
            _seed("enabled: true\n      request_header_names: []"), encoding="utf-8"
        )
        assert [o.patch for o in env.bundle.store.list()] == before
        state = (await env.admin.get("/state")).json()["state"]
        [entry] = [e for e in state["web_apps"] if e["name"] == "auto-a"]
        assert entry["request_headers"] == {"X-Team": "{{username}}"}
        assert (await env.auto.get("/upstreams/webapp/auto-a")).status_code == 200

    async def test_disabling_makes_entries_unreachable_to_automation_only(
        self, env: Env
    ) -> None:
        assert (await env.auto.put("/upstreams/webapp/auto-a", json=_app())).status_code == 200
        before = [o.patch for o in env.bundle.store.list()]
        env.bundle.seed_path.write_text(_seed("enabled: false"), encoding="utf-8")
        assert (await env.auto.get("/upstreams/webapp/auto-a")).status_code == 403
        assert (await env.auto.delete("/upstreams/webapp/auto-a")).status_code == 403
        assert [o.patch for o in env.bundle.store.list()] == before
        assert (await env.admin.get("/upstreams/webapp/auto-a")).status_code == 200
        assert (await env.admin.delete("/upstreams/webapp/auto-a")).status_code == 200


class TestAdminUnaffected:
    async def test_admin_ignores_the_field_policy_and_exclusivity(self, env: Env) -> None:
        env.tenant.add("t-1", "taken.apps.example.com")
        tls_and_names = await env.admin.put(
            "/upstreams/webapp/ops-app",
            json=_app(
                address="taken.apps.example.com",
                alias="seed-alias.corp.example.com",
                upstream_tls="verify_ca",
                request_headers={"X-Debug": "{{username}}"},
            ),
        )
        assert tls_and_names.status_code == 200, tls_and_names.text
        jwt = await env.admin.put(
            "/upstreams/webapp/ops-jwt",
            json=_app(address="taken.apps.example.com", request_headers={"X-Debug": "{{jwt}}"}),
        )
        assert jwt.status_code == 200, jwt.text
        assert env.tenant.listings == 0


class TestExclusivity:
    async def test_conflict_with_a_seed_entry_of_any_kind(self, env: Env) -> None:
        for taken in (
            "seed-web.apps.example.com",
            "seed-alias.corp.example.com",
            "seed-ssh.apps.example.com",
            "seed-k8s.apps.example.com",
        ):
            response = await env.auto.put("/upstreams/webapp/auto-a", json=_app(address=taken))
            assert response.status_code == 403, taken
            assert response.json()["violations"] == [{"field": "address", "reason": _CONFLICT}]
        env.assert_nothing_persisted()

    async def test_an_alias_may_not_equal_a_seed_address_or_alias(self, env: Env) -> None:
        for taken in ("seed-web.apps.example.com", "seed-alias.corp.example.com"):
            response = await env.auto.put("/upstreams/webapp/auto-a", json=_app(alias=taken))
            assert response.status_code == 403, taken
            assert response.json()["violations"] == [{"field": "alias", "reason": _CONFLICT}]

    async def test_both_fields_are_listed_together(self, env: Env) -> None:
        response = await env.auto.put(
            "/upstreams/webapp/auto-a",
            json=_app(address="seed-web.apps.example.com", alias="seed-alias.corp.example.com"),
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "automation policy refused web_apps entry 'auto-a'"
        assert _fields(response) == ["address", "alias"]

    async def test_conflict_with_an_admin_overlay_entry(self, env: Env) -> None:
        assert (
            await env.admin.put("/upstreams/ssh/ops-ssh", json={"address": "ops.apps.example.com"})
        ).status_code == 200
        assert (
            await env.admin.put(
                "/upstreams/webapp/ops-web",
                json=_app(address="opsweb.apps.example.com", alias="ops-alias.corp.example.com"),
            )
        ).status_code == 200
        persisted = len(env.bundle.store.list())
        for kwargs in (
            {"address": "ops.apps.example.com"},
            {"address": "opsweb.apps.example.com"},
            {"alias": "ops-alias.corp.example.com"},
        ):
            response = await env.auto.put("/upstreams/webapp/auto-a", json=_app(**kwargs))
            assert response.status_code == 403, kwargs
        assert len(env.bundle.store.list()) == persisted

    async def test_conflict_with_another_automation_web_app(self, env: Env) -> None:
        first = await env.auto.put(
            "/upstreams/webapp/auto-a", json=_app(alias="a-alias.corp.example.com")
        )
        assert first.status_code == 200
        same_address = await env.auto.put("/upstreams/webapp/auto-b", json=_app())
        same_alias = await env.auto.put(
            "/upstreams/webapp/auto-b",
            json=_app(address="b.apps.example.com", alias="a-alias.corp.example.com"),
        )
        assert (same_address.status_code, same_alias.status_code) == (403, 403)

    async def test_conflict_with_an_automation_ssh_entry(self, env: Env) -> None:
        ssh = await env.auto.put(
            "/upstreams/ssh/auto-ssh", json={"address": "ssh1.apps.example.com"}
        )
        assert ssh.status_code == 200
        assert env.tenant.listings == 0
        web = await env.auto.put(
            "/upstreams/webapp/auto-a", json=_app(address="ssh1.apps.example.com:2222")
        )
        assert web.status_code == 403

    async def test_conflict_with_an_unmanaged_tenant_resource(self, env: Env) -> None:
        env.tenant.add("t-1", "Unmanaged.Apps.Example.Com")
        env.tenant.add("t-2", "10.1.0.0/16", alias="net-alias.corp.example.com")
        for kwargs in (
            {"address": "unmanaged.apps.example.com"},
            {"address": "UNMANAGED.apps.example.com:8443"},
            {"alias": "unmanaged.apps.example.com"},
            {"alias": "net-alias.corp.example.com"},
        ):
            response = await env.auto.put("/upstreams/webapp/auto-a", json=_app(**kwargs))
            assert response.status_code == 403, kwargs
        env.assert_nothing_persisted()

    async def test_conflict_with_a_network_resource_address(self, env: Env) -> None:
        env.tenant.add("net-1", "legacy.apps.example.com")
        response = await env.auto.put(
            "/upstreams/webapp/auto-a", json=_app(address="legacy.apps.example.com")
        )
        assert response.status_code == 403

    async def test_every_page_is_read(self, env: Env) -> None:
        for i in range(5):
            env.tenant.add(f"t-{i}", f"filler{i}.apps.example.com")
        env.tenant.add("t-last", "lastpage.apps.example.com")
        env.tenant.page_size = 2
        response = await env.auto.put(
            "/upstreams/webapp/auto-a", json=_app(address="lastpage.apps.example.com")
        )
        assert response.status_code == 403
        assert env.tenant.listings == 3

    async def test_the_entrys_own_resource_is_not_a_conflict(self, env: Env) -> None:
        assert (await env.auto.put("/upstreams/webapp/auto-a", json=_app())).status_code == 200
        env.bundle.deps.registry.record("webapp", "auto-a", "res-a")
        env.tenant.add("res-a", "app.apps.example.com")
        again = await env.auto.put(
            "/upstreams/webapp/auto-a", json=_app(alias="a-alias.corp.example.com")
        )
        assert again.status_code == 200, again.text
        env.tenant.add("res-b", "other.apps.example.com")
        other = await env.auto.put(
            "/upstreams/webapp/auto-b", json=_app(address="other.apps.example.com")
        )
        assert other.status_code == 403

    async def test_a_free_name_is_accepted(self, env: Env) -> None:
        env.tenant.add("t-1", "someone-else.apps.example.com")
        response = await env.auto.put("/upstreams/webapp/auto-a", json=_app())
        assert response.status_code == 200, response.text
        assert env.tenant.listings == 1


class TestExclusivityUnavailable:
    async def test_tenant_down_is_503_and_persists_nothing(self, env: Env) -> None:
        env.tenant.listing_status = 400
        response = await env.auto.put("/upstreams/webapp/auto-a", json=_app())
        assert response.status_code == 503
        env.assert_nothing_persisted()

    async def test_a_failing_later_page_is_503(self, env: Env) -> None:
        for i in range(4):
            env.tenant.add(f"t-{i}", f"filler{i}.apps.example.com")
        env.tenant.page_size = 2
        env.tenant.fail_on_page = 2
        response = await env.auto.put("/upstreams/webapp/auto-a", json=_app())
        assert response.status_code == 503
        env.assert_nothing_persisted()

    async def test_a_listing_with_more_pages_but_no_cursor_is_503(self, env: Env) -> None:
        for i in range(4):
            env.tenant.add(f"t-{i}", f"filler{i}.apps.example.com")
        env.tenant.page_size = 2
        env.tenant.cursorless = True
        response = await env.auto.put("/upstreams/webapp/auto-a", json=_app())
        assert response.status_code == 503
        env.assert_nothing_persisted()

    async def test_no_api_key_is_503(self, env: Env) -> None:
        env.bundle.deps.tg = None
        response = await env.auto.put("/upstreams/webapp/auto-a", json=_app())
        assert response.status_code == 503
        assert "TWINGATE_API_KEY" in response.json()["detail"]
        env.assert_nothing_persisted()


class TestPipelineOrder:
    async def test_namespace_409_precedes_exclusivity(self, env: Env) -> None:
        response = await env.auto.put("/upstreams/webapp/auto-x", json=_app())
        assert response.status_code == 200
        assert (
            await env.admin.put("/upstreams/webapp/auto-x", json=_app(alias="adm.corp.example.com"))
        ).status_code == 200
        env.tenant.operations.clear()
        response = await env.auto.put("/upstreams/webapp/auto-x", json=_app())
        assert response.status_code == 409
        assert env.tenant.operations == []

    async def test_the_address_allowlist_precedes_exclusivity(self, env: Env) -> None:
        response = await env.auto.put("/upstreams/webapp/auto-a", json=_app(address="x.evil.test"))
        assert response.status_code == 403
        assert env.tenant.operations == []

    async def test_the_namespace_check_precedes_the_field_policy(self, env: Env) -> None:
        assert (
            await env.admin.put("/upstreams/webapp/auto-x", json=_app())
        ).status_code == 200
        response = await env.auto.put(
            "/upstreams/webapp/auto-x", json=_app(upstream_tls="insecure")
        )
        assert response.status_code == 409
        # Nothing about the admin-owned entry's field rules is disclosed.
        assert "violations" not in response.json()
        assert "upstream_tls" not in response.text

    async def test_the_field_policy_still_applies_to_an_entry_the_token_owns(
        self, env: Env
    ) -> None:
        assert (await env.auto.put("/upstreams/webapp/auto-x", json=_app())).status_code == 200
        response = await env.auto.put(
            "/upstreams/webapp/auto-x", json=_app(upstream_tls="insecure")
        )
        assert response.status_code == 403
        assert _fields(response) == ["upstream_tls"]

    async def test_pinning_precedes_exclusivity(self, env: Env) -> None:
        response = await env.auto.put(
            "/upstreams/webapp/auto-a",
            json=_app(address="seed-web.apps.example.com", access={"groups": ["No Such Group"]}),
        )
        assert response.status_code == 422
        assert "ListAllResourceAddresses" not in env.tenant.operations
        env.assert_nothing_persisted()

    async def test_the_access_allowlist_precedes_exclusivity(self, env: Env) -> None:
        response = await env.auto.put(
            "/upstreams/webapp/auto-a",
            json=_app(address="seed-web.apps.example.com", access={"groups": ["Other Team"]}),
        )
        assert response.status_code == 403
        assert response.json()["detail"].startswith("access allowlist")
        assert "ListAllResourceAddresses" not in env.tenant.operations
        assert env.tenant.listings == 0
        env.assert_nothing_persisted()

    async def test_exclusivity_runs_after_the_access_allowlist_passes(self, env: Env) -> None:
        response = await env.auto.put(
            "/upstreams/webapp/auto-a",
            json=_app(address="seed-web.apps.example.com", access={"groups": ["App Users"]}),
        )
        assert response.status_code == 403
        assert response.json()["violations"] == [{"field": "address", "reason": _CONFLICT}]
        assert env.tenant.operations.index("FindGroupsByName") < env.tenant.operations.index(
            "ListAllResourceAddresses"
        )

    async def test_schema_validation_precedes_the_field_policy(self, env: Env) -> None:
        response = await env.auto.put(
            "/upstreams/webapp/auto-a", json=_app(upstream_tls="bogus")
        )
        assert response.status_code == 422


class TestDeleteMarkerInPut:
    """A PUT body never carries ``_delete``; DELETE removes an entry."""

    _DETAIL = "use DELETE to remove an entry"

    @pytest.mark.parametrize("marker", [True, False])
    async def test_automation_ssh_is_422(self, env: Env, marker: bool) -> None:
        response = await env.auto.put(
            "/upstreams/ssh/auto-ssh", json={"address": "ssh1.apps.example.com", "_delete": marker}
        )
        assert response.status_code == 422
        assert response.json()["detail"] == self._DETAIL
        env.assert_nothing_persisted()
        assert env.tenant.operations == []

    async def test_automation_web_app_is_422(self, env: Env) -> None:
        response = await env.auto.put("/upstreams/webapp/auto-app", json=_app(_delete=True))
        assert response.status_code == 422
        assert response.json()["detail"] == self._DETAIL
        env.assert_nothing_persisted()
        assert env.tenant.operations == []

    async def test_it_is_refused_before_the_automation_reach_check(self, env: Env) -> None:
        env.bundle.seed_path.write_text(_seed(""), encoding="utf-8")
        response = await env.auto.put("/upstreams/webapp/auto-app", json=_app(_delete=True))
        assert response.status_code == 422

    async def test_automation_cannot_delete_an_existing_entry_through_put(
        self, env: Env
    ) -> None:
        assert (await env.auto.put("/upstreams/webapp/auto-app", json=_app())).status_code == 200
        overlays = env.bundle.store.list()
        response = await env.auto.put("/upstreams/webapp/auto-app", json=_app(_delete=True))
        assert response.status_code == 422
        assert env.bundle.store.list() == overlays

    @pytest.mark.parametrize(
        ("segment", "name", "body"),
        [
            ("ssh", "seed-ssh", {"address": "seed-ssh.apps.example.com"}),
            ("webapp", "ops-app", _app()),
        ],
    )
    async def test_admin_is_422_too(
        self, env: Env, segment: str, name: str, body: dict[str, Any]
    ) -> None:
        response = await env.admin.put(
            f"/upstreams/{segment}/{name}", json={**body, "_delete": True}
        )
        assert response.status_code == 422
        assert response.json()["detail"] == self._DETAIL
        env.assert_nothing_persisted()

    async def test_delete_still_removes_an_entry(self, env: Env) -> None:
        assert (await env.admin.put("/upstreams/webapp/ops-app", json=_app())).status_code == 200
        assert (await env.admin.delete("/upstreams/webapp/ops-app")).status_code == 200

    def test_a_candidate_without_the_entry_yields_none(self, env: Env) -> None:
        state, _provenance = load_effective_state(env.bundle.seed_path, env.bundle.store)
        assert _candidate_entry(SSH, "no-such-entry", state) is None
        assert _candidate_entry(SSH, "seed-ssh", state) is not None

    async def test_the_policy_checks_fail_closed_when_the_entry_is_absent(self, env: Env) -> None:
        state, _provenance = load_effective_state(env.bundle.seed_path, env.bundle.store)
        with pytest.raises(HTTPException) as field_policy:
            _check_field_policy(SSH, "no-such-entry", state)
        with pytest.raises(HTTPException) as exclusivity:
            await _check_exclusivity(env.bundle.deps, SSH, "no-such-entry", state)
        assert (field_policy.value.status_code, exclusivity.value.status_code) == (422, 422)
