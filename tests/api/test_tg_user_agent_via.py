"""An admin route that calls Twingate directly tags the call with ``via=admin_api``."""

import dataclasses
import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from pydantic import SecretStr

from gwops._version import __version__
from gwops.api.app import create_app
from gwops.tgapi.client import TGClient

from .conftest import _TG_URL, ADMIN_TOKEN, FakeCARegistrar, make_deps


class TestRotateCaCompleteViaAdminApi:
    async def test_every_tg_call_of_rotate_ca_complete_carries_via_admin_api(
        self, tmp_path: Path, respx_mock: respx.MockRouter
    ) -> None:
        registrar = FakeCARegistrar()
        user_agents: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            user_agents.append(request.headers["User-Agent"])
            return registrar.handler(request)

        respx_mock.post(_TG_URL).mock(side_effect=handler)
        bundle = make_deps(tmp_path)
        bundle.deps.tg = TGClient(network="acme", api_key="k")
        headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=create_app(bundle.deps)),
                base_url="http://gwops",
                headers=headers,
            ) as client:
                assert (await client.post("/certs/rotate-ca", json={"phase": "stage"})).is_success
                complete = await client.post("/certs/rotate-ca", json={"phase": "complete"})
        finally:
            await bundle.deps.tg.aclose()

        assert complete.status_code == 200
        assert complete.json()["errors"] == []
        assert registrar.created_ca_pems, "the route made no TG calls"
        lib = f"python-httpx/{httpx.__version__}"
        assert user_agents
        for ua in user_agents:
            assert ua.startswith(f"twingate-gwops-gateway/{__version__} (")
            assert ua.endswith(f"; via=admin_api) {lib}")
            assert "op=" in ua
        assert any("op=write" in ua for ua in user_agents)


_ADMIN = "admin-token"
_AUTO = "automation-token"

_SEED_HEAD = """\
twingate:
  network: acme
  gateway_id: g-1
  address_allowlist:
    dns_suffixes: ["apps.example.com"]
"""
_SEED_ALLOWLIST = """\
  access_allowlist:
    groups: ["App Users"]
    security_policies: []
"""
_SEED_TAIL = """\
web_app_proxy:
  plaintext_upstreams:
    dns_suffixes: ["apps.example.com"]
admin_api:
  automation:
    name_prefix: auto-
    web_apps:
      enabled: true
"""
_SEED_WITH_ALLOWLIST = _SEED_HEAD + _SEED_ALLOWLIST + _SEED_TAIL
_SEED_WITHOUT_ALLOWLIST = _SEED_HEAD + _SEED_TAIL


class _TenantRecorder:
    """A fake tenant that records (operation, User-Agent) and answers the lookups routes make."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    @property
    def operations(self) -> set[str]:
        return {op for op, _ua in self.calls}

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        match = re.search(r"(?:query|mutation)\s+(\w+)", body["query"])
        assert match is not None
        operation = match.group(1)
        self.calls.append((operation, request.headers["User-Agent"]))
        no_more = {"hasNextPage": False, "endCursor": None}
        if operation == "FindGroupsByName":
            edges = [{"node": {"id": "g-app", "name": "App Users"}}]
            return httpx.Response(
                200, json={"data": {"groups": {"pageInfo": no_more, "edges": edges}}}
            )
        if operation == "GetGroup":
            return httpx.Response(
                200, json={"data": {"group": {"id": "g-app", "name": "App Users"}}}
            )
        if operation == "ListAllResourceAddresses":
            return httpx.Response(
                200, json={"data": {"resources": {"pageInfo": no_more, "edges": []}}}
            )
        raise AssertionError(f"unexpected tenant operation: {operation}")


class TestRouteSitesViaAdminApi:
    """Each route below reaches exactly one `attribution_via("admin_api")` site that
    `rotate-ca complete` does not: the operations it triggers pin which site ran."""

    @pytest.mark.parametrize(
        ("site", "seed", "principal", "segment", "body", "expected_operations"),
        [
            pytest.param(
                "_check_exclusivity",
                _SEED_WITH_ALLOWLIST,
                "automation",
                "webapp",  # address exclusivity is checked for web apps only
                {"address": "app.apps.example.com"},
                {"ListAllResourceAddresses"},
                id="check_exclusivity",
            ),
            pytest.param(
                "pin_access_or_http_error",
                _SEED_WITHOUT_ALLOWLIST,
                "admin",
                "ssh",
                {"address": "app.apps.example.com", "access": {"groups": ["App Users"]}},
                {"FindGroupsByName"},
                id="pin_access_or_http_error",
            ),
            pytest.param(
                "check_allowlists",
                _SEED_WITH_ALLOWLIST,
                "admin",
                "ssh",
                # An id reference: pinning only does GetGroup, so FindGroupsByName can
                # only come from resolving the seed's access allowlist.
                {"address": "app.apps.example.com", "access": {"groups": [{"id": "g-app"}]}},
                {"GetGroup", "FindGroupsByName"},
                id="check_allowlists",
            ),
        ],
    )
    async def test_every_tg_call_of_the_route_carries_via_admin_api(
        self,
        tmp_path: Path,
        respx_mock: respx.MockRouter,
        site: str,
        seed: str,
        principal: str,
        segment: str,
        body: dict[str, Any],
        expected_operations: set[str],
    ) -> None:
        tenant = _TenantRecorder()
        respx_mock.post(_TG_URL).mock(side_effect=tenant.handler)
        bundle = make_deps(tmp_path, seed=seed, admin_token=_ADMIN)
        bundle.deps = dataclasses.replace(
            bundle.deps,
            settings=bundle.deps.settings.model_copy(
                update={"gwops_automation_token": SecretStr(_AUTO)}
            ),
            tg=TGClient(network="acme", api_key="k"),
        )
        token = _AUTO if principal == "automation" else _ADMIN
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=create_app(bundle.deps)),
                base_url="http://gwops",
                headers={"Authorization": f"Bearer {token}"},
            ) as client:
                response = await client.put(f"/upstreams/{segment}/auto-a", json=body)
        finally:
            assert bundle.deps.tg is not None
            await bundle.deps.tg.aclose()

        assert response.status_code == 200, f"{site}: {response.text}"
        assert tenant.operations == expected_operations, site
        lib = f"python-httpx/{httpx.__version__}"
        for operation, ua in tenant.calls:
            assert ua.startswith(f"twingate-gwops-gateway/{__version__} ("), (site, operation)
            assert ua.endswith(f"; via=admin_api) {lib}"), (site, operation, ua)
