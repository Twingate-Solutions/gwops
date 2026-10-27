"""Web-app writes through the admin API on the real reconciler and the fake tenant."""

import asyncio
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from gwops.api.app import GwopsDeps, create_app
from gwops.renderer.capabilities import Capabilities
from gwops.tgapi.client import TGClient

from .conftest import FakeTGServer
from .test_core import Env

_ADMIN = "admin-token"
_REFUSED = "web-app policy refused the change"

_SEED = """\
twingate:
  network: acme
  gateway_id: g-1
  address_allowlist:
    cidrs: ["10.20.0.0/16"]
    dns_suffixes: ["apps.example.com"]
ssh_upstreams:
  - name: seed-1
    address: 10.0.0.5
"""


@pytest.fixture
def tg_client() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="test-key")


@pytest.fixture
async def setup(
    tmp_path: Path,
    gateway_binary: Callable[..., Path],
    tg_client: TGClient,
    tg_server: FakeTGServer,
) -> AsyncIterator[tuple[Env, httpx.AsyncClient]]:
    env = Env(tmp_path, _SEED, gateway_binary(), Capabilities(), tg_client)
    await env.reconciler.reconcile("startup")
    settings = env.settings.model_copy(update={"gwops_admin_token": SecretStr(_ADMIN)})
    deps = GwopsDeps(
        settings=settings,
        store=env.store,
        reconciler=env.reconciler,
        certs=env.certs,
        process=env.process,  # type: ignore[arg-type]
        caps=Capabilities(),
        registry=env.registry,
        tg=tg_client,
        api_event=asyncio.Event(),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(deps)),
        base_url="http://gwops",
        headers={"Authorization": f"Bearer {_ADMIN}"},
    ) as admin:
        yield env, admin


class TestValidWrite:
    async def test_put_persists_reconciles_and_creates_the_resource(
        self, setup: tuple[Env, httpx.AsyncClient], tg_server: FakeTGServer
    ) -> None:
        env, admin = setup
        response = await admin.put(
            "/upstreams/webapp/grafana",
            json={"address": "grafana.apps.example.com", "alias": "graf.apps.example.com"},
        )
        assert response.status_code == 200, response.text
        assert "CreateWebAppResource" in tg_server.calls
        resource_id = env.registry.managed_ids()["webapp/grafana"]
        created = tg_server.resources[resource_id]
        assert (created.kind, created.address) == ("webapp", "grafana.apps.example.com")
        assert created.web["alias"] == "graf.apps.example.com"
        assert [o.patch["web_apps"][0]["name"] for o in env.store.list()] == ["grafana"]
        assert env.reconciler.last_result is not None
        assert env.reconciler.last_result.trigger == "api"

    async def test_overlay_persists_reconciles_and_creates_the_resource(
        self, setup: tuple[Env, httpx.AsyncClient], tg_server: FakeTGServer
    ) -> None:
        env, admin = setup
        patch = {"web_apps": [{"name": "wiki", "address": "wiki.apps.example.com"}]}
        response = await admin.post("/overlays", json={"patch": patch})
        assert response.status_code == 201, response.text
        assert "CreateWebAppResource" in tg_server.calls
        assert "webapp/wiki" in env.registry.managed_ids()


class TestRefusedWrite:
    @pytest.mark.parametrize("route", ["put", "overlay"])
    async def test_a_policy_violation_never_reaches_persist_reconcile_or_the_tenant(
        self, setup: tuple[Env, httpx.AsyncClient], tg_server: FakeTGServer, route: str
    ) -> None:
        env, admin = setup
        calls_before = list(tg_server.calls)
        body = {"address": "legacy.apps.example.com", "upstream_tls": "insecure"}
        if route == "put":
            response = await admin.put("/upstreams/webapp/legacy", json=body)
        else:
            patch = {"web_apps": [{"name": "legacy", **body}]}
            response = await admin.post("/overlays", json={"patch": patch})

        assert response.status_code == 422, response.text
        payload = response.json()
        assert set(payload) == {"detail", "violations"}
        assert payload["detail"] == _REFUSED
        assert any("plaintext_upstreams" in v for v in payload["violations"])
        assert env.store.list() == []
        assert tg_server.calls == calls_before
        assert env.reconciler.last_result is not None
        assert env.reconciler.last_result.trigger == "startup"
        assert "webapp/legacy" not in env.registry.managed_ids()
