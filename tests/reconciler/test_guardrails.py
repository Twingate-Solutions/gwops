"""End-to-end guardrails for unattended callers.

The admin API runs on the real reconciler and the fake tenant, with both an admin and an
automation token configured, and a seed carrying both allowlists. Covers the allowlists
(applied to every write), the automation token's scope, namespace ownership, the name
prefix, idempotent DELETE, and the per-upstream GET.
"""

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
_AUTO = "automation-token"

_SEED = """\
twingate:
  network: acme
  gateway_id: g-1
  access_allowlist:
    groups: ["App Users"]
    security_policies: []
  address_allowlist:
    cidrs: ["10.20.0.0/16"]
    dns_suffixes: ["apps.example.com"]
ssh_upstreams:
  - name: seed-1
    address: 10.0.0.5
    access:
      groups: ["Platform Engineers"]
"""

Clients = tuple[httpx.AsyncClient, httpx.AsyncClient]


@pytest.fixture
def tg_client() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="test-key")


@pytest.fixture
def tenant(tg_server: FakeTGServer) -> FakeTGServer:
    tg_server.add_group("App Users", "g-app")
    tg_server.add_group("Platform Engineers", "g-pe")
    return tg_server


@pytest.fixture
def make_clients(
    tmp_path: Path,
    gateway_binary: Callable[..., Path],
    tg_client: TGClient,
    tenant: FakeTGServer,
) -> Callable[[str], AsyncIterator[tuple[Env, Clients]]]:
    async def _make(seed: str = _SEED) -> AsyncIterator[tuple[Env, Clients]]:
        env = Env(tmp_path, seed, gateway_binary(), Capabilities(), tg_client)
        await env.reconciler.reconcile("startup")
        settings = env.settings.model_copy(
            update={
                "gwops_admin_token": SecretStr(_ADMIN),
                "gwops_automation_token": SecretStr(_AUTO),
            }
        )
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
        transport = httpx.ASGITransport(app=create_app(deps))
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
            yield env, (admin, auto)

    return _make  # type: ignore[return-value]


@pytest.fixture
async def setup(
    make_clients: Callable[[str], AsyncIterator[tuple[Env, Clients]]],
) -> AsyncIterator[tuple[Env, Clients]]:
    async for value in make_clients(_SEED):
        yield value


def _app(groups: list[object] | None = None, address: str = "10.20.1.5") -> dict[str, object]:
    body: dict[str, object] = {"address": address}
    if groups is not None:
        body["access"] = {"groups": groups}
    return body


class TestAccessAllowlist:
    async def test_non_allowlisted_group_is_403_by_name_and_by_id(
        self, setup: tuple[Env, Clients]
    ) -> None:
        env, (_admin, auto) = setup
        by_name = await auto.put("/upstreams/ssh/app-1", json=_app(["Platform Engineers"]))
        by_id = await auto.put("/upstreams/ssh/app-1", json=_app([{"id": "g-pe"}]))
        assert (by_name.status_code, by_id.status_code) == (403, 403)
        assert "access allowlist" in by_name.json()["detail"]
        assert env.store.list() == []

    async def test_allowlisted_group_is_accepted(
        self, setup: tuple[Env, Clients], tenant: FakeTGServer
    ) -> None:
        _env, (_admin, auto) = setup
        response = await auto.put("/upstreams/ssh/app-1", json=_app(["App Users"]))
        assert response.status_code == 200, response.text
        [app] = [r for r in tenant.resources.values() if r.name == "app-1"]
        assert app.groups == {"g-app"}

    async def test_allowlist_applies_to_the_admin_token_too(
        self, setup: tuple[Env, Clients]
    ) -> None:
        _env, (admin, _auto) = setup
        response = await admin.put("/upstreams/ssh/app-1", json=_app(["Platform Engineers"]))
        assert response.status_code == 403

    async def test_seed_entry_with_non_allowlisted_group_still_syncs(
        self, setup: tuple[Env, Clients], tenant: FakeTGServer
    ) -> None:
        [seed1] = [r for r in tenant.resources.values() if r.name == "seed-1"]
        assert seed1.groups == {"g-pe"}


class TestAddressAllowlist:
    @pytest.mark.parametrize(
        ("address", "status"),
        [("10.20.1.5", 200), ("x.apps.example.com", 200), ("10.30.0.1", 403),
         ("xapps.example.com", 403)],
    )
    async def test_addresses(
        self, setup: tuple[Env, Clients], address: str, status: int
    ) -> None:
        _env, (_admin, auto) = setup
        response = await auto.put("/upstreams/ssh/app-1", json=_app(address=address))
        assert response.status_code == status, response.text


class TestAutomationScope:
    @pytest.mark.parametrize(
        ("method", "path"),
        [("POST", "/overlays"), ("POST", "/certs/rotate-ca"), ("POST", "/reconcile"),
         ("GET", "/state"), ("GET", "/status"), ("DELETE", "/overlays/0001-x")],
    )
    async def test_other_routes_are_403(
        self, setup: tuple[Env, Clients], method: str, path: str
    ) -> None:
        _env, (_admin, auto) = setup
        response = await auto.request(method, path, json={})
        assert response.status_code == 403

    async def test_healthz_and_wrong_token_unchanged(self, setup: tuple[Env, Clients]) -> None:
        _env, (_admin, auto) = setup
        assert (await auto.get("/healthz", headers={"Authorization": ""})).status_code in (
            200, 503,
        )
        wrong = await auto.get("/upstreams/ssh/x", headers={"Authorization": "Bearer nope"})
        assert wrong.status_code == 401
        assert wrong.content == b""

    async def test_kubernetes_is_off_limits_to_automation(
        self, setup: tuple[Env, Clients]
    ) -> None:
        _env, (_admin, auto) = setup
        body = {"address": "10.20.0.9", "bearer_token_file": "/proc/self/environ",
                "ca_file": "/etc/hostname"}
        response = await auto.put("/upstreams/k8s/c1", json=body)
        assert response.status_code == 403
        assert "k8s_clusters" in response.json()["detail"]


class TestNamespace:
    async def test_seed_entry_is_409(self, setup: tuple[Env, Clients]) -> None:
        _env, (_admin, auto) = setup
        response = await auto.put("/upstreams/ssh/seed-1", json=_app())
        assert response.status_code == 409

    async def test_admin_entry_is_409(self, setup: tuple[Env, Clients]) -> None:
        _env, (admin, auto) = setup
        assert (await admin.put("/upstreams/ssh/ops-1", json=_app())).status_code == 200
        response = await auto.put("/upstreams/ssh/ops-1", json=_app())
        assert response.status_code == 409

    async def test_own_entry_can_be_put_again_until_admin_takes_it_over(
        self, setup: tuple[Env, Clients]
    ) -> None:
        env, (admin, auto) = setup
        assert (await auto.put("/upstreams/ssh/app-1", json=_app())).status_code == 200
        again = await auto.put("/upstreams/ssh/app-1", json=_app(address="10.20.1.6"))
        assert again.status_code == 200
        assert [o.origin for o in env.store.list()] == ["automation", "automation"]

        assert (await admin.put("/upstreams/ssh/app-1", json=_app())).status_code == 200
        assert (await auto.put("/upstreams/ssh/app-1", json=_app())).status_code == 409

    async def test_name_prefix_is_enforced(
        self, make_clients: Callable[[str], AsyncIterator[tuple[Env, Clients]]]
    ) -> None:
        seed = _SEED + "admin_api:\n  automation:\n    name_prefix: dokploy-\n"
        async for _env, (_admin, auto) in make_clients(seed):
            assert (await auto.put("/upstreams/ssh/app1", json=_app())).status_code == 403
            ok = await auto.put("/upstreams/ssh/dokploy-app1", json=_app())
            assert ok.status_code == 200, ok.text


class TestIdempotentDelete:
    async def test_automation_delete_of_missing_name_succeeds_twice(
        self, setup: tuple[Env, Clients]
    ) -> None:
        env, (_admin, auto) = setup
        for _ in range(2):
            response = await auto.delete("/upstreams/ssh/app-404")
            assert response.status_code == 200
            assert response.json() == {"deleted": False}
        assert env.store.list() == []

    async def test_admin_delete_of_missing_name_is_404(self, setup: tuple[Env, Clients]) -> None:
        _env, (admin, _auto) = setup
        assert (await admin.delete("/upstreams/ssh/app-404")).status_code == 404

    async def test_automation_deletes_its_own_entry(
        self, setup: tuple[Env, Clients], tenant: FakeTGServer
    ) -> None:
        _env, (_admin, auto) = setup
        await auto.put("/upstreams/ssh/app-1", json=_app())
        response = await auto.delete("/upstreams/ssh/app-1")
        assert response.status_code == 200
        assert response.json()["deleted"] is True
        assert "app-1" not in {r.name for r in tenant.resources.values()}

    async def test_automation_cannot_delete_a_seed_entry(
        self, setup: tuple[Env, Clients]
    ) -> None:
        _env, (_admin, auto) = setup
        assert (await auto.delete("/upstreams/ssh/seed-1")).status_code == 409


class TestGetUpstream:
    async def test_shows_tg_id_and_applied_access(
        self, setup: tuple[Env, Clients]
    ) -> None:
        env, (_admin, auto) = setup
        await auto.put("/upstreams/ssh/app-1", json=_app(["App Users"]))

        response = await auto.get("/upstreams/ssh/app-1")

        assert response.status_code == 200
        body = response.json()
        assert body["origin"] == "automation"
        assert body["tg_resource_id"] == env.registry.managed_ids()["ssh/app-1"]
        assert body["applied_access"] == {"groups": ["g-app"], "security_policy": None}
        assert body["declared_access"] == {"groups": [{"id": "g-app", "name": "App Users"}]}
        assert body["errors"] == []

    async def test_automation_cannot_see_entries_it_does_not_own(
        self, setup: tuple[Env, Clients]
    ) -> None:
        _env, (admin, auto) = setup
        assert (await auto.get("/upstreams/ssh/seed-1")).status_code == 404
        assert (await admin.get("/upstreams/ssh/seed-1")).status_code == 200

    async def test_shows_the_per_resource_error(
        self, make_clients: Callable[[str], AsyncIterator[tuple[Env, Clients]]]
    ) -> None:
        seed = _SEED.replace('["Platform Engineers"]', '["Nope"]')
        async for _env, (admin, _auto) in make_clients(seed):
            body = (await admin.get("/upstreams/ssh/seed-1")).json()
            assert body["tg_resource_id"] is None
            assert body["errors"] == ["access: no group named 'Nope'"]
