"""End-to-end tests for transactional admin-API mutations.

The admin API runs against the REAL reconciler and the fake TG tenant, so these cover
the whole chain: a mutation is persisted, reconciled synchronously, and either kept
(TG sync confirmed, local config healthy) or rolled back — overlay removed and any
tenant object the failed pass created deleted again — with the failure in the response.
"""

import asyncio
import types
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import SecretStr

from gwops.api.app import GwopsDeps, create_app
from gwops.reconciler.registry import AppliedAccess
from gwops.renderer.capabilities import Capabilities
from gwops.tgapi.client import TGClient

from .conftest import FakeTGServer
from .test_core import _SSH_SEED, Env

_ADMIN_TOKEN = "test-admin-token"


@pytest.fixture
def tg_client() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="test-key")


@pytest.fixture
async def env(
    tmp_path: Path,
    gateway_binary: Callable[..., Path],
    tg_server: FakeTGServer,
    tg_client: TGClient,
) -> Env:
    """A reconciler over the SSH seed, already through one healthy startup pass."""
    env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
    result = await env.reconciler.reconcile("startup")
    assert result.ok, result.errors
    return env


@pytest.fixture
async def client(env: Env, tg_client: TGClient) -> AsyncIterator[httpx.AsyncClient]:
    settings = env.settings.model_copy(
        update={"gwops_admin_token": SecretStr(_ADMIN_TOKEN)}
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
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://gwops",
        headers={"Authorization": f"Bearer {_ADMIN_TOKEN}"},
    ) as client:
        yield client


def _k8s_body(source_root: Path, *, token_exists: bool = True) -> dict[str, object]:
    """A k8s upstream body whose credential files live under the confined source root."""
    source_root.mkdir(parents=True, exist_ok=True)
    token = source_root / "prod.token"
    ca = source_root / "prod-ca.crt"
    if token_exists:
        token.write_text("secret-token", encoding="utf-8")
    ca.write_text("PEM", encoding="utf-8")
    return {
        "address": "prod.k8s.internal",
        "port": 6443,
        "bearer_token_file": token.as_posix(),
        "ca_file": ca.as_posix(),
    }


def _names(tg_server: FakeTGServer) -> set[str]:
    return {r.name for r in tg_server.resources.values()}


class TestSuccessIsEndToEnd:
    async def test_put_creates_the_tg_resource_before_answering(
        self, client: httpx.AsyncClient, env: Env, tg_server: FakeTGServer
    ) -> None:
        response = await client.put("/upstreams/ssh/web-9", json={"address": "10.0.0.9:2222"})

        assert response.status_code == 200
        assert response.json()["reconcile"]["ok"] is True
        [created] = [r for r in tg_server.resources.values() if r.name == "web-9"]
        assert created.upstream_port == 2222
        assert "ssh/web-9" in env.registry.managed_ids()
        assert len(env.store.list()) == 1


class TestTGFailureRollsBack:
    async def test_rejected_create_leaves_no_overlay(
        self, client: httpx.AsyncClient, env: Env, tg_server: FakeTGServer
    ) -> None:
        tg_server.fail_ops = {"CreateSSHResource"}

        response = await client.put("/upstreams/ssh/web-9", json={"address": "10.0.0.9"})

        assert response.status_code == 422
        detail = response.json()["detail"]
        assert detail["rolled_back"] is True
        assert detail["unsynced"] == ["ssh/web-9"]
        assert any("ssh/web-9" in e for e in detail["errors"])
        assert env.store.list() == []
        assert "web-9" not in _names(tg_server)
        state = await client.get("/state")
        assert [u["name"] for u in state.json()["state"]["ssh_upstreams"]] == ["web-1"]

    async def test_unreachable_tenant_is_503_and_leaves_no_overlay(
        self, client: httpx.AsyncClient, env: Env, tg_server: FakeTGServer
    ) -> None:
        tg_server.fail = True

        response = await client.put("/upstreams/ssh/web-9", json={"address": "10.0.0.9"})

        assert response.status_code == 503
        assert env.store.list() == []

    async def test_failed_tg_delete_restores_the_upstream(
        self, client: httpx.AsyncClient, env: Env, tg_server: FakeTGServer
    ) -> None:
        web1_id = env.registry.managed_ids()["ssh/web-1"]
        tg_server.fail_ops = {"DeleteResource"}

        response = await client.delete("/upstreams/ssh/web-1")

        assert response.status_code == 422
        assert response.json()["detail"]["unsynced"] == ["ssh/web-1"]
        assert env.store.list() == []  # the _delete overlay is gone
        assert web1_id in tg_server.resources  # still on the tenant, still declared
        assert env.registry.managed_ids()["ssh/web-1"] == web1_id


class TestLocalFailureRollsBack:
    async def test_tg_object_created_by_a_failed_change_is_deleted_again(
        self,
        client: httpx.AsyncClient,
        env: Env,
        tg_server: FakeTGServer,
    ) -> None:
        # TG accepts the cluster, but its bearer-token file does not exist, so the
        # pass fails locally after the tenant resource was already created.
        body = _k8s_body(env.paths.k8s_source_root, token_exists=False)

        response = await client.put("/upstreams/k8s/prod", json=body)

        assert response.status_code == 422
        detail = response.json()["detail"]
        assert "local gateway config" in detail["message"]
        assert any("credential file" in e for e in detail["errors"])
        assert env.store.list() == []
        # The rollback pass deleted the resource the failed pass created.
        assert "prod" not in _names(tg_server)
        assert "kubernetes/prod" not in env.registry.managed_ids()
        assert detail["rollback"]["ok"] is True


class TestAccessReferences:
    """Request-time resolution: names are pinned to {id, name} before persisting."""

    async def test_put_pins_names_and_creates_with_those_groups(
        self, client: httpx.AsyncClient, env: Env, tg_server: FakeTGServer
    ) -> None:
        gid = tg_server.add_group("Platform Engineers")
        pid = tg_server.add_policy("MFA")
        body = {
            "address": "10.0.0.9",
            "access": {"groups": ["Platform Engineers"], "security_policy": "MFA"},
        }

        response = await client.put("/upstreams/ssh/web-9", json=body)

        assert response.status_code == 200, response.text
        [overlay] = env.store.list()
        access = overlay.patch["ssh_upstreams"][0]["access"]
        assert access == {
            "groups": [{"id": gid, "name": "Platform Engineers"}],
            "security_policy": {"id": pid, "name": "MFA"},
        }
        [created] = [r for r in tg_server.resources.values() if r.name == "web-9"]
        assert created.groups == {gid}
        assert created.security_policy == pid

    @pytest.mark.parametrize("copies", [0, 2])
    async def test_unresolvable_name_is_422_and_nothing_persisted(
        self, client: httpx.AsyncClient, env: Env, tg_server: FakeTGServer, copies: int
    ) -> None:
        for _ in range(copies):
            tg_server.add_group("Platform Engineers")
        calls_before = len(tg_server.calls)

        response = await client.put(
            "/upstreams/ssh/web-9",
            json={"address": "10.0.0.9", "access": {"groups": ["Platform Engineers"]}},
        )

        assert response.status_code == 422
        assert "access reference" in response.json()["detail"]
        assert env.store.list() == []
        assert tg_server.calls[calls_before:] == ["FindGroupsByName"]  # no reconcile ran

    async def test_unknown_explicit_id_is_422(
        self, client: httpx.AsyncClient, env: Env
    ) -> None:
        response = await client.put(
            "/upstreams/ssh/web-9",
            json={"address": "10.0.0.9", "access": {"groups": [{"id": "g-missing"}]}},
        )

        assert response.status_code == 422
        assert "no group with id 'g-missing'" in response.json()["detail"]
        assert env.store.list() == []

    async def test_tenant_down_during_resolution_is_503(
        self, client: httpx.AsyncClient, env: Env, tg_server: FakeTGServer
    ) -> None:
        tg_server.add_group("Platform Engineers")
        tg_server.fail = True

        response = await client.put(
            "/upstreams/ssh/web-9",
            json={"address": "10.0.0.9", "access": {"groups": ["Platform Engineers"]}},
        )

        assert response.status_code == 503
        assert env.store.list() == []

    async def test_patch_without_refs_makes_no_lookups(
        self, client: httpx.AsyncClient, tg_server: FakeTGServer
    ) -> None:
        response = await client.put("/upstreams/ssh/web-9", json={"address": "10.0.0.9"})

        assert response.status_code == 200
        assert tg_server.lookups() == []

    async def test_second_put_replaces_the_group_list(
        self, client: httpx.AsyncClient, env: Env, tg_server: FakeTGServer
    ) -> None:
        first = tg_server.add_group("A")
        second = tg_server.add_group("B")
        await client.put(
            "/upstreams/ssh/web-9", json={"address": "10.0.0.9", "access": {"groups": ["A"]}}
        )

        response = await client.put(
            "/upstreams/ssh/web-9", json={"address": "10.0.0.9", "access": {"groups": ["B"]}}
        )

        assert response.status_code == 200, response.text
        state = (await client.get("/state")).json()["state"]
        [web9] = [u for u in state["ssh_upstreams"] if u["name"] == "web-9"]
        assert web9["access"]["groups"] == [{"id": second, "name": "B"}]
        [resource] = [r for r in tg_server.resources.values() if r.name == "web-9"]
        assert resource.groups == {second}
        assert first not in resource.groups

    async def test_failed_access_update_rolls_back_and_keeps_last_applied(
        self, client: httpx.AsyncClient, env: Env, tg_server: FakeTGServer
    ) -> None:
        tg_server.add_group("Platform Engineers")
        tg_server.fail_ops = {"UpdateResourceAccess"}

        response = await client.put(
            "/upstreams/ssh/web-1",
            json={"address": "10.0.0.5:22", "access": {"groups": ["Platform Engineers"]}},
        )

        assert response.status_code == 422
        assert response.json()["detail"]["rolled_back"] is True
        assert env.store.list() == []
        assert env.registry.last_access("ssh/web-1") == AppliedAccess()


class TestDeferredWriteRollsBack:
    """A write deferred by a throttled pass is not confirmed: 422, as ADMIN_API.md documents."""

    @pytest.fixture(autouse=True)
    def _instant_throttle_waits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Replace only the TG client's view of asyncio, never asyncio.sleep globally.
        monkeypatch.setattr(
            "gwops.tgapi.client.asyncio", types.SimpleNamespace(sleep=AsyncMock())
        )

    async def test_put_whose_tg_write_is_deferred_is_422_and_rolled_back(
        self, client: httpx.AsyncClient, env: Env, tg_server: FakeTGServer
    ) -> None:
        # The first create is throttled once (then succeeds), so the pass defers every
        # later write; the overlay below declares two new upstreams.
        tg_server.throttle_ops = {"CreateSSHResource": 1}
        patch = {
            "ssh_upstreams": [
                {"name": "web-8", "address": "10.0.0.8"},
                {"name": "web-9", "address": "10.0.0.9"},
            ]
        }

        response = await client.post("/overlays", json={"patch": patch})

        assert response.status_code == 422
        detail = response.json()["detail"]
        assert detail["rolled_back"] is True
        # The exact wording ADMIN_API.md documents for a deferred write.
        assert "TG sync: ssh/web-9: deferred: rate-limited" in detail["errors"]
        assert detail["unsynced"] == ["ssh/web-9"]
        assert detail["rollback"]["ok"] is True
        # Rolled back: no overlay, and the tenant object the failed pass created is gone.
        assert env.store.list() == []
        assert _names(tg_server) == {"web-1"}
        assert {"ssh/web-8", "ssh/web-9"}.isdisjoint(env.registry.managed_ids())
