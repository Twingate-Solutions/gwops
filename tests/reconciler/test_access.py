"""Reconcile-time access behaviour against the fake tenant.

Seed-declared references (entries and ``twingate.resource_defaults``) are resolved by
the reconciler; creates carry the resolved groups/policy; later changes are a delta
against the registry's last-applied record, so a group an admin added in the console is
never removed and the policy is never reset to Default.
"""

from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from gwops.reconciler.registry import AppliedAccess
from gwops.renderer.capabilities import Capabilities
from gwops.tgapi.client import TGClient

from .conftest import FakeResource, FakeTGServer
from .test_core import Env

_SEED = """\
twingate:
  network: acme
  gateway_id: g-1
  resource_defaults:
    groups: ["App Users"]
ssh_upstreams:
  - name: web-1
    address: 10.0.0.5
  - name: web-2
    address: 10.0.0.6
    access:
      groups: ["Platform Engineers"]
      security_policy: "MFA"
  - name: web-3
    address: 10.0.0.7
    access:
      groups: []
"""


@pytest.fixture
def tg_client() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="test-key")


@pytest.fixture
def tenant(tg_server: FakeTGServer) -> FakeTGServer:
    tg_server.add_group("App Users", "g-app")
    tg_server.add_group("Platform Engineers", "g-pe")
    tg_server.add_group("Ops", "g-ops")
    tg_server.add_policy("MFA", "p-mfa")
    return tg_server


@pytest.fixture
def make_env(
    tmp_path: Path, gateway_binary: Callable[..., Path], tg_client: TGClient
) -> Callable[[str], Env]:
    def _make(seed: str = _SEED) -> Env:
        return Env(tmp_path, seed, gateway_binary(), Capabilities(), tg_client)

    return _make


def _by_name(tenant: FakeTGServer) -> dict[str, FakeResource]:
    return {r.name: r for r in tenant.resources.values()}


class TestCreate:
    async def test_create_applies_precedence_and_records_last_applied(
        self, make_env: Callable[[str], Env], tenant: FakeTGServer
    ) -> None:
        env = make_env(_SEED)

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []
        res = _by_name(tenant)
        assert res["web-1"].groups == {"g-app"}
        assert res["web-1"].security_policy is None
        assert res["web-2"].groups == {"g-pe"}
        assert res["web-2"].security_policy == "p-mfa"
        assert res["web-3"].groups == set()
        assert env.registry.last_access("ssh/web-2") == AppliedAccess(
            frozenset({"g-pe"}), "p-mfa"
        )

    async def test_second_pass_is_quiet_and_names_are_looked_up_once(
        self, make_env: Callable[[str], Env], tenant: FakeTGServer
    ) -> None:
        env = make_env(_SEED)
        await env.reconciler.reconcile("startup")
        lookups_after_first = list(tenant.lookups())

        result = await env.reconciler.reconcile("tick")

        assert result.actions == []
        assert "UpdateResourceAccess" not in tenant.calls
        # Cache hit: no further name lookups on the second pass.
        assert tenant.lookups() == lookups_after_first
        assert sorted(lookups_after_first) == [
            "FindGroupsByName", "FindGroupsByName", "FindSecurityPoliciesByName"
        ]


class TestDelta:
    async def test_delta_adds_and_removes_only_what_gwops_applied(
        self, make_env: Callable[[str], Env], tenant: FakeTGServer
    ) -> None:
        tenant.add_group("A", "g-a")
        tenant.add_group("B", "g-b")
        tenant.add_group("C", "g-c")
        seed = _SEED.replace('groups: ["Platform Engineers"]', 'groups: ["B", "C"]')
        env = make_env(seed)
        await env.reconciler.reconcile("startup")
        web2 = env.registry.managed_ids()["ssh/web-2"]
        # Pretend gwops last applied {A, B}, and an admin added D in the console.
        env.registry.record_access("ssh/web-2", AppliedAccess(frozenset({"g-a", "g-b"}), "p-mfa"))
        tenant.resources[web2].groups = {"g-a", "g-b", "g-d"}

        result = await env.reconciler.reconcile("tick")

        assert result.errors == []
        [update] = tenant.access_updates
        assert update == {"id": web2, "addedGroupIds": ["g-c"], "removedGroupIds": ["g-a"]}
        assert "groupIds" not in update and "securityPolicyId" not in update
        assert tenant.resources[web2].groups == {"g-b", "g-c", "g-d"}  # D survives
        assert env.registry.last_access("ssh/web-2").groups == {"g-b", "g-c"}

    async def test_declared_policy_change_is_sent_never_null(
        self, make_env: Callable[[str], Env], tenant: FakeTGServer
    ) -> None:
        tenant.add_policy("Strict", "p-strict")
        env = make_env(_SEED)
        await env.reconciler.reconcile("startup")
        env.seed_path.write_text(_SEED.replace('"MFA"', '"Strict"'), encoding="utf-8")

        await env.reconciler.reconcile("seed-change")

        [update] = tenant.access_updates
        assert update["securityPolicyId"] == "p-strict"
        assert env.registry.last_access("ssh/web-2").security_policy == "p-strict"

    async def test_undeclaring_access_leaves_it_untouched(
        self, make_env: Callable[[str], Env], tenant: FakeTGServer
    ) -> None:
        env = make_env(_SEED)
        await env.reconciler.reconcile("startup")
        no_access = _SEED.replace(
            '    access:\n      groups: ["Platform Engineers"]\n      security_policy: "MFA"\n', ""
        ).replace("  resource_defaults:\n    groups: [\"App Users\"]\n", "")
        env.seed_path.write_text(no_access, encoding="utf-8")

        result = await env.reconciler.reconcile("seed-change")

        assert result.errors == []
        assert tenant.access_updates == []  # unmanaged keys: nothing sent, nothing reset

    async def test_changed_defaults_move_only_inheriting_resources(
        self, make_env: Callable[[str], Env], tenant: FakeTGServer
    ) -> None:
        env = make_env(_SEED)
        await env.reconciler.reconcile("startup")
        env.seed_path.write_text(_SEED.replace('["App Users"]', '["Ops"]'), encoding="utf-8")

        result = await env.reconciler.reconcile("seed-change")

        web1 = env.registry.managed_ids()["ssh/web-1"]
        [update] = tenant.access_updates
        assert update == {"id": web1, "addedGroupIds": ["g-ops"], "removedGroupIds": ["g-app"]}
        assert any("'web-1' access" in a for a in result.actions)


class TestUnresolvableSeedReference:
    async def test_bad_ref_is_a_per_resource_error_and_others_still_sync(
        self, make_env: Callable[[str], Env], tenant: FakeTGServer
    ) -> None:
        env = make_env(_SEED.replace('["Platform Engineers"]', '["Nope"]'))

        result = await env.reconciler.reconcile("startup")

        assert any("ssh/web-2: access: no group named 'Nope'" in e for e in result.errors)
        assert result.local_ok is True  # never a startup abort
        names = set(_by_name(tenant))
        assert "web-2" not in names  # not created with the wrong access
        assert {"web-1", "web-3"} <= names
        assert "ssh/web-2" not in result.tg_synced

    async def test_ambiguous_name_is_an_error(
        self, make_env: Callable[[str], Env], tenant: FakeTGServer
    ) -> None:
        tenant.add_group("Platform Engineers", "g-pe-2")
        env = make_env(_SEED)

        result = await env.reconciler.reconcile("startup")

        assert any("2 groups are named 'Platform Engineers'" in e for e in result.errors)
