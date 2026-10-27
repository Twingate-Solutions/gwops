"""The reconciler drives a kind's settings hooks: drift sync, per-resource refusals, listing.

Uses a test-only ``ssh`` kind with the hook fields overridden and an ``alias`` setting.
"""

import types
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from gwops import kinds
from gwops.configmodel.schema import SSHUpstream
from gwops.kindhooks import Extras
from gwops.kinds import SSH, ResourceKind
from gwops.reconciler.core import DEFERRED_RATE_LIMITED
from gwops.renderer.capabilities import Capabilities
from gwops.tgapi import ops
from gwops.tgapi.client import TGClient

from .conftest import FakeTGServer
from .test_core import Env

_SECRET_ALIAS = "alias-value-that-must-not-be-logged.example"


@dataclass
class Hooks:
    """The test kind's behaviour: desired aliases per entry name, and what the hook saw."""

    aliases: dict[str, str] = field(default_factory=dict)
    calls: list[tuple[int, dict[str, Any], int, dict[str, Any]]] = field(default_factory=list)


@pytest.fixture
def tg_client() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="test-key")


@pytest.fixture(autouse=True)
def client_sleep(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Instant, recorded 429 waits (only the TG client's sleep is replaced)."""
    fake_sleep = AsyncMock()
    monkeypatch.setattr("gwops.tgapi.client.asyncio", types.SimpleNamespace(sleep=fake_sleep))
    return fake_sleep


@pytest.fixture
def hooks(monkeypatch: pytest.MonkeyPatch) -> Hooks:
    """Register an ``ssh`` kind that overrides the hooks; desired aliases come from `Hooks`."""
    state = Hooks()

    def parse_remote(node: dict[str, Any]) -> Extras:
        if node.get("alias") == "poison":
            raise ValueError("unparseable node")
        return {"alias": node.get("alias")}

    def settings_drift(
        want_port: int, want_extras: Extras, remote_port: int, remote_extras: Extras
    ) -> dict[str, Any]:
        state.calls.append((want_port, dict(want_extras), remote_port, dict(remote_extras)))
        alias = want_extras["alias"]
        if alias == "boom":
            raise ValueError("hook refused this resource")
        if alias == "undeclared":
            return {"notDeclared": True}
        drift: dict[str, Any] = {}
        if alias != remote_extras["alias"]:
            drift["alias"] = alias
        if want_port != remote_port:
            drift["upstream"] = {"port": want_port}
        return drift

    kind: ResourceKind = replace(
        SSH,
        extra_update_args=(("alias", "String"), ("upstream", "SSHUpstreamInput")),
        parse_remote=parse_remote,
        settings_drift=settings_drift,
    )
    monkeypatch.setitem(kinds._BY_KEY, "ssh", kind)
    monkeypatch.setitem(kinds._BY_TG_TYPE, "SSHResource", kind)
    monkeypatch.setattr(
        SSHUpstream, "tg_extras", lambda self: {"alias": state.aliases.get(self.name)}
    )
    return state


def _seed(addresses: Mapping[str, str]) -> str:
    lines = ["twingate:", "  network: acme", "  gateway_id: g-1"]
    lines.append("ssh_upstreams:" if addresses else "ssh_upstreams: []")
    for name, address in addresses.items():
        lines += [f"  - name: {name}", f"    address: {address}"]
    return "\n".join(lines) + "\n"


_ONE = {"web-1": "10.0.0.5:22"}
_TWO = {"web-1": "10.0.0.5:22", "web-2": "10.0.0.6:22"}


@pytest.fixture
def make_env(
    tmp_path: Path, gateway_binary: Callable[..., Path], tg_client: TGClient
) -> Callable[[Mapping[str, str]], Env]:
    def _make(addresses: Mapping[str, str]) -> Env:
        return Env(tmp_path, _seed(addresses), gateway_binary(), Capabilities(), tg_client)

    return _make


class TestSettingsDriftIsCorrected:
    async def test_one_update_per_drift_then_a_no_op_pass(
        self, make_env: Callable[..., Env], tg_server: FakeTGServer, hooks: Hooks
    ) -> None:
        hooks.aliases = {"web-1": _SECRET_ALIAS}
        env = make_env(_ONE)

        created = await env.reconciler.reconcile("startup")

        # A resource created this pass is not diffed against a node that did not exist.
        assert created.errors == []
        assert hooks.calls == []
        assert tg_server.settings_updates == []
        [resource_id] = tg_server.resources

        second = await env.reconciler.reconcile("tick")

        assert hooks.calls == [(22, {"alias": _SECRET_ALIAS}, 22, {"alias": None})]
        assert tg_server.settings_updates == [{"id": resource_id, "alias": _SECRET_ALIAS}]
        assert tg_server.calls.count("UpdateSSHResourceSettings") == 1
        assert second.errors == []
        assert "ssh/web-1" in second.tg_synced
        # The action line names the drifted field and never the value.
        [action] = [a for a in second.actions if "settings" in a]
        assert "alias" in action
        assert _SECRET_ALIAS not in " ".join(second.actions)

        third = await env.reconciler.reconcile("tick")

        assert tg_server.calls.count("UpdateSSHResourceSettings") == 1
        assert len(hooks.calls) == 2  # evaluated again, found in sync
        assert third.errors == []
        assert not [a for a in third.actions if "settings" in a]

    async def test_the_hook_runs_once_per_existing_resource_per_pass(
        self, make_env: Callable[..., Env], tg_server: FakeTGServer, hooks: Hooks
    ) -> None:
        env = make_env(_TWO)
        await env.reconciler.reconcile("startup")
        assert hooks.calls == []

        await env.reconciler.reconcile("tick")

        assert len(hooks.calls) == 2
        assert tg_server.settings_updates == []

    async def test_a_drifted_upstream_travels_in_the_settings_update_alone(
        self, make_env: Callable[..., Env], tg_server: FakeTGServer, hooks: Hooks
    ) -> None:
        env = make_env(_ONE)
        await env.reconciler.reconcile("startup")
        [resource] = tg_server.resources.values()
        env.seed_path.write_text(_seed({"web-1": "10.0.0.5:2222"}), encoding="utf-8")

        result = await env.reconciler.reconcile("tick")

        assert result.errors == []
        assert tg_server.settings_updates == [{"id": resource.id, "upstream": {"port": 2222}}]
        assert "UpdateSSHResourceUpstream" not in tg_server.calls
        assert resource.upstream_port == 2222

    async def test_address_and_settings_drift_are_separate_single_mutations(
        self, make_env: Callable[..., Env], tg_server: FakeTGServer, hooks: Hooks
    ) -> None:
        env = make_env(_ONE)
        await env.reconciler.reconcile("startup")
        hooks.aliases = {"web-1": "a.example"}
        env.seed_path.write_text(_seed({"web-1": "10.0.9.9:22"}), encoding="utf-8")

        result = await env.reconciler.reconcile("tick")

        assert result.errors == []
        assert tg_server.calls.count("UpdateResourceAddress") == 1
        assert tg_server.calls.count("UpdateSSHResourceSettings") == 1


class TestSettingsUpdateIsDeferredWhenThrottled:
    async def test_the_second_update_waits_for_the_next_pass(
        self, make_env: Callable[..., Env], tg_server: FakeTGServer, hooks: Hooks
    ) -> None:
        env = make_env(_TWO)
        await env.reconciler.reconcile("startup")
        hooks.aliases = {"web-1": "a.example", "web-2": "b.example"}
        tg_server.throttle_ops = {"UpdateSSHResourceSettings": 1}

        result = await env.reconciler.reconcile("tick")

        # web-1 was throttled once, waited out and applied; web-2 was never attempted.
        assert tg_server.calls.count("UpdateSSHResourceSettings") == 2
        assert len(tg_server.settings_updates) == 1
        assert result.resource_errors == {"ssh/web-2": [DEFERRED_RATE_LIMITED]}
        assert result.tg_synced == {"ssh/web-1"}

        third = await env.reconciler.reconcile("tick")

        assert third.errors == []
        assert len(tg_server.settings_updates) == 2
        assert third.tg_synced == {"ssh/web-1", "ssh/web-2"}


class TestRefusalsArePerResource:
    async def test_a_hook_or_op_refusal_does_not_abort_the_pass(
        self, make_env: Callable[..., Env], tg_server: FakeTGServer, hooks: Hooks
    ) -> None:
        addresses = {
            "web-1": "10.0.0.5:22",
            "web-2": "10.0.0.6:22",
            "web-3": "10.0.0.7:22",
        }
        env = make_env(addresses)
        await env.reconciler.reconcile("startup")
        hooks.aliases = {"web-1": "boom", "web-2": "undeclared", "web-3": "fine.example"}

        result = await env.reconciler.reconcile("tick")

        [hook_refusal] = result.resource_errors["ssh/web-1"]
        assert "hook refused this resource" in hook_refusal
        [op_refusal] = result.resource_errors["ssh/web-2"]
        assert "undeclared settings ['notDeclared']" in op_refusal
        assert "ssh/web-3" not in result.resource_errors
        assert "ssh/web-3" in result.tg_synced
        assert not {"ssh/web-1", "ssh/web-2"} & result.tg_synced
        [update] = tg_server.settings_updates
        assert update["alias"] == "fine.example"
        # Loud, but a TG-side error: the local steps still ran.
        assert result.ok is False
        assert result.local_ok is True
        assert env.config_path.is_file()

    async def test_a_delete_refusal_does_not_abort_the_other_deletes(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        hooks: Hooks,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        env = make_env(_TWO)
        await env.reconciler.reconcile("startup")
        by_name = {r.name: r.id for r in tg_server.resources.values()}
        real_delete = ops.delete_resource

        async def delete(tg: TGClient, resource_id: str) -> None:
            if resource_id == by_name["web-1"]:
                raise ValueError("delete refused")
            await real_delete(tg, resource_id)

        monkeypatch.setattr(ops, "delete_resource", delete)
        env.seed_path.write_text(_seed({}), encoding="utf-8")

        result = await env.reconciler.reconcile("tick")

        assert result.resource_errors["ssh/web-1"] == ["delete: delete refused"]
        assert "ssh/web-2" not in result.resource_errors
        assert set(tg_server.resources) == {by_name["web-1"]}
        assert "ssh/web-2" in result.tg_synced
        assert "ssh/web-1" in env.registry.managed_ids()  # still owned, retried next pass
        assert result.local_ok is True


class TestUnparseableNodes:
    async def test_an_unmanaged_node_is_skipped_and_the_pass_proceeds(
        self, make_env: Callable[..., Env], tg_server: FakeTGServer, hooks: Hooks
    ) -> None:
        stranger = tg_server.add_resource("ssh", "stranger", "10.9.9.9", "g-1")
        tg_server.resources[stranger].settings["alias"] = "poison"
        env = make_env(_ONE)

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []
        assert result.tg_unavailable is False
        assert "ssh/web-1" in result.tg_synced
        # Untouched: not adopted, not changed, not deleted.
        assert tg_server.resources[stranger].address == "10.9.9.9"
        assert tg_server.calls.count("DeleteResource") == 0

    async def test_a_managed_node_that_will_not_parse_fails_the_listing(
        self, make_env: Callable[..., Env], tg_server: FakeTGServer, hooks: Hooks
    ) -> None:
        env = make_env(_ONE)
        await env.reconciler.reconcile("startup")
        [resource] = tg_server.resources.values()
        resource.settings["alias"] = "poison"

        result = await env.reconciler.reconcile("tick")

        assert result.tg_unavailable is True
        assert any("could not list resources" in e for e in result.errors)
        assert result.local_ok is True
