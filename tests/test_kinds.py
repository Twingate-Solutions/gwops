"""Invariants of the resource-kind registry (gwops.kinds).

These are the checks that keep a newly added kind fully wired: every descriptor must
point at a real ``list[UpstreamEntry]`` field, be uniquely addressable, and show up in
every place that iterates the registry (TG list fragments, create mutations, overlay
allowlist, desired objects, SANs, admin API routes).
"""

import dataclasses
import typing

import pytest

from gwops.api.routes_state import _OVERLAY_ALLOWED_TOP_KEYS
from gwops.configmodel.schema import EffectiveState, UpstreamEntry
from gwops.kinds import KINDS, ResourceKind, by_key, by_segment, by_tg_type, is_resource_key
from gwops.renderer.desired import desired_tg_objects
from gwops.renderer.sans import required_sans
from gwops.tgapi.ops import _LIST_RESOURCES_QUERY, _create_mutation, _update_upstream_mutation


@pytest.mark.parametrize("attr", ["key", "state_field", "api_segment", "tg_type"])
def test_descriptor_identifiers_are_unique(attr: str) -> None:
    values = [getattr(kind, attr) for kind in KINDS]
    assert len(values) == len(set(values))


@pytest.mark.parametrize("kind", KINDS, ids=lambda k: k.key)
def test_state_field_is_a_list_of_upstream_entries(kind: ResourceKind) -> None:
    field = EffectiveState.model_fields[kind.state_field]
    assert typing.get_origin(field.annotation) is list
    [item_type] = typing.get_args(field.annotation)
    assert issubclass(item_type, UpstreamEntry)


@pytest.mark.parametrize("kind", KINDS, ids=lambda k: k.key)
def test_lookups_round_trip(kind: ResourceKind) -> None:
    assert by_key(kind.key) is kind
    assert by_segment(kind.api_segment) is kind
    assert by_tg_type(kind.tg_type) is kind
    assert is_resource_key(f"{kind.key}/x")


def test_non_resource_registry_keys_are_not_resource_keys() -> None:
    assert not is_resource_key("ca/x509")
    assert not is_resource_key("gateway/self")
    assert not is_resource_key("ssh")


@pytest.mark.parametrize("kind", KINDS, ids=lambda k: k.key)
def test_every_kind_is_wired_into_tg_ops(kind: ResourceKind) -> None:
    assert f"... on {kind.tg_type} {{" in _LIST_RESOURCES_QUERY
    create = _create_mutation(kind)
    assert f"{kind.tg_field_prefix}Create(" in create
    assert f"$upstream: {kind.tg_upstream_input}" in create
    update = _update_upstream_mutation(kind)
    assert f"{kind.tg_field_prefix}Update(" in update


def test_every_kind_is_overlayable() -> None:
    assert {kind.state_field for kind in KINDS} <= _OVERLAY_ALLOWED_TOP_KEYS


def test_desired_objects_and_sans_cover_every_kind() -> None:
    state = EffectiveState.model_validate(
        {
            "twingate": {"network": "acme", "gateway_id": "g-1"},
            "ssh_upstreams": [{"name": "web-1", "address": "10.0.0.5:2222"}],
            "k8s_clusters": [
                {"name": "prod", "address": "prod.k8s.internal", "port": 6443,
                 "bearer_token_file": "/t", "ca_file": "/c"},
            ],
            "web_apps": [
                {"name": "wiki", "address": "wiki.internal", "alias": "wiki.corp.example"},
            ],
        }
    )
    assert {(d.kind, d.key) for d in desired_tg_objects(state)} == {
        ("ssh", "ssh/web-1"),
        ("kubernetes", "kubernetes/prod"),
        ("webapp", "webapp/wiki"),
    }
    assert required_sans(state) == {
        "10.0.0.5", "prod.k8s.internal", "wiki.internal", "wiki.corp.example",
    }


@pytest.mark.parametrize("kind", KINDS, ids=lambda k: k.key)
def test_hook_overrides_are_complete(kind: ResourceKind) -> None:
    """A kind's settings hooks come as a set; a partial set would silently not sync."""
    defaults = {
        f.name: f.default for f in dataclasses.fields(ResourceKind)
        if f.default is not dataclasses.MISSING
    }

    def overridden(name: str) -> bool:
        return bool(getattr(kind, name) != defaults[name])

    problems: list[str] = []
    if overridden("settings_drift") and not kind.extra_update_args:
        problems.append("settings_drift is overridden but extra_update_args is empty")
    if kind.extra_create_args and not overridden("create_variables"):
        problems.append("extra_create_args is declared but create_variables is not overridden")
    if kind.automation_exclusive_addresses and not kind.automation_allowed:
        problems.append("automation_exclusive_addresses is set but automation_allowed is not")
    if (
        overridden("automation_enabled") or overridden("automation_field_violations")
    ) and not kind.automation_allowed:
        problems.append("an automation hook is overridden but automation_allowed is False")
    [item_type] = typing.get_args(EffectiveState.model_fields[kind.state_field].annotation)
    if item_type.tg_extras is not UpstreamEntry.tg_extras and not (
        overridden("parse_remote") and overridden("settings_drift")
    ):
        problems.append(
            f"{item_type.__name__}.tg_extras is overridden but parse_remote and settings_drift "
            "are not both overridden, so the extras could never be compared or corrected"
        )
    assert not problems, f"kind {kind.key!r}: {'; '.join(problems)}"


@pytest.mark.parametrize("kind", KINDS, ids=lambda k: k.key)
def test_automation_hooks_have_the_documented_shapes(kind: ResourceKind) -> None:
    """The defaulted automation fields answer for every kind without a seed opt-in."""
    state = EffectiveState.model_validate({"twingate": {"network": "acme", "gateway_id": "g-1"}})
    assert isinstance(kind.automation_enabled(state), bool)
    assert isinstance(kind.automation_exclusive_addresses, bool)
    [item_type] = typing.get_args(EffectiveState.model_fields[kind.state_field].annotation)
    sample = {
        "ssh": {"name": "a", "address": "a.internal"},
        "kubernetes": {
            "name": "a", "address": "a.internal", "bearer_token_file": "/t", "ca_file": "/c",
        },
        "webapp": {"name": "a", "address": "a.internal"},
    }[kind.key]
    assert isinstance(kind.automation_field_violations(item_type(**sample), state), list)


def test_only_web_apps_need_an_opt_in_and_exclusive_addresses() -> None:
    off = EffectiveState.model_validate({"twingate": {"network": "acme", "gateway_id": "g-1"}})
    assert {k.key for k in KINDS if not k.automation_enabled(off)} == {"webapp"}
    assert {k.key for k in KINDS if k.automation_exclusive_addresses} == {"webapp"}
    assert {k.key for k in KINDS if k.automation_allowed} == {"ssh", "webapp"}


def test_only_web_apps_take_the_merged_update() -> None:
    assert {k.key for k in KINDS if k.merged_update} == {"webapp"}


@pytest.mark.parametrize("kind", [k for k in KINDS if k.merged_update], ids=lambda k: k.key)
def test_a_merged_update_kind_has_its_own_update_mutation_and_gateway_argument(
    kind: ResourceKind,
) -> None:
    """The merged update replaces the generic mutation, so the kind must name its own."""
    assert kind.update_mutation != "resourceUpdate"
    assert "gatewayId" in {arg for arg, _gql in kind.extra_update_args}
