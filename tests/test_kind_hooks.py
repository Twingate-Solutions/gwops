"""The per-kind hook fields on ResourceKind and their defaults.

SSH and Kubernetes keep every hook at its default, so they behave exactly as before the
hooks existed; a kind with more to sync overrides them on its descriptor.
"""

import subprocess
import sys
from dataclasses import MISSING, fields

import pytest

from gwops.configmodel.schema import EffectiveState, K8sCluster, SSHUpstream
from gwops.kindhooks import EMPTY_EXTRAS, no_drift, no_extras, upstream_port_only
from gwops.kinds import KINDS, ResourceKind
from gwops.renderer.desired import DesiredResource, desired_tg_objects
from gwops.renderer.sans import required_sans
from gwops.tgapi.ops import RemoteResource

_HOOK_FIELDS = {
    "list_fields",
    "upstream_input_required",
    "extra_create_args",
    "extra_update_args",
    "parse_remote",
    "create_variables",
    "settings_drift",
    "update_mutation",
    "automation_enabled",
    "automation_field_violations",
    "automation_exclusive_addresses",
}


def test_resource_kind_declares_every_hook_field_with_a_default() -> None:
    declared = {f.name: f for f in fields(ResourceKind)}
    assert set(declared) >= _HOOK_FIELDS
    for name in _HOOK_FIELDS:
        field = declared[name]
        assert field.default is not MISSING or field.default_factory is not MISSING, name


def test_supported_variants_is_not_a_field() -> None:
    assert "supported_variants" not in {f.name for f in fields(ResourceKind)}


@pytest.mark.parametrize(
    "kind", [k for k in KINDS if k.key != "webapp"], ids=lambda k: k.key
)
def test_ssh_and_kubernetes_use_the_defaults(kind: ResourceKind) -> None:
    assert kind.list_fields == "gateway { id } upstream { port }"
    assert kind.upstream_input_required is False
    assert kind.extra_create_args == ()
    assert kind.extra_update_args == ()
    assert kind.parse_remote is no_extras
    assert kind.create_variables is upstream_port_only
    assert kind.settings_drift is no_drift
    assert kind.update_mutation == "resourceUpdate"
    state = EffectiveState.model_validate({"twingate": {"network": "acme", "gateway_id": "g-1"}})
    assert kind.automation_enabled(state) is True
    assert kind.automation_exclusive_addresses is False
    sample = SSHUpstream(name="a", address="a.internal")
    assert kind.automation_field_violations(sample, state) == []


def test_default_hooks_behave() -> None:
    assert no_extras({"anything": 1}) is EMPTY_EXTRAS
    assert dict(EMPTY_EXTRAS) == {}
    assert upstream_port_only(2222, EMPTY_EXTRAS) == {"upstream": {"port": 2222}}
    assert no_drift(22, EMPTY_EXTRAS, 2222, EMPTY_EXTRAS) == {}


def test_empty_extras_is_immutable() -> None:
    with pytest.raises(TypeError):
        EMPTY_EXTRAS["x"] = 1  # type: ignore[index]


def test_hook_module_does_not_import_tgapi() -> None:
    """tgapi.ops imports kinds, which imports the hooks: the hooks must not import back."""
    code = (
        "import sys, gwops.kindhooks, gwops.kinds;"
        "assert not [m for m in sys.modules if m.startswith('gwops.tgapi')], 'tgapi imported'"
    )
    subprocess.run([sys.executable, "-c", code], check=True, capture_output=True)


def test_extras_are_excluded_from_remote_and_desired_equality_and_hash() -> None:
    plain = RemoteResource("r", "ssh", "n", "a", "g", 22)
    with_extras = RemoteResource("r", "ssh", "n", "a", "g", 22, extras={"alias": "x"})
    assert plain == with_extras
    assert hash(plain) == hash(with_extras)
    assert with_extras.extras == {"alias": "x"}
    assert plain.extras is EMPTY_EXTRAS

    want = DesiredResource(kind="ssh", name="n", address="a", upstream_port=22)
    want_extras = DesiredResource(
        kind="ssh", name="n", address="a", upstream_port=22, extras={"alias": "x"}
    )
    assert want == want_extras
    assert hash(want) == hash(want_extras)
    assert want.extras is EMPTY_EXTRAS


def test_upstream_entry_defaults() -> None:
    ssh = SSHUpstream(name="web", address="10.0.0.5:2222")
    cluster = K8sCluster(
        name="prod", address="prod.k8s.internal", port=6443, bearer_token_file="/t", ca_file="/c"
    )
    assert ssh.tg_extras() == {}
    assert cluster.tg_extras() == {}
    assert ssh.san_names() == ["10.0.0.5"]
    assert cluster.san_names() == ["prod.k8s.internal"]


def _state() -> EffectiveState:
    return EffectiveState.model_validate(
        {
            "twingate": {"network": "acme", "gateway_id": "g-1"},
            "ssh_upstreams": [{"name": "web", "address": "10.0.0.5:2222"}],
            "k8s_clusters": [
                {"name": "prod", "address": "prod.k8s.internal", "port": 6443,
                 "bearer_token_file": "/t", "ca_file": "/c"},
            ],
        }
    )


def test_required_sans_unions_san_names(monkeypatch: pytest.MonkeyPatch) -> None:
    assert required_sans(_state()) == {"10.0.0.5", "prod.k8s.internal"}

    monkeypatch.setattr(SSHUpstream, "san_names", lambda self: ["web.example", "alias.example"])
    assert required_sans(_state()) == {"web.example", "alias.example", "prod.k8s.internal"}


def test_desired_objects_carry_the_entries_extras(monkeypatch: pytest.MonkeyPatch) -> None:
    assert {d.key: dict(d.extras) for d in desired_tg_objects(_state())} == {
        "ssh/web": {},
        "kubernetes/prod": {},
    }
    monkeypatch.setattr(SSHUpstream, "tg_extras", lambda self: {"alias": "web.example"})
    by_key = {d.key: d for d in desired_tg_objects(_state())}
    assert dict(by_key["ssh/web"].extras) == {"alias": "web.example"}
    assert dict(by_key["kubernetes/prod"].extras) == {}
