"""Tests for gwops.renderer.desired.desired_tg_objects."""

from types import MappingProxyType
from typing import Any

import pytest

from gwops.configmodel.schema import EffectiveState
from gwops.kindhooks import EMPTY_EXTRAS, normalise_extras, normalise_rewrites
from gwops.kinds import KINDS, ResourceKind
from gwops.renderer import desired as desired_module
from gwops.renderer.desired import DesiredResource, desired_tg_objects


def make_state(**overrides: Any) -> EffectiveState:
    base: dict[str, Any] = {"twingate": {"network": "acme", "gateway_id": "g-1"}}
    base.update(overrides)
    return EffectiveState.model_validate(base)


class TestSSHUpstreams:
    def test_one_desired_resource_per_ssh_upstream(self) -> None:
        state = make_state(
            ssh_upstreams=[
                {"name": "web-1", "address": "10.0.10.5:22"},
                {"name": "build-box", "address": "build.internal.example.com"},
            ]
        )
        objects = desired_tg_objects(state)
        ssh_objects = [o for o in objects if o.kind == "ssh"]
        assert ssh_objects == [
            DesiredResource(kind="ssh", name="web-1", address="10.0.10.5", upstream_port=22),
            DesiredResource(
                kind="ssh", name="build-box", address="build.internal.example.com",
                upstream_port=22,
            ),
        ]

    def test_ssh_address_is_portless(self) -> None:
        state = make_state(ssh_upstreams=[{"name": "web-1", "address": "10.0.10.5:22"}])
        [obj] = desired_tg_objects(state)
        assert obj.address == "10.0.10.5"
        assert ":" not in obj.address

    def test_ssh_upstream_port_comes_from_address(self) -> None:
        state = make_state(ssh_upstreams=[{"name": "web-1", "address": "10.0.10.5:2222"}])
        [obj] = desired_tg_objects(state)
        assert obj.address == "10.0.10.5"
        assert obj.upstream_port == 2222

    def test_ssh_upstream_port_defaults_to_22(self) -> None:
        state = make_state(ssh_upstreams=[{"name": "web-1", "address": "web.internal"}])
        [obj] = desired_tg_objects(state)
        assert obj.upstream_port == 22


class TestK8sClusters:
    def test_one_desired_resource_per_cluster_address_without_port(self) -> None:
        state = make_state(
            k8s_clusters=[
                {"name": "prod", "address": "prod.k8s.internal", "port": 6443,
                 "bearer_token_file": "/t", "ca_file": "/c"},
            ]
        )
        [obj] = desired_tg_objects(state)
        assert obj == DesiredResource(
            kind="kubernetes", name="prod", address="prod.k8s.internal", upstream_port=6443
        )

    def test_cluster_upstream_port_defaults_to_443(self) -> None:
        state = make_state(
            k8s_clusters=[
                {"name": "prod", "address": "prod.k8s.internal",
                 "bearer_token_file": "/t", "ca_file": "/c"},
            ]
        )
        [obj] = desired_tg_objects(state)
        assert obj.upstream_port == 443


class TestNormaliseRewrites:
    """``normalise_rewrites``: the comparison form of per-resource header rewrites."""

    def test_none_stays_none(self) -> None:
        assert normalise_rewrites(None) is None

    def test_empty_is_an_empty_tuple_not_none(self) -> None:
        result = normalise_rewrites(())
        assert result == ()
        assert result is not None

    def test_names_are_lowercased_values_kept_exact(self) -> None:
        result = normalise_rewrites((("X-Team", "Eng {{groups}}"),))
        assert result == (("x-team", "Eng {{groups}}"),)

    def test_sorted_case_insensitively_on_name(self) -> None:
        # ASCII order would put "B-Hdr" before "a-hdr"; the lowercased key must not.
        result = normalise_rewrites((("B-Hdr", "1"), ("a-hdr", "2"), ("C-Hdr", "3")))
        assert result == (("a-hdr", "2"), ("b-hdr", "1"), ("c-hdr", "3"))

    def test_input_order_does_not_change_the_result(self) -> None:
        pairs = (("X-B", "b"), ("x-a", "a"), ("X-C", "c"))
        assert normalise_rewrites(pairs) == normalise_rewrites(tuple(reversed(pairs)))

    def test_same_name_different_case_is_ordered_by_value_and_not_collapsed(self) -> None:
        result = normalise_rewrites((("X-A", "2"), ("x-a", "1")))
        assert result == (("x-a", "1"), ("x-a", "2"))

    def test_value_case_is_significant(self) -> None:
        assert normalise_rewrites((("x-a", "V"),)) != normalise_rewrites((("x-a", "v"),))

    def test_accepts_any_iterable_of_pairs(self) -> None:
        assert normalise_rewrites([("B", "1"), ("A", "2")]) == (("a", "2"), ("b", "1"))


class TestNormaliseExtras:
    def test_extras_without_rewrites_are_returned_unchanged(self) -> None:
        assert normalise_extras(EMPTY_EXTRAS) is EMPTY_EXTRAS
        extras = MappingProxyType({"alias": "a.corp"})
        assert normalise_extras(extras) is extras

    def test_rewrites_are_normalised_and_other_keys_kept(self) -> None:
        extras = MappingProxyType(
            {"alias": None, "request_header_rewrites": (("X-B", "1"), ("X-A", "2"))}
        )
        result = normalise_extras(extras)
        assert result["request_header_rewrites"] == (("x-a", "2"), ("x-b", "1"))
        assert result["alias"] is None

    def test_none_rewrites_stay_none_and_empty_stays_empty(self) -> None:
        assert normalise_extras(MappingProxyType({"request_header_rewrites": None}))[
            "request_header_rewrites"
        ] is None
        assert normalise_extras(MappingProxyType({"request_header_rewrites": ()}))[
            "request_header_rewrites"
        ] == ()

    def test_result_is_immutable_and_input_is_untouched(self) -> None:
        extras = MappingProxyType({"request_header_rewrites": (("X-B", "1"),)})
        result = normalise_extras(extras)
        assert result is not extras
        assert extras["request_header_rewrites"] == (("X-B", "1"),)
        with pytest.raises(TypeError):
            result["x"] = 1  # type: ignore[index]


_TEST_WEBAPP_KIND = ResourceKind(
    key="webapp",
    state_field="web_apps",
    api_segment="webapp",
    tg_type="WebAppResource",
    tg_field_prefix="webAppResource",
    tg_upstream_input="WebAppUpstreamInput",
    gateway_id_required=True,
    automation_allowed=True,
)


@pytest.fixture
def webapp_kind(monkeypatch: pytest.MonkeyPatch) -> None:
    """Splice a stand-in web-app descriptor into the module's KINDS."""
    kinds = (*(k for k in KINDS if k.state_field != "web_apps"), _TEST_WEBAPP_KIND)
    monkeypatch.setattr(desired_module, "KINDS", kinds)


@pytest.mark.usefixtures("webapp_kind")
class TestWebApps:
    def test_address_is_portless_and_port_comes_from_address(self) -> None:
        state = make_state(web_apps=[{"name": "g", "address": "Grafana.corp:3000"}])
        [obj] = desired_tg_objects(state)
        assert (obj.kind, obj.name, obj.address, obj.upstream_port) == (
            "webapp", "g", "grafana.corp", 3000,
        )

    def test_extras_carry_settings_and_alias(self) -> None:
        state = make_state(
            web_apps=[
                {
                    "name": "g",
                    "address": "grafana.corp",
                    "alias": "Graf.corp",
                    "upstream_tls": "verify_ca",
                    "downstream": {"tls": "none", "port": 8080},
                }
            ]
        )
        [obj] = desired_tg_objects(state)
        assert dict(obj.extras) == {
            "downstream_port": 8080,
            "downstream_tls_mode": "NONE",
            "upstream_tls_mode": "VERIFY_CA",
            "alias": "graf.corp",
            "request_header_rewrites": None,
        }

    def test_alias_absent_is_none(self) -> None:
        [obj] = desired_tg_objects(make_state(web_apps=[{"name": "g", "address": "g.corp"}]))
        assert obj.extras["alias"] is None

    def test_rewrites_are_sorted_and_lowercased(self) -> None:
        state = make_state(
            web_apps=[
                {
                    "name": "g",
                    "address": "g.corp",
                    "request_headers": {"X-Zed": "z", "x-Alpha": "a {{username}}", "B-Mid": "m"},
                }
            ]
        )
        [obj] = desired_tg_objects(state)
        assert obj.extras["request_header_rewrites"] == (
            ("b-mid", "m"),
            ("x-alpha", "a {{username}}"),
            ("x-zed", "z"),
        )

    def test_seed_order_does_not_change_the_extras(self) -> None:
        def rewrites(headers: dict[str, str]) -> Any:
            state = make_state(
                web_apps=[{"name": "g", "address": "g.corp", "request_headers": headers}]
            )
            [obj] = desired_tg_objects(state)
            return obj.extras["request_header_rewrites"]

        assert rewrites({"X-A": "1", "X-B": "2"}) == rewrites({"X-B": "2", "X-A": "1"})

    def test_unmanaged_rewrites_are_none_and_empty_rewrites_are_empty(self) -> None:
        unmanaged = make_state(web_apps=[{"name": "g", "address": "g.corp"}])
        empty = make_state(web_apps=[{"name": "g", "address": "g.corp", "request_headers": {}}])
        [u] = desired_tg_objects(unmanaged)
        [e] = desired_tg_objects(empty)
        assert u.extras["request_header_rewrites"] is None
        assert e.extras["request_header_rewrites"] == ()

    def test_ssh_extras_are_untouched(self) -> None:
        state = make_state(ssh_upstreams=[{"name": "s", "address": "s.corp"}])
        [obj] = desired_tg_objects(state)
        assert obj.extras is EMPTY_EXTRAS


class TestCombined:
    def test_ssh_and_k8s_together_preserve_declaration_order(self) -> None:
        state = make_state(
            ssh_upstreams=[{"name": "web-1", "address": "10.0.10.5:22"}],
            k8s_clusters=[
                {"name": "prod", "address": "prod.k8s.internal", "port": 6443,
                 "bearer_token_file": "/t", "ca_file": "/c"},
            ],
        )
        objects = desired_tg_objects(state)
        assert objects == [
            DesiredResource(kind="ssh", name="web-1", address="10.0.10.5", upstream_port=22),
            DesiredResource(
                kind="kubernetes", name="prod", address="prod.k8s.internal", upstream_port=6443
            ),
        ]

    def test_empty_state_yields_empty_list(self) -> None:
        assert desired_tg_objects(make_state()) == []
