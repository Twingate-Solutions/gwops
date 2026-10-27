"""Tests for gwops.configmodel.merge.merge_layers."""

from datetime import UTC, datetime
from typing import Any

import pytest

from gwops.configmodel.merge import merge_layers
from gwops.configmodel.store import Overlay


def make_overlay(overlay_id: str, patch: dict[str, Any]) -> Overlay:
    return Overlay(
        id=overlay_id, created_at=datetime.now(UTC), comment="", patch=patch
    )


def base_seed() -> dict[str, Any]:
    return {
        "twingate": {"network": "acme", "host": "twingate.com", "gateway_id": "g-1"},
        "ssh_upstreams": [
            {"name": "web-1", "address": "10.0.0.5:22"},
            {"name": "web-2", "address": "10.0.0.6:22"},
        ],
        "k8s_clusters": [
            {"name": "prod", "address": "prod.k8s.internal", "port": 443},
        ],
        "admin_api": {"bind": "127.0.0.1", "port": 8081},
        "tags": ["a", "b"],
    }


class TestNoOverlays:
    def test_returns_seed_unchanged_with_all_seed_provenance(self) -> None:
        merged, prov = merge_layers(base_seed(), [])
        assert merged == base_seed()
        assert prov["twingate.network"] == "seed"
        assert prov["ssh_upstreams.web-1.address"] == "seed"
        assert prov["k8s_clusters.prod.port"] == "seed"
        assert prov["tags"] == "seed"
        assert set(prov.values()) == {"seed"}

    def test_seed_dict_is_not_mutated(self) -> None:
        seed = base_seed()
        merged, _ = merge_layers(seed, [make_overlay("0001-x", {"admin_api": {"port": 1}})])
        assert seed["admin_api"]["port"] == 8081
        assert merged["admin_api"]["port"] == 1


class TestMapRecursion:
    def test_nested_scalar_override_keeps_siblings(self) -> None:
        ov = make_overlay("0001-port", {"admin_api": {"port": 9001}})
        merged, prov = merge_layers(base_seed(), [ov])
        assert merged["admin_api"] == {"bind": "127.0.0.1", "port": 9001}
        assert prov["admin_api.port"] == "0001-port"
        assert prov["admin_api.bind"] == "seed"


class TestNamedListMerge:
    def test_merge_existing_item_by_name(self) -> None:
        ov = make_overlay(
            "0001-k8s-port", {"k8s_clusters": [{"name": "prod", "port": 6443}]}
        )
        merged, prov = merge_layers(base_seed(), [ov])
        assert merged["k8s_clusters"] == [
            {"name": "prod", "address": "prod.k8s.internal", "port": 6443}
        ]
        assert prov["k8s_clusters.prod.port"] == "0001-k8s-port"
        assert prov["k8s_clusters.prod.address"] == "seed"

    def test_add_new_named_item(self) -> None:
        ov = make_overlay(
            "0001-add", {"ssh_upstreams": [{"name": "web-3", "address": "10.0.0.7:22"}]}
        )
        merged, prov = merge_layers(base_seed(), [ov])
        names = [u["name"] for u in merged["ssh_upstreams"]]
        assert names == ["web-1", "web-2", "web-3"]
        assert prov["ssh_upstreams.web-3.address"] == "0001-add"
        assert prov["ssh_upstreams.web-1.address"] == "seed"

    def test_delete_named_item(self) -> None:
        ov = make_overlay(
            "0001-rm", {"ssh_upstreams": [{"name": "web-1", "_delete": True}]}
        )
        merged, prov = merge_layers(base_seed(), [ov])
        assert [u["name"] for u in merged["ssh_upstreams"]] == ["web-2"]
        assert not any(k.startswith("ssh_upstreams.web-1") for k in prov)

    def test_delete_then_readd_named_item(self) -> None:
        overlays = [
            make_overlay("0001-rm", {"ssh_upstreams": [{"name": "web-1", "_delete": True}]}),
            make_overlay(
                "0002-back", {"ssh_upstreams": [{"name": "web-1", "address": "10.9.9.9:22"}]}
            ),
        ]
        merged, prov = merge_layers(base_seed(), overlays)
        assert [u["name"] for u in merged["ssh_upstreams"]] == ["web-2", "web-1"]
        assert prov["ssh_upstreams.web-1.address"] == "0002-back"

    def test_delete_against_empty_seed_list_drops_the_marker(self) -> None:
        # A `_delete` of a name that the seed no longer has must be a no-op, NOT a copy of
        # the invalid `{"name","_delete"}` marker into the merged config (which would fail
        # schema validation and boot-loop the container). Covers empty [] and absent key.
        seed = base_seed()
        seed["ssh_upstreams"] = []
        ov = make_overlay("0001-rm", {"ssh_upstreams": [{"name": "gone", "_delete": True}]})
        merged, _ = merge_layers(seed, [ov])
        assert merged["ssh_upstreams"] == []

        seed_no_key = base_seed()
        del seed_no_key["k8s_clusters"]
        ov2 = make_overlay("0001-rm", {"k8s_clusters": [{"name": "gone", "_delete": True}]})
        merged2, _ = merge_layers(seed_no_key, [ov2])
        assert merged2["k8s_clusters"] == []

    def test_add_against_empty_seed_list_merges_by_name(self) -> None:
        seed = base_seed()
        seed["ssh_upstreams"] = []
        ov = make_overlay(
            "0001-add",
            {"ssh_upstreams": [{"name": "new", "address": "10.0.0.9:22", "_delete": False}]},
        )
        merged, _ = merge_layers(seed, [ov])
        assert merged["ssh_upstreams"] == [{"name": "new", "address": "10.0.0.9:22"}]


class TestScalarAndPlainLists:
    def test_scalar_last_overlay_wins(self) -> None:
        overlays = [
            make_overlay("0001-a", {"admin_api": {"port": 1111}}),
            make_overlay("0002-b", {"admin_api": {"port": 2222}}),
        ]
        merged, prov = merge_layers(base_seed(), overlays)
        assert merged["admin_api"]["port"] == 2222
        assert prov["admin_api.port"] == "0002-b"

    def test_nested_named_list_replaces_wholesale(self) -> None:
        # Pinned access refs are {id, name} dicts: merged by name they would union across
        # overlays, so a later declaration could never drop a group.
        def put(overlay_id: str, gid: str, name: str) -> Overlay:
            entry = {"name": "web-1", "access": {"groups": [{"id": gid, "name": name}]}}
            return make_overlay(overlay_id, {"ssh_upstreams": [entry]})

        overlays = [put("0001-a", "g-a", "A"), put("0002-b", "g-b", "B")]
        merged, prov = merge_layers(base_seed(), overlays)

        [web1] = [u for u in merged["ssh_upstreams"] if u["name"] == "web-1"]
        assert web1["access"]["groups"] == [{"id": "g-b", "name": "B"}]
        assert web1["address"] == "10.0.0.5:22"  # sibling fields still merge by name
        assert prov["ssh_upstreams.web-1.access.groups"] == "0002-b"

    def test_plain_list_replaces_wholesale(self) -> None:
        ov = make_overlay("0001-tags", {"tags": ["z"]})
        merged, prov = merge_layers(base_seed(), [ov])
        assert merged["tags"] == ["z"]
        assert prov["tags"] == "0001-tags"

    def test_dict_replacing_scalar_records_new_leaves(self) -> None:
        ov = make_overlay("0001-new", {"recording": {"enabled": True, "receiver_url": "u"}})
        merged, prov = merge_layers(base_seed(), [ov])
        assert merged["recording"] == {"enabled": True, "receiver_url": "u"}
        assert prov["recording.enabled"] == "0001-new"
        assert prov["recording.receiver_url"] == "0001-new"


class TestRequestHeadersReplaceWholesale:
    """`request_headers` inside a named-list item is replaced, never deep-merged."""

    @staticmethod
    def _seed() -> dict[str, Any]:
        seed = base_seed()
        seed["web_apps"] = [
            {
                "name": "grafana",
                "address": "grafana.apps.internal:3000",
                "request_headers": {"X-A": "{{username}}", "X-B": "{{groups}}"},
            }
        ]
        return seed

    @staticmethod
    def _headers_overlay(overlay_id: str, headers: dict[str, str]) -> Overlay:
        patch = {"web_apps": [{"name": "grafana", "request_headers": headers}]}
        return make_overlay(overlay_id, patch)

    def test_overlay_removes_keys_absent_from_the_patch(self) -> None:
        ov = make_overlay(
            "0001-hdr", {"web_apps": [{"name": "grafana", "request_headers": {"X-A": "static"}}]}
        )
        merged, prov = merge_layers(self._seed(), [ov])
        [app] = merged["web_apps"]
        assert app["request_headers"] == {"X-A": "static"}
        assert app["address"] == "grafana.apps.internal:3000"  # siblings still merge
        assert prov["web_apps.grafana.request_headers.X-A"] == "0001-hdr"
        assert "web_apps.grafana.request_headers.X-B" not in prov
        assert prov["web_apps.grafana.address"] == "seed"

    def test_empty_map_clears_all_headers_but_stays_managed(self) -> None:
        ov = make_overlay("0001-clr", {"web_apps": [{"name": "grafana", "request_headers": {}}]})
        merged, prov = merge_layers(self._seed(), [ov])
        assert merged["web_apps"][0]["request_headers"] == {}
        assert prov["web_apps.grafana.request_headers"] == "0001-clr"
        assert not any(k.startswith("web_apps.grafana.request_headers.") for k in prov)

    def test_null_flips_the_entry_to_unmanaged(self) -> None:
        ov = make_overlay("0001-nul", {"web_apps": [{"name": "grafana", "request_headers": None}]})
        merged, _ = merge_layers(self._seed(), [ov])
        assert merged["web_apps"][0]["request_headers"] is None

    def test_later_overlay_replaces_earlier_overlay(self) -> None:
        overlays = [
            self._headers_overlay("0001-a", {"X-C": "1"}),
            self._headers_overlay("0002-b", {"X-D": "2"}),
        ]
        merged, prov = merge_layers(self._seed(), overlays)
        assert merged["web_apps"][0]["request_headers"] == {"X-D": "2"}
        assert prov["web_apps.grafana.request_headers.X-D"] == "0002-b"
        assert "web_apps.grafana.request_headers.X-C" not in prov

    def test_omitting_request_headers_leaves_them_untouched(self) -> None:
        ov = make_overlay("0001-alias", {"web_apps": [{"name": "grafana", "alias": "g.corp"}]})
        merged, prov = merge_layers(self._seed(), [ov])
        assert merged["web_apps"][0]["request_headers"] == {
            "X-A": "{{username}}",
            "X-B": "{{groups}}",
        }
        assert prov["web_apps.grafana.request_headers.X-A"] == "seed"

    def test_other_nested_maps_still_deep_merge(self) -> None:
        seed = self._seed()
        seed["web_apps"][0]["downstream"] = {"tls": "tls13", "port": 8443}
        patch = {"web_apps": [{"name": "grafana", "downstream": {"port": 9000}}]}
        ov = make_overlay("0001-port", patch)
        merged, _ = merge_layers(seed, [ov])
        assert merged["web_apps"][0]["downstream"] == {"tls": "tls13", "port": 9000}

    def test_gateway_wide_request_headers_map_still_deep_merges(self) -> None:
        # Replacement applies only inside named-list items; web_app_proxy keeps the generic rule.
        seed = base_seed()
        seed["web_app_proxy"] = {"request_headers": {"X-A": "1", "X-B": "2"}}
        ov = make_overlay("0001-x", {"web_app_proxy": {"request_headers": {"X-C": "3"}}})
        merged, _ = merge_layers(seed, [ov])
        assert merged["web_app_proxy"]["request_headers"] == {"X-A": "1", "X-B": "2", "X-C": "3"}

    def test_new_entry_added_by_overlay_keeps_its_headers(self) -> None:
        wiki = {"name": "wiki", "address": "wiki.internal", "request_headers": {"X-W": "1"}}
        ov = make_overlay("0001-add", {"web_apps": [wiki]})
        merged, prov = merge_layers(self._seed(), [ov])
        assert merged["web_apps"][1]["request_headers"] == {"X-W": "1"}
        assert prov["web_apps.wiki.request_headers.X-W"] == "0001-add"


class TestProvenanceHygiene:
    def test_replaced_subtree_drops_stale_paths(self) -> None:
        ov = make_overlay("0001-x", {"admin_api": 5})  # scalar replaces whole map
        merged, prov = merge_layers(base_seed(), [ov])
        assert merged["admin_api"] == 5
        assert prov["admin_api"] == "0001-x"
        assert "admin_api.port" not in prov
        assert "admin_api.bind" not in prov


class TestMergeDepthGuard:
    def test_too_deep_patch_on_disk_raises_valueerror_not_recursionerror(self) -> None:
        # An overlay already on disk (bypassing OverlayStore.add's cap) that is
        # nested far beyond the merge depth guard must surface a clear ValueError,
        # not a RecursionError that load_effective_state would fail to catch.
        patch: dict[str, Any] = {}
        node = patch
        for _ in range(500):
            child: dict[str, Any] = {}
            node["k"] = child
            node = child
        node["k"] = 1
        ov = make_overlay("0001-deep", patch)
        with pytest.raises(ValueError, match="[Dd]epth"):
            merge_layers(base_seed(), [ov])
