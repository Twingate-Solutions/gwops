"""Tests for gwops.renderer.sans.required_sans: table-driven SAN computation.

Rationale (why the SAN set must cover every upstream/cluster address verbatim,
port stripped): the Twingate Client verifies the *dialed resource address* against
the gateway leaf's SAN, not the gateway's own address.
"""

import ipaddress
from typing import Any

import pytest

from gwops.certs.validate import classify_san
from gwops.configmodel.schema import EffectiveState
from gwops.kinds import KINDS, ResourceKind
from gwops.renderer import sans as sans_module
from gwops.renderer.sans import required_sans


def make_state(**overrides: Any) -> EffectiveState:
    base: dict[str, Any] = {"twingate": {"network": "acme", "gateway_id": "g-1"}}
    base.update(overrides)
    return EffectiveState.model_validate(base)


class TestTableDriven:
    @pytest.mark.parametrize(
        ("ssh_upstreams", "k8s_clusters", "expected"),
        [
            pytest.param(
                [{"name": "web-1", "address": "10.0.10.5:22"}],
                [],
                {"10.0.10.5"},
                id="ipv4-ssh-port-stripped",
            ),
            pytest.param(
                [{"name": "build", "address": "build.internal.example.com"}],
                [],
                {"build.internal.example.com"},
                id="dns-ssh-no-port",
            ),
            pytest.param(
                [],
                [{"name": "prod", "address": "prod.k8s.internal", "port": 6443,
                  "bearer_token_file": "/t", "ca_file": "/c"}],
                {"prod.k8s.internal"},
                id="dns-k8s-cluster",
            ),
            pytest.param(
                [],
                [{"name": "prod", "address": "10.0.0.16", "port": 6443,
                  "bearer_token_file": "/t", "ca_file": "/c"}],
                {"10.0.0.16"},
                id="ipv4-k8s-cluster",
            ),
            pytest.param(
                [
                    {"name": "web-1", "address": "10.0.10.5:22"},
                    {"name": "web-2", "address": "10.0.10.5:2222"},
                ],
                [],
                {"10.0.10.5"},
                id="dedup-same-host-different-ports",
            ),
            pytest.param([], [], set(), id="empty-state-yields-empty-set"),
        ],
    )
    def test_required_sans(
        self,
        ssh_upstreams: list[dict[str, Any]],
        k8s_clusters: list[dict[str, Any]],
        expected: set[str],
    ) -> None:
        state = make_state(ssh_upstreams=ssh_upstreams, k8s_clusters=k8s_clusters)
        assert required_sans(state) == expected


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
    monkeypatch.setattr(sans_module, "KINDS", kinds)


@pytest.mark.usefixtures("webapp_kind")
class TestWebApps:
    def test_address_and_alias_both_covered_port_stripped(self) -> None:
        state = make_state(
            web_apps=[{"name": "g", "address": "grafana.corp:3000", "alias": "graf.corp"}]
        )
        assert required_sans(state) == {"grafana.corp", "graf.corp"}

    def test_alias_absent_adds_only_the_address(self) -> None:
        state = make_state(web_apps=[{"name": "g", "address": "grafana.corp"}])
        assert required_sans(state) == {"grafana.corp"}

    def test_alias_is_lowercased(self) -> None:
        state = make_state(web_apps=[{"name": "g", "address": "g.corp", "alias": "Graf.Corp"}])
        assert required_sans(state) == {"g.corp", "graf.corp"}

    def test_ip_address_and_ip_alias_classify_as_ip_sans(self) -> None:
        state = make_state(
            web_apps=[{"name": "g", "address": "10.1.2.3:8080", "alias": "10.1.2.4"}]
        )
        sans = required_sans(state)
        assert sans == {"10.1.2.3", "10.1.2.4"}
        assert {classify_san(s) for s in sans} == {
            ipaddress.IPv4Address("10.1.2.3"),
            ipaddress.IPv4Address("10.1.2.4"),
        }

    def test_dns_alias_classifies_as_dns_san(self) -> None:
        state = make_state(web_apps=[{"name": "g", "address": "10.1.2.3", "alias": "graf.corp"}])
        assert classify_san("graf.corp") == "graf.corp"
        assert "graf.corp" in required_sans(state)

    def test_dedupe_when_two_entries_share_a_name(self) -> None:
        state = make_state(
            ssh_upstreams=[{"name": "s", "address": "shared.corp:22"}],
            web_apps=[
                {"name": "a", "address": "shared.corp:8443", "alias": "common.corp"},
                {"name": "b", "address": "b.corp", "alias": "common.corp"},
                {"name": "c", "address": "c.corp", "alias": "SHARED.corp"},
            ],
        )
        assert required_sans(state) == {"shared.corp", "common.corp", "b.corp", "c.corp"}

    def test_web_apps_combine_with_other_kinds(self) -> None:
        state = make_state(
            ssh_upstreams=[{"name": "web-1", "address": "10.0.10.5:22"}],
            web_apps=[{"name": "g", "address": "g.corp", "alias": "graf.corp"}],
        )
        assert required_sans(state) == {"10.0.10.5", "g.corp", "graf.corp"}


class TestCombined:
    def test_sans_from_both_ssh_and_k8s_combine(self) -> None:
        state = make_state(
            ssh_upstreams=[
                {"name": "web-1", "address": "10.0.10.5:22"},
                {"name": "build", "address": "build.internal.example.com"},
            ],
            k8s_clusters=[
                {"name": "prod", "address": "prod.k8s.internal", "port": 6443,
                 "bearer_token_file": "/t", "ca_file": "/c"},
                {"name": "staging", "address": "10.0.0.16", "port": 443,
                 "bearer_token_file": "/t2", "ca_file": "/c2"},
            ],
        )
        assert required_sans(state) == {
            "10.0.10.5",
            "build.internal.example.com",
            "prod.k8s.internal",
            "10.0.0.16",
        }
