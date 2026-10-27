"""Tests for the on-demand issuance render: `tls.automation.issuer.local` beside the static leaf."""

from pathlib import Path
from typing import Any

import pytest
import yaml

from gwops.configmodel.schema import EffectiveState
from gwops.renderer.capabilities import Capabilities
from gwops.renderer.render import K8sCredentialFiles, RuntimePaths, render_gateway_config
from gwops.settings import GwopsSettings

FIXTURES = Path(__file__).parent.parent / "fixtures" / "rendered"

_CA_CERT = "/data/pki/x509-ca.crt"
_CA_KEY = "/data/pki/x509-ca.key"
_LEAF = {
    "certificateFile": "/data/pki/leaf/fullchain.pem",
    "privateKeyFile": "/data/pki/leaf/privkey.pem",
}
_SOLO = K8sCredentialFiles(
    token=Path("/data/k8s-creds/solo-token-0123456789ab"),
    ca=Path("/data/k8s-creds/solo-ca-fedcba987654.crt"),
)
_FORBIDDEN_AUTOMATION_KEYS = {"vault", "gcpPrivateCA", "commonName", "certificate", "ttl", "key"}


def _state(*, on_demand: bool | None, **overrides: Any) -> EffectiveState:
    base: dict[str, Any] = {"twingate": {"network": "acme", "gateway_id": "g-1"}}
    if on_demand is not None:
        base["ca"] = {"x509": {"on_demand_issuance": on_demand}}
    base.update(overrides)
    return EffectiveState.model_validate(base)


def _paths() -> RuntimePaths:
    return RuntimePaths.from_settings(GwopsSettings()).with_k8s_credentials({"solo": _SOLO})


def _render(state: EffectiveState) -> dict[str, Any]:
    text = render_gateway_config(state, Capabilities(gateway_version="2.0.0"), _paths()).config_yaml
    doc: dict[str, Any] = yaml.safe_load(text)
    return doc


def _all_keys(node: Any) -> set[str]:
    if isinstance(node, dict):
        return set(node) | {k for v in node.values() for k in _all_keys(v)}
    if isinstance(node, list):
        return {k for v in node for k in _all_keys(v)}
    return set()


_K8S = [
    {
        "name": "solo",
        "address": "solo.k8s.internal",
        "port": 443,
        "bearer_token_file": "/config/k8s-creds/solo.token",
        "ca_file": "/config/k8s-creds/solo-ca.crt",
    }
]
_WEB_APP = [{"name": "grafana", "address": "grafana.corp.internal"}]

_SHAPES = [
    pytest.param({}, id="no-upstreams"),
    pytest.param({"k8s_clusters": _K8S}, id="k8s"),
    pytest.param(
        {
            "web_apps": _WEB_APP,
            "web_app_proxy": {"request_headers": {"X-Geo": "{{clientGeoCity}}"}},
        },
        id="web-app",
    ),
]


class TestDefaultRendersNoAutomation:
    @pytest.mark.parametrize("on_demand", [None, False])
    def test_tls_has_only_the_static_certificates_block(self, on_demand: bool | None) -> None:
        """Mode off (absent or explicit false) renders no tls.automation key."""
        doc = _render(_state(on_demand=on_demand))
        assert set(doc["tls"]) == {"certificates"}
        assert "automation" not in _all_keys(doc)

    @pytest.mark.parametrize("extra", _SHAPES)
    def test_explicit_false_renders_the_same_text_as_the_default(
        self, extra: dict[str, Any]
    ) -> None:
        """Setting the key false changes nothing, so the existing goldens stay valid."""
        caps = Capabilities(gateway_version="2.0.0")
        default = render_gateway_config(_state(on_demand=None, **extra), caps, _paths())
        explicit = render_gateway_config(_state(on_demand=False, **extra), caps, _paths())
        assert explicit.config_yaml == default.config_yaml


class TestOptInRendersTheLocalIssuer:
    def test_tls_automation_is_exactly_the_local_issuer_with_the_ca_paths(self) -> None:
        """Opt-in renders issuer.local.{certificateFile, privateKeyFile} at the gwops CA files."""
        doc = _render(_state(on_demand=True))
        assert doc["tls"]["automation"] == {
            "issuer": {"local": {"certificateFile": _CA_CERT, "privateKeyFile": _CA_KEY}}
        }

    def test_the_static_leaf_stays_the_only_static_entry(self) -> None:
        """tls.certificates.files is unchanged: one entry, the gwops leaf."""
        doc = _render(_state(on_demand=True))
        assert doc["tls"]["certificates"] == {"files": [_LEAF]}
        assert set(doc["tls"]) == {"certificates", "automation"}

    def test_the_issuer_points_at_the_ca_and_never_at_the_leaf(self) -> None:
        """The issuer's files are the CA pair, not the leaf pair."""
        local = _render(_state(on_demand=True))["tls"]["automation"]["issuer"]["local"]
        assert local["certificateFile"] != _LEAF["certificateFile"]
        assert local["privateKeyFile"] != _LEAF["privateKeyFile"]

    def test_no_other_automation_keys_are_rendered(self) -> None:
        """No certificate block, no other issuer, nothing but issuer.local."""
        doc = _render(_state(on_demand=True))
        automation = doc["tls"]["automation"]
        assert set(automation) == {"issuer"}
        assert set(automation["issuer"]) == {"local"}
        assert set(automation["issuer"]["local"]) == {"certificateFile", "privateKeyFile"}
        assert not _all_keys(automation) & _FORBIDDEN_AUTOMATION_KEYS

    def test_the_key_names_are_camel_case(self) -> None:
        """The gateway reads camelCase; snake_case keys would be rejected at validate."""
        local = _render(_state(on_demand=True))["tls"]["automation"]["issuer"]["local"]
        assert not any("_" in key for key in local)

    @pytest.mark.parametrize("extra", _SHAPES)
    def test_only_tls_automation_differs_from_the_mode_off_render(
        self, extra: dict[str, Any]
    ) -> None:
        """Every other section renders identically with the mode on."""
        on = _render(_state(on_demand=True, **extra))
        off = _render(_state(on_demand=False, **extra))
        del on["tls"]["automation"]
        assert on == off

    def test_a_generated_ca_state_with_generate_true_renders_the_pki_dir_paths(self) -> None:
        """An explicit generate=true renders the same canonical pki_dir CA files."""
        state = EffectiveState.model_validate(
            {
                "twingate": {"network": "acme", "gateway_id": "g-1"},
                "ca": {"x509": {"generate": True, "on_demand_issuance": True}},
            }
        )
        local = _render(state)["tls"]["automation"]["issuer"]["local"]
        assert local == {"certificateFile": _CA_CERT, "privateKeyFile": _CA_KEY}

    def test_the_render_is_byte_stable(self) -> None:
        """Rendering twice gives identical text, so an unchanged pass never restarts."""
        state = _state(on_demand=True, k8s_clusters=_K8S)
        caps = Capabilities(gateway_version="2.0.0")
        first = render_gateway_config(state, caps, _paths()).config_yaml
        assert render_gateway_config(state, caps, _paths()).config_yaml == first

    def test_the_rendered_text_carries_no_pem_or_key_material(self) -> None:
        """Only file paths reach the config, never certificate or key content."""
        text = render_gateway_config(
            _state(on_demand=True), Capabilities(gateway_version="2.0.0"), _paths()
        ).config_yaml
        assert "BEGIN" not in text


class TestGolden:
    def test_on_demand_render_matches_golden_file(self) -> None:
        """The opt-in render equals tests/fixtures/rendered/tls-on-demand.yaml."""
        state = EffectiveState.model_validate(
            {
                "twingate": {"network": "acme2", "gateway_id": "g-2"},
                "ca": {"x509": {"on_demand_issuance": True}},
            }
        )
        paths = RuntimePaths.from_settings(GwopsSettings())
        rendered = render_gateway_config(state, Capabilities(gateway_version="2.0.0"), paths)
        golden = yaml.safe_load((FIXTURES / "tls-on-demand.yaml").read_text(encoding="utf-8"))
        assert yaml.safe_load(rendered.config_yaml) == golden
