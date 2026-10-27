"""Tests for the seed-only `ca.x509.on_demand_issuance` key."""

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from gwops.configmodel.loader import load_effective_state
from gwops.configmodel.schema import EffectiveState, SeedConfig, X509CASettings
from gwops.configmodel.store import OverlayStore
from gwops.logging import looks_secret
from gwops.renderer.sans import required_sans
from tests.on_demand_support import BASE_SEED, SSH_UPSTREAM_SEED, ca_section


def _state(**ca_x509: Any) -> EffectiveState:
    return EffectiveState.model_validate(
        {
            "twingate": {"network": "acme", "gateway_id": "g-1"},
            "ca": {"x509": ca_x509},
            "ssh_upstreams": [{"name": "web-1", "address": "10.0.0.5"}],
            "web_apps": [
                {"name": "grafana", "address": "grafana.corp.internal", "alias": "graf.corp.test"}
            ],
        }
    )


class TestDefaults:
    def test_the_key_is_a_bool_that_defaults_to_false(self) -> None:
        """The field exists on X509CASettings as a bool defaulting to False."""
        field = X509CASettings.model_fields["on_demand_issuance"]
        assert field.annotation is bool
        assert field.default is False

    def test_a_seed_without_the_key_has_it_off(self) -> None:
        """An absent key means off, for both a bare ca block and no ca block."""
        assert SeedConfig.model_validate(
            {"twingate": {"network": "acme", "gateway_id": "g-1"}}
        ).ca.x509.on_demand_issuance is False
        assert _state(generate=True).ca.x509.on_demand_issuance is False


class TestAccepted:
    def test_true_is_accepted_for_a_generated_ca(self) -> None:
        """The key can be set beside generate=true."""
        assert _state(generate=True, on_demand_issuance=True).ca.x509.on_demand_issuance is True

    def test_true_is_accepted_for_a_bring_your_own_ca(self) -> None:
        """The key can be set beside generate=false with a cert and key path."""
        state = _state(
            generate=False,
            cert_path="/mnt/ca/ca.crt",
            key_path="/mnt/ca/ca.key",
            on_demand_issuance=True,
        )
        assert state.ca.x509.on_demand_issuance is True

    def test_the_value_round_trips_through_model_dump(self) -> None:
        """model_dump reports the key so the state view can show it."""
        dumped = _state(on_demand_issuance=True).model_dump(mode="json")
        assert dumped["ca"]["x509"]["on_demand_issuance"] is True

    def test_the_key_name_is_not_treated_as_secret_by_output_redaction(self) -> None:
        """Operators must be able to see the setting in redacted state output."""
        assert looks_secret("on_demand_issuance") is False


class TestRejected:
    @pytest.mark.parametrize("value", ["sometimes", None, 2, []])
    def test_a_non_boolean_value_is_rejected(self, value: object) -> None:
        """Only booleans validate."""
        with pytest.raises(ValidationError):
            X509CASettings.model_validate({"on_demand_issuance": value})

    def test_a_misspelled_sibling_key_is_still_rejected(self) -> None:
        """Unknown keys under ca.x509 keep failing loud."""
        with pytest.raises(ValidationError):
            X509CASettings.model_validate({"on_demand_issuence": True})


class TestLoaded:
    def test_the_seed_file_sets_it_and_provenance_says_seed(self, tmp_path: Path) -> None:
        """A seed with the key true loads true, attributed to the seed layer."""
        seed = tmp_path / "seed.yaml"
        seed.write_text(BASE_SEED + ca_section(on_demand=True), encoding="utf-8")

        state, provenance = load_effective_state(seed, OverlayStore(tmp_path / "overlays"))

        assert state.ca.x509.on_demand_issuance is True
        assert provenance["ca.x509.on_demand_issuance"] == "seed"

    def test_an_unrelated_overlay_does_not_switch_it_off(self, tmp_path: Path) -> None:
        """Seed-true stays true after overlays touching other keys merge in."""
        seed = tmp_path / "seed.yaml"
        seed.write_text(SSH_UPSTREAM_SEED + ca_section(on_demand=True), encoding="utf-8")
        store = OverlayStore(tmp_path / "overlays")
        store.add({"ssh_upstreams": [{"name": "web-2", "address": "10.0.0.6"}]}, comment="x")

        state, _provenance = load_effective_state(seed, store)

        assert state.ca.x509.on_demand_issuance is True


class TestRequiredSans:
    def test_the_required_san_set_is_the_same_with_the_mode_on(self) -> None:
        """On-demand issuance does not shrink or grow the static leaf's SANs."""
        off = required_sans(_state(on_demand_issuance=False))
        on = required_sans(_state(on_demand_issuance=True))
        assert on == off == {"10.0.0.5", "grafana.corp.internal", "graf.corp.test"}
