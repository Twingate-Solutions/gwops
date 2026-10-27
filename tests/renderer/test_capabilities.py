"""Tests for gwops.renderer.capabilities: the reported gateway version."""

import dataclasses

import pytest

from gwops.renderer.capabilities import Capabilities, gateway_capabilities
from gwops.settings import GwopsSettings


class TestCapabilitiesDefaults:
    def test_no_arg_construction_has_empty_version(self) -> None:
        assert Capabilities().gateway_version == ""

    def test_fields(self) -> None:
        assert [f.name for f in dataclasses.fields(Capabilities)] == [
            "gateway_version",
            "web_app_template_keys",
        ]

    def test_web_app_template_keys_are_the_pinned_preview_set(self) -> None:
        # From upstream template.go; there is no "email" key.
        assert Capabilities().web_app_template_keys == frozenset(
            {
                "jwt",
                "username",
                "groups",
                "clientGeoLatLong",
                "clientGeoCity",
                "clientGeoRegion",
                "clientGeoCountry",
            }
        )

    def test_template_keys_are_immutable_and_survive_a_version_only_constructor(self) -> None:
        caps = Capabilities(gateway_version="2.0.0")
        assert isinstance(caps.web_app_template_keys, frozenset)
        assert "jwt" in caps.web_app_template_keys

    def test_gateway_capabilities_carries_the_keys(self) -> None:
        assert gateway_capabilities("2.0.0").web_app_template_keys == (
            Capabilities().web_app_template_keys
        )

    def test_is_frozen(self) -> None:
        caps = Capabilities()
        with pytest.raises(AttributeError):
            caps.gateway_version = "2.0.0"  # type: ignore[misc]


class TestGwopsSettingsGatewayVersion:
    def test_default_is_empty(self) -> None:
        assert GwopsSettings().gateway_version == ""

    def test_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GWOPS_GATEWAY_VERSION", "2.0.0-dev")
        assert GwopsSettings().gateway_version == "2.0.0-dev"


class TestGatewayCapabilities:
    def test_no_arg_reads_settings_and_defaults_to_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GWOPS_GATEWAY_VERSION", raising=False)
        assert gateway_capabilities().gateway_version == ""

    def test_no_arg_picks_up_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GWOPS_GATEWAY_VERSION", "2.0.0-dev-5ed8e12")
        assert gateway_capabilities().gateway_version == "2.0.0-dev-5ed8e12"

    def test_explicit_version_overrides_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GWOPS_GATEWAY_VERSION", "2.0.0-dev")
        assert gateway_capabilities("2.0.0").gateway_version == "2.0.0"

    @pytest.mark.parametrize("version", ["1.1.0", "dev", "latest", "not-a-version"])
    def test_version_is_reported_never_enforced(self, version: str) -> None:
        # No startup guard: whatever the env or caller supplies is carried verbatim.
        assert gateway_capabilities(version).gateway_version == version
