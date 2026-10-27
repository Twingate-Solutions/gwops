"""`tls_mode` and `tls_warning`: the pure helpers the /status `tls` block reads."""

from typing import Any

import pytest

from gwops.certs.on_demand import (
    ON_DEMAND_BROWSER_TRUST_WARNING,
    ON_DEMAND_BYO_TRUST_WARNING,
    ON_DEMAND_WARNING,
    tls_mode,
    tls_warning,
)
from gwops.configmodel.schema import EffectiveState


def _state(on_demand: bool) -> EffectiveState:
    ca: dict[str, Any] = {"x509": {"on_demand_issuance": on_demand}}
    return EffectiveState.model_validate(
        {"twingate": {"network": "acme", "gateway_id": "g-1"}, "ca": ca}
    )


class TestTlsMode:
    @pytest.mark.parametrize(("on_demand", "mode"), [(False, "static"), (True, "static+on_demand")])
    def test_mode_follows_the_seed_key(self, on_demand: bool, mode: str) -> None:
        """The mode is static unless the seed opted in."""
        assert tls_mode(_state(on_demand)) == mode


class TestTlsWarning:
    @pytest.mark.parametrize("generated", [True, False])
    @pytest.mark.parametrize("tls13", [True, False])
    def test_no_warning_with_the_mode_off(self, generated: bool, tls13: bool) -> None:
        """Mode off never warns, whatever the CA source or web-app TLS."""
        assert tls_warning(_state(False), generated, tls13) is None

    def test_a_generated_ca_without_tls13_gives_the_base_text(self) -> None:
        """Mode on, gwops-generated CA, no tls13 web app: the base text only."""
        assert tls_warning(_state(True), True, False) == ON_DEMAND_WARNING

    def test_base_warning_states_the_exposure(self) -> None:
        """A client gets a certificate, not a key; the CA key is used before authentication."""
        assert "any SNI" in ON_DEMAND_WARNING and ":8443" in ON_DEMAND_WARNING
        assert "receives a certificate for that name" in ON_DEMAND_WARNING
        assert "loads the gwops X.509 CA private key" in ON_DEMAND_WARNING
        assert "before the access token is authenticated" in ON_DEMAND_WARNING
        assert "any client that can reach :8443" in ON_DEMAND_WARNING

    def test_escalates_for_a_generated_ca_with_a_tls13_web_app(self) -> None:
        """A gwops-generated CA plus downstream tls13 adds the browser-trust text."""
        warning = tls_warning(_state(True), True, True)
        assert warning == ON_DEMAND_WARNING + ON_DEMAND_BROWSER_TRUST_WARNING
        assert "browser trust stores" in warning

    @pytest.mark.parametrize("tls13", [True, False])
    def test_escalates_for_a_byo_ca_whatever_the_web_app_tls(self, tls13: bool) -> None:
        """A BYO CA is typically already device-trusted, so it always escalates."""
        warning = tls_warning(_state(True), False, tls13)
        assert warning == ON_DEMAND_WARNING + ON_DEMAND_BYO_TRUST_WARNING
        assert "bring-your-own" in warning and "already trusted" in warning

    def test_the_text_constants_are_exported(self) -> None:
        """core.py imports the active-warning constant by name."""
        import gwops.certs.on_demand as module

        assert {
            "ON_DEMAND_WARNING", "ON_DEMAND_BROWSER_TRUST_WARNING", "ON_DEMAND_BYO_TRUST_WARNING"
        } <= set(module.__all__)
