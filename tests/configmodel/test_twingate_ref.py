"""Tests for gwops.configmodel.schema.TwingateRef mutually-exclusive modes.

Mode A pins an existing gateway by ``gateway_id``. Mode B names a remote network
(by console name or GraphQL id) plus a connector-reachable ``gateway_address`` so
the control plane can auto-create the gateway object.
"""

import pytest
from pydantic import ValidationError

from gwops.configmodel.schema import TwingateRef


class TestTwingateRefModeA:
    def test_valid_mode_a_pins_gateway_id(self) -> None:
        ref = TwingateRef.model_validate(
            {"network": "acme", "gateway_id": "R2Vad2F5OjEyMw=="}
        )
        assert ref.gateway_id == "R2Vad2F5OjEyMw=="
        assert ref.remote_network is None
        assert ref.remote_network_id is None
        assert ref.gateway_address is None


class TestTwingateRefModeB:
    def test_valid_mode_b_by_name(self) -> None:
        ref = TwingateRef.model_validate(
            {
                "network": "acme",
                "remote_network": "prod-dc",
                "gateway_address": "10.0.0.1:8443",
            }
        )
        assert ref.gateway_id is None
        assert ref.remote_network == "prod-dc"
        assert ref.remote_network_id is None
        assert ref.gateway_address == "10.0.0.1:8443"

    def test_valid_mode_b_by_id(self) -> None:
        ref = TwingateRef.model_validate(
            {
                "network": "acme",
                "remote_network_id": "Um10Ok5ldDo0NTY=",
                "gateway_address": "10.0.0.1:8443",
            }
        )
        assert ref.gateway_id is None
        assert ref.remote_network is None
        assert ref.remote_network_id == "Um10Ok5ldDo0NTY="
        assert ref.gateway_address == "10.0.0.1:8443"

    def test_gateway_address_is_lowercased(self) -> None:
        ref = TwingateRef.model_validate(
            {
                "network": "acme",
                "remote_network": "prod-dc",
                "gateway_address": "GW.Internal:8443",
            }
        )
        assert ref.gateway_address == "gw.internal:8443"


class TestTwingateRefErrors:
    def test_neither_mode_configured(self) -> None:
        with pytest.raises(
            ValidationError,
            match="provide gateway_id, or remote_network",
        ):
            TwingateRef.model_validate({"network": "acme"})

    def test_mode_a_and_mode_b_fields_together(self) -> None:
        with pytest.raises(ValidationError, match="not both"):
            TwingateRef.model_validate(
                {
                    "network": "acme",
                    "gateway_id": "R2Vad2F5OjEyMw==",
                    "gateway_address": "10.0.0.1:8443",
                }
            )

    def test_mode_a_with_remote_network(self) -> None:
        with pytest.raises(ValidationError, match="not both"):
            TwingateRef.model_validate(
                {
                    "network": "acme",
                    "gateway_id": "R2Vad2F5OjEyMw==",
                    "remote_network": "prod-dc",
                }
            )

    def test_mode_b_both_remote_network_and_id(self) -> None:
        with pytest.raises(
            ValidationError,
            match="exactly one of remote_network",
        ):
            TwingateRef.model_validate(
                {
                    "network": "acme",
                    "remote_network": "prod-dc",
                    "remote_network_id": "Um10Ok5ldDo0NTY=",
                    "gateway_address": "10.0.0.1:8443",
                }
            )

    def test_mode_b_missing_gateway_address(self) -> None:
        with pytest.raises(ValidationError, match="requires gateway_address"):
            TwingateRef.model_validate(
                {"network": "acme", "remote_network": "prod-dc"}
            )

    def test_gateway_address_without_port_rejected(self) -> None:
        with pytest.raises(ValidationError, match="explicit"):
            TwingateRef.model_validate(
                {
                    "network": "acme",
                    "remote_network": "prod-dc",
                    "gateway_address": "10.0.0.1",
                }
            )

    def test_gateway_address_malformed_rejected(self) -> None:
        with pytest.raises(ValidationError, match="gateway_address"):
            TwingateRef.model_validate(
                {
                    "network": "acme",
                    "remote_network": "prod-dc",
                    "gateway_address": "http://10.0.0.1:8443",
                }
            )

    def test_gateway_address_port_out_of_range_rejected(self) -> None:
        with pytest.raises(ValidationError, match="port must be 1-65535"):
            TwingateRef.model_validate(
                {
                    "network": "acme",
                    "remote_network": "prod-dc",
                    "gateway_address": "10.0.0.1:99999",
                }
            )
