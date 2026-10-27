"""Tests for gwops.configmodel.schema: SeedConfig and nested models."""

from typing import Any

import pytest
from pydantic import ValidationError

from gwops.configmodel.schema import (
    EffectiveState,
    K8sCluster,
    SeedConfig,
    SSHUpstream,
)
from gwops.shipper.limits import LINE_MAX_BYTES


def minimal_seed(**overrides: Any) -> dict[str, Any]:
    seed: dict[str, Any] = {
        "twingate": {"network": "acme", "gateway_id": "R2Vad2F5OjEyMw=="},
    }
    seed.update(overrides)
    return seed


class TestSeedConfigHappyPath:
    def test_minimal_seed_validates_with_defaults(self) -> None:
        cfg = SeedConfig.model_validate(minimal_seed())
        assert cfg.twingate.network == "acme"
        assert cfg.twingate.host == "twingate.com"
        assert cfg.ca.x509.generate is True
        assert cfg.ca.ssh.generate is True
        assert cfg.ssh_upstreams == []
        assert cfg.k8s_clusters == []
        assert cfg.recording.enabled is False
        assert cfg.admin_api.bind == "127.0.0.1"
        assert cfg.admin_api.port == 8081

    def test_full_seed_validates(self) -> None:
        cfg = SeedConfig.model_validate(
            minimal_seed(
                ca={
                    "x509": {"generate": False, "cert_path": "/data/pki/ca.crt",
                             "key_path": "/data/pki/ca.key"},
                    "ssh": {"generate": True},
                },
                ssh_upstreams=[{"name": "web-1", "address": "10.0.0.5:22"}],
                k8s_clusters=[
                    {"name": "prod", "address": "prod.k8s.internal", "port": 6443,
                     "bearer_token_file": "/data/k8s-creds/prod.token",
                     "ca_file": "/data/k8s-creds/prod-ca.crt"},
                ],
                recording={"enabled": True, "receiver_url": "http://gatorcast:8000"},
                admin_api={"bind": "0.0.0.0", "port": 9001},
            )
        )
        assert cfg.ssh_upstreams[0].address == "10.0.0.5:22"
        assert cfg.k8s_clusters[0].port == 6443
        assert cfg.recording.receiver_url == "http://gatorcast:8000"

    def test_k8s_port_defaults_to_443(self) -> None:
        c = K8sCluster.model_validate(
            {"name": "c1", "address": "k8s.local",
             "bearer_token_file": "/t", "ca_file": "/c"}
        )
        assert c.port == 443


class TestAddressValidation:
    @pytest.mark.parametrize(
        "address",
        ["host", "host.example.com", "10.0.0.5", "host:22", "10.0.0.5:6443"],
    )
    def test_valid_addresses(self, address: str) -> None:
        SSHUpstream.model_validate({"name": "u1", "address": address})

    @pytest.mark.parametrize(
        "address",
        ["", "host:0", "host:99999", "host:abc", "http://host", "host:22:33", "ho st"],
    )
    def test_invalid_addresses(self, address: str) -> None:
        with pytest.raises(ValidationError):
            SSHUpstream.model_validate({"name": "u1", "address": address})


class TestAddressNormalization:
    def test_mixed_case_ssh_address_is_lowercased(self) -> None:
        upstream = SSHUpstream.model_validate({"name": "u1", "address": "Host.Example.COM:22"})
        assert upstream.address == "host.example.com:22"

    def test_mixed_case_k8s_address_is_lowercased(self) -> None:
        cluster = K8sCluster.model_validate(
            {"name": "c1", "address": "Prod.K8s.Internal",
             "bearer_token_file": "/t", "ca_file": "/c"}
        )
        assert cluster.address == "prod.k8s.internal"

    def test_already_lowercase_address_is_unchanged(self) -> None:
        upstream = SSHUpstream.model_validate({"name": "u1", "address": "host.example.com:22"})
        assert upstream.address == "host.example.com:22"


class TestNameValidation:
    @pytest.mark.parametrize("name", ["a", "web-1", "prod-cluster", "x" * 63])
    def test_valid_names(self, name: str) -> None:
        SSHUpstream.model_validate({"name": name, "address": "h:22"})

    @pytest.mark.parametrize("name", ["", "UPPER", "under_score", "sp ace", "x" * 64, "dot.ted"])
    def test_invalid_names(self, name: str) -> None:
        with pytest.raises(ValidationError):
            SSHUpstream.model_validate({"name": name, "address": "h:22"})


class TestPortAndUniqueness:
    @pytest.mark.parametrize("port", [0, -1, 65536])
    def test_k8s_port_out_of_range(self, port: int) -> None:
        with pytest.raises(ValidationError):
            K8sCluster.model_validate(
                {"name": "c1", "address": "a", "port": port,
                 "bearer_token_file": "/t", "ca_file": "/c"}
            )

    def test_duplicate_ssh_upstream_names_rejected(self) -> None:
        with pytest.raises(ValidationError, match="web-1"):
            SeedConfig.model_validate(
                minimal_seed(
                    ssh_upstreams=[
                        {"name": "web-1", "address": "a:22"},
                        {"name": "web-1", "address": "b:22"},
                    ]
                )
            )

    def test_duplicate_k8s_cluster_names_rejected(self) -> None:
        cluster = {"address": "a", "bearer_token_file": "/t", "ca_file": "/c"}
        with pytest.raises(ValidationError, match="prod"):
            SeedConfig.model_validate(
                minimal_seed(
                    k8s_clusters=[{"name": "prod", **cluster}, {"name": "prod", **cluster}]
                )
            )


class TestFailLoud:
    def test_unknown_top_level_key_rejected(self) -> None:
        with pytest.raises(ValidationError, match="ssh_upstream"):
            SeedConfig.model_validate(minimal_seed(ssh_upstream=[]))  # typo'd key

    def test_byo_ca_requires_paths(self) -> None:
        with pytest.raises(ValidationError):
            SeedConfig.model_validate(
                minimal_seed(ca={"x509": {"generate": False}, "ssh": {"generate": True}})
            )

    def test_recording_enabled_requires_url(self) -> None:
        with pytest.raises(ValidationError, match="receiver_url"):
            SeedConfig.model_validate(minimal_seed(recording={"enabled": True}))

    def test_receiver_url_rejects_non_http_scheme(self) -> None:
        # A URL without an http/https scheme (typo, wrong protocol) fails loud
        # rather than silently shipping the token to nowhere or over a bad transport.
        with pytest.raises(ValidationError, match="http://"):
            SeedConfig.model_validate(
                minimal_seed(
                    recording={"enabled": True, "receiver_url": "gatorcast:8000"}
                )
            )

    def test_receiver_url_allows_http_and_https(self) -> None:
        for url in ("http://gatorcast:8000", "https://gatorcast:8000"):
            cfg = SeedConfig.model_validate(
                minimal_seed(recording={"enabled": True, "receiver_url": url})
            )
            assert cfg.recording.receiver_url == url

    def test_spool_max_bytes_below_the_line_cap_is_refused_with_an_actionable_error(
        self,
    ) -> None:
        with pytest.raises(ValidationError) as exc:
            SeedConfig.model_validate(
                minimal_seed(recording={"spool_max_bytes": LINE_MAX_BYTES - 1})
            )
        message = str(exc.value)
        assert "recording.spool_max_bytes must be at least 16777216" in message
        assert str(LINE_MAX_BYTES - 1) in message
        assert "268435456" in message

    def test_spool_max_bytes_accepts_the_line_cap_and_defaults_to_256_mib(self) -> None:
        at_cap = SeedConfig.model_validate(
            minimal_seed(recording={"spool_max_bytes": LINE_MAX_BYTES})
        )
        assert at_cap.recording.spool_max_bytes == 16 * 1024 * 1024
        default = SeedConfig.model_validate(minimal_seed())
        assert default.recording.spool_max_bytes == 256 * 1024 * 1024


class TestEffectiveState:
    def test_effective_state_is_same_shape(self) -> None:
        state = EffectiveState.model_validate(minimal_seed())
        assert state.twingate.network == "acme"
        assert isinstance(state, SeedConfig)
