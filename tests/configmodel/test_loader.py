"""Tests for gwops.configmodel.loader.load_effective_state."""

from pathlib import Path

import pytest
import yaml

from gwops.configmodel.loader import ConfigLoadError, load_effective_state
from gwops.configmodel.schema import EffectiveState
from gwops.configmodel.store import OverlayStore

VALID_SEED = {
    "twingate": {"network": "acme", "gateway_id": "g-1"},
    "ssh_upstreams": [{"name": "web-1", "address": "10.0.0.5:22"}],
    "k8s_clusters": [
        {
            "name": "prod",
            "address": "prod.k8s.internal",
            "port": 443,
            "bearer_token_file": "/data/k8s-creds/prod.token",
            "ca_file": "/data/k8s-creds/prod-ca.crt",
        }
    ],
}


@pytest.fixture
def seed_path(tmp_path: Path) -> Path:
    path = tmp_path / "seed.yaml"
    path.write_text(yaml.safe_dump(VALID_SEED), encoding="utf-8")
    return path


@pytest.fixture
def store(tmp_path: Path) -> OverlayStore:
    return OverlayStore(tmp_path / "overlays")


class TestHappyPath:
    def test_seed_only(self, seed_path: Path, store: OverlayStore) -> None:
        state, prov = load_effective_state(seed_path, store)
        assert isinstance(state, EffectiveState)
        assert state.twingate.network == "acme"
        assert state.k8s_clusters[0].port == 443
        assert prov["k8s_clusters.prod.port"] == "seed"
        assert set(prov.values()) == {"seed"}

    def test_overlay_changes_cluster_port_with_provenance(
        self, seed_path: Path, store: OverlayStore
    ) -> None:
        ov = store.add({"k8s_clusters": [{"name": "prod", "port": 6443}]}, comment="f5 fix")
        state, prov = load_effective_state(seed_path, store)
        assert state.k8s_clusters[0].port == 6443
        assert prov["k8s_clusters.prod.port"] == ov.id
        assert prov["k8s_clusters.prod.address"] == "seed"
        assert prov["twingate.network"] == "seed"


class TestFailLoud:
    def test_missing_seed_file(self, tmp_path: Path, store: OverlayStore) -> None:
        with pytest.raises(ConfigLoadError, match="seed"):
            load_effective_state(tmp_path / "nope.yaml", store)

    def test_non_mapping_seed(self, tmp_path: Path, store: OverlayStore) -> None:
        path = tmp_path / "seed.yaml"
        path.write_text("- just\n- a list\n", encoding="utf-8")
        with pytest.raises(ConfigLoadError, match="mapping"):
            load_effective_state(path, store)

    def test_invalid_yaml_syntax(self, tmp_path: Path, store: OverlayStore) -> None:
        path = tmp_path / "seed.yaml"
        path.write_text("twingate: [unclosed", encoding="utf-8")
        with pytest.raises(ConfigLoadError):
            load_effective_state(path, store)

    def test_seed_error_names_dotted_path_and_seed_layer(
        self, tmp_path: Path, store: OverlayStore
    ) -> None:
        bad = {
            "twingate": {"network": "acme", "gateway_id": "g-1"},
            "k8s_clusters": [
                {
                    "name": "prod",
                    "address": "prod.k8s.internal",
                    "port": 999999,
                    "bearer_token_file": "/t",
                    "ca_file": "/c",
                }
            ],
        }
        path = tmp_path / "seed.yaml"
        path.write_text(yaml.safe_dump(bad), encoding="utf-8")
        with pytest.raises(ConfigLoadError) as exc_info:
            load_effective_state(path, store)
        message = str(exc_info.value)
        assert "k8s_clusters.prod.port" in message
        assert "seed" in message

    def test_overlay_error_names_dotted_path_and_overlay_id(
        self, seed_path: Path, store: OverlayStore
    ) -> None:
        ov = store.add({"k8s_clusters": [{"name": "prod", "port": 0}]}, comment="bad port")
        with pytest.raises(ConfigLoadError) as exc_info:
            load_effective_state(seed_path, store)
        message = str(exc_info.value)
        assert "k8s_clusters.prod.port" in message
        assert ov.id in message

    def test_overlay_introducing_unknown_key_names_overlay(
        self, seed_path: Path, store: OverlayStore
    ) -> None:
        ov = store.add({"no_such_field": True}, comment="typo")
        with pytest.raises(ConfigLoadError) as exc_info:
            load_effective_state(seed_path, store)
        message = str(exc_info.value)
        assert "no_such_field" in message
        assert ov.id in message
