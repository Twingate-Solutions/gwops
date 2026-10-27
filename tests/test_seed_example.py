"""Acceptance tests: seed.example.yaml loads clean and overlays track provenance."""

from pathlib import Path

import pytest
import yaml

from gwops.configmodel.loader import load_effective_state
from gwops.configmodel.schema import EffectiveState
from gwops.configmodel.store import OverlayStore
from gwops.renderer.capabilities import Capabilities
from gwops.renderer.render import K8sCredentialFiles, RuntimePaths, render_gateway_config

SEED_EXAMPLE = Path(__file__).parent.parent / "seed.example.yaml"


@pytest.fixture
def store(tmp_path: Path) -> OverlayStore:
    return OverlayStore(tmp_path / "overlays")


def test_seed_example_loads_with_zero_overlays(store: OverlayStore) -> None:
    state, prov = load_effective_state(SEED_EXAMPLE, store)
    assert isinstance(state, EffectiveState)
    assert len(state.ssh_upstreams) == 2
    assert [c.name for c in state.k8s_clusters] == ["prod"]
    assert state.recording.enabled is False
    assert set(prov.values()) == {"seed"}


def test_seed_example_renders_gateway_config_without_error(
    store: OverlayStore, tmp_path: Path
) -> None:
    """The shipped example is valid end to end: it renders, not just loads."""
    state, _ = load_effective_state(SEED_EXAMPLE, store)
    data = tmp_path / "data"
    paths = RuntimePaths(
        pki_dir=data / "pki",
        recording_spool_dir=data / "recording-spool",
        k8s_creds_dir=data / "k8s-creds",
        upstream_ca_dir=data / "upstream-ca",
        k8s_source_root=tmp_path / "k8s-source",
        webapp_ca_root=tmp_path / "webapp-cas",
        public_tls_root=tmp_path / "public-tls",
        public_tls_dir=data / "public-tls",
    ).with_k8s_credentials(
        {"prod": K8sCredentialFiles(token=data / "k8s-creds" / "prod-token-abc",
                                    ca=data / "k8s-creds" / "prod-ca-abc.crt")}
    )

    rendered = yaml.safe_load(render_gateway_config(state, Capabilities(), paths).config_yaml)

    assert [u["name"] for u in rendered["kubernetes"]["upstreams"]] == ["prod"]


def test_overlay_port_change_yields_targeted_provenance(store: OverlayStore) -> None:
    ov = store.add({"k8s_clusters": [{"name": "prod", "port": 7443}]}, comment="port fix")
    state, prov = load_effective_state(SEED_EXAMPLE, store)

    prod = next(c for c in state.k8s_clusters if c.name == "prod")
    assert prod.port == 7443
    assert prov["k8s_clusters.prod.port"] == ov.id

    everything_else = {path: layer for path, layer in prov.items()
                       if path != "k8s_clusters.prod.port"}
    assert set(everything_else.values()) == {"seed"}
