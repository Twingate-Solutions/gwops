"""Golden render for public mode: two static certificate entries at the stable store paths."""

from pathlib import Path
from typing import Any

import yaml

from gwops.configmodel.schema import EffectiveState
from gwops.renderer.capabilities import Capabilities
from gwops.renderer.render import RuntimePaths, render_gateway_config
from gwops.settings import GwopsSettings

FIXTURES = Path(__file__).parent.parent / "fixtures" / "rendered"

# The seed behind tests/fixtures/rendered/public-tls.yaml. Every served name is inside the zone
# and matches exactly one certificate. Rendering reads no material, so no files are needed.
GOLDEN_SEED: dict[str, Any] = {
    "twingate": {"network": "acme2", "gateway_id": "g-2"},
    "ssh_upstreams": [{"name": "bastion", "address": "bastion.example.com"}],
    "web_apps": [
        {"name": "grafana", "address": "grafana.apps.example.com", "upstream_tls": "verify_full"}
    ],
    "public_tls": {
        "zones": ["example.com"],
        "registered_root": "isrg_root_x1",
        "certificates": [
            {
                "name": "ssh-bastion",
                "names": ["bastion.example.com"],
                "source": "file",
                "cert_file": "/config/public-tls/ssh-bastion/fullchain.pem",
                "key_file": "/config/public-tls/ssh-bastion/privkey.pem",
            },
            {
                "name": "app-wildcard",
                "names": ["*.apps.example.com"],
                "source": "file",
                "cert_file": "/config/public-tls/app-wildcard/fullchain.pem",
                "key_file": "/config/public-tls/app-wildcard/privkey.pem",
            },
        ],
    },
}


def _render_golden_seed() -> str:
    state = EffectiveState.model_validate(GOLDEN_SEED)
    paths = RuntimePaths.from_settings(GwopsSettings())
    return render_gateway_config(state, Capabilities(gateway_version="2.0.0"), paths).config_yaml


class TestPublicGolden:
    def test_public_render_matches_golden_file(self) -> None:
        """The public-mode render equals tests/fixtures/rendered/public-tls.yaml."""
        golden = yaml.safe_load((FIXTURES / "public-tls.yaml").read_text(encoding="utf-8"))
        assert yaml.safe_load(_render_golden_seed()) == golden

    def test_certificates_render_sorted_by_name_at_the_store_paths(self) -> None:
        """Entries are sorted by certificate name even though the seed lists them unsorted."""
        files = yaml.safe_load(_render_golden_seed())["tls"]["certificates"]["files"]
        assert files == [
            {
                "certificateFile": f"/data/public-tls/{name}/fullchain.pem",
                "privateKeyFile": f"/data/public-tls/{name}/privkey.pem",
            }
            for name in ("app-wildcard", "ssh-bastion")
        ]

    def test_public_render_has_no_tls_automation(self) -> None:
        """Public mode never renders an issuer."""
        assert "automation" not in yaml.safe_load(_render_golden_seed())["tls"]
