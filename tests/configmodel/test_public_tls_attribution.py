"""A rule 3 or rule 5 refusal is attributed to the layer that set the offending value.

The refusals are model-level validators. Without a location on the error the loader
would report `set by layer: seed` for every one of them, even when an overlay added the
resource; the validators therefore point at the declaring entry
(`<list>.<index>.address|alias`), which the loader maps to the entry's name and then to its
provenance.
"""

from pathlib import Path

import pytest
import yaml

from gwops.configmodel.loader import ConfigLoadError, load_effective_state
from gwops.configmodel.store import OverlayStore
from tests.public_tls_support import ZONE, public_cert, public_seed, ssh, tls_block, webapp


def _refusal(tmp_path: Path, seed: dict[str, object], *patches: dict[str, object]) -> tuple[
    str, list[str]
]:
    """The load error for `seed` + overlays, and the overlay ids in order."""
    seed_path = tmp_path / "seed.yaml"
    seed_path.write_text(yaml.safe_dump(seed, sort_keys=False), encoding="utf-8")
    store = OverlayStore(tmp_path / "overlays")
    ids = [store.add(patch, comment=f"o{i}").id for i, patch in enumerate(patches)]
    with pytest.raises(ConfigLoadError) as exc:
        load_effective_state(seed_path, store)
    return str(exc.value), ids


_TWO_CERTS = tls_block(
    certificates=[
        public_cert("wildcard", [f"*.{ZONE}"]),
        public_cert("api-specific", [f"api.{ZONE}"]),
    ]
)


class TestRule3Attribution:
    def test_an_overlay_entry_outside_the_zones_is_attributed_to_the_overlay(
        self, tmp_path: Path
    ) -> None:
        message, [overlay_id] = _refusal(
            tmp_path, public_seed(), {"ssh_upstreams": [ssh("late", "late.example.net")]}
        )

        assert "ssh_upstreams.late.address: " in message
        assert f"(set by layer: {overlay_id})" in message
        assert "(set by layer: seed)" not in message

    def test_an_overlay_alias_is_attributed_to_the_overlay(self, tmp_path: Path) -> None:
        seed = public_seed(web_apps=[webapp("app", f"app.{ZONE}")])
        message, [overlay_id] = _refusal(
            tmp_path, seed, {"web_apps": [{"name": "app", "alias": "10.0.0.9"}]}
        )

        assert "web_apps.app.alias: " in message
        assert f"(set by layer: {overlay_id})" in message

    def test_an_overlay_changing_a_seed_entrys_address_is_attributed_to_the_overlay(
        self, tmp_path: Path
    ) -> None:
        seed = public_seed(ssh_upstreams=[ssh("host1", f"host1.{ZONE}")])
        message, [overlay_id] = _refusal(
            tmp_path, seed, {"ssh_upstreams": [{"name": "host1", "address": "10.0.0.5"}]}
        )

        assert f"(set by layer: {overlay_id})" in message

    def test_a_seed_entry_is_attributed_to_the_seed_even_with_an_unrelated_overlay(
        self, tmp_path: Path
    ) -> None:
        seed = public_seed(ssh_upstreams=[ssh("bad", "bad.example.net")])
        message, _ids = _refusal(
            tmp_path, seed, {"ssh_upstreams": [ssh("fine", f"fine.{ZONE}")]}
        )

        assert "ssh_upstreams.bad.address: " in message
        assert "(set by layer: seed)" in message

    def test_each_refusal_is_attributed_separately(self, tmp_path: Path) -> None:
        seed = public_seed(ssh_upstreams=[ssh("bad", "bad.example.net")])
        message, [overlay_id] = _refusal(
            tmp_path, seed, {"ssh_upstreams": [ssh("late", "late.example.net")]}
        )

        lines = {line.split(":")[0].strip(): line for line in message.splitlines()[1:]}
        assert "(set by layer: seed)" in lines["ssh_upstreams.bad.address"]
        assert f"(set by layer: {overlay_id})" in lines["ssh_upstreams.late.address"]


class TestRule5Attribution:
    def test_an_overlay_name_no_certificate_covers_is_attributed_to_the_overlay(
        self, tmp_path: Path
    ) -> None:
        message, [overlay_id] = _refusal(
            tmp_path, public_seed(), {"ssh_upstreams": [ssh("deep", f"a.b.{ZONE}")]}
        )

        assert "ssh_upstreams.deep.address: " in message
        assert f"(set by layer: {overlay_id})" in message

    def test_an_overlay_name_two_certificates_cover_is_attributed_to_the_overlay(
        self, tmp_path: Path
    ) -> None:
        message, [overlay_id] = _refusal(
            tmp_path,
            public_seed(_TWO_CERTS),
            {"web_apps": [webapp("app", f"app.{ZONE}", f"api.{ZONE}")]},
        )

        assert "web_apps.app.alias: " in message
        assert f"(set by layer: {overlay_id})" in message

    def test_a_seed_entry_nothing_covers_is_attributed_to_the_seed(self, tmp_path: Path) -> None:
        message, _ids = _refusal(
            tmp_path, public_seed(ssh_upstreams=[ssh("deep", f"a.b.{ZONE}")])
        )

        assert "(set by layer: seed)" in message
