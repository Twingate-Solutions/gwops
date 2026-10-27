"""`ca.x509.on_demand_issuance` is seed-only: overlays cannot set it."""

from pathlib import Path

import httpx
import pytest

from gwops.api.app import create_app
from gwops.api.routes_state import _OVERLAY_ALLOWED_TOP_KEYS

from .conftest import ADMIN_TOKEN, SEED, DepsBundle, make_deps


class TestOverlayRefusal:
    def test_ca_is_not_an_overlay_top_level_key(self) -> None:
        """The overlay allowlist has no `ca`, so nothing under it is writable."""
        assert "ca" not in _OVERLAY_ALLOWED_TOP_KEYS

    @pytest.mark.parametrize("value", [True, False])
    async def test_an_overlay_setting_the_key_is_422_and_persists_nothing(
        self, client: httpx.AsyncClient, bundle: DepsBundle, value: bool
    ) -> None:
        """POST /overlays with ca.x509.on_demand_issuance is refused as seed-only."""
        response = await client.post(
            "/overlays", json={"patch": {"ca": {"x509": {"on_demand_issuance": value}}}}
        )

        assert response.status_code == 422
        assert "seed-only" in response.json()["detail"]
        assert bundle.store.list() == []
        assert bundle.reconciler.triggers == []

    async def test_an_overlay_cannot_switch_the_mode_off_when_the_seed_has_it_on(
        self, tmp_path: Path
    ) -> None:
        """Even with the seed true, an overlay patch for the key is refused."""
        bundle = make_deps(tmp_path, seed=SEED + "ca:\n  x509:\n    on_demand_issuance: true\n")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(bundle.deps)),
            base_url="http://gwops",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        ) as client:
            response = await client.post(
                "/overlays", json={"patch": {"ca": {"x509": {"on_demand_issuance": False}}}}
            )

        assert response.status_code == 422
        assert bundle.store.list() == []
