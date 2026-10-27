"""`rotate-leaf` and `rotate-ca` are 409 in public mode, ahead of every other check.

The BYO-CA check (`ca.x509.generate` false) cannot be reached in public mode through a seed,
because `public_tls` and an explicit `ca.x509` are mutually exclusive; the ordering is pinned
here for the empty-SAN check of `rotate-leaf` and by the detail text of `rotate-ca`, which names
neither the BYO CA nor a missing staged rotation.
"""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from gwops.api.app import create_app
from tests.public_tls_support import ZONE, public_seed, ssh

from .conftest import ADMIN_TOKEN, DepsBundle, make_deps

_LEAF_DETAIL = "public certificate mode (public_tls): gwops does not mint or rotate the leaf"
_CA_DETAIL = "public certificate mode (public_tls): gwops does not mint or rotate the CA"


def _seed(**top: Any) -> str:
    base: dict[str, Any] = {"ssh_upstreams": [ssh("host1", f"host1.{ZONE}:22")]}
    base.update(top)
    return yaml.safe_dump(public_seed(**base), sort_keys=False)


def _client(bundle: DepsBundle) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(bundle.deps)),
        base_url="http://gwops",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )


def _assert_nothing_minted(bundle: DepsBundle) -> None:
    pki = bundle.deps.settings.data_dir / "pki"
    assert [p for p in pki.rglob("*") if p.is_file()] == []


@pytest.fixture
def public_bundle(tmp_path: Path) -> DepsBundle:
    return make_deps(tmp_path, seed=_seed(), ensure_cas=False)


@pytest.fixture
async def admin(public_bundle: DepsBundle) -> AsyncIterator[httpx.AsyncClient]:
    async with _client(public_bundle) as client:
        yield client


async def test_rotate_leaf_is_409_naming_the_mode_and_the_leaf(
    admin: httpx.AsyncClient, public_bundle: DepsBundle
) -> None:
    response = await admin.post("/certs/rotate-leaf")

    assert response.status_code == 409
    assert response.json()["detail"] == _LEAF_DETAIL
    _assert_nothing_minted(public_bundle)


@pytest.mark.parametrize("phase", ["stage", "complete"])
async def test_rotate_ca_is_409_naming_the_mode_and_the_ca(
    admin: httpx.AsyncClient, public_bundle: DepsBundle, phase: str
) -> None:
    response = await admin.post("/certs/rotate-ca", json={"phase": phase})

    assert response.status_code == 409
    assert response.json()["detail"] == _CA_DETAIL
    assert "bring-your-own" not in response.json()["detail"]
    _assert_nothing_minted(public_bundle)


async def test_the_public_check_runs_before_the_empty_sans_check(tmp_path: Path) -> None:
    """No upstreams would be the leaf route's own 409; the public-mode detail wins."""
    bundle = make_deps(tmp_path, seed=_seed(ssh_upstreams=[]), ensure_cas=False)
    async with _client(bundle) as client:
        response = await client.post("/certs/rotate-leaf")

    assert response.status_code == 409
    assert response.json()["detail"] == _LEAF_DETAIL
