"""Reconciler re-mints the private-mode leaf on a CA swap and sheds removed names."""

from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from gwops.certs.manager import CertManager
from gwops.renderer.capabilities import Capabilities
from gwops.tgapi.client import TGClient
from tests.store_support import leaf_cert_path

from .conftest import FakeTGServer
from .test_core import _SSH_SEED, _TWO_SSH_SEED, Env, _leaf_sans


@pytest.fixture
def tg_client() -> TGClient:
    return TGClient(network="acme", api_key="test-key")


def _byo_seed(cert: Path, key: Path) -> str:
    return f"""\
twingate:
  network: acme
  gateway_id: g-1
ca:
  x509:
    generate: false
    cert_path: {cert.as_posix()}
    key_path: {key.as_posix()}
ssh_upstreams:
  - name: web-1
    address: 10.0.0.5:22
"""


def _bundled_ca_fingerprint(pki_dir: Path) -> bytes:
    chain = x509.load_pem_x509_certificates(leaf_cert_path(pki_dir).read_bytes())
    assert len(chain) == 2
    return chain[1].fingerprint(hashes.SHA256())


async def test_byo_ca_swap_remints_leaf_on_next_pass(
    tmp_path: Path,
    gateway_binary: Callable[..., Path],
    tg_server: FakeTGServer,
    tg_client: TGClient,
) -> None:
    ca_a = CertManager(tmp_path / "byo-a").ensure_x509_ca(generate=True)
    ca_b = CertManager(tmp_path / "byo-b").ensure_x509_ca(generate=True)
    env = Env(
        tmp_path,
        _byo_seed(ca_a.cert_path, ca_a.key_path),
        gateway_binary(),
        Capabilities(),
        tg_client,
    )
    first = await env.reconciler.reconcile("startup")
    assert first.errors == []
    fingerprint_a = x509.load_pem_x509_certificate(ca_a.pem.encode("ascii")).fingerprint(
        hashes.SHA256()
    )
    assert _bundled_ca_fingerprint(env.paths.pki_dir) == fingerprint_a

    env.seed_path.write_text(_byo_seed(ca_b.cert_path, ca_b.key_path), encoding="utf-8")
    second = await env.reconciler.reconcile("tick")

    assert second.errors == []
    fingerprint_b = x509.load_pem_x509_certificate(ca_b.pem.encode("ascii")).fingerprint(
        hashes.SHA256()
    )
    assert _bundled_ca_fingerprint(env.paths.pki_dir) == fingerprint_b
    assert any("minted TLS leaf" in action for action in second.actions)

    third = await env.reconciler.reconcile("tick")
    assert not any("minted TLS leaf" in action for action in third.actions)


async def test_removed_upstream_sheds_its_name_from_the_leaf(
    tmp_path: Path,
    gateway_binary: Callable[..., Path],
    tg_server: FakeTGServer,
    tg_client: TGClient,
) -> None:
    env = Env(tmp_path, _TWO_SSH_SEED, gateway_binary(), Capabilities(), tg_client)
    await env.reconciler.reconcile("startup")
    assert _leaf_sans(env.paths.pki_dir) == {"10.0.0.5", "10.0.0.6"}

    env.seed_path.write_text(_SSH_SEED, encoding="utf-8")
    result = await env.reconciler.reconcile("tick")

    assert result.errors == []
    assert _leaf_sans(env.paths.pki_dir) == {"10.0.0.5"}
    assert any("sans_extra" in action for action in result.actions)

    again = await env.reconciler.reconcile("tick")
    assert not any("minted TLS leaf" in action for action in again.actions)
