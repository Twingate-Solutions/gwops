"""Leaf vs. active-CA comparison: a leaf must bundle the CA that is active now."""

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from gwops.certs.manager import CertManager, LeafState
from gwops.certs.validate import ProblemCategory, evaluate_leaf, validate_leaf
from tests.store_support import leaf_cert_path, leaf_key_path, write_leaf

_SANS = {"10.0.0.5", "db.internal"}


@pytest.fixture
def manager(tmp_path: Path) -> CertManager:
    """A manager with a generated CA and a minted leaf that bundles it."""
    mgr = CertManager(tmp_path / "pki")
    mgr.ensure_x509_ca(generate=True)
    mgr.mint_leaf(_SANS)
    return mgr


def _pki_dir(manager: CertManager) -> Path:
    return leaf_cert_path(Path(manager._pki_dir)).parent.parent


def test_leaf_bundling_active_ca_is_ok(manager: CertManager) -> None:
    assert manager.leaf_status(_SANS).state is LeafState.OK


def test_leaf_bundled_with_old_ca_is_invalid_after_ca_change(
    manager: CertManager, tmp_path: Path
) -> None:
    new_ca = CertManager(tmp_path / "new-ca").ensure_x509_ca(generate=True)

    manager.ensure_x509_ca(generate=False, cert_path=new_ca.cert_path, key_path=new_ca.key_path)
    status = manager.leaf_status(_SANS)

    assert status.state is LeafState.INVALID
    assert any("active X.509 CA" in problem for problem in status.problems)


def test_remint_after_ca_change_is_ok_again(manager: CertManager, tmp_path: Path) -> None:
    new_ca = CertManager(tmp_path / "new-ca").ensure_x509_ca(generate=True)
    manager.ensure_x509_ca(generate=False, cert_path=new_ca.cert_path, key_path=new_ca.key_path)

    manager.mint_leaf(_SANS)

    assert manager.leaf_status(_SANS).state is LeafState.OK


def test_leaf_without_bundled_ca_is_invalid(manager: CertManager) -> None:
    pki_dir = _pki_dir(manager)
    chain = x509.load_pem_x509_certificates(leaf_cert_path(pki_dir).read_bytes())
    leaf_only = chain[0].public_bytes(serialization.Encoding.PEM)
    key_pem = leaf_key_path(pki_dir).read_bytes()
    write_leaf(pki_dir, leaf_only, key_pem)

    status = manager.leaf_status(_SANS)

    assert status.state is LeafState.INVALID
    assert any("bundles no CA" in problem for problem in status.problems)


def test_unreadable_active_ca_skips_the_comparison(manager: CertManager) -> None:
    manager._active_x509_ca_cert_path.unlink()

    status = manager.leaf_status(_SANS)

    assert status.state is LeafState.OK


def test_evaluate_leaf_without_ca_cert_keeps_current_behaviour(manager: CertManager) -> None:
    pki_dir = _pki_dir(manager)
    chain = x509.load_pem_x509_certificates(leaf_cert_path(pki_dir).read_bytes())
    leaf_only = chain[0].public_bytes(serialization.Encoding.PEM)
    write_leaf(pki_dir, leaf_only, leaf_key_path(pki_dir).read_bytes())

    assert evaluate_leaf(leaf_cert_path(pki_dir), _SANS) == []
    assert validate_leaf(leaf_cert_path(pki_dir), _SANS) == []


def test_evaluate_leaf_with_ca_cert_reports_chain_category(
    manager: CertManager, tmp_path: Path
) -> None:
    pki_dir = _pki_dir(manager)
    other = CertManager(tmp_path / "other")
    info = other.ensure_x509_ca(generate=True)
    other_ca = x509.load_pem_x509_certificate(info.pem.encode("ascii"))

    problems = evaluate_leaf(leaf_cert_path(pki_dir), _SANS, ca_cert=other_ca)

    assert [p.category for p in problems] == [ProblemCategory.CHAIN]
