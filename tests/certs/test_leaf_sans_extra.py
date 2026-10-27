"""`LeafState.SANS_EXTRA`: a leaf carrying names beyond the required set is re-minted."""

from pathlib import Path

import pytest

from gwops.certs.manager import CertManager, LeafState


@pytest.fixture
def manager(tmp_path: Path) -> CertManager:
    mgr = CertManager(tmp_path / "pki")
    mgr.ensure_x509_ca(generate=True)
    return mgr


def test_strict_superset_is_sans_extra(manager: CertManager) -> None:
    manager.mint_leaf({"a.internal", "b.internal"})

    status = manager.leaf_status({"a.internal"})

    assert status.state is LeafState.SANS_EXTRA
    assert status.not_after is not None
    assert "b.internal" in status.problems[0]
    assert "a.internal" not in status.problems[0]


def test_exact_match_is_ok(manager: CertManager) -> None:
    manager.mint_leaf({"a.internal", "b.internal"})

    assert manager.leaf_status({"a.internal", "b.internal"}).state is LeafState.OK


def test_missing_plus_extra_is_sans_incomplete(manager: CertManager) -> None:
    manager.mint_leaf({"a.internal", "b.internal"})

    status = manager.leaf_status({"a.internal", "c.internal"})

    assert status.state is LeafState.SANS_INCOMPLETE


def test_ip_san_superset_is_sans_extra(manager: CertManager) -> None:
    manager.mint_leaf({"10.0.0.5", "10.0.0.6", "a.internal"})

    status = manager.leaf_status({"10.0.0.5", "a.internal"})

    assert status.state is LeafState.SANS_EXTRA
    assert "10.0.0.6" in status.problems[0]


def test_ip_and_mixed_case_names_normalise_to_ok(manager: CertManager) -> None:
    required = {"10.0.0.5", "DB.Internal"}
    manager.mint_leaf(required)

    assert manager.leaf_status(required).state is LeafState.OK


def test_mixed_case_required_name_does_not_make_the_lowercase_leaf_name_extra(
    manager: CertManager,
) -> None:
    manager.mint_leaf({"10.0.0.5", "DB.Internal"})

    status = manager.leaf_status({"10.0.0.5"})

    assert status.state is LeafState.SANS_EXTRA
    assert "db.internal" in status.problems[0]


def test_sans_extra_takes_precedence_over_expiring(manager: CertManager) -> None:
    manager.mint_leaf({"a.internal", "b.internal"})

    status = manager.leaf_status({"a.internal"}, min_days=100_000)

    assert status.state is LeafState.SANS_EXTRA
