"""Tests for the gwops leaf installed through the atomic store.

`CertManager` installs the leaf as store name ``leaf`` under its PKI directory, so the stable
paths are ``<pki_dir>/leaf/fullchain.pem`` (leaf + bundled CA)
and ``<pki_dir>/leaf/privkey.pem``. These tests run on Windows against the symlink-free
stand-in installed by ``tests/conftest.py``; the ones that look at the on-disk store layout
or at atomicity need real symlinks and skip on win32.

Constraints on the implementation: `gwops.certs.manager` imports the class as
``from gwops.certs.store import MaterialStore`` (the Windows stand-in patches that name),
builds one ``MaterialStore(pki_dir)``, and calls only ``install``, ``stable_paths`` and ``gc``.
"""

import shutil
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes

import gwops.certs.manager as manager_module
from gwops.certs.manager import CertManager, LeafState
from tests.store_support import (
    FsCall,
    FsProbe,
    generation_dirs,
    leaf_cert_path,
    leaf_dir,
    leaf_key_path,
    pair_matches,
    read_pair,
    stray_temporaries,
)

_SANS = {"10.0.0.5", "db.internal"}

_needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32",
    reason="creating symlinks needs elevation on Windows (WinError 1314)",
)


@pytest.fixture
def pki_dir(tmp_path: Path) -> Path:
    return tmp_path / "pki"


@pytest.fixture
def manager(pki_dir: Path) -> CertManager:
    instance = CertManager(pki_dir)
    instance.ensure_x509_ca(generate=True)
    return instance


# --- where the leaf lives ----------------------------------------------------------------


def test_mint_leaf_returns_the_stable_store_paths(manager: CertManager, pki_dir: Path) -> None:
    """The returned paths are the ones the rendered config references."""
    paths = manager.mint_leaf(_SANS)

    assert paths.cert_path == leaf_cert_path(pki_dir)
    assert paths.key_path == leaf_key_path(pki_dir)
    assert paths.cert_path == pki_dir / "leaf" / "fullchain.pem"
    assert paths.key_path == pki_dir / "leaf" / "privkey.pem"


def test_mint_leaf_writes_nothing_at_the_old_pki_root_paths(
    manager: CertManager, pki_dir: Path
) -> None:
    """leaf.crt and leaf.key at the PKI root are retired, not rewritten."""
    manager.mint_leaf(_SANS)

    assert not (pki_dir / "leaf.crt").exists()
    assert not (pki_dir / "leaf.key").exists()


def test_the_minted_certificate_and_key_are_a_matching_pair(
    manager: CertManager, pki_dir: Path
) -> None:
    """Read back through the stable paths, the key belongs to the leaf certificate."""
    manager.mint_leaf(_SANS)

    cert_pem, key_pem = read_pair(leaf_cert_path(pki_dir), leaf_key_path(pki_dir))
    assert pair_matches(cert_pem, key_pem)


def test_the_leaf_fullchain_is_the_leaf_followed_by_the_bundled_ca(
    manager: CertManager, pki_dir: Path
) -> None:
    """fullchain.pem holds the leaf first, the signing CA second."""
    ca_info = manager.ensure_x509_ca(generate=True)
    manager.mint_leaf(_SANS)

    chain = x509.load_pem_x509_certificates(leaf_cert_path(pki_dir).read_bytes())

    assert len(chain) == 2
    ca = x509.load_pem_x509_certificate(ca_info.pem.encode("ascii"))
    assert chain[1].fingerprint(hashes.SHA256()) == ca.fingerprint(hashes.SHA256())
    assert chain[0].issuer == ca.subject
    san = chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert {*san.get_values_for_type(x509.DNSName)} == {"db.internal"}


def test_leaf_status_is_ok_for_a_leaf_minted_into_the_store(manager: CertManager) -> None:
    """leaf_status reads the stable cert path."""
    manager.mint_leaf(_SANS)

    assert manager.leaf_status(_SANS).state == LeafState.OK


def test_leaf_status_is_missing_when_the_stable_certificate_is_removed(
    manager: CertManager, pki_dir: Path
) -> None:
    """Deleting the stable cert (the reconciler's re-mint trigger) reads as MISSING."""
    manager.mint_leaf(_SANS)
    leaf_cert_path(pki_dir).unlink()

    assert manager.leaf_status(_SANS).state == LeafState.MISSING


def test_minting_again_after_the_stable_certificate_was_removed_restores_a_valid_pair(
    manager: CertManager, pki_dir: Path
) -> None:
    """The remint after a vanished leaf file leaves a readable, matching, OK leaf."""
    manager.mint_leaf(_SANS)
    leaf_cert_path(pki_dir).unlink()

    manager.mint_leaf(_SANS)

    assert manager.leaf_status(_SANS).state == LeafState.OK
    assert pair_matches(*read_pair(leaf_cert_path(pki_dir), leaf_key_path(pki_dir)))


@_needs_symlinks
def test_mint_leaf_installs_a_generation_through_the_store(
    manager: CertManager, pki_dir: Path
) -> None:
    """The leaf directory has the store layout: ..data, one generation, stable links."""
    manager.mint_leaf(_SANS)

    directory = leaf_dir(pki_dir)
    assert (directory / "..data").is_symlink()
    assert len(generation_dirs(directory)) == 1
    assert leaf_cert_path(pki_dir).is_symlink()
    assert leaf_key_path(pki_dir).is_symlink()


@_needs_symlinks
def test_re_minting_leaves_exactly_one_generation(manager: CertManager, pki_dir: Path) -> None:
    """The previous leaf generation is deleted as soon as the new one is current."""
    manager.mint_leaf(_SANS)
    first = read_pair(leaf_cert_path(pki_dir), leaf_key_path(pki_dir))

    manager.mint_leaf(_SANS | {"extra.internal"})

    second = read_pair(leaf_cert_path(pki_dir), leaf_key_path(pki_dir))
    assert second != first
    assert len(generation_dirs(leaf_dir(pki_dir))) == 1
    assert stray_temporaries(leaf_dir(pki_dir)) == []


# --- upgrade from the two-file layout ------------------------------------------------------


def _plant_the_old_layout(pki_dir: Path) -> tuple[bytes, bytes]:
    """Turn the current store leaf into an old-style leaf.crt + leaf.key, store emptied."""
    old = read_pair(leaf_cert_path(pki_dir), leaf_key_path(pki_dir))
    (pki_dir / "leaf.crt").write_bytes(old[0])
    (pki_dir / "leaf.key").write_bytes(old[1])
    shutil.rmtree(leaf_dir(pki_dir))
    return old


def test_an_old_leaf_with_an_empty_store_is_treated_as_missing(
    manager: CertManager, pki_dir: Path
) -> None:
    """A valid old /data/pki/leaf.crt does not count: the store, not the old file, decides."""
    manager.mint_leaf(_SANS)
    _plant_the_old_layout(pki_dir)

    upgraded = CertManager(pki_dir)

    assert upgraded.leaf_status(_SANS).state == LeafState.MISSING
    assert upgraded.leaf_sans() is None


def test_the_first_mint_after_upgrade_installs_into_the_store_and_keeps_the_old_files(
    manager: CertManager, pki_dir: Path
) -> None:
    """The old two files survive the mint: a `.last-good` config may still name them.

    The reconciler removes them later, once no gateway config references them.
    """
    manager.mint_leaf(_SANS)
    old_cert, old_key = _plant_the_old_layout(pki_dir)
    upgraded = CertManager(pki_dir)

    paths = upgraded.mint_leaf(_SANS)

    assert (pki_dir / "leaf.crt").read_bytes() == old_cert
    assert (pki_dir / "leaf.key").read_bytes() == old_key
    assert paths.cert_path == leaf_cert_path(pki_dir)
    new_cert, new_key = read_pair(paths.cert_path, paths.key_path)
    assert new_cert != old_cert, "the upgrade mints a fresh leaf; it does not migrate the old one"
    assert pair_matches(new_cert, new_key)
    assert upgraded.leaf_status(_SANS).state == LeafState.OK


def test_the_manager_exposes_the_legacy_leaf_paths_for_garbage_collection(
    pki_dir: Path,
) -> None:
    """The reconciler's guarded cleanup needs the two pre-store paths."""
    assert CertManager(pki_dir).legacy_leaf_paths == (pki_dir / "leaf.crt", pki_dir / "leaf.key")


def test_mint_leaf_reports_a_pending_reload_from_the_store(
    manager: CertManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An install whose previous generation was not deleted marks the paths reload_pending."""
    from tests.store_support import FakeInstallResult

    monkeypatch.setattr(
        manager._store,
        "install",
        lambda name, cert, key: FakeInstallResult("a" * 12, True, None, reload_pending=True),
    )

    assert manager.mint_leaf(_SANS).reload_pending is True


def test_mint_leaf_is_not_reload_pending_after_a_clean_install(manager: CertManager) -> None:
    """The common case: nothing pending."""
    assert manager.mint_leaf(_SANS).reload_pending is False


@_needs_symlinks
def test_a_failed_delete_of_the_previous_leaf_generation_is_reported_and_retried(
    manager: CertManager, pki_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The failed delete sets reload_pending; collect_leaf_generations removes it later."""
    import gwops.certs.store as store_module
    from gwops.certs.store import StoreError

    manager.mint_leaf(_SANS)
    real_remove = store_module._remove_entry

    def refuse(path: Path) -> None:
        raise OSError(13, "simulated: permission denied")

    monkeypatch.setattr(store_module, "_remove_entry", refuse)
    paths = manager.mint_leaf(_SANS | {"extra.internal"})

    assert paths.reload_pending is True
    assert len(generation_dirs(leaf_dir(pki_dir))) == 2
    with pytest.raises(StoreError):
        manager.collect_leaf_generations()

    monkeypatch.setattr(store_module, "_remove_entry", real_remove)
    removed = manager.collect_leaf_generations()

    assert len(removed) == 1
    assert len(generation_dirs(leaf_dir(pki_dir))) == 1
    assert manager.collect_leaf_generations() == []


def test_a_re_mint_with_no_old_files_present_is_fine(manager: CertManager, pki_dir: Path) -> None:
    """A re-mint with no pre-store files on disk has nothing to leave or remove."""
    manager.mint_leaf(_SANS)

    manager.mint_leaf(_SANS | {"again.internal"})

    assert manager.leaf_status(_SANS | {"again.internal"}).state == LeafState.OK


def test_the_old_files_are_kept_when_minting_fails_before_the_store(pki_dir: Path) -> None:
    """With no CA yet, mint_leaf raises and the operator's existing leaf files stay put."""
    pki_dir.mkdir(parents=True)
    (pki_dir / "leaf.crt").write_bytes(b"old cert")
    (pki_dir / "leaf.key").write_bytes(b"old key")

    with pytest.raises(FileNotFoundError):
        CertManager(pki_dir).mint_leaf(_SANS)

    assert (pki_dir / "leaf.crt").read_bytes() == b"old cert"
    assert (pki_dir / "leaf.key").read_bytes() == b"old key"


def test_the_old_files_are_kept_when_the_store_install_fails(
    manager: CertManager, pki_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """They go only after the new leaf is safely installed; a failed install loses nothing."""
    (pki_dir / "leaf.crt").write_bytes(b"old cert")
    (pki_dir / "leaf.key").write_bytes(b"old key")

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise OSError(28, "simulated: no space left on device")

    monkeypatch.setattr(manager_module.MaterialStore, "install", refuse)

    with pytest.raises(OSError, match="no space"):
        manager.mint_leaf(_SANS)

    assert (pki_dir / "leaf.crt").read_bytes() == b"old cert"
    assert (pki_dir / "leaf.key").read_bytes() == b"old key"


# --- no mixed key/cert pair ---------------------------------------------------------


@_needs_symlinks
def test_a_reader_never_sees_a_mismatched_leaf_pair_while_the_leaf_is_re_minted(
    manager: CertManager, pki_dir: Path, probe: FsProbe
) -> None:
    """A reader never sees a new key with an old certificate.

    Sampled before and after every filesystem call of a re-mint, the stable paths always
    hold one whole generation.
    """
    manager.mint_leaf(_SANS)
    cert_path, key_path = leaf_cert_path(pki_dir), leaf_key_path(pki_dir)
    old = read_pair(cert_path, key_path)
    samples: list[tuple[bytes, bytes]] = []

    def sample(call: FsCall) -> None:
        served = read_pair(cert_path, key_path)
        samples.append(served)
        if not pair_matches(*served):
            pytest.fail(f"cert and key from different generations around os.{call.name}")

    probe.before(sample)
    probe.after(sample)
    probe.start()
    manager.mint_leaf(_SANS | {"new.internal"})
    probe.stop()

    new = read_pair(cert_path, key_path)
    assert new != old
    assert len(samples) >= 8
    assert all(served in (old, new) for served in samples)
    assert samples[0] == old
    assert samples[-1] == new
