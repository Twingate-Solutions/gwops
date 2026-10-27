"""Tests for gwops.certs.manager.CertManager: on-disk PKI, minting, status, rotation.

Everything here exercises real `cryptography` primitives against real files in
`tmp_path` — no mocking of the crypto itself. Windows cannot express POSIX 0600
faithfully via `os.chmod` (it can only toggle the read-only bit), so the permission
assertions are skipped there; they run for real in the Linux CI image.
"""

import os
import stat
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from gwops.certs.manager import CAInfo, CertManager, LeafState
from gwops.certs.validate import validate_leaf
from tests.store_support import leaf_cert_path, write_leaf

_SANS = {"10.0.0.5", "db.internal"}

_posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="os.chmod cannot express POSIX modes on Windows; 0600 is asserted in Linux CI",
)


@pytest.fixture
def pki_dir(tmp_path: Path) -> Path:
    return tmp_path / "pki"


# --- ensure_x509_ca --------------------------------------------------------------------


def test_ensure_x509_ca_generates_ca_true_10y_keycertsign(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)

    info = manager.ensure_x509_ca(generate=True)

    assert info.cert_path.is_file()
    assert info.key_path.is_file()
    cert = x509.load_pem_x509_certificate(info.pem.encode("ascii"))
    basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic_constraints.ca is True
    key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert key_usage.key_cert_sign is True
    validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
    assert validity_days >= 3650 - 1  # allow for the not_before backdate


def test_ensure_x509_ca_is_idempotent_never_regenerates(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    first = manager.ensure_x509_ca(generate=True)
    first_key_bytes = first.key_path.read_bytes()

    second = manager.ensure_x509_ca(generate=True)

    assert second.key_path.read_bytes() == first_key_bytes
    assert second.pem == first.pem


def test_ensure_x509_ca_loads_provided_paths_without_generating(
    pki_dir: Path, tmp_path: Path
) -> None:
    external_dir = tmp_path / "external"
    external_dir.mkdir()
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "External CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = external_dir / "ca.crt"
    key_path = external_dir / "ca.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    manager = CertManager(pki_dir)
    info = manager.ensure_x509_ca(generate=False, cert_path=cert_path, key_path=key_path)

    assert info.cert_path == cert_path
    assert info.key_path == key_path
    assert info.pem == cert_path.read_text(encoding="ascii")


def test_mint_leaf_uses_ca_from_a_bring_your_own_path(pki_dir: Path, tmp_path: Path) -> None:
    """A CA loaded from a caller-supplied path (not the pki_dir default) must still
    be the CA `mint_leaf` signs against — not silently ignored in favor of a
    (nonexistent) default-location CA."""
    external_dir = tmp_path / "external"
    external_dir.mkdir()
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "External CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = external_dir / "ca.crt"
    key_path = external_dir / "ca.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    # Deliberately do NOT create anything at the pki_dir default CA location.
    manager = CertManager(pki_dir)
    manager.ensure_x509_ca(generate=False, cert_path=cert_path, key_path=key_path)

    paths = manager.mint_leaf(_SANS)

    certs = x509.load_pem_x509_certificates(paths.cert_path.read_bytes())
    assert certs[1] == cert


def test_ensure_x509_ca_absent_and_generate_false_raises(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    with pytest.raises(FileNotFoundError):
        manager.ensure_x509_ca(generate=False)


@_posix_only
def test_ensure_x509_ca_key_written_0600(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    info = manager.ensure_x509_ca(generate=True)
    mode = stat.S_IMODE(info.key_path.stat().st_mode)
    assert mode == 0o600


# --- ensure_ssh_ca -----------------------------------------------------------------------


def test_ensure_ssh_ca_generates_ed25519_openssh_public_key(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)

    info = manager.ensure_ssh_ca(generate=True)

    assert info.key_path.is_file()
    assert info.public_key_openssh.startswith("ssh-ed25519 ")
    # Round-trips through cryptography's OpenSSH public-key loader.
    loaded = serialization.load_ssh_public_key(info.public_key_openssh.encode("ascii"))
    assert loaded.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode("ascii") in info.public_key_openssh


def test_ensure_ssh_ca_is_idempotent_never_regenerates(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    first = manager.ensure_ssh_ca(generate=True)
    second = manager.ensure_ssh_ca(generate=True)
    assert second.public_key_openssh == first.public_key_openssh


def test_ensure_ssh_ca_absent_and_generate_false_raises(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    with pytest.raises(FileNotFoundError):
        manager.ensure_ssh_ca(generate=False)


@_posix_only
def test_ensure_ssh_ca_key_written_0600(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    info = manager.ensure_ssh_ca(generate=True)
    mode = stat.S_IMODE(info.key_path.stat().st_mode)
    assert mode == 0o600


# --- mint_leaf + leaf_status: happy path -------------------------------------------------


def test_mint_leaf_then_status_is_ok(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    manager.ensure_x509_ca(generate=True)

    paths = manager.mint_leaf(_SANS)

    assert paths.cert_path.is_file()
    assert paths.key_path.is_file()
    assert validate_leaf(paths.cert_path, _SANS) == []
    status = manager.leaf_status(_SANS)
    assert status.state == LeafState.OK
    assert status.problems == []
    assert status.not_after is not None


@_posix_only
def test_mint_leaf_key_written_0600(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    manager.ensure_x509_ca(generate=True)
    paths = manager.mint_leaf(_SANS)
    mode = stat.S_IMODE(paths.key_path.stat().st_mode)
    assert mode == 0o600


def test_mint_leaf_fullchain_contains_leaf_and_ca(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    ca_info = manager.ensure_x509_ca(generate=True)
    paths = manager.mint_leaf(_SANS)

    certs = x509.load_pem_x509_certificates(paths.cert_path.read_bytes())
    assert len(certs) == 2
    ca_cert = x509.load_pem_x509_certificate(ca_info.pem.encode("ascii"))
    assert certs[1] == ca_cert


def test_mint_leaf_without_ca_raises(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    with pytest.raises(FileNotFoundError):
        manager.mint_leaf(_SANS)


def test_mint_leaf_empty_sans_raises(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    manager.ensure_x509_ca(generate=True)
    with pytest.raises(ValueError, match="SAN"):
        manager.mint_leaf(set())


# --- leaf_status: MISSING ------------------------------------------------------------------


def test_leaf_status_missing_when_no_leaf_minted(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    status = manager.leaf_status(_SANS)
    assert status.state == LeafState.MISSING
    assert status.not_after is None
    assert status.problems


# --- leaf_status: SANS_INCOMPLETE ----------------------------------------------------------


def test_leaf_status_sans_incomplete_names_missing_san(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    manager.ensure_x509_ca(generate=True)
    manager.mint_leaf({"10.0.0.5"})

    status = manager.leaf_status({"10.0.0.5", "new-upstream.internal"})

    assert status.state == LeafState.SANS_INCOMPLETE
    assert any("new-upstream.internal" in p for p in status.problems)


# --- leaf_status: EXPIRING (short-validity fixture) ----------------------------------------


def test_leaf_status_expiring_when_within_min_days_window(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    ca_info = manager.ensure_x509_ca(generate=True)
    ca_cert = x509.load_pem_x509_certificate(ca_info.pem.encode("ascii"))
    ca_key = serialization.load_pem_private_key(ca_info.key_path.read_bytes(), password=None)
    assert isinstance(ca_key, ec.EllipticCurvePrivateKey)

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gateway")]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))  # short validity: within a 14-day window
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("db.internal")]), critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    write_leaf(
        pki_dir,
        leaf_cert.public_bytes(serialization.Encoding.PEM)
        + ca_cert.public_bytes(serialization.Encoding.PEM),
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )

    status = manager.leaf_status({"db.internal"}, min_days=14)

    assert status.state == LeafState.EXPIRING
    assert status.not_after is not None


# --- leaf_status: INVALID (CA served as leaf) ---------------------------


def test_leaf_status_invalid_when_ca_cert_placed_as_leaf(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    ca_info = manager.ensure_x509_ca(generate=True)

    write_leaf(pki_dir, ca_info.pem.encode("ascii"), ca_info.key_path.read_bytes())

    status = manager.leaf_status(_SANS)

    assert status.state == LeafState.INVALID
    joined = " ".join(status.problems).lower()
    assert "serverauth" in joined
    assert "ca:true" in joined


# --- rotation --------------------------------------------------------------------------


def test_x509_rotation_stage_then_complete(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    old_ca = manager.ensure_x509_ca(generate=True)
    old_leaf_paths = manager.mint_leaf(_SANS)
    old_leaf_certs = x509.load_pem_x509_certificates(old_leaf_paths.cert_path.read_bytes())
    old_leaf_issuer = old_leaf_certs[0].issuer

    staged = manager.stage_x509_rotation()

    assert isinstance(staged, CAInfo)
    assert staged.cert_path != old_ca.cert_path
    assert staged.pem != old_ca.pem

    # Minting again before completion must still use the OLD (current) CA.
    still_old_paths = manager.mint_leaf(_SANS)
    still_old_certs = x509.load_pem_x509_certificates(still_old_paths.cert_path.read_bytes())
    assert still_old_certs[0].issuer == old_leaf_issuer
    assert still_old_certs[1] == x509.load_pem_x509_certificate(old_ca.pem.encode("ascii"))

    manager.complete_x509_rotation()

    # The (former) old CA material now lives under archive/.
    archive_dir = pki_dir / "archive"
    archived_files = list(archive_dir.glob("*.crt"))
    assert len(archived_files) == 1
    archived_cert = x509.load_pem_x509_certificate(archived_files[0].read_bytes())
    assert archived_cert == x509.load_pem_x509_certificate(old_ca.pem.encode("ascii"))

    # Minting after completion uses the NEW CA.
    new_paths = manager.mint_leaf(_SANS)
    new_certs = x509.load_pem_x509_certificates(new_paths.cert_path.read_bytes())
    assert new_certs[1] == x509.load_pem_x509_certificate(staged.pem.encode("ascii"))
    assert new_certs[1] != x509.load_pem_x509_certificate(old_ca.pem.encode("ascii"))


def test_stage_x509_rotation_is_idempotent(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    manager.ensure_x509_ca(generate=True)

    first = manager.stage_x509_rotation()
    second = manager.stage_x509_rotation()

    assert first.pem == second.pem


def test_complete_x509_rotation_without_staged_ca_is_a_noop(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    manager.ensure_x509_ca(generate=True)

    manager.complete_x509_rotation()  # nothing staged: must not raise or archive anything

    assert not (pki_dir / "archive").exists() or not list((pki_dir / "archive").glob("*"))


def test_staged_rotation_survives_a_fresh_manager_instance(pki_dir: Path) -> None:
    """Staged state is just files: a new CertManager pointed at the same dir sees it."""
    manager = CertManager(pki_dir)
    manager.ensure_x509_ca(generate=True)
    staged = manager.stage_x509_rotation()

    reloaded = CertManager(pki_dir)
    reloaded.complete_x509_rotation()

    current = reloaded.ensure_x509_ca(generate=False)
    assert current.pem == staged.pem


# --- BYO / on-disk CA validation at load (fail loud) --------------------------------------


def _write_byo_ca(
    dest_dir: Path,
    *,
    ca_flag: bool = True,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | None = None,
    sign_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | None = None,
) -> tuple[Path, Path]:
    """Write a bring-your-own CA cert/key pair to `dest_dir`, defaulting to a valid EC CA.

    `key` sets the cert's public key (and the written private key); `sign_key`, if given,
    signs the cert instead of `key` — used to produce a cert whose public key does not
    match the written private key.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    cert_key = key or ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "BYO CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(cert_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(minutes=5))
        .not_valid_after(not_after or now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=ca_flag, path_length=None), critical=True)
        .sign(sign_key or cert_key, hashes.SHA256())
    )
    cert_path = dest_dir / "ca.crt"
    key_path = dest_dir / "ca.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        cert_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_ensure_x509_ca_rejects_non_ca_certificate(pki_dir: Path, tmp_path: Path) -> None:
    cert_path, key_path = _write_byo_ca(tmp_path / "byo", ca_flag=False)
    manager = CertManager(pki_dir)
    with pytest.raises(ValueError, match="CA:FALSE|not a CA"):
        manager.ensure_x509_ca(generate=False, cert_path=cert_path, key_path=key_path)


def test_ensure_x509_ca_rejects_expired_certificate(pki_dir: Path, tmp_path: Path) -> None:
    now = datetime.now(UTC)
    cert_path, key_path = _write_byo_ca(
        tmp_path / "byo",
        not_before=now - timedelta(days=30),
        not_after=now - timedelta(days=1),
    )
    manager = CertManager(pki_dir)
    with pytest.raises(ValueError, match="expired"):
        manager.ensure_x509_ca(generate=False, cert_path=cert_path, key_path=key_path)


def test_ensure_x509_ca_rejects_not_yet_valid_certificate(pki_dir: Path, tmp_path: Path) -> None:
    now = datetime.now(UTC)
    cert_path, key_path = _write_byo_ca(
        tmp_path / "byo",
        not_before=now + timedelta(days=1),
        not_after=now + timedelta(days=30),
    )
    manager = CertManager(pki_dir)
    with pytest.raises(ValueError, match="not yet valid"):
        manager.ensure_x509_ca(generate=False, cert_path=cert_path, key_path=key_path)


def test_ensure_x509_ca_rejects_rsa_key(pki_dir: Path, tmp_path: Path) -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert_path, key_path = _write_byo_ca(tmp_path / "byo", key=rsa_key)
    manager = CertManager(pki_dir)
    with pytest.raises(ValueError, match="RSA|EC"):
        manager.ensure_x509_ca(generate=False, cert_path=cert_path, key_path=key_path)


def test_ensure_x509_ca_rejects_key_not_matching_cert(pki_dir: Path, tmp_path: Path) -> None:
    cert_key = ec.generate_private_key(ec.SECP256R1())
    other_key = ec.generate_private_key(ec.SECP256R1())
    # Cert carries `cert_key`'s public key, but we overwrite the written key with `other_key`.
    cert_path, key_path = _write_byo_ca(tmp_path / "byo", key=cert_key)
    key_path.write_bytes(
        other_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    manager = CertManager(pki_dir)
    with pytest.raises(ValueError, match="does not match"):
        manager.ensure_x509_ca(generate=False, cert_path=cert_path, key_path=key_path)


def test_ensure_x509_ca_rejects_pre_existing_generated_material_that_expired(
    pki_dir: Path,
) -> None:
    """Validation applies to the default location too, not only the BYO branch."""
    now = datetime.now(UTC)
    _write_byo_ca(
        pki_dir,
        not_before=now - timedelta(days=30),
        not_after=now - timedelta(days=1),
    )
    # _write_byo_ca writes ca.crt/ca.key; place them at the default x509-ca.* names.
    (pki_dir / "ca.crt").rename(pki_dir / "x509-ca.crt")
    (pki_dir / "ca.key").rename(pki_dir / "x509-ca.key")
    manager = CertManager(pki_dir)
    with pytest.raises(ValueError, match="expired"):
        manager.ensure_x509_ca(generate=False)


def test_ensure_x509_ca_accepts_valid_byo_ca(pki_dir: Path, tmp_path: Path) -> None:
    cert_path, key_path = _write_byo_ca(tmp_path / "byo")
    manager = CertManager(pki_dir)
    info = manager.ensure_x509_ca(generate=False, cert_path=cert_path, key_path=key_path)
    assert info.cert_path == cert_path
    # A valid BYO CA can immediately mint a leaf.
    paths = manager.mint_leaf(_SANS)
    assert validate_leaf(paths.cert_path, _SANS) == []


# --- ensure_x509_ca: exactly-one-of-pair present (corrupt PKI dir) ------------------------


def test_ensure_x509_ca_cert_present_key_missing_raises(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    pki_dir.mkdir(parents=True, exist_ok=True)
    (pki_dir / "x509-ca.crt").write_text("not-a-real-cert", encoding="ascii")
    with pytest.raises(RuntimeError, match="incomplete"):
        manager.ensure_x509_ca(generate=True)


def test_ensure_x509_ca_key_present_cert_missing_raises(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    pki_dir.mkdir(parents=True, exist_ok=True)
    (pki_dir / "x509-ca.key").write_text("not-a-real-key", encoding="ascii")
    with pytest.raises(RuntimeError, match="incomplete"):
        manager.ensure_x509_ca(generate=True)


# --- crash-safe rotation recovery --------------------------------------------------------


class _SimulatedCrash(RuntimeError):
    """Raised by the fault-injecting os.replace to model a process crash mid-rotation."""


def _flaky_os_replace(fail_on_call: int) -> Callable[[object, object], None]:
    """Return an os.replace wrapper that raises `_SimulatedCrash` on its Nth invocation."""
    real = os.replace
    state = {"n": 0}

    def flaky(src: object, dst: object) -> None:
        state["n"] += 1
        if state["n"] == fail_on_call:
            raise _SimulatedCrash(f"simulated crash on os.replace call #{fail_on_call}")
        real(src, dst)  # type: ignore[arg-type]

    return flaky


def _assert_recovered_to_new_ca(
    pki_dir: Path,
    staged: CAInfo,
    old_pem: str,
    old_key_bytes: bytes,
) -> None:
    """After recovery: default CA is the staged one, old CA archived intact, staged consumed."""
    recovered = CertManager(pki_dir)
    recovered.recover_x509_rotation()

    current = recovered.ensure_x509_ca(generate=False)
    assert current.pem == staged.pem

    paths = recovered.mint_leaf(_SANS)
    leaf_chain = x509.load_pem_x509_certificates(paths.cert_path.read_bytes())
    assert leaf_chain[1] == x509.load_pem_x509_certificate(staged.pem.encode("ascii"))

    # The old CA is preserved in archive as a consistent cert+key pair (not corrupted
    # into a mixed old-cert/new-key pair by a crash mid-promote).
    old_cert = x509.load_pem_x509_certificate(old_pem.encode("ascii"))
    archive_dir = pki_dir / "archive"
    matched = False
    for archived_crt in archive_dir.glob("*.crt"):
        if x509.load_pem_x509_certificate(archived_crt.read_bytes()) == old_cert:
            sibling_key = archived_crt.with_suffix(".key")
            assert sibling_key.read_bytes() == old_key_bytes
            matched = True
    assert matched, "old CA cert+key pair not found intact in archive/"

    # Staged material is consumed; a second recovery is a clean no-op.
    assert not (pki_dir / "staged" / "x509-ca.crt").exists()
    recovered.recover_x509_rotation()


@pytest.mark.parametrize("fail_on", [2, 3, 4, 5])
def test_recover_x509_rotation_after_crash_at_each_step(
    pki_dir: Path, monkeypatch: pytest.MonkeyPatch, fail_on: int
) -> None:
    """A completion crashed AFTER the marker was written is finished by recovery.

    os.replace call #1 is the marker; #2/#3 archive the old CA; #4/#5 promote the new
    one. Failing on #2..#5 leaves the `.rotation-stamp` marker in place, which is how
    recovery knows a completion was interrupted (vs. a deliberate pending staging).
    """
    manager = CertManager(pki_dir)
    old = manager.ensure_x509_ca(generate=True)
    old_key_bytes = old.key_path.read_bytes()
    manager.mint_leaf(_SANS)
    staged = manager.stage_x509_rotation()

    real_replace = os.replace
    monkeypatch.setattr(os, "replace", _flaky_os_replace(fail_on))
    with pytest.raises(_SimulatedCrash):
        manager.complete_x509_rotation()
    # Restore only os.replace for the recovery pass (models a restart). `monkeypatch.undo()`
    # would also revert the autouse Windows leaf-store stand-in (tests/conftest.py).
    monkeypatch.setattr(os, "replace", real_replace)

    # The marker must be present, marking this as an interrupted completion.
    assert (pki_dir / "staged" / ".rotation-stamp").is_file()
    _assert_recovered_to_new_ca(pki_dir, staged, old.pem, old_key_bytes)


def test_recover_x509_rotation_noop_when_crash_before_marker(
    pki_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash on the very first completion write (the marker) promoted/archived nothing.

    With no marker and a still-valid default CA, this is indistinguishable from — and
    treated identically to — a deliberate pending staging: recovery is a no-op, and the
    operator's later explicit `complete_x509_rotation` performs the rotation.
    """
    manager = CertManager(pki_dir)
    old = manager.ensure_x509_ca(generate=True)
    staged = manager.stage_x509_rotation()

    monkeypatch.setattr(os, "replace", _flaky_os_replace(1))  # fail on the marker write
    with pytest.raises(_SimulatedCrash):
        manager.complete_x509_rotation()
    monkeypatch.undo()

    assert not (pki_dir / "staged" / ".rotation-stamp").is_file()

    reloaded = CertManager(pki_dir)
    reloaded.recover_x509_rotation()  # must NOT force-promote

    assert reloaded.ensure_x509_ca(generate=False).pem == old.pem  # default untouched
    assert (pki_dir / "staged" / "x509-ca.crt").is_file()  # staged preserved
    assert not (pki_dir / "archive").exists() or not list((pki_dir / "archive").glob("*"))

    # The operator can still complete the deliberate rotation explicitly.
    reloaded.complete_x509_rotation()
    assert reloaded.ensure_x509_ca(generate=False).pem == staged.pem


def test_recover_x509_rotation_noop_for_deliberate_pending_staging(pki_dir: Path) -> None:
    """A boot inside the stage -> register -> complete window must not force-promote.

    The staged CA may not yet be trusted by the Twingate controller; promoting it on
    restart would publish an untrusted CA and cause a TLS outage. With a valid default
    and no completion marker, recovery leaves both the default and staged untouched.
    """
    manager = CertManager(pki_dir)
    old = manager.ensure_x509_ca(generate=True)
    staged = manager.stage_x509_rotation()

    reloaded = CertManager(pki_dir)  # models a supervisor restart mid-window
    reloaded.recover_x509_rotation()

    # Default CA is unchanged and staged material is preserved for the eventual complete.
    assert reloaded.ensure_x509_ca(generate=False).pem == old.pem
    assert reloaded.ensure_x509_ca(generate=False).pem != staged.pem
    assert (pki_dir / "staged" / "x509-ca.crt").is_file()
    assert (pki_dir / "staged" / "x509-ca.key").is_file()
    assert not (pki_dir / "archive").exists() or not list((pki_dir / "archive").glob("*"))

    # A leaf minted now still chains to the OLD (currently trusted) CA.
    leaf_chain = x509.load_pem_x509_certificates(reloaded.mint_leaf(_SANS).cert_path.read_bytes())
    assert leaf_chain[1] == x509.load_pem_x509_certificate(old.pem.encode("ascii"))


def test_recover_x509_rotation_after_crash_during_cleanup(
    pki_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash after promotion but before staged/ is cleaned still recovers cleanly."""
    manager = CertManager(pki_dir)
    old = manager.ensure_x509_ca(generate=True)
    old_key_bytes = old.key_path.read_bytes()
    staged = manager.stage_x509_rotation()

    real_unlink = Path.unlink

    def flaky_unlink(self: Path, *, missing_ok: bool = False) -> None:
        if self.name == "x509-ca.crt" and self.parent.name == "staged":
            raise _SimulatedCrash("simulated crash unlinking staged cert during cleanup")
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", flaky_unlink)
    with pytest.raises(_SimulatedCrash):
        manager.complete_x509_rotation()
    monkeypatch.setattr(Path, "unlink", real_unlink)  # not undo(): keeps the leaf-store stand-in

    _assert_recovered_to_new_ca(pki_dir, staged, old.pem, old_key_bytes)


def test_recover_x509_rotation_is_noop_when_clean(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    ca = manager.ensure_x509_ca(generate=True)

    manager.recover_x509_rotation()  # nothing staged: must not raise or change the CA

    assert not (pki_dir / "archive").exists() or not list((pki_dir / "archive").glob("*"))
    assert manager.ensure_x509_ca(generate=False).pem == ca.pem


def test_recover_x509_rotation_is_noop_after_successful_completion(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    manager.ensure_x509_ca(generate=True)
    staged = manager.stage_x509_rotation()
    manager.complete_x509_rotation()
    archived_before = sorted(p.name for p in (pki_dir / "archive").glob("*"))

    manager.recover_x509_rotation()  # already complete: no second archive, no churn

    assert sorted(p.name for p in (pki_dir / "archive").glob("*")) == archived_before
    assert manager.ensure_x509_ca(generate=False).pem == staged.pem


# --- _atomic_write failure-path cleanup ------------------------------------------------


def test_atomic_write_unlinks_tmp_and_leaves_dest_untouched_when_replace_fails(
    pki_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gwops.certs import manager as manager_mod
    from gwops.certs.manager import _KEY_MODE, _atomic_write

    dest = pki_dir / "key.pem"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(b"original")

    def boom(src: object, dst: object) -> None:
        raise OSError("simulated rename failure")

    monkeypatch.setattr(manager_mod.os, "replace", boom)
    with pytest.raises(OSError, match="simulated rename failure"):
        _atomic_write(dest, b"new-secret-material", mode=_KEY_MODE)

    # The .tmp holding the (unencrypted) new material must not linger on disk.
    assert not (dest.parent / "key.pem.tmp").exists()
    # The destination is untouched.
    assert dest.read_bytes() == b"original"


# --- leaf_sans ---------------------------------------------------------------------------


def test_leaf_sans_lists_dns_and_ip_names_lowercased(pki_dir: Path) -> None:
    manager = CertManager(pki_dir)
    manager.ensure_x509_ca(generate=True)
    manager.mint_leaf({"10.0.0.5", "DB.internal"})

    assert manager.leaf_sans() == {"10.0.0.5", "db.internal"}


def test_leaf_sans_is_none_and_logged_when_the_leaf_is_missing(pki_dir: Path) -> None:
    import structlog

    with structlog.testing.capture_logs() as logs:
        assert CertManager(pki_dir).leaf_sans() is None

    [event] = [e for e in logs if e["event"] == "certs.leaf_sans_unreadable"]
    assert event["log_level"] == "warning"
    assert event["error_type"] == "FileNotFoundError"


def test_leaf_sans_is_none_when_the_leaf_is_not_pem(pki_dir: Path) -> None:
    import structlog

    manager = CertManager(pki_dir)
    manager.ensure_x509_ca(generate=True)
    manager.mint_leaf({"10.0.0.5"})
    leaf_cert_path(pki_dir).write_text("garbage", encoding="utf-8")

    with structlog.testing.capture_logs() as logs:
        assert manager.leaf_sans() is None

    assert any(e["event"] == "certs.leaf_sans_unreadable" for e in logs)
