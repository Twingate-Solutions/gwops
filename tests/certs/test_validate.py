"""Tests for gwops.certs.validate: SAN classification and loud leaf validation.

Certificates are built by hand with `cryptography` (real EC keys, real X.509 encoding)
so these tests exercise the same parsing/verification code paths production will hit,
rather than mocking cryptography away.
"""

import ipaddress
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from gwops.certs.validate import classify_san, validate_leaf

# --- shared cert-building helpers -------------------------------


def _self_signed_ca(
    *, common_name: str = "Test CA"
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    *,
    sans: list[str],
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    eku: list[x509.ObjectIdentifier] | None = None,
    ca_flag: bool = False,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    general_names: list[x509.GeneralName] = []
    for value in sans:
        try:
            general_names.append(x509.IPAddress(ipaddress.IPv4Address(value)))
        except ValueError:
            general_names.append(x509.DNSName(value))
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gateway")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(minutes=5))
        .not_valid_after(not_after or now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=ca_flag, path_length=None), critical=True)
    )
    if general_names:
        builder = builder.add_extension(x509.SubjectAlternativeName(general_names), critical=False)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def _write_fullchain(path: Path, *certs: x509.Certificate) -> None:
    data = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)
    path.write_bytes(data)


def _write_single(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


@pytest.fixture
def pki_dir(tmp_path: Path) -> Iterator[Path]:
    yield tmp_path


# --- classify_san --------------------------------------------------------------------


def test_classify_san_ipv4_returns_ipv4address() -> None:
    result = classify_san("10.0.0.5")
    assert result == ipaddress.IPv4Address("10.0.0.5")


def test_classify_san_dns_name_returns_string() -> None:
    result = classify_san("db.internal.example.com")
    assert result == "db.internal.example.com"


# --- validate_leaf: happy path --------------------------------------------------------


def test_validate_leaf_valid_fullchain_returns_no_problems(pki_dir: Path) -> None:
    ca_key, ca_cert = _self_signed_ca()
    _, leaf_cert = _leaf(
        ca_key, ca_cert, sans=["10.0.0.5", "db.internal"], eku=[ExtendedKeyUsageOID.SERVER_AUTH]
    )
    cert_path = pki_dir / "leaf.crt"
    _write_fullchain(cert_path, leaf_cert, ca_cert)

    assert validate_leaf(cert_path, {"10.0.0.5", "db.internal"}) == []


# --- validate_leaf: SAN gap ------------------------------------------------------------


def test_validate_leaf_missing_san_names_it(pki_dir: Path) -> None:
    ca_key, ca_cert = _self_signed_ca()
    _, leaf_cert = _leaf(ca_key, ca_cert, sans=["10.0.0.5"], eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    cert_path = pki_dir / "leaf.crt"
    _write_fullchain(cert_path, leaf_cert, ca_cert)

    problems = validate_leaf(cert_path, {"10.0.0.5", "db.internal"})

    assert len(problems) == 1
    assert "db.internal" in problems[0]


# --- validate_leaf: CA served as leaf --------------------------


def test_validate_leaf_ca_cert_as_leaf_names_eku_and_ca_true(pki_dir: Path) -> None:
    _, ca_cert = _self_signed_ca()
    cert_path = pki_dir / "leaf.crt"
    _write_single(cert_path, ca_cert)

    problems = validate_leaf(cert_path, {"10.0.0.5"})

    joined = " ".join(problems).lower()
    assert "serverauth" in joined
    assert "ca:true" in joined or "ca=true" in joined or "ca is true" in joined


# --- validate_leaf: expired ------------------------------------------------------------


def test_validate_leaf_expired_cert_is_flagged(pki_dir: Path) -> None:
    ca_key, ca_cert = _self_signed_ca()
    now = datetime.now(UTC)
    _, leaf_cert = _leaf(
        ca_key,
        ca_cert,
        sans=["10.0.0.5"],
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        not_before=now - timedelta(days=10),
        not_after=now - timedelta(days=1),
    )
    cert_path = pki_dir / "leaf.crt"
    _write_fullchain(cert_path, leaf_cert, ca_cert)

    problems = validate_leaf(cert_path, {"10.0.0.5"})

    assert any("expired" in p.lower() for p in problems)


# --- validate_leaf: missing serverAuth EKU --------------------------------------------


def test_validate_leaf_missing_eku_is_flagged(pki_dir: Path) -> None:
    ca_key, ca_cert = _self_signed_ca()
    _, leaf_cert = _leaf(ca_key, ca_cert, sans=["10.0.0.5"], eku=None)
    cert_path = pki_dir / "leaf.crt"
    _write_fullchain(cert_path, leaf_cert, ca_cert)

    problems = validate_leaf(cert_path, {"10.0.0.5"})

    assert any("serverauth" in p.lower() for p in problems)


# --- validate_leaf: chain not signed by the accompanying CA ---------------------------


def test_validate_leaf_chain_signed_by_wrong_ca_is_flagged(pki_dir: Path) -> None:
    ca_key, ca_cert = _self_signed_ca(common_name="Real CA")
    _, other_ca_cert = _self_signed_ca(common_name="Impostor CA")
    _, leaf_cert = _leaf(ca_key, ca_cert, sans=["10.0.0.5"], eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    cert_path = pki_dir / "leaf.crt"
    # Bundle the leaf with a CA cert that did NOT sign it.
    _write_fullchain(cert_path, leaf_cert, other_ca_cert)

    problems = validate_leaf(cert_path, {"10.0.0.5"})

    assert any("chain" in p.lower() or "sign" in p.lower() for p in problems)


def test_validate_leaf_missing_file_is_flagged(pki_dir: Path) -> None:
    problems = validate_leaf(pki_dir / "does-not-exist.crt", {"10.0.0.5"})
    assert len(problems) == 1
    assert "does-not-exist.crt" in problems[0]
