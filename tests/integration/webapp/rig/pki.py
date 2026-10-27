"""Per-run private PKI for the webapp rig: an upstream CA and P-256 serverAuth leaves."""

import contextlib
import datetime as dt
import ipaddress
import os
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEFAULT_VALIDITY_DAYS = 2.0
DEFAULT_WRONG_HOST_SANS = ("wrong-host.rig.invalid",)
_BACKDATE = dt.timedelta(minutes=5)

ECKey = ec.EllipticCurvePrivateKey


@dataclass(frozen=True)
class RigPki:
    """Paths of one generated PKI; every certificate is PEM, every key unencrypted PKCS#8 PEM."""

    ca_bundle: Path
    echo_cert: Path
    echo_key: Path
    verifier_cert: Path
    verifier_key: Path
    wrong_host_cert: Path
    wrong_host_key: Path


def generate_rig_pki(
    out_dir: Path,
    *,
    echo_sans: Sequence[str],
    verifier_sans: Sequence[str],
    wrong_host_sans: Sequence[str] = DEFAULT_WRONG_HOST_SANS,
    validity_days: float = DEFAULT_VALIDITY_DAYS,
) -> RigPki:
    """Write an upstream CA bundle and echo, verifier and wrong-host leaves (no CA key)."""
    if validity_days <= 0:
        raise ValueError("validity_days must be positive")
    lists = {
        "echo_sans": _normalise(echo_sans, "echo_sans"),
        "verifier_sans": _normalise(verifier_sans, "verifier_sans"),
        "wrong_host_sans": _normalise(wrong_host_sans, "wrong_host_sans"),
    }
    for other in ("echo_sans", "verifier_sans"):
        shared = set(lists["wrong_host_sans"]) & set(lists[other])
        if shared:
            raise ValueError(f"wrong_host_sans overlaps {other}: {sorted(shared)}")

    out_dir.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.UTC)
    not_before = now - _BACKDATE
    not_after = now + dt.timedelta(days=validity_days)

    ca_key, ca_cert = _make_ca(not_before, not_after)
    paths = RigPki(
        ca_bundle=out_dir / "upstream-ca.pem",
        echo_cert=out_dir / "echo.crt",
        echo_key=out_dir / "echo.key",
        verifier_cert=out_dir / "verifier.crt",
        verifier_key=out_dir / "verifier.key",
        wrong_host_cert=out_dir / "wrong-host.crt",
        wrong_host_key=out_dir / "wrong-host.key",
    )
    _write_cert(paths.ca_bundle, ca_cert)
    for sans, cert_path, key_path in (
        (lists["echo_sans"], paths.echo_cert, paths.echo_key),
        (lists["verifier_sans"], paths.verifier_cert, paths.verifier_key),
        (lists["wrong_host_sans"], paths.wrong_host_cert, paths.wrong_host_key),
    ):
        key, cert = _make_leaf(sans, ca_key, ca_cert, not_before, not_after)
        _write_cert(cert_path, cert)
        _write_key(key_path, key)
    return paths


def _normalise(sans: Sequence[str], label: str) -> list[str]:
    """Strip, de-duplicate (keeping order) and require at least one entry."""
    cleaned = list(dict.fromkeys(s.strip() for s in sans))
    if not cleaned or any(not s for s in cleaned):
        raise ValueError(f"{label} must hold at least one non-empty name")
    return cleaned


def _general_name(value: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        return x509.DNSName(value)


def _make_ca(not_before: dt.datetime, not_after: dt.datetime) -> tuple[ECKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"gwops-it upstream CA {secrets.token_hex(4)}")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(
    sans: Sequence[str],
    ca_key: ECKey,
    ca_cert: x509.Certificate,
    not_before: dt.datetime,
    not_after: dt.datetime,
) -> tuple[ECKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sans[0])]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([_general_name(s) for s in sans]), critical=False
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_key(path: Path, key: ECKey) -> None:
    """Write the key at 0600; the mode is a no-op where the platform ignores it."""
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    with contextlib.suppress(OSError):
        path.chmod(0o600)
