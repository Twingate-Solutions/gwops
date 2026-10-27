"""Generated certificate hierarchies and PEM helpers for the public-mode material tests.

Everything here is built with ``cryptography`` (real keys, real DER), so the tests exercise
the same parsing and path-validation code production uses. Times are fixed (``NOW``) and
names are fixed; only key material is random, generated once per process (the hierarchies
are cached and immutable, so tests can share them).

Hierarchies (the registered root is always a *test* root, never ISRG Root X1):

* :func:`rsa_hierarchy`: RSA root -> RSA intermediate (``R12``-like, pathlen 0) -> leaf.
* :func:`ecdsa_hierarchy`: shaped like Let's Encrypt's 2025+ ECDSA chain. An RSA
  root (``X1``-like, the registered root) cross-signs ``X2``; ``X2`` cross-signs ``Root YE``;
  ``Root YE`` signs the intermediate ``YE2``; ``YE2`` signs the leaf. The served chain is
  ``[leaf, YE2, Root YE (cross), X2 (cross)]``; the root is never served.
* :func:`other_hierarchy`: an unrelated RSA hierarchy (different root name and keys).
* :func:`impostor_hierarchy`: an RSA hierarchy whose root has the *same subject* as
  :func:`rsa_hierarchy`'s root but different keys.
* :func:`expired_intermediate_hierarchy`: the RSA shape with the intermediate expired at ``NOW``.

Every certificate satisfies the CA/B Forum profile ``cryptography``'s verifier enforces
(SAN on leaves, AKI/SKI, critical ``basicConstraints`` and ``keyUsage`` on CAs, ``serverAuth``
EKU), so a correct implementation verifies them.
"""

from __future__ import annotations

import functools
import hashlib
import ipaddress
import itertools
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from gwops.configmodel.schema import FilePublicCertificate
from tests.public_tls_support import ZONE, public_cert

__all__ = [
    "NOW",
    "ZONE",
    "ZONES",
    "Hierarchy",
    "Issued",
    "declared",
    "ec_key",
    "ecdsa_hierarchy",
    "ed25519_key",
    "expired_intermediate_hierarchy",
    "fingerprint",
    "impostor_hierarchy",
    "key_pem_of",
    "other_hierarchy",
    "pem_of",
    "pem_bodies",
    "rsa_hierarchy",
    "rsa_key",
]

NOW = datetime(2026, 10, 19, 12, 0, 0, tzinfo=UTC)
ZONES = (ZONE,)
DAY = timedelta(days=1)
DEFAULT_ROOT_CN = "ISRG Root X1 (test)"

type PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
type KeyFormat = Literal["pkcs8", "traditional", "encrypted", "encrypted-traditional"]

_serials = itertools.count(0x5000)


# --- keys -----------------------------------------------------------------------------


def rsa_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def ec_key(curve: ec.EllipticCurve | None = None) -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(curve or ec.SECP256R1())


def ed25519_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


# --- PEM helpers ----------------------------------------------------------------------


def pem_of(*certs: x509.Certificate) -> bytes:
    """PEM for `certs` in the order given (a ``fullchain.pem`` when leaf comes first)."""
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def key_pem_of(key: PrivateKey, fmt: KeyFormat = "pkcs8", password: bytes = b"pw") -> bytes:
    """PEM for `key`: PKCS#8, traditional (``RSA``/``EC PRIVATE KEY``), or encrypted forms."""
    private = serialization.PrivateFormat
    encoding = serialization.Encoding.PEM
    encryption: serialization.KeySerializationEncryption = serialization.NoEncryption()
    if fmt.startswith("encrypted"):
        encryption = serialization.BestAvailableEncryption(password)
    layout = private.TraditionalOpenSSL if "traditional" in fmt else private.PKCS8
    return key.private_bytes(encoding, layout, encryption)


def pem_bodies(*blobs: bytes) -> list[str]:
    """Base64 body lines (at least 40 characters) of every PEM block in `blobs`.

    Tests assert that none of these appear in an error message or a log line.
    """
    lines: list[str] = []
    for blob in blobs:
        for raw in blob.decode("utf-8", "replace").splitlines():
            line = raw.strip()
            if len(line) >= 40 and not line.startswith(("-----", "Proc-Type", "DEK-Info")):
                lines.append(line)
    return lines


def fingerprint(cert: x509.Certificate) -> str:
    """Lowercase hex SHA-256 of the DER encoding (the form ``KNOWN_ROOTS`` uses)."""
    return cert.fingerprint(hashes.SHA256()).hex()


def der_sha256(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


# --- certificate builders -------------------------------------------------------------


def _sign_hash(issuer_key: PrivateKey) -> hashes.HashAlgorithm | None:
    if isinstance(issuer_key, ed25519.Ed25519PrivateKey):
        return None
    if isinstance(issuer_key, ec.EllipticCurvePrivateKey) and issuer_key.curve.name == "secp384r1":
        return hashes.SHA384()
    return hashes.SHA256()


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "gwops test PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _ski(cert: x509.Certificate) -> x509.SubjectKeyIdentifier:
    return cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value


def make_ca(
    common_name: str,
    key: PrivateKey,
    *,
    issuer_cert: x509.Certificate | None = None,
    issuer_key: PrivateKey | None = None,
    not_before: datetime = NOW - 3 * 365 * DAY,
    not_after: datetime = NOW + 5 * 365 * DAY,
    path_length: int | None = None,
) -> x509.Certificate:
    """A CA certificate for `key`: self-signed, or signed by `issuer_key` under `issuer_cert`.

    Passing the *same subject* with a different `issuer_cert` makes a cross-signed
    certificate for an existing key.
    """
    subject = _name(common_name)
    signer = issuer_key if issuer_key is not None else key
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert is not None else subject)
        .public_key(key.public_key())
        .serial_number(next(_serials))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
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
    )
    if issuer_cert is not None:
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(_ski(issuer_cert))
    else:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())
    builder = builder.add_extension(aki, critical=False)
    return builder.sign(signer, _sign_hash(signer))


@dataclass(frozen=True)
class Issued:
    """A leaf certificate, its private key and the intermediates served with it."""

    cert: x509.Certificate
    key: PrivateKey
    intermediates: tuple[x509.Certificate, ...]

    @property
    def chain(self) -> tuple[x509.Certificate, ...]:
        """The served chain: leaf first, then the intermediates."""
        return (self.cert, *self.intermediates)

    @property
    def cert_pem(self) -> bytes:
        """A ``fullchain.pem``: the leaf then the intermediates, no root."""
        return pem_of(*self.chain)

    @property
    def key_pem(self) -> bytes:
        """An unencrypted PKCS#8 ``privkey.pem``."""
        return key_pem_of(self.key)

    def with_intermediates(self, intermediates: Iterable[x509.Certificate]) -> Issued:
        return Issued(self.cert, self.key, tuple(intermediates))


@dataclass(frozen=True)
class Hierarchy:
    """A CA hierarchy that can issue leaves. ``root`` is the registered root (never served)."""

    root: x509.Certificate
    intermediates: tuple[x509.Certificate, ...]
    issuer_key: PrivateKey
    leaf_key: PrivateKey

    def issue(
        self,
        dns: Sequence[str] = (f"*.{ZONE}",),
        *,
        ips: Sequence[str] = (),
        key: PrivateKey | None = None,
        not_before: datetime = NOW - 10 * DAY,
        not_after: datetime = NOW + 80 * DAY,
        basic_constraints: Literal["false", "absent", "ca"] = "false",
        eku: Sequence[x509.ObjectIdentifier] | None = (ExtendedKeyUsageOID.SERVER_AUTH,),
    ) -> Issued:
        """Issue a leaf. No SAN extension is written when `dns` and `ips` are both empty;
        `eku=None` omits the extended key usage extension; `basic_constraints` is
        ``CA:FALSE`` (critical), absent, or ``CA:TRUE``.
        """
        leaf_key = key if key is not None else self.leaf_key
        issuer_cert = self.intermediates[0]
        builder = (
            x509.CertificateBuilder()
            .subject_name(_name(dns[0] if dns else "leaf"))
            .issuer_name(issuer_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(next(_serials))
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=basic_constraints == "ca",
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(_ski(issuer_cert)),
                critical=False,
            )
        )
        if basic_constraints != "absent":
            builder = builder.add_extension(
                x509.BasicConstraints(ca=basic_constraints == "ca", path_length=None),
                critical=True,
            )
        if eku is not None:
            builder = builder.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=False)
        names: list[x509.GeneralName] = [x509.DNSName(d) for d in dns]
        names += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
        if names:
            builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
        cert = builder.sign(self.issuer_key, _sign_hash(self.issuer_key))
        return Issued(cert, leaf_key, self.intermediates)


# --- hierarchies ----------------------------------------------------------------------


def build_rsa_hierarchy(
    root_cn: str = DEFAULT_ROOT_CN,
    *,
    intermediate_not_after: datetime = NOW + 5 * 365 * DAY,
) -> Hierarchy:
    root_key = rsa_key()
    root = make_ca(root_cn, root_key, not_after=NOW + 10 * 365 * DAY)
    inter_key = rsa_key()
    inter = make_ca(
        "R12 (test)",
        inter_key,
        issuer_cert=root,
        issuer_key=root_key,
        not_after=intermediate_not_after,
        path_length=0,
    )
    return Hierarchy(root, (inter,), inter_key, rsa_key())


def build_ecdsa_hierarchy() -> Hierarchy:
    x1_key = rsa_key()
    x1 = make_ca(DEFAULT_ROOT_CN, x1_key, not_after=NOW + 10 * 365 * DAY)
    x2_key = ec_key(ec.SECP384R1())
    x2_cross = make_ca(
        "ISRG Root X2 (test)", x2_key, issuer_cert=x1, issuer_key=x1_key, path_length=2
    )
    ye_key = ec_key(ec.SECP384R1())
    ye_cross = make_ca(
        "Root YE (test)", ye_key, issuer_cert=x2_cross, issuer_key=x2_key, path_length=1
    )
    e_key = ec_key(ec.SECP384R1())
    e_inter = make_ca("YE2 (test)", e_key, issuer_cert=ye_cross, issuer_key=ye_key, path_length=0)
    return Hierarchy(x1, (e_inter, ye_cross, x2_cross), e_key, ec_key())


@functools.cache
def rsa_hierarchy() -> Hierarchy:
    return build_rsa_hierarchy()


@functools.cache
def ecdsa_hierarchy() -> Hierarchy:
    return build_ecdsa_hierarchy()


@functools.cache
def other_hierarchy() -> Hierarchy:
    return build_rsa_hierarchy("Some Other Root (test)")


@functools.cache
def impostor_hierarchy() -> Hierarchy:
    """Same root subject as :func:`rsa_hierarchy`, different keys."""
    return build_rsa_hierarchy(DEFAULT_ROOT_CN)


@functools.cache
def expired_intermediate_hierarchy() -> Hierarchy:
    return build_rsa_hierarchy(intermediate_not_after=NOW - DAY)


# --- seed entries ---------------------------------------------------------------------


def declared(
    names: Sequence[str] = (f"*.{ZONE}",), name: str = "wildcard"
) -> FilePublicCertificate:
    """The ``FilePublicCertificate`` seed entry a material check runs against."""
    return FilePublicCertificate.model_validate(public_cert(name=name, names=list(names)))
