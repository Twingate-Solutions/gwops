"""Loud validation of a minted TLS leaf certificate.

``validate_leaf`` is the public entry point: it reads the certificate (and any accompanying
CA certificate bundled in the same PEM file; :mod:`gwops.certs.manager` writes leaf + CA as
a fullchain to ``leaf/fullchain.pem``) and returns one actionable sentence per problem found.
An empty list means the certificate is fully valid.

:func:`evaluate_leaf` is the categorized variant used by
:class:`gwops.certs.manager.CertManager` to classify problems into
``SANS_INCOMPLETE`` vs. ``INVALID`` for :meth:`CertManager.leaf_status`.

:func:`validate_x509_ca_material` is the CA-side counterpart: it checks a CA cert/key
pair at load time (CA:TRUE, in-window, EC key that matches the cert) so
:meth:`CertManager.ensure_x509_ca` can fail loud on bring-your-own material instead of
exploding later in ``mint_leaf`` or at TLS time.
"""

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID


def classify_san(value: str) -> ipaddress.IPv4Address | str:
    """Classify a raw SAN string as an IPv4 address or a DNS name.

    A string that parses as dotted-quad IPv4 becomes an IP SAN; anything else
    (including IPv6, which is not supported) becomes a DNS SAN.
    """
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        return value


class ProblemCategory(StrEnum):
    """Classification of a leaf validation problem.

    Lets :meth:`gwops.certs.manager.CertManager.leaf_status` distinguish a SAN-only gap
    (``SANS_INCOMPLETE``) from a structurally broken certificate (``INVALID``).
    """

    PARSE = "parse"
    EXPIRY = "expiry"
    EKU = "eku"
    BASIC_CONSTRAINTS = "basic_constraints"
    SAN = "san"
    CHAIN = "chain"


@dataclass(frozen=True)
class LeafProblem:
    """One categorized, human-readable validation failure."""

    category: ProblemCategory
    message: str


def load_first_certificate(cert_path: Path) -> x509.Certificate:
    """Parse `cert_path` as PEM and return the first certificate (the leaf).

    Raises ``ValueError`` if the file is missing, empty, or unparseable — callers
    (both `evaluate_leaf` and `CertManager.leaf_status`) turn that into an actionable
    problem string rather than letting it propagate as a bare exception.
    """
    try:
        data = cert_path.read_bytes()
    except OSError as exc:
        raise ValueError(f"could not read certificate file {cert_path}: {exc}") from exc
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError as exc:
        raise ValueError(f"{cert_path} does not contain a valid PEM certificate: {exc}") from exc
    if not certs:
        raise ValueError(f"{cert_path} contains no certificates")
    return certs[0]


def _load_chain(cert_path: Path) -> list[x509.Certificate]:
    data = cert_path.read_bytes()
    return x509.load_pem_x509_certificates(data)


def _check_validity_window(cert: x509.Certificate) -> list[LeafProblem]:
    now = datetime.now(UTC)
    if now < cert.not_valid_before_utc:
        return [
            LeafProblem(
                ProblemCategory.EXPIRY,
                f"certificate is not yet valid (not valid before "
                f"{cert.not_valid_before_utc.isoformat()}); check the host clock and reissue.",
            )
        ]
    if now > cert.not_valid_after_utc:
        return [
            LeafProblem(
                ProblemCategory.EXPIRY,
                f"certificate has already expired (was valid until "
                f"{cert.not_valid_after_utc.isoformat()}); mint a new leaf.",
            )
        ]
    return []


def _check_eku(cert: x509.Certificate) -> list[LeafProblem]:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return [
            LeafProblem(
                ProblemCategory.EKU,
                "certificate has no extended key usage extension, so TLS clients will reject "
                "the handshake for missing serverAuth; re-mint the leaf with "
                "CertManager.mint_leaf().",
            )
        ]
    if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
        return [
            LeafProblem(
                ProblemCategory.EKU,
                "certificate's extended key usage does not include serverAuth, so TLS "
                "clients will reject the handshake; re-mint the leaf with "
                "CertManager.mint_leaf().",
            )
        ]
    return []


def _check_basic_constraints(cert: x509.Certificate) -> list[LeafProblem]:
    try:
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return []
    if basic_constraints.ca:
        return [
            LeafProblem(
                ProblemCategory.BASIC_CONSTRAINTS,
                "certificate has CA:TRUE (basicConstraints) but must be CA:FALSE — this looks "
                "like the CA certificate served as the leaf, not the TLS leaf itself.",
            )
        ]
    return []


def _san_entries(cert: x509.Certificate) -> set[ipaddress.IPv4Address | str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return set()
    entries: set[ipaddress.IPv4Address | str] = set(san.get_values_for_type(x509.DNSName))
    entries |= {
        ip
        for ip in san.get_values_for_type(x509.IPAddress)
        if isinstance(ip, ipaddress.IPv4Address)
    }
    return entries


def _check_sans(cert: x509.Certificate, required_sans: set[str]) -> list[LeafProblem]:
    present = _san_entries(cert)
    problems: list[LeafProblem] = []
    for value in sorted(required_sans):
        if classify_san(value) not in present:
            problems.append(
                LeafProblem(
                    ProblemCategory.SAN,
                    f"required SAN {value!r} is not present in the certificate's "
                    "subjectAltName; re-mint the leaf with the current required SAN set.",
                )
            )
    return problems


def _check_chain(
    certs: list[x509.Certificate], *, active_ca: x509.Certificate | None = None
) -> list[LeafProblem]:
    if active_ca is not None:
        if len(certs) < 2:
            return [
                LeafProblem(
                    ProblemCategory.CHAIN,
                    "the leaf's file bundles no CA certificate, so it cannot be tied to the "
                    "active X.509 CA; re-mint the leaf so it chains to the current CA.",
                )
            ]
        if certs[1].fingerprint(hashes.SHA256()) != active_ca.fingerprint(hashes.SHA256()):
            return [
                LeafProblem(
                    ProblemCategory.CHAIN,
                    "the CA certificate bundled with the leaf is not the active X.509 CA "
                    "(the CA changed since the leaf was minted); re-mint the leaf so it "
                    "chains to the current CA.",
                )
            ]
    if len(certs) < 2:
        return []
    leaf, ca = certs[0], certs[1]
    ca_public_key = ca.public_key()
    if not isinstance(ca_public_key, ec.EllipticCurvePublicKey):
        return [
            LeafProblem(
                ProblemCategory.CHAIN,
                "the CA certificate bundled alongside the leaf uses an unsupported key "
                "type (expected EC); cannot verify the chain signature.",
            )
        ]
    if leaf.signature_hash_algorithm is None:
        return [
            LeafProblem(
                ProblemCategory.CHAIN,
                "the leaf certificate's signature hash algorithm could not be determined; "
                "cannot verify the chain signature.",
            )
        ]
    try:
        ca_public_key.verify(
            leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm)
        )
    except InvalidSignature:
        return [
            LeafProblem(
                ProblemCategory.CHAIN,
                "the leaf certificate was not signed by the CA certificate bundled with it "
                "in the same file; re-mint the leaf so it chains to the current CA.",
            )
        ]
    if leaf.issuer != ca.subject:
        return [
            LeafProblem(
                ProblemCategory.CHAIN,
                "the leaf certificate's issuer does not match the subject of the CA "
                "certificate bundled with it; re-mint the leaf so it chains to the current CA.",
            )
        ]
    return []


def evaluate_leaf(
    cert_path: Path,
    required_sans: set[str],
    *,
    ca_cert: x509.Certificate | None = None,
) -> list[LeafProblem]:
    """Run every structural, expiry, SAN, and chain check against `cert_path`.

    `cert_path` is expected to hold the leaf certificate, optionally followed in the
    same PEM file by the CA certificate that signed it (the fullchain shape
    :meth:`gwops.certs.manager.CertManager.mint_leaf` writes) — the chain-signature
    check only runs when a second certificate is present. When `ca_cert` (the active
    X.509 CA) is given, a leaf with no bundled CA, or whose bundled CA has a different
    SHA-256 fingerprint, is a ``CHAIN`` problem.
    """
    try:
        certs = _load_chain(cert_path)
    except (OSError, ValueError) as exc:
        return [LeafProblem(ProblemCategory.PARSE, f"could not read or parse {cert_path}: {exc}")]
    if not certs:
        return [LeafProblem(ProblemCategory.PARSE, f"{cert_path} contains no certificates")]

    leaf = certs[0]
    problems: list[LeafProblem] = []
    problems.extend(_check_validity_window(leaf))
    problems.extend(_check_eku(leaf))
    problems.extend(_check_basic_constraints(leaf))
    problems.extend(_check_sans(leaf, required_sans))
    problems.extend(_check_chain(certs, active_ca=ca_cert))
    return problems


def _private_key_type_name(key: object) -> str:
    """Return a human-readable key-type name for a loaded private key."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return "EC"
    if isinstance(key, rsa.RSAPrivateKey):
        return "RSA"
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PrivateKey):
        return "Ed448"
    if isinstance(key, dsa.DSAPrivateKey):
        return "DSA"
    return type(key).__name__


def validate_x509_ca_material(cert_path: Path, key_path: Path) -> list[str]:
    """Validate an X.509 CA cert/key pair for use as :meth:`CertManager.mint_leaf`'s signer.

    Returns one actionable sentence per problem found (an empty list means the material
    is usable). Checks, in order: the certificate parses; it is a CA
    (``basicConstraints`` CA:TRUE); the current time is within its validity window; the
    private key parses; the key is an EC key (the only type ``mint_leaf``'s ECDSA signing
    path supports); and the key matches the certificate's public key. The key-match check
    is skipped when the key type is already unsupported, to avoid a redundant second
    sentence about the same wrong key.
    """
    try:
        cert = load_first_certificate(cert_path)
    except ValueError as exc:
        return [str(exc)]

    problems: list[str] = []

    try:
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = basic_constraints.ca
    except x509.ExtensionNotFound:
        is_ca = False
    if not is_ca:
        problems.append(
            f"the CA certificate at {cert_path} is not a CA (basicConstraints CA:FALSE or "
            "missing); supply a certificate whose basicConstraints sets CA:TRUE."
        )

    now = datetime.now(UTC)
    if now < cert.not_valid_before_utc:
        problems.append(
            f"the CA certificate at {cert_path} is not yet valid (not valid before "
            f"{cert.not_valid_before_utc.isoformat()}); check the host clock or supply a "
            "currently-valid CA."
        )
    elif now > cert.not_valid_after_utc:
        problems.append(
            f"the CA certificate at {cert_path} has expired (was valid until "
            f"{cert.not_valid_after_utc.isoformat()}); supply a currently-valid CA."
        )

    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        problems.append(
            f"the CA private key at {key_path} could not be loaded ({exc}); supply the CA's "
            "unencrypted PEM private key."
        )
        return problems

    if not isinstance(key, ec.EllipticCurvePrivateKey):
        problems.append(
            f"the CA private key at {key_path} is {_private_key_type_name(key)} but only EC "
            "keys are supported for signing leaves; supply an EC (P-256) CA key."
        )
        return problems

    cert_public_der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_public_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if cert_public_der != key_public_der:
        problems.append(
            f"the CA private key at {key_path} does not match the public key in the "
            f"certificate at {cert_path}; supply the matching key/cert pair."
        )

    return problems


def validate_leaf(
    cert_path: Path,
    required_sans: set[str],
    *,
    ca_cert: x509.Certificate | None = None,
) -> list[str]:
    """Validate a leaf certificate at `cert_path` against `required_sans`.

    Checks: current time within the certificate's validity window, the extended key
    usage includes serverAuth, basicConstraints CA is false, every required SAN is
    present, and (when a CA certificate is bundled alongside the leaf) the leaf is
    actually signed by it. With `ca_cert` (the active CA), the bundled CA must also be
    that CA. Returns one actionable sentence per failure; an empty list means the
    certificate is fully valid.
    """
    return [
        problem.message for problem in evaluate_leaf(cert_path, required_sans, ca_cert=ca_cert)
    ]
