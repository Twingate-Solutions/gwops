"""Public-mode certificate material: registered root and loud validation.

Two halves, both pure (no network, no gwops state):

* **Registered root.** :func:`resolve_registered_root` finds the one known public
  root the gateway is bound to in the image's system trust store, by SHA-256 fingerprint of
  its DER encoding. A missing store, a store with no CERTIFICATE block, or no block with the pinned
  fingerprint is a :class:`RegisteredRootError`; nothing is ever matched by subject name.
* **Material validation.** :func:`validate_public_material` checks one operator
  supplied ``cert_file`` / ``key_file`` pair before anything is installed or rendered. The
  gateway binary performs no checks on static material (no chain, expiry or SAN checks), so
  this is the only gate. Checks run in a fixed order: certificate file, key file, leaf
  profile, key-to-leaf match, then the chain, so a leaf-level problem is reported as itself
  and not as a chain failure.

Chain building uses :class:`cryptography.x509.verification.PolicyBuilder` with a store that
holds only the registered root. That verifier applies the CA/Browser Forum profile, so an
operator certificate from another public CA may be refused for a profile reason; the
verifier's own text is carried in the error so the reason is named.

Messages name the certificate, the file and the property. They never contain PEM text or key
material, and this module logs nothing.
"""

import base64
import binascii
import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from gwops.certs.store import MaterialStore, StoreError
from gwops.configmodel.schema import (
    AcmePublicCertificate,
    FilePublicCertificate,
    PublicCertificate,
)
from gwops.confined import ConfinedFileError, read_confined
from gwops.tlsnames import covering_certificate, name_matches, wildcard_parent, zone_of

__all__ = [
    "KNOWN_ROOTS",
    "SYSTEM_TRUST_STORE",
    "PublicCertState",
    "PublicMaterial",
    "PublicMaterialError",
    "RegisteredRootError",
    "SanOverlap",
    "covering_certificate",
    "find_san_overlaps",
    "leaf_dns_sans",
    "read_installed_public_material",
    "read_public_material",
    "resolve_registered_root",
    "validate_public_material",
    "validate_public_material_without_root",
    "verify_chain",
]

KNOWN_ROOTS: Mapping[str, str] = MappingProxyType(
    {"isrg_root_x1": "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6"}
)
"""Registered-root name to the lowercase hex SHA-256 of the root certificate's DER."""

SYSTEM_TRUST_STORE = Path("/etc/ssl/certs/ca-certificates.crt")
"""The image's system trust store (Debian ``ca-certificates`` bundle)."""

_SUPPORTED_EC_CURVES = frozenset({"secp256r1", "secp384r1"})
_MIN_RSA_BITS = 2048
_WILDCARD_PROBE_LABEL = "gwops-probe"
_CERTIFICATE_BLOCK = re.compile(
    r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.DOTALL
)
_KEY_LABEL_SUFFIX = "PRIVATE KEY"

# check slug -> (file, property word). Every message carries both words.
_CHECKS: Mapping[str, tuple[str, str]] = MappingProxyType(
    {
        "cert_not_utf8": ("cert_file", "encoding"),
        "cert_unreadable": ("cert_file", "read"),
        "key_unreadable": ("key_file", "read"),
        "cert_empty": ("cert_file", "certificate"),
        "cert_unexpected_block": ("cert_file", "PEM block"),
        "cert_unparseable": ("cert_file", "certificate"),
        "key_missing": ("key_file", "private key"),
        "key_multiple": ("key_file", "private key"),
        "key_unexpected_block": ("key_file", "PEM block"),
        "key_encrypted": ("key_file", "encryption"),
        "key_unparseable": ("key_file", "private key"),
        "key_unsupported": ("key_file", "key type"),
        "key_mismatch": ("key_file", "public key"),
        "leaf_is_ca": ("cert_file", "basicConstraints"),
        "leaf_no_server_auth": ("cert_file", "extendedKeyUsage"),
        "leaf_expired": ("cert_file", "notAfter"),
        "leaf_not_yet_valid": ("cert_file", "notBefore"),
        "san_missing_name": ("cert_file", "subjectAltName"),
        "san_outside_zone": ("cert_file", "subjectAltName"),
        "san_ip": ("cert_file", "subjectAltName"),
        "chain": ("cert_file", "chain"),
    }
)


class RegisteredRootError(Exception):
    """The configured registered root cannot be resolved from the system trust store."""


class PublicCertState(StrEnum):
    """Expiry state of validated material."""

    OK = "ok"
    EXPIRING = "expiring"


@dataclass(frozen=True)
class PublicMaterial:
    """The facts about one validated certificate and key pair.

    Attributes:
        not_before: Leaf start of validity, timezone-aware UTC.
        not_after: Leaf end of validity, timezone-aware UTC.
        chain: The chain as served: the leaf first, then the intermediates in file order.
        fingerprint: SHA-256 of the leaf's DER encoding, lowercase hex.
        state: ``EXPIRING`` once less than one third of the leaf's lifetime remains.
    """

    not_before: datetime
    not_after: datetime
    chain: tuple[x509.Certificate, ...]
    fingerprint: str
    state: PublicCertState


class PublicMaterialError(Exception):
    """Operator-supplied certificate material was refused.

    The message names the certificate, the file and the property. It holds no PEM text or
    key bytes. A chain failure sets ``__cause__`` to the verifier's error and includes its
    text.

    Attributes:
        certificate: The seed entry's ``name``.
        file: ``"cert_file"`` or ``"key_file"``.
        check: A stable slug naming the failed check (for example ``"key_mismatch"``).
    """

    def __init__(self, certificate: str, check: str, detail: str) -> None:
        file, prop = _CHECKS[check]
        self.certificate = certificate
        self.file = file
        self.check = check
        super().__init__(f"public certificate {certificate!r}: {file}: {prop}: {detail}")


def _sha256_hex(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def resolve_registered_root(
    name: str,
    trust_store_path: Path = SYSTEM_TRUST_STORE,
    *,
    known_roots: Mapping[str, str] = KNOWN_ROOTS,
) -> x509.Certificate:
    """Find the registered root in the system trust store.

    The root is located by the SHA-256 of each block's decoded DER, so only the matched
    block is ever parsed as a certificate. A block that does not decode, or whose hash
    differs, is skipped: one certificate cryptography cannot parse (the bundle holds some
    with non-positive serials) never aborts startup.

    Args:
        name: A key of ``known_roots`` (for example ``"isrg_root_x1"``).
        trust_store_path: A PEM bundle of trusted roots.
        known_roots: Root name to pinned SHA-256 fingerprint; a test seam.

    Returns:
        The bundle certificate whose DER fingerprint equals the pin.

    Raises:
        RegisteredRootError: The name is unknown, the bundle is unreadable or holds no
            CERTIFICATE block, no block has the pinned fingerprint, or the matched block
            cannot be parsed.
    """
    pin = known_roots.get(name)
    if pin is None:
        raise RegisteredRootError(f"unknown registered root {name!r}")
    try:
        bundle = Path(trust_store_path).read_bytes()
    except OSError as exc:
        raise RegisteredRootError(
            f"cannot read the trust store {trust_store_path} for registered root {name!r}: "
            f"{exc.__class__.__name__}"
        ) from exc
    blocks = _CERTIFICATE_BLOCK.findall(bundle.decode("ascii", errors="replace"))
    if not blocks:
        raise RegisteredRootError(f"trust store {trust_store_path} holds no CERTIFICATE blocks")
    wanted = pin.lower()
    for body in blocks:
        try:
            der = base64.b64decode("".join(body.split()), validate=True)
        except binascii.Error:
            continue  # not decodable; never the root, and never an error
        if hashlib.sha256(der).hexdigest() != wanted:
            continue
        try:
            return x509.load_der_x509_certificate(der)
        except ValueError as exc:
            raise RegisteredRootError(
                f"registered root {name!r} (sha256 {pin}) is in the trust store "
                f"{trust_store_path} but cannot be parsed"
            ) from exc
    raise RegisteredRootError(
        f"registered root {name!r} (sha256 {pin}) is not in the trust store {trust_store_path}"
    )


def verify_chain(
    leaf: x509.Certificate,
    intermediates: Sequence[x509.Certificate],
    root: x509.Certificate,
    name: str,
    now: datetime,
) -> list[x509.Certificate]:
    """Build and verify a server path from ``leaf`` to ``root`` for ``name`` at ``now``.

    The trust store holds only ``root``. A leading ``*.`` in ``name`` (a declared wildcard)
    is replaced by a concrete label first. No leaf-profile checks beyond what the verifier
    applies: zones, SAN coverage and the key belong to :func:`validate_public_material`.

    Args:
        leaf: The server certificate.
        intermediates: The served intermediates, any order.
        root: The registered root, never served.
        name: The DNS name to verify the leaf for.
        now: The validation time, timezone-aware.

    Returns:
        The verified path, leaf first and ``root`` last.

    Raises:
        VerificationError: No valid path exists.
    """
    subject = f"{_WILDCARD_PROBE_LABEL}.{wildcard_parent(name)}" if name.startswith("*.") else name
    verifier = (
        PolicyBuilder().store(Store([root])).time(now).build_server_verifier(x509.DNSName(subject))
    )
    return list(verifier.verify(leaf, list(intermediates)))


def _pem_blocks(text: str) -> tuple[list[tuple[str, str]], str]:
    """Split ``text`` into ``(label, block)`` pairs, and the non-whitespace text left over."""
    blocks: list[tuple[str, str]] = []
    remainder: list[str] = []
    position = 0
    while (begin := text.find("-----BEGIN ", position)) != -1:
        label_end = text.find("-----", begin + len("-----BEGIN "))
        if label_end == -1:
            break
        label = text[begin + len("-----BEGIN ") : label_end]
        footer = f"-----END {label}-----"
        end = text.find(footer, label_end)
        if end == -1:
            break
        remainder.append(text[position:begin])
        blocks.append((label, text[begin : end + len(footer)]))
        position = end + len(footer)
    remainder.append(text[position:])
    return blocks, "".join(remainder).strip()


class _Refuser:
    """Builds :class:`PublicMaterialError` for one certificate entry."""

    def __init__(self, certificate: str) -> None:
        self._certificate = certificate

    def __call__(self, check: str, detail: str) -> PublicMaterialError:
        return PublicMaterialError(self._certificate, check, detail)


def _parse_certificates(cert_pem: bytes, refuse: _Refuser) -> tuple[x509.Certificate, ...]:
    """Parse a ``cert_file`` holding only ``CERTIFICATE`` blocks, leaf first."""
    try:
        text = cert_pem.decode("utf-8")
    except UnicodeDecodeError:
        raise refuse("cert_not_utf8", "the file is not valid UTF-8") from None
    blocks, remainder = _pem_blocks(text)
    if not blocks and not remainder:
        raise refuse("cert_empty", "the file holds no certificate")
    if remainder or any(label != "CERTIFICATE" for label, _ in blocks):
        raise refuse("cert_unexpected_block", "the file may hold only CERTIFICATE blocks")
    try:
        return tuple(x509.load_pem_x509_certificate(block.encode()) for _, block in blocks)
    except ValueError:
        raise refuse("cert_unparseable", "a CERTIFICATE block cannot be parsed") from None
    except UnsupportedAlgorithm:
        raise refuse(
            "cert_unreadable", "a CERTIFICATE block uses an algorithm this build cannot read"
        ) from None


type _LeafKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


def _parse_private_key(key_pem: bytes, refuse: _Refuser) -> _LeafKey:
    """Parse a ``key_file`` holding exactly one unencrypted EC P-256/P-384 or RSA >= 2048 key."""
    try:
        text = key_pem.decode("utf-8")
    except UnicodeDecodeError:
        raise refuse(
            "key_missing", "the file is not valid UTF-8 and holds no private key"
        ) from None
    blocks, remainder = _pem_blocks(text)
    keys = [block for label, block in blocks if label.endswith(_KEY_LABEL_SUFFIX)]
    if not keys:
        raise refuse("key_missing", "the file holds no private key")
    if len(keys) > 1:
        raise refuse("key_multiple", "the file must hold exactly one private key")
    if remainder or len(blocks) != 1:
        raise refuse("key_unexpected_block", "the file may hold only the one private key block")
    label, block = blocks[0]
    if label == f"ENCRYPTED {_KEY_LABEL_SUFFIX}" or "Proc-Type: 4,ENCRYPTED" in block:
        raise refuse("key_encrypted", "the key must be unencrypted")
    try:
        key = serialization.load_pem_private_key(block.encode(), password=None)
    except TypeError:
        raise refuse("key_encrypted", "the key must be unencrypted") from None
    except ValueError:
        raise refuse("key_unparseable", "the private key block cannot be parsed") from None
    except UnsupportedAlgorithm:
        raise refuse(
            "key_unreadable", "the private key uses an algorithm this build cannot read"
        ) from None
    if isinstance(key, rsa.RSAPrivateKey) and key.key_size >= _MIN_RSA_BITS:
        return key
    if isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name in _SUPPORTED_EC_CURVES:
        return key
    raise refuse(
        "key_unsupported", "the key must be EC P-256, EC P-384 or RSA of 2048 bits or more"
    )


def _extension[E: x509.ExtensionType](
    leaf: x509.Certificate, extension_type: type[E], refuse: _Refuser
) -> E | None:
    """The leaf's extension of ``extension_type``, or ``None`` when absent."""
    try:
        return leaf.extensions.get_extension_for_class(extension_type).value
    except x509.ExtensionNotFound:
        return None
    except (ValueError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
        raise refuse("cert_unparseable", "the leaf's extensions cannot be parsed") from None


def _check_leaf_profile(
    leaf: x509.Certificate,
    declared: Sequence[str],
    zones: Sequence[str],
    now: datetime,
    refuse: _Refuser,
) -> None:
    """Refuse a leaf that is a CA, lacks ``serverAuth``, is out of window, or has bad SANs."""
    constraints = _extension(leaf, x509.BasicConstraints, refuse)
    if constraints is not None and constraints.ca:
        raise refuse("leaf_is_ca", "the first certificate must be a leaf (CA:FALSE)")
    usage = _extension(leaf, x509.ExtendedKeyUsage, refuse)
    if usage is None or ExtendedKeyUsageOID.SERVER_AUTH not in usage:
        raise refuse("leaf_no_server_auth", "the leaf must carry the serverAuth usage")
    if now < leaf.not_valid_before_utc:
        raise refuse(
            "leaf_not_yet_valid", f"valid only from {leaf.not_valid_before_utc:%Y-%m-%dT%H:%M:%SZ}"
        )
    if now > leaf.not_valid_after_utc:
        raise refuse("leaf_expired", f"expired at {leaf.not_valid_after_utc:%Y-%m-%dT%H:%M:%SZ}")

    sans = _extension(leaf, x509.SubjectAlternativeName, refuse)
    dns_names = [n.lower() for n in sans.get_values_for_type(x509.DNSName)] if sans else []
    ip_names = sans.get_values_for_type(x509.IPAddress) if sans else []
    if ip_names:
        raise refuse("san_ip", f"IP address SAN {ip_names[0]} is not allowed in public mode")
    for san in dns_names:
        parent = wildcard_parent(san)
        if "*" in parent or zone_of(parent, zones) is None:
            raise refuse("san_outside_zone", f"SAN {san} is outside every configured zone")
    for name in declared:
        # A declared wildcard needs the identical wildcard SAN; a concrete name may be
        # covered by a concrete or a one-label wildcard SAN.
        covered = (
            name in dns_names
            if name.startswith("*.")
            else any(name_matches(san, name) for san in dns_names)
        )
        if not covered:
            raise refuse("san_missing_name", f"declared name {name} is not covered by any SAN")


def _check_key_matches(leaf: x509.Certificate, key: _LeafKey, refuse: _Refuser) -> None:
    """Refuse a key whose public half differs from the leaf's."""
    der, spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(der, spki) != leaf.public_key().public_bytes(der, spki):
        raise refuse("key_mismatch", "the key does not match the leaf's public key")


def validate_public_material(
    cert: PublicCertificate,
    cert_pem: bytes,
    key_pem: bytes,
    *,
    zones: Iterable[str],
    root: x509.Certificate,
    now: datetime,
) -> PublicMaterial:
    """Validate one operator-supplied certificate and key pair against the registered root.

    Args:
        cert: The seed entry; supplies the certificate name and the declared ``names``.
        cert_pem: The ``cert_file`` bytes: the leaf, then the served intermediates.
        key_pem: The ``key_file`` bytes: one unencrypted private key.
        zones: The seed's ``public_tls.zones``.
        root: The registered root (see :func:`resolve_registered_root`).
        now: The validation time, timezone-aware.

    Returns:
        The validated material. A certificate with less than one third of its lifetime
        remaining is returned with state ``EXPIRING``, not refused.

    Raises:
        PublicMaterialError: Any check failed; ``check`` names which.
        TypeError: `root` is None. Only :func:`validate_public_material_without_root` may skip
            the chain check; this function never does.
    """
    if root is None:
        raise TypeError(
            "validate_public_material requires the registered root; "
            "use validate_public_material_without_root for a staging dry run"
        )
    return _validate_material(cert, cert_pem, key_pem, zones=zones, root=root, now=now)


def validate_public_material_without_root(
    cert: PublicCertificate,
    cert_pem: bytes,
    key_pem: bytes,
    *,
    zones: Iterable[str],
    now: datetime,
) -> PublicMaterial:
    """Validate material for a staging dry run: every check except the path to the root.

    Staging certificate authorities chain to roots that are not the registered root (and are
    untrusted by design), so the chain check is the only one skipped. The certificate and key
    parse, the leaf profile (CA flag, ``serverAuth``, validity window, SANs inside the zones,
    no IP SANs, declared names covered) and the key-to-leaf match run exactly as in
    :func:`validate_public_material`. Material that passes this must never be installed or
    rendered: nothing here proves it chains to a root a Client trusts.

    Args:
        cert: The seed entry; supplies the certificate name and the declared ``names``.
        cert_pem: The certificate file bytes: the leaf, then the intermediates.
        key_pem: The private key file bytes: one unencrypted private key.
        zones: The seed's ``public_tls.zones``.
        now: The validation time, timezone-aware.

    Returns:
        The validated material (its ``chain`` is as supplied, unverified).

    Raises:
        PublicMaterialError: Any check but the chain check failed; ``check`` names which.
    """
    return _validate_material(cert, cert_pem, key_pem, zones=zones, root=None, now=now)


def _validate_material(
    cert: PublicCertificate,
    cert_pem: bytes,
    key_pem: bytes,
    *,
    zones: Iterable[str],
    root: x509.Certificate | None,
    now: datetime,
) -> PublicMaterial:
    """The shared validation; ``root=None`` skips only the chain-to-root check."""
    refuse = _Refuser(cert.name)
    chain = _parse_certificates(cert_pem, refuse)
    key = _parse_private_key(key_pem, refuse)
    leaf, intermediates = chain[0], chain[1:]
    _check_leaf_profile(leaf, cert.names, list(zones), now, refuse)
    _check_key_matches(leaf, key, refuse)
    if root is not None:
        for name in cert.names:
            try:
                verify_chain(leaf, intermediates, root, name, now)
            except (VerificationError, ValueError) as exc:
                raise refuse(
                    "chain", f"no valid path to the registered root for {name}: {exc}"
                ) from exc

    not_before, not_after = leaf.not_valid_before_utc, leaf.not_valid_after_utc
    expiring = (not_after - now) * 3 < (not_after - not_before)
    return PublicMaterial(
        not_before=not_before,
        not_after=not_after,
        chain=chain,
        fingerprint=_sha256_hex(leaf),
        state=PublicCertState.EXPIRING if expiring else PublicCertState.OK,
    )


@dataclass(frozen=True)
class SanOverlap:
    """A served name matched by the actual leaf SANs of a certificate other than its cover.

    Attributes:
        name: The served name.
        covering: The certificate whose declared ``names`` cover ``name``.
        other: Another certificate whose leaf SANs also match ``name``.
    """

    name: str
    covering: str
    other: str

    @property
    def message(self) -> str:
        """The refusal text; names both certificates and the served name."""
        return (
            f"served name {self.name!r} is covered by certificate {self.covering!r} but the "
            f"leaf of certificate {self.other!r} also matches it; each served name must "
            "match exactly one certificate"
        )


def leaf_dns_sans(material: PublicMaterial) -> list[str]:
    """Lowercase DNS SANs of the validated leaf; empty when the extension is absent."""
    try:
        san = material.chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except (x509.ExtensionNotFound, ValueError):
        return []
    return [name.lower() for name in san.value.get_values_for_type(x509.DNSName)]


def find_san_overlaps(
    served: Iterable[str],
    certificates: Sequence[PublicCertificate],
    materials: Mapping[str, PublicMaterial],
) -> list[SanOverlap]:
    """Served names that more than one validated leaf matches by its actual SANs.

    The seed rule checks declared ``names`` only; a leaf may carry SANs beyond what its
    entry declares, and the gateway selects the first loaded certificate that supports the
    ClientHello, so such a name would be served by whichever entry happens to come first.
    Matching follows :func:`gwops.tlsnames.name_matches`.

    Args:
        served: The names the gateway serves (``required_sans``).
        certificates: The declared certificates, in seed order.
        materials: Validated material by certificate name; a certificate without an entry
            (it failed validation) is skipped, its failure is reported separately.

    Returns:
        One overlap per (served name, other certificate), in served-name order.
    """
    sans = {name: leaf_dns_sans(material) for name, material in materials.items()}
    overlaps: list[SanOverlap] = []
    for name in sorted(set(served)):
        covering = covering_certificate(name, certificates)
        if covering is None:
            continue
        overlaps.extend(
            SanOverlap(name=name, covering=covering.name, other=cert.name)
            for cert in certificates
            if cert.name != covering.name
            and cert.name in sans
            and any(name_matches(san, name) for san in sans[cert.name])
        )
    return overlaps


def read_public_material(
    cert: FilePublicCertificate,
    source_root: Path,
    *,
    zones: Iterable[str],
    root: x509.Certificate,
    now: datetime,
) -> tuple[bytes, bytes, PublicMaterial]:
    """Read one ``source: file`` certificate's files under ``source_root`` and validate them.

    Both files are read through :func:`gwops.confined.read_confined` (a path that
    resolves outside ``source_root``, a missing, non-regular or oversized file, is refused),
    then handed to :func:`validate_public_material`. Bootstrap and the reconciler share this.
    ``source: acme`` certificates have no files under ``source_root``; their installed
    material is read with :func:`read_installed_public_material`.

    Args:
        cert: The seed entry.
        source_root: The confined root (``/config/public-tls``).
        zones: The seed's ``public_tls.zones``.
        root: The registered root.
        now: The validation time, timezone-aware.

    Returns:
        ``(cert_pem, key_pem, material)``: the bytes exactly as read, and their validation.

    Raises:
        PublicMaterialError: A file could not be read, or any validation check failed. The
            message names the certificate and the file, never contents.
    """
    try:
        cert_pem = read_confined(cert.cert_file, source_root)
    except ConfinedFileError as exc:
        raise PublicMaterialError(cert.name, "cert_unreadable", str(exc)) from None
    try:
        key_pem = read_confined(cert.key_file, source_root)
    except ConfinedFileError as exc:
        raise PublicMaterialError(cert.name, "key_unreadable", str(exc)) from None
    material = validate_public_material(cert, cert_pem, key_pem, zones=zones, root=root, now=now)
    return cert_pem, key_pem, material


def read_installed_public_material(
    cert: AcmePublicCertificate,
    store: MaterialStore,
    *,
    zones: Iterable[str],
    root: x509.Certificate,
    now: datetime,
) -> tuple[bytes, bytes, PublicMaterial, str] | None:
    """Read and validate what the store holds for a ``source: acme`` certificate.

    The pair comes from one store generation (:meth:`MaterialStore.read_current`), so the
    certificate and key always belong together even while an install swaps generations. They
    are validated against the registered root exactly like operator files.

    Args:
        cert: The seed entry.
        store: The public store (``/data/public-tls``).
        zones: The seed's ``public_tls.zones``.
        root: The registered root.
        now: The validation time, timezone-aware.

    Returns:
        ``(cert_pem, key_pem, material, generation)``, or ``None`` when the store holds nothing
        for the entry (nothing has been issued yet). `generation` is the 12-hex store
        generation the bytes were read from.

    Raises:
        PublicMaterialError: Material is present but could not be read (``cert_unreadable``,
            also for a permission or OS error) or a validation check failed. The message names
            the certificate and the file, never contents.
    """
    try:
        current = store.read_current(cert.name)
    except (OSError, StoreError) as exc:
        raise PublicMaterialError(
            cert.name, "cert_unreadable", f"the store cannot be read ({type(exc).__name__})"
        ) from None
    if current is None:
        return None
    cert_pem, key_pem, generation = current
    material = validate_public_material(cert, cert_pem, key_pem, zones=zones, root=root, now=now)
    return cert_pem, key_pem, material, generation
