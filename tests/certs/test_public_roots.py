"""Tests for the registered-root half of gwops.certs.public.

Interface::

    KNOWN_ROOTS: Mapping[str, str]            # name -> lowercase hex SHA-256 of the root's DER
    SYSTEM_TRUST_STORE: Path                  # Path("/etc/ssl/certs/ca-certificates.crt")
    class RegisteredRootError(Exception)
    def resolve_registered_root(
        name: str,
        trust_store_path: Path = SYSTEM_TRUST_STORE,
        *,
        known_roots: Mapping[str, str] = KNOWN_ROOTS,
    ) -> x509.Certificate

``known_roots`` is the test seam: tests resolve a generated root through a temporary bundle
without touching ``/etc/ssl`` (absent on the Windows dev machine). One test checks that the
real ISRG Root X1 (public data, committed under ``tests/fixtures/tls/``) hashes to the pinned
value, so the pin and the fixture cannot drift apart.
"""

import hashlib
import inspect
import ssl
import warnings
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from gwops.certs.public import (
    KNOWN_ROOTS,
    SYSTEM_TRUST_STORE,
    RegisteredRootError,
    resolve_registered_root,
)
from tests.public_chain_support import (
    ec_key,
    fingerprint,
    impostor_hierarchy,
    make_ca,
    other_hierarchy,
    pem_of,
    rsa_hierarchy,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "tls"
ISRG_ROOT_X1_SHA256 = "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6"

CORRUPT_BLOCK = (
    b"-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n"
)
NOT_BASE64_BLOCK = b"-----BEGIN CERTIFICATE-----\n!!!! not base64 !!!!\n-----END CERTIFICATE-----\n"


def _non_positive_serial_der() -> bytes:
    """A CA certificate whose serial number is negative (DER bytes patched after signing).

    cryptography's builder only issues positive serials, so the serial's high bit is flipped
    in the encoding. The signature no longer verifies; nothing here checks it.
    """
    cert = make_ca("Non-positive serial (test)", ec_key())
    der = cert.public_bytes(serialization.Encoding.DER)
    serial = cert.serial_number.to_bytes((cert.serial_number.bit_length() + 8) // 8, "big")
    encoded = bytes([0x02, len(serial)]) + serial
    assert der.count(encoded) == 1
    patched = bytes([0x02, len(serial), serial[0] | 0x80]) + serial[1:]
    return der.replace(encoded, patched)


def _bundle(tmp_path: Path, *certs: x509.Certificate) -> Path:
    path = tmp_path / "ca-certificates.crt"
    path.write_bytes(pem_of(*certs))
    return path


class TestKnownRoots:
    def test_known_roots_holds_exactly_isrg_root_x1_at_its_pinned_fingerprint(self) -> None:
        assert dict(KNOWN_ROOTS) == {"isrg_root_x1": ISRG_ROOT_X1_SHA256}

    def test_the_committed_isrg_root_x1_pem_hashes_to_the_pinned_value(self) -> None:
        cert = x509.load_pem_x509_certificate((FIXTURES / "isrg-root-x1.pem").read_bytes())

        assert fingerprint(cert) == KNOWN_ROOTS["isrg_root_x1"]
        assert "ISRG Root X1" in cert.subject.rfc4514_string()

    def test_the_default_trust_store_is_the_debian_system_bundle(self) -> None:
        assert Path("/etc/ssl/certs/ca-certificates.crt") == SYSTEM_TRUST_STORE
        default = inspect.signature(resolve_registered_root).parameters["trust_store_path"].default
        assert default == SYSTEM_TRUST_STORE


class TestResolveRegisteredRoot:
    def test_the_matching_certificate_is_found_among_others_in_the_bundle(
        self, tmp_path: Path
    ) -> None:
        wanted = rsa_hierarchy().root
        bundle = _bundle(tmp_path, other_hierarchy().root, wanted, impostor_hierarchy().root)

        found = resolve_registered_root(
            "test_root", bundle, known_roots={"test_root": fingerprint(wanted)}
        )

        assert found == wanted

    def test_the_real_isrg_root_x1_is_resolved_with_the_real_pin(self, tmp_path: Path) -> None:
        real = x509.load_pem_x509_certificate((FIXTURES / "isrg-root-x1.pem").read_bytes())
        bundle = _bundle(tmp_path, other_hierarchy().root, real, rsa_hierarchy().root)

        found = resolve_registered_root("isrg_root_x1", bundle)

        assert fingerprint(found) == ISRG_ROOT_X1_SHA256

    def test_an_unknown_root_name_is_refused_and_named(self, tmp_path: Path) -> None:
        bundle = _bundle(tmp_path, rsa_hierarchy().root)

        with pytest.raises(RegisteredRootError, match="isrg_root_x2"):
            resolve_registered_root("isrg_root_x2", bundle)

    def test_a_missing_trust_store_file_is_refused_and_the_path_named(self, tmp_path: Path) -> None:
        missing = tmp_path / "no" / "ca-certificates.crt"

        with pytest.raises(RegisteredRootError, match="ca-certificates.crt"):
            resolve_registered_root("t", missing, known_roots={"t": "00" * 32})

    def test_a_bundle_without_a_matching_certificate_is_refused_with_the_expected_pin(
        self, tmp_path: Path
    ) -> None:
        bundle = _bundle(tmp_path, other_hierarchy().root)
        pin = fingerprint(rsa_hierarchy().root)

        with pytest.raises(RegisteredRootError) as excinfo:
            resolve_registered_root("t", bundle, known_roots={"t": pin})

        assert pin in str(excinfo.value)

    def test_a_same_subject_certificate_with_a_different_key_is_not_a_match(
        self, tmp_path: Path
    ) -> None:
        """Matching is by DER fingerprint, never by subject name."""
        genuine = rsa_hierarchy().root
        bundle = _bundle(tmp_path, impostor_hierarchy().root)
        assert impostor_hierarchy().root.subject == genuine.subject

        with pytest.raises(RegisteredRootError):
            resolve_registered_root("t", bundle, known_roots={"t": fingerprint(genuine)})

    def test_an_empty_bundle_is_refused(self, tmp_path: Path) -> None:
        bundle = tmp_path / "ca-certificates.crt"
        bundle.write_bytes(b"")

        with pytest.raises(RegisteredRootError):
            resolve_registered_root("t", bundle, known_roots={"t": "00" * 32})

    def test_a_corrupt_block_that_does_not_match_is_skipped_and_the_root_still_resolves(
        self, tmp_path: Path
    ) -> None:
        wanted = rsa_hierarchy().root
        bundle = tmp_path / "ca-certificates.crt"
        bundle.write_bytes(CORRUPT_BLOCK + pem_of(wanted) + NOT_BASE64_BLOCK)

        found = resolve_registered_root("t", bundle, known_roots={"t": fingerprint(wanted)})

        assert found == wanted

    def test_a_bundle_of_only_corrupt_blocks_is_refused_with_the_expected_pin(
        self, tmp_path: Path
    ) -> None:
        bundle = tmp_path / "ca-certificates.crt"
        bundle.write_bytes(CORRUPT_BLOCK + NOT_BASE64_BLOCK)
        pin = fingerprint(rsa_hierarchy().root)

        with pytest.raises(RegisteredRootError) as excinfo:
            resolve_registered_root("t", bundle, known_roots={"t": pin})

        assert pin in str(excinfo.value)

    def test_a_bundle_without_any_certificate_block_is_refused(self, tmp_path: Path) -> None:
        bundle = tmp_path / "ca-certificates.crt"
        bundle.write_text("# nothing here\n")

        with pytest.raises(RegisteredRootError, match="CERTIFICATE"):
            resolve_registered_root("t", bundle, known_roots={"t": "00" * 32})

    def test_a_matched_block_that_does_not_parse_is_refused(self, tmp_path: Path) -> None:
        """The pin matches the block's DER, but the DER is not a certificate."""
        der = b"not a certificate"
        bundle = tmp_path / "ca-certificates.crt"
        bundle.write_text(ssl.DER_cert_to_PEM_cert(der))

        with pytest.raises(RegisteredRootError, match="cannot be parsed"):
            resolve_registered_root("t", bundle, known_roots={"t": hashlib.sha256(der).hexdigest()})

    def test_a_non_positive_serial_certificate_is_never_parsed(self, tmp_path: Path) -> None:
        """cryptography objects to such a certificate on load; the lookup hashes it unparsed."""
        wanted = rsa_hierarchy().root
        bad_der = _non_positive_serial_der()
        with warnings.catch_warnings(record=True) as seen:
            warnings.simplefilter("always")
            try:
                x509.load_der_x509_certificate(bad_der)
            except ValueError:
                seen.append(warnings.WarningMessage("raised", UserWarning, "", 0))
        assert seen, "the fixture must be something cryptography objects to when parsing"
        bundle = tmp_path / "ca-certificates.crt"
        bundle.write_text(ssl.DER_cert_to_PEM_cert(bad_der) + pem_of(wanted).decode())

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            found = resolve_registered_root("t", bundle, known_roots={"t": fingerprint(wanted)})

        assert found == wanted

    def test_a_directory_in_place_of_the_bundle_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(RegisteredRootError):
            resolve_registered_root("t", tmp_path, known_roots={"t": "00" * 32})
