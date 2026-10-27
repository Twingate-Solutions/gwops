"""Tests for ``gwops.certs.public.validate_public_material``.

Checks run in this order: cert_file parse, key_file parse (shape, encryption, type), leaf
profile (basicConstraints, EKU, validity, SANs: IP, zones, coverage), key-matches-leaf, then the
chain. Leaf-level problems are therefore reported as themselves, not as chain failures, and a
file whose first certificate is a CA reports ``leaf_is_ca``. A missing EKU is refused; EC P-521,
secp256k1 and Ed25519 keys are refused; extra DNS SANs inside a zone are accepted; a wildcard SAN
must have its parent inside a zone; CRLF line endings and blank lines between blocks are
accepted; a served root is not refused.

``PublicMaterialError`` names the certificate, the file and the property, never PEM text or key
bytes. A chain failure sets ``__cause__`` to the verifier's ``VerificationError`` and includes
its text.
"""

import dataclasses
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import VerificationError

from gwops import tlsnames
from gwops.certs import public
from gwops.certs.public import (
    PublicCertState,
    PublicMaterial,
    PublicMaterialError,
    leaf_dns_sans,
    validate_public_material,
    validate_public_material_without_root,
)
from tests.public_chain_support import (
    NOW,
    ZONE,
    ZONES,
    Hierarchy,
    PrivateKey,
    declared,
    ec_key,
    ecdsa_hierarchy,
    ed25519_key,
    expired_intermediate_hierarchy,
    fingerprint,
    impostor_hierarchy,
    key_pem_of,
    other_hierarchy,
    pem_bodies,
    pem_of,
    rsa_hierarchy,
    rsa_key,
)

WILDCARD = f"*.{ZONE}"
CERT_NAME = "wildcard"
DAY = timedelta(days=1)
BAD_DER_CERTIFICATE = (
    b"-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n"
)
CSR_BLOCK = b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"

# check slug -> (file, property word); both must appear in str(error)
PROPERTIES: dict[str, tuple[str, str]] = {
    "cert_not_utf8": ("cert_file", "encoding"),
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


def _validate(
    issued_by: Hierarchy | None = None,
    *,
    dns: Iterable[str] = (WILDCARD,),
    names: Iterable[str] = (WILDCARD,),
    zones: Iterable[str] = ZONES,
    now_offset: timedelta = timedelta(0),
    cert_pem: bytes | None = None,
    key_pem: bytes | None = None,
    root: x509.Certificate | None = None,
    **issue_options: object,
) -> PublicMaterial:
    """Issue a leaf from `issued_by` (default RSA) and validate it, overriding any input."""
    hierarchy = issued_by or rsa_hierarchy()
    issued = hierarchy.issue(list(dns), **issue_options)  # type: ignore[arg-type]
    return validate_public_material(
        declared(list(names), CERT_NAME),
        issued.cert_pem if cert_pem is None else cert_pem,
        issued.key_pem if key_pem is None else key_pem,
        zones=list(zones),
        root=hierarchy.root if root is None else root,
        now=NOW + now_offset,
    )


def _refusal(check: str, *args: object, **kwargs: object) -> PublicMaterialError:
    """Run `_validate`, expect `PublicMaterialError` for `check`, and check its shape."""
    with pytest.raises(PublicMaterialError) as excinfo:
        _validate(*args, **kwargs)  # type: ignore[arg-type]
    error = excinfo.value
    file, prop = PROPERTIES[check]
    message = str(error)
    assert error.check == check
    assert error.file == file
    assert error.certificate == CERT_NAME
    assert CERT_NAME in message, "the message names the certificate"
    assert file in message, "the message names the file"
    assert prop in message, "the message names the property"
    return error


@pytest.fixture(params=["rsa", "ecdsa"])
def hierarchy(request: pytest.FixtureRequest) -> Hierarchy:
    return rsa_hierarchy() if request.param == "rsa" else ecdsa_hierarchy()


class TestAcceptedMaterial:
    def test_a_valid_certificate_returns_its_validity_fingerprint_and_ok_state(
        self, hierarchy: Hierarchy
    ) -> None:
        issued = hierarchy.issue()

        material = validate_public_material(
            declared(),
            issued.cert_pem,
            issued.key_pem,
            zones=ZONES,
            root=hierarchy.root,
            now=NOW,
        )

        assert material.not_before == issued.cert.not_valid_before_utc
        assert material.not_after == issued.cert.not_valid_after_utc
        assert material.not_before.tzinfo is not None
        assert material.fingerprint == fingerprint(issued.cert)
        assert material.state == PublicCertState.OK
        assert material.state == "ok"

    def test_the_served_chain_is_the_leaf_then_the_intermediates_in_file_order(
        self, hierarchy: Hierarchy
    ) -> None:
        issued = hierarchy.issue()

        material = _validate(hierarchy)

        assert isinstance(material.chain, tuple)
        assert material.chain[0].subject == issued.cert.subject
        assert [c.subject for c in material.chain[1:]] == [
            c.subject for c in hierarchy.intermediates
        ]

    def test_the_result_is_immutable(self) -> None:
        material = _validate()

        with pytest.raises(dataclasses.FrozenInstanceError):
            material.state = PublicCertState.EXPIRING  # type: ignore[misc]

    @pytest.mark.parametrize("fmt", ["pkcs8", "traditional"])
    def test_pkcs8_and_traditional_key_encodings_are_accepted(
        self, hierarchy: Hierarchy, fmt: str
    ) -> None:
        issued = hierarchy.issue()

        material = _validate(hierarchy, key_pem=key_pem_of(issued.key, fmt))  # type: ignore[arg-type]

        assert material.state == PublicCertState.OK

    def test_an_ec_p384_leaf_key_is_accepted(self) -> None:
        key = ec_key(ec.SECP384R1())
        issued = rsa_hierarchy().issue(key=key)

        material = _validate(cert_pem=issued.cert_pem, key_pem=key_pem_of(key), key=key)

        assert material.state == PublicCertState.OK

    def test_a_leaf_without_basic_constraints_is_accepted(self, hierarchy: Hierarchy) -> None:
        assert _validate(hierarchy, basic_constraints="absent").state == PublicCertState.OK

    def test_an_eku_with_server_auth_among_others_is_accepted(self) -> None:
        eku = (ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH)

        assert _validate(eku=eku).state == PublicCertState.OK

    def test_crlf_line_endings_and_blank_lines_between_blocks_are_accepted(self) -> None:
        issued = rsa_hierarchy().issue()
        crlf = issued.cert_pem.replace(b"\n", b"\r\n").replace(
            b"-----END CERTIFICATE-----\r\n", b"-----END CERTIFICATE-----\r\n\r\n"
        )

        assert _validate(cert_pem=crlf).state == PublicCertState.OK

    def test_a_wildcard_san_covers_a_declared_concrete_name(self) -> None:
        material = _validate(dns=[WILDCARD], names=[f"echo.{ZONE}", f"web.{ZONE}"])

        assert material.state == PublicCertState.OK

    def test_a_declared_wildcard_needs_the_identical_wildcard_san(self) -> None:
        assert _validate(dns=[WILDCARD], names=[WILDCARD]).state == PublicCertState.OK

    def test_a_concrete_san_covers_a_declared_concrete_name(self) -> None:
        assert _validate(dns=[f"echo.{ZONE}"], names=[f"echo.{ZONE}"]).state == "ok"

    def test_an_extra_san_inside_a_zone_is_accepted(self) -> None:
        assert _validate(dns=[WILDCARD, f"extra.deeper.{ZONE}"], names=[WILDCARD]).state == "ok"

    def test_the_zone_apex_as_a_san_is_accepted(self) -> None:
        assert _validate(dns=[WILDCARD, ZONE], names=[WILDCARD, ZONE]).state == "ok"

    def test_a_san_in_any_one_of_several_zones_is_accepted(self) -> None:
        zones = ["other.example", ZONE]

        assert _validate(zones=zones, dns=[WILDCARD, "a.other.example"]).state == "ok"


class TestCertFileRefusals:
    def test_an_empty_file_is_refused(self) -> None:
        _refusal("cert_empty", cert_pem=b"")

    def test_a_whitespace_only_file_is_refused(self) -> None:
        _refusal("cert_empty", cert_pem=b"\n  \r\n\t\n")

    def test_a_file_that_is_not_utf8_is_refused(self) -> None:
        _refusal("cert_not_utf8", cert_pem=b"\xff\xfe\x00-----BEGIN CERTIFICATE-----\n")

    def test_a_private_key_block_after_the_certificates_is_refused(self) -> None:
        issued = rsa_hierarchy().issue()

        _refusal("cert_unexpected_block", cert_pem=issued.cert_pem + issued.key_pem)

    def test_a_private_key_block_before_the_certificates_is_refused(self) -> None:
        issued = rsa_hierarchy().issue()

        _refusal("cert_unexpected_block", cert_pem=issued.key_pem + issued.cert_pem)

    @pytest.mark.parametrize(
        "junk",
        [b"garbage\n", b"# comment\n", CSR_BLOCK],
        ids=["text", "comment", "csr-block"],
    )
    @pytest.mark.parametrize("where", ["before", "after"])
    def test_anything_that_is_not_a_certificate_block_is_refused(
        self, junk: bytes, where: str
    ) -> None:
        pem = rsa_hierarchy().issue().cert_pem

        _refusal("cert_unexpected_block", cert_pem=junk + pem if where == "before" else pem + junk)

    @pytest.mark.parametrize("label", ["TRUSTED CERTIFICATE", "X509 CERTIFICATE"])
    def test_a_block_labelled_other_than_certificate_is_refused(self, label: str) -> None:
        pem = rsa_hierarchy().issue().cert_pem
        relabelled = pem.replace(b"CERTIFICATE", label.encode())

        _refusal("cert_unexpected_block", cert_pem=relabelled)

    def test_a_certificate_block_that_is_not_a_certificate_is_refused(self) -> None:
        bad = b"-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n"

        _refusal("cert_unparseable", cert_pem=bad)

    def test_a_file_whose_first_certificate_is_not_the_leaf_is_refused(self) -> None:
        hierarchy = rsa_hierarchy()
        issued = hierarchy.issue()
        reordered = pem_of(*hierarchy.intermediates, issued.cert)

        _refusal("leaf_is_ca", cert_pem=reordered)


class TestKeyFileRefusals:
    @pytest.mark.parametrize(
        "pem",
        [b"", b"\n\n", b"not a key at all\n", rsa_hierarchy().issue().cert_pem],
        ids=["empty", "blank", "text", "certificate-only"],
    )
    def test_a_file_with_no_private_key_is_refused(self, pem: bytes) -> None:
        _refusal("key_missing", key_pem=pem)

    @pytest.mark.parametrize("label", ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"])
    def test_a_key_block_that_is_not_a_key_is_refused(self, label: str) -> None:
        corrupt = f"-----BEGIN {label}-----\nbm90IGEga2V5\n-----END {label}-----\n".encode()

        _refusal("key_unparseable", key_pem=corrupt)

    def test_two_private_keys_are_refused(self) -> None:
        issued = rsa_hierarchy().issue()

        _refusal("key_multiple", key_pem=issued.key_pem + key_pem_of(rsa_key()))

    def test_the_same_key_twice_is_still_refused(self) -> None:
        issued = rsa_hierarchy().issue()

        _refusal("key_multiple", key_pem=issued.key_pem + issued.key_pem)

    @pytest.mark.parametrize(
        "build",
        [
            lambda key: key_pem_of(key) + b"\n" + b"trailing text\n",
            lambda key: key_pem_of(key) + rsa_hierarchy().issue().cert_pem,
            lambda key: rsa_hierarchy().issue().cert_pem + key_pem_of(key),
        ],
        ids=["trailing-text", "key-then-certificate", "certificate-then-key"],
    )
    def test_a_key_file_with_anything_besides_the_one_key_is_refused(
        self, build: Callable[[PrivateKey], bytes]
    ) -> None:
        issued = rsa_hierarchy().issue()

        _refusal("key_unexpected_block", key_pem=build(issued.key))

    @pytest.mark.parametrize("fmt", ["encrypted", "encrypted-traditional"])
    def test_an_encrypted_key_is_refused(self, fmt: str) -> None:
        issued = rsa_hierarchy().issue()

        _refusal("key_encrypted", key_pem=key_pem_of(issued.key, fmt))  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "make_key",
        [
            lambda: rsa_key(1024),
            lambda: rsa_key(2047),
            lambda: ec_key(ec.SECP521R1()),
            lambda: ec_key(ec.SECP256K1()),
            ed25519_key,
        ],
        ids=["rsa-1024", "rsa-2047", "ec-p521", "ec-secp256k1", "ed25519"],
    )
    def test_a_key_type_outside_ec_p256_p384_or_rsa_2048_up_is_refused(
        self, make_key: Callable[[], PrivateKey]
    ) -> None:
        """The certificate carries the matching public key, so only the key type is at fault."""
        key = make_key()
        issued = rsa_hierarchy().issue(key=key)

        _refusal("key_unsupported", cert_pem=issued.cert_pem, key_pem=key_pem_of(key))

    @pytest.mark.parametrize(
        "other",
        [other_hierarchy().leaf_key, ecdsa_hierarchy().leaf_key],
        ids=["another-rsa-key", "an-ec-key"],
    )
    def test_a_key_that_does_not_match_the_leaf_is_refused(self, other: PrivateKey) -> None:
        _refusal("key_mismatch", key_pem=key_pem_of(other))

    def test_a_leaf_key_matching_a_different_certificate_in_the_chain_is_still_a_mismatch(
        self,
    ) -> None:
        """The key must match the *leaf*, not merely some certificate in the file."""
        hierarchy = rsa_hierarchy()
        issued = hierarchy.issue()
        issuer_key = hierarchy.issuer_key
        assert issued.cert.public_key() != issuer_key.public_key()

        _refusal("key_mismatch", key_pem=key_pem_of(issuer_key))


class TestLeafRefusals:
    def test_a_leaf_that_is_a_ca_is_refused(self, hierarchy: Hierarchy) -> None:
        _refusal("leaf_is_ca", hierarchy, basic_constraints="ca")

    def test_a_leaf_without_extended_key_usage_is_refused(self, hierarchy: Hierarchy) -> None:
        _refusal("leaf_no_server_auth", hierarchy, eku=None)

    @pytest.mark.parametrize(
        "eku",
        [
            (ExtendedKeyUsageOID.CLIENT_AUTH,),
            (ExtendedKeyUsageOID.CODE_SIGNING, ExtendedKeyUsageOID.EMAIL_PROTECTION),
            (x509.ObjectIdentifier("2.5.29.37.0"),),
        ],
        ids=["client-auth", "code-signing-and-email", "any-extended-key-usage"],
    )
    def test_extended_key_usage_without_server_auth_is_refused(
        self, eku: tuple[x509.ObjectIdentifier, ...]
    ) -> None:
        _refusal("leaf_no_server_auth", eku=eku)

    def test_an_expired_leaf_is_refused(self, hierarchy: Hierarchy) -> None:
        _refusal("leaf_expired", hierarchy, not_before=NOW - 90 * DAY, not_after=NOW - 1 * DAY)

    def test_a_leaf_one_second_past_its_not_after_is_refused(self) -> None:
        not_after = NOW + 10 * DAY

        _refusal(
            "leaf_expired",
            not_before=NOW - 80 * DAY,
            not_after=not_after,
            now_offset=timedelta(days=10, seconds=1),
        )

    def test_a_leaf_that_is_not_yet_valid_is_refused(self, hierarchy: Hierarchy) -> None:
        _refusal(
            "leaf_not_yet_valid", hierarchy, not_before=NOW + 1 * DAY, not_after=NOW + 91 * DAY
        )

    def test_a_leaf_one_second_before_its_not_before_is_refused(self) -> None:
        _refusal(
            "leaf_not_yet_valid",
            not_before=NOW + 1 * DAY,
            not_after=NOW + 91 * DAY,
            now_offset=timedelta(days=1, seconds=-1),
        )


class TestSanRefusals:
    def test_a_leaf_without_any_san_extension_is_refused(self) -> None:
        error = _refusal("san_missing_name", dns=[], names=[WILDCARD])

        assert WILDCARD in str(error)

    def test_a_declared_name_missing_from_the_sans_is_refused_and_named(self) -> None:
        error = _refusal("san_missing_name", dns=[f"a.{ZONE}"], names=[f"a.{ZONE}", f"b.{ZONE}"])

        assert f"b.{ZONE}" in str(error)

    def test_a_declared_wildcard_is_not_covered_by_concrete_sans(self) -> None:
        _refusal("san_missing_name", dns=[f"a.{ZONE}", f"b.{ZONE}"], names=[WILDCARD])

    def test_a_wildcard_san_covers_only_one_label(self) -> None:
        """`*.zone` does not cover `a.b.zone` (Go's VerifyHostname, as in the seed rules)."""
        _refusal("san_missing_name", dns=[WILDCARD], names=[f"a.b.{ZONE}"])

    def test_a_declared_wildcard_is_not_covered_by_a_wider_wildcard_san(self) -> None:
        """Wildcard-for-wildcard is an exact string match, not a containment test."""
        _refusal("san_missing_name", dns=[WILDCARD], names=[f"*.sub.{ZONE}"])

    @pytest.mark.parametrize(
        "extra",
        ["evil.example.org", "*.example.org", f"evil-{ZONE}", f"{ZONE}.evil.org"],
        ids=["other-domain", "other-wildcard", "no-label-boundary", "zone-as-prefix"],
    )
    def test_a_dns_san_outside_every_zone_is_refused_and_named(self, extra: str) -> None:
        error = _refusal("san_outside_zone", dns=[WILDCARD, extra], names=[WILDCARD])

        assert extra in str(error)

    def test_a_wildcard_san_whose_parent_is_above_the_zone_is_refused(self) -> None:
        """`*.example.com` also matches `x.example.com`, outside zone `rig.example.com`."""
        error = _refusal(
            "san_outside_zone",
            zones=[f"rig.{ZONE}"],
            dns=[WILDCARD],
            names=[f"rig.{ZONE}"],
        )

        assert WILDCARD in str(error)

    @pytest.mark.parametrize("ip", ["192.0.2.10", "2001:db8::1"])
    def test_an_ip_san_is_refused_and_named(self, ip: str) -> None:
        error = _refusal("san_ip", dns=[WILDCARD], ips=[ip], names=[WILDCARD])

        assert ip in str(error)


class TestChainRefusals:
    def test_a_chain_to_a_different_root_is_refused(self, hierarchy: Hierarchy) -> None:
        _refusal("chain", hierarchy, root=other_hierarchy().root)

    def test_a_chain_to_a_root_with_the_same_subject_but_other_keys_is_refused(self) -> None:
        _refusal("chain", rsa_hierarchy(), root=impostor_hierarchy().root)

    def test_a_leaf_signed_under_a_different_hierarchy_is_refused_against_the_registered_root(
        self,
    ) -> None:
        _refusal("chain", other_hierarchy(), root=rsa_hierarchy().root)

    def test_a_missing_intermediate_is_refused(self) -> None:
        issued = rsa_hierarchy().issue()

        _refusal("chain", cert_pem=pem_of(issued.cert))

    @pytest.mark.parametrize("dropped", [1, 2], ids=["no-root-ye-cross", "no-x2-cross"])
    def test_a_missing_cross_signed_link_in_the_ecdsa_chain_is_refused(self, dropped: int) -> None:
        hierarchy = ecdsa_hierarchy()
        issued = hierarchy.issue()
        served = [c for i, c in enumerate(issued.intermediates) if i != dropped]

        _refusal("chain", hierarchy, cert_pem=pem_of(issued.cert, *served))

    def test_an_expired_intermediate_is_refused_as_a_chain_failure(self) -> None:
        _refusal("chain", expired_intermediate_hierarchy())

    def test_the_verifier_error_is_the_cause_and_its_text_is_in_the_message(self) -> None:
        error = _refusal("chain", rsa_hierarchy(), root=other_hierarchy().root)

        assert isinstance(error.__cause__, VerificationError)
        assert str(error.__cause__) in str(error)

    def test_every_declared_name_is_verified_against_the_chain(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`verify_chain` runs once per declared name, wildcards passed as declared."""
        real = public.verify_chain
        seen: list[str] = []

        def spy(
            leaf: x509.Certificate,
            intermediates: Sequence[x509.Certificate],
            root: x509.Certificate,
            name: str,
            now: datetime,
        ) -> list[x509.Certificate]:
            seen.append(name)
            return real(leaf, intermediates, root, name, now)

        monkeypatch.setattr(public, "verify_chain", spy)
        declared_names = [WILDCARD, ZONE, f"apex-alias.{ZONE}"]

        material = _validate(
            ecdsa_hierarchy(),
            dns=[WILDCARD, f"apex-alias.{ZONE}", ZONE],
            names=declared_names,
        )

        assert material.state == PublicCertState.OK
        assert sorted(seen) == sorted(declared_names)

    def test_a_chain_failure_for_any_declared_name_refuses_the_certificate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The second declared name failing verification is enough to refuse."""
        real = public.verify_chain

        def fail_for_apex(
            leaf: x509.Certificate,
            intermediates: Sequence[x509.Certificate],
            root: x509.Certificate,
            name: str,
            now: datetime,
        ) -> list[x509.Certificate]:
            if name == ZONE:
                raise VerificationError("simulated path failure for the apex")
            return real(leaf, intermediates, root, name, now)

        monkeypatch.setattr(public, "verify_chain", fail_for_apex)

        error = _refusal("chain", dns=[WILDCARD, ZONE], names=[WILDCARD, ZONE])

        assert "simulated path failure" in str(error)


class TestExpiryState:
    """Ok until less than one third of the lifetime remains, then expiring."""

    LIFETIME = 90 * DAY

    def _state(self, now_offset: timedelta, *, lifetime: timedelta = LIFETIME) -> PublicCertState:
        return _validate(
            not_before=NOW,
            not_after=NOW + lifetime,
            now_offset=now_offset,
        ).state

    def test_a_fresh_certificate_is_ok(self) -> None:
        assert self._state(timedelta(0)) == PublicCertState.OK

    def test_exactly_one_third_remaining_is_still_ok(self) -> None:
        assert self._state(self.LIFETIME - self.LIFETIME / 3) == PublicCertState.OK

    def test_one_second_under_a_third_remaining_is_expiring(self) -> None:
        offset = self.LIFETIME - self.LIFETIME / 3 + timedelta(seconds=1)

        assert self._state(offset) == PublicCertState.EXPIRING

    def test_a_certificate_a_day_from_its_end_is_expiring(self) -> None:
        assert self._state(self.LIFETIME - 1 * DAY) == PublicCertState.EXPIRING

    def test_the_threshold_scales_with_the_lifetime(self) -> None:
        """A 6-day certificate expires at 2 days remaining, not at a fixed 14 days."""
        short = 6 * DAY

        assert self._state(4 * DAY, lifetime=short) == PublicCertState.OK
        assert self._state(4 * DAY + timedelta(seconds=1), lifetime=short) == "expiring"

    def test_the_threshold_is_a_third_of_the_lifetime_for_long_lifetimes_too(self) -> None:
        """200-day lifetime: a third is 66.7 days, so 100 days remaining is ok, 60 is not."""
        lifetime = 200 * DAY

        assert self._state(100 * DAY, lifetime=lifetime) == PublicCertState.OK
        assert self._state(140 * DAY, lifetime=lifetime) == PublicCertState.EXPIRING

    def test_an_expiring_certificate_is_still_returned_not_refused(self) -> None:
        material = _validate(
            not_before=NOW, not_after=NOW + self.LIFETIME, now_offset=self.LIFETIME - 1 * DAY
        )

        assert material.not_after == NOW + self.LIFETIME
        assert material.state == "expiring"


def _leak_scenarios() -> dict[str, tuple[str, dict[str, object]]]:
    """name -> (expected check, `_validate` overrides) for inputs that carry key/PEM text."""
    hierarchy = rsa_hierarchy()
    issued = hierarchy.issue()
    weak = rsa_key(1024)
    weak_issued = hierarchy.issue(key=weak)
    return {
        "key-mismatch": ("key_mismatch", {"key_pem": key_pem_of(other_hierarchy().leaf_key)}),
        "encrypted-key": ("key_encrypted", {"key_pem": key_pem_of(issued.key, "encrypted")}),
        "weak-key": (
            "key_unsupported",
            {"cert_pem": weak_issued.cert_pem, "key_pem": key_pem_of(weak)},
        ),
        "two-keys": ("key_multiple", {"key_pem": issued.key_pem + key_pem_of(rsa_key())}),
        "key-in-cert-file": (
            "cert_unexpected_block",
            {"cert_pem": issued.cert_pem + issued.key_pem},
        ),
        "certificate-in-key-file": (
            "key_unexpected_block",
            {"key_pem": issued.key_pem + issued.cert_pem},
        ),
        "chain": ("chain", {"root": other_hierarchy().root}),
        "garbage-cert": (
            "cert_unparseable",
            {
                "cert_pem": BAD_DER_CERTIFICATE,
            },
        ),
    }


LEAK_SCENARIOS = [
    "key-mismatch",
    "encrypted-key",
    "weak-key",
    "two-keys",
    "key-in-cert-file",
    "certificate-in-key-file",
    "chain",
    "garbage-cert",
]


class TestNoSecretsInDiagnostics:
    """Messages and logs name the certificate, file and property, never PEM or key bytes."""

    @pytest.mark.parametrize("scenario", LEAK_SCENARIOS)
    def test_error_text_cause_chain_and_logs_hold_no_pem_or_key_bytes(
        self, scenario: str, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        check, kwargs = _leak_scenarios()[scenario]
        issued = rsa_hierarchy().issue()
        cert_pem = kwargs.get("cert_pem", issued.cert_pem)
        key_pem = kwargs.get("key_pem", issued.key_pem)
        assert isinstance(cert_pem, bytes)
        assert isinstance(key_pem, bytes)
        fragments = pem_bodies(cert_pem, key_pem, issued.key_pem, issued.cert_pem)
        assert fragments, "the scenario must have PEM bodies to look for"

        with caplog.at_level("DEBUG"):
            error = _refusal(check, **kwargs)

        texts = [str(error), repr(error), *(str(arg) for arg in error.args)]
        link: BaseException | None = error
        while link is not None:
            texts += [str(link), repr(link)]
            link = link.__cause__ or link.__context__
        captured = capsys.readouterr()
        haystack = "\n".join([*texts, caplog.text, captured.out, captured.err])
        for fragment in fragments:
            assert fragment not in haystack

    def test_a_password_protected_key_does_not_leak_its_password(self) -> None:
        issued = rsa_hierarchy().issue()

        error = _refusal("key_encrypted", key_pem=key_pem_of(issued.key, "encrypted", b"s3cret-pw"))

        assert "s3cret-pw" not in str(error)
        assert "s3cret-pw" not in repr(error)

    def test_a_successful_validation_logs_no_pem_or_key_bytes(
        self, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        issued = rsa_hierarchy().issue()
        fragments = pem_bodies(issued.cert_pem, issued.key_pem)

        with caplog.at_level("DEBUG"):
            _validate(rsa_hierarchy())

        captured = capsys.readouterr()
        haystack = caplog.text + captured.out + captured.err
        assert all(fragment not in haystack for fragment in fragments)

    def test_the_error_exposes_the_certificate_file_and_check(self) -> None:
        error = _refusal("key_mismatch", key_pem=key_pem_of(other_hierarchy().leaf_key))

        assert isinstance(error, Exception)
        assert (error.certificate, error.file, error.check) == (
            CERT_NAME,
            "key_file",
            "key_mismatch",
        )


class TestReExport:
    def test_covering_certificate_is_the_tlsnames_function(self) -> None:
        assert public.covering_certificate is tlsnames.covering_certificate

    def test_the_public_module_exports_the_pinned_names(self) -> None:
        for name in (
            "KNOWN_ROOTS",
            "SYSTEM_TRUST_STORE",
            "PublicCertState",
            "PublicMaterial",
            "PublicMaterialError",
            "RegisteredRootError",
            "resolve_registered_root",
            "validate_public_material",
            "verify_chain",
            "covering_certificate",
            "leaf_dns_sans",
            "read_installed_public_material",
        ):
            assert hasattr(public, name), name
            assert name in public.__all__, name


def _validate_without_root(
    issued_by: Hierarchy | None = None,
    *,
    dns: Iterable[str] = (WILDCARD,),
    names: Iterable[str] = (WILDCARD,),
    zones: Iterable[str] = ZONES,
    now_offset: timedelta = timedelta(0),
    cert_pem: bytes | None = None,
    key_pem: bytes | None = None,
    **issue_options: object,
) -> PublicMaterial:
    """Issue a leaf and run the staging (root-less) validator on it."""
    hierarchy = issued_by or rsa_hierarchy()
    issued = hierarchy.issue(list(dns), **issue_options)  # type: ignore[arg-type]
    return validate_public_material_without_root(
        declared(list(names), CERT_NAME),
        issued.cert_pem if cert_pem is None else cert_pem,
        issued.key_pem if key_pem is None else key_pem,
        zones=list(zones),
        now=NOW + now_offset,
    )


class TestWithoutRoot:
    """Staging dry run: every check but the path to the registered root."""

    def test_a_chain_to_a_root_nobody_registered_is_accepted(self, hierarchy: Hierarchy) -> None:
        """No root is offered, so a staging chain is not checked against anything."""
        issued = hierarchy.issue()

        material = validate_public_material_without_root(
            declared(), issued.cert_pem, issued.key_pem, zones=ZONES, now=NOW
        )

        assert material.fingerprint == fingerprint(issued.cert)
        assert material.state == PublicCertState.OK

    def test_material_from_an_unrelated_hierarchy_is_accepted(self) -> None:
        """Staging roots are untrusted by design; the chain's origin is not examined."""
        assert _validate_without_root(other_hierarchy()).state == PublicCertState.OK

    def test_the_same_material_is_refused_by_the_rooted_validator_against_another_root(
        self,
    ) -> None:
        """Contrast: what the root-less validator skips, `validate_public_material` enforces."""
        issued = other_hierarchy().issue()

        accepted = validate_public_material_without_root(
            declared(), issued.cert_pem, issued.key_pem, zones=ZONES, now=NOW
        )
        with pytest.raises(PublicMaterialError) as excinfo:
            validate_public_material(
                declared(),
                issued.cert_pem,
                issued.key_pem,
                zones=ZONES,
                root=rsa_hierarchy().root,
                now=NOW,
            )

        assert accepted.fingerprint == fingerprint(issued.cert)
        assert excinfo.value.check == "chain"

    def test_a_chain_without_its_intermediates_is_accepted(self) -> None:
        issued = rsa_hierarchy().issue()

        material = _validate_without_root(cert_pem=pem_of(issued.cert))

        assert len(material.chain) == 1

    def test_a_leaf_only_file_is_a_chain_failure_for_the_rooted_validator_only(self) -> None:
        leaf_only = pem_of(rsa_hierarchy().issue().cert)

        _refusal("chain", cert_pem=leaf_only)

        assert _validate_without_root(cert_pem=leaf_only).chain

    def test_an_expired_intermediate_is_not_examined(self) -> None:
        """Chain validity (including intermediates) belongs to the skipped check."""
        material = _validate_without_root(expired_intermediate_hierarchy())

        assert material.state == PublicCertState.OK

    def test_the_chain_is_returned_as_supplied_leaf_first(self, hierarchy: Hierarchy) -> None:
        issued = hierarchy.issue()

        material = _validate_without_root(hierarchy)

        assert material.chain[0].subject == issued.cert.subject
        assert [c.subject for c in material.chain[1:]] == [
            c.subject for c in hierarchy.intermediates
        ]

    def test_validity_comes_from_the_leaf(self) -> None:
        material = _validate_without_root(not_before=NOW, not_after=NOW + 90 * DAY)

        assert material.not_before == NOW
        assert material.not_after == NOW + 90 * DAY
        assert material.not_before.tzinfo is not None

    def test_a_leaf_with_under_a_third_of_its_lifetime_left_is_expiring_not_refused(self) -> None:
        material = _validate_without_root(
            not_before=NOW, not_after=NOW + 90 * DAY, now_offset=89 * DAY
        )

        assert material.state == PublicCertState.EXPIRING

    def test_zones_may_be_a_one_shot_iterable(self) -> None:
        issued = rsa_hierarchy().issue()

        material = validate_public_material_without_root(
            declared(), issued.cert_pem, issued.key_pem, zones=(z for z in ZONES), now=NOW
        )

        assert material.state == PublicCertState.OK

    def test_the_two_validators_differ_in_their_root_parameter(self) -> None:
        issued = rsa_hierarchy().issue()

        with pytest.raises(TypeError):
            validate_public_material(  # type: ignore[call-arg]
                declared(), issued.cert_pem, issued.key_pem, zones=ZONES, now=NOW
            )
        with pytest.raises(TypeError):
            validate_public_material_without_root(  # type: ignore[call-arg]
                declared(),
                issued.cert_pem,
                issued.key_pem,
                zones=ZONES,
                now=NOW,
                root=rsa_hierarchy().root,
            )


# case -> (expected check, overrides for `_validate` and `_validate_without_root`)
_PROFILE_REFUSALS: dict[str, tuple[str, dict[str, object]]] = {
    "ca-leaf": ("leaf_is_ca", {"basic_constraints": "ca"}),
    "no-eku": ("leaf_no_server_auth", {"eku": None}),
    "client-auth-only": ("leaf_no_server_auth", {"eku": (ExtendedKeyUsageOID.CLIENT_AUTH,)}),
    "expired": ("leaf_expired", {"not_before": NOW - 90 * DAY, "not_after": NOW - 1 * DAY}),
    "not-yet-valid": (
        "leaf_not_yet_valid",
        {"not_before": NOW + 1 * DAY, "not_after": NOW + 91 * DAY},
    ),
    "san-outside-zone": ("san_outside_zone", {"dns": [WILDCARD, "evil.example.org"]}),
    "san-ip": ("san_ip", {"ips": ["192.0.2.10"]}),
    "no-san": ("san_missing_name", {"dns": []}),
    "declared-name-uncovered": (
        "san_missing_name",
        {"dns": [f"a.{ZONE}"], "names": [f"a.{ZONE}", f"b.{ZONE}"]},
    ),
    "wildcard-declared-concrete-san": (
        "san_missing_name",
        {"dns": [f"a.{ZONE}", f"b.{ZONE}"], "names": [WILDCARD]},
    ),
    "outside-configured-zone": (
        "san_outside_zone",
        {"zones": [f"rig.{ZONE}"], "names": [f"rig.{ZONE}"]},
    ),
    "key-mismatch": ("key_mismatch", {"key_pem": key_pem_of(other_hierarchy().leaf_key)}),
    "key-encrypted": (
        "key_encrypted",
        {"key_pem": key_pem_of(rsa_hierarchy().leaf_key, "encrypted")},
    ),
    "key-missing": ("key_missing", {"key_pem": b"not a key\n"}),
    "cert-empty": ("cert_empty", {"cert_pem": b""}),
    "cert-unparseable": ("cert_unparseable", {"cert_pem": BAD_DER_CERTIFICATE}),
    "cert-extra-block": (
        "cert_unexpected_block",
        {"cert_pem": rsa_hierarchy().issue().cert_pem + CSR_BLOCK},
    ),
}


class TestWithoutRootStillEnforces:
    """Everything except the chain check runs exactly as in `validate_public_material`."""

    @pytest.mark.parametrize("case", list(_PROFILE_REFUSALS))
    def test_each_refusal_matches_the_rooted_validator(self, case: str) -> None:
        check, overrides = _PROFILE_REFUSALS[case]

        with pytest.raises(PublicMaterialError) as rooted:
            _validate(**overrides)  # type: ignore[arg-type]
        with pytest.raises(PublicMaterialError) as rootless:
            _validate_without_root(**overrides)  # type: ignore[arg-type]

        assert rooted.value.check == check
        assert rootless.value.check == check
        assert rootless.value.file == rooted.value.file
        assert str(rootless.value) == str(rooted.value)

    @pytest.mark.parametrize("case", list(_PROFILE_REFUSALS))
    def test_each_refusal_names_the_certificate_file_and_property(self, case: str) -> None:
        check, overrides = _PROFILE_REFUSALS[case]
        file, prop = PROPERTIES[check]

        with pytest.raises(PublicMaterialError) as excinfo:
            _validate_without_root(**overrides)  # type: ignore[arg-type]

        message = str(excinfo.value)
        assert CERT_NAME in message
        assert file in message
        assert prop in message

    def test_a_leaf_one_second_past_its_not_after_is_refused(self) -> None:
        with pytest.raises(PublicMaterialError) as excinfo:
            _validate_without_root(
                not_before=NOW - 80 * DAY,
                not_after=NOW + 10 * DAY,
                now_offset=timedelta(days=10, seconds=1),
            )

        assert excinfo.value.check == "leaf_expired"

    def test_a_leaf_that_is_a_ca_is_refused_even_though_its_chain_is_not_checked(self) -> None:
        with pytest.raises(PublicMaterialError) as excinfo:
            _validate_without_root(other_hierarchy(), basic_constraints="ca")

        assert excinfo.value.check == "leaf_is_ca"

    def test_a_foreign_chain_does_not_hide_a_leaf_problem(self) -> None:
        with pytest.raises(PublicMaterialError) as excinfo:
            _validate_without_root(other_hierarchy(), eku=None)

        assert excinfo.value.check == "leaf_no_server_auth"

    def test_a_refusal_carries_no_pem_or_key_text(self) -> None:
        issued = rsa_hierarchy().issue()
        bodies = pem_bodies(issued.cert_pem, issued.key_pem)
        assert bodies

        with pytest.raises(PublicMaterialError) as excinfo:
            _validate_without_root(cert_pem=issued.cert_pem + CSR_BLOCK, key_pem=issued.key_pem)

        assert not any(body in str(excinfo.value) for body in bodies)


class TestRootedValidatorUnchanged:
    def test_a_valid_chain_is_accepted_and_returned_as_supplied(self, hierarchy: Hierarchy) -> None:
        issued = hierarchy.issue()

        material = validate_public_material(
            declared(),
            issued.cert_pem,
            issued.key_pem,
            zones=ZONES,
            root=hierarchy.root,
            now=NOW,
        )

        assert material.fingerprint == fingerprint(issued.cert)
        assert material.chain == issued.chain

    @pytest.mark.parametrize(
        "overrides",
        [
            {"root": other_hierarchy().root},
            {"root": impostor_hierarchy().root},
            {"cert_pem": pem_of(rsa_hierarchy().issue().cert)},
        ],
        ids=["other-root", "impostor-root", "missing-intermediate"],
    )
    def test_it_still_refuses_what_only_the_chain_check_catches(
        self, overrides: dict[str, object]
    ) -> None:
        _refusal("chain", **overrides)

    def test_it_still_refuses_an_expired_intermediate(self) -> None:
        _refusal("chain", expired_intermediate_hierarchy())


class TestRootIsRequired:
    """``validate_public_material`` never skips the chain check; only the root-less one may."""

    def test_a_none_root_is_a_type_error_naming_the_staging_entry_point(self) -> None:
        issued = rsa_hierarchy().issue()

        with pytest.raises(TypeError, match="validate_public_material_without_root"):
            validate_public_material(
                declared(),
                issued.cert_pem,
                issued.key_pem,
                zones=ZONES,
                root=None,  # type: ignore[arg-type]
                now=NOW,
            )

    def test_the_type_error_comes_before_any_material_is_examined(self) -> None:
        """Garbage input with no root is a programming error, not a refusal of the material."""
        with pytest.raises(TypeError):
            validate_public_material(
                declared(),
                b"",
                b"",
                zones=ZONES,
                root=None,  # type: ignore[arg-type]
                now=NOW,
            )

    def test_a_none_root_never_degrades_to_the_rootless_result(self) -> None:
        issued = other_hierarchy().issue()  # would pass without a root, fails the chain check

        with pytest.raises(TypeError):
            validate_public_material(
                declared(),
                issued.cert_pem,
                issued.key_pem,
                zones=ZONES,
                root=None,  # type: ignore[arg-type]
                now=NOW,
            )
        assert validate_public_material_without_root(
            declared(), issued.cert_pem, issued.key_pem, zones=ZONES, now=NOW
        ).fingerprint == fingerprint(issued.cert)


class TestUnsupportedAlgorithms:
    """An algorithm this build cannot read is a refusal naming the file, not a crash."""

    @staticmethod
    def _raise_unsupported(*_args: object, **_kwargs: object) -> None:
        raise UnsupportedAlgorithm("secret-looking provider detail")

    @pytest.mark.parametrize("rooted", [True, False], ids=["rooted", "rootless"])
    def test_an_unreadable_certificate_algorithm_is_cert_unreadable(
        self, monkeypatch: pytest.MonkeyPatch, rooted: bool
    ) -> None:
        monkeypatch.setattr(public.x509, "load_pem_x509_certificate", self._raise_unsupported)

        with pytest.raises(PublicMaterialError) as excinfo:
            if rooted:
                _validate()
            else:
                _validate_without_root()

        error = excinfo.value
        assert (error.check, error.file, error.certificate) == (
            "cert_unreadable",
            "cert_file",
            CERT_NAME,
        )
        assert "cert_file" in str(error) and "read" in str(error)
        assert "secret-looking" not in str(error)

    @pytest.mark.parametrize("rooted", [True, False], ids=["rooted", "rootless"])
    def test_an_unreadable_key_algorithm_is_key_unreadable(
        self, monkeypatch: pytest.MonkeyPatch, rooted: bool
    ) -> None:
        monkeypatch.setattr(public.serialization, "load_pem_private_key", self._raise_unsupported)

        with pytest.raises(PublicMaterialError) as excinfo:
            if rooted:
                _validate()
            else:
                _validate_without_root()

        error = excinfo.value
        assert (error.check, error.file, error.certificate) == (
            "key_unreadable",
            "key_file",
            CERT_NAME,
        )
        assert "key_file" in str(error) and "read" in str(error)
        assert "secret-looking" not in str(error)


class TestLeafDnsSans:
    def test_the_dns_names_of_the_validated_leaf_are_returned_lowercased(self) -> None:
        issued = rsa_hierarchy().issue([f"A.{ZONE.upper()}", f"b.{ZONE}"])
        material = validate_public_material_without_root(
            declared([f"a.{ZONE}", f"b.{ZONE}"], CERT_NAME),
            issued.cert_pem,
            issued.key_pem,
            zones=ZONES,
            now=NOW,
        )

        assert leaf_dns_sans(material) == [f"a.{ZONE}", f"b.{ZONE}"]

    def test_a_leaf_without_a_san_extension_has_none(self) -> None:
        issued = rsa_hierarchy().issue([])
        material = PublicMaterial(
            not_before=issued.cert.not_valid_before_utc,
            not_after=issued.cert.not_valid_after_utc,
            chain=issued.chain,
            fingerprint=fingerprint(issued.cert),
            state=PublicCertState.OK,
        )

        assert leaf_dns_sans(material) == []

    def test_it_reads_the_leaf_not_the_intermediates(self) -> None:
        issued = rsa_hierarchy().issue([f"a.{ZONE}"])
        material = validate_public_material(
            declared([f"a.{ZONE}"], CERT_NAME),
            issued.cert_pem,
            issued.key_pem,
            zones=ZONES,
            root=rsa_hierarchy().root,
            now=NOW,
        )

        assert len(material.chain) > 1
        assert leaf_dns_sans(material) == [f"a.{ZONE}"]
