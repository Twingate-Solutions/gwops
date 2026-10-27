"""Tests for gwops.tlsnames: pure certificate-name matching shared by the seed rules,
material validation and the status/readiness code.
"""

import pytest

from gwops.configmodel.schema import FilePublicCertificate
from gwops.tlsnames import covering_certificate, name_matches


class TestNameMatchesExact:
    def test_an_identical_name_matches(self) -> None:
        assert name_matches("app.a.com", "app.a.com") is True

    def test_a_different_name_does_not_match(self) -> None:
        assert name_matches("app.a.com", "other.a.com") is False

    @pytest.mark.parametrize(
        ("pattern", "name"),
        [("APP.A.COM", "app.a.com"), ("app.a.com", "App.A.Com"), ("*.A.com", "X.a.COM")],
    )
    def test_matching_is_case_insensitive(self, pattern: str, name: str) -> None:
        assert name_matches(pattern, name) is True

    def test_a_suffix_is_not_a_match(self) -> None:
        """`app.a.com` is not a match for `pp.a.com` or `xapp.a.com` (label boundaries)."""
        assert name_matches("app.a.com", "xapp.a.com") is False
        assert name_matches("xapp.a.com", "app.a.com") is False

    @pytest.mark.parametrize(("pattern", "name"), [("", ""), ("", "a.com"), ("a.com", "")])
    def test_an_empty_side_never_matches(self, pattern: str, name: str) -> None:
        assert name_matches(pattern, name) is False


class TestNameMatchesWildcard:
    """Go `crypto/x509` `VerifyHostname`: leftmost label exactly `*`, one label."""

    def test_a_wildcard_matches_exactly_one_label(self) -> None:
        assert name_matches("*.a.com", "x.a.com") is True

    def test_a_wildcard_does_not_match_the_bare_parent(self) -> None:
        assert name_matches("*.a.com", "a.com") is False

    def test_a_wildcard_does_not_match_two_labels(self) -> None:
        assert name_matches("*.a.com", "x.y.a.com") is False

    def test_a_wildcard_does_not_match_an_empty_label(self) -> None:
        assert name_matches("*.a.com", ".a.com") is False

    def test_a_wildcard_does_not_match_a_different_parent(self) -> None:
        assert name_matches("*.a.com", "x.b.com") is False
        assert name_matches("*.a.com", "x.xa.com") is False

    @pytest.mark.parametrize(
        ("pattern", "name"),
        [
            ("f*.a.com", "foo.a.com"),
            ("*o.a.com", "foo.a.com"),
            ("f*o.a.com", "foo.a.com"),
            ("f*.a.com", "f.a.com"),
            ("**.a.com", "x.a.com"),
        ],
    )
    def test_a_partial_wildcard_label_matches_nothing(self, pattern: str, name: str) -> None:
        assert name_matches(pattern, name) is False

    @pytest.mark.parametrize(
        ("pattern", "name"),
        [
            ("a.*.com", "a.x.com"),
            ("a.b.*", "a.b.c"),
            ("*.*.com", "x.y.com"),
            ("x.*.a.com", "x.y.a.com"),
        ],
    )
    def test_a_wildcard_that_is_not_leftmost_matches_nothing(
        self, pattern: str, name: str
    ) -> None:
        assert name_matches(pattern, name) is False

    def test_the_wildcard_is_the_pattern_not_the_name(self) -> None:
        """A literal `*` label in the name is not matched by a concrete pattern."""
        assert name_matches("x.a.com", "*.a.com") is False


def _cert(name: str, *names: str) -> FilePublicCertificate:
    return FilePublicCertificate(
        name=name,
        names=list(names),
        source="file",
        cert_file=f"/config/public-tls/{name}/fullchain.pem",
        key_file=f"/config/public-tls/{name}/privkey.pem",
    )


class TestCoveringCertificate:
    def test_the_certificate_whose_names_match_is_returned(self) -> None:
        wildcard = _cert("wild", "*.a.com")
        other = _cert("other", "*.b.com")
        assert covering_certificate("x.a.com", [wildcard, other]) is wildcard
        assert covering_certificate("x.b.com", [wildcard, other]) is other

    def test_a_name_no_certificate_covers_is_none(self) -> None:
        certs = [_cert("wild", "*.a.com")]
        assert covering_certificate("x.c.com", certs) is None

    def test_no_certificates_cover_nothing(self) -> None:
        assert covering_certificate("x.a.com", []) is None

    def test_a_wildcard_certificate_does_not_cover_the_apex_or_two_labels(self) -> None:
        certs = [_cert("wild", "*.a.com")]
        assert covering_certificate("a.com", certs) is None
        assert covering_certificate("x.y.a.com", certs) is None

    def test_any_of_a_certificates_names_can_cover(self) -> None:
        both = _cert("both", "a.com", "*.a.com")
        assert covering_certificate("a.com", [both]) is both
        assert covering_certificate("x.a.com", [both]) is both

    def test_a_concrete_name_is_covered_by_its_certificate(self) -> None:
        api = _cert("api", "api.a.com")
        assert covering_certificate("api.a.com", [api]) is api
        assert covering_certificate("web.a.com", [api]) is None

    def test_the_lookup_is_case_insensitive(self) -> None:
        wild = _cert("wild", "*.a.com")
        assert covering_certificate("X.A.COM", [wild]) is wild
