"""Tests for ``gwops.certs.public.verify_chain``: path building only.

Signature::

    def verify_chain(
        leaf: x509.Certificate,
        intermediates: Sequence[x509.Certificate],
        root: x509.Certificate,
        name: str,
        now: datetime,
    ) -> list[x509.Certificate]

Builds a path from `leaf` through `intermediates` to `root` with
``cryptography.x509.verification.PolicyBuilder``: a store holding only `root`, validation
time `now`, server verification for `name`. A leading ``*.`` in `name` (a declared wildcard)
is replaced by a concrete label first. Returns the verified path, leaf first and `root` last;
raises ``cryptography.x509.verification.VerificationError`` unchanged when no path exists.
It does no leaf-profile checks (zones, SAN coverage, key): those belong to
``validate_public_material``, which calls it.

Captured real chains (certificates only, public data; no private key exists for them),
fetched 2026-10-19 over a TLS 1.3 handshake with Python's ``ssl`` (certificate verification
off, ``get_unverified_chain``) and re-encoded to PEM, root not served:

* ``le-ecdsa-letsencrypt.org-chain.pem``: ``letsencrypt.org`` served [leaf, YE2, Root YE,
  ISRG Root X2]. The ECDSA hierarchy; reaches ISRG Root X1 through two cross-signs.
  Leaf window 2026-09-04T14:34:32Z to 2026-12-03T14:34:31Z.
* ``le-rsa-community.letsencrypt.org-chain.pem``: ``community.letsencrypt.org`` served
  [leaf, YR2, Root YR]. Leaf window 2026-10-17T00:01:41Z to 2027-01-15T00:01:40Z.
* ``isrg-root-x1.pem``: ISRG Root X1 from ``https://letsencrypt.org/certs/isrgrootx1.pem``.

The fixed validation times below sit inside every certificate's window. Refreshing a
fixture means re-capturing, re-recording the windows here and picking a new ``now``.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.verification import VerificationError

from gwops.certs.public import verify_chain
from tests.public_chain_support import (
    NOW,
    ZONE,
    Hierarchy,
    ecdsa_hierarchy,
    expired_intermediate_hierarchy,
    impostor_hierarchy,
    other_hierarchy,
    rsa_hierarchy,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "tls"

ECDSA_CHAIN = FIXTURES / "le-ecdsa-letsencrypt.org-chain.pem"
RSA_CHAIN = FIXTURES / "le-rsa-community.letsencrypt.org-chain.pem"
ISRG_ROOT_X1 = FIXTURES / "isrg-root-x1.pem"


@dataclass(frozen=True)
class RealChain:
    """One captured chain and the facts recorded when it was captured."""

    path: Path
    count: int  # served certificates, leaf first
    name: str  # a DNS SAN of the leaf
    not_before: datetime  # leaf
    not_after: datetime  # leaf
    now: datetime  # fixed validation time inside every certificate's window


REAL_CHAINS = [
    pytest.param(
        RealChain(
            ECDSA_CHAIN,
            4,
            "letsencrypt.org",
            datetime(2026, 9, 4, 14, 34, 32, tzinfo=UTC),
            datetime(2026, 12, 3, 14, 34, 31, tzinfo=UTC),
            datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC),
        ),
        id="ecdsa-ye-via-x2-to-x1",
    ),
    pytest.param(
        RealChain(
            RSA_CHAIN,
            3,
            "community.letsencrypt.org",
            datetime(2026, 10, 17, 0, 1, 41, tzinfo=UTC),
            datetime(2027, 1, 15, 0, 1, 40, tzinfo=UTC),
            datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC),
        ),
        id="rsa-yr-to-x1",
    ),
]


def _load(path: Path) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(path.read_bytes())


def _real_root() -> x509.Certificate:
    return x509.load_pem_x509_certificate(ISRG_ROOT_X1.read_bytes())


@pytest.fixture(params=["rsa", "ecdsa"])
def hierarchy(request: pytest.FixtureRequest) -> Hierarchy:
    return rsa_hierarchy() if request.param == "rsa" else ecdsa_hierarchy()


class TestVerifyChainGenerated:
    def test_a_path_from_leaf_to_the_registered_root_is_returned(
        self, hierarchy: Hierarchy
    ) -> None:
        issued = hierarchy.issue([f"echo.{ZONE}"])

        path = verify_chain(issued.cert, issued.intermediates, hierarchy.root, f"echo.{ZONE}", NOW)

        assert path[0] == issued.cert
        assert path[-1] == hierarchy.root
        assert list(path[1:-1]) == list(issued.intermediates)

    def test_a_declared_wildcard_name_is_verified_with_a_concrete_label(
        self, hierarchy: Hierarchy
    ) -> None:
        issued = hierarchy.issue([f"*.{ZONE}"])

        path = verify_chain(issued.cert, issued.intermediates, hierarchy.root, f"*.{ZONE}", NOW)

        assert path[-1] == hierarchy.root

    def test_a_name_the_leaf_does_not_cover_is_refused(self, hierarchy: Hierarchy) -> None:
        issued = hierarchy.issue([f"echo.{ZONE}"])

        with pytest.raises(VerificationError):
            verify_chain(issued.cert, issued.intermediates, hierarchy.root, "echo.example.org", NOW)

    def test_a_different_root_is_refused(self, hierarchy: Hierarchy) -> None:
        issued = hierarchy.issue()

        with pytest.raises(VerificationError):
            verify_chain(
                issued.cert, issued.intermediates, other_hierarchy().root, f"*.{ZONE}", NOW
            )

    def test_a_root_with_the_same_subject_and_different_keys_is_refused(self) -> None:
        issued = rsa_hierarchy().issue()

        with pytest.raises(VerificationError):
            verify_chain(
                issued.cert, issued.intermediates, impostor_hierarchy().root, f"*.{ZONE}", NOW
            )

    def test_a_chain_missing_its_only_intermediate_is_refused(self) -> None:
        issued = rsa_hierarchy().issue()

        with pytest.raises(VerificationError):
            verify_chain(issued.cert, [], rsa_hierarchy().root, f"*.{ZONE}", NOW)

    @pytest.mark.parametrize("dropped", [1, 2], ids=["no-root-ye-cross", "no-x2-cross"])
    def test_an_ecdsa_chain_missing_a_cross_signed_link_is_refused(self, dropped: int) -> None:
        hierarchy = ecdsa_hierarchy()
        issued = hierarchy.issue()
        served = [c for i, c in enumerate(issued.intermediates) if i != dropped]
        assert len(served) == 2

        with pytest.raises(VerificationError):
            verify_chain(issued.cert, served, hierarchy.root, f"*.{ZONE}", NOW)

    def test_an_intermediate_from_an_unrelated_hierarchy_is_refused(self) -> None:
        issued = rsa_hierarchy().issue()

        with pytest.raises(VerificationError):
            verify_chain(
                issued.cert,
                other_hierarchy().intermediates,
                rsa_hierarchy().root,
                f"*.{ZONE}",
                NOW,
            )

    def test_an_expired_intermediate_is_refused(self) -> None:
        hierarchy = expired_intermediate_hierarchy()
        issued = hierarchy.issue()

        with pytest.raises(VerificationError):
            verify_chain(issued.cert, issued.intermediates, hierarchy.root, f"*.{ZONE}", NOW)

    def test_validation_uses_the_supplied_time_not_the_wall_clock(self) -> None:
        """A leaf valid only in the past verifies at a past `now` and fails at a later one."""
        hierarchy = rsa_hierarchy()
        long_ago = NOW - 400 * timedelta(days=1)
        issued = hierarchy.issue(not_before=long_ago, not_after=long_ago + timedelta(days=90))

        verify_chain(
            issued.cert,
            issued.intermediates,
            hierarchy.root,
            f"*.{ZONE}",
            long_ago + timedelta(days=1),
        )
        with pytest.raises(VerificationError):
            verify_chain(issued.cert, issued.intermediates, hierarchy.root, f"*.{ZONE}", NOW)


class TestVerifyChainRealLetsEncrypt:
    @pytest.mark.parametrize("chain", REAL_CHAINS)
    def test_the_fixture_is_the_recorded_capture(self, chain: RealChain) -> None:
        certs = _load(chain.path)

        assert len(certs) == chain.count
        assert certs[0].not_valid_before_utc == chain.not_before
        assert certs[0].not_valid_after_utc == chain.not_after
        sans = certs[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert chain.name in sans.get_values_for_type(x509.DNSName)
        assert chain.not_before < chain.now < chain.not_after

    @pytest.mark.parametrize("chain", REAL_CHAINS)
    def test_the_captured_chain_validates_against_the_committed_isrg_root_x1(
        self, chain: RealChain
    ) -> None:
        leaf, *intermediates = _load(chain.path)

        verified = verify_chain(leaf, intermediates, _real_root(), chain.name, chain.now)

        assert verified[0] == leaf
        assert verified[-1] == _real_root()
        assert list(verified[1:-1]) == intermediates

    @pytest.mark.parametrize("chain", REAL_CHAINS)
    def test_the_captured_chain_is_refused_after_the_leaf_expires(self, chain: RealChain) -> None:
        leaf, *intermediates = _load(chain.path)
        late = chain.not_after + timedelta(seconds=1)

        with pytest.raises(VerificationError):
            verify_chain(leaf, intermediates, _real_root(), chain.name, late)

    @pytest.mark.parametrize("chain", REAL_CHAINS)
    def test_the_captured_chain_is_refused_before_the_leaf_is_valid(self, chain: RealChain) -> None:
        leaf, *intermediates = _load(chain.path)
        early = chain.not_before - timedelta(seconds=1)

        with pytest.raises(VerificationError):
            verify_chain(leaf, intermediates, _real_root(), chain.name, early)

    @pytest.mark.parametrize("chain", REAL_CHAINS)
    def test_the_captured_chain_is_refused_against_any_other_root(self, chain: RealChain) -> None:
        leaf, *intermediates = _load(chain.path)

        with pytest.raises(VerificationError):
            verify_chain(leaf, intermediates, rsa_hierarchy().root, chain.name, chain.now)

    @pytest.mark.parametrize("chain", REAL_CHAINS)
    def test_the_captured_chain_is_refused_without_its_intermediates(
        self, chain: RealChain
    ) -> None:
        leaf, *_ = _load(chain.path)
        no_intermediates: Sequence[x509.Certificate] = []

        with pytest.raises(VerificationError):
            verify_chain(leaf, no_intermediates, _real_root(), chain.name, chain.now)

    def test_the_captured_ecdsa_chain_is_refused_without_its_cross_signed_x2(self) -> None:
        leaf, ye2, root_ye, _x2 = _load(ECDSA_CHAIN)

        with pytest.raises(VerificationError):
            verify_chain(
                leaf,
                [ye2, root_ye],
                _real_root(),
                "letsencrypt.org",
                datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC),
            )

    @pytest.mark.parametrize("chain", REAL_CHAINS)
    def test_the_captured_chain_is_refused_for_a_name_its_leaf_does_not_cover(
        self, chain: RealChain
    ) -> None:
        leaf, *intermediates = _load(chain.path)

        with pytest.raises(VerificationError):
            verify_chain(
                leaf, intermediates, _real_root(), "not-on-this-leaf.example.org", chain.now
            )
