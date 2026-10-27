"""CA suitability for the gateway's local issuer: what CertManager accepts today (mode off).

The mode-on refusals live in tests/supervisor/test_on_demand_ca.py (startup) and
tests/reconciler/test_on_demand.py (every pass). These tests pin the other side: the
gwops-generated CA meets the upstream issuer's rules, and the extra checks are not added
to `CertManager.ensure_x509_ca` when the mode is off.
"""

from pathlib import Path

import pytest
from cryptography import x509

from gwops.certs.manager import CertManager
from tests.on_demand_support import BasicConstraintsMode, KeyUsageMode, build_ca


class TestGeneratedCaMeetsTheIssuerRules:
    def test_the_generated_ca_is_ca_true_with_key_cert_sign_and_a_key(self, tmp_path: Path) -> None:
        """A gwops-generated CA satisfies basicConstraints CA:TRUE, keyCertSign and has a key."""
        info = CertManager(tmp_path / "pki").ensure_x509_ca(generate=True)
        cert = x509.load_pem_x509_certificate(info.pem.encode("ascii"))
        assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
        assert cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign is True
        assert info.key_path.is_file()


class TestModeOffAddsNoChecks:
    @pytest.mark.parametrize("key_usage", ["no_key_cert_sign", "absent"])
    def test_a_byo_ca_without_key_cert_sign_still_loads(
        self, tmp_path: Path, key_usage: KeyUsageMode
    ) -> None:
        """CertManager keeps accepting a BYO CA the upstream issuer would reject for signing."""
        ca = build_ca(tmp_path / "byo", key_usage=key_usage)

        info = CertManager(tmp_path / "pki").ensure_x509_ca(
            generate=False, cert_path=ca.cert, key_path=ca.key
        )

        assert info.cert_path == ca.cert

    def test_a_byo_ca_with_a_signing_key_usage_loads(self, tmp_path: Path) -> None:
        """A BYO CA with keyCertSign is accepted."""
        ca = build_ca(tmp_path / "byo", key_usage="key_cert_sign")

        info = CertManager(tmp_path / "pki").ensure_x509_ca(
            generate=False, cert_path=ca.cert, key_path=ca.key
        )

        assert info.key_path == ca.key

    @pytest.mark.parametrize("basic_constraints", ["not_ca", "absent"])
    def test_a_byo_ca_that_is_not_ca_true_is_already_refused_naming_the_file(
        self, tmp_path: Path, basic_constraints: BasicConstraintsMode
    ) -> None:
        """Existing behaviour: CA:TRUE is required regardless of the mode."""
        ca = build_ca(tmp_path / "byo", basic_constraints=basic_constraints)

        with pytest.raises(ValueError, match="CA:TRUE") as caught:
            CertManager(tmp_path / "pki").ensure_x509_ca(
                generate=False, cert_path=ca.cert, key_path=ca.key
            )

        assert str(ca.cert) in str(caught.value)
