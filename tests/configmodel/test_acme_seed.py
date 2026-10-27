"""The seed-only ``public_tls.acme`` block and ``source: acme`` certificates.

Three layers are exercised:

* :class:`AcmeSettings` on its own (field rules, with the exact actionable message text);
* :func:`parse_public_certificate` on one ``certificates[]`` entry (the ``source``
  discriminator and the file/acme field exclusions);
* the whole block through ``load_effective_state`` (the startup entry point), for the rules
  that need the enclosing ``public_tls`` (the block is required for an ACME certificate,
  every name sits inside a zone).

Messages are asserted by substring so wording can be tightened without churn, but every
assertion names the thing the operator must change.
"""

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from gwops.configmodel.schema import (
    AcmePublicCertificate,
    AcmeSettings,
    FilePublicCertificate,
    PublicTlsSettings,
    parse_public_certificate,
)
from tests.public_tls_support import ZONE, load, load_error, public_cert, public_seed, tls_block

EMAIL = "ops@example.com"
TOKEN_FILE = "/config/acme/cloudflare-token"
STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
PRODUCTION_URL = "https://acme-v02.api.letsencrypt.org/directory"


def acme_block(**fields: Any) -> dict[str, Any]:
    """A valid ``public_tls.acme`` block (staging defaults); `fields` override or add keys."""
    block: dict[str, Any] = {"email": EMAIL, "accept_tos": True}
    block.update(fields)
    return block


def acme_cert(
    name: str = "wildcard", names: list[str] | None = None, **fields: Any
) -> dict[str, Any]:
    """One ``source: acme`` certificate entry; `fields` override or add keys."""
    entry: dict[str, Any] = {
        "name": name,
        "names": [f"*.{ZONE}"] if names is None else names,
        "source": "acme",
    }
    entry.update(fields)
    return entry


def acme_tls(**fields: Any) -> dict[str, Any]:
    """A valid public_tls block with one ACME certificate and the acme block."""
    return tls_block(certificates=[acme_cert()], acme=acme_block(), **fields)


def _messages(exc: pytest.ExceptionInfo[ValidationError]) -> str:
    """The pydantic ``msg`` of every line error (never the echoed input values)."""
    return " | ".join(str(e["msg"]) for e in exc.value.errors())


def _acme_error(**fields: Any) -> str:
    with pytest.raises(ValidationError) as exc:
        AcmeSettings.model_validate(acme_block(**fields))
    return _messages(exc)


def _cert_error(entry: dict[str, Any]) -> str:
    with pytest.raises(ValidationError) as exc:
        parse_public_certificate(entry)
    return _messages(exc)


class TestAcmeSettingsDefaults:
    def test_only_email_and_accept_tos_are_needed(self) -> None:
        settings = AcmeSettings.model_validate(acme_block())

        assert settings.email == EMAIL
        assert settings.accept_tos is True
        assert settings.directory == "staging"
        assert settings.provider == "cloudflare"
        assert settings.propagation == "resolver"
        assert settings.token_file == TOKEN_FILE

    def test_staging_is_the_default_dry_run(self) -> None:
        settings = AcmeSettings.model_validate(acme_block())

        assert settings.is_staging is True
        assert settings.directory_url == "https://acme-staging-v02.api.letsencrypt.org/directory"

    def test_production_maps_to_the_lets_encrypt_url_and_is_not_staging(self) -> None:
        settings = AcmeSettings.model_validate(acme_block(directory="production"))

        assert settings.is_staging is False
        assert settings.directory_url == "https://acme-v02.api.letsencrypt.org/directory"

    def test_a_custom_directory_is_used_verbatim_and_is_not_staging(self) -> None:
        url = "https://acme.example.com/directory"
        settings = AcmeSettings.model_validate(acme_block(directory=url))

        assert settings.directory_url == url
        assert settings.is_staging is False

    def test_authoritative_propagation_is_accepted(self) -> None:
        settings = AcmeSettings.model_validate(acme_block(propagation="authoritative"))
        assert settings.propagation == "authoritative"


class TestIsStaging:
    """``is_staging`` decides dry run (never installed) versus the serving path."""

    @pytest.mark.parametrize(
        ("directory", "staging"),
        [
            ("staging", True),
            (STAGING_URL, True),
            ("production", False),
            (PRODUCTION_URL, False),
            ("https://acme.example.com/directory", False),
            ("https://localhost:14000/dir", False),
        ],
        ids=[
            "staging-shortcut",
            "explicit-staging-url",
            "production-shortcut",
            "explicit-production-url",
            "custom-host",
            "custom-host-and-port",
        ],
    )
    def test_staging_is_the_lets_encrypt_staging_directory_however_it_is_spelled(
        self, directory: str, staging: bool
    ) -> None:
        settings = AcmeSettings.model_validate(acme_block(directory=directory))

        assert settings.is_staging is staging

    def test_the_explicit_staging_url_is_kept_verbatim_and_equals_the_shortcut_url(self) -> None:
        explicit = AcmeSettings.model_validate(acme_block(directory=STAGING_URL))
        shortcut = AcmeSettings.model_validate(acme_block(directory="staging"))

        assert explicit.directory == STAGING_URL
        assert explicit.directory_url == shortcut.directory_url == STAGING_URL

    def test_the_explicit_production_url_is_production_like_the_shortcut(self) -> None:
        explicit = AcmeSettings.model_validate(acme_block(directory=PRODUCTION_URL))
        shortcut = AcmeSettings.model_validate(acme_block(directory="production"))

        assert explicit.directory_url == shortcut.directory_url == PRODUCTION_URL
        assert explicit.is_staging is shortcut.is_staging is False

    def test_another_url_on_the_staging_host_is_not_staging(self) -> None:
        """Only the exact staging directory URL is a dry run; anything else may serve."""
        other = "https://acme-staging-v02.api.letsencrypt.org/other-directory"

        assert AcmeSettings.model_validate(acme_block(directory=other)).is_staging is False

    def test_the_explicit_staging_url_loads_through_the_seed_as_staging(
        self, tmp_path: Path
    ) -> None:
        tls = tls_block(certificates=[acme_cert()], acme=acme_block(directory=STAGING_URL))

        state = load(tmp_path, public_seed(tls))

        assert state.public_tls is not None
        assert state.public_tls.acme is not None
        assert state.public_tls.acme.is_staging is True


class TestEmail:
    def test_email_is_required(self) -> None:
        with pytest.raises(ValidationError) as exc:
            AcmeSettings.model_validate({"accept_tos": True})
        assert "email" in str(exc.value)

    @pytest.mark.parametrize(
        "bad",
        ["", "ops", "ops@example", "@example.com", "ops@", "a b@example.com", "a@@example.com",
         "-ops@example.com"],
    )
    def test_a_value_that_is_not_a_contact_address_is_refused(self, bad: str) -> None:
        message = _acme_error(email=bad)

        assert "public_tls.acme.email must be a contact address" in message
        assert "ops@example.com" in message

    @pytest.mark.parametrize("good", ["ops@example.com", "a.b+tag@sub.example.org"])
    def test_a_contact_address_is_accepted(self, good: str) -> None:
        assert AcmeSettings.model_validate(acme_block(email=good)).email == good


class TestAcceptTos:
    def test_false_is_refused_with_the_remedy(self) -> None:
        message = _acme_error(accept_tos=False)

        assert "public_tls.acme.accept_tos must be true" in message
        assert "terms of service" in message

    def test_omitting_it_is_refused_the_same_way(self) -> None:
        """The default is false, and defaults are validated: omission cannot slip through."""
        with pytest.raises(ValidationError) as exc:
            AcmeSettings.model_validate({"email": EMAIL})

        assert "public_tls.acme.accept_tos must be true" in _messages(exc)

    def test_true_is_accepted(self) -> None:
        assert AcmeSettings.model_validate(acme_block(accept_tos=True)).accept_tos is True


class TestDirectory:
    @pytest.mark.parametrize(
        "good",
        [
            "staging",
            "production",
            "https://acme.example.com/directory",
            "https://localhost:14000/dir",
            "https://acme.example.com",
        ],
    )
    def test_a_known_shortcut_or_https_url_is_accepted(self, good: str) -> None:
        assert AcmeSettings.model_validate(acme_block(directory=good)).directory == good

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "Staging",
            "prod",
            "letsencrypt",
            "http://acme.example.com/directory",
            "ftp://acme.example.com/directory",
            "acme.example.com/directory",
            "https://",
            "https://user:hunter2@acme.example.com/directory",
            "https://user@acme.example.com/directory",
            "https://acme.example.com/directory#frag",
            "https://acme.example.com/dir ectory",
            "https://acme.example.com/dir\x00ectory",
            "https://acme.example.com/directory\n--tls-skip-verify",
        ],
    )
    def test_anything_else_is_refused_with_the_allowed_forms(self, bad: str) -> None:
        message = _acme_error(directory=bad)

        assert "public_tls.acme.directory must be 'staging', 'production' or an https://" in message
        assert "without credentials or a fragment" in message

    def test_a_refused_directory_does_not_echo_its_credentials(self) -> None:
        message = _acme_error(directory="https://user:hunter2@acme.example.com/directory")
        assert "hunter2" not in message


class TestProviderAndPropagation:
    @pytest.mark.parametrize("bad", ["route53", "Cloudflare", "", "cloudflare "])
    def test_only_cloudflare_is_a_provider(self, bad: str) -> None:
        message = _acme_error(provider=bad)

        assert f"public_tls.acme.provider {bad!r} is not supported" in message
        assert "use 'cloudflare'" in message

    @pytest.mark.parametrize("bad", ["none", "Resolver", "", "both"])
    def test_propagation_is_resolver_or_authoritative(self, bad: str) -> None:
        message = _acme_error(propagation=bad)

        assert f"public_tls.acme.propagation {bad!r} is not supported" in message
        assert "use 'resolver' or 'authoritative'" in message

    def test_an_unknown_key_is_refused_naming_it(self) -> None:
        with pytest.raises(ValidationError) as exc:
            AcmeSettings.model_validate(acme_block(dns_api_token="x"))
        assert "dns_api_token" in str(exc.value)


class TestTokenFile:
    @pytest.mark.parametrize(
        ("bad", "problem"),
        [
            pytest.param("", "must be an absolute path", id="empty"),
            pytest.param("cloudflare-token", "must be an absolute path", id="relative"),
            pytest.param("acme/cloudflare-token", "must be an absolute path", id="relative-dir"),
            pytest.param(
                "/config/acme/../seed.yaml", "must not contain '..' components", id="dotdot"
            ),
            pytest.param(
                "/config/acme/sub/../../seed.yaml", "must not contain '..' components",
                id="dotdot-deep",
            ),
            pytest.param("/config/acme/..", "must not contain '..' components", id="dotdot-end"),
            pytest.param("/config/acme", "must name a file under /config/acme/", id="the-root"),
            pytest.param("/config/acme/", "must name a file under /config/acme/", id="root-slash"),
            pytest.param("/config/seed.yaml", "must name a file under /config/acme/", id="sibling"),
            pytest.param(
                "/config/acme-other/token", "must name a file under /config/acme/",
                id="prefix-without-boundary",
            ),
            pytest.param("/etc/shadow", "must name a file under /config/acme/", id="elsewhere"),
            pytest.param("/data/acme/token", "must name a file under /config/acme/", id="data"),
            pytest.param(
                "/config/acme/to\nken", "contains a control character", id="newline"
            ),
            pytest.param("/config/acme/to\x00ken", "contains a control character", id="nul"),
            pytest.param("/config/acme/to\tken", "contains a control character", id="tab"),
            pytest.param("/config/acme/to\x7fken", "contains a control character", id="del"),
        ],
    )
    def test_a_path_outside_the_acme_root_is_refused_with_the_remedy(
        self, bad: str, problem: str
    ) -> None:
        message = _acme_error(token_file=bad)

        assert f"public_tls.acme.token_file {problem}" in message
        assert "mount the DNS API token file under /config/acme/" in message
        assert "/config/acme/cloudflare-token" in message

    @pytest.mark.parametrize(
        ("good", "expected"),
        [
            ("/config/acme/cloudflare-token", "/config/acme/cloudflare-token"),
            ("/config/acme/dns/token", "/config/acme/dns/token"),
            ("/config/acme//token", "/config/acme/token"),
            ("/config/acme/./token", "/config/acme/token"),
            ("/config/acme/.hidden", "/config/acme/.hidden"),
        ],
    )
    def test_a_file_under_the_root_is_accepted_and_normalised(
        self, good: str, expected: str
    ) -> None:
        assert AcmeSettings.model_validate(acme_block(token_file=good)).token_file == expected


class TestCertificateSource:
    def test_source_defaults_to_file(self) -> None:
        entry = public_cert()
        entry.pop("source")

        cert = parse_public_certificate(entry)

        assert isinstance(cert, FilePublicCertificate)
        assert cert.source == "file"

    def test_source_file_is_a_file_certificate(self) -> None:
        cert = parse_public_certificate(public_cert(source="file"))
        assert isinstance(cert, FilePublicCertificate)

    def test_source_acme_is_an_acme_certificate(self) -> None:
        cert = parse_public_certificate(acme_cert())

        assert isinstance(cert, AcmePublicCertificate)
        assert cert.source == "acme"
        assert cert.name == "wildcard"
        assert cert.names == [f"*.{ZONE}"]
        assert cert.challenge_alias is None

    def test_names_are_lowercased_for_both_kinds(self) -> None:
        cert = parse_public_certificate(acme_cert(names=[f"*.{ZONE.upper()}", f"App.{ZONE}"]))
        assert cert.names == [f"*.{ZONE}", f"app.{ZONE}"]

    @pytest.mark.parametrize("bad", ["env", "ACME", "File", "", "acme ", None, 3, ["acme"]])
    def test_any_other_source_is_refused_naming_the_choices(self, bad: Any) -> None:
        message = _cert_error(public_cert(source=bad))
        assert "source must be 'file' (default) or 'acme'" in message

    def test_a_non_mapping_entry_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            parse_public_certificate("wildcard")


class TestAcmeCertificateFields:
    def test_cert_file_and_key_file_are_refused_together(self) -> None:
        message = _cert_error(
            acme_cert(cert_file="/config/public-tls/x/fullchain.pem",
                      key_file="/config/public-tls/x/privkey.pem")
        )

        assert "source: acme issues the certificate itself" in message
        assert "remove cert_file and key_file" in message
        assert "source: file" in message

    def test_cert_file_alone_is_refused_naming_only_it(self) -> None:
        message = _cert_error(acme_cert(cert_file="/config/public-tls/x/fullchain.pem"))

        assert "remove cert_file (" in message
        assert "key_file" not in message

    def test_key_file_alone_is_refused_naming_only_it(self) -> None:
        message = _cert_error(acme_cert(key_file="/config/public-tls/x/privkey.pem"))

        assert "remove key_file (" in message
        assert "cert_file" not in message

    def test_an_unknown_key_is_refused_naming_it(self) -> None:
        with pytest.raises(ValidationError) as exc:
            parse_public_certificate(acme_cert(passphrase="x"))
        assert "passphrase" in str(exc.value)

    def test_names_are_required(self) -> None:
        entry = acme_cert()
        entry.pop("names")
        with pytest.raises(ValidationError) as exc:
            parse_public_certificate(entry)
        assert "names" in str(exc.value)

    def test_names_must_not_be_empty(self) -> None:
        with pytest.raises(ValidationError) as exc:
            parse_public_certificate(acme_cert(names=[]))
        assert "names" in str(exc.value)


class TestChallengeAlias:
    def test_a_concrete_dns_name_is_accepted(self) -> None:
        cert = parse_public_certificate(acme_cert(challenge_alias="acme.delegated.example.net"))

        assert isinstance(cert, AcmePublicCertificate)
        assert cert.challenge_alias == "acme.delegated.example.net"

    def test_it_is_lowercased(self) -> None:
        cert = parse_public_certificate(acme_cert(challenge_alias="ACME.Delegated.Example.NET"))

        assert isinstance(cert, AcmePublicCertificate)
        assert cert.challenge_alias == "acme.delegated.example.net"

    def test_an_explicit_null_is_the_default(self) -> None:
        cert = parse_public_certificate(acme_cert(challenge_alias=None))

        assert isinstance(cert, AcmePublicCertificate)
        assert cert.challenge_alias is None

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "delegated",
            "*.delegated.example.net",
            "bad_name.example.net",
            "acme.example.net.",
            "a b.example.net",
            "-x.example.net",
            "acme..example.net",
        ],
    )
    def test_anything_but_a_concrete_dns_name_is_refused(self, bad: str) -> None:
        message = _cert_error(acme_cert(challenge_alias=bad))

        assert "challenge_alias" in message
        assert "must be a concrete lowercase DNS name" in message
        assert "_acme-challenge.<name>" in message

    @pytest.mark.parametrize("source", [None, "file"])
    def test_a_file_certificate_refuses_it(self, source: str | None) -> None:
        entry = public_cert(challenge_alias="acme.delegated.example.net")
        if source is None:
            entry.pop("source")

        message = _cert_error(entry)

        assert "challenge_alias applies only to source: acme certificates" in message
        assert "set source: acme" in message


class TestAcmeBlockRequirement:
    """Load-time rules that need the enclosing ``public_tls`` block."""

    def test_an_acme_certificate_without_the_block_aborts_naming_the_certificate(
        self, tmp_path: Path
    ) -> None:
        tls = tls_block(certificates=[acme_cert()])

        message = load_error(tmp_path, public_seed(tls))

        assert "'wildcard'" in message
        assert "source: acme but public_tls.acme is missing" in message
        assert "accept_tos: true" in message
        assert "token_file" in message

    def test_every_acme_certificate_without_the_block_is_named(self, tmp_path: Path) -> None:
        tls = tls_block(
            certificates=[
                acme_cert("one", [f"one.{ZONE}"]),
                public_cert("filed", [f"filed.{ZONE}"]),
                acme_cert("two", [f"two.{ZONE}"]),
            ]
        )

        message = load_error(tmp_path, public_seed(tls))

        assert "'one'" in message
        assert "'two'" in message
        assert "'filed'" not in message

    def test_the_block_is_optional_when_every_certificate_is_a_file(self, tmp_path: Path) -> None:
        state = load(tmp_path, public_seed())

        assert state.public_tls is not None
        assert state.public_tls.acme is None

    def test_the_block_is_allowed_without_any_acme_certificate(self, tmp_path: Path) -> None:
        state = load(tmp_path, public_seed(tls_block(acme=acme_block())))

        assert state.public_tls is not None
        assert state.public_tls.acme is not None
        assert state.public_tls.acme.email == EMAIL

    def test_an_acme_certificate_with_the_block_loads(self, tmp_path: Path) -> None:
        state = load(tmp_path, public_seed(acme_tls()))

        assert isinstance(state.public_tls, PublicTlsSettings)
        [cert] = state.public_tls.certificates
        assert isinstance(cert, AcmePublicCertificate)
        assert state.public_tls.acme is not None
        assert state.public_tls.acme.directory == "staging"
        assert state.public_tls.acme.token_file == TOKEN_FILE

    def test_file_and_acme_certificates_may_be_mixed(self, tmp_path: Path) -> None:
        tls = tls_block(
            certificates=[
                public_cert("filed", [f"filed.{ZONE}"]),
                acme_cert("issued", [f"*.apps.{ZONE}"]),
            ],
            acme=acme_block(directory="production", propagation="authoritative"),
        )

        state = load(tmp_path, public_seed(tls))

        assert state.public_tls is not None
        kinds = {c.name: type(c) for c in state.public_tls.certificates}
        assert kinds == {"filed": FilePublicCertificate, "issued": AcmePublicCertificate}

    def test_the_acme_block_round_trips_through_model_dump(self, tmp_path: Path) -> None:
        dumped = load(tmp_path, public_seed(acme_tls())).model_dump(mode="json")

        assert dumped["public_tls"]["acme"]["email"] == EMAIL
        assert dumped["public_tls"]["certificates"][0]["source"] == "acme"

    def test_an_unknown_key_in_the_block_aborts_naming_it(self, tmp_path: Path) -> None:
        tls = tls_block(certificates=[acme_cert()], acme=acme_block(dns_api_token="x"))

        message = load_error(tmp_path, public_seed(tls))

        assert "dns_api_token" in message


class TestAcmeBlockThroughTheLoader:
    """The field rules abort startup with the same actionable text."""

    def test_accept_tos_false_aborts(self, tmp_path: Path) -> None:
        tls = tls_block(certificates=[acme_cert()], acme=acme_block(accept_tos=False))

        message = load_error(tmp_path, public_seed(tls))

        assert "public_tls.acme.accept_tos must be true" in message

    def test_accept_tos_omitted_aborts(self, tmp_path: Path) -> None:
        tls = tls_block(certificates=[acme_cert()], acme={"email": EMAIL})

        message = load_error(tmp_path, public_seed(tls))

        assert "public_tls.acme.accept_tos must be true" in message

    def test_a_token_file_outside_the_root_aborts(self, tmp_path: Path) -> None:
        tls = tls_block(
            certificates=[acme_cert()], acme=acme_block(token_file="/config/seed.yaml")
        )

        message = load_error(tmp_path, public_seed(tls))

        assert "public_tls.acme.token_file must name a file under /config/acme/" in message

    def test_a_bad_directory_aborts(self, tmp_path: Path) -> None:
        tls = tls_block(
            certificates=[acme_cert()], acme=acme_block(directory="http://acme.example.com/d")
        )

        message = load_error(tmp_path, public_seed(tls))

        assert "public_tls.acme.directory must be 'staging', 'production' or an https://" in message

    def test_an_unsupported_provider_aborts(self, tmp_path: Path) -> None:
        tls = tls_block(certificates=[acme_cert()], acme=acme_block(provider="route53"))

        message = load_error(tmp_path, public_seed(tls))

        assert "public_tls.acme.provider 'route53' is not supported" in message


class TestAcmeCertificateNames:
    """Rule 4 holds for ACME certificates: every name sits inside a zone."""

    def test_a_name_outside_every_zone_aborts_naming_certificate_and_name(
        self, tmp_path: Path
    ) -> None:
        tls = tls_block(
            certificates=[acme_cert(names=[f"*.{ZONE}", "app.example.net"])],
            acme=acme_block(),
        )

        message = load_error(tmp_path, public_seed(tls))

        assert "wildcard" in message
        assert "app.example.net" in message
        assert "is outside every zone" in message

    def test_a_wildcard_that_is_not_leftmost_aborts(self, tmp_path: Path) -> None:
        tls = tls_block(
            certificates=[acme_cert(names=[f"foo.*.{ZONE}"])], acme=acme_block()
        )

        message = load_error(tmp_path, public_seed(tls))

        assert "wildcard" in message
        assert "must be a concrete DNS name, or '*.' followed by one" in message

    def test_a_name_declared_by_a_file_and_an_acme_certificate_aborts_naming_both(
        self, tmp_path: Path
    ) -> None:
        tls = tls_block(
            certificates=[public_cert("filed", [f"*.{ZONE}"]), acme_cert("issued")],
            acme=acme_block(),
        )

        message = load_error(tmp_path, public_seed(tls))

        assert "filed" in message
        assert "issued" in message
        assert f"*.{ZONE}" in message

    def test_duplicate_certificate_names_abort_across_sources(self, tmp_path: Path) -> None:
        tls = tls_block(
            certificates=[
                public_cert("dup", [f"a.{ZONE}"]),
                acme_cert("dup", [f"b.{ZONE}"]),
            ],
            acme=acme_block(),
        )

        message = load_error(tmp_path, public_seed(tls))

        assert "duplicate certificate name 'dup'" in message

    def test_an_acme_certificate_with_file_paths_aborts_at_load(self, tmp_path: Path) -> None:
        entry = acme_cert(cert_file="/config/public-tls/x/fullchain.pem")
        tls = tls_block(certificates=[entry], acme=acme_block())

        message = load_error(tmp_path, public_seed(tls))

        assert "source: acme issues the certificate itself" in message
        assert "remove cert_file" in message

    def test_a_file_certificate_with_challenge_alias_aborts_at_load(self, tmp_path: Path) -> None:
        entry = public_cert(challenge_alias="acme.delegated.example.net")
        tls = tls_block(certificates=[entry])

        message = load_error(tmp_path, public_seed(tls))

        assert "challenge_alias applies only to source: acme certificates" in message
