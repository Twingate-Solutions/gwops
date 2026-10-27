"""The seed-only `public_tls` block (D30-1) and its load-time rules 1-5.

Each rule is exercised through `load_effective_state`, the startup entry point, so a
refusal here is a startup abort: `ConfigLoadError` whose message names the entry and the
field. The same validators run for an overlay candidate; the two rules an overlay can
reach (3 and 5) are repeated through the admin API in `tests/api/test_public_tls_overlay.py`.

Rule 6 (`cert_file` / `key_file` under `/config/public-tls/`) is deliberately absent: it is
enforced where the files are read, by the confined reader (30.6), as for CA bundles. The
model keeps the paths as opaque strings, so there is nothing to assert on it here.

Decisions the tests encode where the session file is silent:

* A zone is refused, not normalised, when it is not already lowercase ASCII (rule 2 says
  "lowercased A-labels"; silently rewriting an operator's zone would hide a typo).
* A zone's own apex counts as "inside" that zone, for served names and certificate names.
* A served name that sits under `kubernetes.default.svc` is outside every ordinary zone.
"""

from pathlib import Path
from typing import Any

import pytest
import structlog.testing
import yaml
from pydantic import ValidationError

from gwops.configmodel.loader import ConfigLoadError, load_effective_state
from gwops.configmodel.schema import (
    EffectiveState,
    FilePublicCertificate,
    PublicTlsSettings,
    SeedConfig,
    _served_names,
    unused_public_certificates,
)
from gwops.configmodel.store import OverlayStore
from gwops.renderer.sans import required_sans
from tests.public_tls_support import (
    ZONE,
    k8s,
    load,
    load_error,
    public_cert,
    public_seed,
    ssh,
    tls_block,
    webapp,
)


def _says_duplicate(message: str) -> bool:
    lowered = message.lower()
    return "duplicate" in lowered or "unique" in lowered


class TestShape:
    def test_a_seed_without_the_block_is_not_public_mode(self) -> None:
        cfg = SeedConfig.model_validate({"twingate": {"network": "acme", "gateway_id": "g-1"}})
        assert cfg.public_tls is None

    def test_the_block_loads_into_typed_models(self, tmp_path: Path) -> None:
        state = load(tmp_path, public_seed())
        assert isinstance(state.public_tls, PublicTlsSettings)
        assert state.public_tls.zones == [ZONE]
        assert state.public_tls.registered_root == "isrg_root_x1"
        [cert] = state.public_tls.certificates
        assert isinstance(cert, FilePublicCertificate)
        assert cert.name == "wildcard"
        assert cert.names == [f"*.{ZONE}"]
        assert cert.source == "file"
        assert cert.cert_file == "/config/public-tls/wildcard/fullchain.pem"
        assert cert.key_file == "/config/public-tls/wildcard/privkey.pem"

    def test_the_block_round_trips_through_model_dump(self, tmp_path: Path) -> None:
        dumped = load(tmp_path, public_seed()).model_dump(mode="json")
        assert dumped["public_tls"]["zones"] == [ZONE]
        assert dumped["public_tls"]["certificates"][0]["name"] == "wildcard"

    def test_several_certificates_and_zones_load(self, tmp_path: Path) -> None:
        tls = tls_block(
            zones=[ZONE, "example.org"],
            certificates=[
                public_cert("one", [f"*.{ZONE}"]),
                public_cert("two", ["*.example.org", "example.org"]),
            ],
        )
        state = load(tmp_path, public_seed(tls))
        assert state.public_tls is not None
        assert [c.name for c in state.public_tls.certificates] == ["one", "two"]

    def test_the_block_is_seed_provenance(self, tmp_path: Path) -> None:
        seed_path = tmp_path / "seed.yaml"
        seed_path.write_text(yaml.safe_dump(public_seed()), encoding="utf-8")
        _state, provenance = load_effective_state(seed_path, OverlayStore(tmp_path / "ov"))
        assert provenance["public_tls.zones"] == "seed"

    @pytest.mark.parametrize(
        ("mutate", "needle"),
        [
            pytest.param(lambda t: t.pop("zones"), "zones", id="zones-missing"),
            pytest.param(lambda t: t.pop("registered_root"), "registered_root",
                         id="registered-root-missing"),
            pytest.param(lambda t: t.update(registered_root="isrg_root_x2"), "registered_root",
                         id="registered-root-other-root"),
            pytest.param(lambda t: t.update(registered_root="ISRG_ROOT_X1"), "registered_root",
                         id="registered-root-case"),
            pytest.param(lambda t: t.update(certificates=[]), "certificates",
                         id="certificates-empty"),
            pytest.param(lambda t: t.pop("certificates"), "certificates",
                         id="certificates-missing"),
            pytest.param(lambda t: t.update(acme={"email": "a@b.c"}), "acme",
                         id="acme-block-without-tos"),
        ],
    )
    def test_a_malformed_block_aborts_naming_the_field(
        self, tmp_path: Path, mutate: Any, needle: str
    ) -> None:
        tls = tls_block()
        mutate(tls)
        message = load_error(tmp_path, public_seed(tls))
        assert "public_tls" in message
        assert needle in message

    @pytest.mark.parametrize(
        ("mutate", "needle"),
        [
            pytest.param(lambda c: c.update(source="ACME"), "source", id="source-wrong-case"),
            pytest.param(lambda c: c.update(source="env"), "source", id="source-other"),
            pytest.param(lambda c: c.pop("cert_file"), "cert_file", id="cert-file-missing"),
            pytest.param(lambda c: c.pop("key_file"), "key_file", id="key-file-missing"),
            pytest.param(lambda c: c.pop("names"), "names", id="names-missing"),
            pytest.param(lambda c: c.update(names=[]), "names", id="names-empty"),
            pytest.param(lambda c: c.update(passphrase="x"), "passphrase", id="unknown-key"),
        ],
    )
    def test_a_malformed_certificate_aborts_naming_entry_and_field(
        self, tmp_path: Path, mutate: Any, needle: str
    ) -> None:
        cert = public_cert("wildcard")
        mutate(cert)
        message = load_error(tmp_path, public_seed(tls_block(certificates=[cert])))
        assert "wildcard" in message
        assert needle in message

    @pytest.mark.parametrize("bad", ["Upper", "a_b", "a.b", "", "x" * 64, "-é"])
    def test_a_certificate_name_must_be_a_dns_label_style_identifier(
        self, tmp_path: Path, bad: str
    ) -> None:
        cert = public_cert("placeholder")
        cert["name"] = bad
        message = load_error(tmp_path, public_seed(tls_block(certificates=[cert])))
        assert "name" in message

    @pytest.mark.parametrize("good", ["a", "wildcard", "x" * 63, "0-9"])
    def test_a_valid_certificate_name_is_accepted(self, tmp_path: Path, good: str) -> None:
        cert = public_cert(good)
        assert load(tmp_path, public_seed(tls_block(certificates=[cert]))).public_tls is not None

    def test_duplicate_certificate_names_abort_naming_the_certificate(
        self, tmp_path: Path
    ) -> None:
        certs = [
            public_cert("dup", ["a.example.com"]),
            public_cert("dup", ["b.example.com"]),
        ]
        message = load_error(tmp_path, public_seed(tls_block(certificates=certs)))
        assert "dup" in message
        assert _says_duplicate(message)

    def test_a_name_declared_by_two_certificates_aborts_naming_both(
        self, tmp_path: Path
    ) -> None:
        """`names` are unique across certificates; the message names both owners."""
        certs = [
            public_cert("first", [f"*.{ZONE}"]),
            public_cert("second", [f"*.{ZONE}"]),
        ]
        message = load_error(tmp_path, public_seed(tls_block(certificates=certs)))
        assert "first" in message
        assert "second" in message
        assert f"*.{ZONE}" in message


class TestExclusivityWithCaX509:
    """Rule 1: `public_tls` and an explicit `ca.x509` block never coexist."""

    @pytest.mark.parametrize(
        "x509",
        [
            pytest.param({"generate": True}, id="generate"),
            pytest.param({}, id="empty-block"),
            pytest.param(
                {"generate": False, "cert_path": "/mnt/ca.crt", "key_path": "/mnt/ca.key"},
                id="byo",
            ),
            pytest.param({"on_demand_issuance": True}, id="on-demand-true"),
            pytest.param({"on_demand_issuance": False}, id="on-demand-false"),
        ],
    )
    def test_an_explicit_ca_x509_block_aborts_naming_both_keys(
        self, tmp_path: Path, x509: dict[str, Any]
    ) -> None:
        message = load_error(tmp_path, public_seed(ca={"x509": x509}))
        assert "public_tls" in message
        assert "ca.x509" in message

    def test_the_model_refuses_it_too(self) -> None:
        raw = public_seed(ca={"x509": {"generate": True}})
        with pytest.raises(ValidationError) as exc:
            SeedConfig.model_validate(raw)
        message = " ".join(str(e["msg"]) for e in exc.value.errors())
        assert "public_tls" in message
        assert "ca.x509" in message

    def test_no_ca_block_is_accepted_and_x509_keeps_its_defaults(self, tmp_path: Path) -> None:
        state = load(tmp_path, public_seed())
        assert state.public_tls is not None
        assert state.ca.x509.generate is True
        assert state.ca.x509.on_demand_issuance is False

    def test_an_empty_ca_block_is_accepted(self, tmp_path: Path) -> None:
        assert load(tmp_path, public_seed(ca={})).public_tls is not None

    def test_an_ssh_only_ca_block_is_accepted(self, tmp_path: Path) -> None:
        state = load(tmp_path, public_seed(ca={"ssh": {"generate": True}}))
        assert state.public_tls is not None

    def test_ca_x509_without_public_tls_is_unchanged(self, tmp_path: Path) -> None:
        seed = {
            "twingate": {"network": "acme", "gateway_id": "g-1"},
            "ca": {"x509": {"generate": True, "on_demand_issuance": True}},
        }
        state = load(tmp_path, seed)
        assert state.public_tls is None
        assert state.ca.x509.on_demand_issuance is True


_BASE_SERVED = [ssh("host1", f"host1.{ZONE}:22")]


class TestZones:
    """Rule 2: at least one zone; lowercase A-labels; two or more labels; no wildcard or dot."""

    @pytest.mark.parametrize(
        "zones",
        [
            pytest.param(["Example.Com"], id="uppercase"),
            pytest.param(["example.com."], id="trailing-dot"),
            pytest.param(["*.example.com"], id="wildcard"),
            pytest.param(["com"], id="single-label"),
            pytest.param(["münchen.de"], id="u-label"),
            pytest.param(["ex_ample.com"], id="underscore"),
            pytest.param(["example..com"], id="empty-label"),
            pytest.param([".example.com"], id="leading-dot"),
            pytest.param(["-tg.site"], id="leading-hyphen"),
            pytest.param(["tg-.site"], id="trailing-hyphen"),
            pytest.param([" example.com"], id="whitespace"),
            pytest.param([""], id="empty-string"),
            pytest.param([("a" * 64) + ".site"], id="label-over-63"),
        ],
    )
    def test_a_bad_zone_aborts_naming_the_field(self, tmp_path: Path, zones: list[str]) -> None:
        message = load_error(tmp_path, public_seed(tls_block(zones=zones)))
        assert "zones" in message

    @pytest.mark.parametrize("bad", ["Example.Com", "example.com.", "com", "münchen.de"])
    def test_the_message_shows_the_offending_zone(self, tmp_path: Path, bad: str) -> None:
        message = load_error(tmp_path, public_seed(tls_block(zones=[bad])))
        assert bad in message

    def test_no_zones_aborts_naming_the_field(self, tmp_path: Path) -> None:
        message = load_error(tmp_path, public_seed(tls_block(zones=[])))
        assert "zones" in message
        assert "public_tls" in message

    def test_a_duplicate_zone_aborts(self, tmp_path: Path) -> None:
        message = load_error(tmp_path, public_seed(tls_block(zones=[ZONE, ZONE])))
        assert "zones" in message
        assert ZONE in message
        assert _says_duplicate(message)

    @pytest.mark.parametrize(
        "zones",
        [
            pytest.param([ZONE], id="plain"),
            pytest.param(["xn--mnchen-3ya.de"], id="a-label"),
            pytest.param(["a.b.example.net"], id="deep"),
            pytest.param(["1a.example.net", "x-1.example.org"], id="digits-and-hyphens"),
            pytest.param([ZONE, "example.org"], id="two-zones"),
        ],
    )
    def test_a_good_zone_list_is_accepted(self, tmp_path: Path, zones: list[str]) -> None:
        tls = tls_block(zones=zones, certificates=[public_cert("c", [f"*.{zones[0]}"])])
        assert load(tmp_path, public_seed(tls)).public_tls is not None


class TestServedNames:
    """Rule 3: every served name is a DNS name inside a zone; the message names the
    entry (list field and resource name) and the field (`address` or `alias`)."""

    @pytest.mark.parametrize(
        ("kind", "entry", "field", "shown"),
        [
            pytest.param("ssh_upstreams", ssh("bastion", "10.0.0.5:22"), "address", "10.0.0.5",
                         id="ssh-ip-literal"),
            pytest.param("ssh_upstreams", ssh("bastion", "10.0.0.5"), "address", "10.0.0.5",
                         id="ssh-ip-literal-no-port"),
            pytest.param("ssh_upstreams", ssh("bastion", "bastion"), "address", "bastion",
                         id="ssh-single-label"),
            pytest.param("ssh_upstreams", ssh("bastion", "bastion:22"), "address", "bastion",
                         id="ssh-single-label-with-port"),
            pytest.param("ssh_upstreams", ssh("bastion", f"my_host.{ZONE}"), "address",
                         f"my_host.{ZONE}", id="ssh-underscore"),
            pytest.param("ssh_upstreams", ssh("bastion", f"_x.{ZONE}"), "address",
                         f"_x.{ZONE}", id="ssh-leading-underscore"),
            pytest.param("ssh_upstreams", ssh("bastion", "bastion.example.net"), "address",
                         "bastion.example.net", id="ssh-outside-every-zone"),
            pytest.param("ssh_upstreams", ssh("bastion", f"bastion.not{ZONE}"), "address",
                         f"bastion.not{ZONE}", id="ssh-suffix-without-label-boundary"),
            pytest.param("k8s_clusters", k8s("prod", "kubernetes.default.svc"), "address",
                         "kubernetes.default.svc", id="k8s-in-cluster-name"),
            pytest.param("k8s_clusters", k8s("prod", "10.96.0.1"), "address", "10.96.0.1",
                         id="k8s-ip-literal"),
            pytest.param("web_apps", webapp("grafana", "grafana.example.net"), "address",
                         "grafana.example.net", id="webapp-address-outside"),
            pytest.param("web_apps", webapp("grafana", "grafana"), "address", "grafana",
                         id="webapp-address-single-label"),
            pytest.param("web_apps", webapp("grafana", f"grafana.{ZONE}", "10.0.0.9"), "alias",
                         "10.0.0.9", id="webapp-alias-ip-literal"),
            pytest.param("web_apps", webapp("grafana", f"grafana.{ZONE}", "graf"), "alias",
                         "graf", id="webapp-alias-single-label"),
            pytest.param("web_apps", webapp("grafana", f"grafana.{ZONE}", "graf.example.net"),
                         "alias", "graf.example.net", id="webapp-alias-outside"),
            pytest.param("web_apps", webapp("grafana", f"grafana.{ZONE}", f"g_f.{ZONE}"),
                         "alias", f"g_f.{ZONE}", id="webapp-alias-underscore"),
        ],
    )
    def test_a_bad_served_name_aborts_naming_entry_and_field(
        self, tmp_path: Path, kind: str, entry: dict[str, Any], field: str, shown: str
    ) -> None:
        seed = public_seed(**{kind: [entry]})
        message = load_error(tmp_path, seed)
        assert kind in message
        assert entry["name"] in message
        assert field in message
        assert shown in message

    def test_the_same_names_are_fine_without_public_mode(self, tmp_path: Path) -> None:
        """Rule 3 only applies in public mode: private mode keeps IPs and short names."""
        seed = {
            "twingate": {"network": "acme", "gateway_id": "g-1"},
            "ssh_upstreams": [ssh("bastion", "10.0.0.5:22"), ssh("short", "short")],
            "k8s_clusters": [k8s("prod", "kubernetes.default.svc")],
            "web_apps": [webapp("grafana", "grafana.example.net", "10.0.0.9")],
        }
        assert load(tmp_path, seed).public_tls is None

    def test_a_name_directly_under_the_zone_is_accepted(self, tmp_path: Path) -> None:
        seed = public_seed(
            ssh_upstreams=[ssh("host1", f"host1.{ZONE}:22")],
            k8s_clusters=[k8s("prod", f"k8s.{ZONE}")],
            web_apps=[webapp("grafana", f"grafana.{ZONE}", f"graf.{ZONE}")],
        )
        assert len(load(tmp_path, seed).web_apps) == 1

    def test_a_name_inside_any_one_of_several_zones_is_accepted(self, tmp_path: Path) -> None:
        tls = tls_block(
            zones=[ZONE, "example.org"],
            certificates=[public_cert("a", [f"*.{ZONE}"]), public_cert("b", ["*.example.org"])],
        )
        seed = public_seed(
            tls, ssh_upstreams=[ssh("one", f"one.{ZONE}"), ssh("two", "two.example.org")]
        )
        assert len(load(tmp_path, seed).ssh_upstreams) == 2

    def test_a_deeper_name_under_a_zone_is_inside_it(self, tmp_path: Path) -> None:
        tls = tls_block(certificates=[public_cert("deep", [f"*.rig.{ZONE}"])])
        seed = public_seed(tls, ssh_upstreams=[ssh("h", f"h.rig.{ZONE}")])
        assert len(load(tmp_path, seed).ssh_upstreams) == 1

    def test_the_zone_apex_is_inside_its_zone(self, tmp_path: Path) -> None:
        tls = tls_block(certificates=[public_cert("apex", [ZONE])])
        seed = public_seed(tls, ssh_upstreams=[ssh("h", ZONE)])
        assert len(load(tmp_path, seed).ssh_upstreams) == 1


class TestCertificateNames:
    """Rule 4: each certificate's `names` sit inside a zone; a wildcard is a leftmost `*.`."""

    @pytest.mark.parametrize(
        "names",
        [
            pytest.param(["app.example.net"], id="outside-every-zone"),
            pytest.param(["*.example.net"], id="wildcard-outside-every-zone"),
            pytest.param([f"*.{ZONE}", "x.example.net"], id="second-name-outside"),
            pytest.param([f"foo.*.{ZONE}"], id="wildcard-not-leftmost"),
            pytest.param([f"f*.{ZONE}"], id="partial-wildcard-prefix"),
            pytest.param([f"*f.{ZONE}"], id="partial-wildcard-suffix"),
            pytest.param([f"*.*.{ZONE}"], id="two-wildcards"),
            pytest.param([f"**.{ZONE}"], id="double-star"),
            pytest.param([f"*{ZONE}"], id="star-without-dot"),
            pytest.param(["*"], id="bare-star"),
            pytest.param([f"{ZONE}."], id="trailing-dot"),
            pytest.param(["com"], id="single-label"),
            pytest.param([f"a b.{ZONE}"], id="space"),
            pytest.param(["*.org"], id="wildcard-over-a-tld"),
        ],
    )
    def test_a_bad_certificate_name_aborts_naming_certificate_and_field(
        self, tmp_path: Path, names: list[str]
    ) -> None:
        tls = tls_block(certificates=[public_cert("wildcard", names)])
        message = load_error(tmp_path, public_seed(tls))
        assert "wildcard" in message
        assert "names" in message

    def test_the_message_shows_the_offending_name(self, tmp_path: Path) -> None:
        tls = tls_block(certificates=[public_cert("wildcard", [f"*.{ZONE}", "x.example.net"])])
        assert "x.example.net" in load_error(tmp_path, public_seed(tls))

    def test_a_wildcard_wider_than_a_narrow_zone_is_refused(self, tmp_path: Path) -> None:
        """`*.example.com` would match names outside the zone `rig.example.com`."""
        tls = tls_block(
            zones=[f"rig.{ZONE}"], certificates=[public_cert("wide", [f"*.{ZONE}"])]
        )
        message = load_error(tmp_path, public_seed(tls))
        assert "wide" in message
        assert f"*.{ZONE}" in message

    @pytest.mark.parametrize(
        "names",
        [
            pytest.param([f"*.{ZONE}"], id="wildcard-of-the-zone"),
            pytest.param([ZONE], id="apex"),
            pytest.param([f"app.{ZONE}"], id="concrete"),
            pytest.param([f"*.rig.{ZONE}"], id="wildcard-of-a-subdomain"),
            pytest.param([ZONE, f"*.{ZONE}"], id="apex-and-wildcard"),
            pytest.param([f"a.{ZONE}", f"b.{ZONE}", f"c.d.{ZONE}"], id="several-concrete"),
        ],
    )
    def test_a_good_certificate_name_list_is_accepted(
        self, tmp_path: Path, names: list[str]
    ) -> None:
        tls = tls_block(certificates=[public_cert("ok", names)])
        assert load(tmp_path, public_seed(tls)).public_tls is not None


class TestCoverage:
    """Rule 5 / D30-7: every served name matches exactly one certificate."""

    def test_an_uncovered_served_name_aborts_naming_it(self, tmp_path: Path) -> None:
        tls = tls_block(certificates=[public_cert("other", [f"other.{ZONE}"])])
        message = load_error(tmp_path, public_seed(tls, ssh_upstreams=_BASE_SERVED))
        assert f"host1.{ZONE}" in message

    def test_a_wildcard_does_not_cover_the_zone_apex(self, tmp_path: Path) -> None:
        seed = public_seed(ssh_upstreams=[ssh("apex", ZONE)])
        message = load_error(tmp_path, seed)
        assert f'{ZONE}' in message
        assert "apex" in message

    def test_a_wildcard_does_not_cover_two_labels(self, tmp_path: Path) -> None:
        seed = public_seed(ssh_upstreams=[ssh("deep", f"a.b.{ZONE}")])
        assert f"a.b.{ZONE}" in load_error(tmp_path, seed)

    def test_an_uncovered_alias_aborts_naming_the_alias(self, tmp_path: Path) -> None:
        tls = tls_block(certificates=[public_cert("only-app", [f"app.{ZONE}"])])
        seed = public_seed(tls, web_apps=[webapp("app", f"app.{ZONE}", f"alias.{ZONE}")])
        message = load_error(tmp_path, seed)
        assert f"alias.{ZONE}" in message

    def test_a_served_name_matched_by_two_certificates_aborts_naming_both(
        self, tmp_path: Path
    ) -> None:
        tls = tls_block(
            certificates=[
                public_cert("wildcard", [f"*.{ZONE}"]),
                public_cert("api-specific", [f"api.{ZONE}"]),
            ]
        )
        seed = public_seed(tls, ssh_upstreams=[ssh("api", f"api.{ZONE}")])
        message = load_error(tmp_path, seed)
        assert "wildcard" in message
        assert "api-specific" in message
        assert f"api.{ZONE}" in message

    def test_the_overlap_is_refused_even_when_one_name_is_listed_first(
        self, tmp_path: Path
    ) -> None:
        """List order never decides: reversing the certificates is the same refusal."""
        tls = tls_block(
            certificates=[
                public_cert("api-specific", [f"api.{ZONE}"]),
                public_cert("wildcard", [f"*.{ZONE}"]),
            ]
        )
        seed = public_seed(tls, ssh_upstreams=[ssh("api", f"api.{ZONE}")])
        message = load_error(tmp_path, seed)
        assert "wildcard" in message
        assert "api-specific" in message

    def test_two_overlapping_certificates_are_fine_when_no_served_name_is_in_the_overlap(
        self, tmp_path: Path
    ) -> None:
        tls = tls_block(
            certificates=[
                public_cert("wildcard", [f"*.{ZONE}"]),
                public_cert("api-specific", [f"api.{ZONE}"]),
            ]
        )
        seed = public_seed(tls, ssh_upstreams=[ssh("web", f"web.{ZONE}")])
        assert load(tmp_path, seed).public_tls is not None

    def test_an_address_and_an_alias_may_be_covered_by_different_certificates(
        self, tmp_path: Path
    ) -> None:
        tls = tls_block(
            certificates=[
                public_cert("apps", [f"*.apps.{ZONE}"]),
                public_cert("docs", [f"*.docs.{ZONE}"]),
            ]
        )
        seed = public_seed(
            tls, web_apps=[webapp("app", f"app.apps.{ZONE}", f"app.docs.{ZONE}")]
        )
        assert len(load(tmp_path, seed).web_apps) == 1

    def test_one_certificate_may_cover_many_served_names(self, tmp_path: Path) -> None:
        seed = public_seed(
            ssh_upstreams=[ssh("a", f"a.{ZONE}"), ssh("b", f"b.{ZONE}")],
            web_apps=[webapp("w", f"w.{ZONE}", f"x.{ZONE}")],
        )
        assert len(load(tmp_path, seed).ssh_upstreams) == 2

    def test_public_mode_with_no_served_names_loads(self, tmp_path: Path) -> None:
        assert load(tmp_path, public_seed()).ssh_upstreams == []

    def test_no_coverage_rule_applies_without_public_mode(self, tmp_path: Path) -> None:
        seed = {
            "twingate": {"network": "acme", "gateway_id": "g-1"},
            "ssh_upstreams": [ssh("h", "h.example.net")],
        }
        assert load(tmp_path, seed).public_tls is None


class TestUnusedCertificates:
    """A certificate whose names match no served name is reported, never an error.

    `unused_public_certificates` is pure. Validation stays silent (it runs on every load,
    several times per API request); the warning is logged by the reconciler, see
    `tests/reconciler/test_public_cert_unused_log.py`.
    """

    def test_an_unused_certificate_is_listed_and_the_state_loads(self, tmp_path: Path) -> None:
        tls = tls_block(
            certificates=[
                public_cert("wildcard", [f"*.{ZONE}"]),
                public_cert("unused", [f"never.{ZONE}"]),
            ]
        )
        state = load(tmp_path, public_seed(tls, ssh_upstreams=_BASE_SERVED))

        assert state.public_tls is not None
        assert unused_public_certificates(state) == ["unused"]

    def test_every_unused_certificate_is_listed_in_declaration_order(
        self, tmp_path: Path
    ) -> None:
        tls = tls_block(
            certificates=[
                public_cert("two", [f"two.{ZONE}"]),
                public_cert("one", [f"one.{ZONE}"]),
            ]
        )
        assert unused_public_certificates(load(tmp_path, public_seed(tls))) == ["two", "one"]

    def test_used_certificates_are_not_listed(self, tmp_path: Path) -> None:
        state = load(tmp_path, public_seed(ssh_upstreams=_BASE_SERVED))
        assert unused_public_certificates(state) == []

    def test_a_certificate_used_only_by_an_alias_is_used(self, tmp_path: Path) -> None:
        tls = tls_block(
            certificates=[
                public_cert("apps", [f"app.{ZONE}"]),
                public_cert("alias-only", [f"alias.{ZONE}"]),
            ]
        )
        seed = public_seed(tls, web_apps=[webapp("app", f"app.{ZONE}", f"alias.{ZONE}")])
        assert unused_public_certificates(load(tmp_path, seed)) == []

    def test_nothing_is_unused_without_public_mode(self, tmp_path: Path) -> None:
        seed = {"twingate": {"network": "acme", "gateway_id": "g-1"}}
        assert unused_public_certificates(load(tmp_path, seed)) == []

    def test_loading_logs_nothing(self, tmp_path: Path) -> None:
        """Validation runs on every load; it must not warn."""
        tls = tls_block(certificates=[public_cert("unused", [f"never.{ZONE}"])])
        with structlog.testing.capture_logs() as logs:
            load(tmp_path, public_seed(tls))
        assert [log for log in logs if log["event"] == "public_cert_unused"] == []

    def test_the_served_names_match_required_sans(self, tmp_path: Path) -> None:
        """The schema scans entries itself (renderer.sans would be an import cycle); the
        two must agree on which names are served."""
        seed = public_seed(
            ssh_upstreams=[ssh("a", f"a.{ZONE}:2222")],
            k8s_clusters=[k8s("prod", f"k8s.{ZONE}")],
            web_apps=[webapp("app", f"app.{ZONE}", f"alias.{ZONE}")],
        )
        state = load(tmp_path, seed)
        assert {s.name for s in _served_names(state)} == required_sans(state)


class TestOverlayLayer:
    """The same rules hold on seed + overlays (the API reaches them as 422)."""

    def test_an_overlay_adding_an_out_of_zone_resource_aborts_the_load(
        self, tmp_path: Path
    ) -> None:
        seed_path = tmp_path / "seed.yaml"
        seed_path.write_text(yaml.safe_dump(public_seed()), encoding="utf-8")
        store = OverlayStore(tmp_path / "overlays")
        store.add({"ssh_upstreams": [ssh("late", "late.example.net")]}, comment="x")

        with pytest.raises(ConfigLoadError) as exc:
            load_effective_state(seed_path, store)

        message = str(exc.value)
        assert "ssh_upstreams" in message
        assert "late" in message
        assert "address" in message

    def test_an_overlay_adding_a_covered_resource_loads(self, tmp_path: Path) -> None:
        seed_path = tmp_path / "seed.yaml"
        seed_path.write_text(yaml.safe_dump(public_seed()), encoding="utf-8")
        store = OverlayStore(tmp_path / "overlays")
        store.add({"ssh_upstreams": [ssh("late", f"late.{ZONE}")]}, comment="x")

        state, _ = load_effective_state(seed_path, store)

        assert [e.name for e in state.ssh_upstreams] == ["late"]


def test_effective_state_inherits_the_field() -> None:
    assert "public_tls" in EffectiveState.model_fields
