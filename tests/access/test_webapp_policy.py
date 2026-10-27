"""Tests for gwops.access.webapp_policy; no message may carry a header value or PEM content."""

import ast
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from gwops.access import webapp_policy
from gwops.access.webapp_policy import (
    FieldViolation,
    automation_field_violations,
    is_denied_header_name,
    pem_violations,
    trusted_gateway_header_names,
    violations,
    warnings,
)
from gwops.configmodel.schema import EffectiveState, WebApp
from gwops.renderer.capabilities import Capabilities

CAPS = Capabilities()
SECRET = "Zx9Qp4Lm7Vb2Nc5Rt8Yh3Wk6Jd1Fs0Ga"  # 33 chars, mixed case + digits: high entropy
NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


def make_state(
    web_apps: list[dict[str, Any]] | None = None,
    proxy: dict[str, Any] | None = None,
    automation: dict[str, Any] | None = None,
) -> EffectiveState:
    data: dict[str, Any] = {
        "twingate": {"network": "acme", "gateway_id": "R2Vad2F5OjEyMw=="},
        "web_apps": web_apps or [],
    }
    if proxy is not None:
        data["web_app_proxy"] = proxy
    if automation is not None:
        data["admin_api"] = {"automation": {"web_apps": automation}}
    return EffectiveState.model_validate(data)


def app(name: str = "grafana", **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"name": name, "address": "grafana.apps.internal:3000"}
    base.update(overrides)
    return base


def check(
    web_apps: list[dict[str, Any]] | None = None,
    proxy: dict[str, Any] | None = None,
    automation: dict[str, Any] | None = None,
    caps: Capabilities = CAPS,
) -> list[str]:
    return violations(make_state(web_apps, proxy, automation), caps)


def assert_no_value(messages: list[str], value: str = SECRET) -> None:
    assert not any(value in m for m in messages), messages


def test_clean_state_has_no_violations() -> None:
    assert check() == []
    headers = {"X-Twingate-User": "{{username}}", "Authorization": "Bearer {{jwt}}"}
    assert check([app(request_headers=headers)]) == []


DENIED = [
    "Connection",
    "Keep-Alive",
    "Proxy-Authorization",
    "Proxy-Connection",
    "TE",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
    "Content-Length",
    "Expect",
    "Forwarded",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "Via",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-HTTP-Method-Override",
    "Cookie",
    "Host",
]


@pytest.mark.parametrize("name", DENIED)
def test_denied_names_are_refused_per_resource(name: str) -> None:
    result = check([app(request_headers={name: "{{username}}"})])
    assert len(result) == 1
    assert "'grafana'" in result[0] and "request_headers" in result[0] and name in result[0]
    assert "denied" in result[0]


@pytest.mark.parametrize("name", ["host", "COOKIE", "x-forwarded-for", "X-FORWARDED-PROTO"])
def test_denied_names_are_case_insensitive(name: str) -> None:
    assert is_denied_header_name(name)
    assert check([app(request_headers={name: "{{username}}"})]) != []


@pytest.mark.parametrize("name", ["X_Forwarded_For", "Transfer_Encoding", "Proxy_Foo"])
def test_denied_names_include_underscore_variants(name: str) -> None:
    assert is_denied_header_name(name)


def test_denied_names_are_refused_gateway_wide() -> None:
    result = check(proxy={"request_headers": {"Host": "{{username}}"}})
    assert len(result) == 1
    assert "web_app_proxy.request_headers" in result[0] and "'Host'" in result[0]


@pytest.mark.parametrize("name", ["X-Twingate-User", "Authorization", "X-Forward", "Proxy", "TEA"])
def test_ordinary_names_are_not_denied(name: str) -> None:
    assert not is_denied_header_name(name)


@pytest.mark.parametrize(
    "value",
    [
        "{{username}}",
        "{{ username }}",
        "{{  groups  }}",
        "Bearer {{jwt}}",
        "pre-{{jwt}}-post",
        "{{clientGeoCity}}",
        "{{clientGeoLatLong}}",
        "{{clientGeoRegion}}",
        "{{clientGeoCountry}}",
        "plain-static",
        "x",
    ],
)
def test_valid_values_pass(value: str) -> None:
    assert check([app(request_headers={"X-Thing": value})]) == []


def test_two_keys_refused() -> None:
    result = check([app(request_headers={"X-Thing": "{{username}}{{groups}}"})])
    assert len(result) == 1 and "X-Thing" in result[0] and "template" in result[0]


@pytest.mark.parametrize(
    "value",
    [
        "a{b{{username}}",  # brace in prefix
        "{{username}}c}d",  # brace in suffix
        "{{username}",  # unbalanced
        "{username}",  # single braces
        "{{ user name }}",  # space inside the key
        "{{}}",  # empty key
        "{{user.name}}",  # character outside [a-zA-Z0-9_-]
        "x}",
        "{{username}} {{groups}}",
    ],
)
def test_malformed_templates_refused(value: str) -> None:
    result = check([app(request_headers={"X-Thing": value})])
    assert len(result) == 1 and "template" in result[0], result


def test_unknown_key_refused_and_supported_keys_listed() -> None:
    result = check([app(request_headers={"X-Thing": "{{email}}"})])
    assert len(result) == 1
    assert "X-Thing" in result[0] and "does not support" in result[0]
    assert "username" in result[0]  # the supported set is shown
    assert "email" not in result[0]  # the offending key is not echoed


@pytest.mark.parametrize("value", ["{{JWT}}", "{{Username}}", "{{clientgeocity}}", "{{GROUPS}}"])
def test_template_keys_are_case_sensitive(value: str) -> None:
    assert len(check([app(request_headers={"X-Thing": value})])) == 1


def test_key_must_be_in_the_capability_set() -> None:
    narrow = Capabilities(web_app_template_keys=frozenset({"username"}))
    assert check([app(request_headers={"X-Thing": "{{groups}}"})], caps=narrow) != []
    assert check([app(request_headers={"X-Thing": "{{username}}"})], caps=narrow) == []


def test_unknown_key_refused_gateway_wide() -> None:
    result = check(proxy={"request_headers": {"X-Thing": "{{email}}"}})
    assert len(result) == 1 and "web_app_proxy.request_headers" in result[0]


@pytest.mark.parametrize("value", ["", "   ", " "])
def test_empty_values_refused(value: str) -> None:
    result = check([app(request_headers={"X-Thing": value})])
    assert len(result) == 1 and "X-Thing" in result[0] and "empty" in result[0]


def test_empty_gateway_wide_value_refused() -> None:
    result = check(proxy={"request_headers": {"X-Thing": ""}})
    assert len(result) == 1 and "empty" in result[0]


@pytest.mark.parametrize(
    "name", ["Authorization", "X-Api-Key", "X-Auth-Token", "X-Secret", "X-Password-Hint"]
)
def test_static_value_under_secret_name_refused(name: str) -> None:
    result = check([app(request_headers={name: "hunter2"})])
    assert len(result) == 1 and "static" in result[0] and name in result[0]
    assert_no_value(result, "hunter2")


def test_template_under_secret_name_is_fine() -> None:
    assert check([app(request_headers={"Authorization": "Bearer {{jwt}}"})]) == []
    assert check([app(request_headers={"X-Api-Key": "{{username}}"})]) == []


@pytest.mark.parametrize(
    "value",
    [
        SECRET,
        "ghp" + "_O7wfYlSTwuJQEyAxLOnalGDL3kQz9",  # split so secret scanners skip it
        "0123456789abcdef0123456789abcdef",  # 32 hex
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk",
    ],
)
def test_high_entropy_static_refused(value: str) -> None:
    result = check([app(request_headers={"X-Thing": value})])
    assert len(result) == 1 and "X-Thing" in result[0] and "secret" in result[0]
    assert_no_value(result, value)


@pytest.mark.parametrize(
    "value",
    [
        "production-environment",
        "acme-corp-internal-apps-2",
        "grafana.apps.internal:3000",
        "https://internal.example.com/some/path",
        "mozilla/5.0 compatible",
        "some-long-descriptive-value",
        "short",
        "a" * 40,
        "12345678901234567890",
    ],
)
def test_ordinary_static_values_pass(value: str) -> None:
    assert check([app(request_headers={"X-Thing": value})]) == []


def test_high_entropy_prefix_or_suffix_of_a_template_refused() -> None:
    assert len(check([app(request_headers={"X-Thing": SECRET + "{{username}}"})])) == 1
    assert len(check([app(request_headers={"X-Thing": "{{username}}" + SECRET})])) == 1
    assert check([app(request_headers={"X-Thing": "Bearer {{jwt}}"})]) == []


def test_static_secret_refused_gateway_wide() -> None:
    result = check(proxy={"request_headers": {"X-Thing": SECRET}})
    assert len(result) == 1 and "web_app_proxy.request_headers" in result[0]
    assert_no_value(result)


TRUSTED_PROXY = {
    "request_headers": {
        "X-Twingate-User": "{{username}}",
        "X-Twingate-Groups": "{{groups}}",
        "X-Geo": "{{clientGeoCity}}",
    }
}


def test_trusted_names_are_those_whose_template_uses_identity_keys() -> None:
    state = make_state(proxy=TRUSTED_PROXY)
    assert trusted_gateway_header_names(state) == frozenset(
        {"X-Twingate-User", "X-Twingate-Groups"}
    )


def test_trusted_name_refused_per_resource_but_untrusted_gateway_name_allowed() -> None:
    result = check([app(request_headers={"X-Twingate-User": "someone"})], TRUSTED_PROXY)
    assert len(result) == 1
    assert "'grafana'" in result[0] and "X-Twingate-User" in result[0] and "trusted" in result[0]
    assert check([app(request_headers={"X-Geo": "override"})], TRUSTED_PROXY) == []


@pytest.mark.parametrize(
    "name", ["x-twingate-user", "X_Twingate_User", "x_TWINGATE_user", "X-TWINGATE-USER"]
)
def test_trusted_name_variants_refused(name: str) -> None:
    result = check([app(request_headers={name: "someone"})], TRUSTED_PROXY)
    assert len(result) == 1 and "trusted" in result[0]


def test_trusted_name_given_with_underscores_gateway_wide_blocks_hyphen_form() -> None:
    proxy = {"request_headers": {"X_Twingate_User": "{{username}}"}}
    assert check([app(request_headers={"X-Twingate-User": "someone"})], proxy) != []


def test_gateway_jwt_refused() -> None:
    result = check(proxy={"request_headers": {"Authorization": "Bearer {{jwt}}"}})
    assert len(result) == 1
    assert "web_app_proxy.request_headers" in result[0] and "Authorization" in result[0]
    assert "jwt" in result[0]
    # per-resource jwt is the supported form
    assert check([app(request_headers={"Authorization": "Bearer {{jwt}}"})]) == []


def test_gateway_jwt_name_still_counts_as_trusted() -> None:
    proxy = {"request_headers": {"X-Token": "{{jwt}}"}}
    state = make_state(proxy=proxy)
    assert trusted_gateway_header_names(state) == frozenset({"X-Token"})


PLAINTEXT = {
    "plaintext_upstreams": {"cidrs": ["10.20.0.0/16"], "dns_suffixes": ["legacy.internal"]}
}


@pytest.mark.parametrize("mode", ["insecure", "none"])
def test_plaintext_modes_need_plaintext_upstreams(mode: str) -> None:
    result = check([app(address="10.20.0.5:8080", upstream_tls=mode)])
    assert len(result) == 1 and "upstream_tls" in result[0] and "plaintext_upstreams" in result[0]
    assert "'grafana'" in result[0]
    assert check([app(address="10.20.0.5:8080", upstream_tls=mode)], PLAINTEXT) == []


@pytest.mark.parametrize("mode", ["insecure", "none"])
def test_plaintext_modes_refused_outside_the_allowlist(mode: str) -> None:
    assert check([app(address="10.30.0.5", upstream_tls=mode)], PLAINTEXT) != []
    assert check([app(address="evil-legacy.internal", upstream_tls=mode)], PLAINTEXT) != []
    assert check([app(address="db.legacy.internal", upstream_tls=mode)], PLAINTEXT) == []
    assert check([app(address="legacy.internal", upstream_tls=mode)], PLAINTEXT) == []


def test_empty_plaintext_allowlist_allows_nothing() -> None:
    proxy = {"plaintext_upstreams": {}}
    assert check([app(address="10.20.0.5", upstream_tls="none")], proxy) != []


def test_verify_modes_need_no_allowlist() -> None:
    for mode in ("verify_full", "verify_ca"):
        assert check([app(upstream_tls=mode)]) == []


def test_none_with_jwt_refused_unless_loopback() -> None:
    headers = {"Authorization": "Bearer {{jwt}}"}
    remote = check(
        [app(address="10.20.0.5", upstream_tls="none", request_headers=headers)], PLAINTEXT
    )
    assert len(remote) == 1
    assert "none" in remote[0] and "jwt" in remote[0] and "Authorization" in remote[0]
    assert "loopback" in remote[0]
    proxy = {"plaintext_upstreams": {"cidrs": ["127.0.0.0/8"], "dns_suffixes": ["localhost"]}}
    for host in ("127.0.0.1", "127.8.9.1", "localhost"):
        entry = app(address=host, upstream_tls="none", request_headers=headers)
        assert check([entry], proxy) == [], host


@pytest.mark.parametrize("mode", ["verify_ca", "insecure"])
def test_unverified_modes_with_jwt_refused_unless_loopback(mode: str) -> None:
    headers = {"Authorization": "Bearer {{jwt}}"}
    entry = app(address="10.20.0.5", upstream_tls=mode, request_headers=headers)
    remote = check([entry], PLAINTEXT)
    assert len(remote) == 1
    assert mode in remote[0] and "jwt" in remote[0] and "Authorization" in remote[0]
    assert "loopback" in remote[0] and "'grafana'" in remote[0]
    proxy = {"plaintext_upstreams": {"cidrs": ["127.0.0.0/8"], "dns_suffixes": ["localhost"]}}
    for host in ("127.0.0.1", "localhost"):
        entry = app(address=host, upstream_tls=mode, request_headers=headers)
        assert check([entry], proxy) == [], host


@pytest.mark.parametrize("mode", ["verify_ca", "insecure"])
def test_unverified_modes_refuse_a_gateway_wide_jwt_header_too(mode: str) -> None:
    proxy = {**PLAINTEXT, "request_headers": {"Authorization": "Bearer {{jwt}}"}}
    result = check([app(address="10.20.0.5", upstream_tls=mode)], proxy)
    assert any(mode in m and "loopback" in m and "Authorization" in m for m in result), result


def test_verify_full_with_jwt_is_allowed() -> None:
    headers = {"Authorization": "Bearer {{jwt}}"}
    assert check([app(address="10.20.0.5", request_headers=headers)]) == []


@pytest.mark.parametrize("mode", ["verify_ca", "insecure"])
def test_unverified_modes_without_jwt_are_not_affected_by_the_jwt_rule(mode: str) -> None:
    entry = app(address="10.20.0.5", upstream_tls=mode, request_headers={"X-U": "{{username}}"})
    assert check([entry], PLAINTEXT) == []


def test_four_separators_in_a_trusted_name_are_allowed() -> None:
    proxy = {"request_headers": {"X-A-B-C-D": "{{username}}"}}
    assert check(proxy=proxy) == []


@pytest.mark.parametrize("name", ["X-A-B-C-D-E", "X_A_B_C_D_E", "X-Twingate_User-Id-Of-Me"])
def test_more_than_four_separators_in_a_trusted_name_is_a_violation(name: str) -> None:
    result = check(proxy={"request_headers": {name: "{{username}}"}})
    assert len(result) == 1
    assert "web_app_proxy.request_headers" in result[0] and name in result[0]
    assert "more than 4 separators" in result[0]


def test_the_separator_limit_only_applies_to_trusted_names() -> None:
    proxy = {"request_headers": {"X-A-B-C-D-E-F": "{{clientGeoCity}}"}}
    assert check(proxy=proxy) == []


def test_none_without_jwt_to_remote_host_passes() -> None:
    entry = app(address="10.20.0.5", upstream_tls="none", request_headers={"X-U": "{{username}}"})
    assert check([entry], PLAINTEXT) == []


def test_warnings_surface_separately_from_violations() -> None:
    state = make_state(
        [
            app("a", upstream_tls="verify_ca"),
            app("b", address="10.20.0.5", upstream_tls="insecure"),
            app("c", address="10.20.0.6", upstream_tls="none", downstream={"tls": "none"}),
            app("d"),
        ],
        PLAINTEXT,
    )
    assert violations(state, CAPS) == []
    found = warnings(state)
    assert any("'a'" in w and "verify_ca" in w for w in found)
    assert any("'b'" in w and "insecure" in w for w in found)
    assert any("'c'" in w and "upstream_tls" in w and "none" in w for w in found)
    assert any("'c'" in w and "downstream.tls" in w for w in found)
    assert not any("'d'" in w for w in found)


def test_no_warnings_for_defaults() -> None:
    assert warnings(make_state([app()])) == []


def test_automation_header_names_with_denied_or_trusted_name_refused() -> None:
    denied = check(automation={"enabled": True, "request_header_names": ["Host"]})
    assert len(denied) == 1
    assert "admin_api.automation.web_apps.request_header_names" in denied[0]
    assert "'Host'" in denied[0] and "denied" in denied[0]
    trusted = check(
        proxy=TRUSTED_PROXY,
        automation={"enabled": True, "request_header_names": ["x_twingate_user"]},
    )
    assert len(trusted) == 1 and "trusted" in trusted[0]
    ok = check(
        proxy=TRUSTED_PROXY, automation={"enabled": True, "request_header_names": ["X-Debug"]}
    )
    assert ok == []


def test_automation_header_names_checked_even_when_not_enabled() -> None:
    assert check(automation={"enabled": False, "request_header_names": ["Cookie"]}) != []


def test_no_message_ever_carries_a_value() -> None:
    state = make_state(
        [
            app(
                "bad",
                address="10.30.0.5",
                upstream_tls="none",
                request_headers={
                    "Host": SECRET,
                    "X-Twingate-User": SECRET,
                    "X-Static": SECRET,
                    "Authorization": SECRET,
                    "X-Tpl": "{{" + SECRET + "}}",
                    "X-Two": SECRET + "{{username}}{{groups}}",
                    "X-Brace": "{" + SECRET,
                    "X-Jwt": "Bearer {{jwt}}" + SECRET,
                },
            )
        ],
        {
            "request_headers": {
                "X-Twingate-User": "{{username}}",
                "X-Gw-Secret": SECRET,
                "X-Gw-Tpl": "{{" + SECRET + "}}",
                "X-Gw-Jwt": "{{jwt}}",
            }
        },
        {"enabled": True, "request_header_names": ["Host"]},
    )
    found = violations(state, CAPS) + warnings(state)
    assert len(found) >= 10
    assert_no_value(found)
    assert_no_value(found, "{{" + SECRET)


def make_cert(
    *,
    ca: bool | None = True,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    cn: str = "test-ca",
) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - timedelta(days=1))
        .not_valid_after(not_after or NOW + timedelta(days=365))
    )
    if ca is not None:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def make_key_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def test_valid_bundle_passes() -> None:
    assert pem_violations("corp", make_cert(), NOW) == []
    assert pem_violations("corp", make_cert() + b"\n\n  \n" + make_cert(), NOW) == []
    assert pem_violations("corp", b"\r\n" + make_cert() + b"\r\n", NOW) == []


def test_empty_bundle_refused() -> None:
    for data in (b"", b"   \n"):
        result = pem_violations("corp", data, NOW)
        assert len(result) == 1 and "'corp'" in result[0] and "no CERTIFICATE" in result[0]


def test_non_pem_text_refused() -> None:
    result = pem_violations("corp", b"this is not a certificate " + SECRET.encode(), NOW)
    assert result != [] and all("'corp'" in m for m in result)
    assert_no_value(result)


def test_binary_der_refused() -> None:
    der = x509.load_pem_x509_certificate(make_cert()).public_bytes(serialization.Encoding.DER)
    result = pem_violations("corp", der, NOW)
    assert result != [] and all("'corp'" in m for m in result)


def test_private_key_block_refused() -> None:
    key = make_key_pem()
    result = pem_violations("corp", make_cert() + key, NOW)
    assert len(result) == 1 and "private key" in result[0]
    assert_no_value(result, key.decode().splitlines()[1])


def test_key_only_bundle_refused() -> None:
    result = pem_violations("corp", make_key_pem(), NOW)
    assert any("private key" in m for m in result)
    assert any("no CERTIFICATE" in m for m in result)


def test_other_block_types_refused() -> None:
    cert = make_cert().decode()
    csr_like = cert.replace("CERTIFICATE", "CERTIFICATE REQUEST")
    result = pem_violations("corp", make_cert() + csr_like.encode(), NOW)
    assert len(result) == 1 and "non-CERTIFICATE" in result[0]


def test_junk_outside_blocks_refused_without_echo() -> None:
    junk = b"# my comment " + SECRET.encode() + b"\n"
    for data in (junk + make_cert(), make_cert() + junk, make_cert() + junk + make_cert()):
        result = pem_violations("corp", data, NOW)
        assert len(result) == 1 and "outside" in result[0], result
        assert_no_value(result)


def test_unterminated_block_refused() -> None:
    truncated = make_cert().decode().rsplit("-----END", 1)[0].encode()
    result = pem_violations("corp", make_cert() + truncated, NOW)
    assert len(result) == 1 and "outside" in result[0]


def test_unparseable_certificate_names_its_position() -> None:
    bad = b"-----BEGIN CERTIFICATE-----\nAAAAAAAA\n-----END CERTIFICATE-----\n"
    result = pem_violations("corp", make_cert() + bad, NOW)
    assert len(result) == 1 and "certificate #2" in result[0] and "parse" in result[0]


def test_ca_false_refused() -> None:
    result = pem_violations("corp", make_cert(ca=False), NOW)
    assert len(result) == 1 and "CA:TRUE" in result[0] and "'corp'" in result[0]


def test_missing_basic_constraints_refused() -> None:
    result = pem_violations("corp", make_cert(ca=None), NOW)
    assert len(result) == 1 and "BasicConstraints" in result[0]


def make_duplicate_basic_constraints_cert() -> bytes:
    """A certificate whose DER carries BasicConstraints twice (the builder refuses to)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    decoy = x509.ObjectIdentifier("2.5.29.99")
    basic_constraints_der = bytes.fromhex("3003010100")
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(x509.UnrecognizedExtension(decoy, basic_constraints_der), True)
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    decoy_oid = bytes.fromhex("0603551d63")
    assert der.count(decoy_oid) == 1
    patched = der.replace(decoy_oid, bytes.fromhex("0603551d13"))
    return x509.load_der_x509_certificate(patched).public_bytes(serialization.Encoding.PEM)


def test_duplicate_extensions_are_refused_not_raised() -> None:
    cert = make_duplicate_basic_constraints_cert()
    with pytest.raises(x509.DuplicateExtension):
        _ = x509.load_pem_x509_certificate(cert).extensions
    result = pem_violations("corp", cert, NOW)
    assert len(result) == 1
    assert "certificate #1" in result[0] and "malformed or duplicate extensions" in result[0]
    assert "'corp'" in result[0]


def test_extension_parse_error_of_any_kind_is_refused_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Broken:
        not_valid_after_utc = NOW
        not_valid_before_utc = NOW

        @property
        def extensions(self) -> None:
            raise x509.UnsupportedGeneralNameType("bad name", 9)

    monkeypatch.setattr(x509, "load_pem_x509_certificate", lambda _data: Broken())
    result = pem_violations("corp", make_cert(), NOW)
    assert len(result) == 1 and "malformed or duplicate extensions" in result[0]


def test_expired_refused() -> None:
    cert = make_cert(not_before=NOW - timedelta(days=400), not_after=NOW - timedelta(days=1))
    result = pem_violations("corp", cert, NOW)
    assert len(result) == 1 and "expired" in result[0]


def test_not_yet_valid_refused() -> None:
    cert = make_cert(not_before=NOW + timedelta(days=1), not_after=NOW + timedelta(days=30))
    result = pem_violations("corp", cert, NOW)
    assert len(result) == 1 and "not yet valid" in result[0]


def test_every_failing_certificate_is_reported() -> None:
    bundle = make_cert(ca=False) + make_cert() + make_cert(ca=None)
    result = pem_violations("corp", bundle, NOW)
    assert len(result) == 2
    assert "certificate #1" in result[0] and "certificate #3" in result[1]


def test_pem_messages_never_carry_subject_or_contents() -> None:
    bundle = make_cert(ca=False, cn=SECRET)
    result = pem_violations("corp", bundle, NOW)
    assert result != []
    assert_no_value(result)
    body = bundle.decode().splitlines()[1]
    assert_no_value(result, body)


AUTO = {"enabled": True, "request_header_names": ["X-Debug", "X-Team"]}


def entry(**overrides: Any) -> WebApp:
    return WebApp.model_validate(app("auto-grafana", **overrides))


def auto_check(candidate: WebApp, automation: dict[str, Any] | None = AUTO) -> list[FieldViolation]:
    return automation_field_violations(candidate, make_state(automation=automation))


def test_field_violation_is_a_frozen_dataclass() -> None:
    fv = FieldViolation("upstream_tls", "why")
    assert (fv.field, fv.reason) == ("upstream_tls", "why")
    with pytest.raises(AttributeError):
        fv.field = "x"  # type: ignore[misc]


def test_default_entry_is_allowed() -> None:
    assert auto_check(entry()) == []


def test_upstream_tls_only_verify_full() -> None:
    assert auto_check(entry(upstream_tls="verify_full")) == []
    for mode in ("verify_ca", "insecure", "none"):
        result = auto_check(entry(upstream_tls=mode))
        assert result == [
            FieldViolation("upstream_tls", "only verify_full is allowed for the automation token")
        ]


def test_downstream_modes_and_port_are_allowed() -> None:
    assert auto_check(entry(downstream={"tls": "tls13", "port": 8443})) == []
    assert auto_check(entry(downstream={"tls": "none", "port": 80})) == []


def test_alias_and_address_are_not_this_functions_business() -> None:
    assert auto_check(entry(alias="grafana.alt.internal")) == []
    assert auto_check(entry(alias=None)) == []


@pytest.mark.parametrize("headers", [None, {}])
def test_request_headers_absent_null_or_empty_always_allowed(headers: Any) -> None:
    assert auto_check(entry(request_headers=headers), automation={"enabled": True}) == []


def test_request_headers_allowlisted_names_pass_case_insensitively() -> None:
    assert auto_check(entry(request_headers={"x-debug": "on", "X-TEAM": "platform"})) == []


def test_request_header_name_not_in_allowlist_refused() -> None:
    result = auto_check(entry(request_headers={"X-Other": "on"}))
    assert result == [
        FieldViolation(
            "request_headers.X-Other",
            "header name not in admin_api.automation.web_apps.request_header_names",
        )
    ]


def test_every_header_outside_the_allowlist_is_listed() -> None:
    result = auto_check(
        entry(request_headers={"X-A": "1", "X-Debug": "on", "X-B": "2"}),
    )
    assert [v.field for v in result] == ["request_headers.X-A", "request_headers.X-B"]


def test_empty_allowlist_means_no_names() -> None:
    result = auto_check(
        entry(request_headers={"X-Debug": "on"}), {"enabled": True, "request_header_names": []}
    )
    assert [v.field for v in result] == ["request_headers.X-Debug"]


@pytest.mark.parametrize(
    "value", ["Bearer {{jwt}}", "{{jwt}}", "{{ jwt }}", "x{{jwt}}y", "{{JWT}}", "{{ Jwt }}"]
)
def test_jwt_value_refused_even_for_an_allowlisted_name(value: str) -> None:
    result = auto_check(entry(request_headers={"X-Debug": value}))
    assert result == [
        FieldViolation(
            "request_headers.X-Debug",
            "the jwt template key is not allowed for the automation token",
        )
    ]


def test_other_templates_allowed_for_an_allowlisted_name() -> None:
    assert auto_check(entry(request_headers={"X-Debug": "{{username}}"})) == []


def test_name_and_jwt_violations_both_reported() -> None:
    result = auto_check(entry(request_headers={"X-Other": "{{jwt}}"}))
    assert [v.field for v in result] == ["request_headers.X-Other"] * 2
    assert len({v.reason for v in result}) == 2


def test_denied_or_trusted_name_refused_even_if_somehow_allowlisted() -> None:
    # Load-time validation forbids this seed; the function does not rely on it.
    state = make_state(
        proxy=TRUSTED_PROXY,
        automation={"enabled": True, "request_header_names": ["X-Twingate-User", "Host"]},
    )
    result = automation_field_violations(
        entry(request_headers={"X-Twingate-User": "x", "Host": "y"}), state
    )
    assert [v.field for v in result] == ["request_headers.X-Twingate-User", "request_headers.Host"]


def test_every_violation_listed_and_no_value_echoed() -> None:
    result = auto_check(
        entry(
            upstream_tls="none",
            request_headers={"X-Other": SECRET, "X-Debug": "Bearer {{jwt}}" + SECRET},
        )
    )
    assert [v.field for v in result] == [
        "upstream_tls",
        "request_headers.X-Other",
        "request_headers.X-Debug",
    ]
    assert_no_value([f"{v.field} {v.reason}" for v in result])


FORBIDDEN_MODULES = ("gwops.kinds", "gwops.tgapi", "gwops.access.allowlist")


def test_importing_the_module_loads_no_forbidden_module() -> None:
    code = (
        "import sys\n"
        "import gwops.access.webapp_policy\n"
        f"bad = [m for m in {FORBIDDEN_MODULES!r} "
        "if m in sys.modules or any(k.startswith(m + '.') for k in sys.modules)]\n"
        "print(','.join(bad))\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=60
    )
    assert done.stdout.strip() == "", done.stdout


def test_source_has_no_forbidden_import() -> None:
    tree = ast.parse(Path(webapp_policy.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
            imported.update(f"{node.module}.{alias.name}" for alias in node.names)
    for forbidden in FORBIDDEN_MODULES:
        assert not any(i == forbidden or i.startswith(forbidden + ".") for i in imported), forbidden
