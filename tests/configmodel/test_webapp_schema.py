"""Tests for the web-app seed models: shape, defaults and model-level rules."""

from typing import Any

import pytest
from pydantic import ValidationError

from gwops.api.routes_state import _OVERLAY_ALLOWED_TOP_KEYS
from gwops.configmodel.schema import (
    AutomationSettings,
    CABundle,
    EffectiveState,
    SeedConfig,
    WebApp,
    WebAppDownstream,
    WebAppProxySettings,
)

SECRET = "s3cr3t-value-that-must-never-leak"


def seed(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"twingate": {"network": "acme", "gateway_id": "R2Vad2F5OjEyMw=="}}
    base.update(overrides)
    return base


def web_app(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"name": "grafana", "address": "grafana.apps.internal:3000"}
    base.update(overrides)
    return base


def message(exc: pytest.ExceptionInfo[ValidationError]) -> str:
    """The messages a caller can see: the str() form and every errors() msg."""
    return str(exc.value) + "\n" + "\n".join(err["msg"] for err in exc.value.errors())


class TestDownstream:
    def test_tls_defaults_to_tls13_and_port_to_none(self) -> None:
        d = WebAppDownstream()
        assert d.tls == "tls13"
        assert d.port is None

    def test_effective_port_follows_tls_when_unset(self) -> None:
        assert WebAppDownstream(tls="tls13").effective_port() == 443
        assert WebAppDownstream(tls="none").effective_port() == 80
        assert WebAppDownstream(tls="tls13", port=8443).effective_port() == 8443

    def test_unknown_tls_value_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            WebAppDownstream.model_validate({"tls": "tls12"})

    @pytest.mark.parametrize("port", [0, -1, 65536, 100000])
    def test_port_out_of_range_is_rejected(self, port: int) -> None:
        with pytest.raises(ValidationError):
            WebAppDownstream.model_validate({"port": port})

    @pytest.mark.parametrize("port", [1, 65535])
    def test_port_bounds_are_accepted(self, port: int) -> None:
        assert WebAppDownstream.model_validate({"port": port}).port == port

    def test_unknown_key_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            WebAppDownstream.model_validate({"tls": "tls13", "bogus": 1})


class TestWebAppDefaults:
    def test_defaults(self) -> None:
        app = WebApp.model_validate(web_app())
        assert app.alias is None
        assert app.upstream_tls == "verify_full"
        assert app.downstream.tls == "tls13"
        assert app.downstream.port is None
        assert app.request_headers is None
        assert app.access is None

    @pytest.mark.parametrize("mode", ["verify_full", "verify_ca", "insecure", "none"])
    def test_upstream_tls_values(self, mode: str) -> None:
        assert WebApp.model_validate(web_app(upstream_tls=mode)).upstream_tls == mode

    def test_unknown_upstream_tls_rejected(self) -> None:
        with pytest.raises(ValidationError):
            WebApp.model_validate(web_app(upstream_tls="tls12"))

    def test_unknown_key_rejected(self) -> None:
        with pytest.raises(ValidationError):
            WebApp.model_validate(web_app(bogus=1))

    def test_address_is_lowercased_like_other_kinds(self) -> None:
        assert WebApp.model_validate(web_app(address="Grafana.Apps.Internal")).address == (
            "grafana.apps.internal"
        )

    def test_default_port_is_443_unless_upstream_tls_none(self) -> None:
        assert WebApp.model_validate(web_app(address="wiki.internal")).default_port() == 443
        assert WebApp.model_validate(
            web_app(address="wiki.internal", upstream_tls="insecure")
        ).default_port() == 443
        assert WebApp.model_validate(
            web_app(address="wiki.internal", upstream_tls="none")
        ).default_port() == 80

    def test_upstream_port_uses_address_port_else_default(self) -> None:
        assert WebApp.model_validate(web_app()).upstream_port() == 3000
        assert WebApp.model_validate(web_app(address="wiki.internal")).upstream_port() == 443
        assert WebApp.model_validate(
            web_app(address="wiki.internal", upstream_tls="none")
        ).upstream_port() == 80

    def test_address_port_out_of_range_rejected(self) -> None:
        with pytest.raises(ValidationError, match="port must be 1-65535"):
            WebApp.model_validate(web_app(address="wiki.internal:70000"))
        with pytest.raises(ValidationError):
            WebApp.model_validate(web_app(address="wiki.internal:0"))


class TestSanNames:
    def test_san_names_is_host_only_without_alias(self) -> None:
        assert WebApp.model_validate(web_app()).san_names() == ["grafana.apps.internal"]

    def test_san_names_includes_alias(self) -> None:
        app = WebApp.model_validate(web_app(alias="Grafana.Corp.Example"))
        assert app.san_names() == ["grafana.apps.internal", "grafana.corp.example"]

    def test_ip_address_is_a_san_name_unchanged(self) -> None:
        app = WebApp.model_validate(web_app(address="10.1.2.3:8080"))
        assert app.san_names() == ["10.1.2.3"]


class TestTgExtras:
    def test_defaults_are_explicit_on_both_legs(self) -> None:
        extras = WebApp.model_validate(web_app()).tg_extras()
        assert dict(extras) == {
            "downstream_port": 443,
            "downstream_tls_mode": "TLS13",
            "upstream_tls_mode": "VERIFY_FULL",
            "alias": None,
            "request_header_rewrites": None,
        }

    def test_all_fields_map_to_the_tg_wire_values(self) -> None:
        app = WebApp.model_validate(
            web_app(
                alias="g.corp.example",
                upstream_tls="verify_ca",
                downstream={"tls": "none", "port": 8080},
                request_headers={"X-Team": "{{groups}}", "X-User": "{{username}}"},
            )
        )
        assert dict(app.tg_extras()) == {
            "downstream_port": 8080,
            "downstream_tls_mode": "NONE",
            "upstream_tls_mode": "VERIFY_CA",
            "alias": "g.corp.example",
            "request_header_rewrites": (("X-Team", "{{groups}}"), ("X-User", "{{username}}")),
        }

    def test_empty_headers_are_managed_empty_not_unmanaged(self) -> None:
        extras = WebApp.model_validate(web_app(request_headers={})).tg_extras()
        assert extras["request_header_rewrites"] == ()

    def test_extras_are_immutable(self) -> None:
        extras = WebApp.model_validate(web_app()).tg_extras()
        with pytest.raises(TypeError):
            extras["alias"] = "x"  # type: ignore[index]


class TestAlias:
    def test_alias_is_lowercased(self) -> None:
        assert WebApp.model_validate(web_app(alias="Wiki.Corp")).alias == "wiki.corp"

    def test_alias_equal_to_address_host_is_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebApp.model_validate(web_app(alias="grafana.apps.internal"))
        text = message(exc)
        assert "grafana" in text and "alias" in text and "address" in text

    def test_alias_equal_to_address_ignoring_case_and_port(self) -> None:
        with pytest.raises(ValidationError, match="alias"):
            WebApp.model_validate(web_app(alias="GRAFANA.apps.internal"))

    def test_alias_with_a_port_is_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebApp.model_validate(web_app(alias="g.corp.example:8443"))
        text = message(exc)
        assert "grafana" in text and "alias" in text and "port" in text

    @pytest.mark.parametrize("alias", ["*.corp.example", "g*.corp.example", "*"])
    def test_wildcard_alias_is_rejected(self, alias: str) -> None:
        with pytest.raises(ValidationError) as exc:
            WebApp.model_validate(web_app(alias=alias))
        text = message(exc)
        assert "grafana" in text and "alias" in text and "wildcard" in text

    @pytest.mark.parametrize("alias", ["", "has space.example", "a/b", "http://x"])
    def test_malformed_alias_is_rejected(self, alias: str) -> None:
        with pytest.raises(ValidationError, match="alias"):
            WebApp.model_validate(web_app(alias=alias))

    def test_null_alias_is_allowed(self) -> None:
        assert WebApp.model_validate(web_app(alias=None)).alias is None


class TestRequestHeaders:
    def test_valid_headers_accepted_and_order_preserved(self) -> None:
        app = WebApp.model_validate(
            web_app(request_headers={"X-B": "{{jwt}}", "Authorization": "Bearer {{jwt}}"})
        )
        assert app.request_headers == {"X-B": "{{jwt}}", "Authorization": "Bearer {{jwt}}"}
        assert list(app.request_headers or {}) == ["X-B", "Authorization"]

    @pytest.mark.parametrize(
        "name", ["Bad Header", "X:Y", "X/Y", "", "Xé", "(paren)", "a" * 65, "X\nY"]
    )
    def test_non_token_or_overlong_name_rejected(self, name: str) -> None:
        with pytest.raises(ValidationError) as exc:
            WebApp.model_validate(web_app(request_headers={name: "v"}))
        text = message(exc)
        assert "grafana" in text and "request_headers" in text

    @pytest.mark.parametrize("name", ["X-Team", "x_team", "A.b", "a" * 64, "X!#$%&'*+^`|~"])
    def test_token_names_accepted(self, name: str) -> None:
        assert WebApp.model_validate(web_app(request_headers={name: "v"})).request_headers

    def test_case_insensitive_duplicates_rejected_naming_both_spellings(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebApp.model_validate(
                web_app(request_headers={"X-Team": "a", "x-team": "b"})
            )
        text = message(exc)
        assert "grafana" in text and "request_headers" in text
        assert "X-Team" in text and "x-team" in text
        assert "duplicate" in text

    @pytest.mark.parametrize(
        "bad", ["a\rb", "a\nb", "a\r\nInjected: 1", "a\x00b", "a\x1fb", "a\x7fb", "a\tb"]
    )
    def test_control_characters_in_value_rejected_without_echo(self, bad: str) -> None:
        with pytest.raises(ValidationError) as exc:
            WebApp.model_validate(web_app(request_headers={"X-Team": bad}))
        text = message(exc)
        assert "grafana" in text and "request_headers" in text and "X-Team" in text
        assert "control character" in text
        assert "Injected" not in text

    def test_value_over_1024_chars_rejected_without_echo(self) -> None:
        value = SECRET + "x" * 1100
        with pytest.raises(ValidationError) as exc:
            WebApp.model_validate(web_app(request_headers={"X-Team": value}))
        text = message(exc)
        assert "grafana" in text and "request_headers" in text and "1024" in text
        assert SECRET not in text

    def test_value_of_exactly_1024_chars_accepted(self) -> None:
        app = WebApp.model_validate(web_app(request_headers={"X-Team": "x" * 1024}))
        assert app.request_headers is not None

    def test_non_string_value_error_does_not_echo_it(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebApp.model_validate(web_app(request_headers={"X-Team": 12345678}))
        assert "12345678" not in message(exc)

    def test_secret_value_never_appears_in_any_error_text(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebApp.model_validate(
                web_app(request_headers={"X-Team": SECRET + "\n", "x-team": SECRET})
            )
        text = message(exc)
        assert SECRET not in text
        assert SECRET not in repr(exc.value.errors(include_input=False))

    def test_secret_value_never_appears_when_loaded_through_the_seed(self) -> None:
        with pytest.raises(ValidationError) as exc:
            EffectiveState.model_validate(
                seed(web_apps=[web_app(request_headers={"X-Team": SECRET + "\r\n"})])
            )
        assert SECRET not in message(exc)

    def test_empty_value_is_left_to_the_policy_module(self) -> None:
        # Empty values are a policy rule, not a model one.
        app = WebApp.model_validate(web_app(request_headers={"X-Team": ""}))
        assert app.request_headers == {"X-Team": ""}


class TestProxySettings:
    def test_defaults(self) -> None:
        p = WebAppProxySettings()
        assert p.request_headers == {}
        assert p.upstream_ca_bundles == []
        assert p.plaintext_upstreams is None

    def test_full_shape(self) -> None:
        p = WebAppProxySettings.model_validate(
            {
                "request_headers": {
                    "X-Twingate-User": "{{username}}",
                    "X-Twingate-Groups": "{{groups}}",
                },
                "upstream_ca_bundles": [
                    {"name": "corp-root", "file": "/config/webapp-cas/corp-root.pem"}
                ],
                "plaintext_upstreams": {
                    "cidrs": ["127.0.0.1/32"],
                    "dns_suffixes": ["sidecar.internal"],
                },
            }
        )
        assert p.upstream_ca_bundles == [
            CABundle(name="corp-root", file="/config/webapp-cas/corp-root.pem")
        ]
        assert p.plaintext_upstreams is not None
        assert p.plaintext_upstreams.cidrs == ["127.0.0.1/32"]

    def test_unknown_key_rejected(self) -> None:
        with pytest.raises(ValidationError):
            WebAppProxySettings.model_validate({"bogus": 1})

    def test_gateway_wide_header_name_rules_apply(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebAppProxySettings.model_validate({"request_headers": {"Bad Name": "v"}})
        assert "web_app_proxy.request_headers" in message(exc)

    def test_gateway_wide_case_insensitive_duplicates_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebAppProxySettings.model_validate(
                {"request_headers": {"X-A": "1", "x-a": "2"}}
            )
        text = message(exc)
        assert "web_app_proxy.request_headers" in text and "X-A" in text and "x-a" in text

    def test_gateway_wide_control_char_and_length_rejected_without_echo(self) -> None:
        for value in (SECRET + "\n", SECRET + "x" * 1100):
            with pytest.raises(ValidationError) as exc:
                WebAppProxySettings.model_validate({"request_headers": {"X-A": value}})
            text = message(exc)
            assert "web_app_proxy.request_headers" in text and "X-A" in text
            assert SECRET not in text

    def test_ca_bundle_names_must_be_unique(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebAppProxySettings.model_validate(
                {
                    "upstream_ca_bundles": [
                        {"name": "corp", "file": "/config/webapp-cas/a.pem"},
                        {"name": "corp", "file": "/config/webapp-cas/b.pem"},
                    ]
                }
            )
        text = message(exc)
        assert "upstream_ca_bundles" in text and "corp" in text and "name" in text

    def test_ca_bundle_files_must_be_unique(self) -> None:
        with pytest.raises(ValidationError) as exc:
            WebAppProxySettings.model_validate(
                {
                    "upstream_ca_bundles": [
                        {"name": "one", "file": "/config/webapp-cas/a.pem"},
                        {"name": "two", "file": "/config/webapp-cas/./a.pem"},
                    ]
                }
            )
        text = message(exc)
        assert "upstream_ca_bundles" in text and "file" in text and "two" in text

    def test_ca_bundle_name_rules_follow_other_names(self) -> None:
        with pytest.raises(ValidationError, match="must match"):
            CABundle.model_validate({"name": "Bad Name", "file": "/config/webapp-cas/a.pem"})

    def test_ca_bundle_file_must_be_non_empty(self) -> None:
        with pytest.raises(ValidationError):
            CABundle.model_validate({"name": "corp", "file": ""})

    def test_ca_bundle_unknown_key_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CABundle.model_validate({"name": "a", "file": "/x", "cert_file": "/y"})


class TestSeedConfigWebApps:
    def test_webapp_seed_loads(self) -> None:
        cfg = SeedConfig.model_validate(
            seed(
                web_app_proxy={
                    "request_headers": {
                        "X-Twingate-User": "{{username}}",
                        "X-Twingate-Groups": "{{groups}}",
                    },
                    "upstream_ca_bundles": [
                        {"name": "corp-root", "file": "/config/webapp-cas/corp-root.pem"}
                    ],
                    "plaintext_upstreams": {
                        "cidrs": ["127.0.0.1/32"],
                        "dns_suffixes": ["sidecar.internal"],
                    },
                },
                web_apps=[
                    {
                        "name": "grafana",
                        "address": "grafana.apps.internal:3000",
                        "alias": "grafana.corp.example",
                        "upstream_tls": "verify_full",
                        "downstream": {"tls": "tls13"},
                        "request_headers": {"X-JWT-Assertion": "{{jwt}}"},
                        "access": {"groups": ["Grafana Users"]},
                    },
                    {
                        "name": "wiki",
                        "address": "wiki.apps.internal",
                        "request_headers": {"Authorization": "Bearer {{jwt}}"},
                    },
                ],
            )
        )
        grafana, wiki = cfg.web_apps
        assert grafana.alias == "grafana.corp.example"
        assert grafana.downstream.tls == "tls13"
        assert grafana.upstream_port() == 3000
        assert wiki.upstream_port() == 443
        assert wiki.downstream.tls == "tls13"  # default
        assert cfg.web_app_proxy.upstream_ca_bundles[0].name == "corp-root"

    def test_defaults_when_absent(self) -> None:
        cfg = SeedConfig.model_validate(seed())
        assert cfg.web_apps == []
        assert cfg.web_app_proxy == WebAppProxySettings()

    def test_duplicate_web_app_names_rejected(self) -> None:
        with pytest.raises(ValidationError, match="duplicate web_apps name"):
            SeedConfig.model_validate(
                seed(web_apps=[web_app(), web_app(address="other.internal")])
            )

    def test_effective_state_has_the_same_shape(self) -> None:
        state = EffectiveState.model_validate(seed(web_apps=[web_app()]))
        assert state.web_apps[0].name == "grafana"


class TestAutomationWebApps:
    def test_defaults_are_off_and_empty(self) -> None:
        a = AutomationSettings()
        assert a.web_apps.enabled is False
        assert a.web_apps.request_header_names == []

    def test_seed_shape(self) -> None:
        cfg = SeedConfig.model_validate(
            seed(
                admin_api={
                    "automation": {
                        "name_prefix": "auto-",
                        "web_apps": {"enabled": True, "request_header_names": ["X-Team", "X-Env"]},
                    }
                }
            )
        )
        auto = cfg.admin_api.automation
        assert auto.name_prefix == "auto-"
        assert auto.web_apps.enabled is True
        assert auto.web_apps.request_header_names == ["X-Team", "X-Env"]

    def test_unknown_key_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AutomationSettings.model_validate({"web_apps": {"enabled": True, "bogus": 1}})

    def test_names_are_case_insensitively_unique(self) -> None:
        with pytest.raises(ValidationError) as exc:
            AutomationSettings.model_validate(
                {"web_apps": {"request_header_names": ["X-Team", "x-team"]}}
            )
        text = message(exc)
        assert "automation.web_apps.request_header_names" in text
        assert "X-Team" in text and "x-team" in text

    @pytest.mark.parametrize("name", ["Bad Header", "", "X:Y", "a" * 65, "X\nY"])
    def test_names_must_be_tokens(self, name: str) -> None:
        with pytest.raises(ValidationError) as exc:
            AutomationSettings.model_validate({"web_apps": {"request_header_names": [name]}})
        assert "automation.web_apps.request_header_names" in message(exc)


class TestOverlayAllowlist:
    def test_web_app_proxy_is_seed_only(self) -> None:
        assert "web_app_proxy" not in _OVERLAY_ALLOWED_TOP_KEYS

    def test_reject_helper_returns_422_for_web_app_proxy(self) -> None:
        from fastapi import HTTPException

        from gwops.api.routes_state import _reject_forbidden_overlay_keys

        with pytest.raises(HTTPException) as exc:
            _reject_forbidden_overlay_keys({"web_app_proxy": {"request_headers": {}}})
        assert exc.value.status_code == 422
        assert "web_app_proxy" in str(exc.value.detail)
