"""`gwops.acme.lego.build_argv`: the lego command line and child environment.

The function is pure, so every test builds the argv and environment from literals. Sentinel
values stand in for host credentials; none may reach argv, and only the two token-file
variables may carry Cloudflare configuration into the child's environment.
"""

import itertools
from pathlib import Path
from typing import Any

import pytest

from gwops.acme import lego as lego_module
from gwops.acme.lego import (
    KEY_TYPE,
    LEGO_ENV_STRIP_NAMES,
    LEGO_ENV_STRIP_PREFIXES,
    TOKEN_ENV_VARS,
    build_argv,
)
from gwops.configmodel.schema import AcmePublicCertificate, AcmeSettings
from gwops.settings import GwopsSettings
from gwops.supervisor.childenv import child_env

STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
PRODUCTION_URL = "https://acme-v02.api.letsencrypt.org/directory"
TOKEN_FILE = "/config/acme/cloudflare-token"
STAGING_PATH = "/data/acme/lego/acme-staging-v02.api.letsencrypt.org"
PRODUCTION_PATH = "/data/acme/lego/acme-v02.api.letsencrypt.org"

EXPECTED_DEFAULT_ARGV = [
    "/usr/local/bin/lego",
    "--log.format", "json",
    "--log.level", "info",
    "run",
    "--path", STAGING_PATH,
    "--server", STAGING_URL,
    "--email", "ops@example.com",
    "--accept-tos",
    "--dns", "cloudflare",
    "--dns.propagation.disable-ans",
    "--key-type", "EC256",
    "--cert.name=wildcard",
    "--domains=*.example.com",
    "--force-cert-domains",
    "--no-random-sleep",
]  # fmt: skip

# Stand-in values for credentials in the host environment; none may leak.
_SENTINEL_TOKEN = "sentinel-cf-token-0123456789"
_SENTINEL_KEY = "sentinel-global-api-key-9876543210"
_SENTINEL_TWINGATE = "sentinel-twingate-api-key"
_SENTINEL_ADMIN = "sentinel-admin-token"

_HOST_ENV: dict[str, str] = {
    "PATH": "/usr/local/bin:/usr/bin",
    "HOME": "/home/gwops",
    "LANG": "C.UTF-8",
    "HTTPS_PROXY": "http://proxy.internal:3128",
    "https_proxy": "http://proxy.internal:3128",
    "HTTP_PROXY": "http://proxy.internal:3128",
    "NO_PROXY": "localhost,127.0.0.1",
    "SSL_CERT_FILE": "/etc/ssl/certs/ca.pem",
    "CF_API_KEY": _SENTINEL_KEY,
    "CF_API_EMAIL": "attacker@example.com",
    "CF_DNS_API_TOKEN": _SENTINEL_TOKEN,
    "CF_ZONE_API_TOKEN": _SENTINEL_TOKEN,
    "CF_DNS_API_TOKEN_FILE": "/host/other-token",
    "CLOUDFLARE_API_KEY": _SENTINEL_KEY,
    "CLOUDFLARE_DNS_API_TOKEN": _SENTINEL_TOKEN,
    "CLOUDFLARE_BASE_URL": "https://evil.example.com",
    "cloudflare_zone_api_token": _SENTINEL_TOKEN,
    "LEGO_CONFIG": "/host/lego.toml",
    "LEGO_DISABLE_CNAME_SUPPORT": "true",
    "LEGO_PATH": "/host/lego",
    "lego_tls_skip_verify": "true",
    "GODEBUG": "http2debug=2,tls13=0",
    "TWINGATE_API_KEY": _SENTINEL_TWINGATE,
    "GWOPS_ADMIN_TOKEN": _SENTINEL_ADMIN,
}

_SENTINELS = (
    _SENTINEL_TOKEN,
    _SENTINEL_KEY,
    _SENTINEL_TWINGATE,
    _SENTINEL_ADMIN,
    "attacker@example.com",
    "evil.example.com",
)


def make_settings(**fields: Any) -> AcmeSettings:
    """The ``public_tls.acme`` block (staging, resolver propagation); `fields` override."""
    data: dict[str, Any] = {"email": "ops@example.com", "accept_tos": True}
    data.update(fields)
    return AcmeSettings.model_validate(data)


def make_cert(
    name: str = "wildcard", names: list[str] | None = None, **fields: Any
) -> AcmePublicCertificate:
    """One ``source: acme`` certificate."""
    data: dict[str, Any] = {
        "name": name,
        "names": ["*.example.com"] if names is None else names,
        "source": "acme",
    }
    data.update(fields)
    return AcmePublicCertificate.model_validate(data)


def make_gwops(**fields: Any) -> GwopsSettings:
    """Default paths (``/usr/local/bin/lego``, ``/data/acme/lego``), independent of the host env."""
    data: dict[str, Any] = {
        "data_dir": Path("/data"),
        "lego_binary": Path("/usr/local/bin/lego"),
    }
    data.update(fields)
    return GwopsSettings(**data)


def argv_for(
    settings: AcmeSettings | None = None,
    cert: AcmePublicCertificate | None = None,
    *,
    force: bool = False,
    gwops: GwopsSettings | None = None,
    environ: dict[str, str] | None = None,
    token_path: str | None = None,
) -> list[str]:
    argv, _env = build_argv(
        settings or make_settings(),
        cert or make_cert(),
        gwops=gwops or make_gwops(),
        force=force,
        environ={} if environ is None else environ,
        token_path=token_path,
    )
    return argv


def env_for(
    settings: AcmeSettings | None = None,
    environ: dict[str, str] | None = None,
    *,
    token_path: str | None = None,
) -> dict[str, str]:
    _argv, env = build_argv(
        settings or make_settings(),
        make_cert(),
        gwops=make_gwops(),
        environ=_HOST_ENV if environ is None else environ,
        token_path=token_path,
    )
    return env


def _value_after(argv: list[str], flag: str) -> str:
    """The value of `flag`, whether passed as ``--flag value`` or ``--flag=value``."""
    if flag in argv:
        return argv[argv.index(flag) + 1]
    (joined,) = [a for a in argv if a.startswith(f"{flag}=")]
    return joined.partition("=")[2]


def _flag_names(argv: list[str]) -> list[str]:
    """Every ``--flag`` in `argv` without its ``=value``."""
    return [a.partition("=")[0] for a in argv if a.startswith("--")]


class TestArgv:
    def test_defaults_yield_the_documented_command_line(self) -> None:
        assert argv_for() == EXPECTED_DEFAULT_ARGV

    def test_global_flags_precede_run_and_run_flags_follow_it(self) -> None:
        argv = argv_for()
        run = argv.index("run")

        assert argv[1:run] == ["--log.format", "json", "--log.level", "info"]
        assert "--path" in argv[run + 1 :]
        assert not {"--log.format", "--log.level"} & set(argv[run + 1 :])

    def test_run_is_the_only_subcommand(self) -> None:
        assert argv_for().count("run") == 1

    def test_the_binary_comes_from_the_settings(self) -> None:
        argv = argv_for(gwops=make_gwops(lego_binary=Path("/opt/lego/bin/lego")))
        assert argv[0] == "/opt/lego/bin/lego"

    def test_the_storage_root_is_the_directorys_subdirectory_under_the_data_dir(self) -> None:
        argv = argv_for(gwops=make_gwops(data_dir=Path("/var/lib/gwops")))

        assert _value_after(argv, "--path") == (
            "/var/lib/gwops/acme/lego/acme-staging-v02.api.letsencrypt.org"
        )

    def test_the_email_is_passed_after_the_server(self) -> None:
        argv = argv_for(make_settings(email="dns-admin@example.org"))

        assert _value_after(argv, "--email") == "dns-admin@example.org"
        assert argv.index("--email") > argv.index("--server")

    def test_tos_is_accepted_without_a_value(self) -> None:
        argv = argv_for()
        assert argv[argv.index("--accept-tos") + 1].startswith("--")

    def test_the_provider_is_passed_to_dns(self) -> None:
        assert _value_after(argv_for(), "--dns") == "cloudflare"

    def test_the_key_type_is_ec256(self) -> None:
        assert KEY_TYPE == "EC256"
        assert _value_after(argv_for(), "--key-type") == "EC256"

    def test_the_certificate_name_is_the_seed_name_not_the_first_domain(self) -> None:
        argv = argv_for(cert=make_cert("edge", ["*.example.com"]))
        assert _value_after(argv, "--cert.name") == "edge"

    def test_renewal_never_sleeps_and_pins_the_declared_names(self) -> None:
        argv = argv_for()

        assert "--no-random-sleep" in argv
        assert "--force-cert-domains" in argv

    def test_dangerous_or_unneeded_flags_are_never_passed(self) -> None:
        argv = argv_for(make_settings(directory="production", propagation="authoritative"),
                        force=True)

        for flag in ("--tls-skip-verify", "--http", "--tls", "--dns-persist", "--pem", "--pfx",
                     "--dns.propagation.wait", "--dns.propagation.disable-rns",
                     "--ari-disable", "--reuse-key", "--config", "--env-file"):
            assert flag not in _flag_names(argv)


class TestDirectory:
    def test_staging_is_the_default_server(self) -> None:
        assert _value_after(argv_for(), "--server") == STAGING_URL

    def test_production_uses_the_production_url(self) -> None:
        argv = argv_for(make_settings(directory="production"))
        assert _value_after(argv, "--server") == PRODUCTION_URL

    def test_a_custom_directory_is_passed_verbatim(self) -> None:
        url = "https://acme.corp.example/directory"
        argv = argv_for(make_settings(directory=url))
        assert _value_after(argv, "--server") == url

    def test_a_shortcut_never_reaches_lego_as_a_shortcut(self) -> None:
        """lego would resolve `letsencrypt` itself; the argv always carries a full URL."""
        server = _value_after(argv_for(make_settings(directory="production")), "--server")
        assert server.startswith("https://")

    def test_the_explicit_staging_url_is_the_same_command_as_the_shortcut(self) -> None:
        assert argv_for(make_settings(directory=STAGING_URL)) == argv_for()


class TestStoragePath:
    """``--path`` is ``<lego base>/<directory host[_port]>``; a directory never shares files."""

    def test_staging_and_production_use_different_directories(self) -> None:
        staging = _value_after(argv_for(make_settings(directory="staging")), "--path")
        production = _value_after(argv_for(make_settings(directory="production")), "--path")

        assert staging == STAGING_PATH
        assert production == PRODUCTION_PATH
        assert staging != production

    def test_the_path_comes_from_the_settings_helper(self) -> None:
        gwops = make_gwops(data_dir=Path("/srv/state"))
        url = "https://acme.corp.example:8443/directory"

        argv = argv_for(make_settings(directory=url), gwops=gwops)

        assert _value_after(argv, "--path") == gwops.lego_storage_dir(url).as_posix()
        assert _value_after(argv, "--path") == "/srv/state/acme/lego/acme.corp.example_8443"

    def test_two_urls_on_one_host_share_a_directory(self) -> None:
        one = argv_for(make_settings(directory="https://acme.corp.example/a"))
        two = argv_for(make_settings(directory="https://acme.corp.example/b"))

        assert _value_after(one, "--path") == _value_after(two, "--path")

    def test_the_path_is_never_the_bare_lego_base(self) -> None:
        for directory in ("staging", "production", "https://acme.corp.example/dir"):
            path = _value_after(argv_for(make_settings(directory=directory)), "--path")
            assert path != "/data/acme/lego"
            assert path.startswith("/data/acme/lego/")


class TestPropagation:
    def test_resolver_propagation_disables_the_authoritative_check(self) -> None:
        argv = argv_for(make_settings(propagation="resolver"))
        assert "--dns.propagation.disable-ans" in argv

    def test_authoritative_propagation_drops_that_flag(self) -> None:
        argv = argv_for(make_settings(propagation="authoritative"))

        assert "--dns.propagation.disable-ans" not in argv
        assert argv.index("--dns") + 2 == argv.index("--key-type")

    def test_authoritative_leaves_the_rest_of_the_command_unchanged(self) -> None:
        expected = [a for a in EXPECTED_DEFAULT_ARGV if a != "--dns.propagation.disable-ans"]
        assert argv_for(make_settings(propagation="authoritative")) == expected


class TestForce:
    def test_force_appends_renew_force_last(self) -> None:
        argv = argv_for(force=True)

        assert argv[-1] == "--renew-force"
        assert argv[:-1] == EXPECTED_DEFAULT_ARGV

    def test_without_force_the_flag_is_absent(self) -> None:
        assert "--renew-force" not in argv_for(force=False)

    def test_force_is_after_run(self) -> None:
        argv = argv_for(force=True)
        assert argv.index("--renew-force") > argv.index("run")


class TestNames:
    def test_one_name_is_one_domains_value(self) -> None:
        argv = argv_for(cert=make_cert(names=["app.example.com"]))

        assert _value_after(argv, "--domains") == "app.example.com"

    def test_several_names_are_comma_joined_in_a_single_flag(self) -> None:
        names = ["*.example.com", "example.com", "x.example.com"]
        argv = argv_for(cert=make_cert(names=names))

        assert _flag_names(argv).count("--domains") == 1
        assert _value_after(argv, "--domains") == "*.example.com,example.com,x.example.com"

    def test_seed_values_use_the_equals_form_so_they_cannot_parse_as_flags(self) -> None:
        argv = argv_for(cert=make_cert(names=["*.example.com", "example.com"]))

        assert "--cert.name=wildcard" in argv
        assert "--domains=*.example.com,example.com" in argv
        assert "--cert.name" not in argv
        assert "--domains" not in argv

    def test_a_value_with_a_leading_dash_stays_one_argument_with_its_flag(self) -> None:
        """Seed validation refuses such names; the builder must not rely on that alone."""
        cert = make_cert().model_copy(update={"name": "-x", "names": ["-y.example.com"]})

        argv = argv_for(cert=cert)

        assert "--cert.name=-x" in argv
        assert "--domains=-y.example.com" in argv
        assert not any(a in ("-x", "-y.example.com") for a in argv)

    def test_a_value_that_looks_like_a_flag_does_not_add_a_flag(self) -> None:
        cert = make_cert().model_copy(update={"names": ["*.example.com,--tls-skip-verify"]})

        argv = argv_for(cert=cert)

        assert "--tls-skip-verify" not in argv
        assert "--tls-skip-verify" not in _flag_names(argv)

    def test_names_keep_the_declared_order(self) -> None:
        names = ["z.example.com", "a.example.com"]
        assert _value_after(argv_for(cert=make_cert(names=names)), "--domains") == ",".join(names)

    def test_wildcards_keep_their_star(self) -> None:
        assert _value_after(argv_for(), "--domains").startswith("*.")

    def test_a_challenge_alias_does_not_change_the_argv(self) -> None:
        """Aliasing is DNS-driven: lego follows the CNAME itself."""
        plain = argv_for()
        aliased = argv_for(cert=make_cert(challenge_alias="acme.delegated.example.net"))

        assert aliased == plain
        assert not any("delegated" in a for a in aliased)


class TestEnvironment:
    def test_only_the_allowlisted_process_and_proxy_variables_and_the_token_files(self) -> None:
        env = env_for()

        assert env == {
            "PATH": _HOST_ENV["PATH"],
            "HOME": _HOST_ENV["HOME"],
            "LANG": _HOST_ENV["LANG"],
            "HTTPS_PROXY": _HOST_ENV["HTTPS_PROXY"],
            "https_proxy": _HOST_ENV["https_proxy"],
            "HTTP_PROXY": _HOST_ENV["HTTP_PROXY"],
            "NO_PROXY": _HOST_ENV["NO_PROXY"],
            "SSL_CERT_FILE": _HOST_ENV["SSL_CERT_FILE"],
            "CF_DNS_API_TOKEN_FILE": TOKEN_FILE,
            "CF_ZONE_API_TOKEN_FILE": TOKEN_FILE,
        }

    def test_both_token_file_variables_name_the_configured_file(self) -> None:
        env = env_for(make_settings(token_file="/config/acme/dns/zone-token"))

        assert TOKEN_ENV_VARS == ("CF_DNS_API_TOKEN_FILE", "CF_ZONE_API_TOKEN_FILE")
        for name in TOKEN_ENV_VARS:
            assert env[name] == "/config/acme/dns/zone-token"

    def test_an_inherited_token_file_variable_is_replaced_not_kept(self) -> None:
        assert env_for()["CF_DNS_API_TOKEN_FILE"] != _HOST_ENV["CF_DNS_API_TOKEN_FILE"]

    @pytest.mark.parametrize(
        "name",
        [
            "CF_API_KEY",
            "CF_API_EMAIL",
            "CF_DNS_API_TOKEN",
            "CF_ZONE_API_TOKEN",
            "CLOUDFLARE_API_KEY",
            "CLOUDFLARE_DNS_API_TOKEN",
            "CLOUDFLARE_BASE_URL",
            "cloudflare_zone_api_token",
            "LEGO_CONFIG",
            "LEGO_DISABLE_CNAME_SUPPORT",
            "LEGO_PATH",
            "lego_tls_skip_verify",
            "TWINGATE_API_KEY",
            "GWOPS_ADMIN_TOKEN",
            "GODEBUG",
        ],
    )
    def test_a_host_credential_or_lego_override_never_reaches_the_child(self, name: str) -> None:
        assert name not in env_for()

    def test_godebug_is_stripped_although_the_gateway_allowlist_keeps_it(self) -> None:
        """``child_env`` passes ``GODEBUG`` to the gateway; lego's child must not inherit it."""
        assert child_env(_HOST_ENV)["GODEBUG"] == _HOST_ENV["GODEBUG"]
        assert LEGO_ENV_STRIP_NAMES == ("GODEBUG",)
        assert "GODEBUG" not in env_for()
        assert _HOST_ENV["GODEBUG"] not in "\n".join(env_for().values())

    def test_the_second_guard_strips_godebug_in_any_case_even_if_child_env_let_it_through(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(lego_module, "child_env", lambda environ=None: dict(environ or {}))

        env = env_for(environ={"GODEBUG": "x", "godebug": "y", "PATH": "/bin"})

        assert {n.upper() for n in env} == {"PATH", *TOKEN_ENV_VARS}

    def test_no_sentinel_value_appears_anywhere_in_the_environment(self) -> None:
        values = "\n".join(env_for().values())

        for sentinel in _SENTINELS:
            assert sentinel not in values

    def test_the_proxy_variables_pass_through_in_both_cases(self) -> None:
        env = env_for()

        assert env["HTTPS_PROXY"] == "http://proxy.internal:3128"
        assert env["https_proxy"] == "http://proxy.internal:3128"
        assert env["HTTP_PROXY"] == "http://proxy.internal:3128"
        assert env["NO_PROXY"] == "localhost,127.0.0.1"

    def test_the_second_guard_strips_the_prefixes_even_if_child_env_let_them_through(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`child_env` is an allowlist today; the prefix filter must hold on its own."""
        monkeypatch.setattr(lego_module, "child_env", lambda environ=None: dict(environ or {}))

        env = env_for()

        assert LEGO_ENV_STRIP_PREFIXES == ("CF_", "CLOUDFLARE_", "LEGO_")
        for name in env:
            if name not in TOKEN_ENV_VARS:
                assert not name.upper().startswith(LEGO_ENV_STRIP_PREFIXES), name
        assert env["CF_DNS_API_TOKEN_FILE"] == TOKEN_FILE
        assert env["CF_ZONE_API_TOKEN_FILE"] == TOKEN_FILE
        # The prefix guard owns Cloudflare and lego names; the allowlist owns the rest.
        cloudflare_sentinels = (_SENTINEL_TOKEN, _SENTINEL_KEY, "attacker@example.com")
        for sentinel in (*cloudflare_sentinels, "evil.example.com"):
            assert sentinel not in "\n".join(env.values())

    def test_with_no_source_variables_only_the_token_files_remain(self) -> None:
        assert env_for(environ={}) == dict.fromkeys(TOKEN_ENV_VARS, TOKEN_FILE)

    def test_a_resolved_token_path_replaces_the_configured_one_in_both_variables(self) -> None:
        env = env_for(environ={}, token_path="/config/acme/real/token-file")

        assert env == dict.fromkeys(TOKEN_ENV_VARS, "/config/acme/real/token-file")

    def test_an_empty_token_path_falls_back_to_the_configured_file(self) -> None:
        assert env_for(environ={}, token_path="") == dict.fromkeys(TOKEN_ENV_VARS, TOKEN_FILE)

    def test_the_token_path_never_reaches_argv(self) -> None:
        argv = argv_for(token_path="/config/acme/real/token-file")

        assert not any("token-file" in a or "/config/acme" in a for a in argv)
        assert argv == EXPECTED_DEFAULT_ARGV

    def test_the_default_source_is_the_process_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HTTPS_PROXY", "http://from-process:8080")
        monkeypatch.setenv("CF_API_KEY", _SENTINEL_KEY)

        _argv, env = build_argv(make_settings(), make_cert(), gwops=make_gwops())

        assert env["HTTPS_PROXY"] == "http://from-process:8080"
        assert "CF_API_KEY" not in env
        assert _SENTINEL_KEY not in "\n".join(env.values())


class TestNoSecretInArgv:
    def test_no_host_secret_reaches_argv(self) -> None:
        argv = argv_for(environ=_HOST_ENV, force=True)
        joined = "\n".join(argv)

        for sentinel in _SENTINELS:
            assert sentinel not in joined

    def test_the_token_file_path_is_environment_only(self) -> None:
        argv = argv_for(make_settings(token_file="/config/acme/dns/zone-token"))

        assert not any("zone-token" in a or "/config/acme" in a for a in argv)
        assert not any(a.startswith(("CF_", "CLOUDFLARE_")) for a in argv)

    def test_nothing_in_argv_looks_like_a_key_value_credential(self) -> None:
        for argument in argv_for(force=True):
            assert "token" not in argument.lower()
            assert "api_key" not in argument.lower()

    def test_a_dry_run_and_production_argv_differ_only_in_the_server_and_its_storage_path(
        self,
    ) -> None:
        staging = argv_for(make_settings(directory="staging"))
        production = argv_for(make_settings(directory="production"))

        differing = [(a, b) for a, b in zip(staging, production, strict=True) if a != b]
        assert differing == [(STAGING_PATH, PRODUCTION_PATH), (STAGING_URL, PRODUCTION_URL)]


class TestPurity:
    def test_the_same_inputs_give_equal_results(self) -> None:
        first = build_argv(make_settings(), make_cert(), gwops=make_gwops(), environ=_HOST_ENV)
        second = build_argv(make_settings(), make_cert(), gwops=make_gwops(), environ=_HOST_ENV)

        assert first == second

    def test_each_call_returns_fresh_containers(self) -> None:
        settings, cert, gwops = make_settings(), make_cert(), make_gwops()
        argv, env = build_argv(settings, cert, gwops=gwops, environ={})
        argv.append("--mutated")
        env["MUTATED"] = "1"

        again_argv, again_env = build_argv(settings, cert, gwops=gwops, environ={})

        assert "--mutated" not in again_argv
        assert "MUTATED" not in again_env

    def test_the_source_environment_is_not_modified(self) -> None:
        source = dict(_HOST_ENV)

        build_argv(make_settings(), make_cert(), gwops=make_gwops(), environ=source)

        assert source == _HOST_ENV

    def test_the_certificate_and_settings_are_not_modified(self) -> None:
        settings, cert = make_settings(), make_cert(names=["*.example.com", "example.com"])
        before = (settings.model_dump(), cert.model_dump())

        build_argv(settings, cert, gwops=make_gwops(), force=True, environ=_HOST_ENV)

        assert (settings.model_dump(), cert.model_dump()) == before


class TestEveryCombination:
    """Across every option combination the shape holds: global flags, `run`, then run flags."""

    @pytest.mark.parametrize(
        ("directory", "propagation", "force", "names"),
        list(
            itertools.product(
                ["staging", "production", "https://acme.example.org/dir"],
                ["resolver", "authoritative"],
                [False, True],
                [["*.example.com"], ["*.example.com", "example.com"]],
            )
        ),
    )
    def test_the_command_has_the_same_shape(
        self, directory: str, propagation: str, force: bool, names: list[str]
    ) -> None:
        argv = argv_for(
            make_settings(directory=directory, propagation=propagation),
            make_cert(names=names),
            force=force,
            environ=_HOST_ENV,
        )

        run = argv.index("run")
        assert argv[0] == "/usr/local/bin/lego"
        assert argv[1:run] == ["--log.format", "json", "--log.level", "info"]
        assert argv[run + 1] == "--path"
        flags = _flag_names(argv[run + 1 :])
        assert len(flags) == len(set(flags)), "no flag may repeat"
        assert ("--renew-force" in argv) is force
        assert ("--dns.propagation.disable-ans" in argv) is (propagation == "resolver")
        assert _value_after(argv, "--domains") == ",".join(names)
