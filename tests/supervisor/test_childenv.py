"""Tests for gwops.supervisor.child_env: the gateway child's allowlisted environment.

`child_env(source=None, *, platform=None)` returns a new dict holding only the allowlisted
names present in `source` (default ``os.environ``). `platform` (default ``sys.platform``) is
injectable so the win32-only extras are testable on any host. The spawn sites that apply it
are covered in ``test_child_env_spawn.py``.
"""

import os
import sys
from collections.abc import Mapping
from types import MappingProxyType

import pytest

from gwops.supervisor import child_env
from tests.supervisor.childenv_names import ALLOWLIST, SECRET_NAMES, WIN32_EXTRAS, sentinel

_PLATFORMS = ("linux", "darwin", "win32")


class TestAllowlist:
    @pytest.mark.parametrize("name", ALLOWLIST)
    def test_allowlisted_name_is_copied_with_its_value(self, name: str) -> None:
        assert child_env({name: f"value-of-{name}"}, platform="linux") == {
            name: f"value-of-{name}"
        }

    def test_exactly_the_documented_names_pass_on_linux(self) -> None:
        source = {name: f"value-of-{name}" for name in (*ALLOWLIST, *WIN32_EXTRAS, *SECRET_NAMES)}
        result = child_env(source, platform="linux")
        assert set(result) == set(ALLOWLIST)

    def test_names_absent_from_source_are_not_invented(self) -> None:
        assert child_env({"PATH": "/usr/bin"}, platform="linux") == {"PATH": "/usr/bin"}
        assert child_env({}, platform="linux") == {}
        assert child_env({}, platform="win32") == {}

    def test_empty_values_are_preserved_not_dropped(self) -> None:
        assert child_env({"NO_PROXY": ""}, platform="linux") == {"NO_PROXY": ""}

    def test_matching_is_case_sensitive(self) -> None:
        source = {"path": "x", "Home": "x", "Https_Proxy": "x", "ssl_cert_file": "x", "Tz": "x"}
        assert child_env(source, platform="linux") == {}

    def test_both_cases_of_the_proxy_variables_pass_independently(self) -> None:
        source = {"HTTPS_PROXY": "http://upper", "https_proxy": "http://lower"}
        assert child_env(source, platform="linux") == source

    @pytest.mark.parametrize(
        "name",
        ["MYPATH", "PATH_INFO", "XHOME", "SSL_CERT_DIRS", "SSL_CERT_FILE_OLD", "HTTPS_PROXY_USER",
         "GOMEMLIMITS", "GODEBUG_EXTRA", "LANGUAGE", "LC_CTYPE", "TZDIR", "PATHEXT"],
    )
    def test_lookalike_names_are_not_matched_by_substring_or_prefix(self, name: str) -> None:
        assert child_env({name: "x"}, platform="linux") == {}


class TestSecretsStripped:
    @pytest.mark.parametrize("platform", _PLATFORMS)
    @pytest.mark.parametrize("name", SECRET_NAMES)
    def test_secret_is_stripped_by_name_and_by_value(self, name: str, platform: str) -> None:
        source = {"PATH": "/usr/bin", name: sentinel(name)}
        result = child_env(source, platform=platform)
        assert name not in result
        assert sentinel(name) not in result.values()
        assert result == {"PATH": "/usr/bin"}

    @pytest.mark.parametrize("platform", _PLATFORMS)
    @pytest.mark.parametrize(
        "name",
        [
            "TWINGATE_NETWORK",
            "TWINGATE_CONFIG",
            "GWOPS_ADMIN_PORT",
            "GWOPS_GATEWAY_VERSION",
            "GWOPS_RECORDING_URL",
            "CF_API_EMAIL",
            "CF_ZONE_API_TOKEN",
        ],
    )
    def test_reserved_prefixes_never_pass(self, name: str, platform: str) -> None:
        assert child_env({name: "x"}, platform=platform) == {}

    @pytest.mark.parametrize("platform", _PLATFORMS)
    def test_all_secrets_set_at_once_leave_only_the_allowlisted_names(
        self, platform: str
    ) -> None:
        source = {name: sentinel(name) for name in SECRET_NAMES}
        source.update({"PATH": "/usr/bin", "HTTPS_PROXY": "http://proxy.invalid:3128"})
        result = child_env(source, platform=platform)
        assert result == {"PATH": "/usr/bin", "HTTPS_PROXY": "http://proxy.invalid:3128"}


class TestWin32Extras:
    @pytest.mark.parametrize("name", WIN32_EXTRAS)
    def test_extra_passes_on_win32(self, name: str) -> None:
        assert child_env({name: "C:\\x"}, platform="win32") == {name: "C:\\x"}

    @pytest.mark.parametrize("platform", ["linux", "darwin"])
    @pytest.mark.parametrize("name", WIN32_EXTRAS)
    def test_extra_is_stripped_off_win32(self, name: str, platform: str) -> None:
        assert child_env({name: "x"}, platform=platform) == {}

    def test_win32_passes_allowlist_and_extras_together(self) -> None:
        source = {name: f"value-of-{name}" for name in (*ALLOWLIST, *WIN32_EXTRAS)}
        source.update({name: sentinel(name) for name in SECRET_NAMES})
        result = child_env(source, platform="win32")
        assert set(result) == {*ALLOWLIST, *WIN32_EXTRAS}

    def test_win32_extras_absent_from_source_are_not_invented(self) -> None:
        assert child_env({"PATH": "C:\\bin"}, platform="win32") == {"PATH": "C:\\bin"}

    def test_platform_defaults_to_sys_platform(self, monkeypatch: pytest.MonkeyPatch) -> None:
        source = {"SYSTEMROOT": "C:\\Windows", "PATH": "x"}
        monkeypatch.setattr(sys, "platform", "win32")
        assert child_env(source) == source
        monkeypatch.setattr(sys, "platform", "linux")
        assert child_env(source) == {"PATH": "x"}

    @pytest.mark.skipif(
        sys.platform != "win32", reason="os.environ is case-insensitive only on Windows"
    )
    def test_lowercase_proxy_set_in_the_windows_environment_arrives_upper_cased(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # os.environ upper-cases every key on Windows, and the OS treats names
        # case-insensitively, so "https_proxy" is observed (and passed) as "HTTPS_PROXY".
        monkeypatch.setenv("https_proxy", "http://lower.invalid:3128")
        assert child_env().get("HTTPS_PROXY") == "http://lower.invalid:3128"


class TestSource:
    def test_default_source_is_the_live_os_environ(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
        monkeypatch.setenv("SSL_CERT_FILE", "/certs/ca.pem")
        result = child_env()
        assert result["HTTPS_PROXY"] == "http://proxy.invalid:3128"
        assert result["SSL_CERT_FILE"] == "/certs/ca.pem"

    def test_default_source_strips_secrets_from_the_live_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for name in SECRET_NAMES:
            monkeypatch.setenv(name, sentinel(name))
        result = child_env()
        assert not set(SECRET_NAMES) & set(result)
        assert not {sentinel(name) for name in SECRET_NAMES} & set(result.values())

    def test_default_source_is_read_at_call_time_not_import_time(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GOGC", "50")
        assert child_env()["GOGC"] == "50"
        monkeypatch.setenv("GOGC", "75")
        assert child_env()["GOGC"] == "75"
        monkeypatch.delenv("GOGC")
        assert "GOGC" not in child_env()

    def test_explicit_none_means_the_live_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GOMAXPROCS", "2")
        assert child_env(None)["GOMAXPROCS"] == "2"

    def test_explicit_source_is_used_instead_of_the_live_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GOMAXPROCS", "2")
        assert "GOMAXPROCS" not in child_env({"PATH": "/x"}, platform="linux")

    def test_any_mapping_is_accepted_as_source(self) -> None:
        source: Mapping[str, str] = MappingProxyType({"PATH": "/x", "FOO": "bar"})
        assert child_env(source, platform="linux") == {"PATH": "/x"}


class TestReturnValue:
    def test_returns_a_plain_dict_that_is_not_os_environ(self) -> None:
        result = child_env()
        assert type(result) is dict
        assert result is not os.environ

    def test_result_is_a_new_dict_and_mutating_it_leaves_the_source_alone(self) -> None:
        source = {"PATH": "/usr/bin"}
        result = child_env(source, platform="linux")
        assert result is not source
        result["PATH"] = "/changed"
        result["INJECTED"] = "1"
        assert source == {"PATH": "/usr/bin"}

    def test_mutating_the_source_afterwards_leaves_the_result_alone(self) -> None:
        source = {"PATH": "/usr/bin"}
        result = child_env(source, platform="linux")
        source["PATH"] = "/changed"
        source["HOME"] = "/root"
        assert result == {"PATH": "/usr/bin"}

    def test_calling_it_does_not_modify_the_live_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TWINGATE_API_KEY", sentinel("TWINGATE_API_KEY"))
        before = dict(os.environ)
        result = child_env()
        result["PATH"] = "/changed"
        assert dict(os.environ) == before

    def test_returned_values_are_strings(self) -> None:
        result = child_env({"PATH": "/x", "TZ": "UTC"}, platform="linux")
        assert all(isinstance(k, str) and isinstance(v, str) for k, v in result.items())
