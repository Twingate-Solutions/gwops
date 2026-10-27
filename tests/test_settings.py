"""Tests for gwops.settings.GwopsSettings."""

from pathlib import PurePosixPath

import pytest
from pydantic import ValidationError

from gwops.settings import GwopsSettings


class TestDefaults:
    def test_default_paths(self) -> None:
        s = GwopsSettings()
        assert PurePosixPath(s.seed_path.as_posix()) == PurePosixPath("/config/seed.yaml")
        assert PurePosixPath(s.data_dir.as_posix()) == PurePosixPath("/data")
        assert PurePosixPath(s.runtime_dir.as_posix()) == PurePosixPath("/run/gateway")
        assert PurePosixPath(s.gateway_binary.as_posix()) == PurePosixPath(
            "/usr/local/bin/gateway"
        )

    def test_default_healthcheck_admin_fallback(self) -> None:
        s = GwopsSettings()
        assert s.healthcheck_admin_fallback == 8081

    def test_secrets_default_to_none(self) -> None:
        s = GwopsSettings()
        assert s.twingate_api_key is None
        assert s.gwops_admin_token is None
        assert s.recording_token is None


class TestEnvOverrides:
    def test_paths_and_ports_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GWOPS_SEED_PATH", "/tmp/seed.yaml")
        monkeypatch.setenv("GWOPS_DATA_DIR", "/var/lib/gwops")
        monkeypatch.setenv("GWOPS_HEALTHCHECK_ADMIN_FALLBACK", "9999")
        s = GwopsSettings()
        assert s.seed_path.as_posix() == "/tmp/seed.yaml"
        assert s.data_dir.as_posix() == "/var/lib/gwops"
        assert s.healthcheck_admin_fallback == 9999

    def test_secrets_from_unprefixed_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TWINGATE_API_KEY", "tg-key")
        monkeypatch.setenv("GWOPS_ADMIN_TOKEN", "admin-token")
        monkeypatch.setenv("GWOPS_RECORDING_TOKEN", "gc-token")
        s = GwopsSettings()
        assert s.twingate_api_key is not None
        assert s.twingate_api_key.get_secret_value() == "tg-key"
        assert s.gwops_admin_token is not None
        assert s.gwops_admin_token.get_secret_value() == "admin-token"
        assert s.recording_token is not None
        assert s.recording_token.get_secret_value() == "gc-token"


class TestSecretsNeverLeak:
    def test_repr_and_dump_hide_secret_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TWINGATE_API_KEY", "tg-key-XYZ")
        s = GwopsSettings()
        assert "tg-key-XYZ" not in repr(s)
        assert "tg-key-XYZ" not in str(s)
        assert "tg-key-XYZ" not in str(s.model_dump())


class TestKubernetesServiceLinks:
    """Service-link variables for Services named ``gwops-*`` must not break settings."""

    @staticmethod
    def _service_link_env(stem: str) -> dict[str, str]:
        """The variables Kubernetes injects for a Service whose env stem is `stem`."""
        return {
            f"{stem}_SERVICE_HOST": "10.96.0.10",
            f"{stem}_SERVICE_PORT": "8081",
            f"{stem}_SERVICE_PORT_HTTP": "8081",
            f"{stem}_PORT": "tcp://10.96.0.10:8081",
            f"{stem}_PORT_8081_TCP": "tcp://10.96.0.10:8081",
            f"{stem}_PORT_8081_TCP_PROTO": "tcp",
            f"{stem}_PORT_8081_TCP_PORT": "8081",
            f"{stem}_PORT_8081_TCP_ADDR": "10.96.0.10",
        }

    @pytest.mark.parametrize(
        "stem",
        [
            "GWOPS",
            "GWOPS_ADMIN",
            "GWOPS_GATEWAY",
            "GWOPS_METRICS",
            "GWOPS_HEALTHCHECK",
            "GWOPS_ADMIN_TOKEN",
        ],
    )
    def test_settings_load_with_injected_service_variables(
        self, stem: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for name, value in self._service_link_env(stem).items():
            monkeypatch.setenv(name, value)

        s = GwopsSettings()

        assert s.healthcheck_admin_fallback == 8081
        assert s.gwops_admin_token is None

    def test_no_setting_is_named_like_a_service_link_variable(self) -> None:
        for field_name in GwopsSettings.model_fields:
            env_name = f"GWOPS_{field_name.upper()}"
            assert not env_name.endswith(("_PORT", "_SERVICE_HOST", "_SERVICE_PORT"))
            assert "_PORT_" not in env_name


class TestLegoBinary:
    """``GWOPS_LEGO_BINARY`` is the second pinned binary; a relative path is refused."""

    def test_the_default_is_the_image_path(self) -> None:
        s = GwopsSettings()
        assert PurePosixPath(s.lego_binary.as_posix()) == PurePosixPath("/usr/local/bin/lego")

    def test_an_absolute_path_from_the_environment_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GWOPS_LEGO_BINARY", "/opt/lego/bin/lego")

        assert GwopsSettings().lego_binary.as_posix() == "/opt/lego/bin/lego"

    @pytest.mark.parametrize("good", ["/usr/bin/lego", "/lego", "/opt/a b/lego"])
    def test_a_posix_absolute_path_is_accepted_on_every_platform(self, good: str) -> None:
        assert GwopsSettings(lego_binary=good).lego_binary.as_posix() == good

    @pytest.mark.parametrize("bad", ["lego", "./lego", "bin/lego", "../lego", "", "."])
    def test_a_relative_path_is_refused_with_the_remedy(self, bad: str) -> None:
        with pytest.raises(ValidationError) as caught:
            GwopsSettings(lego_binary=bad)

        message = str(caught.value)
        assert "GWOPS_LEGO_BINARY must be an absolute path" in message
        assert "/usr/local/bin/lego" in message

    def test_a_relative_path_from_the_environment_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GWOPS_LEGO_BINARY", "lego")

        with pytest.raises(ValidationError, match="GWOPS_LEGO_BINARY must be an absolute path"):
            GwopsSettings()


class TestLegoTimeout:
    """``GWOPS_LEGO_TIMEOUT_SECONDS`` is a finite number of seconds in (0, 3600]."""

    def test_the_default_is_ten_minutes(self) -> None:
        assert GwopsSettings().lego_timeout_seconds == 600.0

    @pytest.mark.parametrize("good", [0.001, 0.5, 1, 30, 600, 3599.9, 3600])
    def test_a_value_inside_the_range_is_accepted(self, good: float) -> None:
        assert GwopsSettings(lego_timeout_seconds=good).lego_timeout_seconds == float(good)

    @pytest.mark.parametrize("bad", [0, 0.0, -1, -0.001, 3600.001, 3601, 86400, 1e9])
    def test_a_value_outside_the_range_is_refused(self, bad: float) -> None:
        with pytest.raises(ValidationError) as caught:
            GwopsSettings(lego_timeout_seconds=bad)

        assert "lego_timeout_seconds" in str(caught.value)

    @pytest.mark.parametrize("bad", [float("inf"), float("-inf"), float("nan")])
    def test_infinity_and_nan_are_refused(self, bad: float) -> None:
        with pytest.raises(ValidationError) as caught:
            GwopsSettings(lego_timeout_seconds=bad)

        assert "lego_timeout_seconds" in str(caught.value)

    @pytest.mark.parametrize("text", ["inf", "Infinity", "nan", "-inf"])
    def test_infinity_and_nan_spelled_in_the_environment_are_refused(
        self, text: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GWOPS_LEGO_TIMEOUT_SECONDS", text)

        with pytest.raises(ValidationError, match="lego_timeout_seconds"):
            GwopsSettings()

    def test_a_number_from_the_environment_is_read(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GWOPS_LEGO_TIMEOUT_SECONDS", "45.5")

        assert GwopsSettings().lego_timeout_seconds == 45.5

    @pytest.mark.parametrize("text", ["0", "-5", "3601", "forever", ""])
    def test_a_bad_number_from_the_environment_is_refused(
        self, text: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GWOPS_LEGO_TIMEOUT_SECONDS", text)

        with pytest.raises(ValidationError, match="lego_timeout_seconds"):
            GwopsSettings()


class TestAcmePaths:
    """``acme_dir``, ``lego_path_dir`` and ``lego_storage_dir`` (lego's ``--path``)."""

    def test_the_directories_nest_under_the_data_dir(self) -> None:
        s = GwopsSettings(data_dir="/var/lib/gwops")

        assert s.acme_dir.as_posix() == "/var/lib/gwops/acme"
        assert s.lego_path_dir.as_posix() == "/var/lib/gwops/acme/lego"

    @pytest.mark.parametrize(
        ("url", "label"),
        [
            pytest.param(
                "https://acme-staging-v02.api.letsencrypt.org/directory",
                "acme-staging-v02.api.letsencrypt.org",
                id="staging",
            ),
            pytest.param(
                "https://acme-v02.api.letsencrypt.org/directory",
                "acme-v02.api.letsencrypt.org",
                id="production",
            ),
            pytest.param(
                "https://ACME-V02.Api.LetsEncrypt.org/directory",
                "acme-v02.api.letsencrypt.org",
                id="host-is-lowercased",
            ),
            pytest.param("https://localhost:14000/dir", "localhost_14000", id="port"),
            pytest.param("https://acme.example.test:443/", "acme.example.test_443", id="port-443"),
            pytest.param("https://[::1]:14000/dir", "__1_14000", id="ipv6-and-port"),
            pytest.param("https://host:99999/dir", "host", id="invalid-port-is-dropped"),
            pytest.param("https://a..b/x", "a..b", id="inner-dots-kept"),
            pytest.param("https://.hidden.example/", "hidden.example", id="leading-dot-stripped"),
            pytest.param("https://exa mple.test/", "exa_mple.test", id="space-replaced"),
            pytest.param("https://../x", "unknown", id="dot-dot-host"),
            pytest.param("", "unknown", id="empty"),
            pytest.param("not a url", "unknown", id="no-host"),
        ],
    )
    def test_the_directory_name_is_the_sanitised_host_and_port(self, url: str, label: str) -> None:
        s = GwopsSettings(data_dir="/data")

        assert s.lego_storage_dir(url).name == label

    @pytest.mark.parametrize(
        "url",
        [
            "https://acme-v02.api.letsencrypt.org/directory",
            "https://localhost:14000/dir",
            "https://../x",
            "https://./x",
            "https://a/b/../../c",
            "https://%2e%2e/x",
            "https://user:pw@acme.example.test/d",
            "",
        ],
    )
    def test_the_result_is_always_a_direct_child_of_the_lego_base(self, url: str) -> None:
        s = GwopsSettings(data_dir="/data")

        path = s.lego_storage_dir(url)

        assert path.parent == s.lego_path_dir
        assert path.name not in {"", ".", ".."}
        assert "/" not in path.name
        assert "\\" not in path.name

    def test_credentials_in_the_url_never_reach_the_path(self) -> None:
        s = GwopsSettings(data_dir="/data")

        path = s.lego_storage_dir("https://operator:hunter2@acme.example.test/directory")

        assert path.name == "acme.example.test"
        assert "hunter2" not in path.as_posix()
        assert "operator" not in path.as_posix()

    def test_staging_and_production_never_share_a_directory(self) -> None:
        s = GwopsSettings(data_dir="/data")

        assert s.lego_storage_dir("https://acme-staging-v02.api.letsencrypt.org/directory") != (
            s.lego_storage_dir("https://acme-v02.api.letsencrypt.org/directory")
        )

    def test_two_urls_on_one_host_share_a_directory(self) -> None:
        s = GwopsSettings(data_dir="/data")

        assert s.lego_storage_dir("https://acme.example.test/a") == s.lego_storage_dir(
            "https://acme.example.test/b?x=1"
        )

    def test_a_port_distinguishes_two_directories_on_one_host(self) -> None:
        s = GwopsSettings(data_dir="/data")

        assert s.lego_storage_dir("https://acme.example.test:14000/d") != s.lego_storage_dir(
            "https://acme.example.test:15000/d"
        )
        assert s.lego_storage_dir("https://acme.example.test:14000/d") != s.lego_storage_dir(
            "https://acme.example.test/d"
        )

    def test_the_data_dir_moves_the_directory(self) -> None:
        url = "https://acme.example.test/d"

        moved = GwopsSettings(data_dir="/srv/other").lego_storage_dir(url)

        assert moved.as_posix() == "/srv/other/acme/lego/acme.example.test"
