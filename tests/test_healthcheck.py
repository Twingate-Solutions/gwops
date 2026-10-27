"""Tests for gwops.healthcheck — the Docker HEALTHCHECK client.

A tiny synchronous httpx probe of the admin API's ``/healthz`` (no auth). It maps
the composite health signal to a process exit code: 0 iff the endpoint answers 200,
1 for anything else (503 unhealthy, connection refused while the API is still binding,
timeouts). ``curl`` is not in ``python:3.12-slim``, so this module is the healthcheck.
"""

from types import SimpleNamespace

import httpx
import pytest
import respx

import gwops.healthcheck as hc
from gwops.healthcheck import check, main


class TestCheck:
    @respx.mock
    def test_returns_zero_when_healthz_ok(self) -> None:
        respx.get("http://127.0.0.1:8081/healthz").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        assert check("http://127.0.0.1:8081/healthz") == 0

    @respx.mock
    def test_returns_one_when_healthz_unhealthy(self) -> None:
        respx.get("http://127.0.0.1:8081/healthz").mock(
            return_value=httpx.Response(503, json={"status": "unhealthy"})
        )
        assert check("http://127.0.0.1:8081/healthz") == 1

    @respx.mock
    def test_returns_one_on_connection_error(self) -> None:
        # The API socket is not up yet (or gwops crashed): a transport error, not a
        # response. The probe must report unhealthy, never raise.
        respx.get("http://127.0.0.1:8081/healthz").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        assert check("http://127.0.0.1:8081/healthz") == 1

    @respx.mock
    def test_returns_one_on_timeout(self) -> None:
        respx.get("http://127.0.0.1:8081/healthz").mock(
            side_effect=httpx.ReadTimeout("timed out")
        )
        assert check("http://127.0.0.1:8081/healthz") == 1


def _fake_state(bind: str, port: int) -> SimpleNamespace:
    return SimpleNamespace(admin_api=SimpleNamespace(bind=bind, port=port))


class TestMain:
    @respx.mock
    def test_probes_admin_port_from_settings_when_seed_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # No seed to load (the default /config/seed.yaml does not exist under test): main()
        # falls back to the GWOPS_HEALTHCHECK_ADMIN_FALLBACK env default on loopback.
        monkeypatch.setenv("GWOPS_HEALTHCHECK_ADMIN_FALLBACK", "9999")
        route = respx.get("http://127.0.0.1:9999/healthz").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        assert main() == 0
        assert route.called

    @respx.mock
    def test_probes_port_from_effective_seed_not_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The server binds the SEED's admin_api.port, so the healthcheck must probe that,
        # not the GWOPS_HEALTHCHECK_ADMIN_FALLBACK env default, or it silently probes the
        # wrong port when an operator overrides the seed.
        # env default, deliberately wrong
        monkeypatch.setenv("GWOPS_HEALTHCHECK_ADMIN_FALLBACK", "8081")
        monkeypatch.setattr(hc, "OverlayStore", lambda *a, **k: object())
        monkeypatch.setattr(
            hc, "load_effective_state", lambda *a, **k: (_fake_state("0.0.0.0", 7777), {})
        )
        route = respx.get("http://127.0.0.1:7777/healthz").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        assert main() == 0
        assert route.called

    @respx.mock
    def test_probes_specific_non_wildcard_bind_address(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A seed that binds a specific non-loopback address is probed at that address.
        monkeypatch.setattr(hc, "OverlayStore", lambda *a, **k: object())
        monkeypatch.setattr(
            hc, "load_effective_state", lambda *a, **k: (_fake_state("10.1.2.3", 8081), {})
        )
        route = respx.get("http://10.1.2.3:8081/healthz").mock(
            return_value=httpx.Response(200, json={"status": "ok"})
        )
        assert main() == 0
        assert route.called

    @respx.mock
    def test_main_reports_unhealthy_as_nonzero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GWOPS_HEALTHCHECK_ADMIN_FALLBACK", "8081")
        respx.get("http://127.0.0.1:8081/healthz").mock(
            return_value=httpx.Response(503, json={"status": "unhealthy"})
        )
        assert main() == 1
