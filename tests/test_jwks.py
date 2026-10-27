"""Tests for gwops.jwks: the Twingate JWKS reachability probe and its monitor.

Interface under test:

* ``jwks_url(network, host)`` -> ``https://<network>.<host>/api/v1/jwk/ec``
* ``probe_jwks(client, url)`` -> ``JwksStatus`` (never raises for transport or HTTP failures)
* ``JwksStatus(ok, checked_at, error_class, reason=None)``: frozen, ``checked_at`` is tz-aware UTC
* ``make_client()`` -> ``httpx.AsyncClient`` (``trust_env``, 5 s timeout, system-root SSLContext)
* ``JwksMonitor(client, url)``: ``status`` is ``None`` until the first ``check()``; ``check()``
  stores and returns the status and never raises.

Classification: ``unreachable`` (DNS, refused, TLS verify, proxy auth), ``degraded`` (5xx,
timeouts), ``invalid`` (200 with an unusable key set), ``internal_error`` (an unexpected
exception inside ``check()``). ``JwksMonitor.mark`` records a status set by the caller.
"""

import json
import socket
import ssl
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import structlog.testing

import gwops.jwks as jwks_module
from gwops._version import __version__
from gwops.jwks import JwksMonitor, JwksStatus, jwks_url, make_client, probe_jwks

URL = "https://acme.twingate.com/api/v1/jwk/ec"
FIXTURE = Path(__file__).parent / "fixtures" / "tg" / "jwks_acme.json"
BODY_MARKER = "RESPONSE-BODY-MARKER-do-not-log"


@pytest.fixture
def jwks_doc() -> dict[str, Any]:
    """The captured acme JWKS document."""
    return json.loads(FIXTURE.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


@pytest.fixture
async def client() -> Any:
    """A client with TLS setup skipped; respx intercepts its transport."""
    async with httpx.AsyncClient(verify=False) as c:
        yield c


def _key(**overrides: Any) -> dict[str, Any]:
    key: dict[str, Any] = {"kty": "EC", "crv": "P-256", "kid": "k1", "x": "AAAA", "y": "BBBB"}
    key.update(overrides)
    return {k: v for k, v in key.items() if v is not None}


def _connect_error(cause: BaseException, message: str = "connect failed") -> httpx.ConnectError:
    error = httpx.ConnectError(message)
    error.__cause__ = cause
    return error


class TestJwksUrl:
    def test_builds_the_ec_jwk_endpoint_for_the_default_host(self) -> None:
        assert jwks_url("acme", "twingate.com") == URL

    def test_uses_the_configured_host_verbatim(self) -> None:
        assert jwks_url("acme", "stg.opstg.com") == "https://acme.stg.opstg.com/api/v1/jwk/ec"


class TestJwksStatus:
    def test_carries_ok_checked_at_and_error_class(self) -> None:
        now = datetime.now(UTC)
        status = JwksStatus(ok=False, checked_at=now, error_class="degraded")
        assert (status.ok, status.checked_at, status.error_class) == (False, now, "degraded")

    def test_reason_defaults_to_none(self) -> None:
        status = JwksStatus(ok=True, checked_at=datetime.now(UTC), error_class=None)
        assert status.reason is None

    def test_is_immutable(self) -> None:
        status = JwksStatus(ok=True, checked_at=datetime.now(UTC), error_class=None)
        with pytest.raises((AttributeError, TypeError, ValueError)):
            status.ok = False  # type: ignore[misc]

    def test_equal_when_all_fields_match(self) -> None:
        now = datetime.now(UTC)
        assert JwksStatus(ok=True, checked_at=now, error_class=None) == JwksStatus(
            ok=True, checked_at=now, error_class=None
        )


class TestProbeOk:
    async def test_ok_for_200_with_the_captured_jwks(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter, jwks_doc: dict[str, Any]
    ) -> None:
        respx_mock.get(URL).mock(return_value=httpx.Response(200, json=jwks_doc))
        status = await probe_jwks(client, URL)
        assert status.ok is True
        assert status.error_class is None

    async def test_requests_the_given_url_with_get(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter, jwks_doc: dict[str, Any]
    ) -> None:
        route = respx_mock.get(URL).mock(return_value=httpx.Response(200, json=jwks_doc))
        await probe_jwks(client, URL)
        assert route.call_count == 1

    async def test_sends_no_credentials(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter, jwks_doc: dict[str, Any]
    ) -> None:
        route = respx_mock.get(URL).mock(return_value=httpx.Response(200, json=jwks_doc))
        await probe_jwks(client, URL)
        headers = route.calls.last.request.headers
        assert "authorization" not in headers
        assert "x-api-key" not in headers

    async def test_ok_when_keys_carry_no_alg_or_use(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter
    ) -> None:
        body = {"keys": [_key()]}
        assert "alg" not in body["keys"][0] and "use" not in body["keys"][0]
        respx_mock.get(URL).mock(return_value=httpx.Response(200, json=body))
        assert (await probe_jwks(client, URL)).ok is True

    async def test_ok_when_keys_carry_alg_and_use(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter
    ) -> None:
        body = {"keys": [_key(alg="ES256", use="sig")]}
        respx_mock.get(URL).mock(return_value=httpx.Response(200, json=body))
        assert (await probe_jwks(client, URL)).ok is True

    async def test_checked_at_is_utc_and_taken_during_the_probe(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter, jwks_doc: dict[str, Any]
    ) -> None:
        respx_mock.get(URL).mock(return_value=httpx.Response(200, json=jwks_doc))
        before = datetime.now(UTC)
        status = await probe_jwks(client, URL)
        after = datetime.now(UTC)
        assert status.checked_at.utcoffset() == timedelta(0)
        assert before <= status.checked_at <= after

    async def test_checked_at_is_set_on_failures_too(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(URL).mock(return_value=httpx.Response(503))
        before = datetime.now(UTC)
        status = await probe_jwks(client, URL)
        assert status.checked_at.utcoffset() == timedelta(0)
        assert status.checked_at >= before


_UNREACHABLE_ERRORS: list[tuple[str, Callable[[], Exception]]] = [
    (
        "dns_failure",
        lambda: _connect_error(
            socket.gaierror(-2, "Name or service not known"),
            "[Errno -2] Name or service not known",
        ),
    ),
    ("connection_refused", lambda: _connect_error(ConnectionRefusedError(111, "refused"))),
    (
        "tls_verification_failure",
        lambda: _connect_error(
            ssl.SSLCertVerificationError(1, "certificate verify failed: unable to get issuer"),
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed",
        ),
    ),
    ("proxy_error", lambda: httpx.ProxyError("407 Proxy Authentication Required")),
]

_TIMEOUTS: list[Callable[[str], Exception]] = [
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
]


class TestProbeUnreachable:
    @pytest.mark.parametrize(
        "make_error", [e for _, e in _UNREACHABLE_ERRORS], ids=[n for n, _ in _UNREACHABLE_ERRORS]
    )
    async def test_transport_failures_are_unreachable(
        self,
        client: httpx.AsyncClient,
        respx_mock: respx.MockRouter,
        make_error: Callable[[], Exception],
    ) -> None:
        respx_mock.get(URL).mock(side_effect=make_error())
        status = await probe_jwks(client, URL)
        assert status.ok is False
        assert status.error_class == "unreachable"

    async def test_http_407_is_unreachable(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(URL).mock(return_value=httpx.Response(407))
        status = await probe_jwks(client, URL)
        assert status.ok is False
        assert status.error_class == "unreachable"


class TestProbeDegraded:
    @pytest.mark.parametrize("code", [500, 502, 503, 504])
    async def test_5xx_is_degraded(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter, code: int
    ) -> None:
        respx_mock.get(URL).mock(return_value=httpx.Response(code))
        status = await probe_jwks(client, URL)
        assert status.ok is False
        assert status.error_class == "degraded"

    @pytest.mark.parametrize("error", _TIMEOUTS, ids=[t.__name__ for t in _TIMEOUTS])
    async def test_timeouts_are_degraded(
        self,
        client: httpx.AsyncClient,
        respx_mock: respx.MockRouter,
        error: Callable[[str], Exception],
    ) -> None:
        respx_mock.get(URL).mock(side_effect=error("timed out"))
        status = await probe_jwks(client, URL)
        assert status.ok is False
        assert status.error_class == "degraded"


_INVALID_BODIES: list[tuple[str, Any]] = [
    ("empty_keys", {"keys": []}),
    ("keys_missing", {}),
    ("keys_not_a_list", {"keys": "nope"}),
    ("top_level_list", []),
    ("key_not_an_object", {"keys": ["k1"]}),
    ("wrong_kty", {"keys": [_key(kty="RSA")]}),
    ("missing_kty", {"keys": [_key(kty=None)]}),
    ("wrong_crv", {"keys": [_key(crv="P-384")]}),
    ("missing_crv", {"keys": [_key(crv=None)]}),
    ("missing_kid", {"keys": [_key(kid=None)]}),
    ("one_bad_key_among_good", {"keys": [_key(kid="a"), _key(kid="b", crv="P-521"), _key()]}),
]


class TestProbeInvalid:
    @pytest.mark.parametrize(
        "body", [b for _, b in _INVALID_BODIES], ids=[n for n, _ in _INVALID_BODIES]
    )
    async def test_unusable_key_sets_are_invalid(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter, body: Any
    ) -> None:
        respx_mock.get(URL).mock(return_value=httpx.Response(200, json=body))
        status = await probe_jwks(client, URL)
        assert status.ok is False
        assert status.error_class == "invalid"

    @pytest.mark.parametrize(
        "content",
        [b"<html>captive portal</html>", b"", b'{"keys": [', b"not json at all"],
        ids=["html", "empty", "truncated", "text"],
    )
    async def test_non_json_200_is_invalid(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter, content: bytes
    ) -> None:
        respx_mock.get(URL).mock(return_value=httpx.Response(200, content=content))
        status = await probe_jwks(client, URL)
        assert status.ok is False
        assert status.error_class == "invalid"

    @pytest.mark.parametrize("code", [403, 404])
    async def test_other_client_errors_are_not_ok_and_classified(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter, code: int
    ) -> None:
        respx_mock.get(URL).mock(return_value=httpx.Response(code))
        status = await probe_jwks(client, URL)
        assert status.ok is False
        assert status.error_class is not None


class TestMakeClient:
    @pytest.fixture
    def init_kwargs(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        """Record the keyword arguments make_client passes to httpx.AsyncClient."""
        captured: dict[str, Any] = {}
        original = httpx.AsyncClient.__init__

        def spy(self: httpx.AsyncClient, *args: Any, **kwargs: Any) -> None:
            captured.update(kwargs)
            original(self, *args, **kwargs)

        monkeypatch.setattr(httpx.AsyncClient, "__init__", spy)
        return captured

    async def test_returns_an_async_client(self) -> None:
        c = make_client()
        try:
            assert isinstance(c, httpx.AsyncClient)
        finally:
            await c.aclose()

    async def test_trusts_the_environment_for_proxies(self) -> None:
        c = make_client()
        try:
            assert c.trust_env is True
        finally:
            await c.aclose()

    async def test_uses_a_five_second_timeout(self) -> None:
        c = make_client()
        try:
            assert c.timeout == httpx.Timeout(5.0)
        finally:
            await c.aclose()

    async def test_verify_is_a_default_ssl_context(self, init_kwargs: dict[str, Any]) -> None:
        c = make_client()
        await c.aclose()
        context = init_kwargs["verify"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True

    async def test_verify_context_comes_from_ssl_create_default_context(
        self, init_kwargs: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        created: list[ssl.SSLContext] = []
        real = ssl.create_default_context

        def spy(*args: Any, **kwargs: Any) -> ssl.SSLContext:
            context = real(*args, **kwargs)
            created.append(context)
            return context

        monkeypatch.setattr(ssl, "create_default_context", spy)
        c = make_client()
        await c.aclose()
        assert created, "make_client must call ssl.create_default_context() (system roots)"
        assert init_kwargs["verify"] is created[-1]

    async def test_verify_is_not_a_bool_or_certifi_path(self, init_kwargs: dict[str, Any]) -> None:
        c = make_client()
        await c.aclose()
        assert not isinstance(init_kwargs["verify"], bool | str)


class TestMonitor:
    @pytest.fixture
    async def monitor(self) -> Any:
        async with httpx.AsyncClient(verify=False) as c:
            yield JwksMonitor(c, URL)

    async def test_status_is_none_before_the_first_check(self, monitor: JwksMonitor) -> None:
        assert monitor.status is None

    async def test_check_returns_and_stores_an_ok_status(
        self, monitor: JwksMonitor, respx_mock: respx.MockRouter, jwks_doc: dict[str, Any]
    ) -> None:
        respx_mock.get(URL).mock(return_value=httpx.Response(200, json=jwks_doc))
        status = await monitor.check()
        assert status.ok is True
        assert monitor.status is status

    async def test_check_stores_a_failure_status(
        self, monitor: JwksMonitor, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(URL).mock(return_value=httpx.Response(502))
        status = await monitor.check()
        assert (status.ok, status.error_class) == (False, "degraded")
        assert monitor.status is status

    async def test_status_tracks_recovery_on_the_next_check(
        self, monitor: JwksMonitor, respx_mock: respx.MockRouter, jwks_doc: dict[str, Any]
    ) -> None:
        respx_mock.get(URL).mock(
            side_effect=[
                _connect_error(ConnectionRefusedError()),
                httpx.Response(200, json=jwks_doc),
            ]
        )
        first = await monitor.check()
        second = await monitor.check()
        assert first.error_class == "unreachable"
        assert second.ok is True
        assert monitor.status is second
        assert second.checked_at >= first.checked_at

    async def test_check_does_not_raise_on_an_unexpected_client_exception(
        self, monitor: JwksMonitor, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(URL).mock(side_effect=RuntimeError("boom"))
        status = await monitor.check()
        assert status.ok is False
        assert status.error_class == "internal_error"
        assert monitor.status is status

    async def test_check_does_not_raise_when_the_probe_itself_fails(
        self, monitor: JwksMonitor, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def broken(_client: httpx.AsyncClient, _url: str) -> JwksStatus:
            raise ValueError("probe exploded")

        monkeypatch.setattr(jwks_module, "probe_jwks", broken)
        status = await monitor.check()
        assert status.ok is False
        assert status.error_class == "internal_error"
        assert status.checked_at.utcoffset() == timedelta(0)
        assert monitor.status is status

    async def test_unexpected_exception_is_logged(
        self, monitor: JwksMonitor, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def broken(_client: httpx.AsyncClient, _url: str) -> JwksStatus:
            raise ValueError("probe exploded")

        monkeypatch.setattr(jwks_module, "probe_jwks", broken)
        with structlog.testing.capture_logs() as logs:
            await monitor.check()
        assert [e for e in logs if e["log_level"] in ("error", "warning", "critical")]


class TestMark:
    @pytest.fixture
    async def monitor(self) -> Any:
        async with httpx.AsyncClient(verify=False) as c:
            yield JwksMonitor(c, URL)

    async def test_mark_stores_and_returns_the_class_and_reason(
        self, monitor: JwksMonitor
    ) -> None:
        status = monitor.mark("degraded", "check_timeout")
        assert (status.ok, status.error_class, status.reason) == (
            False, "degraded", "check_timeout",
        )
        assert status.checked_at.utcoffset() == timedelta(0)
        assert monitor.status is status

    async def test_mark_replaces_a_stale_ok_status(
        self, monitor: JwksMonitor, respx_mock: respx.MockRouter, jwks_doc: dict[str, Any]
    ) -> None:
        respx_mock.get(URL).mock(return_value=httpx.Response(200, json=jwks_doc))
        assert (await monitor.check()).ok is True
        monitor.mark("degraded", "check_timeout")
        assert monitor.status is not None and monitor.status.ok is False

    async def test_the_next_check_clears_the_reason(
        self, monitor: JwksMonitor, respx_mock: respx.MockRouter, jwks_doc: dict[str, Any]
    ) -> None:
        monitor.mark("degraded", "check_timeout")
        respx_mock.get(URL).mock(return_value=httpx.Response(200, json=jwks_doc))
        status = await monitor.check()
        assert (status.ok, status.error_class, status.reason) == (True, None, None)

    async def test_mark_rejects_an_unknown_error_class(self, monitor: JwksMonitor) -> None:
        with pytest.raises(ValueError, match="error_class"):
            monitor.mark("bogus", "x")

    async def test_mark_logs_a_warning_with_the_reason(self, monitor: JwksMonitor) -> None:
        with structlog.testing.capture_logs() as logs:
            monitor.mark("degraded", "check_timeout")
        [entry] = [e for e in logs if e["event"] == "jwks.marked"]
        assert entry["log_level"] == "warning"
        assert entry["reason"] == "check_timeout"


class TestLogging:
    @pytest.mark.parametrize(
        "make_error", [e for _, e in _UNREACHABLE_ERRORS], ids=[n for n, _ in _UNREACHABLE_ERRORS]
    )
    async def test_unreachable_logs_an_error(
        self,
        client: httpx.AsyncClient,
        respx_mock: respx.MockRouter,
        make_error: Callable[[], Exception],
    ) -> None:
        respx_mock.get(URL).mock(side_effect=make_error())
        with structlog.testing.capture_logs() as logs:
            await probe_jwks(client, URL)
        entries = [e for e in logs if e["event"] == "jwks.unreachable"]
        assert len(entries) == 1
        assert entries[0]["log_level"] == "error"

    async def test_http_407_logs_unreachable_as_an_error(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(URL).mock(return_value=httpx.Response(407))
        with structlog.testing.capture_logs() as logs:
            await probe_jwks(client, URL)
        entries = [e for e in logs if e["event"] == "jwks.unreachable"]
        assert [e["log_level"] for e in entries] == ["error"]

    async def test_5xx_logs_a_degraded_warning(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(URL).mock(return_value=httpx.Response(503))
        with structlog.testing.capture_logs() as logs:
            await probe_jwks(client, URL)
        entries = [e for e in logs if e["event"] == "jwks.degraded"]
        assert [e["log_level"] for e in entries] == ["warning"]

    async def test_timeout_logs_a_degraded_warning(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(URL).mock(side_effect=httpx.ReadTimeout("timed out"))
        with structlog.testing.capture_logs() as logs:
            await probe_jwks(client, URL)
        entries = [e for e in logs if e["event"] == "jwks.degraded"]
        assert [e["log_level"] for e in entries] == ["warning"]

    async def test_ok_logs_no_unreachable_or_degraded_event(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter, jwks_doc: dict[str, Any]
    ) -> None:
        respx_mock.get(URL).mock(return_value=httpx.Response(200, json=jwks_doc))
        with structlog.testing.capture_logs() as logs:
            await probe_jwks(client, URL)
        assert not [e for e in logs if e["event"] in ("jwks.unreachable", "jwks.degraded")]

    @pytest.mark.parametrize(
        "response",
        [
            httpx.Response(503, content=BODY_MARKER.encode()),
            httpx.Response(407, content=BODY_MARKER.encode()),
            httpx.Response(404, content=BODY_MARKER.encode()),
            httpx.Response(200, content=BODY_MARKER.encode()),
            httpx.Response(200, json={"keys": [_key(kid=None, x=BODY_MARKER)]}),
            httpx.Response(200, json={"keys": [], "note": BODY_MARKER}),
        ],
        ids=["503", "407", "404", "200_non_json", "200_bad_key", "200_empty_keys"],
    )
    async def test_log_lines_never_contain_the_response_body(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter, response: httpx.Response
    ) -> None:
        respx_mock.get(URL).mock(return_value=response)
        with structlog.testing.capture_logs() as logs:
            await probe_jwks(client, URL)
        assert BODY_MARKER not in repr(logs)

    async def test_monitor_check_logs_carry_no_response_body(
        self, client: httpx.AsyncClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(URL).mock(return_value=httpx.Response(503, content=BODY_MARKER.encode()))
        with structlog.testing.capture_logs() as logs:
            await JwksMonitor(client, URL).check()
        assert BODY_MARKER not in repr(logs)


class TestProbeUserAgent:
    async def test_probe_sends_the_attribution_user_agent_with_no_keys(
        self, monkeypatch: pytest.MonkeyPatch, jwks_doc: dict[str, Any]
    ) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers["User-Agent"])
            return httpx.Response(200, json=jwks_doc)

        original = httpx.AsyncClient.__init__

        def with_mock_transport(self: httpx.AsyncClient, *args: Any, **kwargs: Any) -> None:
            original(self, *args, transport=httpx.MockTransport(handler), **kwargs)

        monkeypatch.setattr(httpx.AsyncClient, "__init__", with_mock_transport)
        c = make_client()
        try:
            status = await probe_jwks(c, URL)
        finally:
            await c.aclose()

        assert status.ok is True
        assert seen == [f"twingate-gwops-gateway/{__version__} python-httpx/{httpx.__version__}"]
