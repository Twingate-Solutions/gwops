"""Tests for gwops.tgapi.client.TGClient: retries, backoff, error surfacing, logging."""

import dataclasses
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
import structlog

from gwops.kinds import KINDS, SSH
from gwops.tgapi import ops
from gwops.tgapi.client import (
    _PASS_THROTTLE_BUDGET_SECONDS,
    TGClient,
    _backoff_delay,
    _is_mutation,
    _operation_name,
    _parse_body_hint,
    _parse_retry_after,
)
from gwops.tgapi.errors import TGAPIError, TGAuthError, TGGraphQLError, TGRateLimited

_URL = "https://acme.twingate.com/api/graphql/"
_API_KEY = "tg-secret-key-XYZ"


@pytest.fixture
def client() -> Iterator[TGClient]:
    tg = TGClient(network="acme", api_key=_API_KEY)
    yield tg


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Patch asyncio.sleep in the client module so backoff tests run instantly."""
    fake_sleep = AsyncMock()
    monkeypatch.setattr("gwops.tgapi.client.asyncio.sleep", fake_sleep)
    return fake_sleep


class TestBackoffDelay:
    def test_exponential_growth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("gwops.tgapi.client.random.uniform", lambda lo, hi: hi)
        assert _backoff_delay(1) == pytest.approx(1.0)
        assert _backoff_delay(2) == pytest.approx(2.0)
        assert _backoff_delay(3) == pytest.approx(4.0)
        assert _backoff_delay(4) == pytest.approx(8.0)
        assert _backoff_delay(5) == pytest.approx(16.0)

    def test_capped_at_thirty_seconds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("gwops.tgapi.client.random.uniform", lambda lo, hi: hi)
        assert _backoff_delay(6) == pytest.approx(30.0)
        assert _backoff_delay(10) == pytest.approx(30.0)

    def test_jitter_is_between_zero_and_ceiling(self) -> None:
        for _ in range(50):
            delay = _backoff_delay(3)
            assert 0.0 <= delay <= 4.0


class TestRetryOn429:
    async def test_retries_once_then_succeeds(
        self, client: TGClient, _no_real_sleep: AsyncMock, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(429, json={"error": "rate limited"}),
            httpx.Response(200, json={"data": {"ok": True}}),
        ]
        data = await client.execute("query Q { ok }", {})
        assert data == {"ok": True}
        assert route.call_count == 2
        assert _no_real_sleep.await_count == 1


_THROTTLE_MESSAGE = "Request was throttled. Expected available in {n} seconds."
_JITTER = 0.25  # what the patched RNG returns, so jitter shows up in the slept value


@pytest.fixture
def jitter_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[float, float]]:
    """Pin the client's RNG to a constant and record every (lo, hi) it was asked for."""
    calls: list[tuple[float, float]] = []

    def _uniform(lo: float, hi: float) -> float:
        calls.append((lo, hi))
        return _JITTER

    monkeypatch.setattr("gwops.tgapi.client.random.uniform", _uniform)
    return calls


def _throttled_then_ok(throttle: httpx.Response) -> list[httpx.Response]:
    return [throttle, httpx.Response(200, json={"data": {"ok": True}})]


class TestThrottleWait:
    """On 429 the client waits for the server's hint (capped), plus jitter."""

    async def test_retry_after_seconds_is_honoured(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(httpx.Response(429, headers={"Retry-After": "7"}))
        assert await client.execute("query Q { ok }", {}) == {"ok": True}
        assert route.call_count == 2
        _no_real_sleep.assert_awaited_once_with(7 + _JITTER)
        assert jitter_calls == [(0, 1.0)]

    async def test_retry_after_http_date_is_honoured(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        monkeypatch: pytest.MonkeyPatch,
        respx_mock: respx.MockRouter,
    ) -> None:
        now = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)
        monkeypatch.setattr("gwops.tgapi.client._utcnow", lambda: now)
        when = format_datetime(now + timedelta(seconds=30), usegmt=True)
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(httpx.Response(429, headers={"Retry-After": when}))
        await client.execute("query Q { ok }", {})
        _no_real_sleep.assert_awaited_once_with(30 + _JITTER)

    async def test_retry_after_http_date_in_the_past_waits_only_the_jitter(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        monkeypatch: pytest.MonkeyPatch,
        respx_mock: respx.MockRouter,
    ) -> None:
        now = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)
        monkeypatch.setattr("gwops.tgapi.client._utcnow", lambda: now)
        when = format_datetime(now - timedelta(seconds=30), usegmt=True)
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(httpx.Response(429, headers={"Retry-After": when}))
        await client.execute("query Q { ok }", {})
        _no_real_sleep.assert_awaited_once_with(0 + _JITTER)

    async def test_body_hint_is_parsed_when_no_retry_after(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
    ) -> None:
        body = {"errors": [{"message": _THROTTLE_MESSAGE.format(n=12)}]}
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(httpx.Response(429, json=body))
        await client.execute("query Q { ok }", {})
        _no_real_sleep.assert_awaited_once_with(12 + _JITTER)
        assert jitter_calls == [(0, 1.0)]

    async def test_body_hint_singular_second_and_plain_text_body(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(
            httpx.Response(429, text="Throttled. expected available in 1 second.")
        )
        await client.execute("query Q { ok }", {})
        _no_real_sleep.assert_awaited_once_with(1 + _JITTER)

    async def test_retry_after_wins_over_body_hint(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(
            httpx.Response(
                429,
                headers={"Retry-After": "3"},
                json={"errors": [{"message": _THROTTLE_MESSAGE.format(n=40)}]},
            )
        )
        await client.execute("query Q { ok }", {})
        _no_real_sleep.assert_awaited_once_with(3 + _JITTER)

    async def test_unparseable_retry_after_falls_back_to_body_hint(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(
            httpx.Response(
                429,
                headers={"Retry-After": "soon"},
                json={"errors": [{"message": _THROTTLE_MESSAGE.format(n=9)}]},
            )
        )
        await client.execute("query Q { ok }", {})
        _no_real_sleep.assert_awaited_once_with(9 + _JITTER)

    async def test_no_hint_falls_back_to_exponential_backoff(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(httpx.Response(429, text="slow down"))
        await client.execute("query Q { ok }", {})
        # Attempt 1's backoff ceiling is 1 s; the patched RNG returns its constant.
        _no_real_sleep.assert_awaited_once_with(_JITTER)
        assert jitter_calls == [(0, 1.0)]

    async def test_retry_after_is_capped_at_sixty_seconds(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(
            httpx.Response(429, headers={"Retry-After": "3600"})
        )
        await client.execute("query Q { ok }", {})
        _no_real_sleep.assert_awaited_once_with(60 + _JITTER)

    async def test_body_hint_is_capped_at_sixty_seconds(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
    ) -> None:
        body = {"errors": [{"message": _THROTTLE_MESSAGE.format(n=500)}]}
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(httpx.Response(429, json=body))
        await client.execute("query Q { ok }", {})
        _no_real_sleep.assert_awaited_once_with(60 + _JITTER)

    async def test_hint_below_cap_is_not_stretched(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(httpx.Response(429, headers={"Retry-After": "60"}))
        await client.execute("query Q { ok }", {})
        _no_real_sleep.assert_awaited_once_with(60 + _JITTER)

    async def test_jitter_is_drawn_fresh_for_every_throttle(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        monkeypatch: pytest.MonkeyPatch,
        respx_mock: respx.MockRouter,
    ) -> None:
        draws = iter([0.1, 0.9])
        monkeypatch.setattr("gwops.tgapi.client.random.uniform", lambda lo, hi: next(draws))
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(429, headers={"Retry-After": "5"}),
            httpx.Response(429, headers={"Retry-After": "5"}),
            httpx.Response(200, json={"data": {"ok": True}}),
        ]
        await client.execute("query Q { ok }", {})
        waits = [c.args[0] for c in _no_real_sleep.await_args_list]
        assert waits == pytest.approx([5.1, 5.9])

    async def test_exhausted_throttling_still_raises_rate_limited(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(429, headers={"Retry-After": "2"}))
        with pytest.raises(TGRateLimited):
            await client.execute("query Q { ok }", {})
        assert route.call_count == 6
        assert [c.args[0] for c in _no_real_sleep.await_args_list] == [2 + _JITTER] * 5


class TestWriteThrottleCount:
    """Only throttled mutations move `write_throttle_count`; reads never do."""

    async def test_throttled_mutation_increments_even_when_the_retry_succeeds(
        self, client: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(httpx.Response(429, headers={"Retry-After": "1"}))
        assert client.write_throttle_count == 0
        await client.execute("mutation M { ok }", {})
        assert client.write_throttle_count == 1

    async def test_throttled_read_does_not_increment(
        self, client: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(httpx.Response(429, headers={"Retry-After": "1"}))
        await client.execute("query Q { ok }", {})
        assert client.write_throttle_count == 0

    async def test_every_429_of_a_mutation_counts_including_the_final_one(
        self, client: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(429, headers={"Retry-After": "1"}))
        with pytest.raises(TGRateLimited):
            await client.execute("\n  mutation M { ok }", {})
        assert client.write_throttle_count == 6

    async def test_5xx_on_a_mutation_does_not_increment(
        self, client: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(503, text="down"),
            httpx.Response(200, json={"data": {"ok": True}}),
        ]
        await client.execute("mutation M { ok }", {})
        assert client.write_throttle_count == 0


class TestThrottleLogging:
    async def test_throttle_event_reports_wait_without_secrets(
        self,
        client: TGClient,
        capsys: pytest.CaptureFixture[str],
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
    ) -> None:
        from gwops.logging import configure_logging

        configure_logging()
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(
            httpx.Response(429, headers={"Retry-After": "3600"})
        )
        await client.execute("mutation DoIt { ok }", {})
        out = capsys.readouterr().out
        assert _API_KEY not in out
        records = [json.loads(line) for line in out.splitlines() if line.strip()]
        [event] = [r for r in records if r["event"] == "tgapi.throttled"]
        assert event["query_name"] == "DoIt"
        assert event["is_write"] is True
        assert event["attempt"] == 1
        assert event["wait_source"] == "retry-after"
        assert event["server_hint_seconds"] == 3600
        assert event["capped"] is True
        assert event["wait_seconds"] == 60 + _JITTER


class TestRetryExhaustionOn5xx:
    async def test_raises_after_max_attempts(
        self, client: TGClient, _no_real_sleep: AsyncMock, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(503, text="upstream unavailable"))
        with pytest.raises(TGAPIError) as exc_info:
            await client.execute("query Q { ok }", {})
        assert exc_info.value.status == 503
        assert exc_info.value.query_name == "Q"
        assert route.call_count == 6
        assert _no_real_sleep.await_count == 5


class TestNoRetryOnOther4xx:
    async def test_400_raises_immediately(
        self, client: TGClient, _no_real_sleep: AsyncMock, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(400, text="bad request"))
        with pytest.raises(TGAPIError) as exc_info:
            await client.execute("query Q { ok }", {})
        assert exc_info.value.status == 400
        assert route.call_count == 1
        assert _no_real_sleep.await_count == 0

    async def test_401_raises_tg_auth_error_immediately(
        self, client: TGClient, _no_real_sleep: AsyncMock, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(401, text="invalid token"))
        with pytest.raises(TGAuthError):
            await client.execute("query Q { ok }", {})
        assert route.call_count == 1
        assert _no_real_sleep.await_count == 0

    async def test_403_raises_tg_auth_error_immediately(
        self, client: TGClient, _no_real_sleep: AsyncMock, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(403, text="forbidden"))
        with pytest.raises(TGAuthError):
            await client.execute("query Q { ok }", {})
        assert route.call_count == 1


class TestRateLimitExhaustion:
    async def test_429_exhaustion_raises_tg_rate_limited(
        self, client: TGClient, _no_real_sleep: AsyncMock, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(429, text="slow down"))
        with pytest.raises(TGRateLimited):
            await client.execute("query Q { ok }", {})
        assert route.call_count == 6
        assert _no_real_sleep.await_count == 5


class TestTransportErrorRetry:
    async def test_retries_on_connect_error_then_succeeds(
        self, client: TGClient, _no_real_sleep: AsyncMock, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.ConnectError("connection refused"),
            httpx.Response(200, json={"data": {"ok": True}}),
        ]
        data = await client.execute("query Q { ok }", {})
        assert data == {"ok": True}
        assert route.call_count == 2
        assert _no_real_sleep.await_count == 1

    async def test_exhausts_after_max_attempts(
        self, client: TGClient, _no_real_sleep: AsyncMock, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(side_effect=httpx.ConnectError("connection refused"))
        with pytest.raises(TGAPIError) as exc_info:
            await client.execute("query Q { ok }", {})
        assert exc_info.value.status is None
        assert route.call_count == 6
        assert _no_real_sleep.await_count == 5


class TestGraphQLErrorSurfacing:
    async def test_200_with_errors_raises_tg_graphql_error(
        self, client: TGClient, _no_real_sleep: AsyncMock, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200, json={"data": None, "errors": [{"message": "field not found"}]}
            )
        )
        with pytest.raises(TGGraphQLError) as exc_info:
            await client.execute("query Q { ok }", {})
        assert exc_info.value.errors == [{"message": "field not found"}]
        assert route.call_count == 1
        assert _no_real_sleep.await_count == 0


class TestSuccessfulExecute:
    async def test_returns_data_payload(
        self, client: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json={"data": {"resources": []}}))
        data = await client.execute("query ListResources { resources { id } }", {"first": 50})
        assert data == {"resources": []}
        sent = json.loads(route.calls.last.request.content)
        assert sent == {
            "query": "query ListResources { resources { id } }",
            "variables": {"first": 50},
        }

    async def test_sends_x_api_key_header(
        self, client: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json={"data": {}}))
        await client.execute("query Q { ok }", {})
        assert route.calls.last.request.headers["X-API-KEY"] == _API_KEY

    async def test_host_override_changes_url(self, respx_mock: respx.MockRouter) -> None:
        tg = TGClient(network="acme", api_key=_API_KEY, host="twingate.example")
        route = respx_mock.post("https://acme.twingate.example/api/graphql/")
        route.mock(return_value=httpx.Response(200, json={"data": {}}))
        await tg.execute("query Q { ok }", {})
        assert route.called


class TestApiKeyNeverLogged:
    async def test_logs_never_contain_the_api_key(
        self,
        client: TGClient,
        capsys: pytest.CaptureFixture[str],
        respx_mock: respx.MockRouter,
    ) -> None:
        from gwops.logging import configure_logging

        configure_logging()
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(429, json={}),
            httpx.Response(200, json={"data": {"ok": True}}),
        ]
        await client.execute("query Q { ok }", {})
        out = capsys.readouterr().out
        assert _API_KEY not in out
        # sanity: something was actually logged, and it carries the fields we expect
        lines = [line for line in out.strip().splitlines() if line]
        assert lines
        records = [json.loads(line) for line in lines]
        assert any("status" in r and "duration" in r for r in records)
        assert any(r.get("query_name") == "Q" for r in records)


class TestNonJsonResponseBody:
    async def test_200_with_non_json_body_raises_tgapi_error(
        self, client: TGClient, _no_real_sleep: AsyncMock, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, text="<html>not json</html>"))
        with pytest.raises(TGAPIError) as exc_info:
            await client.execute("query Q { ok }", {})
        assert exc_info.value.status == 200
        assert exc_info.value.query_name == "Q"
        assert "not json" in exc_info.value.body
        assert route.call_count == 1
        assert _no_real_sleep.await_count == 0

    async def test_200_with_non_object_json_body_raises_tgapi_error(
        self, client: TGClient, _no_real_sleep: AsyncMock, respx_mock: respx.MockRouter
    ) -> None:
        # Valid JSON but not a top-level object (e.g. a misconfigured proxy) must
        # surface as a typed TGAPIError, not an AttributeError from body.get(...).
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json=["not", "an", "object"]))
        with pytest.raises(TGAPIError) as exc_info:
            await client.execute("query Q { ok }", {})
        assert exc_info.value.status == 200
        assert exc_info.value.query_name == "Q"
        assert "not" in exc_info.value.body
        assert route.call_count == 1
        assert _no_real_sleep.await_count == 0


class TestStructlogFieldsExplicitly:
    async def test_logs_query_name_status_duration(
        self,
        client: TGClient,
        capsys: pytest.CaptureFixture[str],
        respx_mock: respx.MockRouter,
    ) -> None:
        structlog.configure(
            processors=[structlog.processors.JSONRenderer()],
            logger_factory=structlog.PrintLoggerFactory(),
        )
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json={"data": {"ok": True}}))
        await client.execute("query ListResources { ok }", {})
        out = capsys.readouterr().out
        record = json.loads(out.strip().splitlines()[-1])
        assert record["query_name"] == "ListResources"
        assert record["status"] == 200
        assert "duration" in record


_HOSTILE_RETRY_AFTER = [
    pytest.param("1" * 400, id="400-digits"),
    pytest.param("1" * 5000, id="5000-digits"),
    pytest.param("Wed, 21 Oct 99999999999999999999 07:28:00 GMT", id="date-overflow"),
    pytest.param("not-a-time", id="garbage"),
    pytest.param("-5", id="negative"),
    pytest.param("1.5", id="fractional"),
]
_NOW = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)


class TestHostileThrottleHints:
    """A header/body value from the server must never raise out of `execute()`."""

    @pytest.mark.parametrize("value", _HOSTILE_RETRY_AFTER)
    def test_unparseable_retry_after_is_none(self, value: str) -> None:
        assert _parse_retry_after(value, _NOW) is None

    def test_nine_digit_delta_seconds_still_parses(self) -> None:
        assert _parse_retry_after("999999999", _NOW) == 999_999_999.0

    @pytest.mark.parametrize("digits", [400, 5000])
    def test_non_finite_body_hint_is_none(self, digits: int) -> None:
        assert _parse_body_hint(f"Expected available in {'9' * digits} seconds") is None

    def test_ordinary_body_hint_still_parses(self) -> None:
        assert _parse_body_hint("Expected available in 12.5 seconds.") == 12.5

    @pytest.mark.parametrize("value", _HOSTILE_RETRY_AFTER)
    async def test_hostile_retry_after_falls_back_to_backoff(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
        capsys: pytest.CaptureFixture[str],
        value: str,
    ) -> None:
        from gwops.logging import configure_logging

        configure_logging()
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(httpx.Response(429, headers={"Retry-After": value}))

        assert await client.execute("query Q { ok }", {}) == {"ok": True}

        # Backoff for attempt 1 is uniform(0, 1.0): the pinned RNG returns _JITTER.
        _no_real_sleep.assert_awaited_once_with(_JITTER)
        assert jitter_calls == [(0, 1.0)]
        out = capsys.readouterr().out
        records = [json.loads(line) for line in out.splitlines() if line.strip()]
        assert [r for r in records if r["event"] == "tgapi.retry_after_unparseable"]
        [event] = [r for r in records if r["event"] == "tgapi.throttled"]
        assert event["wait_source"] == "backoff"
        assert event["server_hint_seconds"] is None

    @pytest.mark.parametrize("digits", [400, 5000])
    async def test_non_finite_body_hint_falls_back_and_logs_valid_json(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
        capsys: pytest.CaptureFixture[str],
        digits: int,
    ) -> None:
        from gwops.logging import configure_logging

        configure_logging()
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(
            httpx.Response(429, text=f"Expected available in {'9' * digits} seconds")
        )

        assert await client.execute("query Q { ok }", {}) == {"ok": True}

        _no_real_sleep.assert_awaited_once_with(_JITTER)
        out = capsys.readouterr().out
        assert "Infinity" not in out
        assert "NaN" not in out
        [event] = [
            r for r in map(json.loads, out.splitlines()) if r["event"] == "tgapi.throttled"
        ]
        assert event["wait_source"] == "backoff"
        assert event["server_hint_seconds"] is None

    async def test_any_failure_deriving_the_hint_falls_back_to_backoff(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        monkeypatch: pytest.MonkeyPatch,
        respx_mock: respx.MockRouter,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from gwops.logging import configure_logging

        configure_logging()

        def _boom(value: str, now: datetime) -> float | None:
            raise RuntimeError("unexpected")

        monkeypatch.setattr("gwops.tgapi.client._parse_retry_after", _boom)
        route = respx_mock.post(_URL)
        route.side_effect = _throttled_then_ok(httpx.Response(429, headers={"Retry-After": "5"}))

        assert await client.execute("query Q { ok }", {}) == {"ok": True}

        _no_real_sleep.assert_awaited_once_with(_JITTER)
        events = [json.loads(line)["event"] for line in capsys.readouterr().out.splitlines()]
        assert "tgapi.retry_after_unparseable" in events


class TestThrottleBudget:
    """429 sleeping is capped per pass; the next wait that would overrun raises at once."""

    async def test_budget_is_consumed_across_calls(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
    ) -> None:
        assert _PASS_THROTTLE_BUDGET_SECONDS == 90.0
        assert client.throttle_budget_remaining == 90.0
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(429, headers={"Retry-After": "40"}),
            httpx.Response(429, headers={"Retry-After": "40"}),
            httpx.Response(200, json={"data": {"ok": True}}),
            httpx.Response(429, headers={"Retry-After": "40"}),
        ]

        await client.execute("query Q { ok }", {})
        assert client.throttle_budget_remaining == pytest.approx(90.0 - 2 * 40.25)

        # The second call's wait (40.25 s) no longer fits in the 9.5 s left: no sleep, no retry.
        with pytest.raises(TGRateLimited, match="budget is exhausted"):
            await client.execute("query Q { ok }", {})
        assert route.call_count == 4
        assert _no_real_sleep.await_count == 2
        assert client.throttle_budget_remaining == pytest.approx(9.5)

    async def test_begin_pass_restores_the_full_budget(
        self,
        client: TGClient,
        _no_real_sleep: AsyncMock,
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(429, headers={"Retry-After": "60"}),
            httpx.Response(200, json={"data": {"ok": True}}),
            httpx.Response(429, headers={"Retry-After": "60"}),
            httpx.Response(429, headers={"Retry-After": "60"}),
            httpx.Response(200, json={"data": {"ok": True}}),
        ]
        await client.execute("query Q { ok }", {})
        with pytest.raises(TGRateLimited):
            await client.execute("query Q { ok }", {})  # 29.75 s left, wants 60.25

        client.begin_pass()

        assert client.throttle_budget_remaining == 90.0
        assert await client.execute("query Q { ok }", {}) == {"ok": True}
        assert route.call_count == 5

    async def test_exhaustion_is_logged_and_a_write_still_counts_as_throttled(
        self,
        client: TGClient,
        jitter_calls: list[tuple[float, float]],
        respx_mock: respx.MockRouter,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from gwops.logging import configure_logging

        configure_logging()
        client._throttle_budget_remaining = 5.0
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(429, headers={"Retry-After": "30"}))

        with pytest.raises(TGRateLimited) as exc_info:
            await client.execute("mutation DoIt { ok }", {})

        assert exc_info.value.status == 429
        assert route.call_count == 1
        assert client.write_throttle_count == 1  # the reconciler defers later writes on this
        records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        [event] = [r for r in records if r["event"] == "tgapi.throttle_budget_exhausted"]
        assert event["query_name"] == "DoIt"
        assert event["is_write"] is True
        assert event["budget_remaining_seconds"] == 5.0
        assert event["wait_seconds"] == 30 + _JITTER

    async def test_non_429_retries_do_not_draw_on_the_budget(
        self, client: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(503, text="down"),
            httpx.ConnectError("refused"),
            httpx.Response(200, json={"data": {"ok": True}}),
        ]
        await client.execute("query Q { ok }", {})
        assert client.throttle_budget_remaining == 90.0


def _ops_graphql_documents() -> dict[str, str]:
    """Every GraphQL document ops.py can send: module constants plus per-kind builders."""
    docs: dict[str, str] = {}
    for name, value in vars(ops).items():
        if isinstance(value, str) and value.lstrip().startswith(("mutation", "query")):
            docs[name] = value
    for kind in KINDS:
        docs[f"_create_mutation[{kind.key}]"] = ops._create_mutation(kind)
        docs[f"_update_upstream_mutation[{kind.key}]"] = ops._update_upstream_mutation(kind)
        docs[f"_update_address_mutation[{kind.key}]"] = ops._update_address_mutation(kind)
        docs[f"_update_access_mutation[{kind.key}]"] = ops._update_access_mutation(kind)
        docs[f"_update_settings_mutation[{kind.key}]"] = ops._update_settings_mutation(kind)
    custom = dataclasses.replace(SSH, update_mutation="sshResourceUpdate")
    docs["_update_address_mutation[custom update_mutation]"] = ops._update_address_mutation(custom)
    docs["_update_access_mutation[custom update_mutation]"] = ops._update_access_mutation(custom)
    return docs


class TestWriteDetection:
    """`_is_mutation` decides what counts as a throttled write; it must see every mutation."""

    def test_the_document_inventory_is_not_empty(self) -> None:
        docs = _ops_graphql_documents()
        assert sum(1 for d in docs.values() if d.lstrip().startswith("mutation")) >= 15
        assert sum(1 for d in docs.values() if d.lstrip().startswith("query")) >= 5

    @pytest.mark.parametrize("name", sorted(_ops_graphql_documents()))
    def test_every_ops_document_is_classified_by_its_keyword(self, name: str) -> None:
        document = _ops_graphql_documents()[name]
        assert _is_mutation(document) is document.lstrip().startswith("mutation"), name
        assert _operation_name(document) != "anonymous", name

    @pytest.mark.parametrize("name", sorted(_ops_graphql_documents()))
    def test_leading_comment_lines_do_not_hide_the_operation(self, name: str) -> None:
        document = _ops_graphql_documents()[name]
        commented = "# a comment\n   # another, mentioning mutation\n\n" + document
        assert _is_mutation(commented) is _is_mutation(document), name
        assert _operation_name(commented) == _operation_name(document), name

    def test_a_comment_mentioning_mutation_does_not_make_a_query_a_write(self) -> None:
        assert _is_mutation("# mutation\nquery Q { ok }") is False

    def test_an_anonymous_query_and_a_shorthand_query_are_reads(self) -> None:
        assert _is_mutation("query { ok }") is False
        assert _is_mutation("{ ok }") is False
