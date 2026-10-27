"""``update_webapp_resource``: one merged ``webAppResourceUpdate`` with presence-significant keys.

Ids and settings come from the capture in ``tests/fixtures/tg/tg_webapp_list.json``; the
mutation text is compared byte for byte.
"""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
import structlog.testing

from gwops.kinds import WEBAPP
from gwops.logging import configure_logging
from gwops.tgapi.client import TGClient
from gwops.tgapi.errors import TGAPIError, TGGraphQLError, TGRateLimited
from gwops.tgapi.ops import list_resources, update_webapp_resource

_URL = "https://acme.twingate.com/api/graphql/"
_FIXTURE = Path(__file__).parent.parent / "fixtures" / "tg" / "tg_webapp_list.json"

# A header-template value that must never surface in a log line or an exception message.
_SENTINEL = "{{username}}-SENTINEL-8f3a"

_ALL_KEYS_TEXT = """
mutation UpdateWebAppResource($id: ID!, $address: String, $alias: String, $upstream: WebAppUpstreamInput, $downstream: WebAppDownstreamInput, $requestHeaderRewrites: [KeyValueInputObject!], $addedGroupIds: [ID], $removedGroupIds: [ID], $securityPolicyId: ID, $gatewayId: ID) {
  webAppResourceUpdate(id: $id, address: $address, alias: $alias, upstream: $upstream, downstream: $downstream, requestHeaderRewrites: $requestHeaderRewrites, addedGroupIds: $addedGroupIds, removedGroupIds: $removedGroupIds, securityPolicyId: $securityPolicyId, gatewayId: $gatewayId) {
    ok
    error
  }
}
"""  # noqa: E501

_ADDRESS_ONLY_TEXT = """
mutation UpdateWebAppResource($id: ID!, $address: String) {
  webAppResourceUpdate(id: $id, address: $address) {
    ok
    error
  }
}
"""


def _nodes() -> dict[str, dict[str, Any]]:
    payload = json.loads(_FIXTURE.read_text())
    return {e["node"]["name"]: e["node"] for e in payload["data"]["resources"]["edges"]}


_FULL = _nodes()["lt-full"]
_ID = str(_FULL["id"])
_GATEWAY = str(_FULL["gateway"]["id"])


@pytest.fixture
def tg() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="tg-secret-key")


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    fake_sleep = AsyncMock()
    monkeypatch.setattr("gwops.tgapi.client.asyncio.sleep", fake_sleep)
    return fake_sleep


def _ok() -> httpx.Response:
    return httpx.Response(
        200, json={"data": {"webAppResourceUpdate": {"ok": True, "error": None}}}
    )


def _sent(route: respx.Route) -> list[dict[str, Any]]:
    return [json.loads(call.request.content) for call in route.calls]


async def _update(tg: TGClient, respx_mock: respx.MockRouter, **kwargs: Any) -> dict[str, Any]:
    """Run the op against an ok response; return the one request body sent."""
    route = respx_mock.post(_URL)
    route.mock(return_value=_ok())
    await update_webapp_resource(tg, _ID, **kwargs)
    [sent] = _sent(route)
    return sent


_LEG = {"port": 8443, "tlsMode": "VERIFY_FULL"}
_REWRITES = [{"key": "X-User", "value": "{{username}}"}]

_EACH_KEY: list[tuple[dict[str, Any], str, str, Any]] = [
    ({"address": "new.internal"}, "address", "String", "new.internal"),
    ({"alias": "wiki.corp.internal"}, "alias", "String", "wiki.corp.internal"),
    ({"upstream": _LEG}, "upstream", "WebAppUpstreamInput", _LEG),
    (
        {"downstream": {"port": 443, "tlsMode": "TLS13"}},
        "downstream",
        "WebAppDownstreamInput",
        {"port": 443, "tlsMode": "TLS13"},
    ),
    (
        {"request_header_rewrites": _REWRITES},
        "requestHeaderRewrites",
        "[KeyValueInputObject!]",
        _REWRITES,
    ),
    ({"added_group_ids": ["g-1", "g-2"]}, "addedGroupIds", "[ID]", ["g-1", "g-2"]),
    ({"removed_group_ids": ["g-3"]}, "removedGroupIds", "[ID]", ["g-3"]),
    ({"security_policy_id": "p-1"}, "securityPolicyId", "ID", "p-1"),
    ({"gateway_id": "gw-2"}, "gatewayId", "ID", "gw-2"),
]


class TestPresenceIsSignificant:
    @pytest.mark.parametrize(("kwargs", "variable", "gql_type", "value"), _EACH_KEY)
    async def test_each_key_alone_is_the_only_variable_declared_and_sent(
        self,
        tg: TGClient,
        respx_mock: respx.MockRouter,
        kwargs: dict[str, Any],
        variable: str,
        gql_type: str,
        value: Any,
    ) -> None:
        sent = await _update(tg, respx_mock, **kwargs)
        assert sent["variables"] == {"id": _ID, variable: value}
        assert sent["query"] == (
            f"\nmutation UpdateWebAppResource($id: ID!, ${variable}: {gql_type}) {{\n"
            f"  webAppResourceUpdate(id: $id, {variable}: ${variable}) {{\n"
            "    ok\n    error\n  }\n}\n"
        )

    async def test_address_only_text_is_exact(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        sent = await _update(tg, respx_mock, address="new.internal")
        assert sent["query"] == _ADDRESS_ONLY_TEXT

    async def test_all_keys_together_in_one_mutation(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        sent = await _update(
            tg,
            respx_mock,
            address="new.internal",
            alias="wiki.corp.internal",
            upstream=_LEG,
            downstream={"port": 443, "tlsMode": "TLS13"},
            request_header_rewrites=_REWRITES,
            added_group_ids=["g-1"],
            removed_group_ids=["g-2"],
            security_policy_id="p-1",
            gateway_id=_GATEWAY,
        )
        assert sent["query"] == _ALL_KEYS_TEXT
        assert sent["variables"] == {
            "id": _ID,
            "address": "new.internal",
            "alias": "wiki.corp.internal",
            "upstream": _LEG,
            "downstream": {"port": 443, "tlsMode": "TLS13"},
            "requestHeaderRewrites": _REWRITES,
            "addedGroupIds": ["g-1"],
            "removedGroupIds": ["g-2"],
            "securityPolicyId": "p-1",
            "gatewayId": _GATEWAY,
        }
        # Key order is part of the request bytes.
        assert list(sent["variables"]) == [
            "id",
            "address",
            "alias",
            "upstream",
            "downstream",
            "requestHeaderRewrites",
            "addedGroupIds",
            "removedGroupIds",
            "securityPolicyId",
            "gatewayId",
        ]

    async def test_alias_none_sends_an_explicit_null(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=_ok())
        await update_webapp_resource(tg, _ID, alias=None)
        [call] = route.calls
        assert '"alias":null' in call.request.content.decode()
        assert json.loads(call.request.content)["variables"] == {"id": _ID, "alias": None}

    async def test_managed_empty_rewrites_are_sent_as_an_empty_list(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        sent = await _update(tg, respx_mock, request_header_rewrites=[])
        assert sent["variables"] == {"id": _ID, "requestHeaderRewrites": []}
        assert "$requestHeaderRewrites: [KeyValueInputObject!]" in sent["query"]

    async def test_one_drifted_leg_leaves_the_other_leg_unsent(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        sent = await _update(tg, respx_mock, downstream={"port": 8080, "tlsMode": "NONE"})
        assert sent["variables"] == {"id": _ID, "downstream": {"port": 8080, "tlsMode": "NONE"}}
        assert "upstream" not in sent["variables"]
        assert "upstream" not in sent["query"]

    async def test_a_leg_may_omit_tls_mode(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        sent = await _update(tg, respx_mock, upstream={"port": 81})
        assert sent["variables"]["upstream"] == {"port": 81}

    @pytest.mark.parametrize("empty", [None, []])
    async def test_empty_group_deltas_are_omitted(
        self, tg: TGClient, respx_mock: respx.MockRouter, empty: list[str] | None
    ) -> None:
        sent = await _update(
            tg, respx_mock, address="a.internal", added_group_ids=empty, removed_group_ids=empty
        )
        assert sent["variables"] == {"id": _ID, "address": "a.internal"}
        assert "GroupIds" not in sent["query"]

    async def test_a_group_delta_alone_is_a_valid_update(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        sent = await _update(tg, respx_mock, added_group_ids=["g-1"])
        assert sent["variables"] == {"id": _ID, "addedGroupIds": ["g-1"]}


class TestRefusalsBeforeAnyRequest:
    async def test_nothing_to_update_is_refused(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        with pytest.raises(ValueError, match="no fields to update"):
            await update_webapp_resource(tg, _ID)
        with pytest.raises(ValueError, match="no fields to update"):
            await update_webapp_resource(tg, _ID, added_group_ids=[], removed_group_ids=[])
        assert route.call_count == 0

    @pytest.mark.parametrize(
        "name",
        [
            "address",
            "upstream",
            "downstream",
            "request_header_rewrites",
            "security_policy_id",
            "gateway_id",
        ],
    )
    async def test_null_for_a_non_nullable_field_is_refused(
        self, tg: TGClient, respx_mock: respx.MockRouter, name: str
    ) -> None:
        route = respx_mock.post(_URL)
        with pytest.raises(ValueError, match="cannot be null"):
            await update_webapp_resource(tg, _ID, **{name: None})  # type: ignore[arg-type]
        assert route.call_count == 0

    @pytest.mark.parametrize(
        "leg",
        [{}, {"tlsMode": "NONE"}, {"port": 80, "host": "x"}],
    )
    async def test_a_malformed_leg_is_refused(
        self, tg: TGClient, respx_mock: respx.MockRouter, leg: dict[str, Any]
    ) -> None:
        route = respx_mock.post(_URL)
        with pytest.raises(ValueError, match="upstream must carry 'port'"):
            await update_webapp_resource(tg, _ID, upstream=leg)
        assert route.call_count == 0

    @pytest.mark.parametrize(
        "rewrite",
        [
            {"key": "X-A"},
            {"key": "X-A", "value": _SENTINEL, "extra": "x"},
            {"key": 1, "value": "v"},
        ],
    )
    async def test_a_malformed_rewrite_is_refused_without_echoing_a_value(
        self, tg: TGClient, respx_mock: respx.MockRouter, rewrite: dict[str, Any]
    ) -> None:
        route = respx_mock.post(_URL)
        with pytest.raises(ValueError, match="rewrite 0 must be a key/value string pair") as exc:
            await update_webapp_resource(tg, _ID, request_header_rewrites=[rewrite])
        assert _SENTINEL not in str(exc.value)
        assert route.call_count == 0


class TestFailures:
    async def test_ok_false_payload_raises_with_the_servers_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(_URL).mock(
            return_value=httpx.Response(
                200, json={"data": {"webAppResourceUpdate": {"ok": False, "error": "bad alias"}}}
            )
        )
        with pytest.raises(TGAPIError, match="UpdateWebAppResource failed: bad alias") as exc:
            await update_webapp_resource(tg, _ID, alias="x")
        assert exc.value.query_name == "UpdateWebAppResource"

    async def test_ok_false_without_an_error_text_is_still_a_failure(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(_URL).mock(
            return_value=httpx.Response(
                200, json={"data": {"webAppResourceUpdate": {"ok": False, "error": None}}}
            )
        )
        with pytest.raises(TGAPIError, match="unknown error"):
            await update_webapp_resource(tg, _ID, alias="x")

    async def test_a_payload_without_the_mutation_field_is_malformed(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(_URL).mock(return_value=httpx.Response(200, json={"data": {}}))
        with pytest.raises(TGAPIError, match="malformed response"):
            await update_webapp_resource(tg, _ID, alias="x")

    async def test_graphql_errors_raise_tg_graphql_error_without_retrying(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200, json={"errors": [{"message": "Cannot query field", "path": []}]}
            )
        )
        with pytest.raises(TGGraphQLError) as exc:
            await update_webapp_resource(tg, _ID, alias="x")
        assert exc.value.query_name == "UpdateWebAppResource"
        assert exc.value.errors == [{"message": "Cannot query field", "path": []}]
        assert route.call_count == 1

    async def test_a_throttled_write_is_retried_and_counted(
        self, tg: TGClient, respx_mock: respx.MockRouter, _no_real_sleep: AsyncMock
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [httpx.Response(429, headers={"Retry-After": "2"}), _ok()]
        await update_webapp_resource(tg, _ID, alias="x")
        assert route.call_count == 2
        assert tg.write_throttle_count == 1
        assert _no_real_sleep.await_count == 1

    async def test_an_exhausted_throttle_budget_raises_rate_limited(
        self, tg: TGClient, respx_mock: respx.MockRouter, _no_real_sleep: AsyncMock
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(429, headers={"Retry-After": "3600"}))
        with pytest.raises(TGRateLimited) as exc:
            await update_webapp_resource(
                tg, _ID, request_header_rewrites=[{"key": "X-A", "value": _SENTINEL}]
            )
        # The first 60 s hint fits the 90 s pass budget; the second does not.
        assert route.call_count == 2
        assert _no_real_sleep.await_count == 1
        assert tg.write_throttle_count == 2
        assert "budget is exhausted" in str(exc.value)
        assert _SENTINEL not in str(exc.value)


class TestVariablesNeverSurface:
    """Header templates travel in the variables; no log line or exception message carries them."""

    _KWARGS: dict[str, Any] = {
        "alias": "wiki.corp.internal",
        "request_header_rewrites": [{"key": "X-Secret-Ish", "value": _SENTINEL}],
    }

    async def test_request_logging_omits_variables(
        self,
        tg: TGClient,
        respx_mock: respx.MockRouter,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        configure_logging()
        route = respx_mock.post(_URL)
        route.side_effect = [httpx.Response(429, headers={"Retry-After": "1"}), _ok()]
        with structlog.testing.capture_logs() as captured:
            await update_webapp_resource(tg, _ID, **self._KWARGS)
        out = capsys.readouterr().out

        assert [entry["event"] for entry in captured] == [
            "tgapi.request",
            "tgapi.throttled",
            "tgapi.request",
        ]
        for blob in (repr(captured), out):
            assert _SENTINEL not in blob
            assert "wiki.corp.internal" not in blob
        assert all("variables" not in entry for entry in captured)
        assert "tg-secret-key" not in repr(captured) + out

    async def test_graphql_error_message_omits_variables(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(_URL).mock(
            return_value=httpx.Response(200, json={"errors": [{"message": "boom"}]})
        )
        with pytest.raises(TGGraphQLError) as exc:
            await update_webapp_resource(tg, _ID, **self._KWARGS)
        for text in (str(exc.value), repr(exc.value), exc.value.body, *map(str, exc.value.args)):
            assert _SENTINEL not in text
            assert "wiki.corp.internal" not in text

    async def test_ok_false_message_omits_variables(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(_URL).mock(
            return_value=httpx.Response(
                200, json={"data": {"webAppResourceUpdate": {"ok": False, "error": "rejected"}}}
            )
        )
        with pytest.raises(TGAPIError) as exc:
            await update_webapp_resource(tg, _ID, **self._KWARGS)
        for text in (str(exc.value), repr(exc.value), exc.value.body):
            assert _SENTINEL not in text

    async def test_transport_and_http_errors_omit_variables(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(_URL).mock(return_value=httpx.Response(400, text="bad request"))
        with pytest.raises(TGAPIError) as http_exc:
            await update_webapp_resource(tg, _ID, **self._KWARGS)
        assert _SENTINEL not in str(http_exc.value) + http_exc.value.body

        respx_mock.post(_URL).mock(side_effect=httpx.ConnectError("refused"))
        with pytest.raises(TGAPIError) as transport_exc:
            await update_webapp_resource(tg, _ID, **self._KWARGS)
        assert _SENTINEL not in str(transport_exc.value) + transport_exc.value.body


class TestAgainstTheLiveCapture:
    async def test_drift_from_the_capture_round_trips_through_one_mutation(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(200, json=json.loads(_FIXTURE.read_text())),
            _ok(),
        ]
        remote = {r.name: r for r in await list_resources(tg)}["lt-full"]
        assert (remote.id, remote.gateway_id) == (_ID, _GATEWAY)

        # lt-full is upstream 8443 VERIFY_CA / downstream 443 TLS13; want it on VERIFY_FULL
        # with an alias and one rewrite, on another gateway.
        want_extras = {
            "upstream_tls_mode": "VERIFY_FULL",
            "downstream_port": 443,
            "downstream_tls_mode": "TLS13",
            "alias": "full.corp.internal",
            "request_header_rewrites": (("x-user", "{{username}}"),),
        }
        drift = WEBAPP.settings_drift(8443, want_extras, remote.upstream_port, remote.extras)
        assert set(drift) == {"upstream", "alias", "requestHeaderRewrites"}

        await update_webapp_resource(
            tg,
            remote.id,
            upstream=drift["upstream"],
            alias=drift["alias"],
            request_header_rewrites=drift["requestHeaderRewrites"],
            added_group_ids=["g-1"],
            gateway_id="gw-2",
        )
        sent = _sent(route)[1]
        assert sent["variables"] == {
            "id": _ID,
            "alias": "full.corp.internal",
            "upstream": {"port": 8443, "tlsMode": "VERIFY_FULL"},
            "requestHeaderRewrites": [{"key": "x-user", "value": "{{username}}"}],
            "addedGroupIds": ["g-1"],
            "gatewayId": "gw-2",
        }
        assert "resourceUpdate(" not in sent["query"].replace("webAppResourceUpdate(", "")
        assert route.call_count == 2

    async def test_every_capture_node_id_is_a_valid_target(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=_ok())
        for node in _nodes().values():
            await update_webapp_resource(tg, str(node["id"]), alias=None)
        assert [s["variables"]["id"] for s in _sent(route)] == [
            str(n["id"]) for n in _nodes().values()
        ]
