"""Tests for the gateway/remote-network resolution operations in gwops.tgapi.ops.

Same conventions as ``test_ops.py``: each query/mutation text below is an independent
snapshot of the wire request (operation name, arguments, selection set); whitespace is
normalized before comparison so reformatting the implementation's triple-quoted strings
stays non-brittle, but the GraphQL content itself must match. The HTTP layer is mocked
with respx so the real :class:`TGClient` (and its ``execute``) runs end to end.
"""

import json
from collections.abc import Iterator

import httpx
import pytest
import respx

from gwops.tgapi.client import TGClient
from gwops.tgapi.errors import TGAPIError
from gwops.tgapi.ops import (
    create_gateway,
    find_gateway_by_address,
    resolve_remote_network_id,
    update_gateway,
)

_URL = "https://acme.twingate.com/api/graphql/"


def _normalize(query: str) -> str:
    """Collapse whitespace so query-text comparisons ignore formatting only."""
    return " ".join(query.split())


def _sent(route: respx.Route, call_index: int = -1) -> dict[str, object]:
    """Parse the JSON body of one recorded call on `route`."""
    request = route.calls[call_index].request
    body: dict[str, object] = json.loads(request.content)
    return body


def _assert_request(
    route: respx.Route, call_index: int, expected_query: str, expected_variables: dict[str, object]
) -> None:
    sent = _sent(route, call_index)
    assert _normalize(str(sent["query"])) == _normalize(expected_query)
    assert sent["variables"] == expected_variables


@pytest.fixture
def tg() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="tg-secret-key")


_RESOLVE_REMOTE_NETWORK_QUERY = """
query ResolveRemoteNetwork($filter: RemoteNetworkFilterInput) {
  remoteNetworks(filter: $filter) {
    edges {
      node {
        id
        name
      }
    }
  }
}
"""

_LIST_GATEWAYS_QUERY = """
query ListGateways($id: ID, $first: Int!, $after: String) {
  remoteNetwork(id: $id) {
    gateways(first: $first, after: $after) {
      pageInfo {
        hasNextPage
        endCursor
      }
      edges {
        node {
          id
          address
        }
      }
    }
  }
}
"""

_CREATE_GATEWAY_MUTATION = """
mutation CreateGateway(
  $address: String!, $remoteNetworkId: ID!, $x509CAId: ID!, $sshCAId: ID
) {
  gatewayCreate(
    address: $address, remoteNetworkId: $remoteNetworkId, x509CAId: $x509CAId, sshCAId: $sshCAId
  ) {
    ok
    error
    entity {
      id
    }
  }
}
"""

_UPDATE_GATEWAY_MUTATION = """
mutation UpdateGateway(
  $id: ID!, $remoteNetworkId: ID!, $x509CAId: ID, $sshCAId: ID, $address: String
) {
  gatewayUpdate(
    id: $id, remoteNetworkId: $remoteNetworkId, x509CAId: $x509CAId,
    sshCAId: $sshCAId, address: $address
  ) {
    ok
    error
  }
}
"""


def _rn_page(names: list[tuple[str, str]]) -> dict:
    """Build a remoteNetworks response from (id, name) pairs."""
    return {
        "data": {
            "remoteNetworks": {
                "edges": [{"node": {"id": rid, "name": name}} for rid, name in names]
            }
        }
    }


def _gw_page(gateways: list[tuple[str, str]], has_next: bool, end_cursor: str | None) -> dict:
    """Build one remoteNetwork.gateways page from (id, address) pairs."""
    return {
        "data": {
            "remoteNetwork": {
                "gateways": {
                    "pageInfo": {"hasNextPage": has_next, "endCursor": end_cursor},
                    "edges": [
                        {"node": {"id": gid, "address": address}}
                        for gid, address in gateways
                    ],
                }
            }
        }
    }


class TestResolveRemoteNetworkId:
    async def test_single_match_returns_id(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json=_rn_page([("network-1", "prod")])))
        result = await resolve_remote_network_id(tg, "prod")
        assert result == "network-1"
        _assert_request(
            route, 0, _RESOLVE_REMOTE_NETWORK_QUERY, {"filter": {"name": {"eq": "prod"}}}
        )

    async def test_zero_matches_raises_no_remote_network(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json=_rn_page([])))
        with pytest.raises(TGAPIError, match="no remote network named 'prod'"):
            await resolve_remote_network_id(tg, "prod")

    async def test_multiple_matches_raises_multiple_remote_networks(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200, json=_rn_page([("network-1", "prod"), ("network-2", "prod")])
            )
        )
        with pytest.raises(TGAPIError, match="multiple remote networks named 'prod'"):
            await resolve_remote_network_id(tg, "prod")

    async def test_malformed_response_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json={"data": {}}))
        with pytest.raises(TGAPIError) as exc_info:
            await resolve_remote_network_id(tg, "prod")
        assert exc_info.value.query_name == "ResolveRemoteNetwork"

    async def test_null_matched_id_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json=_rn_page([(None, "prod")])))  # type: ignore[list-item]
        with pytest.raises(TGAPIError) as exc_info:
            await resolve_remote_network_id(tg, "prod")
        assert exc_info.value.query_name == "ResolveRemoteNetwork"


class TestFindGatewayByAddress:
    async def test_hit_returns_id(self, tg: TGClient, respx_mock: respx.MockRouter) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200,
                json=_gw_page(
                    [("gw-1", "gw1.acme.internal"), ("gw-2", "gw2.acme.internal")],
                    has_next=False,
                    end_cursor=None,
                ),
            )
        )
        result = await find_gateway_by_address(tg, "network-1", "gw2.acme.internal")
        assert result == "gw-2"
        _assert_request(
            route, 0, _LIST_GATEWAYS_QUERY, {"id": "network-1", "first": 50, "after": None}
        )

    async def test_miss_returns_none(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200,
                json=_gw_page(
                    [("gw-1", "gw1.acme.internal")], has_next=False, end_cursor=None
                ),
            )
        )
        result = await find_gateway_by_address(tg, "network-1", "nope.acme.internal")
        assert result is None

    async def test_paginates_across_pages(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(
                200,
                json=_gw_page(
                    [("gw-1", "gw1.acme.internal")], has_next=True, end_cursor="c1"
                ),
            ),
            httpx.Response(
                200,
                json=_gw_page(
                    [("gw-2", "gw2.acme.internal")], has_next=False, end_cursor=None
                ),
            ),
        ]
        result = await find_gateway_by_address(tg, "network-1", "gw2.acme.internal")
        assert result == "gw-2"
        assert route.call_count == 2
        assert _sent(route, 0)["variables"] == {"id": "network-1", "first": 50, "after": None}
        assert _sent(route, 1)["variables"] == {"id": "network-1", "first": 50, "after": "c1"}

    async def test_two_matches_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200,
                json=_gw_page(
                    [("gw-1", "dup.acme.internal"), ("gw-2", "dup.acme.internal")],
                    has_next=False,
                    end_cursor=None,
                ),
            )
        )
        with pytest.raises(TGAPIError, match="multiple gateways"):
            await find_gateway_by_address(tg, "network-1", "dup.acme.internal")

    async def test_remote_network_not_found_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json={"data": {"remoteNetwork": None}}))
        with pytest.raises(TGAPIError) as exc_info:
            await find_gateway_by_address(tg, "network-missing", "gw1.acme.internal")
        assert exc_info.value.query_name == "ListGateways"

    async def test_malformed_response_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200, json={"data": {"remoteNetwork": {"gateways": {"edges": []}}}}
            )
        )
        with pytest.raises(TGAPIError) as exc_info:
            await find_gateway_by_address(tg, "network-1", "gw1.acme.internal")
        assert exc_info.value.query_name == "ListGateways"


class TestCreateGateway:
    async def test_sends_expected_mutation_and_returns_id(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "gatewayCreate": {
                            "ok": True,
                            "error": None,
                            "entity": {"id": "gateway-new"},
                        }
                    }
                },
            )
        )
        gateway_id = await create_gateway(
            tg, "gw.acme.internal", "network-1", "ca-x509-1", "ca-ssh-1"
        )
        assert gateway_id == "gateway-new"
        _assert_request(
            route,
            0,
            _CREATE_GATEWAY_MUTATION,
            {
                "address": "gw.acme.internal",
                "remoteNetworkId": "network-1",
                "x509CAId": "ca-x509-1",
                "sshCAId": "ca-ssh-1",
            },
        )

    async def test_omits_ssh_ca_id_variable_when_not_given(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "gatewayCreate": {
                            "ok": True,
                            "error": None,
                            "entity": {"id": "gateway-new"},
                        }
                    }
                },
            )
        )
        gateway_id = await create_gateway(tg, "gw.acme.internal", "network-1", "ca-x509-1")
        assert gateway_id == "gateway-new"
        sent = _sent(route, 0)
        assert sent["variables"] == {
            "address": "gw.acme.internal",
            "remoteNetworkId": "network-1",
            "x509CAId": "ca-x509-1",
        }
        assert "sshCAId" not in sent["variables"]  # type: ignore[operator]

    async def test_raises_when_not_ok(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "gatewayCreate": {
                            "ok": False,
                            "error": "address already in use",
                            "entity": None,
                        }
                    }
                },
            )
        )
        with pytest.raises(TGAPIError, match="address already in use"):
            await create_gateway(tg, "gw.acme.internal", "network-1", "ca-x509-1")

    async def test_null_entity_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "gatewayCreate": {"ok": True, "error": None, "entity": None}
                    }
                },
            )
        )
        with pytest.raises(TGAPIError) as exc_info:
            await create_gateway(tg, "gw.acme.internal", "network-1", "ca-x509-1")
        assert exc_info.value.query_name == "CreateGateway"


class TestUpdateGatewayAddress:
    async def test_address_included_in_variables_when_given(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(
                200, json={"data": {"gateway": {"remoteNetwork": {"id": "network-1"}}}}
            ),
            httpx.Response(
                200, json={"data": {"gatewayUpdate": {"ok": True, "error": None}}}
            ),
        ]
        await update_gateway(tg, "gateway-1", address="gw-new.acme.internal")
        sent = _sent(route, 1)
        assert sent["variables"] == {
            "id": "gateway-1",
            "remoteNetworkId": "network-1",
            "address": "gw-new.acme.internal",
        }
        assert "x509CAId" not in sent["variables"]  # type: ignore[operator]
        assert "sshCAId" not in sent["variables"]  # type: ignore[operator]
        assert _normalize(str(sent["query"])) == _normalize(_UPDATE_GATEWAY_MUTATION)

    async def test_address_omitted_when_not_given(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(
                200, json={"data": {"gateway": {"remoteNetwork": {"id": "network-1"}}}}
            ),
            httpx.Response(
                200, json={"data": {"gatewayUpdate": {"ok": True, "error": None}}}
            ),
        ]
        await update_gateway(tg, "gateway-1", x509_ca_id="ca-x509-new")
        sent = _sent(route, 1)
        assert "address" not in sent["variables"]  # type: ignore[operator]
        assert sent["variables"] == {
            "id": "gateway-1",
            "remoteNetworkId": "network-1",
            "x509CAId": "ca-x509-new",
        }

    async def test_address_and_ca_ids_together(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(
                200, json={"data": {"gateway": {"remoteNetwork": {"id": "network-1"}}}}
            ),
            httpx.Response(
                200, json={"data": {"gatewayUpdate": {"ok": True, "error": None}}}
            ),
        ]
        await update_gateway(
            tg,
            "gateway-1",
            x509_ca_id="ca-x509-new",
            ssh_ca_id="ca-ssh-new",
            address="gw-new.acme.internal",
        )
        sent = _sent(route, 1)
        assert sent["variables"] == {
            "id": "gateway-1",
            "remoteNetworkId": "network-1",
            "x509CAId": "ca-x509-new",
            "sshCAId": "ca-ssh-new",
            "address": "gw-new.acme.internal",
        }
