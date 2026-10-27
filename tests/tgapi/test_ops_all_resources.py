"""``ops.list_all_resource_addresses``: unfiltered, all pages, never partial."""

import json
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import respx

from gwops.tgapi import ops
from gwops.tgapi.client import TGClient
from gwops.tgapi.errors import TGAPIError
from gwops.tgapi.ops import TenantResource, list_all_resource_addresses

_URL = "https://acme.twingate.com/api/graphql/"


@pytest.fixture
def tg() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="tg-secret-key")


def _node(resource_id: str, address: str, alias: str | None = None, **extra: Any) -> dict[str, Any]:
    return {"node": {"id": resource_id, "address": {"value": address}, "alias": alias, **extra}}


def _page(
    nodes: list[dict[str, Any]], *, next_page: bool = False, cursor: str | None = None
) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": {
                "resources": {
                    "pageInfo": {"hasNextPage": next_page, "endCursor": cursor},
                    "edges": nodes,
                }
            }
        },
    )


def _sent(route: respx.Route, index: int) -> dict[str, Any]:
    return json.loads(route.calls[index].request.content)  # type: ignore[no-any-return]


class TestQuery:
    def test_selects_the_interface_fields_every_resource_type_carries(self) -> None:
        query = ops._LIST_ALL_RESOURCE_ADDRESSES_QUERY
        assert "query ListAllResourceAddresses($first: Int!, $after: String)" in query
        assert "resources(first: $first, after: $after)" in query
        assert "filter" not in query
        assert "... on" not in query
        for selected in ("id", "alias", "address {", "value", "pageInfo", "hasNextPage"):
            assert selected in query


class TestListing:
    async def test_returns_every_type_including_ones_list_resources_drops(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=_page(
                [
                    _node("net-1", "10.0.0.0/24"),
                    _node("web-1", "Wiki.Internal", "Wiki.Corp.Example"),
                    _node("k8s-1", "cluster.internal"),
                ]
            )
        )
        found = await list_all_resource_addresses(tg)
        assert found == [
            TenantResource(id="net-1", address="10.0.0.0/24", alias=None),
            TenantResource(id="web-1", address="wiki.internal", alias="wiki.corp.example"),
            TenantResource(id="k8s-1", address="cluster.internal", alias=None),
        ]
        assert _sent(route, 0)["variables"] == {"first": 50, "after": None}

    async def test_follows_every_page(self, tg: TGClient, respx_mock: respx.MockRouter) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            _page([_node("a", "a.internal")], next_page=True, cursor="c1"),
            _page([_node("b", "b.internal", "b-alias.internal")], next_page=True, cursor="c2"),
            _page([_node("c", "c.internal")]),
        ]
        found = await list_all_resource_addresses(tg)
        assert [r.id for r in found] == ["a", "b", "c"]
        assert [_sent(route, i)["variables"]["after"] for i in range(3)] == [None, "c1", "c2"]

    async def test_an_empty_tenant_is_an_empty_list(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(_URL).mock(return_value=_page([]))
        assert await list_all_resource_addresses(tg) == []

    async def test_an_empty_alias_is_none(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(_URL).mock(return_value=_page([_node("a", "a.internal", "")]))
        [found] = await list_all_resource_addresses(tg)
        assert found.alias is None


class TestIncompleteListingsFailLoud:
    async def test_a_failing_later_page_raises_not_a_partial_list(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            _page([_node("a", "a.internal")], next_page=True, cursor="c1"),
            httpx.Response(400, text="boom"),
        ]
        with pytest.raises(TGAPIError):
            await list_all_resource_addresses(tg)

    async def test_more_pages_without_a_cursor_is_incomplete(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(_URL).mock(
            return_value=_page([_node("a", "a.internal")], next_page=True, cursor=None)
        )
        with pytest.raises(TGAPIError, match="incomplete"):
            await list_all_resource_addresses(tg)

    async def test_a_cursor_that_does_not_advance_is_incomplete(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            _page([_node("a", "a.internal")], next_page=True, cursor="c1"),
            _page([_node("b", "b.internal")], next_page=True, cursor="c1"),
        ]
        with pytest.raises(TGAPIError, match="incomplete"):
            await list_all_resource_addresses(tg)
        assert route.call_count == 2

    @pytest.mark.parametrize(
        "bad_edge",
        [
            {"node": {"id": "", "address": {"value": "a.internal"}, "alias": None}},
            {"node": {"id": "a", "address": {"value": ""}, "alias": None}},
            {"node": {"id": "a", "address": None, "alias": None}},
            {"node": {"id": "a", "alias": None}},
            {"node": None},
            {},
        ],
    )
    async def test_a_node_without_an_id_or_address_is_malformed(
        self, tg: TGClient, respx_mock: respx.MockRouter, bad_edge: dict[str, Any]
    ) -> None:
        respx_mock.post(_URL).mock(return_value=_page([_node("ok", "ok.internal"), bad_edge]))
        with pytest.raises(TGAPIError, match="malformed"):
            await list_all_resource_addresses(tg)

    async def test_a_missing_connection_is_malformed(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(_URL).mock(
            return_value=httpx.Response(200, json={"data": {"resources": None}})
        )
        with pytest.raises(TGAPIError, match="malformed"):
            await list_all_resource_addresses(tg)
