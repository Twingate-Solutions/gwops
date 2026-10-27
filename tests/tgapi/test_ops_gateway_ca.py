"""Tests for the gateway X.509 CA binding read and the CA fingerprint search in ops.

Query texts are independent snapshots of the wire request (whitespace-normalised); the HTTP
layer is mocked with respx so the real :class:`TGClient` runs end to end. Response bodies
come from ``tests/fixtures/tg/public_root_*.json``.
"""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from gwops.tgapi.client import TGClient
from gwops.tgapi.errors import TGAPIError
from gwops.tgapi.ops import (
    GatewayCABinding,
    find_x509_ca_ids_by_fingerprint,
    get_gateway_x509_ca,
    normalise_fingerprint,
)

_URL = "https://acme.twingate.com/api/graphql/"
_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "tg"
_ROOT_SHA = "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6"
_ROOT_COLONS = ":".join(_ROOT_SHA[i : i + 2] for i in range(0, 64, 2)).upper()

_GET_BINDING_QUERY = """
query GetGatewayX509CA($id: ID!) {
  gateway(id: $id) {
    id
    x509CA {
      id
      fingerprint
    }
  }
}
"""

_LIST_CAS_QUERY = """
query FindX509CAsByFingerprint($first: Int!, $after: String) {
  certificateAuthorities(first: $first, after: $after) {
    pageInfo {
      hasNextPage
      endCursor
    }
    edges {
      node {
        __typename
        ... on X509CertificateAuthority {
          id
          name
          fingerprint
        }
      }
    }
  }
}
"""


def _fixture(name: str) -> Any:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


def _sent(route: respx.Route, index: int) -> dict[str, Any]:
    body: dict[str, Any] = json.loads(route.calls[index].request.content)
    return body


def _normalize(query: str) -> str:
    return " ".join(query.split())


@pytest.fixture
def tg() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="tg-secret-key")


class TestNormaliseFingerprint:
    @pytest.mark.parametrize(
        "raw",
        [_ROOT_COLONS, _ROOT_SHA, _ROOT_SHA.upper(), f"  {_ROOT_COLONS.lower()}\n"],
    )
    def test_every_spelling_normalises_to_lowercase_hex_without_colons(self, raw: str) -> None:
        assert normalise_fingerprint(raw) == _ROOT_SHA


class TestGetGatewayX509CA:
    async def test_the_binding_is_returned_with_a_normalised_fingerprint(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(200, json=_fixture("public_root_gateway_bound.json"))
        )

        binding = await get_gateway_x509_ca(tg, "gw-1")

        assert binding == GatewayCABinding(ca_id="WDUwOUNBOjQy", fingerprint=_ROOT_SHA)
        sent = _sent(route, 0)
        assert _normalize(str(sent["query"])) == _normalize(_GET_BINDING_QUERY)
        assert sent["variables"] == {"id": "gw-1"}

    async def test_a_foreign_binding_keeps_its_own_fingerprint(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(_URL).mock(
            return_value=httpx.Response(200, json=_fixture("public_root_gateway_foreign.json"))
        )

        binding = await get_gateway_x509_ca(tg, "gw-1")

        assert binding is not None
        assert binding.ca_id == "WDUwOUNBOjQz"
        assert binding.fingerprint == "ab" * 32

    async def test_every_call_is_a_round_trip(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(200, json=_fixture("public_root_gateway_bound.json"))
        )

        await get_gateway_x509_ca(tg, "gw-1")
        await get_gateway_x509_ca(tg, "gw-1")

        assert route.call_count == 2

    async def test_a_null_gateway_raises(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(_URL).mock(
            return_value=httpx.Response(200, json={"data": {"gateway": None}})
        )

        with pytest.raises(TGAPIError, match="gw-9 not found") as exc_info:
            await get_gateway_x509_ca(tg, "gw-9")

        assert exc_info.value.query_name == "GetGatewayX509CA"

    async def test_a_null_x509ca_returns_none(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.post(_URL).mock(
            return_value=httpx.Response(
                200, json={"data": {"gateway": {"id": "gw-1", "x509CA": None}}}
            )
        )

        assert await get_gateway_x509_ca(tg, "gw-1") is None

    @pytest.mark.parametrize(
        "gateway",
        [
            {"id": "gw-1"},
            {"id": "gw-1", "x509CA": {"id": "ca-1"}},
            {"id": "gw-1", "x509CA": {"id": "", "fingerprint": "AB"}},
            {"id": "gw-1", "x509CA": {"id": "ca-1", "fingerprint": None}},
            {"id": "gw-1", "x509CA": "ca-1"},
        ],
    )
    async def test_a_malformed_binding_raises(
        self, tg: TGClient, respx_mock: respx.MockRouter, gateway: dict[str, Any]
    ) -> None:
        respx_mock.post(_URL).mock(
            return_value=httpx.Response(200, json={"data": {"gateway": gateway}})
        )

        with pytest.raises(TGAPIError, match="malformed"):
            await get_gateway_x509_ca(tg, "gw-1")


class TestFindX509CAIdsByFingerprint:
    async def test_the_match_on_the_second_page_is_found_in_any_fingerprint_spelling(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        page_one, page_two = _fixture("public_root_cas.json")
        route.side_effect = [
            httpx.Response(200, json=page_one),
            httpx.Response(200, json=page_two),
        ]

        ids = await find_x509_ca_ids_by_fingerprint(tg, _ROOT_SHA)

        assert ids == ["WDUwOUNBOjQy"]
        assert route.call_count == 2
        assert _normalize(str(_sent(route, 0)["query"])) == _normalize(_LIST_CAS_QUERY)
        assert _sent(route, 0)["variables"] == {"first": 50, "after": None}
        assert _sent(route, 1)["variables"] == {"first": 50, "after": "Y3Vyc29yOjI="}

    async def test_a_colon_separated_uppercase_argument_matches_too(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        page_one, page_two = _fixture("public_root_cas.json")
        respx_mock.post(_URL).side_effect = [
            httpx.Response(200, json=page_one),
            httpx.Response(200, json=page_two),
        ]

        assert await find_x509_ca_ids_by_fingerprint(tg, _ROOT_COLONS) == ["WDUwOUNBOjQy"]

    async def test_no_match_returns_an_empty_list(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        page_one, page_two = _fixture("public_root_cas.json")
        respx_mock.post(_URL).side_effect = [
            httpx.Response(200, json=page_one),
            httpx.Response(200, json=page_two),
        ]

        assert await find_x509_ca_ids_by_fingerprint(tg, "cd" * 32) == []

    async def test_every_matching_ca_is_returned_in_order(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        nodes = [
            {"node": {"__typename": "X509CertificateAuthority", "id": cid, "name": cid,
                      "fingerprint": _ROOT_COLONS}}
            for cid in ("ca-1", "ca-2")
        ]
        body = {
            "data": {
                "certificateAuthorities": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "edges": nodes,
                }
            }
        }
        respx_mock.post(_URL).mock(return_value=httpx.Response(200, json=body))

        assert await find_x509_ca_ids_by_fingerprint(tg, _ROOT_SHA) == ["ca-1", "ca-2"]

    @pytest.mark.parametrize(
        "connection",
        [
            {"edges": []},
            {"pageInfo": {"hasNextPage": False, "endCursor": None}},
            {"pageInfo": {"hasNextPage": False, "endCursor": None},
             "edges": [{"node": {"__typename": "X509CertificateAuthority", "id": "ca-1"}}]},
            {"pageInfo": {"hasNextPage": False, "endCursor": None},
             "edges": [{"node": {"__typename": "X509CertificateAuthority", "id": "",
                                 "fingerprint": "AB"}}]},
            {"pageInfo": {"hasNextPage": False, "endCursor": None}, "edges": [{}]},
        ],
    )
    async def test_a_malformed_page_raises(
        self, tg: TGClient, respx_mock: respx.MockRouter, connection: dict[str, Any]
    ) -> None:
        respx_mock.post(_URL).mock(
            return_value=httpx.Response(
                200, json={"data": {"certificateAuthorities": connection}}
            )
        )

        with pytest.raises(TGAPIError, match="malformed") as exc_info:
            await find_x509_ca_ids_by_fingerprint(tg, _ROOT_SHA)

        assert exc_info.value.query_name == "FindX509CAsByFingerprint"

    async def test_a_malformed_second_page_never_yields_the_first_pages_partial_list(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        match_page = {
            "data": {
                "certificateAuthorities": {
                    "pageInfo": {"hasNextPage": True, "endCursor": "c1"},
                    "edges": [
                        {"node": {"__typename": "X509CertificateAuthority", "id": "ca-1",
                                  "name": "n", "fingerprint": _ROOT_COLONS}}
                    ],
                }
            }
        }
        respx_mock.post(_URL).side_effect = [
            httpx.Response(200, json=match_page),
            httpx.Response(200, json={"data": {"certificateAuthorities": None}}),
        ]

        with pytest.raises(TGAPIError, match="malformed"):
            await find_x509_ca_ids_by_fingerprint(tg, _ROOT_SHA)

    @pytest.mark.parametrize("end_cursor", [None, "", "c1"])
    async def test_a_non_progressing_cursor_raises_rather_than_looping(
        self, tg: TGClient, respx_mock: respx.MockRouter, end_cursor: str | None
    ) -> None:
        def page(cursor: str | None) -> dict[str, Any]:
            return {
                "data": {
                    "certificateAuthorities": {
                        "pageInfo": {"hasNextPage": True, "endCursor": cursor},
                        "edges": [],
                    }
                }
            }

        responses = [
            httpx.Response(200, json=page("c1")),
            httpx.Response(200, json=page(end_cursor)),
        ]
        if not end_cursor:
            # The first page already has no usable cursor.
            responses = [httpx.Response(200, json=page(end_cursor))]
        route = respx_mock.post(_URL)
        route.side_effect = responses

        with pytest.raises(TGAPIError, match="did not advance"):
            await find_x509_ca_ids_by_fingerprint(tg, _ROOT_SHA)

        assert route.call_count == len(responses)
