"""Tests for gwops.tgapi.ops: typed operations, request shapes, and pagination.

Each mutation/query text below is an independent snapshot of what the wire request
must contain (operation name, field arguments, selection set) — whitespace is
normalized before comparison so reformatting the implementation's triple-quoted
strings doesn't make these tests brittle, but the GraphQL content itself must match.
"""

import json
from collections.abc import Iterator

import httpx
import pytest
import respx

from gwops.kinds import KUBERNETES, SSH
from gwops.tgapi.client import TGClient
from gwops.tgapi.errors import TGAPIError
from gwops.tgapi.ops import (
    RemoteResource,
    create_resource,
    create_ssh_ca,
    create_x509_ca,
    delete_resource,
    find_group_ids_by_name,
    get_group_name,
    get_security_policy_name,
    list_resources,
    update_gateway,
    update_resource_access,
    update_resource_address,
    update_resource_upstream_port,
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


_LIST_RESOURCES_QUERY = """
query ListResources($first: Int!, $after: String, $filter: ResourceFilterInput) {
  resources(first: $first, after: $after, filter: $filter) {
    pageInfo {
      hasNextPage
      endCursor
    }
    edges {
      node {
        __typename
        id
        name
        address {
          value
        }
        ... on SSHResource {
          gateway {
            id
          }
          upstream {
            port
          }
        }
        ... on KubernetesResource {
          gateway {
            id
          }
          upstream {
            port
          }
        }
        ... on WebAppResource {
          gateway {
            id
          }
          alias
          upstream {
            port
            tlsMode
          }
          downstream {
            port
            tlsMode
          }
          requestHeaderRewrites {
            key
            value
          }
        }
      }
    }
  }
}
"""

_GATEWAY_REMOTE_NETWORK_QUERY = """
query GatewayRemoteNetwork($id: ID!) {
  gateway(id: $id) {
    remoteNetwork {
      id
    }
  }
}
"""

_CREATE_SSH_RESOURCE_MUTATION = """
mutation CreateSSHResource(
  $name: String!, $address: String!, $remoteNetworkId: ID!, $gatewayId: ID!,
  $upstream: SSHUpstreamInput, $groupIds: [ID], $securityPolicyId: ID
) {
  sshResourceCreate(
    name: $name, address: $address, remoteNetworkId: $remoteNetworkId, gatewayId: $gatewayId,
    upstream: $upstream, groupIds: $groupIds, securityPolicyId: $securityPolicyId
  ) {
    ok
    error
    entity {
      id
    }
  }
}
"""

_CREATE_KUBERNETES_RESOURCE_MUTATION = """
mutation CreateKubernetesResource(
  $name: String!, $address: String!, $remoteNetworkId: ID!, $gatewayId: ID,
  $upstream: KubernetesUpstreamInput, $groupIds: [ID], $securityPolicyId: ID
) {
  kubernetesResourceCreate(
    name: $name, address: $address, remoteNetworkId: $remoteNetworkId, gatewayId: $gatewayId,
    upstream: $upstream, groupIds: $groupIds, securityPolicyId: $securityPolicyId
  ) {
    ok
    error
    entity {
      id
    }
  }
}
"""

_UPDATE_RESOURCE_ADDRESS_MUTATION = """
mutation UpdateResourceAddress($id: ID!, $address: String) {
  resourceUpdate(id: $id, address: $address) {
    ok
    error
  }
}
"""

_UPDATE_SSH_RESOURCE_UPSTREAM_MUTATION = """
mutation UpdateSSHResourceUpstream($id: ID!, $upstream: SSHUpstreamInput) {
  sshResourceUpdate(id: $id, upstream: $upstream) {
    ok
    error
  }
}
"""

_UPDATE_KUBERNETES_RESOURCE_UPSTREAM_MUTATION = """
mutation UpdateKubernetesResourceUpstream($id: ID!, $upstream: KubernetesUpstreamInput) {
  kubernetesResourceUpdate(id: $id, upstream: $upstream) {
    ok
    error
  }
}
"""

_DELETE_RESOURCE_MUTATION = """
mutation DeleteResource($id: ID!) {
  resourceDelete(id: $id) {
    ok
    error
  }
}
"""

_CREATE_X509_CA_MUTATION = """
mutation CreateX509CA($name: String!, $certificate: String!) {
  x509CertificateAuthorityCreate(name: $name, certificate: $certificate) {
    ok
    error
    entity {
      id
    }
  }
}
"""

_CREATE_SSH_CA_MUTATION = """
mutation CreateSSHCA($name: String!, $publicKey: String!) {
  sshCertificateAuthorityCreate(name: $name, publicKey: $publicKey) {
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


class TestCreateSSHResource:
    async def test_sends_expected_mutation_and_returns_id(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(
                200, json={"data": {"gateway": {"remoteNetwork": {"id": "network-1"}}}}
            ),
            httpx.Response(
                200,
                json={
                    "data": {
                        "sshResourceCreate": {
                            "ok": True,
                            "error": None,
                            "entity": {"id": "resource-ssh-1"},
                        }
                    }
                },
            ),
        ]
        resource_id = await create_resource(
            tg, SSH, "bastion", "10.0.0.5", "gateway-1", upstream_port=2222
        )
        assert resource_id == "resource-ssh-1"
        assert route.call_count == 2
        _assert_request(
            route, 0, _GATEWAY_REMOTE_NETWORK_QUERY, {"id": "gateway-1"}
        )
        _assert_request(
            route,
            1,
            _CREATE_SSH_RESOURCE_MUTATION,
            {
                "name": "bastion",
                "address": "10.0.0.5",
                "remoteNetworkId": "network-1",
                "gatewayId": "gateway-1",
                "upstream": {"port": 2222},
            },
        )

    async def test_raises_tg_api_error_when_mutation_not_ok(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(
                200, json={"data": {"gateway": {"remoteNetwork": {"id": "network-1"}}}}
            ),
            httpx.Response(
                200,
                json={
                    "data": {
                        "sshResourceCreate": {
                            "ok": False,
                            "error": "name already exists",
                            "entity": None,
                        }
                    }
                },
            ),
        ]
        with pytest.raises(TGAPIError, match="name already exists"):
            await create_resource(tg, SSH, "bastion", "10.0.0.5", "gateway-1", upstream_port=22)


class TestCreateKubernetesResource:
    async def test_sends_expected_mutation_and_returns_id(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(
                200, json={"data": {"gateway": {"remoteNetwork": {"id": "network-2"}}}}
            ),
            httpx.Response(
                200,
                json={
                    "data": {
                        "kubernetesResourceCreate": {
                            "ok": True,
                            "error": None,
                            "entity": {"id": "resource-k8s-1"},
                        }
                    }
                },
            ),
        ]
        resource_id = await create_resource(
            tg, KUBERNETES, "prod-cluster", "10.0.1.5", "gateway-2", upstream_port=6443
        )
        assert resource_id == "resource-k8s-1"
        _assert_request(route, 0, _GATEWAY_REMOTE_NETWORK_QUERY, {"id": "gateway-2"})
        _assert_request(
            route,
            1,
            _CREATE_KUBERNETES_RESOURCE_MUTATION,
            {
                "name": "prod-cluster",
                "address": "10.0.1.5",
                "remoteNetworkId": "network-2",
                "gatewayId": "gateway-2",
                "upstream": {"port": 6443},
            },
        )


class TestUpdateResourceAddress:
    async def test_sends_expected_mutation(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200, json={"data": {"resourceUpdate": {"ok": True, "error": None}}}
            )
        )
        await update_resource_address(tg, "ssh", "resource-1", "10.0.0.99")
        _assert_request(
            route,
            0,
            _UPDATE_RESOURCE_ADDRESS_MUTATION,
            {"id": "resource-1", "address": "10.0.0.99"},
        )

    async def test_raises_on_not_ok(self, tg: TGClient, respx_mock: respx.MockRouter) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {"resourceUpdate": {"ok": False, "error": "not found"}}
                },
            )
        )
        with pytest.raises(TGAPIError, match="not found"):
            await update_resource_address(tg, "ssh", "missing", "10.0.0.99")


class TestUpdateResourceUpstreamPort:
    async def test_ssh_sends_ssh_resource_update_with_upstream_port(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200, json={"data": {"sshResourceUpdate": {"ok": True, "error": None}}}
            )
        )
        await update_resource_upstream_port(tg, "ssh", "resource-1", 2222)
        _assert_request(
            route,
            0,
            _UPDATE_SSH_RESOURCE_UPSTREAM_MUTATION,
            {"id": "resource-1", "upstream": {"port": 2222}},
        )

    async def test_kubernetes_sends_kubernetes_resource_update_with_upstream_port(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200, json={"data": {"kubernetesResourceUpdate": {"ok": True, "error": None}}}
            )
        )
        await update_resource_upstream_port(tg, "kubernetes", "resource-2", 6443)
        _assert_request(
            route,
            0,
            _UPDATE_KUBERNETES_RESOURCE_UPSTREAM_MUTATION,
            {"id": "resource-2", "upstream": {"port": 6443}},
        )

    async def test_raises_on_not_ok(self, tg: TGClient, respx_mock: respx.MockRouter) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "kubernetesResourceUpdate": {"ok": False, "error": "invalid port"}
                    }
                },
            )
        )
        with pytest.raises(TGAPIError, match="invalid port") as exc_info:
            await update_resource_upstream_port(tg, "kubernetes", "resource-2", 6443)
        assert exc_info.value.query_name == "UpdateKubernetesResourceUpstream"


class TestDeleteResource:
    async def test_sends_expected_mutation(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200, json={"data": {"resourceDelete": {"ok": True, "error": None}}}
            )
        )
        await delete_resource(tg, "resource-1")
        _assert_request(route, 0, _DELETE_RESOURCE_MUTATION, {"id": "resource-1"})


class TestCreateX509Ca:
    async def test_sends_expected_mutation_and_returns_id(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "x509CertificateAuthorityCreate": {
                            "ok": True,
                            "error": None,
                            "entity": {"id": "ca-x509-1"},
                        }
                    }
                },
            )
        )
        pem = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
        ca_id = await create_x509_ca(tg, "gwops-ca", pem)
        assert ca_id == "ca-x509-1"
        _assert_request(
            route, 0, _CREATE_X509_CA_MUTATION, {"name": "gwops-ca", "certificate": pem}
        )


class TestCreateSshCa:
    async def test_sends_expected_mutation_and_returns_id(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "sshCertificateAuthorityCreate": {
                            "ok": True,
                            "error": None,
                            "entity": {"id": "ca-ssh-1"},
                        }
                    }
                },
            )
        )
        pub_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB gwops-ca"
        ca_id = await create_ssh_ca(tg, "gwops-ssh-ca", pub_key)
        assert ca_id == "ca-ssh-1"
        _assert_request(
            route,
            0,
            _CREATE_SSH_CA_MUTATION,
            {"name": "gwops-ssh-ca", "publicKey": pub_key},
        )


class TestUpdateGateway:
    async def test_x509_only_omits_ssh_ca_id_variable(
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
        assert sent["variables"] == {
            "id": "gateway-1",
            "remoteNetworkId": "network-1",
            "x509CAId": "ca-x509-new",
        }
        assert "sshCAId" not in sent["variables"]  # type: ignore[operator]
        assert _normalize(str(sent["query"])) == _normalize(_UPDATE_GATEWAY_MUTATION)

    async def test_ssh_only_omits_x509_ca_id_variable(
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
        await update_gateway(tg, "gateway-1", ssh_ca_id="ca-ssh-new")
        sent = _sent(route, 1)
        assert sent["variables"] == {
            "id": "gateway-1",
            "remoteNetworkId": "network-1",
            "sshCAId": "ca-ssh-new",
        }
        assert "x509CAId" not in sent["variables"]  # type: ignore[operator]

    async def test_both_ca_ids_present_when_both_given(
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
        await update_gateway(tg, "gateway-1", x509_ca_id="ca-x509-new", ssh_ca_id="ca-ssh-new")
        sent = _sent(route, 1)
        assert sent["variables"] == {
            "id": "gateway-1",
            "remoteNetworkId": "network-1",
            "x509CAId": "ca-x509-new",
            "sshCAId": "ca-ssh-new",
        }

    async def test_raises_when_gateway_not_found(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json={"data": {"gateway": None}}))
        with pytest.raises(TGAPIError, match="gateway-missing"):
            await update_gateway(tg, "gateway-missing", x509_ca_id="ca-x509-new")


def _resource_node(
    typename: str,
    node_id: str,
    name: str,
    address: str,
    gateway_id: str | None,
    upstream_port: int = 22,
) -> dict[str, object]:
    node: dict[str, object] = {
        "__typename": typename,
        "id": node_id,
        "name": name,
        "address": {"value": address},
    }
    if typename in ("SSHResource", "KubernetesResource"):
        node["gateway"] = {"id": gateway_id} if gateway_id is not None else None
        node["upstream"] = {"port": upstream_port}
    return node


def _page(nodes: list[dict[str, object]], has_next: bool, end_cursor: str | None) -> dict:
    return {
        "data": {
            "resources": {
                "pageInfo": {"hasNextPage": has_next, "endCursor": end_cursor},
                "edges": [{"node": node} for node in nodes],
            }
        }
    }


class TestListResourcesPagination:
    async def test_joins_three_pages_and_filters_to_gateway_attached(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        page1 = _page(
            [
                _resource_node("SSHResource", "r-ssh-1", "bastion-1", "10.0.0.1", "gw-1"),
                _resource_node(
                    "KubernetesResource", "r-k8s-1", "cluster-1", "10.0.1.1", "gw-1", 6443
                ),
                _resource_node("NetworkResource", "r-net-1", "plain-1", "10.0.2.1", None),
                _resource_node(
                    "KubernetesResource", "r-k8s-skip", "cluster-skip", "10.0.1.2", None
                ),
            ],
            has_next=True,
            end_cursor="c1",
        )
        page2 = _page(
            [_resource_node("SSHResource", "r-ssh-2", "bastion-2", "10.0.0.2", "gw-2", 2222)],
            has_next=True,
            end_cursor="c2",
        )
        page3 = _page(
            [
                _resource_node(
                    "KubernetesResource", "r-k8s-2", "cluster-2", "10.0.1.3", "gw-1", 443
                )
            ],
            has_next=False,
            end_cursor=None,
        )
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(200, json=page1),
            httpx.Response(200, json=page2),
            httpx.Response(200, json=page3),
        ]

        resources = await list_resources(tg)

        assert route.call_count == 3
        assert _sent(route, 0)["variables"] == {"first": 50, "after": None}
        assert _sent(route, 1)["variables"] == {"first": 50, "after": "c1"}
        assert _sent(route, 2)["variables"] == {"first": 50, "after": "c2"}
        for i in range(3):
            assert _normalize(str(_sent(route, i)["query"])) == _normalize(
                _LIST_RESOURCES_QUERY
            )

        assert resources == [
            RemoteResource(
                id="r-ssh-1",
                kind="ssh",
                name="bastion-1",
                address="10.0.0.1",
                gateway_id="gw-1",
                upstream_port=22,
            ),
            RemoteResource(
                id="r-k8s-1",
                kind="kubernetes",
                name="cluster-1",
                address="10.0.1.1",
                gateway_id="gw-1",
                upstream_port=6443,
            ),
            RemoteResource(
                id="r-ssh-2",
                kind="ssh",
                name="bastion-2",
                address="10.0.0.2",
                gateway_id="gw-2",
                upstream_port=2222,
            ),
            RemoteResource(
                id="r-k8s-2",
                kind="kubernetes",
                name="cluster-2",
                address="10.0.1.3",
                gateway_id="gw-1",
                upstream_port=443,
            ),
        ]

    async def test_passes_remote_network_id_as_filter(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        page = _page([], has_next=False, end_cursor=None)
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json=page))
        await list_resources(tg, remote_network_id="network-9")
        sent = _sent(route, 0)
        assert sent["variables"] == {
            "first": 50,
            "after": None,
            "filter": {"remoteNetworkId": {"eq": "network-9"}},
        }

    async def test_omits_filter_key_when_no_remote_network_given(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        page = _page([], has_next=False, end_cursor=None)
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json=page))
        await list_resources(tg)
        sent = _sent(route, 0)
        assert "filter" not in sent["variables"]  # type: ignore[operator]


class TestListResourcesMalformedResponse:
    """A malformed 200 body must surface as TGAPIError, never a raw KeyError/TypeError."""

    async def test_missing_resources_key_raises_tgapi_error_not_key_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json={"data": {}}))
        with pytest.raises(TGAPIError) as exc_info:
            await list_resources(tg)
        assert exc_info.value.query_name == "ListResources"

    async def test_missing_page_info_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200, json={"data": {"resources": {"edges": []}}}
            )
        )
        with pytest.raises(TGAPIError) as exc_info:
            await list_resources(tg)
        assert exc_info.value.query_name == "ListResources"

    async def test_missing_edges_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "resources": {
                            "pageInfo": {"hasNextPage": False, "endCursor": None}
                        }
                    }
                },
            )
        )
        with pytest.raises(TGAPIError):
            await list_resources(tg)

    async def test_node_missing_required_field_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        page = {
            "data": {
                "resources": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "edges": [
                        {
                            "node": {
                                "__typename": "SSHResource",
                                "gateway": {"id": "gw-1"},
                                # missing id/name/address
                            }
                        }
                    ],
                }
            }
        }
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json=page))
        with pytest.raises(TGAPIError):
            await list_resources(tg)

    async def test_missing_upstream_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        node = _resource_node("KubernetesResource", "r-k8s-1", "cluster-1", "10.0.1.1", "gw-1")
        del node["upstream"]
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(200, json=_page([node], has_next=False, end_cursor=None))
        )
        with pytest.raises(TGAPIError) as exc_info:
            await list_resources(tg)
        assert exc_info.value.query_name == "ListResources"

    async def test_null_node_id_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        page = {
            "data": {
                "resources": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "edges": [
                        {
                            "node": {
                                "__typename": "SSHResource",
                                "id": None,
                                "name": "bastion",
                                "address": {"value": "10.0.0.1"},
                                "gateway": {"id": "gw-1"},
                            }
                        }
                    ],
                }
            }
        }
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json=page))
        with pytest.raises(TGAPIError) as exc_info:
            await list_resources(tg)
        assert exc_info.value.query_name == "ListResources"

    async def test_null_gateway_id_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        page = {
            "data": {
                "resources": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "edges": [
                        {
                            "node": {
                                "__typename": "SSHResource",
                                "id": "r-ssh-1",
                                "name": "bastion",
                                "address": {"value": "10.0.0.1"},
                                "gateway": {"id": None},
                            }
                        }
                    ],
                }
            }
        }
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json=page))
        with pytest.raises(TGAPIError) as exc_info:
            await list_resources(tg)
        assert exc_info.value.query_name == "ListResources"


class TestUnwrapMalformedResponse:
    """A 200 body missing the mutation field or `ok` must raise TGAPIError."""

    async def test_missing_mutation_field_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json={"data": {}}))
        with pytest.raises(TGAPIError) as exc_info:
            await delete_resource(tg, "resource-1")
        assert exc_info.value.query_name == "DeleteResource"

    async def test_missing_ok_key_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200, json={"data": {"resourceDelete": {"error": None}}}
            )
        )
        with pytest.raises(TGAPIError):
            await delete_resource(tg, "resource-1")


class TestEntityNullWithOkTrue:
    """`ok: true` with `entity: null` must raise TGAPIError, not TypeError on indexing."""

    async def test_create_x509_ca_null_entity_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "x509CertificateAuthorityCreate": {
                            "ok": True,
                            "error": None,
                            "entity": None,
                        }
                    }
                },
            )
        )
        with pytest.raises(TGAPIError) as exc_info:
            await create_x509_ca(tg, "gwops-ca", "pem")
        assert exc_info.value.query_name == "CreateX509CA"

    async def test_create_x509_ca_null_entity_id_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        """`entity` present but `entity.id` null must not silently become the string "None"."""
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "x509CertificateAuthorityCreate": {
                            "ok": True,
                            "error": None,
                            "entity": {"id": None},
                        }
                    }
                },
            )
        )
        with pytest.raises(TGAPIError) as exc_info:
            await create_x509_ca(tg, "gwops-ca", "pem")
        assert exc_info.value.query_name == "CreateX509CA"

    async def test_create_ssh_resource_null_entity_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(
                200, json={"data": {"gateway": {"remoteNetwork": {"id": "network-1"}}}}
            ),
            httpx.Response(
                200,
                json={
                    "data": {
                        "sshResourceCreate": {
                            "ok": True,
                            "error": None,
                            "entity": None,
                        }
                    }
                },
            ),
        ]
        with pytest.raises(TGAPIError):
            await create_resource(tg, SSH, "bastion", "10.0.0.5", "gateway-1", upstream_port=22)


class TestGatewayRemoteNetworkMalformedResponse:
    async def test_gateway_found_but_remote_network_missing_raises_tgapi_error(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(return_value=httpx.Response(200, json={"data": {"gateway": {}}}))
        with pytest.raises(TGAPIError):
            await create_resource(tg, SSH, "bastion", "10.0.0.5", "gateway-1", upstream_port=22)

    async def test_null_remote_network_id_raises_tgapi_error_and_is_never_cached(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        """A null remote-network id must not be cached as the literal string "None"."""
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200, json={"data": {"gateway": {"remoteNetwork": {"id": None}}}}
            )
        )
        with pytest.raises(TGAPIError) as exc_info:
            await create_resource(tg, SSH, "bastion", "10.0.0.5", "gateway-1", upstream_port=22)
        assert exc_info.value.query_name == "GatewayRemoteNetwork"

        # A second call for the same gateway must re-issue the lookup, proving
        # nothing was cached from the failed first attempt.
        with pytest.raises(TGAPIError):
            await create_resource(tg, SSH, "bastion", "10.0.0.5", "gateway-1", upstream_port=22)
        assert route.call_count == 2


class TestRemoteNetworkIdCaching:
    """A gateway's remote network is looked up at most once per (client, gateway_id)."""

    async def test_second_create_for_same_gateway_reuses_cached_lookup(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(
                200, json={"data": {"gateway": {"remoteNetwork": {"id": "network-1"}}}}
            ),
            httpx.Response(
                200,
                json={
                    "data": {
                        "sshResourceCreate": {
                            "ok": True,
                            "error": None,
                            "entity": {"id": "resource-1"},
                        }
                    }
                },
            ),
            httpx.Response(
                200,
                json={
                    "data": {
                        "sshResourceCreate": {
                            "ok": True,
                            "error": None,
                            "entity": {"id": "resource-2"},
                        }
                    }
                },
            ),
        ]
        await create_resource(tg, SSH, "bastion-1", "10.0.0.5", "gateway-1", upstream_port=22)
        await create_resource(tg, SSH, "bastion-2", "10.0.0.6", "gateway-1", upstream_port=22)
        assert route.call_count == 3  # one remote-network lookup + two mutations
        _assert_request(route, 0, _GATEWAY_REMOTE_NETWORK_QUERY, {"id": "gateway-1"})

    async def test_different_gateway_id_triggers_fresh_lookup(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(
                200, json={"data": {"gateway": {"remoteNetwork": {"id": "network-1"}}}}
            ),
            httpx.Response(
                200,
                json={
                    "data": {
                        "sshResourceCreate": {
                            "ok": True,
                            "error": None,
                            "entity": {"id": "resource-1"},
                        }
                    }
                },
            ),
            httpx.Response(
                200, json={"data": {"gateway": {"remoteNetwork": {"id": "network-2"}}}}
            ),
            httpx.Response(
                200,
                json={
                    "data": {
                        "sshResourceCreate": {
                            "ok": True,
                            "error": None,
                            "entity": {"id": "resource-2"},
                        }
                    }
                },
            ),
        ]
        await create_resource(tg, SSH, "bastion-1", "10.0.0.5", "gateway-1", upstream_port=22)
        await create_resource(tg, SSH, "bastion-2", "10.0.0.6", "gateway-2", upstream_port=22)
        assert route.call_count == 4  # two remote-network lookups + two mutations

    async def test_different_clients_do_not_share_cached_lookups(
        self, respx_mock: respx.MockRouter
    ) -> None:
        tg_a = TGClient(network="acme", api_key="tg-secret-key-a")
        tg_b = TGClient(network="acme", api_key="tg-secret-key-b")
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(
                200, json={"data": {"gateway": {"remoteNetwork": {"id": "network-1"}}}}
            ),
            httpx.Response(
                200,
                json={
                    "data": {
                        "sshResourceCreate": {
                            "ok": True,
                            "error": None,
                            "entity": {"id": "resource-1"},
                        }
                    }
                },
            ),
            httpx.Response(
                200, json={"data": {"gateway": {"remoteNetwork": {"id": "network-1"}}}}
            ),
            httpx.Response(
                200,
                json={
                    "data": {
                        "sshResourceCreate": {
                            "ok": True,
                            "error": None,
                            "entity": {"id": "resource-2"},
                        }
                    }
                },
            ),
        ]
        await create_resource(tg_a, SSH, "bastion-1", "10.0.0.5", "gateway-1", upstream_port=22)
        await create_resource(tg_b, SSH, "bastion-2", "10.0.0.6", "gateway-1", upstream_port=22)
        assert route.call_count == 4  # each client does its own lookup


class TestAccessOps:
    async def test_create_sends_group_and_policy_ids_only_when_given(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        created = {"data": {"sshResourceCreate": {"ok": True, "error": None,
                                                  "entity": {"id": "r-1"}}}}
        route.side_effect = [
            httpx.Response(200, json={"data": {"gateway": {"remoteNetwork": {"id": "rn"}}}}),
            httpx.Response(200, json=created),
            httpx.Response(200, json=created),
        ]
        await create_resource(
            tg, SSH, "a", "10.0.0.1", "gw", upstream_port=22,
            group_ids=["g-1", "g-2"], security_policy_id="p-1",
        )
        await create_resource(tg, SSH, "b", "10.0.0.2", "gw", upstream_port=22)

        with_access = _sent(route, 1)["variables"]
        assert with_access["groupIds"] == ["g-1", "g-2"]  # type: ignore[index]
        assert with_access["securityPolicyId"] == "p-1"  # type: ignore[index]
        without = _sent(route, 2)["variables"]
        assert "groupIds" not in without  # type: ignore[operator]
        assert "securityPolicyId" not in without  # type: ignore[operator]

    async def test_update_access_sends_only_the_delta_never_group_ids(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200, json={"data": {"resourceUpdate": {"ok": True, "error": None}}}
            )
        )
        await update_resource_access(
            tg, "ssh", "r-1", added_group_ids=["g-c"], removed_group_ids=["g-a"]
        )
        sent = _sent(route, 0)
        assert sent["variables"] == {
            "id": "r-1", "addedGroupIds": ["g-c"], "removedGroupIds": ["g-a"]
        }
        query = _normalize(str(sent["query"]))
        assert "groupIds:" not in query.replace("addedGroupIds:", "").replace(
            "removedGroupIds:", ""
        )

    async def test_update_access_policy_only(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.mock(
            return_value=httpx.Response(
                200, json={"data": {"resourceUpdate": {"ok": True, "error": None}}}
            )
        )
        await update_resource_access(tg, "ssh", "r-1", security_policy_id="p-2")
        assert _sent(route, 0)["variables"] == {"id": "r-1", "securityPolicyId": "p-2"}

    async def test_find_groups_paginates_and_matches_exactly(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        def page(nodes: list[dict[str, str]], has_next: bool) -> httpx.Response:
            return httpx.Response(200, json={"data": {"groups": {
                "pageInfo": {"hasNextPage": has_next, "endCursor": "c1" if has_next else None},
                "edges": [{"node": n} for n in nodes],
            }}})

        route = respx_mock.post(_URL)
        route.side_effect = [
            page([{"id": "g-1", "name": "Ops"}, {"id": "g-x", "name": "ops"}], True),
            page([{"id": "g-2", "name": "Ops"}], False),
        ]
        assert await find_group_ids_by_name(tg, "Ops") == ["g-1", "g-2"]
        assert _sent(route, 0)["variables"] == {
            "first": 50, "after": None, "filter": {"name": {"eq": "Ops"}}
        }
        assert _sent(route, 1)["variables"]["after"] == "c1"  # type: ignore[index]

    async def test_get_by_id_returns_none_when_missing_or_rejected(
        self, tg: TGClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(_URL)
        route.side_effect = [
            httpx.Response(200, json={"data": {"group": {"id": "g-1", "name": "Ops"}}}),
            httpx.Response(200, json={"data": {"group": None}}),
            httpx.Response(200, json={"errors": [{"message": "invalid id"}]}),
            httpx.Response(200, json={"data": {"securityPolicy": {"id": "p", "name": "MFA"}}}),
        ]
        assert await get_group_name(tg, "g-1") == "Ops"
        assert await get_group_name(tg, "g-2") is None
        assert await get_group_name(tg, "bogus") is None
        assert await get_security_policy_name(tg, "p") == "MFA"
