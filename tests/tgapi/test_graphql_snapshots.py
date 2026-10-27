"""Byte-for-byte snapshots of the GraphQL text the SSH and Kubernetes kinds send.

Unlike ``test_ops.py`` nothing is whitespace-normalised:
the query string sent to Twingate must equal the snapshot exactly. A new kind may extend
the generated text; it must never change it for SSH or Kubernetes.
"""

import json
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import respx

from gwops.kinds import KUBERNETES, SSH
from gwops.tgapi.client import TGClient
from gwops.tgapi.ops import (
    create_resource,
    list_resources,
    update_resource_access,
    update_resource_address,
    update_resource_upstream_port,
)

_URL = "https://acme.twingate.com/api/graphql/"

_LIST_RESOURCES = """
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
      }
    }
  }
}
"""

_LIST_TAIL = """      }
    }
  }
}
"""

# Appended by the web-app kind; the SSH and Kubernetes text before it must not change.
_LIST_WEBAPP_FRAGMENT = """        ... on WebAppResource {
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
"""

_CREATE_SSH = """
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

_CREATE_KUBERNETES = """
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

_UPDATE_ADDRESS = """
mutation UpdateResourceAddress($id: ID!, $address: String) {
  resourceUpdate(id: $id, address: $address) {
    ok
    error
  }
}
"""

_UPDATE_ACCESS = """
mutation UpdateResourceAccess(
  $id: ID!, $addedGroupIds: [ID], $removedGroupIds: [ID], $securityPolicyId: ID
) {
  resourceUpdate(
    id: $id, addedGroupIds: $addedGroupIds, removedGroupIds: $removedGroupIds,
    securityPolicyId: $securityPolicyId
  ) {
    ok
    error
  }
}
"""

_UPDATE_UPSTREAM_SSH = """
mutation UpdateSSHResourceUpstream($id: ID!, $upstream: SSHUpstreamInput) {
  sshResourceUpdate(id: $id, upstream: $upstream) {
    ok
    error
  }
}
"""

_UPDATE_UPSTREAM_KUBERNETES = """
mutation UpdateKubernetesResourceUpstream($id: ID!, $upstream: KubernetesUpstreamInput) {
  kubernetesResourceUpdate(id: $id, upstream: $upstream) {
    ok
    error
  }
}
"""

_CREATE_BY_KIND = {"ssh": _CREATE_SSH, "kubernetes": _CREATE_KUBERNETES}
_UPSTREAM_BY_KIND = {"ssh": _UPDATE_UPSTREAM_SSH, "kubernetes": _UPDATE_UPSTREAM_KUBERNETES}
_KINDS = {"ssh": SSH, "kubernetes": KUBERNETES}


@pytest.fixture
def tg() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="tg-secret-key")


def _ok(field: str, **extra: Any) -> httpx.Response:
    return httpx.Response(200, json={"data": {field: {"ok": True, "error": None, **extra}}})


def _sent(route: respx.Route) -> list[dict[str, Any]]:
    """Every request body recorded on `route`, in order."""
    return [json.loads(call.request.content) for call in route.calls]


async def _update_address(tg: TGClient, kind_key: str, resource_id: str, address: str) -> None:
    await update_resource_address(tg, kind_key, resource_id, address)


async def _update_access(tg: TGClient, kind_key: str, resource_id: str, **delta: Any) -> None:
    await update_resource_access(tg, kind_key, resource_id, **delta)


async def test_list_fragment_text_is_unchanged(
    tg: TGClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(_URL)
    route.mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "resources": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "edges": [],
                    }
                }
            },
        )
    )
    await list_resources(tg)
    [sent] = _sent(route)
    assert _LIST_RESOURCES.endswith(_LIST_TAIL)
    assert sent["query"] == _LIST_RESOURCES[: -len(_LIST_TAIL)] + _LIST_WEBAPP_FRAGMENT + _LIST_TAIL


@pytest.mark.parametrize("kind_key", ["ssh", "kubernetes"])
async def test_create_text_and_variables_are_unchanged(
    tg: TGClient, respx_mock: respx.MockRouter, kind_key: str
) -> None:
    kind = _KINDS[kind_key]
    route = respx_mock.post(_URL)
    route.side_effect = [
        httpx.Response(200, json={"data": {"gateway": {"remoteNetwork": {"id": "rn-1"}}}}),
        _ok(f"{kind.tg_field_prefix}Create", entity={"id": "res-1"}),
    ]
    await create_resource(
        tg,
        kind,
        "n",
        "10.0.0.5",
        "gw-1",
        upstream_port=2222,
        group_ids=["g-1"],
        security_policy_id="p-1",
    )
    _gateway_lookup, create = _sent(route)
    assert create["query"] == _CREATE_BY_KIND[kind_key]
    assert create["variables"] == {
        "name": "n",
        "address": "10.0.0.5",
        "remoteNetworkId": "rn-1",
        "gatewayId": "gw-1",
        "upstream": {"port": 2222},
        "groupIds": ["g-1"],
        "securityPolicyId": "p-1",
    }
    # Key order is part of the request bytes.
    assert list(create["variables"]) == [
        "name",
        "address",
        "remoteNetworkId",
        "gatewayId",
        "upstream",
        "groupIds",
        "securityPolicyId",
    ]


@pytest.mark.parametrize("kind_key", ["ssh", "kubernetes"])
async def test_create_omits_unset_access_variables(
    tg: TGClient, respx_mock: respx.MockRouter, kind_key: str
) -> None:
    kind = _KINDS[kind_key]
    route = respx_mock.post(_URL)
    route.side_effect = [
        httpx.Response(200, json={"data": {"gateway": {"remoteNetwork": {"id": "rn-1"}}}}),
        _ok(f"{kind.tg_field_prefix}Create", entity={"id": "res-1"}),
    ]
    await create_resource(tg, kind, "n", "10.0.0.5", "gw-1", upstream_port=22)
    assert list(_sent(route)[1]["variables"]) == [
        "name",
        "address",
        "remoteNetworkId",
        "gatewayId",
        "upstream",
    ]


@pytest.mark.parametrize("kind_key", ["ssh", "kubernetes"])
async def test_address_update_text_and_variables_are_unchanged(
    tg: TGClient, respx_mock: respx.MockRouter, kind_key: str
) -> None:
    route = respx_mock.post(_URL)
    route.mock(return_value=_ok("resourceUpdate"))
    await _update_address(tg, kind_key, "res-1", "10.0.0.99")
    [sent] = _sent(route)
    assert sent["query"] == _UPDATE_ADDRESS
    assert sent["variables"] == {"id": "res-1", "address": "10.0.0.99"}


@pytest.mark.parametrize("kind_key", ["ssh", "kubernetes"])
async def test_access_update_text_and_variables_are_unchanged(
    tg: TGClient, respx_mock: respx.MockRouter, kind_key: str
) -> None:
    route = respx_mock.post(_URL)
    route.mock(return_value=_ok("resourceUpdate"))
    await _update_access(
        tg,
        kind_key,
        "res-1",
        added_group_ids=["g-1"],
        removed_group_ids=["g-2"],
        security_policy_id="p-1",
    )
    [sent] = _sent(route)
    assert sent["query"] == _UPDATE_ACCESS
    assert sent["variables"] == {
        "id": "res-1",
        "addedGroupIds": ["g-1"],
        "removedGroupIds": ["g-2"],
        "securityPolicyId": "p-1",
    }
    assert list(sent["variables"]) == ["id", "addedGroupIds", "removedGroupIds", "securityPolicyId"]


@pytest.mark.parametrize("kind_key", ["ssh", "kubernetes"])
async def test_access_update_omits_empty_delta_keys(
    tg: TGClient, respx_mock: respx.MockRouter, kind_key: str
) -> None:
    route = respx_mock.post(_URL)
    route.mock(return_value=_ok("resourceUpdate"))
    await _update_access(tg, kind_key, "res-1", added_group_ids=["g-1"], removed_group_ids=[])
    [sent] = _sent(route)
    assert sent["query"] == _UPDATE_ACCESS
    assert sent["variables"] == {"id": "res-1", "addedGroupIds": ["g-1"]}


@pytest.mark.parametrize("kind_key", ["ssh", "kubernetes"])
async def test_upstream_port_update_text_is_unchanged(
    tg: TGClient, respx_mock: respx.MockRouter, kind_key: str
) -> None:
    route = respx_mock.post(_URL)
    route.mock(return_value=_ok(f"{_KINDS[kind_key].tg_field_prefix}Update"))
    await update_resource_upstream_port(tg, kind_key, "res-1", 2222)
    [sent] = _sent(route)
    assert sent["query"] == _UPSTREAM_BY_KIND[kind_key]
    assert sent["variables"] == {"id": "res-1", "upstream": {"port": 2222}}
