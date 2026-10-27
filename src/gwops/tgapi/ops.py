"""Typed Twingate GraphQL operations used by the reconciler and cert rotation.

``sshResourceCreate``, ``kubernetesResourceCreate`` and ``gatewayUpdate`` require a
non-null ``remoteNetworkId``, but these functions take only a ``gateway_id``. Each
resolves the remote network from the gateway via :func:`_remote_network_id_for_gateway`
and caches the result per (client, gateway_id), since a gateway's remote network never
changes through these ops.
"""

import enum
import json
import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final
from weakref import WeakKeyDictionary

import structlog

from gwops.kindhooks import EMPTY_EXTRAS, Extras
from gwops.kinds import KINDS, ResourceKind, by_key, by_tg_type
from gwops.tgapi.client import TGClient
from gwops.tgapi.errors import TGAPIError, TGGraphQLError

logger = structlog.get_logger(__name__)

_PAGE_SIZE = 50

# --- list_resources -----------------------------------------------------------------
# Resource is an interface; only the gateway-attached kinds (one inline fragment per
# entry in gwops.kinds.KINDS) carry a `gateway` field, and NetworkResource nodes, which
# have none, are dropped. Pagination is Relay-style. What each fragment selects is the
# kind's ``list_fields``.
_SELECTION_TOKEN_RE = re.compile(r"[{}]|[^\s{}]+")


def _selection_lines(fields: str, indent: int) -> str:
    """Lay a flat GraphQL selection set (``a { b } c``) out one name per line.

    Each name goes on its own line at `indent` plus two spaces per open ``{``; ``{``
    joins the name before it and ``}`` gets its own line. This is the layout of the list
    fragments written out by hand, so a kind's ``list_fields`` reproduces them exactly.
    """
    lines: list[str] = []
    depth = 0
    for token in _SELECTION_TOKEN_RE.findall(fields):
        if token == "{":
            if not lines or lines[-1].endswith("{"):
                raise ValueError(f"selection {fields!r}: '{{' must follow a field name")
            lines[-1] += " {"
            depth += 1
        elif token == "}":
            depth -= 1
            if depth < 0:
                raise ValueError(f"selection {fields!r}: unbalanced '}}'")
            lines.append(" " * (indent + 2 * depth) + "}")
        else:
            lines.append(" " * (indent + 2 * depth) + token)
    if depth:
        raise ValueError(f"selection {fields!r}: unclosed '{{'")
    return "\n".join(lines)


def _list_resources_query() -> str:
    fragments = "".join(
        f"""
        ... on {kind.tg_type} {{
{_selection_lines(kind.list_fields, 10)}
        }}"""
        for kind in KINDS
    )
    return f"""
query ListResources($first: Int!, $after: String, $filter: ResourceFilterInput) {{
  resources(first: $first, after: $after, filter: $filter) {{
    pageInfo {{
      hasNextPage
      endCursor
    }}
    edges {{
      node {{
        __typename
        id
        name
        address {{
          value
        }}{fragments}
      }}
    }}
  }}
}}
"""


_LIST_RESOURCES_QUERY = _list_resources_query()

# --- every resource's address and alias ---------------------------------------------
# Both are fields of the `Resource` interface, so no type fragment is needed.
_LIST_ALL_RESOURCE_ADDRESSES_QUERY = """
query ListAllResourceAddresses($first: Int!, $after: String) {
  resources(first: $first, after: $after) {
    pageInfo {
      hasNextPage
      endCursor
    }
    edges {
      node {
        id
        address {
          value
        }
        alias
      }
    }
  }
}
"""

# --- gateway remote-network lookup ---------------------------------------------------
_GATEWAY_REMOTE_NETWORK_QUERY = """
query GatewayRemoteNetwork($id: ID!) {
  gateway(id: $id) {
    remoteNetwork {
      id
    }
  }
}
"""

# --- remoteNetworks name lookup ------------------------------------------------------
# Filtered by name with `eq` (exact match), which yields few edges, so no pagination.
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

# --- remoteNetwork.gateways connection -----------------------------------------------
# Fetched by remote-network id and paginated like `list_resources`.
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

# --- gateway(id).x509CA --------------------------------------------------------------
# Never cached: callers compare against the live binding.
_GET_GATEWAY_X509_CA_QUERY = """
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

# --- certificateAuthorities ----------------------------------------------------------
# The connection has no filter argument, so the caller matches on fingerprint. SSH CAs
# fall outside the inline fragment.
_LIST_X509_CAS_QUERY = """
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

# --- gatewayCreate -------------------------------------------------------------------
# `sshCAId` is omitted from the variables, not sent as null, when there is no SSH CA.
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

# --- <kind>ResourceCreate / <kind>ResourceUpdate -----------------------------------
# The create mutations share one shape; the field name, the gatewayId nullability, the
# `upstream` input type, whether `upstream` is required and any extra arguments come from
# the kind's descriptor. The update mutations require only `id`; an omitted argument is
# unchanged.
def _create_mutation(kind: ResourceKind) -> str:
    gateway_type = "ID!" if kind.gateway_id_required else "ID"
    upstream_type = kind.tg_upstream_input + ("!" if kind.upstream_input_required else "")
    extra_declarations = "".join(f", ${arg}: {gql}" for arg, gql in kind.extra_create_args)
    extra_arguments = "".join(f", {arg}: ${arg}" for arg, _gql in kind.extra_create_args)
    return f"""
mutation Create{kind.tg_type}(
  $name: String!, $address: String!, $remoteNetworkId: ID!, $gatewayId: {gateway_type},
  $upstream: {upstream_type}, $groupIds: [ID], $securityPolicyId: ID{extra_declarations}
) {{
  {kind.tg_field_prefix}Create(
    name: $name, address: $address, remoteNetworkId: $remoteNetworkId, gatewayId: $gatewayId,
    upstream: $upstream, groupIds: $groupIds, securityPolicyId: $securityPolicyId{extra_arguments}
  ) {{
    ok
    error
    entity {{
      id
    }}
  }}
}}
"""


def _update_upstream_mutation(kind: ResourceKind) -> str:
    return f"""
mutation Update{kind.tg_type}Upstream($id: ID!, $upstream: {kind.tg_upstream_input}) {{
  {kind.tg_field_prefix}Update(id: $id, upstream: $upstream) {{
    ok
    error
  }}
}}
"""


# --- address update: the kind's ``update_mutation`` (``resourceUpdate`` by default) --
# A kind that ``resourceUpdate`` rejects names its own mutation, which takes the same
# ``id`` and ``address`` arguments.
def _update_address_mutation(kind: ResourceKind) -> str:
    return f"""
mutation UpdateResourceAddress($id: ID!, $address: String) {{
  {kind.update_mutation}(id: $id, address: $address) {{
    ok
    error
  }}
}}
"""


# --- access delta via ``update_mutation`` --------------------------------------------
# `groupIds` is deliberately NOT declared: it replaces the whole group set, which would
# strip groups an admin added in the console. Only the added/removed delta is ever sent,
# and `securityPolicyId` is left absent (unchanged) unless a policy is being set; it is
# never sent as null (null resets the resource to the Default policy).
def _update_access_mutation(kind: ResourceKind) -> str:
    return f"""
mutation UpdateResourceAccess(
  $id: ID!, $addedGroupIds: [ID], $removedGroupIds: [ID], $securityPolicyId: ID
) {{
  {kind.update_mutation}(
    id: $id, addedGroupIds: $addedGroupIds, removedGroupIds: $removedGroupIds,
    securityPolicyId: $securityPolicyId
  ) {{
    ok
    error
  }}
}}
"""


# --- settings update: ``<prefix>Update`` with the kind's ``extra_update_args`` -------
# Declares only the arguments the kind lists, so an argument left out of the variables
# is absent (unchanged) and an explicit ``None`` clears it.
def _update_settings_mutation(kind: ResourceKind) -> str:
    declarations = "".join(f", ${arg}: {gql}" for arg, gql in kind.extra_update_args)
    arguments = "".join(f", {arg}: ${arg}" for arg, _gql in kind.extra_update_args)
    return f"""
mutation Update{kind.tg_type}Settings($id: ID!{declarations}) {{
  {kind.tg_field_prefix}Update(id: $id{arguments}) {{
    ok
    error
  }}
}}
"""

# --- web-app update: every field in one ``webAppResourceUpdate`` ---------------------
# Only the variables a caller passes are declared, so an omitted field stays unchanged
# rather than being sent as null.
_WEBAPP_UPDATE_VARIABLES: tuple[tuple[str, str], ...] = (
    ("address", "String"),
    ("alias", "String"),
    ("upstream", "WebAppUpstreamInput"),
    ("downstream", "WebAppDownstreamInput"),
    ("requestHeaderRewrites", "[KeyValueInputObject!]"),
    ("addedGroupIds", "[ID]"),
    ("removedGroupIds", "[ID]"),
    ("securityPolicyId", "ID"),
    ("gatewayId", "ID"),
)
_WEBAPP_LEG_KEYS = frozenset({"port", "tlsMode"})
_WEBAPP_OP_NAME = "UpdateWebAppResource"


def _webapp_update_mutation(present: Collection[str]) -> str:
    """The web-app update document declaring exactly the variables named in `present`."""
    chosen = [(name, gql) for name, gql in _WEBAPP_UPDATE_VARIABLES if name in present]
    declarations = "".join(f", ${name}: {gql}" for name, gql in chosen)
    arguments = "".join(f", {name}: ${name}" for name, _gql in chosen)
    field_name = by_key("webapp").update_mutation
    return f"""
mutation {_WEBAPP_OP_NAME}($id: ID!{declarations}) {{
  {field_name}(id: $id{arguments}) {{
    ok
    error
  }}
}}
"""


class _Unset(enum.Enum):
    """Type of :data:`_UNSET`."""

    UNSET = enum.auto()


_UNSET: Final = _Unset.UNSET
"""Marks an update field the caller leaves out: not sent, so unchanged."""


def _webapp_leg(name: str, leg: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one upstream/downstream input; never echoes a value."""
    unknown = sorted(set(leg) - _WEBAPP_LEG_KEYS)
    if unknown or "port" not in leg:
        raise ValueError(
            f"update_webapp_resource: {name} must carry 'port' and only port/tlsMode keys"
            + (f" (got extra {unknown})" if unknown else "")
        )
    return dict(leg)


def _webapp_rewrites(rewrites: Sequence[Mapping[str, str]]) -> list[dict[str, str]]:
    """Validate header rewrites as ``{key, value}`` string pairs; never echoes a value."""
    inputs: list[dict[str, str]] = []
    for index, rewrite in enumerate(rewrites):
        key, value = rewrite.get("key"), rewrite.get("value")
        if set(rewrite) != {"key", "value"} or not isinstance(key, str) or not isinstance(
            value, str
        ):
            raise ValueError(
                f"update_webapp_resource: rewrite {index} must be a key/value string pair"
            )
        inputs.append({"key": key, "value": value})
    return inputs


async def update_webapp_resource(
    tg: TGClient,
    resource_id: str,
    *,
    address: str | _Unset = _UNSET,
    alias: str | None | _Unset = _UNSET,
    upstream: Mapping[str, Any] | _Unset = _UNSET,
    downstream: Mapping[str, Any] | _Unset = _UNSET,
    request_header_rewrites: Sequence[Mapping[str, str]] | _Unset = _UNSET,
    added_group_ids: Sequence[str] | None = None,
    removed_group_ids: Sequence[str] | None = None,
    security_policy_id: str | _Unset = _UNSET,
    gateway_id: str | _Unset = _UNSET,
) -> None:
    """Update a web app's address, settings, access and gateway in one mutation.

    An argument left at its default is not sent (unchanged). `alias=None` clears the alias;
    `request_header_rewrites=[]` removes every rewrite. Group ids are a delta.

    Raises:
        ValueError: Before any request, when nothing is to be updated, a non-nullable
            argument is ``None`` (``security_policy_id=None`` would reset the policy to
            Default), or a leg or rewrite is malformed.
    """
    variables: dict[str, Any] = {"id": resource_id}
    non_nullable = {
        "address": address,
        "upstream": upstream,
        "downstream": downstream,
        "requestHeaderRewrites": request_header_rewrites,
        "securityPolicyId": security_policy_id,
        "gatewayId": gateway_id,
    }
    nones = sorted(name for name, value in non_nullable.items() if value is None)
    if nones:
        raise ValueError(f"update_webapp_resource: {nones} cannot be null; leave them out instead")

    if address is not _UNSET:
        variables["address"] = address
    if alias is not _UNSET:
        variables["alias"] = alias
    if upstream is not _UNSET:
        variables["upstream"] = _webapp_leg("upstream", upstream)
    if downstream is not _UNSET:
        variables["downstream"] = _webapp_leg("downstream", downstream)
    if request_header_rewrites is not _UNSET:
        variables["requestHeaderRewrites"] = _webapp_rewrites(request_header_rewrites)
    if added_group_ids:
        variables["addedGroupIds"] = list(added_group_ids)
    if removed_group_ids:
        variables["removedGroupIds"] = list(removed_group_ids)
    if security_policy_id is not _UNSET:
        variables["securityPolicyId"] = security_policy_id
    if gateway_id is not _UNSET:
        variables["gatewayId"] = gateway_id

    if len(variables) == 1:
        raise ValueError("update_webapp_resource: no fields to update")
    data = await tg.execute(_webapp_update_mutation(variables), variables)
    _unwrap(data, by_key("webapp").update_mutation, _WEBAPP_OP_NAME)


# --- group / security-policy lookups -------------------------------------------------
# Paginated like list_resources; `eq` is an exact, case-sensitive match.
_FIND_GROUPS_QUERY = """
query FindGroupsByName($first: Int!, $after: String, $filter: GroupFilterInput) {
  groups(first: $first, after: $after, filter: $filter) {
    pageInfo {
      hasNextPage
      endCursor
    }
    edges {
      node {
        id
        name
      }
    }
  }
}
"""

_FIND_SECURITY_POLICIES_QUERY = """
query FindSecurityPoliciesByName(
  $first: Int!, $after: String, $filter: SecurityPolicyFilterField
) {
  securityPolicies(first: $first, after: $after, filter: $filter) {
    pageInfo {
      hasNextPage
      endCursor
    }
    edges {
      node {
        id
        name
      }
    }
  }
}
"""

_GET_GROUP_QUERY = """
query GetGroup($id: ID!) {
  group(id: $id) {
    id
    name
  }
}
"""

_GET_SECURITY_POLICY_QUERY = """
query GetSecurityPolicy($id: ID) {
  securityPolicy(id: $id) {
    id
    name
  }
}
"""

# --- resourceDelete ------------------------------------------------------------------
_DELETE_RESOURCE_MUTATION = """
mutation DeleteResource($id: ID!) {
  resourceDelete(id: $id) {
    ok
    error
  }
}
"""

# --- x509CertificateAuthorityCreate --------------------------------------------------
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

# --- sshCertificateAuthorityCreate ---------------------------------------------------
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

# --- gatewayUpdate -------------------------------------------------------------------
# Each optional argument is declared here but its key is omitted from the variables when
# the caller passes nothing, so the argument is absent (not null) and left unchanged.
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


@dataclass(frozen=True)
class RemoteResource:
    """A Twingate resource that already exists via the admin API.

    Mirrors :class:`gwops.renderer.desired.DesiredResource` (``kind``, ``name``,
    ``address``, ``upstream_port``, ``extras``) so the reconciler can diff desired vs.
    actual directly, plus the identifiers (``id``, ``gateway_id``) needed to act on it.
    ``kind`` is a :class:`gwops.kinds.ResourceKind` key. ``extras`` holds the kind's
    ``parse_remote`` result and is excluded from equality and hashing.
    """

    id: str
    kind: str
    name: str
    address: str
    gateway_id: str
    upstream_port: int
    extras: Extras = field(default_factory=lambda: EMPTY_EXTRAS, compare=False, hash=False)


@dataclass(frozen=True)
class TenantResource:
    """One tenant resource of any type: id plus lowercased address and alias (or None)."""

    id: str
    address: str
    alias: str | None


def _unwrap(payload: dict[str, Any], mutation_field: str, op_name: str) -> dict[str, Any]:
    """Return the mutation result dict, raising TGAPIError if malformed or ``ok`` is false."""
    result = payload.get(mutation_field)
    if not isinstance(result, dict) or "ok" not in result:
        raise TGAPIError(
            f"{op_name} returned a malformed response (missing {mutation_field!r} or 'ok')",
            status=200,
            query_name=op_name,
            body=json.dumps(payload),
        )
    if not result["ok"]:
        raise TGAPIError(
            f"{op_name} failed: {result.get('error') or 'unknown error'}",
            status=200,
            query_name=op_name,
            body=json.dumps(result),
        )
    return result


def _entity_id(result: dict[str, Any], op_name: str) -> str:
    """Return the created entity's id, raising TGAPIError if `entity`/`id` is missing or falsy."""
    entity = result.get("entity")
    if not isinstance(entity, dict) or not entity.get("id"):
        raise TGAPIError(
            f"{op_name} succeeded but returned no entity id",
            status=200,
            query_name=op_name,
            body=json.dumps(result),
        )
    return str(entity["id"])


# Per-(client, gateway_id) cache of remote-network ids, keyed weakly by TGClient so
# entries never outlive their client or cross tenants.
_remote_network_cache: WeakKeyDictionary[TGClient, dict[str, str]] = WeakKeyDictionary()


async def _remote_network_id_for_gateway(tg: TGClient, gateway_id: str) -> str:
    """Resolve the remote network a gateway belongs to (required by several mutations).

    The result is cached per (client, gateway_id).
    """
    cache = _remote_network_cache.setdefault(tg, {})
    cached = cache.get(gateway_id)
    if cached is not None:
        return cached

    data = await tg.execute(_GATEWAY_REMOTE_NETWORK_QUERY, {"id": gateway_id})
    gateway = data.get("gateway")
    if gateway is None:
        raise TGAPIError(
            f"gateway {gateway_id} not found",
            status=200,
            query_name="GatewayRemoteNetwork",
            body=json.dumps(data),
        )
    try:
        raw_remote_network_id = gateway["remoteNetwork"]["id"]
    except (KeyError, TypeError) as exc:
        raise TGAPIError(
            f"GatewayRemoteNetwork returned a malformed response: {exc}",
            status=200,
            query_name="GatewayRemoteNetwork",
            body=json.dumps(data),
        ) from exc
    if not raw_remote_network_id:
        raise TGAPIError(
            "GatewayRemoteNetwork returned a null/empty remote network id",
            status=200,
            query_name="GatewayRemoteNetwork",
            body=json.dumps(data),
        )

    remote_network_id = str(raw_remote_network_id)
    cache[gateway_id] = remote_network_id
    return remote_network_id


class _MalformedNode(ValueError):
    """A node defect whose message names the type and field only, so it is safe to surface."""


def _remote_resource_from_node(
    node: dict[str, Any], managed_ids: Collection[str] | None = None
) -> RemoteResource | None:
    """Convert one `resources` query edge node into a RemoteResource, or None to skip.

    Skips resources with no gateway attachment: plain NetworkResource nodes (which
    have no `gateway` field at all) and KubernetesResource nodes whose `gateway` is
    null (Kubernetes resources may exist without a gateway assigned).

    A node whose address, name, upstream port or ``parse_remote`` settings cannot be read is
    skipped with a warning when `managed_ids` is given and lacks its id (a foreign resource
    must not break the listing); otherwise it raises. A node with no id or gateway id
    always raises.
    """
    kind = by_tg_type(str(node.get("__typename")))
    if kind is None:
        return None

    gateway = node.get("gateway")
    if gateway is None:
        return None

    node_id = node["id"]
    gateway_id = gateway["id"]
    if not node_id:
        raise _MalformedNode(f"{kind.tg_type} node has a null/empty id")
    if not gateway_id:
        raise _MalformedNode(f"{kind.tg_type} node has a null/empty gateway id")

    try:
        address = str(node["address"]["value"])
        name = str(node["name"])
        upstream_port = int(node["upstream"]["port"])
        extras = kind.parse_remote(node)
    except (KeyError, TypeError, ValueError) as exc:
        if managed_ids is None or str(node_id) in managed_ids:
            raise
        logger.warning(
            "tgapi.unmanaged_node_skipped",
            resource_id=str(node_id),
            typename=kind.tg_type,
            error_type=type(exc).__name__,
        )
        return None

    return RemoteResource(
        id=str(node_id),
        kind=kind.key,
        name=name,
        address=address,
        gateway_id=str(gateway_id),
        upstream_port=upstream_port,
        extras=extras,
    )


async def resolve_remote_network_id(tg: TGClient, name: str) -> str:
    """Resolve a remote network's id from its exact name.

    Queries ``remoteNetworks`` filtered by an exact-name match. Raises
    :class:`TGAPIError` if no remote network has that name, or if more than one does
    (the name is expected to be unique).
    """
    data = await tg.execute(
        _RESOLVE_REMOTE_NETWORK_QUERY, {"filter": {"name": {"eq": name}}}
    )
    try:
        edges = data["remoteNetworks"]["edges"]
        ids = [str(edge["node"]["id"]) for edge in edges if edge["node"]["id"]]
    except (KeyError, TypeError) as exc:
        raise TGAPIError(
            f"ResolveRemoteNetwork returned a malformed response: {exc}",
            status=200,
            query_name="ResolveRemoteNetwork",
            body=json.dumps(data),
        ) from exc

    if len(ids) != len(edges):
        raise TGAPIError(
            f"ResolveRemoteNetwork returned a remote network with a null/empty id for {name!r}",
            status=200,
            query_name="ResolveRemoteNetwork",
            body=json.dumps(data),
        )
    if not ids:
        raise TGAPIError(
            f"no remote network named {name!r}",
            status=200,
            query_name="ResolveRemoteNetwork",
            body=json.dumps(data),
        )
    if len(ids) > 1:
        raise TGAPIError(
            f"multiple remote networks named {name!r} ({len(ids)} matches); name must be unique",
            status=200,
            query_name="ResolveRemoteNetwork",
            body=json.dumps(data),
        )
    return ids[0]


async def find_gateway_by_address(
    tg: TGClient, remote_network_id: str, address: str
) -> str | None:
    """Find a gateway in `remote_network_id` whose address exactly equals `address`.

    Returns the matching gateway's id, or ``None`` if no gateway in that remote network
    has the given address. Raises :class:`TGAPIError` if the remote network is not found,
    if the response is malformed, or if more than one gateway matches the address.
    """
    matches: list[str] = []
    cursor: str | None = None
    while True:
        data = await tg.execute(
            _LIST_GATEWAYS_QUERY,
            {"id": remote_network_id, "first": _PAGE_SIZE, "after": cursor},
        )
        remote_network = data.get("remoteNetwork")
        if remote_network is None:
            raise TGAPIError(
                f"remote network {remote_network_id} not found",
                status=200,
                query_name="ListGateways",
                body=json.dumps(data),
            )
        try:
            connection = remote_network["gateways"]
            page_info = connection["pageInfo"]
            has_next_page = page_info["hasNextPage"]
            end_cursor = page_info["endCursor"]
            for edge in connection["edges"]:
                node = edge["node"]
                if node["address"] == address:
                    if not node["id"]:
                        raise ValueError("gateway node has a null/empty id")
                    matches.append(str(node["id"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise TGAPIError(
                f"ListGateways returned a malformed response: {exc}",
                status=200,
                query_name="ListGateways",
                body=json.dumps(data),
            ) from exc
        if not has_next_page:
            break
        cursor = end_cursor

    if len(matches) > 1:
        raise TGAPIError(
            f"multiple gateways in remote network {remote_network_id} have address "
            f"{address!r} ({len(matches)} matches)",
            status=200,
            query_name="ListGateways",
            body="",
        )
    return matches[0] if matches else None


async def create_gateway(
    tg: TGClient,
    address: str,
    remote_network_id: str,
    x509_ca_id: str,
    ssh_ca_id: str | None = None,
) -> str:
    """Create a gateway in `remote_network_id`. Returns the new gateway id.

    `ssh_ca_id` is optional; when omitted, the gateway is created with no SSH CA
    assigned (the mutation's ``sshCAId`` default of null applies).
    """
    variables: dict[str, Any] = {
        "address": address,
        "remoteNetworkId": remote_network_id,
        "x509CAId": x509_ca_id,
    }
    if ssh_ca_id is not None:
        variables["sshCAId"] = ssh_ca_id
    data = await tg.execute(_CREATE_GATEWAY_MUTATION, variables)
    result = _unwrap(data, "gatewayCreate", "CreateGateway")
    return _entity_id(result, "CreateGateway")


async def list_resources(
    tg: TGClient,
    remote_network_id: str | None = None,
    *,
    managed_ids: Collection[str] | None = None,
) -> list[RemoteResource]:
    """List gateway-attached resources of every managed kind, across all pages.

    Resources with no gateway attachment (plain NetworkResource, or a Kubernetes
    resource with no gateway assigned) are filtered out. Pass `remote_network_id` to
    restrict the query to a single remote network.

    `managed_ids` is the gwops-owned id set: an unparseable node outside it is skipped with
    a warning; any other unparseable node (every one when ``None``) fails the listing.
    """
    results: list[RemoteResource] = []
    cursor: str | None = None
    while True:
        variables: dict[str, Any] = {"first": _PAGE_SIZE, "after": cursor}
        if remote_network_id is not None:
            variables["filter"] = {"remoteNetworkId": {"eq": remote_network_id}}
        data = await tg.execute(_LIST_RESOURCES_QUERY, variables)
        try:
            connection = data["resources"]
            page_info = connection["pageInfo"]
            has_next_page = page_info["hasNextPage"]
            end_cursor = page_info["endCursor"]
            page_resources = [
                _remote_resource_from_node(edge["node"], managed_ids)
                for edge in connection["edges"]
            ]
        except (KeyError, TypeError, ValueError) as exc:
            # Only our own node errors are safe to echo; a hook's or int()'s text can carry values.
            detail = str(exc) if isinstance(exc, _MalformedNode) else type(exc).__name__
            raise TGAPIError(
                f"ListResources returned a malformed response: {detail}",
                status=200,
                query_name="ListResources",
                body=json.dumps(data),
            ) from exc
        results.extend(resource for resource in page_resources if resource is not None)
        if not has_next_page:
            break
        cursor = end_cursor
    return results


def _tenant_resource(node: Any) -> TenantResource:
    """Convert one listing node; raises KeyError, TypeError or ValueError if unusable."""
    resource_id = node["id"]
    address = node["address"]["value"]
    if not resource_id or not isinstance(address, str) or not address:
        raise ValueError("resource node has an empty id or address")
    alias = node.get("alias")
    return TenantResource(
        id=str(resource_id),
        address=address.lower(),
        alias=alias.lower() if isinstance(alias, str) and alias else None,
    )


async def list_all_resource_addresses(tg: TGClient) -> list[TenantResource]:
    """List every resource of any type in the tenant, across all pages, unfiltered.

    Raises:
        TGAPIError: On any failed or malformed page, or a next page without a new cursor;
            a partial list is never returned.
    """
    results: list[TenantResource] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    while True:
        data = await tg.execute(
            _LIST_ALL_RESOURCE_ADDRESSES_QUERY, {"first": _PAGE_SIZE, "after": cursor}
        )
        try:
            connection = data["resources"]
            page_info = connection["pageInfo"]
            has_next_page = page_info["hasNextPage"]
            end_cursor = page_info["endCursor"]
            results.extend(_tenant_resource(edge["node"]) for edge in connection["edges"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TGAPIError(
                f"ListAllResourceAddresses returned a malformed response: {type(exc).__name__}",
                status=200,
                query_name="ListAllResourceAddresses",
                body=json.dumps(data),
            ) from exc
        if not has_next_page:
            return results
        if not isinstance(end_cursor, str) or not end_cursor or end_cursor in seen_cursors:
            raise TGAPIError(
                "ListAllResourceAddresses is incomplete: the next page has no new cursor",
                status=200,
                query_name="ListAllResourceAddresses",
                body="",
            )
        seen_cursors.add(end_cursor)
        cursor = end_cursor


# Variables the create mutation always declares and `create_resource` always fills; a kind's
# `create_variables` may supply `upstream` (declared by the shared mutation) and its own
# `extra_create_args`, nothing else.
_SHARED_CREATE_VARIABLES = frozenset(
    {"name", "address", "remoteNetworkId", "gatewayId", "groupIds", "securityPolicyId"}
)


def _check_create_variables(kind: ResourceKind, variables: dict[str, Any]) -> None:
    """Refuse create variables the kind's mutation cannot carry.

    A key outside ``upstream`` and the kind's declared ``extra_create_args`` would be sent
    as an undeclared GraphQL variable; one that shadows a shared variable would silently
    overwrite it.
    """
    extra_keys = set(variables) - {"upstream"}
    shadowed = sorted(extra_keys & _SHARED_CREATE_VARIABLES)
    if shadowed:
        raise ValueError(
            f"create_resource for {kind.key!r}: create_variables overlaps the shared "
            f"variables {shadowed}"
        )
    declared = {arg for arg, _gql in kind.extra_create_args}
    undeclared = sorted(extra_keys - declared)
    if undeclared:
        raise ValueError(
            f"create_resource for {kind.key!r}: create_variables returned undeclared "
            f"variables {undeclared} (declared extra_create_args: {sorted(declared)})"
        )


async def create_resource(
    tg: TGClient,
    kind: ResourceKind,
    name: str,
    address: str,
    gateway_id: str,
    *,
    upstream_port: int,
    extras: Extras = EMPTY_EXTRAS,
    group_ids: list[str] | None = None,
    security_policy_id: str | None = None,
) -> str:
    """Create a resource of `kind` attached to `gateway_id`. Returns the new resource id.

    `upstream_port` is the port the gateway dials on `address`; `extras` are the kind's
    own settings. Both are turned into the create variables from ``upstream`` onward by
    ``kind.create_variables`` (by default ``{"upstream": {"port": upstream_port}}``, with
    the downstream (client) port left at Twingate's default). `group_ids` /
    `security_policy_id` left as ``None`` are omitted from the variables, so the
    mutation's defaults apply (no groups, Default policy).

    Raises :class:`ValueError` (before any request) when ``kind.create_variables`` returns
    a key the create mutation does not declare, or one that would overwrite a shared
    variable.
    """
    kind_variables = kind.create_variables(upstream_port, extras)
    _check_create_variables(kind, kind_variables)
    remote_network_id = await _remote_network_id_for_gateway(tg, gateway_id)
    op_name = f"Create{kind.tg_type}"
    variables: dict[str, Any] = {
        "name": name,
        "address": address,
        "remoteNetworkId": remote_network_id,
        "gatewayId": gateway_id,
        **kind_variables,
    }
    if group_ids is not None:
        variables["groupIds"] = group_ids
    if security_policy_id is not None:
        variables["securityPolicyId"] = security_policy_id
    data = await tg.execute(_create_mutation(kind), variables)
    result = _unwrap(data, f"{kind.tg_field_prefix}Create", op_name)
    return _entity_id(result, op_name)


async def update_resource_upstream_port(
    tg: TGClient, kind_key: str, resource_id: str, port: int
) -> None:
    """Set a resource's upstream port, leaving other fields unchanged."""
    kind = by_key(kind_key)
    data = await tg.execute(
        _update_upstream_mutation(kind), {"id": resource_id, "upstream": {"port": port}}
    )
    _unwrap(data, f"{kind.tg_field_prefix}Update", f"Update{kind.tg_type}Upstream")


async def update_resource_settings(
    tg: TGClient, kind_key: str, resource_id: str, variables: dict[str, Any]
) -> None:
    """Update a resource's kind-specific settings via ``<prefix>Update``.

    `variables` may only use the keys the kind lists in ``extra_update_args``. A key that
    is present is sent (``None`` clears it); a key that is absent is left unchanged.
    Raises :class:`ValueError` for an empty `variables` or an undeclared key.
    """
    kind = by_key(kind_key)
    declared = {arg for arg, _gql in kind.extra_update_args}
    unknown = sorted(set(variables) - declared)
    if unknown:
        raise ValueError(
            f"update_resource_settings for {kind_key!r}: undeclared settings {unknown} "
            f"(declared: {sorted(declared)})"
        )
    if not variables:
        raise ValueError(f"update_resource_settings for {kind_key!r}: no settings to update")
    data = await tg.execute(_update_settings_mutation(kind), {"id": resource_id, **variables})
    _unwrap(data, f"{kind.tg_field_prefix}Update", f"Update{kind.tg_type}Settings")


async def update_resource_address(
    tg: TGClient, kind_key: str, resource_id: str, address: str
) -> None:
    """Update an existing resource's address in place, leaving other fields unchanged.

    Sent through the kind's ``update_mutation`` (``resourceUpdate`` unless the kind's
    resources are rejected by it).
    """
    kind = by_key(kind_key)
    data = await tg.execute(_update_address_mutation(kind), {"id": resource_id, "address": address})
    _unwrap(data, kind.update_mutation, "UpdateResourceAddress")


async def update_resource_access(
    tg: TGClient,
    kind_key: str,
    resource_id: str,
    *,
    added_group_ids: list[str] | None = None,
    removed_group_ids: list[str] | None = None,
    security_policy_id: str | None = None,
) -> None:
    """Apply an access delta to a resource via the kind's ``update_mutation``.

    Empty/``None`` arguments are omitted (absent = unchanged). There is deliberately no
    way to replace the whole group set or to reset the policy to Default.
    """
    kind = by_key(kind_key)
    variables: dict[str, Any] = {"id": resource_id}
    if added_group_ids:
        variables["addedGroupIds"] = added_group_ids
    if removed_group_ids:
        variables["removedGroupIds"] = removed_group_ids
    if security_policy_id is not None:
        variables["securityPolicyId"] = security_policy_id
    data = await tg.execute(_update_access_mutation(kind), variables)
    _unwrap(data, kind.update_mutation, "UpdateResourceAccess")


async def _find_ids_by_name(
    tg: TGClient, query: str, root: str, op_name: str, name: str
) -> list[str]:
    """Ids of every node in the `root` connection whose name exactly equals `name`."""
    ids: list[str] = []
    cursor: str | None = None
    while True:
        data = await tg.execute(
            query, {"first": _PAGE_SIZE, "after": cursor, "filter": {"name": {"eq": name}}}
        )
        try:
            connection = data[root]
            page_info = connection["pageInfo"]
            # `eq` is exact server-side; re-check so a looser server match never counts.
            ids.extend(
                str(edge["node"]["id"])
                for edge in connection["edges"]
                if edge["node"]["name"] == name and edge["node"]["id"]
            )
            has_next_page = page_info["hasNextPage"]
            cursor = page_info["endCursor"]
        except (KeyError, TypeError) as exc:
            raise TGAPIError(
                f"{op_name} returned a malformed response: {exc}",
                status=200,
                query_name=op_name,
                body=json.dumps(data),
            ) from exc
        if not has_next_page:
            return ids


async def find_group_ids_by_name(tg: TGClient, name: str) -> list[str]:
    """Ids of every group named exactly `name` (all pages)."""
    return await _find_ids_by_name(tg, _FIND_GROUPS_QUERY, "groups", "FindGroupsByName", name)


async def find_security_policy_ids_by_name(tg: TGClient, name: str) -> list[str]:
    """Ids of every security policy named exactly `name` (all pages)."""
    return await _find_ids_by_name(
        tg,
        _FIND_SECURITY_POLICIES_QUERY,
        "securityPolicies",
        "FindSecurityPoliciesByName",
        name,
    )


async def _get_name_by_id(tg: TGClient, query: str, root: str, object_id: str) -> str | None:
    """The name of the object with `object_id`, or None if it does not exist.

    A GraphQL-level error (e.g. a malformed or unknown id) counts as "does not exist";
    transport/HTTP failures still raise.
    """
    try:
        data = await tg.execute(query, {"id": object_id})
    except TGGraphQLError:
        return None
    node = data.get(root)
    if not isinstance(node, dict) or not node.get("id"):
        return None
    return str(node.get("name") or "")


async def get_group_name(tg: TGClient, group_id: str) -> str | None:
    """The group's name, or None if no group has `group_id`."""
    return await _get_name_by_id(tg, _GET_GROUP_QUERY, "group", group_id)


async def get_security_policy_name(tg: TGClient, policy_id: str) -> str | None:
    """The security policy's name, or None if no policy has `policy_id`."""
    return await _get_name_by_id(tg, _GET_SECURITY_POLICY_QUERY, "securityPolicy", policy_id)


async def delete_resource(tg: TGClient, resource_id: str) -> None:
    """Delete a resource by id."""
    data = await tg.execute(_DELETE_RESOURCE_MUTATION, {"id": resource_id})
    _unwrap(data, "resourceDelete", "DeleteResource")


async def create_x509_ca(tg: TGClient, name: str, certificate_pem: str) -> str:
    """Register an X.509 CA. `certificate_pem` is the full PEM certificate string."""
    data = await tg.execute(
        _CREATE_X509_CA_MUTATION, {"name": name, "certificate": certificate_pem}
    )
    result = _unwrap(data, "x509CertificateAuthorityCreate", "CreateX509CA")
    return _entity_id(result, "CreateX509CA")


async def create_ssh_ca(tg: TGClient, name: str, public_key: str) -> str:
    """Register an SSH CA. `public_key` is the full OpenSSH public-key line."""
    data = await tg.execute(_CREATE_SSH_CA_MUTATION, {"name": name, "publicKey": public_key})
    result = _unwrap(data, "sshCertificateAuthorityCreate", "CreateSSHCA")
    return _entity_id(result, "CreateSSHCA")


async def update_gateway(
    tg: TGClient,
    gateway_id: str,
    *,
    x509_ca_id: str | None = None,
    ssh_ca_id: str | None = None,
    address: str | None = None,
) -> None:
    """Reassign a gateway's X.509 CA, SSH CA, and/or address.

    Any of `x509_ca_id`, `ssh_ca_id`, and `address` left as ``None`` is omitted from
    the mutation variables so the corresponding argument is *absent* (not null) and the
    field is left unchanged.
    """
    remote_network_id = await _remote_network_id_for_gateway(tg, gateway_id)
    variables: dict[str, Any] = {"id": gateway_id, "remoteNetworkId": remote_network_id}
    if x509_ca_id is not None:
        variables["x509CAId"] = x509_ca_id
    if ssh_ca_id is not None:
        variables["sshCAId"] = ssh_ca_id
    if address is not None:
        variables["address"] = address
    data = await tg.execute(_UPDATE_GATEWAY_MUTATION, variables)
    _unwrap(data, "gatewayUpdate", "UpdateGateway")


def normalise_fingerprint(fingerprint: str) -> str:
    """A certificate fingerprint as lowercase hex with no colons or whitespace.

    The tenant reports X.509 CA fingerprints as uppercase, colon-separated hex; the
    registered root's pin is lowercase hex. Both compare in this form.
    """
    return "".join(fingerprint.replace(":", "").split()).lower()


@dataclass(frozen=True)
class GatewayCABinding:
    """The X.509 CA a gateway is bound to, as the tenant reports it."""

    ca_id: str
    fingerprint: str
    """Normalised: lowercase hex, no colons."""


async def get_gateway_x509_ca(tg: TGClient, gateway_id: str) -> GatewayCABinding | None:
    """Read the X.509 CA bound to `gateway_id` (uncached: every call is a round trip).

    Returns ``None`` when the gateway reports no X.509 CA. Raises :class:`TGAPIError` when
    the gateway does not exist or the response is malformed.
    """
    data = await tg.execute(_GET_GATEWAY_X509_CA_QUERY, {"id": gateway_id})
    gateway = data.get("gateway")
    if gateway is None:
        raise TGAPIError(
            f"gateway {gateway_id} not found",
            status=200,
            query_name="GetGatewayX509CA",
            body=json.dumps(data),
        )
    try:
        ca = gateway["x509CA"]
        if ca is None:
            return None
        ca_id = ca["id"]
        fingerprint = ca["fingerprint"]
        if not ca_id or not isinstance(fingerprint, str) or not fingerprint:
            raise ValueError("x509CA has a null/empty id or fingerprint")
    except (KeyError, TypeError, ValueError) as exc:
        raise TGAPIError(
            f"GetGatewayX509CA returned a malformed response: {exc}",
            status=200,
            query_name="GetGatewayX509CA",
            body=json.dumps(data),
        ) from exc
    return GatewayCABinding(ca_id=str(ca_id), fingerprint=normalise_fingerprint(fingerprint))


async def find_x509_ca_ids_by_fingerprint(tg: TGClient, sha256_hex: str) -> list[str]:
    """Ids of every X.509 CA whose fingerprint equals `sha256_hex` (all pages).

    The comparison is on the normalised form, so the argument may carry colons or any
    case. A malformed page or a cursor that does not advance raises :class:`TGAPIError`;
    a partial list is never returned.
    """
    wanted = normalise_fingerprint(sha256_hex)
    ids: list[str] = []
    cursor: str | None = None
    while True:
        data = await tg.execute(_LIST_X509_CAS_QUERY, {"first": _PAGE_SIZE, "after": cursor})
        try:
            connection = data["certificateAuthorities"]
            page_info = connection["pageInfo"]
            has_next_page = page_info["hasNextPage"]
            end_cursor = page_info["endCursor"]
            for edge in connection["edges"]:
                node = edge["node"]
                typename = node.get("__typename")
                if typename is not None and typename != "X509CertificateAuthority":
                    continue
                node_id = node["id"]
                fingerprint = node["fingerprint"]
                if not node_id or not isinstance(fingerprint, str):
                    raise ValueError("X.509 CA node has a null/empty id or fingerprint")
                if normalise_fingerprint(fingerprint) == wanted:
                    ids.append(str(node_id))
        except (KeyError, TypeError, AttributeError, ValueError) as exc:
            raise TGAPIError(
                f"FindX509CAsByFingerprint returned a malformed response: {exc}",
                status=200,
                query_name="FindX509CAsByFingerprint",
                body=json.dumps(data),
            ) from exc
        if not has_next_page:
            return ids
        if not end_cursor or end_cursor == cursor:
            raise TGAPIError(
                "FindX509CAsByFingerprint pagination did not advance "
                "(hasNextPage with a missing or repeated endCursor)",
                status=200,
                query_name="FindX509CAsByFingerprint",
                body=json.dumps(data),
            )
        cursor = str(end_cursor)
