"""Tenant side of the live rig: inventory, setup, access grant and the id-scoped sweep."""

import argparse
import asyncio
import json
import math
import os
import random
import re
import time
from collections.abc import Awaitable, Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Self

import httpx
import structlog

from . import guards
from .seedgen import (
    ADMIN_TOKEN_FILE,
    CLIENT_ENV_FILE,
    CONNECTOR_ENV_FILE,
    GATORCAST_ENV_FILE,
    GWOPS_ENV_FILE,
    build_names,
)

logger = structlog.get_logger(__name__)

Inventory = dict[str, dict[str, str]]

INVENTORY_KINDS = ("gateway", "gateway_binding", "resource", "ca", "connector", "service_account")
SWEEP_ORDER = (
    "service_account_key",
    "service_account",
    "web_app",
    "ssh",
    "gateway",
    "connector",
    "ca",
    "ssh_ca",
)
RECORDABLE_KINDS = SWEEP_ORDER
INVENTORY_KIND_OF = {
    "service_account": "service_account",
    "web_app": "resource",
    "ssh": "resource",
    "gateway": "gateway",
    "connector": "connector",
    "ca": "ca",
    "ssh_ca": "ca",
}
_DELETE_FIELDS = {
    "service_account_key": ("serviceAccountKeyDelete", "RigDeleteServiceAccountKey"),
    "service_account": ("serviceAccountDelete", "RigDeleteServiceAccount"),
    "web_app": ("resourceDelete", "RigDeleteResource"),
    "ssh": ("resourceDelete", "RigDeleteResource"),
    "gateway": ("gatewayDelete", "RigDeleteGateway"),
    "connector": ("connectorDelete", "RigDeleteConnector"),
    "ca": ("x509CertificateAuthorityDelete", "RigDeleteX509CA"),
    "ssh_ca": ("sshCertificateAuthorityDelete", "RigDeleteSSHCA"),
}

DEFAULT_RUN_ROOT = Path(__file__).resolve().parents[1] / ".run"
STATE_FILE = "state.json"

_PAGE_SIZE = 50
_MAX_ATTEMPTS = 8
_REQUEST_TIMEOUT_SECONDS = 30.0
_THROTTLE_CAP_SECONDS = 60.0
_BACKOFF_CAP_SECONDS = 30.0
_BODY_EXCERPT_CHARS = 300
_RETRY_AFTER_RE = re.compile(r"\d{1,9}", re.ASCII)
_BODY_HINT_RE = re.compile(r"Expected available in (\d+(?:\.\d+)?) seconds?", re.IGNORECASE)
_OP_NAME_RE = re.compile(r"(?:query|mutation)\s+([A-Za-z_]\w*)")
_NOT_FOUND_RE = re.compile(r"does not exist|doesn't exist|not found|no such", re.IGNORECASE)
_ALREADY_REVOKED_RE = re.compile(
    r"already\s+(?:been\s+)?revoked|has\s+been\s+revoked|is\s+revoked", re.IGNORECASE
)
_REVOKE_KEY = """
mutation RigRevokeServiceAccountKey($id: ID!) {
  serviceAccountKeyRevoke(id: $id) { ok error }
}
"""
_LIST_SERVICE_ACCOUNT_KEYS = f"""
query RigListServiceAccountKeys($id: ID!, $first: Int!, $after: String) {{
  serviceAccount(id: $id) {{
    keys(first: $first, after: $after) {{
      {"pageInfo { hasNextPage endCursor }"}
      edges {{ node {{ id name status }} }}
    }}
  }}
}}
"""


# --- errors ----------------------------------------------------------------------------


class RigApiError(Exception):
    """A failed Twingate API call; the message never holds the API key."""


class RigAuthError(RigApiError):
    """The API key was rejected (HTTP 401 or 403)."""


class RigGraphQLError(RigApiError):
    """A 200 response whose body carried GraphQL errors."""

    def __init__(self, message: str, messages: Sequence[str]) -> None:
        super().__init__(message)
        self.messages = list(messages)


class RigMutationError(RigApiError):
    """A mutation answered ok=false."""

    def __init__(self, field_name: str, error: str) -> None:
        super().__init__(f"{field_name} failed: {error}")
        self.error = error


class SweepError(Exception):
    """One or more sweep or inventory problems, all collected."""

    def __init__(self, errors: Sequence[str], report: "SweepReport | None" = None) -> None:
        super().__init__("\n".join(errors))
        self.errors = list(errors)
        self.report = report


# --- throttle hint (pure) --------------------------------------------------------------


def parse_retry_after(value: str, now: datetime) -> float | None:
    """Seconds from a Retry-After header (delta-seconds or HTTP-date), or None."""
    value = value.strip()
    if _RETRY_AFTER_RE.fullmatch(value):
        return float(int(value))
    try:
        when = parsedate_to_datetime(value)
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        seconds = max(0.0, (when - now).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None
    return seconds if math.isfinite(seconds) else None


def parse_body_hint(body: str) -> float | None:
    """Seconds from a body hint like "Expected available in 12 seconds", or None."""
    match = _BODY_HINT_RE.search(body)
    if match is None:
        return None
    seconds = float(match.group(1))
    return seconds if math.isfinite(seconds) else None


def throttle_delay(
    retry_after: str | None, body: str, attempt: int, *, now: datetime, jitter: float
) -> float:
    """Seconds to wait after a 429: the server hint (capped) plus jitter, else backoff."""
    hint = parse_retry_after(retry_after, now) if retry_after else None
    if hint is None:
        hint = parse_body_hint(body)
    if hint is None:
        return min(_BACKOFF_CAP_SECONDS, 2.0**attempt) + jitter
    return min(hint, _THROTTLE_CAP_SECONDS) + jitter


def backoff_delay(attempt: int, jitter: float) -> float:
    """Exponential backoff with jitter for 5xx and transport retries."""
    return min(_BACKOFF_CAP_SECONDS, 2.0 ** (attempt - 1)) + jitter


# --- GraphQL client --------------------------------------------------------------------


def _op_name(query: str) -> str:
    match = _OP_NAME_RE.search(query)
    return match.group(1) if match else "anonymous"


class GraphQLClient:
    """Async GraphQL client for one tenant; 429 waits on the server's throttle hint."""

    def __init__(
        self,
        network: str,
        api_key: str,
        *,
        host: str = "twingate.com",
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """Build a client for `network`; `sleep` is a seam for tests."""
        self._api_key = api_key
        self._url = f"https://{network}.{host}/api/graphql/"
        self._sleep = sleep
        self._http = httpx.AsyncClient(
            headers={"X-API-KEY": api_key, "Content-Type": "application/json"},
            timeout=httpx.Timeout(_REQUEST_TIMEOUT_SECONDS),
        )

    async def aclose(self) -> None:
        """Close the HTTP client."""
        await self._http.aclose()

    def _redact(self, text: str) -> str:
        return text.replace(self._api_key, "***") if self._api_key else text

    async def execute(
        self, query: str, variables: Mapping[str, Any], *, idempotent: bool = True
    ) -> dict[str, Any]:
        """Run one operation and return its data; non-idempotent ops never retry 5xx or timeouts."""
        op = _op_name(query)
        payload = {"query": query, "variables": dict(variables)}
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            started = time.monotonic()
            try:
                response = await self._http.post(self._url, json=payload)
            except httpx.TransportError as exc:
                reason = self._redact(f"{type(exc).__name__}: {exc}")
                if not idempotent or attempt == _MAX_ATTEMPTS:
                    raise RigApiError(
                        f"{op} failed: transport error ({reason})"
                        + ("" if idempotent else "; outcome unknown, not retried")
                    ) from None
                await self._sleep(backoff_delay(attempt, random.uniform(0, 1)))
                continue
            status = response.status_code
            logger.info(
                "rig.request",
                op=op,
                status=status,
                attempt=attempt,
                duration=round(time.monotonic() - started, 3),
            )
            if status in (401, 403):
                raise RigAuthError(f"{op} failed: HTTP {status}")
            if status == 429:
                if attempt == _MAX_ATTEMPTS:
                    raise RigApiError(f"{op} rate-limited after {attempt} attempts")
                delay = throttle_delay(
                    response.headers.get("Retry-After"),
                    response.text,
                    attempt,
                    now=datetime.now(UTC),
                    jitter=random.uniform(0, 1),
                )
                logger.warning("rig.throttled", op=op, wait_seconds=round(delay, 3))
                await self._sleep(delay)
                continue
            if status >= 500:
                if not idempotent or attempt == _MAX_ATTEMPTS:
                    raise RigApiError(
                        f"{op} failed: HTTP {status}"
                        + ("" if idempotent else "; outcome unknown, not retried")
                    )
                await self._sleep(backoff_delay(attempt, random.uniform(0, 1)))
                continue
            if status >= 400:
                excerpt = self._redact(response.text[:_BODY_EXCERPT_CHARS])
                raise RigApiError(f"{op} failed: HTTP {status}: {excerpt}")
            return self._data(op, response)
        raise AssertionError("unreachable: retry loop must return or raise")

    def _data(self, op: str, response: httpx.Response) -> dict[str, Any]:
        try:
            body = response.json()
        except ValueError:
            raise RigApiError(f"{op} returned a non-JSON 200 response") from None
        if not isinstance(body, dict):
            raise RigApiError(f"{op} returned a non-object JSON 200 response")
        if body.get("errors"):
            messages = [
                self._redact(str(err.get("message", err)) if isinstance(err, dict) else str(err))
                for err in body["errors"]
            ]
            raise RigGraphQLError(f"{op} returned GraphQL errors: {'; '.join(messages)}", messages)
        data = body.get("data") or {}
        if not isinstance(data, dict):
            raise RigApiError(f"{op} returned a non-object data payload")
        return data

    async def mutate(
        self,
        query: str,
        variables: Mapping[str, Any],
        field_name: str,
        *,
        idempotent: bool = False,
    ) -> dict[str, Any]:
        """Run a mutation and return its result dict; raises RigMutationError on ok=false."""
        data = await self.execute(query, variables, idempotent=idempotent)
        result = data.get(field_name)
        if not isinstance(result, dict) or "ok" not in result:
            raise RigApiError(f"{_op_name(query)} returned a malformed response")
        if not result["ok"]:
            raise RigMutationError(field_name, self._redact(str(result.get("error") or "unknown")))
        return result

    async def paginate(
        self, query: str, variables: Mapping[str, Any], path: Sequence[str]
    ) -> list[dict[str, Any]]:
        """Collect every node of the connection at `path`, across all pages."""
        op = _op_name(query)
        nodes: list[dict[str, Any]] = []
        cursor: str | None = None
        seen: set[str] = set()
        while True:
            data = await self.execute(query, {**variables, "first": _PAGE_SIZE, "after": cursor})
            page, has_next, end_cursor = read_connection(data, path, op)
            nodes.extend(page)
            if not has_next:
                return nodes
            if not end_cursor or end_cursor in seen:
                raise RigApiError(f"{op} is incomplete: the next page has no new cursor")
            seen.add(end_cursor)
            cursor = end_cursor


def read_connection(
    data: Mapping[str, Any], path: Sequence[str], op: str
) -> tuple[list[dict[str, Any]], bool, str | None]:
    """Walk `path` into `data` and return (nodes, hasNextPage, endCursor); raises if malformed."""
    node: Any = data
    for key in path:
        node = node.get(key) if isinstance(node, dict) else None
        if node is None:
            raise RigApiError(f"{op}: {'.'.join(path)} is null or missing")
    try:
        nodes = [edge["node"] for edge in node["edges"]]
        page_info = node["pageInfo"]
        has_next, end_cursor = bool(page_info["hasNextPage"]), page_info.get("endCursor")
    except (KeyError, TypeError, AttributeError):
        raise RigApiError(f"{op} returned a malformed connection") from None
    if not all(isinstance(item, dict) for item in nodes):
        raise RigApiError(f"{op} returned a connection with a non-object node")
    return nodes, has_next, end_cursor


# --- inventory -------------------------------------------------------------------------

_PAGE_INFO = "pageInfo { hasNextPage endCursor }"
_LIST_GATEWAYS = f"""
query RigListGateways($id: ID, $first: Int!, $after: String) {{
  remoteNetwork(id: $id) {{
    gateways(first: $first, after: $after) {{
      {_PAGE_INFO}
      edges {{ node {{ id address x509CA {{ id }} sshCA {{ id }} }} }}
    }}
  }}
}}
"""
_LIST_RESOURCES = f"""
query RigListResources($id: ID, $first: Int!, $after: String) {{
  remoteNetwork(id: $id) {{
    resources(first: $first, after: $after) {{
      {_PAGE_INFO}
      edges {{ node {{ id name }} }}
    }}
  }}
}}
"""
_LIST_CONNECTORS = f"""
query RigListConnectors($id: ID, $first: Int!, $after: String) {{
  remoteNetwork(id: $id) {{
    connectors(first: $first, after: $after) {{
      {_PAGE_INFO}
      edges {{ node {{ id name }} }}
    }}
  }}
}}
"""
_LIST_CAS = f"""
query RigListCertificateAuthorities($first: Int!, $after: String) {{
  certificateAuthorities(first: $first, after: $after) {{
    {_PAGE_INFO}
    edges {{
      node {{
        ... on X509CertificateAuthority {{ id name }}
        ... on SSHCertificateAuthority {{ id name }}
      }}
    }}
  }}
}}
"""
_LIST_SERVICE_ACCOUNTS = f"""
query RigListServiceAccounts($first: Int!, $after: String) {{
  serviceAccounts(first: $first, after: $after) {{
    {_PAGE_INFO}
    edges {{ node {{ id name }} }}
  }}
}}
"""


def parse_entries(nodes: Iterable[Mapping[str, Any]], name_key: str, op: str) -> dict[str, str]:
    """Map id to name for `nodes`; raises RigApiError on an empty id or non-string name."""
    entries: dict[str, str] = {}
    for node in nodes:
        object_id, name = node.get("id"), node.get(name_key)
        if not object_id or not isinstance(name, str):
            raise RigApiError(f"{op} returned a node with an empty id or missing {name_key}")
        entries[str(object_id)] = name
    return entries


async def _gateway_nodes(client: GraphQLClient, remote_network_id: str) -> list[dict[str, Any]]:
    return await client.paginate(
        _LIST_GATEWAYS, {"id": remote_network_id}, ("remoteNetwork", "gateways")
    )


async def list_gateways(client: GraphQLClient, remote_network_id: str) -> list[tuple[str, str]]:
    """Every (id, address) gateway in the remote network."""
    nodes = await _gateway_nodes(client, remote_network_id)
    return list(parse_entries(nodes, "address", "RigListGateways").items())


def gateway_bindings(nodes: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    """Gateway id to `x509=<ca id>;ssh=<ca id>`; a missing CA reads as empty."""

    def ca_id(node: Mapping[str, Any], key: str) -> str:
        value = node.get(key)
        return str(value.get("id", "")) if isinstance(value, dict) else ""

    return {
        str(node["id"]): f"x509={ca_id(node, 'x509CA')};ssh={ca_id(node, 'sshCA')}"
        for node in nodes
        if node.get("id")
    }


async def fetch_inventory(client: GraphQLClient, remote_network_id: str) -> Inventory:
    """Ids and names of remote-network gateways, resources, connectors, plus CAs and accounts."""
    scope = {"id": remote_network_id}
    gateway_nodes = await _gateway_nodes(client, remote_network_id)
    gateways = list(parse_entries(gateway_nodes, "address", "RigListGateways").items())
    resources = await client.paginate(_LIST_RESOURCES, scope, ("remoteNetwork", "resources"))
    connectors = await client.paginate(_LIST_CONNECTORS, scope, ("remoteNetwork", "connectors"))
    cas = await client.paginate(_LIST_CAS, {}, ("certificateAuthorities",))
    accounts = await client.paginate(_LIST_SERVICE_ACCOUNTS, {}, ("serviceAccounts",))
    return {
        "gateway": dict(gateways),
        "gateway_binding": gateway_bindings(gateway_nodes),
        "resource": parse_entries(resources, "name", "RigListResources"),
        "connector": parse_entries(connectors, "name", "RigListConnectors"),
        "ca": parse_entries(cas, "name", "RigListCertificateAuthorities"),
        "service_account": parse_entries(accounts, "name", "RigListServiceAccounts"),
    }


def diff_inventory(pre: Inventory, post: Inventory) -> list[str]:
    """Human-readable differences between two inventories; empty when identical."""
    problems: list[str] = []
    for kind in INVENTORY_KINDS:
        before, after = pre.get(kind, {}), post.get(kind, {})
        problems.extend(
            f"added {kind} {i} ({after[i]!r})" for i in sorted(after.keys() - before.keys())
        )
        problems.extend(
            f"removed {kind} {i} ({before[i]!r})" for i in sorted(before.keys() - after.keys())
        )
        problems.extend(
            f"renamed {kind} {i} ({before[i]!r} -> {after[i]!r})"
            for i in sorted(before.keys() & after.keys())
            if before[i] != after[i]
        )
    return problems


def select_new(
    pre: Inventory,
    current: Inventory,
    record_kind: str,
    *,
    name: str | None = None,
    name_prefix: str | None = None,
) -> list[tuple[str, str]]:
    """(id, name) entries absent from `pre` whose name matches; at least one filter is required."""
    if record_kind not in INVENTORY_KIND_OF:
        raise ValueError(f"unknown kind {record_kind!r}")
    if name is None and name_prefix is None:
        raise ValueError("select_new needs name or name_prefix; bystander objects are never picked")
    kind = INVENTORY_KIND_OF[record_kind]
    known = pre.get(kind, {})
    return sorted(
        (object_id, found)
        for object_id, found in current.get(kind, {}).items()
        if object_id not in known
        and (name is None or found == name)
        and (name_prefix is None or found.startswith(name_prefix))
    )


def load_inventory(raw: object) -> Inventory:
    """Validate a decoded inventory mapping."""
    if not isinstance(raw, dict):
        raise ValueError("inventory must be an object")
    inventory: Inventory = {}
    for kind, entries in raw.items():
        if kind not in INVENTORY_KINDS or not isinstance(entries, dict):
            raise ValueError(f"inventory has an invalid entry {kind!r}")
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in entries.items()):
            raise ValueError(f"inventory kind {kind!r} must map string ids to string names")
        inventory[kind] = dict(entries)
    return inventory


# --- run state -------------------------------------------------------------------------


@dataclass(frozen=True)
class CreatedObject:
    """One object the run created: kind (see RECORDABLE_KINDS), tenant id and name."""

    kind: str
    object_id: str
    name: str = ""


@dataclass
class RunState:
    """Everything the run created, plus the pre-run inventory; holds no secrets."""

    run_id: str
    network: str
    remote_network_id: str
    gateway_address: str
    created: list[CreatedObject] = field(default_factory=list)
    deleted: list[CreatedObject] = field(default_factory=list)
    pre_inventory: Inventory | None = None
    docker_endpoint: str = ""

    def preexisting_ids(self) -> set[str]:
        """Every id in the pre-run inventory."""
        inventory = self.pre_inventory or {}
        return {oid for entries in inventory.values() for oid in entries}

    def ids(self, kind: str) -> list[str]:
        """Recorded ids of `kind`, in creation order."""
        return [obj.object_id for obj in self.created if obj.kind == kind]

    def record(self, kind: str, object_id: str, name: str = "") -> None:
        """Record a created object; refuses unknown kinds, empty ids and pre-existing ids."""
        if kind not in RECORDABLE_KINDS:
            raise guards.GuardError(f"Cannot record unknown kind {kind!r}.")
        if not object_id:
            raise guards.GuardError(f"Cannot record an empty {kind} id.")
        if self.pre_inventory is None:
            raise guards.GuardError("Cannot record before the pre-run inventory exists.")
        guards.require_not_preexisting(kind, object_id, self.preexisting_ids())
        guards.validate_recorded_name(
            kind, name, run_id=self.run_id, gateway_address=self.gateway_address
        )
        entry = CreatedObject(kind, object_id, name)
        if entry not in self.created:
            self.created.append(entry)

    def mark_deleted(self, entry: CreatedObject) -> None:
        """Move `entry` from created to deleted."""
        self.created.remove(entry)
        self.deleted.append(entry)

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready form."""
        return {
            "version": 1,
            "run_id": self.run_id,
            "network": self.network,
            "remote_network_id": self.remote_network_id,
            "gateway_address": self.gateway_address,
            "created": [_entry_dict(obj) for obj in self.created],
            "deleted": [_entry_dict(obj) for obj in self.deleted],
            "pre_inventory": self.pre_inventory,
            "docker_endpoint": self.docker_endpoint,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> Self:
        """Rebuild from `to_dict` output; raises ValueError on a malformed file."""
        try:
            created = [_entry_from(item) for item in raw["created"]]
            deleted = [_entry_from(item) for item in raw["deleted"]]
            pre = raw["pre_inventory"]
            state = cls(
                run_id=str(raw["run_id"]),
                network=str(raw["network"]),
                remote_network_id=str(raw["remote_network_id"]),
                gateway_address=str(raw["gateway_address"]),
                created=created,
                deleted=deleted,
                pre_inventory=None if pre is None else load_inventory(pre),
                docker_endpoint=str(raw.get("docker_endpoint", "")),
            )
        except (KeyError, TypeError) as exc:
            raise ValueError(f"malformed run state: {type(exc).__name__} {exc}") from None
        state.require_derived_gateway_address()
        state.require_created_are_run_owned()
        return state

    def require_derived_gateway_address(self) -> None:
        """Refuse a gateway address other than the one derived from the run id (name rules)."""
        derived = build_names(self.run_id).gateway_address
        if self.gateway_address != derived:
            raise guards.GuardError(
                f"Refusing to load run state: gateway_address {self.gateway_address!r} is not "
                f"the address derived from run id {self.run_id!r} ({derived!r})."
            )

    def require_created_are_run_owned(self) -> None:
        """Refuse recorded ids that are in the pre-run inventory, or any record without one."""
        if not self.created:
            return
        if self.pre_inventory is None:
            raise guards.GuardError(
                "Refusing to load run state: ids are recorded but there is no pre-run inventory."
            )
        preexisting = self.preexisting_ids()
        for entry in self.created:
            guards.require_not_preexisting(entry.kind, entry.object_id, preexisting)
            guards.validate_recorded_name(
                entry.kind, entry.name, run_id=self.run_id, gateway_address=self.gateway_address
            )


def _entry_dict(obj: CreatedObject) -> dict[str, str]:
    return {"kind": obj.kind, "id": obj.object_id, "name": obj.name}


def _entry_from(item: Mapping[str, Any]) -> CreatedObject:
    kind, object_id = item["kind"], item["id"]
    if kind not in RECORDABLE_KINDS or not isinstance(object_id, str) or not object_id:
        raise ValueError(f"malformed run state entry for kind {kind!r}")
    return CreatedObject(kind, object_id, str(item.get("name", "")))


def save_state(path: Path, state: RunState) -> None:
    """Write the state file atomically."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(state.to_dict(), indent=2))
    os.replace(tmp, path)


def load_state(path: Path) -> RunState:
    """Read a state file; raises ValueError when unreadable or malformed."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read run state {path}: {type(exc).__name__}") from None
    if not isinstance(raw, dict):
        raise ValueError(f"run state {path} is not a JSON object")
    return RunState.from_dict(raw)


def write_secret_file(path: Path, lines: Sequence[str]) -> None:
    """Create `path` exclusively with mode 0600 (where the OS honours it) holding `lines`."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")


# --- sweep planning (pure) -------------------------------------------------------------


@dataclass(frozen=True)
class SweepStep:
    """One delete: the recorded object, the mutation field and the operation name."""

    entry: CreatedObject
    field_name: str
    op_name: str


def plan_sweep(created: Sequence[CreatedObject]) -> list[SweepStep]:
    """Delete steps for recorded objects in SWEEP_ORDER; unknown kinds raise ValueError."""
    unknown = sorted({obj.kind for obj in created} - set(RECORDABLE_KINDS))
    if unknown:
        raise ValueError(f"cannot sweep unknown kind(s): {', '.join(unknown)}")
    return [
        SweepStep(obj, *_DELETE_FIELDS[kind])
        for kind in SWEEP_ORDER
        for obj in created
        if obj.kind == kind
    ]


def delete_mutation(step: SweepStep) -> str:
    """The GraphQL document for `step`."""
    return f"mutation {step.op_name}($id: ID!) {{ {step.field_name}(id: $id) {{ ok error }} }}"


def is_not_found(messages: Iterable[str]) -> bool:
    """True when every message clearly says the object does not exist (and there is one)."""
    texts = list(messages)
    return bool(texts) and all(_NOT_FOUND_RE.search(text) for text in texts)


@dataclass
class SweepReport:
    """Outcome of a sweep: ids deleted, ids already gone, and local files removed."""

    deleted: list[str] = field(default_factory=list)
    already_gone: list[str] = field(default_factory=list)
    secret_files_removed: list[str] = field(default_factory=list)
    inventory_compared: bool = True


async def revoke_key(client: GraphQLClient, key_id: str) -> bool:
    """Revoke a key; False when it is gone, True when revoked now or already revoked."""
    try:
        await client.mutate(_REVOKE_KEY, {"id": key_id}, "serviceAccountKeyRevoke", idempotent=True)
    except RigMutationError as exc:
        messages = [exc.error]
    except RigGraphQLError as exc:
        messages = exc.messages
    else:
        return True
    if is_not_found(messages):
        return False
    if all(_ALREADY_REVOKED_RE.search(text) for text in messages):
        return True
    raise RigApiError(f"RigRevokeServiceAccountKey failed: {'; '.join(messages)}")


async def delete_key(client: GraphQLClient, step: SweepStep, *, revoked: bool) -> bool:
    """Revoke (unless `revoked`) then delete a key; False when it was already gone."""
    if not revoked and not await revoke_key(client, step.entry.object_id):
        return False
    return await delete_one(client, step)


async def delete_one(client: GraphQLClient, step: SweepStep) -> bool:
    """Delete one object; True if deleted, False if it was already gone, else raises."""
    try:
        await client.mutate(
            delete_mutation(step), {"id": step.entry.object_id}, step.field_name, idempotent=True
        )
    except RigMutationError as exc:
        if is_not_found([exc.error]):
            return False
        raise
    except RigGraphQLError as exc:
        if is_not_found(exc.messages):
            return False
        raise
    return True


# --- pre-delete verification ------------------------------------------------------------

_CA_FIELDS = (
    "... on X509CertificateAuthority { id name } ... on SSHCertificateAuthority { id name }"
)
_GET_DOCS: dict[str, tuple[str, str, str]] = {
    "web_app": (
        "RigGetResource",
        "resource",
        "query RigGetResource($id: ID!) { resource(id: $id) { id name remoteNetwork { id } } }",
    ),
    "connector": (
        "RigGetConnector",
        "connector",
        "query RigGetConnector($id: ID!) { connector(id: $id) { id name remoteNetwork { id } } }",
    ),
    "gateway": (
        "RigGetGateway",
        "gateway",
        "query RigGetGateway($id: ID!) { gateway(id: $id) { id address remoteNetwork { id } } }",
    ),
    "ca": (
        "RigGetCertificateAuthority",
        "certificateAuthority",
        "query RigGetCertificateAuthority($id: ID!) "
        "{ certificateAuthority(id: $id) { " + _CA_FIELDS + " } }",
    ),
    "service_account": (
        "RigGetServiceAccount",
        "serviceAccount",
        "query RigGetServiceAccount($id: ID!) { serviceAccount(id: $id) { id name } }",
    ),
}
_GET_DOCS["ssh_ca"] = _GET_DOCS["ca"]
_GET_DOCS["ssh"] = _GET_DOCS["web_app"]
_GET_DOCS["service_account_key"] = (
    "RigGetServiceAccountKey",
    "serviceAccountKey",
    "query RigGetServiceAccountKey($id: ID) "
    "{ serviceAccountKey(id: $id) { id name status serviceAccount { id name } } }",
)


async def fetch_target(client: GraphQLClient, entry: CreatedObject) -> dict[str, Any] | None:
    """The live object `entry` names, fetched by id; None when it no longer exists."""
    op, field_name, document = _GET_DOCS[entry.kind]
    try:
        data = await client.execute(document, {"id": entry.object_id}, idempotent=True)
    except RigGraphQLError as exc:
        if is_not_found(exc.messages):
            return None
        raise
    if field_name not in data:
        raise RigApiError(f"{op} returned no {field_name!r} field")
    node = data[field_name]
    if node is None:
        return None
    if not isinstance(node, dict):
        raise RigApiError(f"{op} returned a malformed object")
    return node


# --- tenant ----------------------------------------------------------------------------

_CREATE_CONNECTOR = """
mutation RigCreateConnector($remoteNetworkId: ID!, $name: String!) {
  connectorCreate(
    remoteNetworkId: $remoteNetworkId, name: $name, hasStatusNotificationsEnabled: false
  ) { ok error entity { id } }
}
"""
_GENERATE_TOKENS = """
mutation RigGenerateConnectorTokens($connectorId: ID!) {
  connectorGenerateTokens(connectorId: $connectorId) {
    ok error connectorTokens { accessToken refreshToken }
  }
}
"""
_CREATE_SERVICE_ACCOUNT = """
mutation RigCreateServiceAccount($name: String!) {
  serviceAccountCreate(name: $name) { ok error entity { id } }
}
"""
_CREATE_SERVICE_KEY = """
mutation RigCreateServiceAccountKey($serviceAccountId: ID!, $name: String, $days: Int!) {
  serviceAccountKeyCreate(serviceAccountId: $serviceAccountId, name: $name, expirationTime: $days) {
    ok error entity { id } token
  }
}
"""
_GRANT_ACCESS = """
mutation RigGrantAccess($resourceId: ID!, $access: [AccessInput!]!) {
  resourceAccessAdd(resourceId: $resourceId, access: $access) { ok error }
}
"""
_SECRET_FILES = (
    CONNECTOR_ENV_FILE,
    CLIENT_ENV_FILE,
    GWOPS_ENV_FILE,
    ADMIN_TOKEN_FILE,
    GATORCAST_ENV_FILE,
)


def entity_id(result: Mapping[str, Any], op: str) -> str:
    """The created entity's id; raises RigApiError when missing."""
    entity = result.get("entity")
    if not isinstance(entity, dict) or not entity.get("id"):
        raise RigApiError(f"{op} succeeded but returned no entity id")
    return str(entity["id"])


@dataclass(frozen=True)
class SetupResult:
    """Ids and secret-file paths from setup; never the secrets themselves."""

    connector_id: str
    service_account_id: str
    connector_env_file: Path
    client_env_file: Path


class RigTenant:
    """One run's view of the tenant: setup, access grant, recording and sweep."""

    def __init__(
        self, env: guards.RigEnv, client: GraphQLClient, state: RunState, run_dir: Path
    ) -> None:
        """Wrap a started run; use `start` or `resume` rather than calling directly."""
        self._env = env
        self._client = client
        self._state = state
        self._run_dir = run_dir
        self._prefix = guards.run_prefix(state.run_id)

    @classmethod
    async def start(
        cls,
        env: guards.RigEnv,
        *,
        gateway_address: str,
        run_root: Path = DEFAULT_RUN_ROOT,
        run_id: str | None = None,
        client: GraphQLClient | None = None,
        docker_endpoint: str = "",
    ) -> Self:
        """Create the run dir and state, apply the adoption guard, take the pre-run inventory."""
        guards.require_approved_pair(
            env.network,
            env.remote_network_id,
            env.approved_network,
            env.approved_remote_network_id,
            secret=env.api_key,
        )
        run_id = run_id or guards.new_run_id()
        guards.run_prefix(run_id)
        run_dir = run_root / run_id
        run_dir.mkdir(parents=True, mode=0o700)
        state = RunState(
            run_id,
            env.network,
            env.remote_network_id,
            gateway_address,
            docker_endpoint=docker_endpoint,
        )
        save_state(run_dir / STATE_FILE, state)
        tenant = cls(env, client or GraphQLClient(env.network, env.api_key), state, run_dir)
        try:
            await tenant.preflight()
        except BaseException:
            await tenant.aclose()
            raise
        return tenant

    @classmethod
    async def resume(
        cls,
        env: guards.RigEnv,
        state_path: Path,
        *,
        client: GraphQLClient | None = None,
        docker_endpoint: str | None = None,
    ) -> Self:
        """Reopen a run from its state file; `docker_endpoint` must match the run's engine."""
        state = load_state(state_path)
        if docker_endpoint is not None:
            guards.require_same_engine(state.docker_endpoint, docker_endpoint)
        guards.require_same_pair(state.network, state.remote_network_id, env)
        guards.require_approved_pair(
            env.network,
            env.remote_network_id,
            env.approved_network,
            env.approved_remote_network_id,
            secret=env.api_key,
        )
        return cls(env, client or GraphQLClient(env.network, env.api_key), state, state_path.parent)

    async def aclose(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    @property
    def run_id(self) -> str:
        """The run id."""
        return self._state.run_id

    @property
    def prefix(self) -> str:
        """The object-name prefix `gwops-it-<run id>-`."""
        return self._prefix

    @property
    def run_dir(self) -> Path:
        """The gitignored run directory holding the state file and secret files."""
        return self._run_dir

    @property
    def state_path(self) -> Path:
        """Path of the run-state JSON file."""
        return self._run_dir / STATE_FILE

    @property
    def state(self) -> RunState:
        """The run state."""
        return self._state

    def _save(self) -> None:
        save_state(self.state_path, self._state)

    def record(self, kind: str, object_id: str, name: str = "") -> None:
        """Record an object the run created so the sweep deletes it; saved immediately."""
        self._state.record(kind, object_id, name)
        self._save()

    async def preflight(self) -> None:
        """Apply the Mode B adoption guard, then store the pre-run inventory."""
        gateways = await list_gateways(self._client, self._env.remote_network_id)
        guards.check_gateway_address_free(
            gateways, self._state.gateway_address, remote_network_id=self._env.remote_network_id
        )
        self._state.pre_inventory = await fetch_inventory(self._client, self._env.remote_network_id)
        self._save()

    async def discover_new(
        self, kind: str, *, name: str | None = None, name_prefix: str | None = None
    ) -> list[tuple[str, str]]:
        """New (id, name) objects of `kind` matching `name` or `name_prefix`, for `record`."""
        current = await fetch_inventory(self._client, self._env.remote_network_id)
        return select_new(
            self._state.pre_inventory or {}, current, kind, name=name, name_prefix=name_prefix
        )

    async def assert_address_free(self) -> None:
        """Re-run the Mode B adoption guard against the live gateway listing."""
        gateways = await list_gateways(self._client, self._env.remote_network_id)
        guards.check_gateway_address_free(
            gateways, self._state.gateway_address, remote_network_id=self._env.remote_network_id
        )

    async def discover_all(self) -> list[tuple[str, str, str]]:
        """New (kind, id, name) objects the run owns, by exact name or run prefix."""
        current = await fetch_inventory(self._client, self._env.remote_network_id)
        pre = self._state.pre_inventory or {}
        account_name = guards.service_account_name(self._state.run_id)
        x509_name, ssh_name = guards.derived_ca_names(self._state.gateway_address)
        wanted: list[tuple[str, dict[str, str]]] = [
            ("gateway", {"name": self._state.gateway_address.strip().lower()}),
            ("ca", {"name": x509_name}),
            ("ssh_ca", {"name": ssh_name}),
            ("web_app", {"name_prefix": self._prefix}),
            ("ssh", {"name": guards.ssh_resource_name(self._state.run_id)}),
            ("connector", {"name": guards.connector_name(self._state.run_id)}),
            ("service_account", {"name": guards.service_account_name(self._state.run_id)}),
        ]
        ssh_name = guards.ssh_resource_name(self._state.run_id)
        found = [
            (kind, object_id, name)
            for kind, selector in wanted
            for object_id, name in select_new(pre, current, kind, **selector)
            if not (kind == "web_app" and name == ssh_name)
        ]
        recorded = {o.object_id for o in (*self._state.created, *self._state.deleted)}
        accounts = {
            object_id
            for object_id, name in current.get("service_account", {}).items()
            if name == account_name
            and (object_id in recorded or object_id not in pre.get("service_account", {}))
        }
        for account_id in sorted(accounts):
            found.extend(await self._active_run_keys(account_id))
        return found

    async def _active_run_keys(self, account_id: str) -> list[tuple[str, str, str]]:
        """Active, run-prefixed keys of one live run service account."""
        nodes = await self._client.paginate(
            _LIST_SERVICE_ACCOUNT_KEYS, {"id": account_id}, ("serviceAccount", "keys")
        )
        return [
            ("service_account_key", str(node["id"]), str(node["name"]))
            for node in nodes
            if str(node.get("status", "")).upper() == "ACTIVE"
            and str(node.get("name", "")).startswith(self._prefix)
        ]

    async def record_discovered(self) -> list[tuple[str, str, str]]:
        """Record everything `discover_all` finds so the sweep deletes it; returns the finds."""
        found = await self.discover_all()
        for kind, object_id, name in found:
            self.record(kind, object_id, name)
        return found

    async def unrecorded_run_objects(self) -> list[tuple[str, str, str]]:
        """Run-owned objects on the tenant that no state entry (created or deleted) records."""
        known = {o.object_id for o in (*self._state.created, *self._state.deleted)}
        return [item for item in await self.discover_all() if item[1] not in known]

    async def verified_node(self, entry: CreatedObject) -> dict[str, Any] | None:
        """Fetch `entry` by id and require it is the run's; None if gone, else raises."""
        node = await fetch_target(self._client, entry)
        if node is None:
            return None
        guards.verify_delete_target(
            entry.kind,
            node,
            run_id=self._state.run_id,
            gateway_address=self._state.gateway_address,
            remote_network_id=self._env.approved_remote_network_id,
        )
        if entry.kind == "service_account_key":
            account = node.get("serviceAccount")
            account_id = account.get("id") if isinstance(account, dict) else None
            owners = {
                o.object_id
                for o in (*self._state.created, *self._state.deleted)
                if o.kind == "service_account"
            }
            if account_id not in owners:
                raise guards.UnrecordedIdError(
                    f"Refusing to delete service_account_key {entry.object_id}: its service "
                    f"account {account_id!r} is not one the run recorded. Nothing further was "
                    "deleted."
                )
        return node

    async def verify_target(self, entry: CreatedObject) -> bool:
        """Like `verified_node`, as a bool: False if the object is already gone."""
        return await self.verified_node(entry) is not None

    async def setup(self) -> SetupResult:
        """Create the connector and tokens, then the service account and key; record each id."""
        connector_id = await self._create(
            "connector",
            _CREATE_CONNECTOR,
            "connectorCreate",
            "RigCreateConnector",
            {"remoteNetworkId": self._env.remote_network_id},
            "connector",
        )
        connector_env = await self._write_connector_env(connector_id)
        account_id = await self._create(
            "service_account",
            _CREATE_SERVICE_ACCOUNT,
            "serviceAccountCreate",
            "RigCreateServiceAccount",
            {},
            "client",
        )
        client_env = await self._create_service_key(account_id)
        return SetupResult(connector_id, account_id, connector_env, client_env)

    async def _create(
        self,
        kind: str,
        query: str,
        field_name: str,
        op: str,
        variables: Mapping[str, Any],
        suffix: str,
    ) -> str:
        name = guards.require_prefixed(f"{self._prefix}{suffix}", self._prefix)
        result = await self._client.mutate(query, {**variables, "name": name}, field_name)
        object_id = entity_id(result, op)
        self.record(kind, object_id, name)
        return object_id

    async def _write_connector_env(self, connector_id: str) -> Path:
        result = await self._client.mutate(
            _GENERATE_TOKENS,
            {"connectorId": connector_id},
            "connectorGenerateTokens",
            idempotent=True,
        )
        tokens = result.get("connectorTokens")
        if (
            not isinstance(tokens, dict)
            or not tokens.get("accessToken")
            or not tokens.get("refreshToken")
        ):
            raise RigApiError("RigGenerateConnectorTokens returned no tokens")
        path = self._run_dir / CONNECTOR_ENV_FILE
        write_secret_file(
            path,
            [
                f"TWINGATE_NETWORK={self._env.network}",
                f"TWINGATE_ACCESS_TOKEN={tokens['accessToken']}",
                f"TWINGATE_REFRESH_TOKEN={tokens['refreshToken']}",
                "TWINGATE_LOG_LEVEL=3",
            ],
        )
        return path

    async def _create_service_key(self, account_id: str) -> Path:
        name = guards.require_prefixed(f"{self._prefix}key", self._prefix)
        result = await self._client.mutate(
            _CREATE_SERVICE_KEY,
            {"serviceAccountId": account_id, "name": name, "days": 1},
            "serviceAccountKeyCreate",
        )
        self.record("service_account_key", entity_id(result, "RigCreateServiceAccountKey"), name)
        token = result.get("token")
        if not isinstance(token, str) or not token:
            raise RigApiError("RigCreateServiceAccountKey returned no token")
        path = self._run_dir / CLIENT_ENV_FILE
        write_secret_file(path, [f"TWINGATE_SERVICE_KEY={single_line_key(token)}"])
        return path

    async def grant_access(self, resource_ids: Iterable[str]) -> None:
        """Grant the run's service account, and no other principal, access to recorded web apps."""
        accounts = self._state.ids("service_account")
        if len(accounts) != 1:
            raise guards.GuardError(
                f"grant_access needs exactly one recorded service account, found {len(accounts)}."
            )
        recorded = [*self._state.ids("web_app"), *self._state.ids("ssh")]
        ids = guards.require_recorded("web_app", resource_ids, recorded)
        for resource_id in ids:
            await self._client.mutate(
                _GRANT_ACCESS,
                {"resourceId": resource_id, "access": [{"principalId": accounts[0]}]},
                "resourceAccessAdd",
                idempotent=True,
            )

    async def sweep(self, *, only_kinds: Collection[str] | None = None) -> SweepReport:
        """Delete recorded ids, each verified live first; `only_kinds` restricts the sweep."""
        report = SweepReport()
        errors: list[str] = []
        steps = [
            step
            for step in plan_sweep(self._state.created)
            if only_kinds is None or step.entry.kind in only_kinds
        ]
        for step in steps:
            label = f"{step.entry.kind} {step.entry.object_id}"
            try:
                node = await self.verified_node(step.entry)
                if node is None:
                    deleted = False
                elif step.entry.kind == "service_account_key":
                    revoked = str(node.get("status", "")).upper() == "REVOKED"
                    deleted = await delete_key(self._client, step, revoked=revoked)
                else:
                    deleted = await delete_one(self._client, step)
            except guards.GuardError:
                raise
            except Exception as exc:
                errors.append(f"{label}: {type(exc).__name__}: {exc}")
                continue
            (report.deleted if deleted else report.already_gone).append(step.entry.object_id)
            self._state.mark_deleted(step.entry)
            self._save()
            logger.info(
                "rig.swept", kind=step.entry.kind, id=step.entry.object_id, gone=not deleted
            )
        if not errors and only_kinds is None:
            errors.extend(self._remove_secret_files(report))
        if errors:
            raise SweepError(errors, report)
        return report

    def _remove_secret_files(self, report: SweepReport) -> list[str]:
        errors: list[str] = []
        for name in _SECRET_FILES:
            path = self._run_dir / name
            try:
                path.unlink()
            except FileNotFoundError:
                continue
            except OSError as exc:
                errors.append(f"secret file {name}: {type(exc).__name__}")
                continue
            report.secret_files_removed.append(name)
        return errors

    async def verify_inventory(self) -> bool:
        """Raise SweepError on a difference from the pre-run inventory; False if none to compare."""
        pre = self._state.pre_inventory
        if pre is None:
            if self._state.created or self._state.deleted:
                raise SweepError(["no pre-run inventory in the run state; cannot verify"])
            return False
        post = await fetch_inventory(self._client, self._env.remote_network_id)
        problems = diff_inventory(pre, post)
        if problems:
            raise SweepError([f"inventory differs from pre-run: {p}" for p in problems])
        return True

    async def cleanup(self, *, only_kinds: Collection[str] | None = None) -> SweepReport:
        """Sweep, look for new run objects, compare inventories; raises one SweepError."""
        errors: list[str] = []
        report = SweepReport()
        try:
            report = await self.sweep(only_kinds=only_kinds)
        except SweepError as exc:
            errors.extend(exc.errors)
            report = exc.report or report
        try:
            stray = await self.unrecorded_run_objects()
        except RigApiError as exc:
            errors.append(f"post-sweep discovery failed: {exc}")
        else:
            errors.extend(
                f"new run object after the sweep: {kind} {object_id} ({name!r})"
                for kind, object_id, name in stray
            )
        compared = True
        if only_kinds is None:
            try:
                compared = await self.verify_inventory()
            except (SweepError, RigApiError) as exc:
                errors.extend(exc.errors if isinstance(exc, SweepError) else [str(exc)])
        else:
            errors.append(
                f"partial sweep (only {', '.join(sorted(only_kinds))}): the rest of the run's "
                "objects remain until the sweep is re-run with gwops stopped"
            )
        if errors:
            raise SweepError(errors, report)
        report.inventory_compared = compared
        return report


def single_line_key(token: str) -> str:
    """Compact a JSON service key onto one line for an env file; raw tokens must be one line."""
    try:
        return json.dumps(json.loads(token), separators=(",", ":"))
    except ValueError:
        if "\n" in token or "\r" in token:
            raise RigApiError("service account key is multi-line and not JSON") from None
        return token


# --- CLI -------------------------------------------------------------------------------


def recovery_command(state_path: Path) -> str:
    """The command that re-runs a sweep for an interrupted or failed run."""
    return f"python -m tests.integration.webapp.rig.tenant sweep --state {state_path}"


async def _sweep_cli(state_path: Path) -> int:
    from . import dockerops, seedgen, teardown
    from .redact import Redactor, RunLog

    env = guards.require_env()
    engine = await dockerops.require_local_engine()
    tenant = await RigTenant.resume(env, state_path, docker_endpoint=engine.endpoint)
    names = seedgen.build_names(tenant.run_id)
    log = RunLog(tenant.run_dir / "run.log", Redactor([env.api_key]))
    compose_vars = seedgen.compose_env(
        names,
        run_dir=tenant.run_dir,
        network=env.network,
        admin_port=1,
        gwops_image="unused",
    )
    log.event("docker-context", name=engine.context, endpoint=engine.endpoint)
    docker = dockerops.Docker(log, names, dockerops.COMPOSE_FILE, compose_vars)
    try:
        result = await teardown.stop_sweep_down(tenant, docker, log)
    finally:
        await tenant.aclose()
    for line in result.errors:
        print(f"ERROR {log.redactor.redact(line)}")
    if result.refused:
        print(f"REFUSED {log.redactor.redact(result.refused)}")
        return 2
    if not result.ok:
        return 1
    deleted = len(result.report.deleted) if result.report else 0
    gone = len(result.report.already_gone) if result.report else 0
    compared = result.report.inventory_compared if result.report else True
    verdict = (
        "inventory matches the pre-run state"
        if compared
        else "nothing to compare (the state has no pre-run inventory)"
    )
    print(f"swept run {tenant.run_id}: deleted {deleted}, already gone {gone}; {verdict}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point: `sweep --state <file>` deletes a run's recorded objects, checks inventory."""
    parser = argparse.ArgumentParser(prog="python -m tests.integration.webapp.rig.tenant")
    sub = parser.add_subparsers(dest="command", required=True)
    sweep = sub.add_parser("sweep", help="delete the objects recorded in a run-state file")
    sweep.add_argument("--state", type=Path, required=True, help="path to the run's state.json")
    args = parser.parse_args(argv)
    try:
        return asyncio.run(_sweep_cli(args.state))
    except (guards.GuardError, RigApiError, ValueError) as exc:
        print(f"REFUSED {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
