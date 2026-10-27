"""Unit tests for the live rig's tenant-safety guards and tenant planning; no tenant access."""

from __future__ import annotations

import dataclasses
import fnmatch
import json
import logging
import re
import sys
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import structlog.testing

from tests.integration.webapp.rig import dockerops, guards, seedgen, teardown, tenant
from tests.integration.webapp.rig.redact import Redactor, RunLog

API_KEY = "tgk_SECRET-key-0123456789abcdef"
ACCESS_TOKEN = "AT-secret-access-token-111"
REFRESH_TOKEN = "RT-secret-refresh-token-222"
PRIVATE_KEY = "SECRET-private-key-333"
SERVICE_KEY = json.dumps({"id": "key-1", "privateKey": PRIVATE_KEY}, indent=2)
SECRETS = (API_KEY, ACCESS_TOKEN, REFRESH_TOKEN, PRIVATE_KEY)

NETWORK = "acme"
REMOTE_NETWORK_ID = "UmVtb3RlTmV0d29yazox"
RUN_ID = "abc12345"
PREFIX = f"gwops-it-{RUN_ID}-"
GATEWAY_ADDRESS = seedgen.build_names(RUN_ID).gateway_address
LOCAL_ENDPOINT = "npipe:////./pipe/docker_engine"
GRAPHQL_URL = f"https://{NETWORK}.twingate.com/api/graphql/"

SWEEP_KIND_ORDER = (
    "service_account_key",
    "service_account",
    "web_app",
    "gateway",
    "connector",
    "ca",
    "ssh_ca",
)
COLLECTION_OF = {
    "service_account": "service_account",
    "web_app": "resource",
    "gateway": "gateway",
    "connector": "connector",
    "ca": "ca",
    "ssh_ca": "ca",
}
PRE_INVENTORY: tenant.Inventory = {
    "gateway": {"GW-B": "b.example.test"},
    "gateway_binding": {"GW-B": "x509=CA-B;ssh="},
    "resource": {"RES-B": "b-app"},
    "connector": {"CON-B": "b-connector"},
    "ca": {"CA-B": "b-ca"},
    "service_account": {"SA-B": "b-sa"},
}

Factory = Callable[[], httpx.Response | Exception]

_LIST_OPS = {
    "RigListGateways": ("gateway", ("remoteNetwork", "gateways"), "address"),
    "RigListResources": ("resource", ("remoteNetwork", "resources"), "name"),
    "RigListConnectors": ("connector", ("remoteNetwork", "connectors"), "name"),
    "RigListCertificateAuthorities": ("ca", ("certificateAuthorities",), "name"),
    "RigListServiceAccounts": ("service_account", ("serviceAccounts",), "name"),
}
_DELETE_OPS = {
    "RigDeleteServiceAccount": ("service_account", "serviceAccountDelete"),
    "RigDeleteResource": ("resource", "resourceDelete"),
    "RigDeleteGateway": ("gateway", "gatewayDelete"),
    "RigDeleteConnector": ("connector", "connectorDelete"),
    "RigDeleteX509CA": ("ca", "x509CertificateAuthorityDelete"),
    "RigDeleteSSHCA": ("ca", "sshCertificateAuthorityDelete"),
}
_GET_OPS = {
    "RigGetResource": ("resource", "resource", "name"),
    "RigGetConnector": ("connector", "connector", "name"),
    "RigGetGateway": ("gateway", "gateway", "address"),
    "RigGetCertificateAuthority": ("ca", "certificateAuthority", "name"),
    "RigGetServiceAccount": ("service_account", "serviceAccount", "name"),
}
X509_CA_NAME = f"gwops-x509-{GATEWAY_ADDRESS}"
SSH_CA_NAME = f"gwops-ssh-{GATEWAY_ADDRESS}"
_KEY_DELETE = "RigDeleteServiceAccountKey"
_KEY_REVOKE = "RigRevokeServiceAccountKey"
_OP_RE = re.compile(r"(?:query|mutation)\s+(\w+)")


# --- fake tenant -----------------------------------------------------------------------


def gql(data: dict[str, Any]) -> httpx.Response:
    """A 200 GraphQL response carrying `data`."""
    return httpx.Response(200, json={"data": data})


def status(code: int, text: str = "", headers: dict[str, str] | None = None) -> Factory:
    """A factory for a non-200 response."""
    return lambda: httpx.Response(code, text=text, headers=headers)


def mutation_failed(field: str, error: str) -> Factory:
    """A factory for a 200 response with ok=false."""
    return lambda: gql({field: {"ok": False, "error": error}})


def graphql_errors(*messages: str) -> Factory:
    """A factory for a 200 response carrying GraphQL errors."""
    return lambda: httpx.Response(
        200, json={"data": None, "errors": [{"message": m} for m in messages]}
    )


def success(field: str = "f") -> Factory:
    """A factory for an ok=true mutation response."""
    return lambda: gql({field: {"ok": True, "error": None}})


def raises(exc: Exception) -> Factory:
    """A factory that makes the transport raise `exc`."""
    return lambda: exc


@dataclass
class Call:
    """One GraphQL request seen by the fake tenant."""

    op: str
    variables: dict[str, Any]
    is_mutation: bool
    body: str


class FakeTenantApi:
    """In-memory Twingate GraphQL endpoint served through respx; records every request."""

    def __init__(self) -> None:
        self.collections: dict[str, dict[str, str]] = {
            kind: dict(entries)
            for kind, entries in PRE_INVENTORY.items()
            if kind != "gateway_binding"
        }
        self.gateway_cas: dict[str, tuple[str, str]] = {"GW-B": ("CA-B", "")}
        self.network_of: dict[str, str] = {}
        self.keys: dict[str, dict[str, str]] = {}
        self.revoke_override: dict[str, Factory] = {}
        self.calls: list[Call] = []
        self.page_size = 1000
        self.tokens: dict[str, str] = {"accessToken": ACCESS_TOKEN, "refreshToken": REFRESH_TOKEN}
        self.queued: dict[str, list[Factory]] = {}
        self.sticky: dict[str, Factory] = {}
        self.delete_override: dict[str, Factory] = {}
        self.missing_style = "mutation"
        self.grants: list[dict[str, Any]] = []
        self._counter = 0

    @property
    def mutations(self) -> list[Call]:
        """Every mutation request seen."""
        return [c for c in self.calls if c.is_mutation]

    @property
    def ops(self) -> list[str]:
        """Operation names in request order."""
        return [c.op for c in self.calls]

    @property
    def delete_ids(self) -> list[str]:
        """Ids sent to any delete mutation, in request order."""
        return [c.variables["id"] for c in self.calls if c.op in _DELETE_OPS or c.op == _KEY_DELETE]

    @property
    def revoke_ids(self) -> list[str]:
        """Ids sent to the key revoke mutation, in request order."""
        return [c.variables["id"] for c in self.calls if c.op == _KEY_REVOKE]

    def inventory(self) -> tenant.Inventory:
        """A snapshot in the rig's inventory shape."""
        snapshot = {kind: dict(entries) for kind, entries in self.collections.items()}
        snapshot["gateway_binding"] = {
            gid: "x509={};ssh={}".format(*self.gateway_cas.get(gid, ("", "")))
            for gid in self.collections["gateway"]
        }
        return snapshot

    def queue(self, op: str, *factories: Factory) -> None:
        """Answer the next requests for `op` with `factories`, then fall back to normal."""
        self.queued.setdefault(op, []).extend(factories)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        query, variables = body["query"], body["variables"]
        match = _OP_RE.search(query)
        op = match.group(1) if match else "anonymous"
        self.calls.append(Call(op, variables, query.lstrip().startswith("mutation"), str(body)))
        if self.queued.get(op):
            return _resolve(self.queued[op].pop(0)())
        if op in self.sticky:
            return _resolve(self.sticky[op]())
        return self._handle(op, variables)

    def _new_id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-RUN-{self._counter}"

    def _handle(self, op: str, variables: dict[str, Any]) -> httpx.Response:
        if op in _LIST_OPS:
            return self._list(op, variables)
        if op in _DELETE_OPS:
            return self._delete(op, variables["id"])
        if op in _GET_OPS:
            return self._get(op, variables["id"])
        if op in (_KEY_DELETE, _KEY_REVOKE, "RigGetServiceAccountKey", "RigListServiceAccountKeys"):
            return self._key_op(op, variables)
        if op == "RigCreateConnector":
            return self._create("connector", "connectorCreate", "CON", variables["name"])
        if op == "RigCreateServiceAccount":
            return self._create("service_account", "serviceAccountCreate", "SA", variables["name"])
        if op == "RigGenerateConnectorTokens":
            return gql(
                {
                    "connectorGenerateTokens": {
                        "ok": True,
                        "error": None,
                        "connectorTokens": self.tokens,
                    }
                }
            )
        if op == "RigCreateServiceAccountKey":
            entity = {"id": self._new_id("KEY")}
            self.keys[entity["id"]] = {
                "name": variables["name"],
                "sa": variables["serviceAccountId"],
                "status": "ACTIVE",
            }
            result = {"ok": True, "error": None, "entity": entity, "token": SERVICE_KEY}
            return gql({"serviceAccountKeyCreate": result})
        if op == "RigGrantAccess":
            self.grants.append(variables)
            return success("resourceAccessAdd")()  # type: ignore[return-value]
        return gql({})

    def _create(self, kind: str, field: str, prefix: str, name: str) -> httpx.Response:
        object_id = self._new_id(prefix)
        self.collections[kind][object_id] = name
        return gql({field: {"ok": True, "error": None, "entity": {"id": object_id}}})

    def _list(self, op: str, variables: dict[str, Any]) -> httpx.Response:
        kind, path, name_key = _LIST_OPS[op]
        entries = list(self.collections[kind].items())
        start = int(variables.get("after") or 0)
        page = entries[start : start + self.page_size]
        end = start + len(page)
        data: dict[str, Any] = {
            "pageInfo": {"hasNextPage": end < len(entries), "endCursor": str(end)},
            "edges": [{"node": self._node(kind, i, name_key, v)} for i, v in page],
        }
        for key in reversed(path):
            data = {key: data}
        return gql(data)

    def _key_op(self, op: str, variables: dict[str, Any]) -> httpx.Response:
        key_id = variables["id"]
        key = self.keys.get(key_id)
        if op == "RigListServiceAccountKeys":
            if key_id not in self.collections["service_account"]:
                return gql({"serviceAccount": None})
            nodes = [
                {"id": i, "name": k["name"], "status": k["status"]}
                for i, k in self.keys.items()
                if k["sa"] == key_id
            ]
            connection = {
                "pageInfo": {"hasNextPage": False, "endCursor": None},
                "edges": [{"node": n} for n in nodes],
            }
            return gql({"serviceAccount": {"keys": connection}})
        if op == "RigGetServiceAccountKey":
            if key is None:
                return gql({"serviceAccountKey": None})
            account = {
                "id": key["sa"],
                "name": self.collections["service_account"].get(key["sa"], "?"),
            }
            node = {"id": key_id, "name": key["name"], "status": key["status"]}
            return gql({"serviceAccountKey": {**node, "serviceAccount": account}})
        if op == _KEY_REVOKE:
            if key_id in self.revoke_override:
                return _resolve(self.revoke_override[key_id]())
            if key is None:
                return _resolve(
                    mutation_failed("serviceAccountKeyRevoke", f"Key {key_id} does not exist")()
                )
            key["status"] = "REVOKED"
            return gql({"serviceAccountKeyRevoke": {"ok": True, "error": None}})
        if key is None:
            message = f"Key {key_id} does not exist"
            return _resolve(mutation_failed("serviceAccountKeyDelete", message)())
        del self.keys[key_id]
        return gql({"serviceAccountKeyDelete": {"ok": True, "error": None}})

    def _get(self, op: str, object_id: str) -> httpx.Response:
        kind, field, name_key = _GET_OPS[op]
        name = self.collections[kind].get(object_id)
        if name is None:
            return gql({field: None})
        node: dict[str, Any] = {"id": object_id, name_key: name}
        if kind in ("resource", "connector", "gateway"):
            node["remoteNetwork"] = {"id": self.network_of.get(object_id, REMOTE_NETWORK_ID)}
        return gql({field: node})

    def _node(self, kind: str, object_id: str, name_key: str, value: str) -> dict[str, Any]:
        node: dict[str, Any] = {"id": object_id, name_key: value}
        if kind == "gateway":
            x509, ssh = self.gateway_cas.get(object_id, ("", ""))
            node["x509CA"] = {"id": x509} if x509 else None
            node["sshCA"] = {"id": ssh} if ssh else None
        return node

    def _delete(self, op: str, object_id: str) -> httpx.Response:
        kind, field = _DELETE_OPS[op]
        active = [k for k in self.keys.values() if k["sa"] == object_id and k["status"] == "ACTIVE"]
        if kind == "service_account" and active:
            name = self.collections[kind].get(object_id)
            error = f"{name} contains {len(active)} active keys that must be revoked first."
            return _resolve(mutation_failed(field, error)())
        if object_id in self.delete_override:
            return _resolve(self.delete_override[object_id]())
        if object_id in self.collections[kind]:
            del self.collections[kind][object_id]
            self.keys = {i: k for i, k in self.keys.items() if k["sa"] != object_id}
            return gql({field: {"ok": True, "error": None}})
        message = f"Resource with id {object_id} does not exist"
        if self.missing_style == "graphql":
            return _resolve(graphql_errors(message)())
        return _resolve(mutation_failed(field, message)())


def _resolve(result: httpx.Response | Exception) -> httpx.Response:
    if isinstance(result, Exception):
        raise result
    return result


class Sleeper:
    """Records requested sleeps instead of waiting."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


# --- fixtures --------------------------------------------------------------------------


def approved_environ(changes: dict[str, str | None] | None = None) -> dict[str, str]:
    """A valid rig environment with `changes` applied (None removes a variable)."""
    environ = {
        guards.ENV_API_KEY: API_KEY,
        guards.ENV_NETWORK: NETWORK,
        guards.ENV_REMOTE_NETWORK_ID: REMOTE_NETWORK_ID,
        guards.ENV_APPROVED_NETWORK: NETWORK,
        guards.ENV_APPROVED_REMOTE_NETWORK_ID: REMOTE_NETWORK_ID,
    }
    for name, value in (changes or {}).items():
        if value is None:
            environ.pop(name, None)
        else:
            environ[name] = value
    return environ


@pytest.fixture(autouse=True)
def _no_jitter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tenant.random, "uniform", lambda _low, _high: 0.0)


@pytest.fixture(autouse=True)
def _skip_tls_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Avoid loading the CA bundle for every mocked client; no request leaves the process."""
    real = httpx.AsyncClient
    monkeypatch.setattr(tenant.httpx, "AsyncClient", lambda **kw: real(verify=False, **kw))


@pytest.fixture
def api() -> Iterator[FakeTenantApi]:
    fake = FakeTenantApi()
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        router.post(GRAPHQL_URL).mock(side_effect=fake)
        yield fake


@pytest.fixture
def sleeper() -> Sleeper:
    return Sleeper()


@pytest.fixture
async def client(api: FakeTenantApi, sleeper: Sleeper) -> AsyncIterator[tenant.GraphQLClient]:
    graphql = tenant.GraphQLClient(NETWORK, API_KEY, sleep=sleeper)
    yield graphql
    await graphql.aclose()


@pytest.fixture
def env() -> guards.RigEnv:
    return guards.require_env(approved_environ())


@pytest.fixture
async def rig(
    api: FakeTenantApi, client: tenant.GraphQLClient, env: guards.RigEnv, tmp_path: Path
) -> tenant.RigTenant:
    started = await tenant.RigTenant.start(
        env, gateway_address=GATEWAY_ADDRESS, run_root=tmp_path, run_id=RUN_ID, client=client
    )
    api.calls.clear()
    return started


@pytest.fixture
async def populated(api: FakeTenantApi, rig: tenant.RigTenant) -> dict[str, list[str]]:
    """A rig after setup plus gwops-created objects, all recorded; returns ids by kind."""
    await rig.setup()
    gwops_created = [
        ("web_app", "RES-APP1", f"{PREFIX}app1"),
        ("web_app", "RES-APP2", f"{PREFIX}app2"),
        ("gateway", "GW-RUN", GATEWAY_ADDRESS),
        ("ca", "CA-X509", X509_CA_NAME),
        ("ssh_ca", "CA-SSH", SSH_CA_NAME),
    ]
    for kind, object_id, name in gwops_created:
        api.collections[COLLECTION_OF[kind]][object_id] = name
        rig.record(kind, object_id, name)
    api.calls.clear()
    return {kind: rig.state.ids(kind) for kind in tenant.RECORDABLE_KINDS}


def expected_delete_order(ids: dict[str, list[str]]) -> list[str]:
    """Recorded ids in the required sweep order."""
    return [object_id for kind in SWEEP_KIND_ORDER for object_id in ids[kind]]


# --- require_env -----------------------------------------------------------------------


class TestRequireEnv:
    """require_env and require_approved_pair."""

    def test_require_env_returns_the_validated_environment_for_the_approved_pair(self) -> None:
        """Happy path: every variable present and the approval matching."""
        env = guards.require_env(approved_environ())
        assert (env.api_key, env.network, env.remote_network_id) == (
            API_KEY,
            NETWORK,
            REMOTE_NETWORK_ID,
        )

    @pytest.mark.parametrize("name", guards.REQUIRED_ENV)
    @pytest.mark.parametrize("value", [None, "", " ", "   ", "\t", "\n", " \t\n "])
    def test_require_env_refuses_an_unset_empty_or_blank_variable(
        self, name: str, value: str | None
    ) -> None:
        """Each IT_* variable unset, empty or whitespace-only is an EnvError naming it."""
        with pytest.raises(guards.EnvError, match=name) as info:
            guards.require_env(approved_environ({name: value}))
        assert API_KEY not in str(info.value)

    def test_require_env_lists_every_missing_variable(self) -> None:
        """An empty environment reports every required name in one message."""
        with pytest.raises(guards.EnvError) as info:
            guards.require_env({})
        assert all(name in str(info.value) for name in guards.REQUIRED_ENV)

    @pytest.mark.parametrize(
        "bad_key",
        ["SECRETVALUE in two", " SECRETVALUE", "SECRETVALUE\n", "SECRET\tVALUE", "SECRETVALUEé"],
    )
    def test_require_env_refuses_an_api_key_with_whitespace_or_non_ascii(
        self, bad_key: str
    ) -> None:
        """A malformed key is refused without echoing any part of it."""
        with pytest.raises(guards.EnvError) as info:
            guards.require_env(approved_environ({guards.ENV_API_KEY: bad_key}))
        assert "SECRET" not in str(info.value)

    @pytest.mark.parametrize(
        "network",
        [
            "ACME",
            "acme ",
            " acme",
            "acme.twingate.com",
            "other",
            "acmex",
        ],
    )
    def test_require_env_refuses_a_network_that_is_not_exactly_the_approved_one(
        self, network: str
    ) -> None:
        """Case, whitespace and suffix variants of the network are all mismatches."""
        with pytest.raises(guards.ApprovedPairError, match="approved tenant"):
            guards.require_env(approved_environ({guards.ENV_NETWORK: network}))

    @pytest.mark.parametrize(
        "remote_id",
        [
            REMOTE_NETWORK_ID.lower(),
            REMOTE_NETWORK_ID + " ",
            "UmVtb3RlTmV0d29yazoy",
            "other",
        ],
    )
    def test_require_env_refuses_a_remote_network_id_that_is_not_exactly_the_approved_one(
        self, remote_id: str
    ) -> None:
        """Any remote-network id other than the approved one is a mismatch."""
        with pytest.raises(guards.ApprovedPairError, match="approved id"):
            guards.require_env(approved_environ({guards.ENV_REMOTE_NETWORK_ID: remote_id}))

    @pytest.mark.parametrize(
        "changes",
        [
            {guards.ENV_APPROVED_NETWORK: "other"},
            {guards.ENV_APPROVED_REMOTE_NETWORK_ID: "UmVtb3RlTmV0d29yazoy"},
            {guards.ENV_APPROVED_NETWORK: NETWORK.upper()},
            {guards.ENV_APPROVED_NETWORK: NETWORK + " "},
        ],
        ids=["network", "remote-id", "case", "whitespace"],
    )
    def test_require_env_refuses_an_approval_that_differs_from_the_configured_pair(
        self, changes: dict[str, str | None]
    ) -> None:
        """The operator's approval must equal the configured tenant and remote network exactly."""
        with pytest.raises(guards.ApprovedPairError, match="Refusing to run"):
            guards.require_env(approved_environ(changes))

    def test_a_rig_env_without_an_approval_is_refused(self) -> None:
        """A hand-built environment that carries no approval never matches."""
        with pytest.raises(guards.ApprovedPairError):
            guards.require_approved_pair(NETWORK, REMOTE_NETWORK_ID, "", "")

    def test_require_env_reports_both_mismatches_in_one_message(self) -> None:
        """A network and a remote-network mismatch are both named."""
        environ = approved_environ(
            {guards.ENV_NETWORK: "other", guards.ENV_REMOTE_NETWORK_ID: "also-other"}
        )
        with pytest.raises(guards.ApprovedPairError) as info:
            guards.require_env(environ)
        message = str(info.value)
        assert "'other'" in message and "'also-other'" in message

    @pytest.mark.parametrize(
        "variable", [guards.ENV_NETWORK, guards.ENV_REMOTE_NETWORK_ID], ids=["network", "remote-id"]
    )
    @pytest.mark.parametrize("template", ["{key}", "x{key}y"], ids=["whole", "embedded"])
    def test_require_env_never_echoes_the_api_key_when_it_lands_in_another_variable(
        self, variable: str, template: str
    ) -> None:
        """A key pasted into the wrong variable is masked in the refusal."""
        environ = approved_environ({variable: template.format(key=API_KEY)})
        with pytest.raises(guards.ApprovedPairError) as info:
            guards.require_env(environ)
        assert API_KEY not in str(info.value)
        assert "<masked>" in str(info.value)

    def test_require_env_truncates_a_long_mismatched_value(self) -> None:
        """An oversized wrong value is cut rather than dumped into the message."""
        with pytest.raises(guards.ApprovedPairError) as info:
            guards.require_env(approved_environ({guards.ENV_NETWORK: "n" * 500}))
        assert "n" * 65 not in str(info.value)

    def test_rig_env_repr_and_str_never_contain_the_api_key(self, env: guards.RigEnv) -> None:
        """The key stays out of repr, str and format output."""
        assert API_KEY not in repr(env)
        assert API_KEY not in str(env)
        assert API_KEY not in f"{env!r} {env}"
        assert env.api_key == API_KEY

    def test_rig_env_is_immutable(self, env: guards.RigEnv) -> None:
        """The validated pair cannot be altered after the check."""
        with pytest.raises(dataclasses.FrozenInstanceError):
            env.network = "other"  # type: ignore[misc]

    def test_require_env_reads_the_process_environment_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With no mapping argument the process environment is used."""
        for name, value in approved_environ().items():
            monkeypatch.setenv(name, value)
        assert guards.require_env().network == NETWORK
        monkeypatch.delenv(guards.ENV_API_KEY)
        with pytest.raises(guards.EnvError):
            guards.require_env()

    def test_require_approved_pair_masks_the_secret_it_is_given(self) -> None:
        """The secret argument is masked wherever it appears in a mismatched value."""
        with pytest.raises(guards.ApprovedPairError) as info:
            guards.require_approved_pair(
                API_KEY, REMOTE_NETWORK_ID, NETWORK, REMOTE_NETWORK_ID, secret=API_KEY
            )
        assert API_KEY not in str(info.value)

    @pytest.mark.parametrize(
        "error",
        [
            guards.EnvError,
            guards.ApprovedPairError,
            guards.GatewayAddressInUseError,
            guards.UnrecordedIdError,
            guards.PreexistingIdError,
        ],
    )
    def test_every_guard_error_is_a_guard_error(self, error: type[Exception]) -> None:
        """The CLI catches GuardError, so every refusal must derive from it."""
        assert issubclass(error, guards.GuardError)


# --- check_gateway_address_free --------------------------------------------------------


class TestGatewayAddressGuard:
    """check_gateway_address_free."""

    @pytest.mark.parametrize(
        "existing",
        ["gw.example.com", "GW.EXAMPLE.COM", "  gw.example.com\t", "Gw.Example.Com"],
    )
    @pytest.mark.parametrize("wanted", ["gw.example.com", " GW.Example.COM ", "GW.EXAMPLE.COM"])
    def test_existing_gateway_at_the_address_is_refused_whatever_the_case_or_padding(
        self, existing: str, wanted: str
    ) -> None:
        """Case and whitespace variants of an existing address all count as taken."""
        with pytest.raises(guards.GatewayAddressInUseError, match="GW-1"):
            guards.check_gateway_address_free(
                [("GW-0", "other.example.com"), ("GW-1", existing)],
                wanted,
                remote_network_id=REMOTE_NETWORK_ID,
            )

    def test_every_clashing_gateway_is_named(self) -> None:
        """All gateways using the address are listed."""
        with pytest.raises(guards.GatewayAddressInUseError) as info:
            guards.check_gateway_address_free(
                [("GW-1", "a.test"), ("GW-2", "A.TEST")], "a.test", remote_network_id="RN"
            )
        assert "GW-1" in str(info.value) and "GW-2" in str(info.value)

    @pytest.mark.parametrize(
        "gateways",
        [[], [("GW-1", "other.example.com")], [("GW-1", "gw.example.com.evil.test")]],
        ids=["none", "other-address", "prefix-only"],
    )
    def test_a_free_address_passes(self, gateways: list[tuple[str, str]]) -> None:
        """No gateway with exactly this address means the check passes."""
        guards.check_gateway_address_free(gateways, "gw.example.com", remote_network_id="RN")

    @pytest.mark.parametrize("wanted", ["", "   ", "\t"])
    def test_an_empty_run_address_is_refused(self, wanted: str) -> None:
        """A blank address could match any blank gateway and is refused outright."""
        with pytest.raises(guards.GatewayAddressInUseError, match="empty"):
            guards.check_gateway_address_free([], wanted, remote_network_id="RN")


# --- run ids, names, recorded ids ------------------------------------------------------


class TestIdsAndNames:
    """run ids, prefixes and the recorded-id guards."""

    def test_new_run_id_is_a_valid_unique_run_id(self) -> None:
        """Generated ids satisfy run_prefix and differ between calls."""
        first, second = guards.new_run_id(), guards.new_run_id()
        assert guards.run_prefix(first) == f"gwops-it-{first}-"
        assert first != second

    @pytest.mark.parametrize(
        "run_id",
        ["", "abc", "ABC12345", "abc-1234", "abc 1234", "abc12345\n", "a" * 17, "abc12345/"],
    )
    def test_run_prefix_refuses_an_invalid_run_id(self, run_id: str) -> None:
        """Only 6-16 lowercase letters and digits form a run id."""
        with pytest.raises(guards.GuardError):
            guards.run_prefix(run_id)

    def test_require_prefixed_accepts_only_names_with_the_run_prefix(self) -> None:
        """Names without the run prefix are never created."""
        assert guards.require_prefixed(f"{PREFIX}app", PREFIX) == f"{PREFIX}app"
        for name in ["app", "gwops-it-other123-app", PREFIX[:-1], f" {PREFIX}app"]:
            with pytest.raises(guards.GuardError):
                guards.require_prefixed(name, PREFIX)

    def test_require_not_preexisting_refuses_ids_from_the_pre_run_inventory(self) -> None:
        """An id that existed before the run is never recorded as run-created."""
        guards.require_not_preexisting("web_app", "RES-NEW", {"RES-B"})
        with pytest.raises(guards.PreexistingIdError, match="RES-B"):
            guards.require_not_preexisting("web_app", "RES-B", {"RES-B"})

    def test_require_recorded_returns_the_ids_when_all_are_recorded(self) -> None:
        """Order is preserved and a one-shot iterable is materialised once."""
        ids = guards.require_recorded("web_app", (i for i in ["B", "A"]), {"A", "B", "C"})
        assert ids == ["B", "A"]

    def test_require_recorded_refuses_and_names_every_unrecorded_id(self) -> None:
        """One foreign id among valid ones refuses the whole batch."""
        with pytest.raises(guards.UnrecordedIdError) as info:
            guards.require_recorded("web_app", ["A", "X", "Y"], {"A"})
        assert "X" in str(info.value) and "Y" in str(info.value)

    def test_require_same_pair_refuses_a_state_from_another_network(
        self, env: guards.RigEnv
    ) -> None:
        """A state file for a different network or remote network is not swept."""
        guards.require_same_pair(NETWORK, REMOTE_NETWORK_ID, env)
        with pytest.raises(guards.ApprovedPairError):
            guards.require_same_pair("other", REMOTE_NETWORK_ID, env)
        with pytest.raises(guards.ApprovedPairError):
            guards.require_same_pair(NETWORK, "other", env)


# --- RunState --------------------------------------------------------------------------


def fresh_state(inventory: tenant.Inventory | None = None) -> tenant.RunState:
    """A RunState with the standard pre-run inventory."""
    return tenant.RunState(
        RUN_ID,
        NETWORK,
        REMOTE_NETWORK_ID,
        GATEWAY_ADDRESS,
        pre_inventory=PRE_INVENTORY if inventory is None else inventory,
    )


class TestRunState:
    """RunState.record and persistence."""

    def test_record_refuses_before_the_pre_run_inventory_exists(self) -> None:
        """Nothing is recorded until the pre-run inventory is stored."""
        state = tenant.RunState(RUN_ID, NETWORK, REMOTE_NETWORK_ID, GATEWAY_ADDRESS)
        with pytest.raises(guards.GuardError, match="pre-run inventory"):
            state.record("web_app", "RES-1")
        assert state.created == []

    @pytest.mark.parametrize(
        ("kind", "object_id"),
        [
            ("web_app", "RES-B"),
            ("gateway", "GW-B"),
            ("connector", "CON-B"),
            ("ca", "CA-B"),
            ("ssh_ca", "CA-B"),
            ("service_account", "SA-B"),
            ("web_app", "SA-B"),
        ],
    )
    def test_record_refuses_an_id_from_the_pre_run_inventory(
        self, kind: str, object_id: str
    ) -> None:
        """Pre-existing ids of any kind can never become sweepable."""
        state = fresh_state()
        with pytest.raises(guards.PreexistingIdError):
            state.record(kind, object_id)
        assert state.created == []

    @pytest.mark.parametrize("kind", ["group", "security_policy", "resource", "", "WEB_APP"])
    def test_record_refuses_kinds_the_rig_never_creates(self, kind: str) -> None:
        """Groups, policies and unknown kinds are not recordable."""
        with pytest.raises(guards.GuardError, match="unknown kind"):
            fresh_state().record(kind, "ID-1")

    def test_record_refuses_an_empty_id(self) -> None:
        """An empty id would make the sweep act on nothing meaningful."""
        with pytest.raises(guards.GuardError, match="empty"):
            fresh_state().record("web_app", "")

    def test_recording_the_same_object_twice_keeps_one_entry(self) -> None:
        """A repeated record is idempotent."""
        state = fresh_state()
        state.record("web_app", "RES-1", f"{PREFIX}n")
        state.record("web_app", "RES-1", f"{PREFIX}n")
        assert state.ids("web_app") == ["RES-1"]

    def test_group_and_policy_kinds_are_not_recordable_or_sweepable(self) -> None:
        """The kind list never includes groups, policies or bare resources."""
        assert not {"group", "security_policy", "resource"} & set(tenant.RECORDABLE_KINDS)

    async def test_tenant_record_persists_the_state_file_immediately(
        self, rig: tenant.RigTenant
    ) -> None:
        """Each record is on disk before the next call, so a crash still sweeps it."""
        rig.record("web_app", "RES-NEW", f"{PREFIX}app")
        reloaded = tenant.load_state(rig.state_path)
        assert reloaded.ids("web_app") == ["RES-NEW"]

    def test_state_round_trips_through_json(self, tmp_path: Path) -> None:
        """to_dict/from_dict and save/load preserve everything."""
        state = fresh_state()
        state.record("web_app", "RES-1", f"{PREFIX}n1")
        state.record("service_account_key", "KEY-1", f"{PREFIX}k")
        state.mark_deleted(state.created[0])
        path = tmp_path / "state.json"
        tenant.save_state(path, state)
        assert tenant.load_state(path) == state
        assert not (tmp_path / "state.json.tmp").exists()

    @pytest.mark.parametrize(
        "raw",
        [
            {},
            {"created": [], "deleted": []},
            {
                "run_id": "r",
                "network": "n",
                "remote_network_id": "x",
                "gateway_address": "g",
                "created": [{"kind": "group", "id": "G"}],
                "deleted": [],
                "pre_inventory": None,
            },
            {
                "run_id": "r",
                "network": "n",
                "remote_network_id": "x",
                "gateway_address": "g",
                "created": [{"kind": "web_app", "id": ""}],
                "deleted": [],
                "pre_inventory": None,
            },
            {
                "run_id": "r",
                "network": "n",
                "remote_network_id": "x",
                "gateway_address": "g",
                "created": ["web_app"],
                "deleted": [],
                "pre_inventory": None,
            },
            {
                "run_id": "r",
                "network": "n",
                "remote_network_id": "x",
                "gateway_address": "g",
                "created": [],
                "deleted": [],
                "pre_inventory": {"bogus": {}},
            },
        ],
    )
    def test_malformed_state_is_refused_with_a_value_error(self, raw: dict[str, Any]) -> None:
        """A damaged state file is rejected rather than half-loaded."""
        with pytest.raises(ValueError):
            tenant.RunState.from_dict(raw)

    @pytest.mark.parametrize("content", ["not json", "[]", "", '"str"'])
    def test_load_state_refuses_unreadable_or_non_object_files(
        self, tmp_path: Path, content: str
    ) -> None:
        """Garbage on disk is a ValueError."""
        path = tmp_path / "state.json"
        path.write_text(content, encoding="utf-8")
        with pytest.raises(ValueError):
            tenant.load_state(path)

    def test_load_state_refuses_a_missing_file(self, tmp_path: Path) -> None:
        """A missing state file is a ValueError, not an OSError."""
        with pytest.raises(ValueError, match="cannot read run state"):
            tenant.load_state(tmp_path / "absent.json")


# --- inventory -------------------------------------------------------------------------


class TestInventory:
    """diff_inventory, select_new and load_inventory."""

    def test_equal_inventories_have_no_differences(self) -> None:
        """Identical inventories diff to an empty list."""
        assert (
            tenant.diff_inventory(PRE_INVENTORY, {k: dict(v) for k, v in PRE_INVENTORY.items()})
            == []
        )

    def test_missing_kinds_are_treated_as_empty(self) -> None:
        """An inventory without a kind equals one with that kind empty."""
        assert tenant.diff_inventory({}, {"gateway": {}}) == []

    def test_added_removed_and_renamed_objects_are_all_reported(self) -> None:
        """Every kind of difference is reported with its id and name."""
        post = {k: dict(v) for k, v in PRE_INVENTORY.items()}
        post["resource"]["RES-NEW"] = "new-app"
        del post["connector"]["CON-B"]
        post["ca"]["CA-B"] = "renamed"
        assert sorted(tenant.diff_inventory(PRE_INVENTORY, post)) == [
            "added resource RES-NEW ('new-app')",
            "removed connector CON-B ('b-connector')",
            "renamed ca CA-B ('b-ca' -> 'renamed')",
        ]

    def test_select_new_requires_a_filter(self) -> None:
        """Without a name or prefix no object can be picked."""
        with pytest.raises(ValueError, match="bystander"):
            tenant.select_new(PRE_INVENTORY, PRE_INVENTORY, "web_app")

    def test_select_new_rejects_an_unknown_kind(self) -> None:
        """Unknown kinds are a programming error."""
        with pytest.raises(ValueError, match="unknown kind"):
            tenant.select_new(PRE_INVENTORY, PRE_INVENTORY, "group", name="x")

    def test_select_new_never_picks_a_pre_existing_object_even_with_a_matching_name(self) -> None:
        """A bystander whose name carries the run prefix is still excluded."""
        pre = {"resource": {"RES-OLD": f"{PREFIX}old"}}
        current = {"resource": {"RES-OLD": f"{PREFIX}old", "RES-1": f"{PREFIX}a", "RES-2": "other"}}
        assert tenant.select_new(pre, current, "web_app", name_prefix=PREFIX) == [
            ("RES-1", f"{PREFIX}a")
        ]

    def test_select_new_maps_both_ca_kinds_to_the_ca_inventory(self) -> None:
        """ca and ssh_ca both search the certificate authorities."""
        current = {"ca": {"CA-1": f"{PREFIX}ca"}}
        assert tenant.select_new({}, current, "ca", name=f"{PREFIX}ca") == [("CA-1", f"{PREFIX}ca")]
        assert tenant.select_new({}, current, "ssh_ca", name=f"{PREFIX}ca") == [
            ("CA-1", f"{PREFIX}ca")
        ]

    @pytest.mark.parametrize(
        "raw",
        ["x", [], {"bogus": {}}, {"gateway": []}, {"gateway": {"a": 1}}, {"gateway": {1: "a"}}],
    )
    def test_load_inventory_refuses_malformed_input(self, raw: object) -> None:
        """Only known kinds mapping string ids to string names are accepted."""
        with pytest.raises(ValueError):
            tenant.load_inventory(raw)

    def test_parse_entries_refuses_empty_ids_and_missing_names(self) -> None:
        """A node without an id or a string name is an API error, not a skipped row."""
        assert tenant.parse_entries([{"id": "A", "name": "n"}], "name", "op") == {"A": "n"}
        for node in [
            {"id": "", "name": "n"},
            {"id": "A"},
            {"id": "A", "name": None},
            {"name": "n"},
        ]:
            with pytest.raises(tenant.RigApiError):
                tenant.parse_entries([node], "name", "op")

    async def test_fetch_inventory_pages_through_every_connection(
        self, api: FakeTenantApi, client: tenant.GraphQLClient
    ) -> None:
        """A multi-page listing is read completely."""
        api.page_size = 1
        for index in range(3):
            api.collections["resource"][f"RES-{index}"] = f"app{index}"
            api.collections["gateway"][f"GW-{index}"] = f"g{index}.test"
        inventory = await tenant.fetch_inventory(client, REMOTE_NETWORK_ID)
        assert inventory == api.inventory()
        assert api.ops.count("RigListResources") == 4

    @pytest.mark.parametrize(
        ("page", "match"),
        [
            ({"hasNextPage": True, "endCursor": None}, "no new cursor"),
            ({"hasNextPage": True, "endCursor": "same"}, "no new cursor"),
        ],
    )
    async def test_paginate_refuses_a_page_that_does_not_advance(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, page: dict[str, Any], match: str
    ) -> None:
        """A stuck cursor is an error rather than a silently truncated or endless listing."""

        def stuck() -> httpx.Response:
            return gql({"c": {"pageInfo": page, "edges": []}})

        api.sticky["RigProbe"] = stuck
        with pytest.raises(tenant.RigApiError, match=match):
            await client.paginate("query RigProbe($first: Int!, $after: String) { c }", {}, ("c",))
        assert len(api.calls) <= 2

    async def test_paginate_refuses_a_null_connection(
        self, api: FakeTenantApi, client: tenant.GraphQLClient
    ) -> None:
        """A null connection is an error, not an empty listing."""
        api.queue("RigProbe", lambda: gql({"c": None}))
        with pytest.raises(tenant.RigApiError, match="null or missing"):
            await client.paginate("query RigProbe($first: Int!, $after: String) { c }", {}, ("c",))


# --- throttle hints (pure) -------------------------------------------------------------

_NOW = datetime(2026, 10, 21, 7, 28, 0, tzinfo=UTC)


class TestThrottleParsing:
    """parse_retry_after, parse_body_hint, throttle_delay and backoff_delay."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("0", 0.0),
            ("7", 7.0),
            ("  30 ", 30.0),
            ("Wed, 21 Oct 2026 07:28:30 GMT", 30.0),
            ("Wed, 21 Oct 2026 07:00:00 GMT", 0.0),
            ("Wed, 21 Oct 2026 07:28:30 -0000", 30.0),
        ],
    )
    def test_parse_retry_after_reads_delta_seconds_and_http_dates(
        self, value: str, expected: float
    ) -> None:
        """Both Retry-After forms yield non-negative seconds."""
        assert tenant.parse_retry_after(value, _NOW) == expected

    @pytest.mark.parametrize(
        "value", ["", "soon", "-5", "5.5", "1e3", "12345678901", "Wed, 99 Foo 2026"]
    )
    def test_parse_retry_after_returns_none_for_unusable_values(self, value: str) -> None:
        """Unparseable headers fall through to the next hint."""
        assert tenant.parse_retry_after(value, _NOW) is None

    @pytest.mark.parametrize(
        ("body", "expected"),
        [
            ("Request was throttled. Expected available in 12 seconds.", 12.0),
            ('{"detail": "expected AVAILABLE in 1 second"}', 1.0),
            ("Expected available in 0.5 seconds", 0.5),
        ],
    )
    def test_parse_body_hint_reads_the_expected_available_phrase(
        self, body: str, expected: float
    ) -> None:
        """The throttle hint in a 429 body is parsed."""
        assert tenant.parse_body_hint(body) == expected

    @pytest.mark.parametrize(
        "body", ["", "throttled", "available in 12 seconds", "Expected available in x seconds"]
    )
    def test_parse_body_hint_returns_none_without_the_phrase(self, body: str) -> None:
        """No phrase means no hint."""
        assert tenant.parse_body_hint(body) is None

    @pytest.mark.parametrize(
        ("retry_after", "body", "attempt", "expected"),
        [
            ("7", "", 1, 7.0),
            ("7", "Expected available in 99 seconds", 1, 7.0),
            ("soon", "Expected available in 3 seconds", 1, 3.0),
            (None, "Expected available in 12 seconds", 5, 12.0),
            ("", "Expected available in 12 seconds", 5, 12.0),
            ("9999", "", 1, 60.0),
            (None, "", 1, 2.0),
            (None, "", 3, 8.0),
            (None, "", 20, 30.0),
        ],
    )
    def test_throttle_delay_prefers_header_then_body_then_backoff_and_caps(
        self, retry_after: str | None, body: str, attempt: int, expected: float
    ) -> None:
        """Hints win over backoff, hints are capped at 60 s and backoff at 30 s."""
        assert tenant.throttle_delay(retry_after, body, attempt, now=_NOW, jitter=0.0) == expected

    def test_throttle_delay_adds_jitter_on_top_of_the_hint(self) -> None:
        """Jitter is added to, not substituted for, the server hint."""
        assert tenant.throttle_delay("5", "", 1, now=_NOW, jitter=0.25) == 5.25

    def test_backoff_delay_doubles_from_one_second_and_caps_at_thirty(self) -> None:
        """5xx backoff: 1, 2, 4, ... capped at 30."""
        assert [tenant.backoff_delay(n, 0.0) for n in (1, 2, 3, 6, 7, 20)] == [
            1.0,
            2.0,
            4.0,
            30.0,
            30.0,
            30.0,
        ]


# --- GraphQLClient over respx ----------------------------------------------------------

_PROBE_QUERY = "query RigProbe { x }"
_PROBE_MUTATION = "mutation RigProbe($a: Int) { f(a: $a) { ok error } }"


class TestGraphQLClient:
    """429, 5xx, auth and redaction behaviour of the rig's client."""

    @pytest.mark.parametrize(
        ("headers", "body", "expected"),
        [
            ({"Retry-After": "7"}, "", 7.0),
            ({"Retry-After": "7"}, "Expected available in 99 seconds", 7.0),
            ({}, "Request was throttled. Expected available in 12 seconds.", 12.0),
            ({"Retry-After": "soon"}, "Expected available in 3 seconds", 3.0),
            ({"Retry-After": "9999"}, "", 60.0),
            ({}, "", 2.0),
        ],
    )
    async def test_429_is_retried_after_the_server_hint_even_for_a_mutation(
        self,
        api: FakeTenantApi,
        client: tenant.GraphQLClient,
        sleeper: Sleeper,
        headers: dict[str, str],
        body: str,
        expected: float,
    ) -> None:
        """A throttled mutation was not processed, so it is retried after the hinted wait."""
        api.queue("RigProbe", status(429, body, headers), success())
        result = await client.mutate(_PROBE_MUTATION, {"a": 1}, "f")
        assert result["ok"] is True
        assert api.ops == ["RigProbe", "RigProbe"]
        assert sleeper.delays == [expected]

    async def test_repeated_429_without_a_hint_backs_off_exponentially(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, sleeper: Sleeper
    ) -> None:
        """Hintless 429s wait 2, 4, 8 seconds."""
        api.queue("RigProbe", status(429), status(429), status(429), success())
        await client.mutate(_PROBE_MUTATION, {}, "f")
        assert sleeper.delays == [2.0, 4.0, 8.0]

    async def test_429_forever_gives_up_after_eight_attempts(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, sleeper: Sleeper
    ) -> None:
        """Rate limiting is bounded and ends in an error, not a hang."""
        api.sticky["RigProbe"] = status(429, headers={"Retry-After": "1"})
        with pytest.raises(tenant.RigApiError, match="rate-limited after 8 attempts"):
            await client.execute(_PROBE_QUERY, {})
        assert len(api.calls) == 8
        assert len(sleeper.delays) == 7

    @pytest.mark.parametrize("code", [500, 502, 503, 504])
    async def test_a_mutation_is_not_retried_on_5xx(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, sleeper: Sleeper, code: int
    ) -> None:
        """A create may have happened server-side, so a 5xx is never retried."""
        api.sticky["RigProbe"] = status(code)
        with pytest.raises(tenant.RigApiError, match=rf"HTTP {code}.*not retried"):
            await client.mutate(_PROBE_MUTATION, {}, "f")
        assert len(api.calls) == 1
        assert sleeper.delays == []

    async def test_an_idempotent_query_is_retried_on_5xx(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, sleeper: Sleeper
    ) -> None:
        """Reads recover from a transient 5xx."""
        api.queue("RigProbe", status(503), lambda: gql({"x": 1}))
        assert await client.execute(_PROBE_QUERY, {}) == {"x": 1}
        assert sleeper.delays == [1.0]

    async def test_an_idempotent_query_gives_up_after_eight_5xx_attempts(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, sleeper: Sleeper
    ) -> None:
        """Persistent 5xx on a read ends in an error after bounded backoff."""
        api.sticky["RigProbe"] = status(500)
        with pytest.raises(tenant.RigApiError, match="HTTP 500"):
            await client.execute(_PROBE_QUERY, {})
        assert len(api.calls) == 8
        assert sleeper.delays == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0]

    @pytest.mark.parametrize("exc", [httpx.ConnectError("boom"), httpx.ReadTimeout("slow")])
    async def test_a_mutation_is_not_retried_after_a_transport_error(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, sleeper: Sleeper, exc: Exception
    ) -> None:
        """A lost response to a mutation leaves the outcome unknown, so it is not retried."""
        api.sticky["RigProbe"] = raises(exc)
        with pytest.raises(tenant.RigApiError, match="outcome unknown, not retried"):
            await client.mutate(_PROBE_MUTATION, {}, "f")
        assert len(api.calls) == 1
        assert sleeper.delays == []

    async def test_a_query_is_retried_after_a_transport_error(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, sleeper: Sleeper
    ) -> None:
        """Reads recover from a dropped connection."""
        api.queue("RigProbe", raises(httpx.ConnectError("boom")), lambda: gql({"x": 1}))
        assert await client.execute(_PROBE_QUERY, {}) == {"x": 1}
        assert sleeper.delays == [1.0]

    async def test_a_transport_error_message_never_contains_the_api_key(
        self, api: FakeTenantApi, client: tenant.GraphQLClient
    ) -> None:
        """Exception text from the transport is redacted."""
        api.sticky["RigProbe"] = raises(httpx.ConnectError(f"refused for {API_KEY}"))
        with pytest.raises(tenant.RigApiError) as info:
            await client.mutate(_PROBE_MUTATION, {}, "f")
        assert API_KEY not in str(info.value)
        assert "***" in str(info.value)

    @pytest.mark.parametrize("code", [401, 403])
    async def test_auth_failures_are_not_retried_and_carry_no_body(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, sleeper: Sleeper, code: int
    ) -> None:
        """401/403 raise RigAuthError immediately."""
        api.sticky["RigProbe"] = status(code, f"denied {API_KEY}")
        with pytest.raises(tenant.RigAuthError) as info:
            await client.execute(_PROBE_QUERY, {})
        assert API_KEY not in str(info.value)
        assert len(api.calls) == 1
        assert sleeper.delays == []

    async def test_a_4xx_is_not_retried_and_its_body_is_redacted_and_capped(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, sleeper: Sleeper
    ) -> None:
        """Client errors fail fast with a bounded, key-free excerpt."""
        api.sticky["RigProbe"] = status(400, f"{API_KEY} " + "z" * 1000)
        with pytest.raises(tenant.RigApiError) as info:
            await client.execute(_PROBE_QUERY, {})
        assert API_KEY not in str(info.value)
        assert "z" * 301 not in str(info.value)
        assert len(api.calls) == 1

    async def test_graphql_errors_in_a_200_are_raised_and_redacted(
        self, api: FakeTenantApi, client: tenant.GraphQLClient
    ) -> None:
        """A 200 with errors is never treated as success."""
        api.queue("RigProbe", graphql_errors(f"bad {API_KEY}", "second"))
        with pytest.raises(tenant.RigGraphQLError) as info:
            await client.execute(_PROBE_QUERY, {})
        assert API_KEY not in str(info.value)
        assert len(info.value.messages) == 2

    @pytest.mark.parametrize(
        "factory",
        [
            lambda: httpx.Response(200, text="<html>"),
            lambda: httpx.Response(200, json=["not", "an", "object"]),
            lambda: httpx.Response(200, json={"data": ["x"]}),
        ],
        ids=["non-json", "non-object", "non-object-data"],
    )
    async def test_malformed_200_bodies_are_errors(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, factory: Factory
    ) -> None:
        """Unexpected body shapes raise rather than yielding empty data."""
        api.queue("RigProbe", factory)
        with pytest.raises(tenant.RigApiError):
            await client.execute(_PROBE_QUERY, {})

    async def test_mutate_raises_on_ok_false_and_on_a_missing_result(
        self, api: FakeTenantApi, client: tenant.GraphQLClient
    ) -> None:
        """ok=false and a result without ok are both failures."""
        api.queue("RigProbe", mutation_failed("f", f"nope {API_KEY}"), lambda: gql({"f": {}}))
        with pytest.raises(tenant.RigMutationError) as info:
            await client.mutate(_PROBE_MUTATION, {}, "f")
        assert API_KEY not in str(info.value) and info.value.error.startswith("nope")
        with pytest.raises(tenant.RigApiError, match="malformed"):
            await client.mutate(_PROBE_MUTATION, {}, "f")

    async def test_requests_carry_the_key_only_in_the_header(
        self, api: FakeTenantApi, client: tenant.GraphQLClient
    ) -> None:
        """The key is sent as X-API-KEY and never inside the request body."""
        await client.execute(_PROBE_QUERY, {"v": 1})
        assert API_KEY not in api.calls[0].body


# --- RigTenant.start -------------------------------------------------------------------


class TestStart:
    """RigTenant.start guards."""

    @pytest.mark.parametrize(
        "variant",
        [lambda a: a, str.upper, lambda a: f"  {a}\t", lambda a: a.upper().center(len(a) + 6)],
        ids=["exact", "upper", "padded", "upper-padded"],
    )
    async def test_start_aborts_before_any_mutation_when_the_gateway_address_is_taken(
        self,
        api: FakeTenantApi,
        client: tenant.GraphQLClient,
        env: guards.RigEnv,
        tmp_path: Path,
        variant: Callable[[str], str],
    ) -> None:
        """An existing gateway at the address stops the run with zero mutation requests."""
        api.collections["gateway"]["GW-TAKEN"] = variant(GATEWAY_ADDRESS)
        with pytest.raises(guards.GatewayAddressInUseError, match="GW-TAKEN"):
            await tenant.RigTenant.start(
                env,
                gateway_address=GATEWAY_ADDRESS,
                run_root=tmp_path,
                run_id=RUN_ID,
                client=client,
            )
        assert api.mutations == []
        assert api.ops == ["RigListGateways"]
        state = tenant.load_state(tmp_path / RUN_ID / tenant.STATE_FILE)
        assert state.created == [] and state.pre_inventory is None
        with pytest.raises(RuntimeError):
            await client.execute(_PROBE_QUERY, {})

    async def test_start_finds_a_clashing_gateway_on_a_later_page(
        self,
        api: FakeTenantApi,
        client: tenant.GraphQLClient,
        env: guards.RigEnv,
        tmp_path: Path,
    ) -> None:
        """The adoption guard reads every page of gateways."""
        api.page_size = 1
        api.collections["gateway"]["GW-X"] = "x.test"
        api.collections["gateway"]["GW-LATE"] = GATEWAY_ADDRESS
        with pytest.raises(guards.GatewayAddressInUseError, match="GW-LATE"):
            await tenant.RigTenant.start(
                env,
                gateway_address=GATEWAY_ADDRESS,
                run_root=tmp_path,
                run_id=RUN_ID,
                client=client,
            )
        assert api.ops.count("RigListGateways") == 3
        assert api.mutations == []

    @pytest.mark.parametrize(
        "factory",
        [
            lambda: gql({"remoteNetwork": None}),
            graphql_errors("Not authorized"),
            status(401),
            status(500),
        ],
        ids=["null-remote-network", "graphql-error", "auth", "server-error"],
    )
    async def test_start_never_treats_an_unreadable_gateway_listing_as_free(
        self,
        api: FakeTenantApi,
        client: tenant.GraphQLClient,
        env: guards.RigEnv,
        tmp_path: Path,
        factory: Factory,
    ) -> None:
        """A failed or null listing aborts the run instead of passing the guard."""
        api.sticky["RigListGateways"] = factory
        with pytest.raises(tenant.RigApiError):
            await tenant.RigTenant.start(
                env,
                gateway_address=GATEWAY_ADDRESS,
                run_root=tmp_path,
                run_id=RUN_ID,
                client=client,
            )
        assert api.mutations == []
        assert "RigListResources" not in api.ops

    @pytest.mark.parametrize(
        ("network", "remote_id"),
        [
            ("other", REMOTE_NETWORK_ID),
            (NETWORK, "other"),
            ("other", "other"),
            (NETWORK.upper(), REMOTE_NETWORK_ID),
        ],
    )
    async def test_start_refuses_a_mismatched_pair_before_any_http_or_file(
        self, api: FakeTenantApi, tmp_path: Path, network: str, remote_id: str
    ) -> None:
        """Even a hand-built RigEnv cannot reach the tenant with a wrong pair."""
        bad = guards.RigEnv(
            api_key=API_KEY,
            network=network,
            remote_network_id=remote_id,
            approved_network=NETWORK,
            approved_remote_network_id=REMOTE_NETWORK_ID,
        )
        with pytest.raises(guards.ApprovedPairError):
            await tenant.RigTenant.start(
                bad, gateway_address=GATEWAY_ADDRESS, run_root=tmp_path, run_id=RUN_ID
            )
        assert api.calls == []
        assert list(tmp_path.iterdir()) == []

    async def test_start_refuses_an_invalid_run_id_before_any_http_or_file(
        self, api: FakeTenantApi, env: guards.RigEnv, tmp_path: Path
    ) -> None:
        """A malformed run id never reaches the tenant or the disk."""
        with pytest.raises(guards.GuardError):
            await tenant.RigTenant.start(
                env, gateway_address=GATEWAY_ADDRESS, run_root=tmp_path, run_id="BAD ID"
            )
        assert api.calls == []
        assert list(tmp_path.iterdir()) == []

    async def test_start_refuses_to_reuse_an_existing_run_directory(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, env: guards.RigEnv, tmp_path: Path
    ) -> None:
        """A second start with the same run id cannot overwrite the first run's state."""
        (tmp_path / RUN_ID).mkdir()
        with pytest.raises(FileExistsError):
            await tenant.RigTenant.start(
                env,
                gateway_address=GATEWAY_ADDRESS,
                run_root=tmp_path,
                run_id=RUN_ID,
                client=client,
            )
        assert api.calls == []

    async def test_start_with_a_free_address_only_reads_and_stores_the_pre_run_inventory(
        self,
        api: FakeTenantApi,
        client: tenant.GraphQLClient,
        env: guards.RigEnv,
        tmp_path: Path,
    ) -> None:
        """A free address proceeds with list queries only and saves the inventory."""
        started = await tenant.RigTenant.start(
            env, gateway_address=GATEWAY_ADDRESS, run_root=tmp_path, run_id=RUN_ID, client=client
        )
        assert api.mutations == []
        assert set(api.ops) <= set(_LIST_OPS)
        assert started.state.pre_inventory == PRE_INVENTORY
        assert tenant.load_state(started.state_path).pre_inventory == PRE_INVENTORY
        assert started.prefix == PREFIX

    async def test_start_generates_a_prefixed_run_id_when_none_is_given(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, env: guards.RigEnv, tmp_path: Path
    ) -> None:
        """Without a run id the prefix is gwops-it-<8 hex>-."""
        started = await tenant.RigTenant.start(
            env, gateway_address="g.test", run_root=tmp_path, client=client
        )
        assert re.fullmatch(r"gwops-it-[0-9a-f]{8}-", started.prefix)
        assert started.run_dir == tmp_path / started.run_id

    async def test_resume_refuses_a_state_written_for_another_pair_before_any_http(
        self, api: FakeTenantApi, env: guards.RigEnv, tmp_path: Path
    ) -> None:
        """A sweep-only recovery cannot be pointed at a different network's state."""
        other = tenant.RunState(RUN_ID, "other", REMOTE_NETWORK_ID, GATEWAY_ADDRESS)
        path = tmp_path / "state.json"
        tenant.save_state(path, other)
        with pytest.raises(guards.ApprovedPairError, match="Refusing to sweep"):
            await tenant.RigTenant.resume(env, path)
        assert api.calls == []

    async def test_resume_refuses_an_unapproved_env_even_when_the_state_matches_it(
        self, api: FakeTenantApi, tmp_path: Path
    ) -> None:
        """The approved-pair check applies to resume as well."""
        bad = guards.RigEnv(
            api_key=API_KEY,
            network="other",
            remote_network_id="other",
            approved_network=NETWORK,
            approved_remote_network_id=REMOTE_NETWORK_ID,
        )
        path = tmp_path / "state.json"
        tenant.save_state(path, tenant.RunState(RUN_ID, "other", "other", GATEWAY_ADDRESS))
        with pytest.raises(guards.ApprovedPairError):
            await tenant.RigTenant.resume(bad, path)
        assert api.calls == []

    async def test_resume_reopens_a_matching_state(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, env: guards.RigEnv, tmp_path: Path
    ) -> None:
        """A state for the approved pair resumes with the same run id and directory."""
        path = tmp_path / "state.json"
        tenant.save_state(path, fresh_state())
        resumed = await tenant.RigTenant.resume(env, path, client=client)
        assert resumed.run_id == RUN_ID and resumed.run_dir == tmp_path

    async def test_discover_new_excludes_pre_existing_objects(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        """Newly created prefixed objects are found; bystanders never are."""
        api.collections["resource"]["RES-NEW"] = f"{PREFIX}app"
        api.collections["resource"]["RES-B2"] = "other-new"
        assert await rig.discover_new("web_app", name_prefix=PREFIX) == [
            ("RES-NEW", f"{PREFIX}app")
        ]


# --- plan_sweep ------------------------------------------------------------------------


def obj(kind: str, object_id: str) -> tenant.CreatedObject:
    """A recorded object."""
    return tenant.CreatedObject(kind, object_id)


class TestPlanSweep:
    """plan_sweep and delete_mutation."""

    def test_plan_orders_service_account_web_apps_gateway_connector_ca_ssh_ca(self) -> None:
        """Deletes run in dependency order whatever order objects were recorded in."""
        created = [
            obj("ssh_ca", "S1"),
            obj("ca", "C1"),
            obj("connector", "N1"),
            obj("gateway", "G1"),
            obj("web_app", "W1"),
            obj("web_app", "W2"),
            obj("service_account", "A1"),
            obj("service_account_key", "K1"),
        ]
        plan = tenant.plan_sweep(created)
        assert [s.entry.kind for s in plan] == [
            "service_account_key",
            "service_account",
            "web_app",
            "web_app",
            "gateway",
            "connector",
            "ca",
            "ssh_ca",
        ]
        assert [s.entry.object_id for s in plan] == ["K1", "A1", "W1", "W2", "G1", "N1", "C1", "S1"]

    def test_plan_names_the_delete_mutation_for_each_kind(self) -> None:
        """Each kind maps to its own delete field."""
        created = [obj(kind, f"ID-{kind}") for kind in SWEEP_KIND_ORDER]
        assert [s.field_name for s in tenant.plan_sweep(created)] == [
            "serviceAccountKeyDelete",
            "serviceAccountDelete",
            "resourceDelete",
            "gatewayDelete",
            "connectorDelete",
            "x509CertificateAuthorityDelete",
            "sshCertificateAuthorityDelete",
        ]

    def test_plan_contains_exactly_the_recorded_ids_including_the_key_first(self) -> None:
        """Only recorded ids appear; the key is swept before its account."""
        created = [
            obj("web_app", "W1"),
            obj("service_account", "A1"),
            obj("service_account_key", "K1"),
        ]
        plan = tenant.plan_sweep(created)
        assert [s.entry.object_id for s in plan] == ["K1", "A1", "W1"]

    def test_plan_of_nothing_is_empty(self) -> None:
        """No recorded objects, no deletes."""
        assert tenant.plan_sweep([]) == []

    @pytest.mark.parametrize("kind", ["group", "security_policy", "resource", ""])
    def test_plan_refuses_unknown_kinds(self, kind: str) -> None:
        """An unrecognised kind is an error, never silently skipped or guessed."""
        with pytest.raises(ValueError, match="unknown kind"):
            tenant.plan_sweep([obj("web_app", "W1"), obj(kind, "X")])

    def test_delete_mutation_passes_the_id_as_a_variable_never_inline(self) -> None:
        """A hostile id cannot alter the mutation document."""
        step = tenant.plan_sweep([obj("web_app", 'W1"){ok}#')])[0]
        document = tenant.delete_mutation(step)
        assert "$id: ID!" in document
        assert "W1" not in document

    @pytest.mark.parametrize(
        ("messages", "expected"),
        [
            (["Resource with id X does not exist"], True),
            (["not found"], True),
            (["A does not exist", "B no such thing"], True),
            (["A does not exist", "permission denied"], False),
            (["permission denied"], False),
            ([], False),
        ],
    )
    def test_is_not_found_requires_every_message_to_say_so(
        self, messages: list[str], expected: bool
    ) -> None:
        """Only unanimous not-found messages count as already gone."""
        assert tenant.is_not_found(messages) is expected


# --- sweep over respx ------------------------------------------------------------------


class TestSweep:
    """RigTenant.sweep against the fake tenant."""

    async def test_sweep_deletes_only_recorded_ids_in_dependency_order(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        """Every delete targets a recorded id; bystanders are untouched."""
        recorded = {o.object_id for o in rig.state.created}
        report = await rig.sweep()
        assert api.delete_ids == expected_delete_order(populated)
        assert set(api.delete_ids) <= recorded
        assert [op for op in api.ops if op.startswith("RigDelete")] == [
            "RigDeleteServiceAccountKey",
            "RigDeleteServiceAccount",
            "RigDeleteResource",
            "RigDeleteResource",
            "RigDeleteGateway",
            "RigDeleteConnector",
            "RigDeleteX509CA",
            "RigDeleteSSHCA",
        ]
        deletes = {op for op in api.ops if op.startswith("RigDelete")}
        assert {c.op for c in api.mutations} == deletes | {"RigRevokeServiceAccountKey"}
        for kind, entries in PRE_INVENTORY.items():
            if kind != "gateway_binding":
                assert all(api.collections[kind][i] == n for i, n in entries.items())
        assert report.deleted == api.delete_ids and report.already_gone == []
        assert rig.state.created == []

    async def test_sweep_of_a_run_that_recorded_nothing_sends_no_request(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        """An empty run sweeps nothing."""
        report = await rig.sweep()
        assert api.calls == []
        assert report.deleted == []

    @pytest.mark.parametrize("style", ["mutation", "graphql"])
    async def test_sweep_treats_not_found_as_done(
        self,
        api: FakeTenantApi,
        rig: tenant.RigTenant,
        populated: dict[str, list[str]],
        style: str,
    ) -> None:
        """An object that vanishes between the live check and the delete counts as gone."""
        api.missing_style = style
        gone = populated["web_app"][0]
        live = {
            "resource": {
                "id": gone,
                "name": f"{PREFIX}app1",
                "remoteNetwork": {"id": REMOTE_NETWORK_ID},
            }
        }
        api.queue("RigGetResource", lambda: gql(live))
        del api.collections["resource"][gone]
        report = await rig.sweep()
        assert report.already_gone == [gone]
        assert gone not in report.deleted
        assert len(report.deleted) == len(api.delete_ids) - 1
        assert rig.state.created == []
        assert gone in [e.object_id for e in rig.state.deleted]

    @pytest.mark.parametrize(
        "failure",
        [
            mutation_failed("gatewayDelete", "permission denied"),
            graphql_errors("internal error"),
            status(500),
            status(401),
            status(400, f"bad request {API_KEY}"),
            raises(httpx.ConnectError(f"refused {API_KEY}")),
            lambda: gql({}),
        ],
        ids=["ok-false", "graphql-error", "500", "401", "400", "transport", "malformed"],
    )
    async def test_sweep_collects_other_errors_and_still_attempts_later_steps(
        self,
        api: FakeTenantApi,
        rig: tenant.RigTenant,
        populated: dict[str, list[str]],
        failure: Factory,
    ) -> None:
        """A failed delete is reported at the end; steps after it still run."""
        gateway = populated["gateway"][0]
        api.delete_override[gateway] = failure
        with pytest.raises(tenant.SweepError) as info:
            await rig.sweep()
        error = info.value
        assert len(error.errors) == 1
        assert f"gateway {gateway}" in error.errors[0]
        assert API_KEY not in str(error)
        for later in populated["connector"] + populated["ca"] + populated["ssh_ca"]:
            assert later in api.delete_ids
        assert error.report is not None
        assert gateway not in error.report.deleted
        assert set(error.report.deleted) == set(expected_delete_order(populated)) - {gateway}
        assert gateway in rig.state.ids("gateway")

    async def test_sweep_reports_every_failure_not_just_the_first(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        """Two failing deletes yield two error lines, in sweep order."""
        gateway, ca = populated["gateway"][0], populated["ca"][0]
        api.delete_override[gateway] = mutation_failed("gatewayDelete", "denied one")
        api.delete_override[ca] = mutation_failed("x509CertificateAuthorityDelete", "denied two")
        with pytest.raises(tenant.SweepError) as info:
            await rig.sweep()
        assert [gateway in info.value.errors[0], ca in info.value.errors[1]] == [True, True]
        assert len(info.value.errors) == 2

    async def test_a_second_sweep_retries_only_what_failed(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        """After a partial failure a re-run deletes the remainder and nothing twice."""
        gateway = populated["gateway"][0]
        api.delete_override[gateway] = mutation_failed("gatewayDelete", "denied")
        with pytest.raises(tenant.SweepError):
            await rig.sweep()
        sent_first = list(api.delete_ids)
        del api.delete_override[gateway]
        report = await rig.sweep()
        assert report.deleted == [gateway]
        assert api.delete_ids[len(sent_first) :] == [gateway]
        assert rig.state.created == []

    async def test_a_successful_sweep_removes_the_secret_files(
        self, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        """Connector and client env files are deleted once everything is swept."""
        assert (rig.run_dir / tenant.CONNECTOR_ENV_FILE).exists()
        assert (rig.run_dir / tenant.CLIENT_ENV_FILE).exists()
        report = await rig.sweep()
        assert not (rig.run_dir / tenant.CONNECTOR_ENV_FILE).exists()
        assert not (rig.run_dir / tenant.CLIENT_ENV_FILE).exists()
        assert report.secret_files_removed == [tenant.CONNECTOR_ENV_FILE, tenant.CLIENT_ENV_FILE]


# --- cleanup and inventory verification ------------------------------------------------


class TestCleanup:
    """verify_inventory and cleanup."""

    async def test_cleanup_succeeds_when_the_tenant_matches_the_pre_run_inventory(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        """Sweep plus an equal inventory is a clean run."""
        report = await rig.cleanup()
        assert report.deleted
        assert api.inventory() == PRE_INVENTORY

    async def test_verify_inventory_reports_leftover_objects(
        self, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        """Objects still present after the run are reported as added."""
        with pytest.raises(tenant.SweepError) as info:
            await rig.verify_inventory()
        assert any("added gateway GW-RUN" in line for line in info.value.errors)

    async def test_verify_inventory_reports_a_bystander_that_disappeared(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        """A removed pre-existing object means the rig touched something it should not."""
        del api.collections["resource"]["RES-B"]
        with pytest.raises(tenant.SweepError, match="removed resource RES-B"):
            await rig.verify_inventory()

    async def test_verify_inventory_reports_a_renamed_bystander(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        """A modified pre-existing object is reported."""
        api.collections["ca"]["CA-B"] = "changed"
        with pytest.raises(tenant.SweepError, match="renamed ca CA-B"):
            await rig.verify_inventory()

    async def test_cleanup_reports_sweep_failures_and_inventory_differences_together(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        """A failed delete does not hide the inventory comparison."""
        gateway = populated["gateway"][0]
        api.delete_override[gateway] = mutation_failed("gatewayDelete", "denied")
        with pytest.raises(tenant.SweepError) as info:
            await rig.cleanup()
        text = "\n".join(info.value.errors)
        assert f"gateway {gateway}" in text
        assert "inventory differs from pre-run: added gateway GW-RUN" in text
        assert info.value.report is not None and info.value.report.deleted

    async def test_cleanup_reports_an_inventory_fetch_failure_instead_of_raising_it_raw(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        """An unreadable post-run inventory is a collected SweepError, not a pass."""
        api.sticky["RigListGateways"] = status(401)
        with pytest.raises(tenant.SweepError, match="RigListGateways failed: HTTP 401"):
            await rig.cleanup()

    async def test_verify_inventory_without_a_pre_run_inventory_refuses_when_objects_were_recorded(
        self, tmp_path: Path, api: FakeTenantApi, client: tenant.GraphQLClient, env: guards.RigEnv
    ) -> None:
        """A state with objects but no baseline cannot be verified, and says so."""
        state = tenant.RunState(RUN_ID, NETWORK, REMOTE_NETWORK_ID, GATEWAY_ADDRESS)
        state.created.append(obj("web_app", "W1"))
        rig = tenant.RigTenant(env, client, state, tmp_path)
        with pytest.raises(tenant.SweepError, match="no pre-run inventory"):
            await rig.verify_inventory()
        assert api.calls == []


# --- grant_access ----------------------------------------------------------------------


class TestGrantAccess:
    """RigTenant.grant_access."""

    async def test_grant_access_grants_only_the_runs_service_account(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        """Each web app gets one access entry for the run's service account and nothing else."""
        account = populated["service_account"][0]
        await rig.grant_access(populated["web_app"])
        assert [c.op for c in api.calls] == ["RigGrantAccess"] * 2
        assert api.grants == [
            {"resourceId": rid, "access": [{"principalId": account}]}
            for rid in populated["web_app"]
        ]
        body = " ".join(c.body for c in api.calls)
        for forbidden in ["securityPolicyId", "groupId", "SA-B", "RES-B", "GW-B", "expiresAt"]:
            assert forbidden not in body

    @pytest.mark.parametrize("object_id", ["RES-B", "RES-UNKNOWN", "", " "])
    async def test_grant_access_refuses_ids_that_were_not_recorded_as_web_apps(
        self,
        api: FakeTenantApi,
        rig: tenant.RigTenant,
        populated: dict[str, list[str]],
        object_id: str,
    ) -> None:
        """Pre-existing and unknown ids are refused with no request sent."""
        with pytest.raises(guards.UnrecordedIdError):
            await rig.grant_access([object_id])
        assert api.calls == []

    async def test_grant_access_refuses_a_recorded_id_of_the_wrong_kind(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        """A gateway, CA, connector or account id is not a web app."""
        wrong = (
            populated["gateway"]
            + populated["ca"]
            + populated["connector"]
            + populated["service_account"]
        )
        for object_id in wrong:
            with pytest.raises(guards.UnrecordedIdError):
                await rig.grant_access([object_id])
        assert api.calls == []

    async def test_grant_access_refuses_the_whole_batch_when_one_id_is_foreign(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        """No grant is sent for the valid ids when another id in the list is not recorded."""
        with pytest.raises(guards.UnrecordedIdError, match="RES-B"):
            await rig.grant_access([populated["web_app"][0], "RES-B"])
        assert api.calls == []

    async def test_a_bystander_cannot_be_recorded_and_so_cannot_be_granted(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        """Recording a pre-existing resource is refused, which keeps it out of grant_access."""
        with pytest.raises(guards.PreexistingIdError):
            rig.record("web_app", "RES-B")
        with pytest.raises(guards.UnrecordedIdError):
            await rig.grant_access(["RES-B"])
        assert api.calls == []

    async def test_grant_access_needs_exactly_one_recorded_service_account(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        """Zero or several recorded accounts make the principal ambiguous, so nothing is sent."""
        rig.record("web_app", "RES-APP1", f"{PREFIX}app1")
        with pytest.raises(guards.GuardError, match="exactly one"):
            await rig.grant_access(["RES-APP1"])
        rig.record("service_account", "SA-1", f"{PREFIX}client")
        rig.record("service_account", "SA-2", f"{PREFIX}client")
        with pytest.raises(guards.GuardError, match="exactly one"):
            await rig.grant_access(["RES-APP1"])
        assert api.calls == []

    async def test_grant_access_with_no_ids_sends_nothing(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        """An empty list is a no-op."""
        await rig.grant_access([])
        assert api.calls == []


# --- setup, partial setup and secret handling ------------------------------------------


class TestSetup:
    """RigTenant.setup and the secret files."""

    async def test_setup_creates_prefixed_net_new_objects_and_records_them(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        """Connector and service account carry the run prefix and are recorded and saved."""
        result = await rig.setup()
        assert api.ops == [
            "RigCreateConnector",
            "RigGenerateConnectorTokens",
            "RigCreateServiceAccount",
            "RigCreateServiceAccountKey",
        ]
        created_names = [
            c.variables["name"] for c in api.calls if c.op != "RigGenerateConnectorTokens"
        ]
        assert all(name.startswith(PREFIX) for name in created_names)
        saved = tenant.load_state(rig.state_path)
        assert saved.ids("connector") == [result.connector_id]
        assert saved.ids("service_account") == [result.service_account_id]
        assert len(saved.ids("service_account_key")) == 1
        assert "securityPolicyId" not in " ".join(c.body for c in api.calls)

    async def test_setup_writes_secrets_only_to_the_run_dir_files(
        self, rig: tenant.RigTenant
    ) -> None:
        """Tokens land in the two env files; the tenant API key and state file hold no secret."""
        result = await rig.setup()
        connector_env = result.connector_env_file.read_text(encoding="utf-8")
        client_env = result.client_env_file.read_text(encoding="utf-8")
        assert f"TWINGATE_ACCESS_TOKEN={ACCESS_TOKEN}" in connector_env
        assert f"TWINGATE_REFRESH_TOKEN={REFRESH_TOKEN}" in connector_env
        key_lines = client_env.strip().splitlines()
        assert len(key_lines) == 1 and key_lines[0].startswith("TWINGATE_SERVICE_KEY=")
        assert json.loads(key_lines[0].split("=", 1)[1])["privateKey"] == PRIVATE_KEY
        assert result.connector_env_file.parent == rig.run_dir
        for text in (connector_env, client_env, rig.state_path.read_text(encoding="utf-8")):
            assert API_KEY not in text
        state_text = rig.state_path.read_text(encoding="utf-8")
        assert not any(s in state_text for s in SECRETS)

    async def test_setup_result_holds_paths_and_ids_not_secrets(
        self, rig: tenant.RigTenant
    ) -> None:
        """repr of the setup result is free of every secret."""
        text = repr(await rig.setup())
        assert not any(secret in text for secret in SECRETS)

    async def test_setup_never_prints_or_logs_any_secret(
        self,
        rig: tenant.RigTenant,
        capsys: pytest.CaptureFixture[str],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Nothing setup does reaches stdout, stderr, stdlib logging or structlog."""
        caplog.set_level(logging.DEBUG)
        with structlog.testing.capture_logs() as events:
            await rig.setup()
        captured = capsys.readouterr()
        everything = f"{captured.out}{captured.err}{caplog.text}{events}"
        assert any(event["event"] == "rig.request" for event in events)
        assert not any(secret in everything for secret in SECRETS)

    async def test_a_full_run_never_leaks_a_secret_to_logs_state_or_errors(
        self,
        api: FakeTenantApi,
        rig: tenant.RigTenant,
        capsys: pytest.CaptureFixture[str],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Setup, grant, a failing delete and cleanup together never emit a secret."""
        caplog.set_level(logging.DEBUG)
        with structlog.testing.capture_logs() as events:
            await rig.setup()
            api.collections["resource"]["RES-APP1"] = f"{PREFIX}app1"
            rig.record("web_app", "RES-APP1", f"{PREFIX}app1")
            await rig.grant_access(["RES-APP1"])
            api.delete_override["RES-APP1"] = status(400, f"echo {API_KEY} {ACCESS_TOKEN}")
            with pytest.raises(tenant.SweepError) as info:
                await rig.cleanup()
        captured = capsys.readouterr()
        everything = f"{captured.out}{captured.err}{caplog.text}{events}{info.value}"
        assert API_KEY not in everything
        assert not any(secret in rig.state_path.read_text(encoding="utf-8") for secret in SECRETS)

    @pytest.mark.parametrize(
        "op", ["RigCreateConnector", "RigCreateServiceAccount", "RigCreateServiceAccountKey"]
    )
    async def test_create_mutations_are_not_retried_on_5xx(
        self, api: FakeTenantApi, rig: tenant.RigTenant, sleeper: Sleeper, op: str
    ) -> None:
        """A 5xx on any create is sent once; no duplicate object can result."""
        api.sticky[op] = status(502)
        with pytest.raises(tenant.RigApiError, match="not retried"):
            await rig.setup()
        assert api.ops.count(op) == 1
        assert sleeper.delays == []

    async def test_a_throttled_create_is_retried_and_creates_one_object(
        self, api: FakeTenantApi, rig: tenant.RigTenant, sleeper: Sleeper
    ) -> None:
        """A 429 on a create waits for the hint and is then sent again exactly once more."""
        api.queue("RigCreateConnector", status(429, headers={"Retry-After": "3"}))
        await rig.setup()
        assert api.ops.count("RigCreateConnector") == 2
        assert sleeper.delays == [3.0]
        assert len([n for n in api.collections["connector"].values() if n.startswith(PREFIX)]) == 1

    async def test_partial_setup_records_what_exists_and_the_sweep_removes_it(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        """A failure after the account was created leaves it recorded, so the sweep deletes it."""
        api.sticky["RigCreateServiceAccountKey"] = status(500)
        with pytest.raises(tenant.RigApiError):
            await rig.setup()
        assert len(rig.state.ids("connector")) == 1 and len(rig.state.ids("service_account")) == 1
        assert not (rig.run_dir / tenant.CLIENT_ENV_FILE).exists()
        await rig.cleanup()
        assert api.inventory() == PRE_INVENTORY

    @pytest.mark.parametrize("tokens", [{}, {"accessToken": ""}, {"refreshToken": REFRESH_TOKEN}])
    async def test_setup_refuses_a_token_response_without_an_access_token(
        self, api: FakeTenantApi, rig: tenant.RigTenant, tokens: dict[str, str]
    ) -> None:
        """No access token means no env file and an error without secrets."""
        api.tokens = tokens
        with pytest.raises(tenant.RigApiError, match="no tokens") as info:
            await rig.setup()
        assert REFRESH_TOKEN not in str(info.value)
        assert not (rig.run_dir / tenant.CONNECTOR_ENV_FILE).exists()

    async def test_setup_refuses_a_token_response_without_a_refresh_token_as_an_api_error(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        """A missing refreshToken is reported as RigApiError, not a bare KeyError."""
        api.tokens = {"accessToken": ACCESS_TOKEN}
        with pytest.raises(tenant.RigApiError):
            await rig.setup()
        assert not (rig.run_dir / tenant.CONNECTOR_ENV_FILE).exists()

    async def test_setup_refuses_a_missing_service_key_token(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        """A key response without a token is an error and writes no client env file."""
        api.queue(
            "RigCreateServiceAccountKey",
            lambda: gql(
                {"serviceAccountKeyCreate": {"ok": True, "entity": {"id": "K"}, "token": ""}}
            ),
        )
        with pytest.raises(tenant.RigApiError, match="no token"):
            await rig.setup()
        assert not (rig.run_dir / tenant.CLIENT_ENV_FILE).exists()

    async def test_setup_refuses_a_create_result_without_an_entity_id(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        """ok=true with no entity id cannot be recorded, so setup stops."""
        api.queue(
            "RigCreateConnector", lambda: gql({"connectorCreate": {"ok": True, "entity": None}})
        )
        with pytest.raises(tenant.RigApiError, match="no entity id"):
            await rig.setup()
        assert rig.state.created == []

    def test_write_secret_file_never_overwrites_an_existing_file(self, tmp_path: Path) -> None:
        """Exclusive creation: a second write to the same path fails and keeps the first."""
        path = tmp_path / "secret.env"
        tenant.write_secret_file(path, ["A=1"])
        with pytest.raises(FileExistsError):
            tenant.write_secret_file(path, ["A=2"])
        assert path.read_text(encoding="utf-8") == "A=1\n"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
    def test_write_secret_file_creates_the_file_with_mode_0600(self, tmp_path: Path) -> None:
        """Secret files are readable by the owner only."""
        path = tmp_path / "secret.env"
        tenant.write_secret_file(path, ["A=1"])
        assert path.stat().st_mode & 0o777 == 0o600

    def test_single_line_key_compacts_json_and_passes_a_one_line_token_through(self) -> None:
        """A pretty-printed JSON key becomes one line; a raw one-line token is unchanged."""
        assert "\n" not in tenant.single_line_key(SERVICE_KEY)
        assert json.loads(tenant.single_line_key(SERVICE_KEY))["privateKey"] == PRIVATE_KEY
        assert tenant.single_line_key("plain-token") == "plain-token"

    def test_single_line_key_refuses_a_multi_line_non_json_token_without_echoing_it(self) -> None:
        """A multi-line raw token would corrupt the env file and is refused."""
        with pytest.raises(tenant.RigApiError) as info:
            tenant.single_line_key("line-one-SECRET\nline-two")
        assert "SECRET" not in str(info.value)

    def test_default_run_root_is_covered_by_gitignore(self) -> None:
        """The directory holding the secret env files must be ignored by git."""
        repo = Path(__file__).resolve().parent.parent
        relative = tenant.DEFAULT_RUN_ROOT.relative_to(repo) / RUN_ID / tenant.CONNECTOR_ENV_FILE
        lines = (repo / ".gitignore").read_text(encoding="utf-8").splitlines()
        assert _gitignore_covers(lines, relative.parts)


def _gitignore_covers(lines: list[str], parts: tuple[str, ...]) -> bool:
    """True when a simple reading of `lines` ignores the path made of `parts`."""
    prefixes = ["/".join(parts[: i + 1]) for i in range(len(parts))]
    for raw in lines:
        pattern = raw.strip()
        if not pattern or pattern.startswith(("#", "!")):
            continue
        pattern = pattern.removeprefix("**/")
        anchored = pattern.startswith("/") or "/" in pattern.rstrip("/")
        pattern = pattern.strip("/")
        if anchored:
            if any(fnmatch.fnmatchcase(prefix, pattern) for prefix in prefixes):
                return True
        elif any(fnmatch.fnmatchcase(part, pattern) for part in parts):
            return True
    return False


# --- CLI -------------------------------------------------------------------------------


def write_state(api: FakeTenantApi, tmp_path: Path, extra: list[tuple[str, str, str]]) -> Path:
    """Write a state file whose baseline is the fake's inventory, then add `extra` objects."""
    state = tenant.RunState(
        RUN_ID,
        NETWORK,
        REMOTE_NETWORK_ID,
        GATEWAY_ADDRESS,
        pre_inventory=api.inventory(),
        docker_endpoint=LOCAL_ENDPOINT,
    )
    for kind, object_id, name in extra:
        api.collections[COLLECTION_OF[kind]][object_id] = name
        state.record(kind, object_id, name)
    path = tmp_path / RUN_ID / tenant.STATE_FILE
    path.parent.mkdir()
    tenant.save_state(path, state)
    return path


class StubDockerRunner:
    """A scripted docker CLI: a local engine, and a gwops container that is not running."""

    def __init__(self, *, gwops_running: bool = False) -> None:
        self.calls: list[list[str]] = []
        self.gwops_running = gwops_running
        self.api: FakeTenantApi | None = None
        self.api_calls_at_stop: int | None = None

    async def __call__(self, argv: Any, env: Any, timeout: float) -> dockerops.CommandResult:
        words = list(argv)
        self.calls.append(words)
        if "stop" in words and self.api is not None and self.api_calls_at_stop is None:
            self.api_calls_at_stop = len(self.api.calls)
        out = ""
        if words[1:3] == ["context", "show"]:
            out = "default"
        elif words[1:3] == ["context", "inspect"]:
            out = LOCAL_ENDPOINT
        elif words[1] == "inspect":
            out = "true" if self.gwops_running else "false"
        return dockerops.CommandResult(0, out, "")


@pytest.fixture
def local_docker(monkeypatch: pytest.MonkeyPatch, api: FakeTenantApi) -> StubDockerRunner:
    stub = StubDockerRunner()
    stub.api = api
    monkeypatch.setattr(dockerops, "subprocess_runner", stub)
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    return stub


@pytest.fixture
def approved_process_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in approved_environ().items():
        monkeypatch.setenv(name, value)


class TestCli:
    """tenant.main sweep."""

    def test_sweep_cli_deletes_recorded_objects_and_exits_zero(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        local_docker: StubDockerRunner,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A clean sweep exits 0 and the tenant equals its baseline."""
        path = write_state(
            api,
            tmp_path,
            [("web_app", "RES-1", f"{PREFIX}a"), ("gateway", "GW-1", GATEWAY_ADDRESS)],
        )
        assert tenant.main(["sweep", "--state", str(path)]) == 0
        out = capsys.readouterr().out
        assert "swept run abc12345: deleted 2, already gone 0" in out
        assert api.delete_ids == ["RES-1", "GW-1"]
        assert API_KEY not in out

    def test_sweep_cli_exits_one_and_prints_every_error_when_a_delete_fails(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        local_docker: StubDockerRunner,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A failed delete is printed and the exit status is non-zero."""
        path = write_state(
            api,
            tmp_path,
            [("web_app", "RES-1", f"{PREFIX}a"), ("gateway", "GW-1", GATEWAY_ADDRESS)],
        )
        api.delete_override["RES-1"] = mutation_failed("resourceDelete", "denied")
        assert tenant.main(["sweep", "--state", str(path)]) == 1
        out = capsys.readouterr().out
        assert "ERROR web_app RES-1" in out
        assert "GW-1" in api.delete_ids
        assert API_KEY not in out

    @pytest.mark.parametrize("name", guards.REQUIRED_ENV)
    def test_sweep_cli_refuses_when_an_it_variable_is_unset(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        name: str,
    ) -> None:
        """Without all IT_* variables the CLI exits 2 before any HTTP."""
        path = write_state(api, tmp_path, [("web_app", "RES-1", f"{PREFIX}a")])
        monkeypatch.delenv(name)
        assert tenant.main(["sweep", "--state", str(path)]) == 2
        assert "REFUSED" in capsys.readouterr().out
        assert api.calls == []

    def test_sweep_cli_refuses_an_unapproved_network_without_echoing_the_key(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A wrong network exits 2 with no HTTP and no key in the output."""
        path = write_state(api, tmp_path, [("web_app", "RES-1", f"{PREFIX}a")])
        monkeypatch.setenv(guards.ENV_NETWORK, "other")
        assert tenant.main(["sweep", "--state", str(path)]) == 2
        out = capsys.readouterr().out
        assert "REFUSED" in out and API_KEY not in out
        assert api.calls == []

    def test_sweep_cli_refuses_a_state_for_another_pair_and_a_missing_state(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A foreign or unreadable state file exits 2 with no HTTP."""
        foreign = tmp_path / "foreign.json"
        tenant.save_state(foreign, tenant.RunState(RUN_ID, "other", REMOTE_NETWORK_ID, "g"))
        assert tenant.main(["sweep", "--state", str(foreign)]) == 2
        assert tenant.main(["sweep", "--state", str(tmp_path / "absent.json")]) == 2
        assert capsys.readouterr().out.count("REFUSED") == 2
        assert api.calls == []


def hand_edited_state(
    tmp_path: Path, created: list[dict[str, str]], *, with_inventory: bool = True
) -> Path:
    """Write a state file whose `created` list was edited by hand."""
    raw = fresh_state().to_dict()
    raw["created"] = created
    if not with_inventory:
        raw["pre_inventory"] = None
    path = tmp_path / RUN_ID / tenant.STATE_FILE
    path.parent.mkdir()
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


class TestHandEditedState:
    """A state file naming a bystander id, or ids without an inventory, never loads."""

    @pytest.mark.parametrize(
        ("kind", "object_id"),
        [("web_app", "RES-B"), ("gateway", "GW-B"), ("ca", "CA-B"), ("web_app", "SA-B")],
    )
    def test_from_dict_refuses_a_recorded_id_from_the_pre_run_inventory(
        self, kind: str, object_id: str
    ) -> None:
        """A pre-existing id listed as created is refused at load time."""
        raw = fresh_state().to_dict()
        raw["created"] = [{"kind": kind, "id": object_id, "name": "x"}]
        with pytest.raises(guards.PreexistingIdError):
            tenant.RunState.from_dict(raw)

    def test_from_dict_refuses_recorded_ids_without_a_pre_run_inventory(self) -> None:
        """Recorded ids with no baseline cannot be vetted, so the state is refused."""
        raw = fresh_state().to_dict()
        raw["created"] = [{"kind": "web_app", "id": "RES-1", "name": "x"}]
        raw["pre_inventory"] = None
        with pytest.raises(guards.GuardError, match="no pre-run inventory"):
            tenant.RunState.from_dict(raw)

    def test_from_dict_accepts_an_empty_state_without_an_inventory(self) -> None:
        """A state from a run that stopped before recording anything still loads."""
        raw = fresh_state().to_dict()
        raw["pre_inventory"] = None
        assert tenant.RunState.from_dict(raw).created == []

    def test_load_state_refuses_a_hand_edited_bystander_id(self, tmp_path: Path) -> None:
        """load_state applies the same check as from_dict."""
        path = hand_edited_state(tmp_path, [{"kind": "gateway", "id": "GW-B", "name": "x"}])
        with pytest.raises(guards.PreexistingIdError):
            tenant.load_state(path)

    async def test_resume_refuses_a_bystander_id_before_any_http(
        self,
        api: FakeTenantApi,
        client: tenant.GraphQLClient,
        env: guards.RigEnv,
        tmp_path: Path,
    ) -> None:
        """resume never reaches the tenant for a state naming a pre-existing id."""
        path = hand_edited_state(tmp_path, [{"kind": "web_app", "id": "RES-B", "name": "x"}])
        with pytest.raises(guards.PreexistingIdError):
            await tenant.RigTenant.resume(env, path, client=client)
        assert api.calls == []

    async def test_resume_refuses_recorded_ids_without_an_inventory_before_any_http(
        self,
        api: FakeTenantApi,
        client: tenant.GraphQLClient,
        env: guards.RigEnv,
        tmp_path: Path,
    ) -> None:
        """resume refuses ids with no baseline without calling the tenant."""
        path = hand_edited_state(
            tmp_path, [{"kind": "web_app", "id": "RES-1", "name": "x"}], with_inventory=False
        )
        with pytest.raises(guards.GuardError, match="no pre-run inventory"):
            await tenant.RigTenant.resume(env, path, client=client)
        assert api.calls == []

    def test_sweep_cli_exits_two_and_deletes_nothing_for_a_bystander_id(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The recovery CLI refuses a state naming a pre-existing id."""
        path = hand_edited_state(tmp_path, [{"kind": "web_app", "id": "RES-B", "name": "x"}])
        assert tenant.main(["sweep", "--state", str(path)]) == 2
        assert "REFUSED" in capsys.readouterr().out
        assert api.calls == [] and api.delete_ids == []


# --- recovery CLI: gwops stopped first, strays found by name ----------------------------------


class TestRecoveryCli:
    """`sweep --state` stops gwops, records run objects by name, sweeps, then tears down."""

    def test_the_cli_stops_gwops_before_any_tenant_call_and_downs_the_stack_last(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        local_docker: StubDockerRunner,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = write_state(api, tmp_path, [("web_app", "RES-1", f"{PREFIX}a")])
        assert tenant.main(["sweep", "--state", str(path)]) == 0
        assert local_docker.api_calls_at_stop == 0
        compose = [c for c in local_docker.calls if c[1] == "compose"]
        assert compose[0][-4:] == ["stop", "-t", "30", "gwops"]
        assert compose[0][2:4] == ["-p", f"gwops-it-{RUN_ID}"]
        assert all(flag in compose[-1] for flag in ("down", "-v", "--remove-orphans"))
        assert "swept run" in capsys.readouterr().out

    def test_the_cli_force_removes_gwops_and_sweeps_only_the_service_account_if_it_may_run(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        stub = StubDockerRunner(gwops_running=True)
        monkeypatch.setattr(dockerops, "subprocess_runner", stub)
        monkeypatch.delenv("DOCKER_HOST", raising=False)
        path = write_state(
            api,
            tmp_path,
            [
                ("service_account", "SA-1", f"{PREFIX}client"),
                ("web_app", "RES-1", f"{PREFIX}a"),
                ("gateway", "GW-1", GATEWAY_ADDRESS),
            ],
        )
        assert tenant.main(["sweep", "--state", str(path)]) == 1
        out = capsys.readouterr().out
        assert ["docker", "rm", "-f", f"gwops-it-{RUN_ID}-gwops"] in stub.calls
        assert api.delete_ids == ["SA-1"]
        assert "gwops may still be running" in out
        assert f"python -m tests.integration.webapp.rig.tenant sweep --state {path}" in out

    def test_the_cli_records_and_sweeps_run_objects_the_state_never_saw(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        local_docker: StubDockerRunner,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = write_state(api, tmp_path, [])
        strays = {
            "service_account": ("SA-X", f"{PREFIX}client"),
            "resource": ("RES-X", f"{PREFIX}stray"),
            "gateway": ("GW-X", GATEWAY_ADDRESS),
            "connector": ("CON-X", f"{PREFIX}connector"),
        }
        for collection, (object_id, name) in strays.items():
            api.collections[collection][object_id] = name
        api.collections["ca"]["CA-X"] = X509_CA_NAME
        api.collections["ca"]["CA-S"] = SSH_CA_NAME
        assert tenant.main(["sweep", "--state", str(path)]) == 0
        assert sorted(api.delete_ids) == sorted(["SA-X", "RES-X", "GW-X", "CON-X", "CA-X", "CA-S"])
        assert tenant.load_state(path).created == []

    def test_the_cli_refuses_and_deletes_nothing_when_a_recorded_id_is_now_someone_elses(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        local_docker: StubDockerRunner,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = write_state(api, tmp_path, [("web_app", "RES-1", f"{PREFIX}a")])
        api.collections["resource"]["RES-1"] = "somebody-elses-app"
        assert tenant.main(["sweep", "--state", str(path)]) == 2
        assert "REFUSED" in capsys.readouterr().out
        assert api.delete_ids == []

    def test_the_cli_refuses_a_remote_docker_before_any_tenant_call(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = write_state(api, tmp_path, [("web_app", "RES-1", f"{PREFIX}a")])
        monkeypatch.setenv("DOCKER_HOST", "tcp://elsewhere:2375")
        stub = StubDockerRunner()
        monkeypatch.setattr(dockerops, "subprocess_runner", stub)
        assert tenant.main(["sweep", "--state", str(path)]) == 2
        assert api.calls == []
        assert not any(c[1] == "compose" for c in stub.calls)


class TestSecretFiles:
    """The sweep removes every secret file the rig writes."""

    async def test_gwops_env_is_removed_with_the_connector_and_client_files(
        self, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        (rig.run_dir / "gwops.env").write_text("TWINGATE_API_KEY='x'\n", encoding="utf-8")
        report = await rig.sweep()
        assert not (rig.run_dir / "gwops.env").exists()
        assert "gwops.env" in report.secret_files_removed

    async def test_a_partial_sweep_keeps_the_secret_files(
        self, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        await rig.sweep(only_kinds={"service_account_key", "service_account"})
        assert (rig.run_dir / tenant.CONNECTOR_ENV_FILE).exists()
        assert rig.state.ids("web_app") == populated["web_app"]

    async def test_state_is_written_0600(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        modes: list[int] = []
        real = tenant.os.open

        def spy(path: Any, flags: int, mode: int = 0o777, **kw: Any) -> int:
            modes.append(mode)
            return real(path, flags, mode, **kw)

        monkeypatch.setattr(tenant.os, "open", spy)
        tenant.save_state(tmp_path / "state.json", fresh_state())
        assert modes == [0o600]


# --- names a run may own ----------------------------------------------------------------------


class TestNameRules:
    """validate_recorded_name and RunState."""

    @pytest.mark.parametrize(
        ("kind", "name"),
        [
            ("web_app", "bystander"),
            ("web_app", "gwops-it-abc12345-"),
            ("web_app", "gwops-it-other123-a"),
            ("connector", "prod-connector"),
            ("service_account", f"{PREFIX}client2"),
            ("service_account", "ci"),
            ("gateway", "10.0.0.1:8443"),
            ("ca", "gwops-x509-someone-elses"),
            ("ssh_ca", X509_CA_NAME),
            ("ca", SSH_CA_NAME),
            ("service_account_key", "key"),
            ("web_app", ""),
        ],
    )
    def test_record_refuses_names_a_run_object_cannot_have(self, kind: str, name: str) -> None:
        with pytest.raises(guards.UnrecordedIdError):
            fresh_state().record(kind, "ID-NEW", name)

    @pytest.mark.parametrize(
        ("kind", "name"),
        [
            ("web_app", f"{PREFIX}a"),
            ("connector", f"{PREFIX}connector"),
            ("service_account", f"{PREFIX}client"),
            ("gateway", GATEWAY_ADDRESS.upper()),
            ("ca", X509_CA_NAME),
            ("ssh_ca", SSH_CA_NAME),
            ("service_account_key", f"{PREFIX}key"),
        ],
    )
    def test_record_accepts_the_runs_own_names(self, kind: str, name: str) -> None:
        state = fresh_state()
        state.record(kind, "ID-NEW", name)
        assert state.ids(kind) == ["ID-NEW"]

    def test_from_dict_refuses_a_hand_edited_state_with_a_foreign_name(
        self, tmp_path: Path
    ) -> None:
        path = hand_edited_state(
            tmp_path, [{"kind": "web_app", "id": "RES-NEW", "name": "not-ours"}]
        )
        with pytest.raises(guards.UnrecordedIdError, match="must start with"):
            tenant.load_state(path)

    def test_from_dict_accepts_the_runs_own_names(self, tmp_path: Path) -> None:
        path = hand_edited_state(
            tmp_path, [{"kind": "web_app", "id": "RES-NEW", "name": f"{PREFIX}a"}]
        )
        assert tenant.load_state(path).ids("web_app") == ["RES-NEW"]


class TestVerifyDeleteTarget:
    """guards.verify_delete_target on a fetched object."""

    def _verify(self, kind: str, node: dict[str, Any]) -> None:
        guards.verify_delete_target(
            kind,
            node,
            run_id=RUN_ID,
            gateway_address=GATEWAY_ADDRESS,
            remote_network_id=REMOTE_NETWORK_ID,
        )

    def _network(self, network_id: str = REMOTE_NETWORK_ID) -> dict[str, Any]:
        return {"remoteNetwork": {"id": network_id}}

    @pytest.mark.parametrize(
        ("kind", "node"),
        [
            ("web_app", {"id": "R", "name": f"{PREFIX}a"}),
            ("connector", {"id": "C", "name": f"{PREFIX}connector"}),
            ("gateway", {"id": "G", "address": GATEWAY_ADDRESS}),
        ],
    )
    def test_the_runs_own_objects_in_the_approved_network_pass(
        self, kind: str, node: dict[str, Any]
    ) -> None:
        self._verify(kind, {**node, **self._network()})

    @pytest.mark.parametrize(
        ("kind", "node"),
        [
            ("web_app", {"id": "R", "name": "prod-app"}),
            ("connector", {"id": "C", "name": "prod-connector"}),
            ("gateway", {"id": "G", "address": "10.0.0.1:8443"}),
            ("ca", {"id": "A", "name": "gwops-x509-other"}),
            ("ssh_ca", {"id": "A", "name": X509_CA_NAME}),
            ("service_account", {"id": "S", "name": "ci-bot"}),
            ("web_app", {"id": "R"}),
        ],
    )
    def test_a_name_that_is_not_the_runs_is_refused(self, kind: str, node: dict[str, Any]) -> None:
        with pytest.raises(guards.UnrecordedIdError):
            self._verify(kind, {**node, **self._network()})

    @pytest.mark.parametrize(
        ("kind", "node"),
        [
            ("web_app", {"id": "R", "name": f"{PREFIX}a"}),
            ("connector", {"id": "C", "name": f"{PREFIX}connector"}),
            ("gateway", {"id": "G", "address": GATEWAY_ADDRESS}),
        ],
    )
    def test_another_remote_network_is_refused(self, kind: str, node: dict[str, Any]) -> None:
        with pytest.raises(guards.UnrecordedIdError, match="remote network"):
            self._verify(kind, {**node, **self._network("OTHER")})
        with pytest.raises(guards.UnrecordedIdError, match="remote network"):
            self._verify(kind, dict(node))

    def test_cas_and_service_accounts_have_no_network_to_check(self) -> None:
        self._verify("ca", {"id": "A", "name": X509_CA_NAME})
        self._verify("ssh_ca", {"id": "A", "name": SSH_CA_NAME})
        self._verify("service_account", {"id": "S", "name": f"{PREFIX}client"})


class TestPreDeleteVerification:
    """RigTenant.sweep fetches each object by id before deleting it."""

    async def test_each_delete_is_preceded_by_a_fetch_of_the_same_id(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        await rig.sweep()
        fetched: list[str] = []
        for call in api.calls:
            if call.op in _GET_OPS:
                fetched.append(call.variables["id"])
            elif call.op in _DELETE_OPS:
                assert call.variables["id"] in fetched, call.op

    @pytest.mark.parametrize(
        ("kind", "collection", "object_id"),
        [
            ("web_app", "resource", "RES-APP2"),
            ("gateway", "gateway", "GW-RUN"),
            ("ca", "ca", "CA-X509"),
            ("ssh_ca", "ca", "CA-SSH"),
        ],
    )
    async def test_a_live_name_that_is_not_the_runs_stops_the_sweep(
        self,
        api: FakeTenantApi,
        rig: tenant.RigTenant,
        populated: dict[str, list[str]],
        kind: str,
        collection: str,
        object_id: str,
    ) -> None:
        api.collections[collection][object_id] = "someone-elses"
        with pytest.raises(guards.UnrecordedIdError):
            await rig.sweep()
        order = expected_delete_order(populated)
        assert object_id not in api.delete_ids
        assert api.delete_ids == order[: order.index(object_id)]

    async def test_a_renamed_connector_or_service_account_stops_the_sweep(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        connector = populated["connector"][0]
        api.collections["connector"][connector] = "prod-connector"
        with pytest.raises(guards.UnrecordedIdError):
            await rig.sweep()
        assert connector not in api.delete_ids
        assert populated["ca"][0] not in api.delete_ids

    @pytest.mark.parametrize(
        ("collection", "object_id"),
        [("resource", "RES-APP1"), ("gateway", "GW-RUN")],
    )
    async def test_an_object_in_another_remote_network_stops_the_sweep(
        self,
        api: FakeTenantApi,
        rig: tenant.RigTenant,
        populated: dict[str, list[str]],
        collection: str,
        object_id: str,
    ) -> None:
        api.network_of[object_id] = "UmVtb3RlTmV0d29yazo5OTk="
        with pytest.raises(guards.UnrecordedIdError, match="remote network"):
            await rig.sweep()
        assert object_id not in api.delete_ids

    async def test_an_object_that_is_already_gone_is_not_deleted(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        gone = populated["web_app"][0]
        del api.collections["resource"][gone]
        report = await rig.sweep()
        assert report.already_gone == [gone]
        assert gone not in api.delete_ids

    async def test_a_failed_fetch_is_collected_and_nothing_unverified_is_deleted(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        api.sticky["RigGetResource"] = status(500)
        with pytest.raises(tenant.SweepError) as caught:
            await rig.sweep()
        assert not set(populated["web_app"]) & set(api.delete_ids)
        assert populated["gateway"][0] in api.delete_ids
        assert any(e.startswith("web_app") for e in caught.value.errors)


# --- discovery by exact name ------------------------------------------------------------------


class TestDiscovery:
    """discover_all and record_discovered."""

    def _add_run_objects(self, api: FakeTenantApi) -> None:
        api.collections["resource"]["RES-X"] = f"{PREFIX}stray"
        api.collections["gateway"]["GW-X"] = GATEWAY_ADDRESS
        api.collections["ca"]["CA-X"] = X509_CA_NAME
        api.collections["ca"]["CA-S"] = SSH_CA_NAME
        api.collections["connector"]["CON-X"] = f"{PREFIX}connector"
        api.collections["service_account"]["SA-X"] = f"{PREFIX}client"

    async def test_discover_all_finds_every_kind_the_run_owns(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        self._add_run_objects(api)
        found = {(kind, object_id) for kind, object_id, _name in await rig.discover_all()}
        assert found == {
            ("web_app", "RES-X"),
            ("gateway", "GW-X"),
            ("ca", "CA-X"),
            ("ssh_ca", "CA-S"),
            ("connector", "CON-X"),
            ("service_account", "SA-X"),
        }

    async def test_discover_all_records_the_ssh_resource_as_ssh_not_web_app(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        api.collections["resource"]["RES-APP"] = f"{PREFIX}plain"
        api.collections["resource"]["RES-SSH"] = f"{PREFIX}ssh"
        found = {(kind, object_id) for kind, object_id, _name in await rig.discover_all()}
        assert found == {("web_app", "RES-APP"), ("ssh", "RES-SSH")}

    def test_the_ssh_kind_is_swept_after_web_apps_and_named_by_the_prefix(self) -> None:
        guards.validate_recorded_name(
            "ssh", f"{PREFIX}ssh", run_id=RUN_ID, gateway_address=GATEWAY_ADDRESS
        )
        with pytest.raises(guards.UnrecordedIdError):
            guards.validate_recorded_name(
                "ssh", "rig-ssh", run_id=RUN_ID, gateway_address=GATEWAY_ADDRESS
            )
        order = tenant.SWEEP_ORDER
        assert order.index("web_app") < order.index("ssh") < order.index("gateway")

    async def test_discover_all_ignores_near_names_and_pre_existing_objects(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        api.collections["connector"]["CON-N"] = f"{PREFIX}connector2"
        api.collections["service_account"]["SA-N"] = f"{PREFIX}client2"
        api.collections["resource"]["RES-N"] = "gwops-it-other123-a"
        api.collections["gateway"]["GW-N"] = "other.example.test:8443"
        api.collections["ca"]["CA-N"] = "gwops-x509-other"
        assert await rig.discover_all() == []

    async def test_record_discovered_records_each_object_once(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        self._add_run_objects(api)
        await rig.record_discovered()
        await rig.record_discovered()
        assert len(rig.state.created) == 6
        assert rig.state.ids("ca") == ["CA-X"]
        assert rig.state.ids("ssh_ca") == ["CA-S"]

    async def test_assert_address_free_refuses_a_gateway_that_appeared_at_the_address(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        await rig.assert_address_free()
        api.collections["gateway"]["GW-LATE"] = GATEWAY_ADDRESS
        with pytest.raises(guards.GatewayAddressInUseError):
            await rig.assert_address_free()


# --- post-sweep checks, partial sweeps, gateway bindings --------------------------------------


class TestCleanupChecks:
    """cleanup after the sweep, and the inventory's gateway CA bindings."""

    async def test_cleanup_fails_on_a_new_run_object_that_appears_after_the_sweep(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        api.collections["resource"]["RES-LATE"] = f"{PREFIX}recreated"
        with pytest.raises(tenant.SweepError) as caught:
            await rig.cleanup()
        assert any(
            "new run object after the sweep: web_app RES-LATE" in e for e in caught.value.errors
        )

    async def test_a_partial_cleanup_deletes_only_the_service_account_and_reports_it(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        with pytest.raises(tenant.SweepError) as caught:
            await rig.cleanup(only_kinds={"service_account_key", "service_account"})
        assert api.delete_ids == [*populated["service_account_key"], *populated["service_account"]]
        assert any("partial sweep" in e for e in caught.value.errors)

    async def test_the_gateway_listing_asks_for_both_cas(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        await rig.verify_inventory()
        bodies = [c.body for c in api.calls if c.op == "RigListGateways"]
        assert bodies
        assert all("x509CA" in body and "sshCA" in body for body in bodies)

    async def test_the_inventory_records_each_gateways_cas(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        assert rig.state.pre_inventory is not None
        assert rig.state.pre_inventory["gateway_binding"] == {"GW-B": "x509=CA-B;ssh="}

    async def test_a_bystander_gateway_rebound_to_another_ca_fails_the_comparison(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        api.gateway_cas["GW-B"] = ("CA-OTHER", "SSH-NEW")
        with pytest.raises(tenant.SweepError) as caught:
            await rig.verify_inventory()
        assert any("gateway_binding GW-B" in e for e in caught.value.errors)

    def test_gateway_bindings_read_missing_cas_as_empty(self) -> None:
        nodes = [
            {"id": "G1", "x509CA": {"id": "X"}, "sshCA": None},
            {"id": "G2"},
            {"id": "G3", "x509CA": {"id": "Y"}, "sshCA": {"id": "Z"}},
        ]
        assert tenant.gateway_bindings(nodes) == {
            "G1": "x509=X;ssh=",
            "G2": "x509=;ssh=",
            "G3": "x509=Y;ssh=Z",
        }


class TestStopSweepDown:
    """teardown.stop_sweep_down with a real RigTenant and Docker over stubs."""

    def _docker(self, rig: tenant.RigTenant, stub: StubDockerRunner) -> dockerops.Docker:
        names = seedgen.build_names(RUN_ID)
        compose_vars = seedgen.compose_env(
            names, run_dir=rig.run_dir, network=NETWORK, admin_port=1, gwops_image="x"
        )
        log = RunLog(rig.run_dir / "run.log", Redactor(), echo=False)
        return dockerops.Docker(log, names, dockerops.COMPOSE_FILE, compose_vars, runner=stub)

    async def test_when_gwops_is_confirmed_stopped_everything_is_swept(
        self,
        api: FakeTenantApi,
        rig: tenant.RigTenant,
        populated: dict[str, list[str]],
        local_docker: StubDockerRunner,
    ) -> None:
        docker = self._docker(rig, local_docker)
        log = RunLog(rig.run_dir / "run.log", Redactor(), echo=False)
        result = await teardown.stop_sweep_down(rig, docker, log)
        assert result.ok and result.gwops_stopped
        assert api.delete_ids == expected_delete_order(populated)

    async def test_when_gwops_may_still_run_only_the_service_account_is_swept(
        self,
        api: FakeTenantApi,
        rig: tenant.RigTenant,
        populated: dict[str, list[str]],
    ) -> None:
        stub = StubDockerRunner(gwops_running=True)
        docker = self._docker(rig, stub)
        log = RunLog(rig.run_dir / "run.log", Redactor(), echo=False)
        result = await teardown.stop_sweep_down(rig, docker, log)
        assert not result.ok and not result.gwops_stopped
        assert api.delete_ids == [*populated["service_account_key"], *populated["service_account"]]
        assert any("gwops may still be running" in e for e in result.errors)
        assert any(tenant.recovery_command(rig.state_path) in e for e in result.errors)
        assert ["docker", "rm", "-f", f"gwops-it-{RUN_ID}-gwops"] in stub.calls
        assert any(c[1] == "compose" and "down" in c for c in stub.calls)


# --- derived gateway address and engine endpoint in the state file ----------------------------


class TestStateBindings:
    """RunState.from_dict and RigTenant.resume bind a state file to its run id and engine."""

    def _raw(self, **changes: Any) -> dict[str, Any]:
        raw = fresh_state().to_dict()
        raw.update(changes)
        return raw

    @pytest.mark.parametrize(
        "address",
        ["evil.example.test:8443", GATEWAY_ADDRESS.upper(), f"{GATEWAY_ADDRESS}x", ""],
    )
    def test_from_dict_refuses_an_edited_gateway_address(self, address: str) -> None:
        with pytest.raises(guards.GuardError, match="gateway_address"):
            tenant.RunState.from_dict(self._raw(gateway_address=address))

    def test_from_dict_accepts_the_address_derived_from_the_run_id(self) -> None:
        state = tenant.RunState.from_dict(self._raw())
        assert state.gateway_address == seedgen.build_names(RUN_ID).gateway_address

    def test_an_edited_address_cannot_redirect_the_ca_name_rules(self) -> None:
        raw = self._raw(
            gateway_address="evil.example.test:8443",
            created=[{"kind": "ca", "id": "CA-NEW", "name": "gwops-x509-evil.example.test:8443"}],
        )
        with pytest.raises(guards.GuardError):
            tenant.RunState.from_dict(raw)

    async def test_resume_refuses_an_edited_gateway_address_before_any_http(
        self, api: FakeTenantApi, env: guards.RigEnv, tmp_path: Path
    ) -> None:
        path = tmp_path / RUN_ID / tenant.STATE_FILE
        path.parent.mkdir()
        path.write_text(
            json.dumps(self._raw(gateway_address="evil.example.test:8443")), encoding="utf-8"
        )
        with pytest.raises(guards.GuardError, match="gateway_address"):
            await tenant.RigTenant.resume(env, path)
        assert api.calls == []

    def test_the_docker_endpoint_round_trips_through_the_state_file(self, tmp_path: Path) -> None:
        state = fresh_state()
        state.docker_endpoint = "unix:///var/run/docker.sock"
        path = tmp_path / "state.json"
        tenant.save_state(path, state)
        assert (
            json.loads(path.read_text(encoding="utf-8"))["docker_endpoint"] == state.docker_endpoint
        )
        assert tenant.load_state(path).docker_endpoint == "unix:///var/run/docker.sock"

    async def test_start_stores_the_docker_endpoint_in_state_json(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, env: guards.RigEnv, tmp_path: Path
    ) -> None:
        started = await tenant.RigTenant.start(
            env,
            gateway_address=GATEWAY_ADDRESS,
            run_root=tmp_path,
            run_id=RUN_ID,
            client=client,
            docker_endpoint=LOCAL_ENDPOINT,
        )
        assert started.state.docker_endpoint == LOCAL_ENDPOINT
        saved = json.loads(started.state_path.read_text(encoding="utf-8"))
        assert saved["docker_endpoint"] == LOCAL_ENDPOINT

    async def _state_file(self, tmp_path: Path, endpoint: str) -> Path:
        state = fresh_state()
        state.docker_endpoint = endpoint
        path = tmp_path / RUN_ID / tenant.STATE_FILE
        path.parent.mkdir()
        tenant.save_state(path, state)
        return path

    async def test_resume_accepts_the_same_engine_endpoint(
        self, api: FakeTenantApi, env: guards.RigEnv, tmp_path: Path
    ) -> None:
        path = await self._state_file(tmp_path, LOCAL_ENDPOINT)
        resumed = await tenant.RigTenant.resume(env, path, docker_endpoint=LOCAL_ENDPOINT)
        await resumed.aclose()

    @pytest.mark.parametrize("stored", ["unix:///other.sock", ""])
    async def test_resume_refuses_a_different_or_unrecorded_engine_endpoint_before_any_http(
        self, api: FakeTenantApi, env: guards.RigEnv, tmp_path: Path, stored: str
    ) -> None:
        path = await self._state_file(tmp_path, stored)
        with pytest.raises(guards.EngineMismatchError, match="docker endpoint"):
            await tenant.RigTenant.resume(env, path, docker_endpoint=LOCAL_ENDPOINT)
        assert api.calls == []

    def test_the_sweep_cli_refuses_a_different_engine_before_touching_anything(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        local_docker: StubDockerRunner,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = write_state(api, tmp_path, [("web_app", "RES-1", f"{PREFIX}a")])
        state = tenant.load_state(path)
        state.docker_endpoint = "unix:///var/run/docker.sock"
        tenant.save_state(path, state)
        assert tenant.main(["sweep", "--state", str(path)]) == 2
        assert "docker endpoint" in capsys.readouterr().out
        assert api.calls == []
        assert not any(call[1] == "compose" for call in local_docker.calls)

    def test_the_sweep_cli_refuses_an_edited_gateway_address(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        local_docker: StubDockerRunner,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = write_state(api, tmp_path, [])
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["gateway_address"] = "evil.example.test:8443"
        path.write_text(json.dumps(raw), encoding="utf-8")
        assert tenant.main(["sweep", "--state", str(path)]) == 2
        assert api.calls == []
        assert not any(call[1] == "compose" for call in local_docker.calls)


# --- service-account keys are revoked, then deleted, before their account ---------------------


class TestKeySweep:
    """The key step: verify, revoke, delete; then the account can be deleted."""

    async def test_the_key_is_verified_revoked_and_deleted_before_its_account(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        key = populated["service_account_key"][0]
        await rig.sweep()
        ops = [c.op for c in api.calls]
        order = [
            ops.index("RigGetServiceAccountKey"),
            ops.index("RigRevokeServiceAccountKey"),
            ops.index("RigDeleteServiceAccountKey"),
            ops.index("RigDeleteServiceAccount"),
        ]
        assert order == sorted(order)
        assert api.revoke_ids == [key]
        assert api.delete_ids[0] == key
        assert key in [e.object_id for e in rig.state.deleted]
        assert api.keys == {}

    async def test_sweeping_the_account_alone_fails_like_the_live_run(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        """The e15bf66c failure: an active key blocks serviceAccountDelete."""
        with pytest.raises(tenant.SweepError, match="active keys that must be revoked first"):
            await rig.sweep(only_kinds={"service_account"})

    async def test_an_already_revoked_key_skips_the_revoke_and_is_deleted(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        key = populated["service_account_key"][0]
        api.keys[key]["status"] = "REVOKED"
        report = await rig.sweep()
        assert api.revoke_ids == []
        assert key in report.deleted

    async def test_a_revoke_that_reports_already_revoked_counts_as_done(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        key = populated["service_account_key"][0]
        api.revoke_override[key] = mutation_failed(
            "serviceAccountKeyRevoke", "The key has already been revoked."
        )
        report = await rig.sweep()
        assert key in report.deleted
        assert key in api.delete_ids

    async def test_a_revoke_that_says_not_found_means_gone_and_sends_no_delete(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        key = populated["service_account_key"][0]
        api.revoke_override[key] = mutation_failed("serviceAccountKeyRevoke", "Key not found")
        report = await rig.sweep(only_kinds={"service_account_key"})
        assert report.already_gone == [key]
        assert key not in api.delete_ids

    async def test_a_key_that_is_already_gone_is_not_touched(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        key = populated["service_account_key"][0]
        del api.keys[key]
        report = await rig.sweep()
        assert key in report.already_gone
        assert api.revoke_ids == []

    async def test_a_failed_revoke_is_collected_and_the_key_is_not_deleted(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        key = populated["service_account_key"][0]
        api.revoke_override[key] = mutation_failed("serviceAccountKeyRevoke", "permission denied")
        with pytest.raises(tenant.SweepError) as caught:
            await rig.sweep()
        assert key not in api.delete_ids
        assert any(e.startswith("service_account_key") for e in caught.value.errors)

    async def test_a_key_of_another_service_account_is_refused(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        key = populated["service_account_key"][0]
        api.keys[key]["sa"] = "SA-B"
        with pytest.raises(guards.UnrecordedIdError, match="belongs to service account"):
            await rig.sweep()
        assert api.revoke_ids == [] and api.delete_ids == []

    async def test_a_key_of_an_unrecorded_look_alike_account_is_refused(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        key = populated["service_account_key"][0]
        api.collections["service_account"]["SA-LOOK"] = f"{PREFIX}client"
        api.keys[key]["sa"] = "SA-LOOK"
        with pytest.raises(guards.UnrecordedIdError, match="not one the run recorded"):
            await rig.sweep()
        assert api.revoke_ids == []

    def test_verify_delete_target_checks_the_keys_account_name(self) -> None:
        good = {
            "id": "K",
            "name": f"{PREFIX}key",
            "serviceAccount": {"id": "S", "name": f"{PREFIX}client"},
        }
        guards.verify_delete_target(
            "service_account_key",
            good,
            run_id=RUN_ID,
            gateway_address=GATEWAY_ADDRESS,
            remote_network_id=REMOTE_NETWORK_ID,
        )
        for bad in (
            {**good, "serviceAccount": {"id": "S", "name": "ci-bot"}},
            {**good, "serviceAccount": None},
            {**good, "name": "someone-elses-key"},
        ):
            with pytest.raises(guards.UnrecordedIdError):
                guards.verify_delete_target(
                    "service_account_key",
                    bad,
                    run_id=RUN_ID,
                    gateway_address=GATEWAY_ADDRESS,
                    remote_network_id=REMOTE_NETWORK_ID,
                )

    def test_a_partial_sweep_for_a_running_gwops_covers_the_key_and_the_account(self) -> None:
        assert {"service_account_key", "service_account"} == teardown.SERVICE_ACCOUNT_ONLY


class TestKeyDiscovery:
    """A state that lacks the key id still finds and revokes the run account's active keys."""

    def _tenant_objects(self, api: FakeTenantApi) -> None:
        api.collections["service_account"]["SA-RUN"] = f"{PREFIX}client"
        api.keys["KEY-ACTIVE"] = {"name": f"{PREFIX}key", "sa": "SA-RUN", "status": "ACTIVE"}
        api.keys["KEY-REVOKED"] = {"name": f"{PREFIX}old", "sa": "SA-RUN", "status": "REVOKED"}
        api.keys["KEY-ODD"] = {"name": "not-ours", "sa": "SA-RUN", "status": "ACTIVE"}
        api.keys["KEY-OTHER"] = {"name": f"{PREFIX}key", "sa": "SA-B", "status": "ACTIVE"}

    async def test_discover_all_finds_only_active_prefixed_keys_of_the_run_account(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        self._tenant_objects(api)
        found = await rig.discover_all()
        keys = [(kind, i) for kind, i, _name in found if kind == "service_account_key"]
        assert keys == [("service_account_key", "KEY-ACTIVE")]

    async def test_no_key_listing_is_attempted_without_a_run_account(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        api.keys["KEY-OTHER"] = {"name": f"{PREFIX}key", "sa": "SA-B", "status": "ACTIVE"}
        await rig.discover_all()
        assert "RigListServiceAccountKeys" not in [c.op for c in api.calls]

    def test_the_recovery_cli_revokes_and_deletes_a_key_the_state_never_recorded(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        local_docker: StubDockerRunner,
    ) -> None:
        path = write_state(api, tmp_path, [])
        self._tenant_objects(api)
        assert tenant.main(["sweep", "--state", str(path)]) == 1  # KEY-ODD blocks the account
        assert api.revoke_ids == ["KEY-ACTIVE"]
        assert api.delete_ids[0] == "KEY-ACTIVE"

    def test_the_recovery_cli_sweeps_cleanly_when_the_only_key_is_the_runs_own(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        local_docker: StubDockerRunner,
    ) -> None:
        path = write_state(api, tmp_path, [])
        api.collections["service_account"]["SA-RUN"] = f"{PREFIX}client"
        api.keys["KEY-ACTIVE"] = {"name": f"{PREFIX}key", "sa": "SA-RUN", "status": "ACTIVE"}
        assert tenant.main(["sweep", "--state", str(path)]) == 0
        assert api.delete_ids == ["KEY-ACTIVE", "SA-RUN"]
        assert api.keys == {}


def test_a_state_shaped_like_the_failed_live_run_loads_and_plans_key_then_account() -> None:
    """The e15bf66c state: service account and key still recorded, the rest already deleted."""
    run_id = "e15bf66c"
    prefix = f"gwops-it-{run_id}-"
    raw = {
        "version": 1,
        "run_id": run_id,
        "network": NETWORK,
        "remote_network_id": REMOTE_NETWORK_ID,
        "gateway_address": seedgen.build_names(run_id).gateway_address,
        "created": [
            {"kind": "service_account", "id": "SA-1", "name": f"{prefix}client"},
            {"kind": "service_account_key", "id": "KEY-1", "name": f"{prefix}key"},
        ],
        "deleted": [{"kind": "web_app", "id": "RES-1", "name": f"{prefix}plain"}],
        "pre_inventory": dict(PRE_INVENTORY),
        "docker_endpoint": "npipe:////./pipe/dockerDesktopLinuxEngine",
    }
    state = tenant.RunState.from_dict(raw)
    plan = tenant.plan_sweep(state.created)
    assert [s.entry.object_id for s in plan] == ["KEY-1", "SA-1"]


class TestStrictResponses:
    """An absent field is an error; only an explicit null means gone."""

    async def test_fetch_target_treats_only_an_explicit_null_as_gone(
        self, api: FakeTenantApi, client: tenant.GraphQLClient
    ) -> None:
        entry = tenant.CreatedObject("web_app", "RES-1", f"{PREFIX}a")
        api.queue("RigGetResource", lambda: gql({"resource": None}))
        assert await tenant.fetch_target(client, entry) is None

    async def test_fetch_target_refuses_a_response_without_the_field(
        self, api: FakeTenantApi, client: tenant.GraphQLClient
    ) -> None:
        entry = tenant.CreatedObject("web_app", "RES-1", f"{PREFIX}a")
        api.queue("RigGetResource", lambda: gql({}))
        with pytest.raises(tenant.RigApiError, match="no 'resource' field"):
            await tenant.fetch_target(client, entry)

    async def test_a_response_without_the_field_is_a_sweep_error_not_already_gone(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        first_app = populated["web_app"][0]
        api.queue("RigGetResource", lambda: gql({}))
        with pytest.raises(tenant.SweepError) as caught:
            await rig.sweep()
        assert first_app not in api.delete_ids
        assert any(e.startswith(f"web_app {first_app}") for e in caught.value.errors)
        assert populated["web_app"][1] in api.delete_ids

    def test_read_connection_refuses_a_node_that_is_not_an_object(self) -> None:
        data = {"c": {"edges": [{"node": "oops"}], "pageInfo": {"hasNextPage": False}}}
        with pytest.raises(tenant.RigApiError, match="non-object node"):
            tenant.read_connection(data, ("c",), "Op")

    def test_read_connection_refuses_a_malformed_page_info(self) -> None:
        data = {"c": {"edges": [], "pageInfo": "bad"}}
        with pytest.raises(tenant.RigApiError, match="malformed"):
            tenant.read_connection(data, ("c",), "Op")

    async def test_a_listing_with_a_non_object_node_fails_the_inventory(
        self, api: FakeTenantApi, rig: tenant.RigTenant
    ) -> None:
        bad = {
            "remoteNetwork": {
                "resources": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "edges": [{"node": None}],
                }
            }
        }
        api.queue("RigListResources", lambda: gql(bad))
        with pytest.raises(tenant.RigApiError, match="non-object node"):
            await rig.verify_inventory()


class TestKeyOwner:
    """A key's account must be a recorded service account, not any recorded id."""

    async def test_a_key_whose_account_id_is_a_recorded_web_app_id_is_refused(
        self, api: FakeTenantApi, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        key = populated["service_account_key"][0]
        web_app = populated["web_app"][0]
        api.collections["service_account"][web_app] = f"{PREFIX}client"
        api.keys[key]["sa"] = web_app
        with pytest.raises(guards.UnrecordedIdError, match="not one the run recorded"):
            await rig.sweep()
        assert api.revoke_ids == []


class TestInventoryMessage:
    """verify_inventory says so when there was nothing to compare."""

    async def test_it_returns_false_with_no_inventory_and_nothing_recorded(
        self, api: FakeTenantApi, client: tenant.GraphQLClient, env: guards.RigEnv, tmp_path: Path
    ) -> None:
        state = tenant.RunState(
            RUN_ID, NETWORK, REMOTE_NETWORK_ID, GATEWAY_ADDRESS, docker_endpoint=LOCAL_ENDPOINT
        )
        path = tmp_path / RUN_ID / tenant.STATE_FILE
        path.parent.mkdir()
        tenant.save_state(path, state)
        resumed = await tenant.RigTenant.resume(env, path, client=client)
        assert await resumed.verify_inventory() is False
        assert api.calls == []

    async def test_it_returns_true_after_a_real_comparison(self, rig: tenant.RigTenant) -> None:
        assert await rig.verify_inventory() is True

    def test_the_sweep_cli_says_nothing_to_compare_instead_of_matches(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        local_docker: StubDockerRunner,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        state = tenant.RunState(
            RUN_ID, NETWORK, REMOTE_NETWORK_ID, GATEWAY_ADDRESS, docker_endpoint=LOCAL_ENDPOINT
        )
        path = tmp_path / RUN_ID / tenant.STATE_FILE
        path.parent.mkdir()
        tenant.save_state(path, state)
        assert tenant.main(["sweep", "--state", str(path)]) == 0
        out = capsys.readouterr().out
        assert "nothing to compare" in out
        assert "matches" not in out

    def test_the_sweep_cli_still_says_matches_after_a_real_comparison(
        self,
        api: FakeTenantApi,
        tmp_path: Path,
        approved_process_env: None,
        local_docker: StubDockerRunner,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = write_state(api, tmp_path, [])
        assert tenant.main(["sweep", "--state", str(path)]) == 0
        assert "matches the pre-run state" in capsys.readouterr().out


class TestAdminTokenFile:
    """The admin token file is swept like the other secret files."""

    async def test_a_full_sweep_removes_admin_token(
        self, rig: tenant.RigTenant, populated: dict[str, list[str]]
    ) -> None:
        (rig.run_dir / "admin-token").write_text("tok", encoding="utf-8")
        report = await rig.sweep()
        assert not (rig.run_dir / "admin-token").exists()
        assert "admin-token" in report.secret_files_removed
