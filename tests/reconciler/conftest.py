"""Shared fixtures for reconciler tests: fake TG GraphQL server, stub process, wiring.

The fake TG server is a stateful in-memory tenant behind respx: it answers the exact
operations `gwops.tgapi.ops` issues (dispatched on operation name) and records every
call, so tests can assert both the resulting tenant state and which mutations ran.
The stub gateway process records lifecycle calls without spawning anything; tests
that need a real child use the `fake_gateway`-style launcher (`gateway_binary`).
"""

import hashlib
import json
import re
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA256 as _SHA256

from gwops.supervisor.process import ProcState

_FAKE_GATEWAY = Path(__file__).parent.parent / "fakes" / "fake_gateway.py"

_TG_URL = "https://acme.twingate.com/api/graphql/"

_OPERATION_RE = re.compile(r"^\s*(?:query|mutation)\s+([A-Za-z_]\w*)")


@dataclass
class FakeResource:
    """One resource as the fake tenant stores it."""

    id: str
    kind: str  # "ssh" | "kubernetes" | "webapp"
    name: str
    address: str
    gateway_id: str
    upstream_port: int
    groups: set[str] = field(default_factory=set)
    security_policy: str | None = None
    settings: dict[str, Any] = field(default_factory=dict)
    """Kind-specific settings: merged into the listed node and set by the settings update."""
    web: dict[str, Any] = field(default_factory=dict)
    """A web app's alias, upstream TLS mode, downstream leg and header rewrites."""


@dataclass
class FakeTGServer:
    """A stateful in-memory Twingate tenant answering the ops' GraphQL operations."""

    resources: dict[str, FakeResource] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)
    gateway_bindings: list[dict[str, Any]] = field(default_factory=list)
    remote_network_id: str = "rn-1"
    gateways: dict[str, str] = field(default_factory=dict)  # gateway id -> address
    created_gateways: list[dict[str, Any]] = field(default_factory=list)  # CreateGateway vars
    fail: bool = False  # when True, every call returns HTTP 400 (no client retries)
    fail_ops: set[str] = field(default_factory=set)  # operation names that return 400
    groups: dict[str, str] = field(default_factory=dict)  # group id -> name
    policies: dict[str, str] = field(default_factory=dict)  # security policy id -> name
    access_updates: list[dict[str, Any]] = field(default_factory=list)  # UpdateResourceAccess
    settings_updates: list[dict[str, Any]] = field(default_factory=list)  # Update*Settings vars
    webapp_updates: list[dict[str, Any]] = field(default_factory=list)  # UpdateWebAppResource vars
    generic_updates_on_web_apps: list[str] = field(default_factory=list)
    """Operation names of generic ``resourceUpdate`` calls that targeted a web-app id."""
    # operation name -> how many more of its requests answer HTTP 429 (with a 1 s
    # Retry-After) before the operation is served normally. Throttled attempts are
    # recorded in `calls` but never reach `_dispatch`, so tenant state is untouched.
    throttle_ops: dict[str, int] = field(default_factory=dict)
    x509_cas: dict[str, tuple[str, str]] = field(default_factory=dict)
    """X.509 CA id -> (name, fingerprint as the tenant spells it: uppercase, colon-separated)."""
    gateway_x509: dict[str, str] = field(default_factory=dict)  # gateway id -> bound X.509 CA id
    created_x509_cas: list[dict[str, Any]] = field(default_factory=list)  # CreateX509CA vars
    _counter: int = 0

    def add_x509_ca(
        self, name: str, fingerprint_hex: str, ca_id: str | None = None
    ) -> str:
        """Seed an X.509 CA; `fingerprint_hex` is stored uppercase and colon-separated."""
        if ca_id is None:
            self._counter += 1
            ca_id = f"ca-x-{self._counter}"
        pairs = [fingerprint_hex[i : i + 2] for i in range(0, len(fingerprint_hex), 2)]
        self.x509_cas[ca_id] = (name, ":".join(pairs).upper())
        return ca_id

    def bind_gateway(self, gateway_id: str, ca_id: str) -> None:
        """Bind a gateway to a seeded X.509 CA (the tenant's view, as `gateway.x509CA`)."""
        self.gateway_x509[gateway_id] = ca_id

    def add_group(self, name: str, group_id: str | None = None) -> str:
        """Seed a tenant group (names need not be unique, like the real API)."""
        group_id = group_id or f"g-{len(self.groups) + 1}"
        self.groups[group_id] = name
        return group_id

    def add_policy(self, name: str, policy_id: str | None = None) -> str:
        """Seed a tenant security policy."""
        policy_id = policy_id or f"p-{len(self.policies) + 1}"
        self.policies[policy_id] = name
        return policy_id

    def lookups(self) -> list[str]:
        """The name/id lookup calls made so far (resolution traffic)."""
        return [
            c for c in self.calls
            if c in ("FindGroupsByName", "FindSecurityPoliciesByName", "GetGroup",
                     "GetSecurityPolicy")
        ]

    def add_resource(
        self,
        kind: str,
        name: str,
        address: str,
        gateway_id: str,
        upstream_port: int | None = None,
    ) -> str:
        """Seed a pre-existing tenant resource (e.g. an unmanaged stranger).

        `upstream_port` defaults to the port Twingate itself would assign (22 for SSH,
        443 for Kubernetes) when a create omits ``upstream``.
        """
        if upstream_port is None:
            upstream_port = 22 if kind == "ssh" else 443
        self._counter += 1
        resource_id = f"r-{self._counter}"
        self.resources[resource_id] = FakeResource(
            id=resource_id,
            kind=kind,
            name=name,
            address=address,
            gateway_id=gateway_id,
            upstream_port=upstream_port,
        )
        return resource_id

    def add_gateway(self, address: str, gateway_id: str | None = None) -> str:
        """Seed a pre-existing gateway (for Mode B adoption tests)."""
        if gateway_id is None:
            self._counter += 1
            gateway_id = f"gw-{self._counter}"
        self.gateways[gateway_id] = address
        return gateway_id

    def add_web_app(
        self,
        name: str,
        address: str,
        gateway_id: str,
        *,
        upstream_port: int = 443,
        upstream_tls: str = "VERIFY_FULL",
        downstream_port: int = 443,
        downstream_tls: str = "TLS13",
        alias: str | None = None,
        rewrites: list[dict[str, str]] | None = None,
    ) -> str:
        """Seed a pre-existing web app with every setting the listing reports."""
        resource_id = self.add_resource("webapp", name, address, gateway_id, upstream_port)
        self.resources[resource_id].web = {
            "alias": alias,
            "upstream_tls": upstream_tls,
            "downstream": {"port": downstream_port, "tlsMode": downstream_tls},
            "rewrites": list(rewrites or []),
        }
        return resource_id

    @staticmethod
    def _node(r: FakeResource, typename: str) -> dict[str, Any]:
        """One listed resource node as the ``ListResources`` query selects it."""
        node: dict[str, Any] = {
            "__typename": typename,
            "id": r.id,
            "name": r.name,
            "address": {"value": r.address},
            "gateway": {"id": r.gateway_id},
            "upstream": {"port": r.upstream_port},
            **r.settings,
        }
        if r.kind == "webapp":
            node["upstream"]["tlsMode"] = r.web["upstream_tls"]
            node["downstream"] = dict(r.web["downstream"])
            node["alias"] = r.web["alias"]
            node["requestHeaderRewrites"] = list(r.web["rewrites"])
        return node

    def _gateway_node(self, gateway_id: str, address: str) -> dict[str, Any]:
        """One listed gateway, as the ``ListGateways`` query selects it."""
        return {"id": gateway_id, "address": address}

    # --- respx side effect -----------------------------------------------------------

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        query = str(body["query"])
        variables: dict[str, Any] = body.get("variables") or {}
        match = _OPERATION_RE.match(query)
        op = match.group(1) if match else "anonymous"
        self.calls.append(op)
        if self.throttle_ops.get(op, 0) > 0:
            self.throttle_ops[op] -= 1
            return httpx.Response(
                429,
                headers={"Retry-After": "1"},
                json={
                    "errors": [
                        {"message": "Request was throttled. Expected available in 1 seconds."}
                    ]
                },
            )
        if self.fail:
            return httpx.Response(400, json={"errors": [{"message": "tenant unreachable"}]})
        if op in self.fail_ops:
            return httpx.Response(400, json={"errors": [{"message": f"{op} rejected"}]})
        data = self._dispatch(op, variables)
        return httpx.Response(200, json={"data": data})

    def _dispatch(self, op: str, variables: dict[str, Any]) -> dict[str, Any]:
        if op == "ListResources":
            typename = {
                "ssh": "SSHResource",
                "kubernetes": "KubernetesResource",
                "webapp": "WebAppResource",
            }
            return {
                "resources": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "edges": [
                        {"node": self._node(r, typename[r.kind])}
                        for r in self.resources.values()
                    ],
                }
            }
        if op == "GatewayRemoteNetwork":
            return {"gateway": {"remoteNetwork": {"id": self.remote_network_id}}}
        if op in ("CreateSSHResource", "CreateKubernetesResource"):
            kind = "ssh" if op == "CreateSSHResource" else "kubernetes"
            upstream = variables.get("upstream")
            resource_id = self.add_resource(
                kind, str(variables["name"]), str(variables["address"]),
                str(variables["gatewayId"]),
                int(upstream["port"]) if upstream is not None else None,
            )
            created = self.resources[resource_id]
            created.groups = set(variables.get("groupIds") or [])
            created.security_policy = variables.get("securityPolicyId")
            field_name = "sshResourceCreate" if kind == "ssh" else "kubernetesResourceCreate"
            return {field_name: {"ok": True, "error": None, "entity": {"id": resource_id}}}
        if op == "CreateWebAppResource":
            upstream = variables["upstream"]
            resource_id = self.add_web_app(
                str(variables["name"]),
                str(variables["address"]),
                str(variables["gatewayId"]),
                upstream_port=int(upstream["port"]),
                upstream_tls=str(upstream["tlsMode"]),
                downstream_port=int(variables["downstream"]["port"]),
                downstream_tls=str(variables["downstream"]["tlsMode"]),
                alias=variables.get("alias"),
                rewrites=variables.get("requestHeaderRewrites"),
            )
            created = self.resources[resource_id]
            created.groups = set(variables.get("groupIds") or [])
            created.security_policy = variables.get("securityPolicyId")
            return {
                "webAppResourceCreate": {"ok": True, "error": None, "entity": {"id": resource_id}}
            }
        if op == "UpdateWebAppResource":
            self.webapp_updates.append(dict(variables))
            resource = self.resources.get(str(variables["id"]))
            if resource is None or resource.kind != "webapp":
                return {"webAppResourceUpdate": {"ok": False, "error": "resource not found"}}
            if "address" in variables:
                resource.address = str(variables["address"])
            if "alias" in variables:
                resource.web["alias"] = variables["alias"]
            if "upstream" in variables:
                resource.upstream_port = int(variables["upstream"]["port"])
                resource.web["upstream_tls"] = str(variables["upstream"]["tlsMode"])
            if "downstream" in variables:
                resource.web["downstream"] = dict(variables["downstream"])
            if "requestHeaderRewrites" in variables:
                resource.web["rewrites"] = list(variables["requestHeaderRewrites"])
            resource.groups |= set(variables.get("addedGroupIds") or [])
            resource.groups -= set(variables.get("removedGroupIds") or [])
            if "securityPolicyId" in variables:
                resource.security_policy = variables["securityPolicyId"]
            if "gatewayId" in variables:
                resource.gateway_id = str(variables["gatewayId"])
            return {"webAppResourceUpdate": {"ok": True, "error": None}}
        if op in ("UpdateResourceAddress", "UpdateResourceAccess"):
            target = self.resources.get(str(variables["id"]))
            if target is not None and target.kind == "webapp":
                # The real API rejects the generic mutation for a web-app id.
                self.generic_updates_on_web_apps.append(op)
                return {"resourceUpdate": {"ok": False, "error": "not a network resource"}}
        if op == "UpdateResourceAddress":
            resource = self.resources.get(str(variables["id"]))
            if resource is None:
                return {"resourceUpdate": {"ok": False, "error": "resource not found"}}
            resource.address = str(variables["address"])
            return {"resourceUpdate": {"ok": True, "error": None}}
        if op in ("UpdateSSHResourceUpstream", "UpdateKubernetesResourceUpstream"):
            field_name = (
                "sshResourceUpdate"
                if op == "UpdateSSHResourceUpstream"
                else "kubernetesResourceUpdate"
            )
            resource = self.resources.get(str(variables["id"]))
            if resource is None:
                return {field_name: {"ok": False, "error": "resource not found"}}
            resource.upstream_port = int(variables["upstream"]["port"])
            return {field_name: {"ok": True, "error": None}}
        if op in ("UpdateSSHResourceSettings", "UpdateKubernetesResourceSettings"):
            field_name = (
                "sshResourceUpdate"
                if op == "UpdateSSHResourceSettings"
                else "kubernetesResourceUpdate"
            )
            self.settings_updates.append(dict(variables))
            resource = self.resources.get(str(variables["id"]))
            if resource is None:
                return {field_name: {"ok": False, "error": "resource not found"}}
            changes = {k: v for k, v in variables.items() if k != "id"}
            if "upstream" in changes:
                resource.upstream_port = int(changes.pop("upstream")["port"])
            resource.settings.update(changes)
            return {field_name: {"ok": True, "error": None}}
        if op in ("UpdateSSHResourceSettings", "UpdateKubernetesResourceSettings"):
            field_name = (
                "sshResourceUpdate"
                if op == "UpdateSSHResourceSettings"
                else "kubernetesResourceUpdate"
            )
            self.settings_updates.append(dict(variables))
            resource = self.resources.get(str(variables["id"]))
            if resource is None:
                return {field_name: {"ok": False, "error": "resource not found"}}
            changes = {k: v for k, v in variables.items() if k != "id"}
            if "upstream" in changes:
                resource.upstream_port = int(changes.pop("upstream")["port"])
            resource.settings.update(changes)
            return {field_name: {"ok": True, "error": None}}
        if op == "UpdateResourceAccess":
            self.access_updates.append(dict(variables))
            resource = self.resources.get(str(variables["id"]))
            if resource is None:
                return {"resourceUpdate": {"ok": False, "error": "resource not found"}}
            resource.groups |= set(variables.get("addedGroupIds") or [])
            resource.groups -= set(variables.get("removedGroupIds") or [])
            if "securityPolicyId" in variables:
                resource.security_policy = variables["securityPolicyId"]
            return {"resourceUpdate": {"ok": True, "error": None}}
        if op in ("FindGroupsByName", "FindSecurityPoliciesByName"):
            table = self.groups if op == "FindGroupsByName" else self.policies
            root = "groups" if op == "FindGroupsByName" else "securityPolicies"
            wanted = variables["filter"]["name"]["eq"]
            return {
                root: {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "edges": [
                        {"node": {"id": oid, "name": name}}
                        for oid, name in table.items()
                        if name == wanted
                    ],
                }
            }
        if op in ("GetGroup", "GetSecurityPolicy"):
            table = self.groups if op == "GetGroup" else self.policies
            root = "group" if op == "GetGroup" else "securityPolicy"
            oid = str(variables["id"])
            return {root: {"id": oid, "name": table[oid]} if oid in table else None}
        if op == "DeleteResource":
            if self.resources.pop(str(variables["id"]), None) is None:
                return {"resourceDelete": {"ok": False, "error": "resource not found"}}
            return {"resourceDelete": {"ok": True, "error": None}}
        if op == "CreateX509CA":
            self._counter += 1
            ca_id = f"ca-x-{self._counter}"
            self.created_x509_cas.append(dict(variables))
            fingerprint = _pem_sha256(str(variables["certificate"]))
            self.add_x509_ca(str(variables["name"]), fingerprint, ca_id)
            return {
                "x509CertificateAuthorityCreate": {
                    "ok": True, "error": None, "entity": {"id": ca_id}
                }
            }
        if op == "GetGatewayX509CA":
            gateway_id = str(variables["id"])
            bound = self.gateway_x509.get(gateway_id)
            ca = None
            if bound is not None:
                ca = {"id": bound, "fingerprint": self.x509_cas[bound][1]}
            return {"gateway": {"id": gateway_id, "x509CA": ca}}
        if op == "FindX509CAsByFingerprint":
            return {
                "certificateAuthorities": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "edges": [
                        {
                            "node": {
                                "__typename": "X509CertificateAuthority",
                                "id": ca_id,
                                "name": name,
                                "fingerprint": fingerprint,
                            }
                        }
                        for ca_id, (name, fingerprint) in self.x509_cas.items()
                    ],
                }
            }
        if op == "CreateSSHCA":
            self._counter += 1
            return {
                "sshCertificateAuthorityCreate": {
                    "ok": True, "error": None, "entity": {"id": f"ca-s-{self._counter}"}
                }
            }
        if op == "UpdateGateway":
            self.gateway_bindings.append(dict(variables))
            if variables.get("x509CAId") is not None:
                self.gateway_x509[str(variables["id"])] = str(variables["x509CAId"])
            return {"gatewayUpdate": {"ok": True, "error": None}}
        if op == "ResolveRemoteNetwork":
            name = variables["filter"]["name"]["eq"]
            return {
                "remoteNetworks": {
                    "edges": [{"node": {"id": self.remote_network_id, "name": name}}]
                }
            }
        if op == "ListGateways":
            return {
                "remoteNetwork": {
                    "gateways": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "edges": [
                            {"node": self._gateway_node(gid, addr)}
                            for gid, addr in self.gateways.items()
                        ],
                    }
                }
            }
        if op == "CreateGateway":
            self._counter += 1
            gateway_id = f"gw-{self._counter}"
            self.gateways[gateway_id] = str(variables["address"])
            self.created_gateways.append(dict(variables))
            if variables.get("x509CAId") is not None:
                self.gateway_x509[gateway_id] = str(variables["x509CAId"])
            return {"gatewayCreate": {"ok": True, "error": None, "entity": {"id": gateway_id}}}
        raise AssertionError(f"fake TG server got an unexpected operation: {op}")


def _pem_sha256(pem: str) -> str:
    """Lowercase hex SHA-256 of a PEM certificate's DER (the tenant's fingerprint basis)."""
    try:
        return x509.load_pem_x509_certificate(pem.encode("ascii")).fingerprint(
            _SHA256()
        ).hex()
    except ValueError:
        return hashlib.sha256(pem.encode("utf-8")).hexdigest()


@pytest.fixture
def tg_server() -> Iterator[FakeTGServer]:
    """A fake TG tenant mounted at the acme network URL via respx."""
    server = FakeTGServer()
    with respx.mock(assert_all_called=False) as router:
        router.post(_TG_URL).mock(side_effect=server.handler)
        yield server


class StubProcess:
    """Records GatewayProcess lifecycle calls without spawning any child."""

    def __init__(self) -> None:
        self.state = ProcState.STOPPED
        self.calls: list[str] = []
        self.last_rolled_back_config: str | None = None

    async def start(self) -> None:
        self.calls.append("start")
        self.state = ProcState.RUNNING

    async def drain_restart(self, timeout: float = 30.0) -> None:
        self.calls.append("drain_restart")
        self.state = ProcState.RUNNING

    async def stop(self, timeout: float = 30.0) -> None:
        self.calls.append("stop")
        self.state = ProcState.STOPPED


@pytest.fixture
def gateway_binary(tmp_path: Path) -> Callable[..., Path]:
    """Factory for a launchable fake gateway whose pre-flight verdict is fixed.

    Mirrors tests/supervisor/conftest.py's launcher (a `.cmd` shim on Windows, an
    executable `sh` script on POSIX) plus the ``FAKE_GW_REJECT_CONFIG`` knob the
    reconciler's render pre-flight step exercises (`validate_config_by_spawn`).
    """

    counter = [0]

    def _make(*, reject: bool = False, interval: float = 0.05) -> Path:
        counter[0] += 1
        env = {
            "FAKE_GW_REJECT_CONFIG": "1" if reject else "0",
            "FAKE_GW_INTERVAL": str(interval),
        }
        name = f"fake-gateway-{counter[0]}"
        if sys.platform == "win32":
            launcher = tmp_path / f"{name}.cmd"
            lines = [f"@set {key}={value}" for key, value in env.items()]
            lines.append(f'@"{sys.executable}" "{_FAKE_GATEWAY}" %*')
            launcher.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")
        else:
            launcher = tmp_path / name
            lines = ["#!/bin/sh"]
            lines += [f"export {key}='{value}'" for key, value in env.items()]
            lines.append(f'exec "{sys.executable}" "{_FAKE_GATEWAY}" "$@"')
            launcher.write_text("\n".join(lines) + "\n", encoding="utf-8")
            launcher.chmod(launcher.stat().st_mode | 0o111)
        return launcher

    return _make
