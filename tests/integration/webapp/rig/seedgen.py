"""Names, seed rendering, PKI SAN plans and compose variables for one rig run; pure functions."""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from . import guards

GATEWAY_PORT = 8443
GWOPS_ENV_FILE = "gwops.env"
CONNECTOR_ENV_FILE = "connector.env"
CLIENT_ENV_FILE = "client.env"
GATORCAST_ENV_FILE = "gatorcast.env"
ENV_FILES = (GWOPS_ENV_FILE, CONNECTOR_ENV_FILE, CLIENT_ENV_FILE, GATORCAST_ENV_FILE)
ADMIN_TOKEN_FILE = "admin-token"
TAP_DIR = "tap"
TAP_LOG_FILE = "ingest.jsonl"
SSH_CA_DIR = "ssh-ca"
SSH_CA_FILE = "ssh-ca.key.pub"
GATORCAST_SERVICE = "gatorcast"
TAP_SERVICE = "ingest-tap"
GATORCAST_PORT = 8080
RECEIVER_URL = f"http://{TAP_SERVICE}:{GATORCAST_PORT}"
DEFAULT_GATORCAST_IMAGE = "ghcr.io/twingate-solutions/gatorcast:latest"
GATORCAST_UI_USER = "rig"
RECORDING_SPOOL_BYTES = 64 * 1024 * 1024
SHIM_STDIO = "/usr/local/bin/gateway-stdio"
SHIM_TEE = "/usr/local/bin/gateway-tee"
SSH_SUFFIX = "ssh"
SSH_TARGET_PORT = 2222
SSH_GATEWAY_USER = "gateway"
PROFILE_GATORCAST = "gatorcast"
PROFILE_SSH = "ssh"
VERIFIER_PORT = 8443
BUNDLE_NAME = "rig-upstream-ca"
BUNDLE_FILE = "/config/webapp-cas/upstream-ca.pem"
IDENTITY_HEADER = "X-Twingate-User"
REWRITE_HEADER = "X-Rig-Rewrite"
GAT_HEADERS = {"Authorization": "Bearer {{jwt}}"}
REWRITE_VALUE = "v2"
WRONG_HOST_SAN = "wrong-host.rig.invalid"

APP_SUFFIXES = ("plain", "vfull", "vca", "vfullwrong", "verifier-a", "verifier-b")
INSECURE_SUFFIX = "insecure"


@dataclass(frozen=True)
class RigNames:
    """Every per-run name: object prefix, hosts, gateway address and compose project."""

    run_id: str
    prefix: str
    domain: str
    project: str
    gateway_host: str
    gateway_address: str
    plain_host: str
    tls_host: str
    alias_host: str
    vca_host: str
    wrongfull_host: str
    insecure_host: str
    verifier_a_host: str
    verifier_b_host: str
    ssh_host: str

    def app_name(self, suffix: str) -> str:
        """The seed and tenant name of a rig web app."""
        return guards.require_prefixed(f"{self.prefix}{suffix}", self.prefix)

    def app_hosts(self) -> tuple[str, ...]:
        """Every host an app or alias is reached by."""
        return (
            self.plain_host,
            self.tls_host,
            self.alias_host,
            self.vca_host,
            self.wrongfull_host,
            self.insecure_host,
            self.verifier_a_host,
            self.verifier_b_host,
        )


def build_names(run_id: str) -> RigNames:
    """Derive every name for `run_id`; the gateway address is unique to the run."""
    prefix = guards.run_prefix(run_id)
    domain = f"{run_id}.rig.test"
    gateway_host = f"{prefix}gw.rig.test"
    return RigNames(
        run_id=run_id,
        prefix=prefix,
        domain=domain,
        project=f"gwops-it-{run_id}",
        gateway_host=gateway_host,
        gateway_address=f"{gateway_host}:{GATEWAY_PORT}",
        plain_host=f"echo-plain.{domain}",
        tls_host=f"echo-tls.{domain}",
        alias_host=f"echo-alias.{domain}",
        vca_host=f"echo-vca.{domain}",
        wrongfull_host=f"echo-wrongfull.{domain}",
        insecure_host=f"echo-insecure.{domain}",
        verifier_a_host=f"verifier-a.{domain}",
        verifier_b_host=f"verifier-b.{domain}",
        ssh_host=f"ssh-target.{domain}",
    )


def pki_sans(names: RigNames) -> dict[str, list[str]]:
    """SANs for the rig PKI: the echo leaf holds the ADDRESS ONLY (never the alias)."""
    return {
        "echo_sans": [names.tls_host],
        "verifier_sans": [names.verifier_a_host, names.verifier_b_host],
        "wrong_host_sans": [WRONG_HOST_SAN],
    }


def _web_apps(names: RigNames) -> list[dict[str, Any]]:
    none = {"tls": "none"}
    return [
        {
            "name": names.app_name("plain"),
            "address": names.plain_host,
            "upstream_tls": "none",
            "downstream": none,
        },
        {
            "name": names.app_name("vfull"),
            "address": names.tls_host,
            "alias": names.alias_host,
            "upstream_tls": "verify_full",
            "downstream": {"tls": "tls13"},
        },
        {
            "name": names.app_name("vca"),
            "address": names.vca_host,
            "upstream_tls": "verify_ca",
            "downstream": none,
        },
        {
            "name": names.app_name("vfullwrong"),
            "address": names.wrongfull_host,
            "upstream_tls": "verify_full",
            "downstream": none,
        },
        {
            "name": names.app_name("verifier-a"),
            "address": f"{names.verifier_a_host}:{VERIFIER_PORT}",
            "upstream_tls": "verify_full",
            "downstream": none,
            "request_headers": dict(GAT_HEADERS),
        },
        {
            "name": names.app_name("verifier-b"),
            "address": f"{names.verifier_b_host}:{VERIFIER_PORT}",
            "upstream_tls": "verify_full",
            "downstream": none,
            "request_headers": dict(GAT_HEADERS),
        },
    ]


def insecure_app_body(names: RigNames) -> dict[str, Any]:
    """The admin-API PUT body for the `insecure` app (the allowlist check target)."""
    return {
        "address": names.insecure_host,
        "upstream_tls": "insecure",
        "downstream": {"tls": "none"},
    }


def rewrite_body(names: RigNames) -> dict[str, Any]:
    """The admin-API PUT body that adds a static rewrite to verifier-a.

    A PUT replaces `request_headers` wholesale, so the GAT `Authorization` rewrite is resent.
    """
    return {
        "address": f"{names.verifier_a_host}:{VERIFIER_PORT}",
        "upstream_tls": "verify_full",
        "downstream": {"tls": "none"},
        "request_headers": {**GAT_HEADERS, REWRITE_HEADER: REWRITE_VALUE},
    }


def render_seed_doc(
    names: RigNames,
    *,
    network: str,
    remote_network_id: str,
    with_bundle: bool,
    allow_insecure_host: bool,
    receiver_url: str | None = None,
    ssh: bool = False,
) -> dict[str, Any]:
    """The rig seed (Mode B) as a dict; the bundle and the insecure allowlist entry are phased."""
    suffixes = [names.plain_host] + ([names.insecure_host] if allow_insecure_host else [])
    proxy: dict[str, Any] = {
        "request_headers": {IDENTITY_HEADER: "{{username}}"},
        "plaintext_upstreams": {"dns_suffixes": suffixes},
        "upstream_tls_probe": True,
    }
    if with_bundle:
        proxy["upstream_ca_bundles"] = [{"name": BUNDLE_NAME, "file": BUNDLE_FILE}]
    document: dict[str, Any] = {
        "twingate": {
            "network": network,
            "host": "twingate.com",
            "remote_network_id": remote_network_id,
            "gateway_address": names.gateway_address,
        },
        "ca": {"x509": {"generate": True}, "ssh": {"generate": True}},
    }
    if ssh:
        address = f"{names.ssh_host}:{SSH_TARGET_PORT}"
        document["ssh_upstreams"] = [{"name": names.app_name(SSH_SUFFIX), "address": address}]
    document["web_apps"] = _web_apps(names)
    document["web_app_proxy"] = proxy
    document["recording"] = (
        {"enabled": True, "receiver_url": receiver_url, "spool_max_bytes": RECORDING_SPOOL_BYTES}
        if receiver_url
        else {"enabled": False}
    )
    document["admin_api"] = {"bind": "0.0.0.0", "port": 8081}
    return document


def render_seed(
    names: RigNames,
    *,
    network: str,
    remote_network_id: str,
    with_bundle: bool,
    allow_insecure_host: bool,
    receiver_url: str | None = None,
    ssh: bool = False,
) -> str:
    """The rig seed as YAML text; holds no secret."""
    doc = render_seed_doc(
        names,
        network=network,
        remote_network_id=remote_network_id,
        with_bundle=with_bundle,
        allow_insecure_host=allow_insecure_host,
        receiver_url=receiver_url,
        ssh=ssh,
    )
    return yaml.safe_dump(doc, sort_keys=False)


def compose_env(
    names: RigNames,
    *,
    run_dir: Path,
    network: str,
    admin_port: int,
    gwops_image: str,
    verifier_expected_id: str = "",
    gatorcast: bool = False,
    gatorcast_image: str = DEFAULT_GATORCAST_IMAGE,
) -> dict[str, str]:
    """Non-secret variables compose.rig.yaml interpolates."""
    return {
        "RIG_PROJECT": names.project,
        "RIG_RUN_DIR": run_dir.resolve().as_posix(),
        "RIG_GWOPS_IMAGE": gwops_image,
        "RIG_ADMIN_PORT": str(admin_port),
        "RIG_GW_HOST": names.gateway_host,
        "RIG_PLAIN_HOST": names.plain_host,
        "RIG_TLS_HOST": names.tls_host,
        "RIG_ALIAS_HOST": names.alias_host,
        "RIG_VCA_HOST": names.vca_host,
        "RIG_WRONGFULL_HOST": names.wrongfull_host,
        "RIG_INSECURE_HOST": names.insecure_host,
        "RIG_VERIFIER_A_HOST": names.verifier_a_host,
        "RIG_VERIFIER_B_HOST": names.verifier_b_host,
        "RIG_TWINGATE_NETWORK": network,
        "RIG_TWINGATE_HOST": "twingate.com",
        "RIG_VERIFIER_EXPECTED_ID": verifier_expected_id,
        "RIG_SSH_HOST": names.ssh_host,
        "RIG_GATEWAY_SHIM": SHIM_TEE if gatorcast else SHIM_STDIO,
        "RIG_GATORCAST_IMAGE": gatorcast_image,
    }


def hold_commands(names: RigNames) -> list[tuple[str, str]]:
    """Ready-to-paste `docker exec` commands (title, command) against every rig app.

    They run curl in the client's network namespace; tls13 apps carry `--cacert`. None holds a
    secret: the GAT is injected by the gateway, never typed.
    """
    curl = f"docker exec {names.project}-curl curl -sS --max-time 25"
    ca = "--cacert /trust/gwops-ca.pem"
    items = [
        ("plain: none/none, expect 200", f"{curl} -i http://{names.plain_host}/"),
        ("vfull: tls13 + verify_full, expect 200", f"{curl} -i {ca} https://{names.tls_host}/"),
        ("vfull via the alias, expect 200", f"{curl} -i {ca} https://{names.alias_host}/"),
        ("vca: verify_ca on a wrong-host leaf, expect 200", f"{curl} -i http://{names.vca_host}/"),
        (
            "vfullwrong: verify_full on the same leaf, expect 502",
            f"{curl} -i http://{names.wrongfull_host}/",
        ),
        ("insecure: allowlisted host, expect 200", f"{curl} -i http://{names.insecure_host}/"),
        (
            "verifier-a: its own GAT, expect 200 and the claims JSON",
            f"{curl} http://{names.verifier_a_host}/ | python -m json.tool",
        ),
        (
            "verifier-b: a GAT for another app, expect 401",
            f"{curl} -i http://{names.verifier_b_host}/",
        ),
        (
            "why verifier-b said 401 (look for resource_id_mismatch)",
            f"docker logs {names.project}-verifier-b",
        ),
    ]
    return items


def single_quoted_env_line(name: str, value: str) -> str:
    """A compose env-file line with a literal (single-quoted) value; refuses a value with `'`."""
    if "'" in value or "\n" in value or "\r" in value:
        raise guards.GuardError(f"{name} cannot be written to an env file (quote or newline).")
    return f"{name}='{value}'"


def gwops_env_lines(
    api_key: str, admin_token: str, recording_token: str | None = None
) -> list[str]:
    """The gwops env-file lines: the only place the API key and admin token are written."""
    lines = [
        single_quoted_env_line("TWINGATE_API_KEY", api_key),
        single_quoted_env_line("GWOPS_ADMIN_TOKEN", admin_token),
    ]
    if recording_token is not None:
        lines.append(single_quoted_env_line("GWOPS_RECORDING_TOKEN", recording_token))
    return lines


def gatorcast_env_lines(ingest_token: str, ui_password: str) -> list[str]:
    """The Gatorcast env-file lines: its ingest bearer token and UI password."""
    return [
        single_quoted_env_line("INGEST_TOKEN", ingest_token),
        single_quoted_env_line("UI_AUTH_PASSWORD", ui_password),
    ]


@dataclass(frozen=True)
class ExpectedWebApp:
    """What the gwops object should say for one rig web app (configured state)."""

    name: str
    downstream_tls: str
    downstream_port: int
    upstream_tls: str
    upstream_port: int


def _expected(
    name: str, address: str, upstream_tls: str, downstream: dict[str, Any]
) -> ExpectedWebApp:
    host, _sep, port = address.partition(":")
    tls = str(downstream.get("tls", "tls13"))
    return ExpectedWebApp(
        name=name,
        downstream_tls=tls,
        downstream_port=int(downstream.get("port") or (443 if tls == "tls13" else 80)),
        upstream_tls=upstream_tls,
        upstream_port=int(port) if port else (80 if upstream_tls == "none" else 443),
    )


def expected_webapps(names: RigNames) -> dict[str, ExpectedWebApp]:
    """Expected gwops object per web-app host (address without port), insecure app included."""
    result = {
        app["address"].partition(":")[0]: _expected(
            app["name"], app["address"], app["upstream_tls"], app["downstream"]
        )
        for app in _web_apps(names)
    }
    body = insecure_app_body(names)
    result[body["address"]] = _expected(
        names.app_name(INSECURE_SUFFIX), body["address"], body["upstream_tls"], body["downstream"]
    )
    return result


def sanitized_child_env(
    base: Mapping[str, str], extra: Mapping[str, str] | None = None
) -> dict[str, str]:
    """A subprocess environment without any IT_* variable, plus `extra`."""
    env = {key: value for key, value in base.items() if not key.upper().startswith("IT_")}
    env.update(extra or {})
    return env
