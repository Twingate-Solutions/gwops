"""Tenant-safety guards for the live rig; pure functions, no network, no secrets in messages."""

import os
import re
import secrets
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field

ENV_API_KEY = "IT_TWINGATE_API_KEY"
ENV_NETWORK = "IT_TWINGATE_NETWORK"
ENV_REMOTE_NETWORK_ID = "IT_TWINGATE_REMOTE_NETWORK_ID"
# The operator's explicit approval: each must equal its counterpart exactly, so the rig only
# writes to a tenant and remote network the operator named twice.
ENV_APPROVED_NETWORK = "IT_APPROVED_NETWORK"
ENV_APPROVED_REMOTE_NETWORK_ID = "IT_APPROVED_REMOTE_NETWORK_ID"
REQUIRED_ENV = (
    ENV_API_KEY,
    ENV_NETWORK,
    ENV_REMOTE_NETWORK_ID,
    ENV_APPROVED_NETWORK,
    ENV_APPROVED_REMOTE_NETWORK_ID,
)

PREFIX_ROOT = "gwops-it-"
_RUN_ID_RE = re.compile(r"[a-z0-9]{6,16}")
_API_KEY_RE = re.compile(r"[\x21-\x7e]+")
_SHOWN_MAX = 64


class GuardError(Exception):
    """A tenant-safety guard refused; the message says what to fix and never holds the API key."""


class EnvError(GuardError):
    """A required IT_* variable is unset, empty or malformed."""


class ApprovedPairError(GuardError):
    """The configured network or remote-network id is not the pair the operator approved."""


class GatewayAddressInUseError(GuardError):
    """A gateway with the run's address already exists, so Mode B would adopt it."""


class UnrecordedIdError(GuardError):
    """An id the run did not record was about to be acted on."""


class EngineMismatchError(GuardError):
    """The docker engine differs from the one the run state was written for."""


class PreexistingIdError(GuardError):
    """An id that existed before the run was about to be recorded as run-created."""


@dataclass(frozen=True)
class RigEnv:
    """Validated rig environment; the API key stays out of repr.

    The approved_* fields default to empty, which no real network or id equals, so a hand-built
    environment without the operator's approval is refused.
    """

    api_key: str = field(repr=False)
    network: str
    remote_network_id: str
    approved_network: str = ""
    approved_remote_network_id: str = ""


def _shown(value: str, secret: str) -> str:
    """Quote `value` for a message, masking it when it equals the API key."""
    if secret and secret in value:
        return "'<masked>'"
    return repr(value if len(value) <= _SHOWN_MAX else value[:_SHOWN_MAX] + "...")


def require_env(environ: Mapping[str, str] | None = None) -> RigEnv:
    """Return the rig environment, refusing on any unset/empty variable or non-approved pair."""
    env = os.environ if environ is None else environ
    missing = [name for name in REQUIRED_ENV if not env.get(name, "").strip()]
    if missing:
        raise EnvError(
            "Refusing to run: unset or empty environment variable(s): "
            f"{', '.join(missing)}. Set all of {', '.join(REQUIRED_ENV)}."
        )
    api_key = env[ENV_API_KEY]
    if not _API_KEY_RE.fullmatch(api_key):
        raise EnvError(
            f"Refusing to run: {ENV_API_KEY} contains whitespace or non-printable characters."
        )
    network = env[ENV_NETWORK]
    remote_network_id = env[ENV_REMOTE_NETWORK_ID]
    approved_network = env[ENV_APPROVED_NETWORK]
    approved_remote_network_id = env[ENV_APPROVED_REMOTE_NETWORK_ID]
    require_approved_pair(
        network, remote_network_id, approved_network, approved_remote_network_id, secret=api_key
    )
    return RigEnv(
        api_key=api_key,
        network=network,
        remote_network_id=remote_network_id,
        approved_network=approved_network,
        approved_remote_network_id=approved_remote_network_id,
    )


def require_approved_pair(
    network: str,
    remote_network_id: str,
    approved_network: str,
    approved_remote_network_id: str,
    *,
    secret: str = "",
) -> None:
    """Raise ApprovedPairError unless both values equal the operator's approved values exactly.

    An empty approved value never matches, so a missing approval is a refusal.
    """
    problems: list[str] = []
    if not approved_network or network != approved_network:
        problems.append(
            f"network {_shown(network, secret)} is not the approved tenant "
            f"{_shown(approved_network, secret)}"
        )
    if not approved_remote_network_id or remote_network_id != approved_remote_network_id:
        problems.append(
            f"remote network id {_shown(remote_network_id, secret)} is not the approved "
            f"id {_shown(approved_remote_network_id, secret)}"
        )
    if problems:
        raise ApprovedPairError(
            f"Refusing to run: {'; '.join(problems)}. Set {ENV_APPROVED_NETWORK} and "
            f"{ENV_APPROVED_REMOTE_NETWORK_ID} to the exact tenant and remote network the rig "
            "may write to."
        )


def require_same_pair(state_network: str, state_remote_network_id: str, env: RigEnv) -> None:
    """Refuse when a run-state file was written for a different network or remote network."""
    if (state_network, state_remote_network_id) != (env.network, env.remote_network_id):
        raise ApprovedPairError(
            "Refusing to sweep: the run state was written for "
            f"{state_network!r} / {state_remote_network_id!r}, not the configured "
            f"{env.network!r} / {env.remote_network_id!r}."
        )


def require_same_engine(state_endpoint: str, current_endpoint: str) -> None:
    """Refuse to sweep through a different docker engine than the run was started on."""
    if not state_endpoint or state_endpoint != current_endpoint:
        raise EngineMismatchError(
            "Refusing to sweep: the run state was written for docker endpoint "
            f"{state_endpoint or '(none recorded)'!r}, but the active endpoint is "
            f"{current_endpoint!r}."
        )


def check_gateway_address_free(
    gateways: Iterable[tuple[str, str]], gateway_address: str, *, remote_network_id: str
) -> None:
    """Abort when any (id, address) gateway already has `gateway_address` (Mode B adoption)."""
    wanted = gateway_address.strip().lower()
    if not wanted:
        raise GatewayAddressInUseError("Refusing to run: the run's gateway_address is empty.")
    clashes = [gid for gid, address in gateways if address.strip().lower() == wanted]
    if clashes:
        raise GatewayAddressInUseError(
            f"Refusing to run: gateway(s) {', '.join(clashes)} in remote network "
            f"{remote_network_id!r} already use address {gateway_address!r}; gwops Mode B would "
            "adopt an existing gateway. Pick a different per-run gateway_address."
        )


def new_run_id() -> str:
    """A fresh lowercase-hex run id."""
    return secrets.token_hex(4)


def run_prefix(run_id: str) -> str:
    """The object-name prefix `gwops-it-<run id>-`, validating the run id."""
    if not _RUN_ID_RE.fullmatch(run_id):
        raise GuardError(f"Invalid run id {run_id!r}: expected 6-16 lowercase letters or digits.")
    return f"{PREFIX_ROOT}{run_id}-"


def require_prefixed(name: str, prefix: str) -> str:
    """Return `name` if it starts with the run prefix, else refuse to create it."""
    if not name.startswith(prefix):
        raise GuardError(f"Refusing to create {name!r}: names must start with {prefix!r}.")
    return name


def require_not_preexisting(kind: str, object_id: str, preexisting: Collection[str]) -> None:
    """Refuse to record `object_id` as run-created when the pre-run inventory already had it."""
    if object_id in preexisting:
        raise PreexistingIdError(
            f"Refusing to record {kind} id {object_id}: it existed before the run and is "
            "never swept."
        )


def require_recorded(kind: str, object_ids: Iterable[str], recorded: Collection[str]) -> list[str]:
    """Return `object_ids` as a list, refusing any id not in `recorded` (never touch others)."""
    ids = list(object_ids)
    foreign = [oid for oid in ids if oid not in recorded]
    if foreign:
        raise UnrecordedIdError(
            f"Refusing to act on {kind} id(s) the run did not record: {', '.join(foreign)}."
        )
    return ids


# --- names the run owns, and pre-delete verification -------------------------------------

_ADOPTION_RE = re.compile(r"adopted existing gateway", re.IGNORECASE)
_LOCAL_ENDPOINT_SCHEMES = ("unix://", "npipe://")


def connector_name(run_id: str) -> str:
    """The connector's name, `<prefix>connector`."""
    return f"{run_prefix(run_id)}connector"


def ssh_resource_name(run_id: str) -> str:
    """The SSH resource's name, `<prefix>ssh`."""
    return f"{run_prefix(run_id)}ssh"


def service_account_name(run_id: str) -> str:
    """The service account's name, `<prefix>client`."""
    return f"{run_prefix(run_id)}client"


def derived_ca_names(gateway_address: str) -> tuple[str, str]:
    """The names gwops gives the X.509 and SSH CAs it registers for `gateway_address`."""
    address = gateway_address.strip().lower()
    return f"gwops-x509-{address}", f"gwops-ssh-{address}"


def _name_rule_problem(kind: str, name: str, run_id: str, gateway_address: str) -> str | None:
    """Why `name` is not an acceptable name for a run-owned `kind`, or None."""
    prefix = run_prefix(run_id)
    x509_name, ssh_name = derived_ca_names(gateway_address)
    if kind in ("web_app", "ssh", "connector", "service_account_key"):
        return None if name.startswith(prefix) and name != prefix else f"must start with {prefix!r}"
    if kind == "service_account":
        wanted = service_account_name(run_id)
        return None if name == wanted else f"must be {wanted!r}"
    if kind == "gateway":
        wanted = gateway_address.strip().lower()
        return None if name.strip().lower() == wanted else f"must be the run's address {wanted!r}"
    if kind in ("ca", "ssh_ca"):
        wanted = x509_name if kind == "ca" else ssh_name
        return None if name == wanted else f"must be {wanted!r}"
    return f"unknown kind {kind!r}"


def validate_recorded_name(kind: str, name: str, *, run_id: str, gateway_address: str) -> None:
    """Refuse a name no run-created object of `kind` can have."""
    problem = _name_rule_problem(kind, name, run_id, gateway_address)
    if problem is not None:
        raise UnrecordedIdError(f"Refusing {kind} named {name!r}: the name {problem}.")


def verify_delete_target(
    kind: str,
    node: Mapping[str, object],
    *,
    run_id: str,
    gateway_address: str,
    remote_network_id: str,
) -> None:
    """Refuse to delete a live object whose name or remote network is not the run's.

    `node` is the object fetched by id: `name` (or `address` for a gateway) and, for web apps,
    connectors and gateways, `remoteNetwork.id`.
    """
    label = str(node.get("id", "?"))
    name = node.get("address" if kind == "gateway" else "name")
    if not isinstance(name, str):
        raise UnrecordedIdError(f"Refusing to delete {kind} {label}: it has no readable name.")
    problem = _name_rule_problem(kind, name, run_id, gateway_address)
    if problem is not None:
        raise UnrecordedIdError(
            f"Refusing to delete {kind} {label}: live name {name!r} {problem}. "
            "Nothing further was deleted."
        )
    if kind == "service_account_key":
        account = node.get("serviceAccount")
        account_name = account.get("name") if isinstance(account, dict) else None
        wanted = service_account_name(run_id)
        if account_name != wanted:
            raise UnrecordedIdError(
                f"Refusing to delete service_account_key {label}: it belongs to service account "
                f"{account_name!r}, not {wanted!r}. Nothing further was deleted."
            )
    if kind in ("web_app", "ssh", "connector", "gateway"):
        network = node.get("remoteNetwork")
        actual = network.get("id") if isinstance(network, dict) else None
        if actual != remote_network_id:
            raise UnrecordedIdError(
                f"Refusing to delete {kind} {label}: it is in remote network {actual!r}, not "
                f"{remote_network_id!r}. Nothing further was deleted."
            )


def require_no_adoption(actions: Iterable[str]) -> None:
    """Refuse when a gwops pass reports it adopted an existing gateway (Mode B adoption)."""
    adopted = [a for a in actions if isinstance(a, str) and _ADOPTION_RE.search(a)]
    if adopted:
        raise GatewayAddressInUseError(
            "gwops adopted an existing gateway instead of creating the run's own; refusing to "
            f"continue ({adopted[0][:160]})."
        )


def require_local_image_ref(ref: str) -> str:
    """Refuse an --image reference that names a registry host (the image must be local)."""
    if not ref or ref != ref.strip() or any(ch.isspace() for ch in ref) or ref.startswith("-"):
        raise GuardError(f"Refusing image reference {ref!r}: empty, padded or option-like.")
    first, sep, _rest = ref.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        raise GuardError(
            f"Refusing image reference {ref!r}: it names a registry host ({first!r}); the rig "
            "runs only the local image built by `make image`."
        )
    return ref


def require_local_docker(docker_host: str | None, endpoint: str) -> None:
    """Refuse a remote docker: DOCKER_HOST set, or a context endpoint that is not a local socket."""
    if docker_host:
        raise GuardError("Refusing to run: DOCKER_HOST is set; the rig uses the local engine only.")
    if not endpoint.startswith(_LOCAL_ENDPOINT_SCHEMES):
        raise GuardError(
            f"Refusing to run: the active docker context endpoint {endpoint!r} is not a local "
            "unix:// or npipe:// socket."
        )
