"""The resource-kind registry: one descriptor per Twingate resource kind gwops manages.

Everything that would otherwise hardcode "ssh" / "kubernetes" — the effective-state
lists the desired objects come from, the TG GraphQL list fragments and create/update
mutations, SAN computation, the overlay allowlist, and the admin API's
``/upstreams/{segment}/{name}`` routes — iterates :data:`KINDS` instead. Adding a kind
takes a config model subclassing :class:`~gwops.configmodel.schema.UpstreamEntry`, a
``list[...]`` field for it on :class:`~gwops.configmodel.schema.SeedConfig`, and one
:class:`ResourceKind` appended to :data:`KINDS`. Hook fields default to the SSH shape.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from gwops.access.webapp_policy import FieldViolation, automation_field_violations, entry_warnings
from gwops.configmodel.schema import EffectiveState, UpstreamEntry, WebApp
from gwops.kindhooks import (
    Extras,
    no_drift,
    no_extras,
    upstream_port_only,
    webapp_create_variables,
    webapp_parse_remote,
    webapp_settings_drift,
)


def _always_enabled(state: EffectiveState) -> bool:
    """Default ``automation_enabled``: no seed opt-in."""
    return True


def _no_field_violations(entry: UpstreamEntry, state: EffectiveState) -> list[FieldViolation]:
    """Default ``automation_field_violations``: no per-field limits."""
    return []


def _webapp_enabled(state: EffectiveState) -> bool:
    """Web apps need the seed opt-in."""
    return state.admin_api.automation.web_apps.enabled


def _webapp_field_violations(entry: UpstreamEntry, state: EffectiveState) -> list[FieldViolation]:
    """The web-app automation field policy."""
    if not isinstance(entry, WebApp):
        raise TypeError(f"expected a WebApp entry, got {type(entry).__name__}")
    return automation_field_violations(entry, state)


def _no_detail(
    entry: UpstreamEntry, state: EffectiveState, automation_owned: bool
) -> dict[str, Any]:
    """Default ``detail``: nothing beyond the shared GET fields."""
    return {}


def _webapp_detail(
    entry: UpstreamEntry, state: EffectiveState, automation_owned: bool
) -> dict[str, Any]:
    """The web-app fields of ``GET /upstreams/webapp/{name}`` (unredacted)."""
    if not isinstance(entry, WebApp):
        raise TypeError(f"expected a WebApp entry, got {type(entry).__name__}")
    detail: dict[str, Any] = {
        "alias": entry.alias,
        "upstream_tls": entry.upstream_tls,
        "downstream": {"tls": entry.downstream.tls, "port": entry.downstream.effective_port()},
        "request_headers": entry.request_headers,
        "warnings": entry_warnings(entry),
    }
    if automation_owned:
        detail["automation_policy_violations"] = [
            {"field": v.field, "reason": v.reason}
            for v in automation_field_violations(entry, state)
        ]
    return detail


@dataclass(frozen=True)
class ResourceKind:
    """How one resource kind maps onto config, the TG GraphQL schema, and the API."""

    key: str
    """Registry / desired-object kind, and the ``<kind>`` in ``<kind>/<name>`` keys."""

    state_field: str
    """The ``EffectiveState`` list holding this kind's entries (also an overlay key)."""

    api_segment: str
    """The admin API path segment: ``/upstreams/<api_segment>/<name>``."""

    tg_type: str
    """The GraphQL ``__typename``; also names the ops (``Create<tg_type>``)."""

    tg_field_prefix: str
    """Mutation field prefix: ``<prefix>Create`` / ``<prefix>Update``."""

    tg_upstream_input: str
    """The GraphQL input type of the create/update ``upstream`` argument."""

    gateway_id_required: bool
    """Whether the create mutation declares ``gatewayId: ID!`` (else ``ID``)."""

    automation_allowed: bool
    """Whether ``GWOPS_AUTOMATION_TOKEN`` may manage this kind. False for any kind whose
    entries name local files (Kubernetes credential paths): an unattended caller could
    otherwise point one at a secret in the container and have the gateway send it to
    an address it controls."""

    list_fields: str = "gateway { id } upstream { port }"
    """The selection set read inside this kind's ``... on <tg_type>`` list fragment: flat
    field names and ``{ }`` sub-selections only (no arguments or directives)."""

    upstream_input_required: bool = False
    """Whether the create mutation declares ``$upstream`` non-null (``!``)."""

    extra_create_args: tuple[tuple[str, str], ...] = ()
    """``(argument, GraphQL type)`` pairs the create mutation declares beyond the shared
    ones; their values come from :attr:`create_variables`."""

    extra_update_args: tuple[tuple[str, str], ...] = ()
    """``(argument, GraphQL type)`` pairs the settings update mutation declares; the
    keys :func:`gwops.tgapi.ops.update_resource_settings` accepts."""

    parse_remote: Callable[[dict[str, Any]], Extras] = no_extras
    """Reads the kind-specific settings off a listed resource node. Raises ``ValueError``
    for a malformed or unknown value, which fails that listing loudly."""

    create_variables: Callable[[int, Extras], dict[str, Any]] = upstream_port_only
    """``(upstream_port, extras)`` -> the create variables from ``upstream`` onward."""

    settings_drift: Callable[[int, Extras, int, Extras], dict[str, Any]] = no_drift
    """``(want_port, want_extras, remote_port, remote_extras)`` -> the settings update
    variables for what differs, or ``{}`` when in sync."""

    update_mutation: str = "resourceUpdate"
    """The mutation field the address and access updates call. ``resourceUpdate`` accepts
    a generic resource id; a kind it rejects names its own ``<prefix>Update`` here."""

    automation_enabled: Callable[[EffectiveState], bool] = _always_enabled
    """Whether the seed lets the automation token manage this kind."""

    automation_field_violations: Callable[[UpstreamEntry, EffectiveState], list[FieldViolation]] = (
        _no_field_violations
    )
    """``(effective candidate entry, state)`` -> per-field refusals of an automation write."""

    detail: Callable[[UpstreamEntry, EffectiveState, bool], dict[str, Any]] = _no_detail
    """``(entry, state, automation_owned)`` -> the kind-specific, not yet redacted fields of
    ``GET /upstreams/<segment>/<name>``."""

    automation_exclusive_addresses: bool = False
    """Whether an automation write's address and alias must be unique across the seed,
    overlays and the tenant."""

    merged_update: bool = False
    """Whether every drifted field, gateway included, goes in one
    :func:`gwops.tgapi.ops.update_webapp_resource` (the kind rejects ``resourceUpdate``)."""

    def entries(self, state: EffectiveState) -> list[UpstreamEntry]:
        """This kind's entries in `state`, in declaration order."""
        items: list[UpstreamEntry] = getattr(state, self.state_field)
        return items

    def resource_key(self, name: str) -> str:
        """The ``<kind>/<name>`` registry key for an entry of this kind."""
        return f"{self.key}/{name}"


SSH = ResourceKind(
    key="ssh",
    state_field="ssh_upstreams",
    api_segment="ssh",
    tg_type="SSHResource",
    tg_field_prefix="sshResource",
    tg_upstream_input="SSHUpstreamInput",
    gateway_id_required=True,
    automation_allowed=True,
)

KUBERNETES = ResourceKind(
    key="kubernetes",
    state_field="k8s_clusters",
    api_segment="k8s",
    tg_type="KubernetesResource",
    tg_field_prefix="kubernetesResource",
    tg_upstream_input="KubernetesUpstreamInput",
    gateway_id_required=False,
    automation_allowed=False,
)

WEBAPP = ResourceKind(
    key="webapp",
    state_field="web_apps",
    api_segment="webapp",
    tg_type="WebAppResource",
    tg_field_prefix="webAppResource",
    tg_upstream_input="WebAppUpstreamInput",
    gateway_id_required=True,
    automation_allowed=True,
    list_fields=(
        "gateway { id } alias upstream { port tlsMode } downstream { port tlsMode } "
        "requestHeaderRewrites { key value }"
    ),
    upstream_input_required=True,
    extra_create_args=(
        ("downstream", "WebAppDownstreamInput!"),
        ("requestHeaderRewrites", "[KeyValueInputObject!]"),
        ("alias", "String"),
    ),
    extra_update_args=(
        ("upstream", "WebAppUpstreamInput"),
        ("downstream", "WebAppDownstreamInput"),
        ("alias", "String"),
        ("requestHeaderRewrites", "[KeyValueInputObject!]"),
        ("gatewayId", "ID"),
    ),
    parse_remote=webapp_parse_remote,
    create_variables=webapp_create_variables,
    settings_drift=webapp_settings_drift,
    update_mutation="webAppResourceUpdate",
    automation_enabled=_webapp_enabled,
    automation_field_violations=_webapp_field_violations,
    detail=_webapp_detail,
    automation_exclusive_addresses=True,
    merged_update=True,
)

KINDS: tuple[ResourceKind, ...] = (SSH, KUBERNETES, WEBAPP)

_BY_KEY = {kind.key: kind for kind in KINDS}
_BY_SEGMENT = {kind.api_segment: kind for kind in KINDS}
_BY_TG_TYPE = {kind.tg_type: kind for kind in KINDS}


def by_key(key: str) -> ResourceKind:
    """The kind with registry key `key`; raises KeyError for an unknown key."""
    return _BY_KEY[key]


def by_segment(segment: str) -> ResourceKind | None:
    """The kind served at ``/upstreams/<segment>/...``, or None."""
    return _BY_SEGMENT.get(segment)


def by_tg_type(typename: str) -> ResourceKind | None:
    """The kind whose GraphQL ``__typename`` is `typename`, or None (unmanaged type)."""
    return _BY_TG_TYPE.get(typename)


def is_resource_key(key: str) -> bool:
    """Whether a registry key names a resource of a managed kind (vs ``ca/*``, ...)."""
    kind, sep, _name = key.partition("/")
    return bool(sep) and kind in _BY_KEY
