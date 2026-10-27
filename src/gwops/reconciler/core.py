"""`Reconciler`: the level-triggered core loop.

One `reconcile()` drives the full chain from declared state to a running gateway:

0. **Load and policy** — load the effective state and apply the web-app policy; a failure
   is a local error and ends the pass.
1. **TG sync** — diff `desired_tg_objects()` against the tenant, creating / correcting /
   deleting only objects the :class:`~gwops.reconciler.registry.StateRegistry` records
   as gwops-owned. A ``merged_update`` kind (web apps) is corrected with one mutation,
   gateway reassignment included.
   The tenant being unreachable is an *error, not an abort*: local
   correctness beats remote sync, so the cert/render steps still run.
2. **Credentials** — read each cluster's token/CA source through :mod:`gwops.confined`
   (confined to ``/config/k8s-creds/``) and write content-addressed copies under
   ``/data/k8s-creds/``, so a changed credential changes the rendered config. Web-app CA
   bundles go from ``/config/webapp-cas/`` to ``/data/upstream-ca/`` the same way.
3. **Certs** — private mode: ensure CAs, register gwops-generated CAs with the tenant exactly
   once (level-triggered on the registry's ``ca/*`` keys, never for bring-your-own CAs),
   and re-mint the TLS leaf whenever it is missing/expiring/SAN-incomplete/SAN-surplus.
   Public mode (the seed has ``public_tls``): mint no CA or leaf. Resolve the registered root
   from the system trust store, read and validate every public certificate and install all of
   them or none (a refusal is a local error and the last good pair keeps serving), ensure the
   SSH CA, then register the root on the tenant (registry key ``ca/x509-public``), read the
   gateway's X.509 CA binding and decide a rebind to the root when it differs; the rebind is
   sent only after step 5 succeeded in the same pass (credentials, CA bundles, certificates,
   render and apply all OK), else it is deferred with a reason. A pass is held down while a
   declared certificate has nothing installed.
4. **Render** — render the config and pre-flight the candidate through a bounded spawn
   of the real gateway binary (`gwops.supervisor.spawn.validate_config_by_spawn`)
   before swapping it in; a rejected candidate is discarded and the last-good config
   stays live.
5. **Apply** — pick the cheapest sufficient action per change class: first reconcile
   starts the process; any config change drain-restarts the gateway (a change in the set of
   public certificate entries is reported as ``TLS certificate set changed``); a changed
   certificate at an unchanged path (a re-minted leaf, a renewed public certificate) needs
   nothing, the gateway hot-reloads cert files. After a fully successful pass,
   copies referenced by neither ``config.yaml`` nor its ``.last-good`` are removed, and
   in public mode the public certificate store is swept.

Any local failure (bad seed, missing credentials, unusable CA, unrenderable state)
skips steps 4–5 entirely, which is what guarantees the acceptance criterion: every
failure path leaves the gateway running on the last good config and says why.

Concurrency: reconciles are single-flight. A trigger arriving mid-run coalesces with
every other waiting trigger into exactly one follow-up run (they all share its
result) — a burst of seed events, ticks, and API calls costs at most one extra pass.
"""

import asyncio
import os
import shutil
import time
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast, get_args

import structlog
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from gwops import webapp_readiness
from gwops.access import webapp_policy
from gwops.access.resolve import AccessResolutionError, AccessResolver, ResolvedAccess
from gwops.acme.runner import AcmeConfig, AcmeRunner
from gwops.acme.token import token_file_problem
from gwops.certs.manager import CAInfo, CertManager, LeafState, SSHCAInfo
from gwops.certs.on_demand import require_on_demand_ca, state_tls_warning
from gwops.certs.public import (
    PublicMaterial,
    PublicMaterialError,
    RegisteredRootError,
    find_san_overlaps,
    leaf_dns_sans,
    read_installed_public_material,
    read_public_material,
    resolve_registered_root,
)
from gwops.certs.store import MaterialStore, StoreError
from gwops.configmodel.loader import ConfigLoadError, load_effective_state
from gwops.configmodel.schema import (
    AcmePublicCertificate,
    DownstreamTLS,
    EffectiveState,
    FilePublicCertificate,
    PublicCertificate,
    PublicTlsSettings,
    UpstreamTLS,
    unused_public_certificates,
)
from gwops.configmodel.store import OverlayStore
from gwops.confined import (
    ConfinedFileError,
    collect_garbage,
    content_address,
    read_confined,
    remove_legacy_credential_dirs,
    write_content_addressed,
)
from gwops.gateway_id import gateway_id_for
from gwops.kindhooks import REWRITES_KEY
from gwops.kinds import KINDS, WEBAPP, by_key, is_resource_key
from gwops.reconciler.registry import AppliedAccess, StateRegistry
from gwops.renderer.capabilities import Capabilities
from gwops.renderer.desired import DesiredResource, desired_tg_objects
from gwops.renderer.render import (
    K8sCredentialFiles,
    RenderError,
    RuntimePaths,
    render_gateway_config,
)
from gwops.renderer.sans import required_sans
from gwops.settings import GwopsSettings
from gwops.shipper.enrich import WebAppIndex
from gwops.supervisor.process import GatewayProcess, ProcState, last_good_path
from gwops.supervisor.spawn import (
    _VALIDATE_TIMEOUT_SECONDS,
    Classification,
    classify_outcome,
    validate_config_by_spawn,
)
from gwops.tgapi import ops
from gwops.tgapi.client import TGClient, attribution_via
from gwops.tgapi.errors import TGAPIError
from gwops.webapp_probe import ProbeRunner

logger = structlog.get_logger(__name__)

_TOKEN_MODE = 0o600
_PUBLIC_MODE = 0o644

# Local (non-TG) failures the per-step guards convert into recorded errors.
_LOCAL_ERRORS = (ValueError, RuntimeError, FileNotFoundError, OSError)

# Per-resource error recorded for each TG write skipped because an earlier write in the
# same pass was throttled (HTTP 429). The skipped work is retried on the next pass.
DEFERRED_RATE_LIMITED = "deferred: rate-limited"


class _WriteDeferred(Exception):
    """Raised before a TG write that this pass must skip because a write was throttled."""


_PUBLIC_HELD_DOWN = "gateway held down until every public certificate is installed"
_PUBLIC_NONE_RENDERABLE = (
    "gateway held down until a public certificate can be rendered "
    "(every certificate is pending ACME issuance)"
)
_PUBLIC_NONE_RENDERABLE_STAGING = (
    "gateway held down until a public certificate can be rendered (every certificate is "
    "pending ACME issuance, and the ACME directory is staging, a dry run that never installs "
    "a certificate: set public_tls.acme.directory: production to serve)"
)
_ACME_HOLDS = frozenset({_PUBLIC_NONE_RENDERABLE, _PUBLIC_NONE_RENDERABLE_STAGING})
_ACME_NAMES_CHANGED = "awaiting reissue for changed names"

PUBLIC_ROOT_KEY = "ca/x509-public"
"""Registry key of the tenant CA object registered for the public root."""


@dataclass
class _RootProgress:
    """What a public-mode pass has learned about the registered root so far."""

    ca_id: str | None = None
    bound: bool | None = None


# `settings_drift` keys of a merged-update kind -> `ops.update_webapp_resource` arguments.
_MERGED_SETTING_ARGS = {
    "upstream": "upstream",
    "downstream": "downstream",
    "alias": "alias",
    "requestHeaderRewrites": "request_header_rewrites",
}


@dataclass(frozen=True)
class _AccessDelta:
    """An access change to send: group delta, a policy to set, and what to record after."""

    added: list[str]
    removed: list[str]
    policy: str | None
    applied: AppliedAccess

    def describe(self) -> list[str]:
        """The change as short phrases for an action line."""
        changes = [f"+groups {self.added}"] if self.added else []
        changes += [f"-groups {self.removed}"] if self.removed else []
        changes += [f"security policy -> {self.policy}"] if self.policy is not None else []
        return changes


def _changed_header_names(
    want: Iterable[tuple[str, str]] | None, remote: Iterable[tuple[str, str]] | None
) -> list[str]:
    """Names of the header rewrites that differ between two normalised sets; never values."""
    differing = set(want or ()) ^ set(remote or ())
    return sorted({name for name, _value in differing})


@dataclass(frozen=True)
class GatewayMismatch:
    """A managed resource attached to a gateway other than gwops' own."""

    remote_gateway_id: str
    """The gateway id the tenant reports for the resource."""
    corrected: bool
    """Whether this pass reassigned the resource to gwops' gateway."""


@dataclass(frozen=True)
class RemoteWebApp:
    """A tenant web app as the pass listed it; header names only, never values."""

    id: str
    name: str
    gateway_id: str
    address: str
    upstream_port: int
    """The port the gateway dials on ``address``, as the tenant listing reports it."""
    alias: str | None
    upstream_tls: UpstreamTLS
    """Seed spelling."""
    downstream_tls: DownstreamTLS
    """Seed spelling."""
    downstream_port: int
    """The port the gateway listens on for this app, as the tenant listing reports it."""
    header_rewrite_names: tuple[str, ...]
    """Lowercase names of the per-resource request header rewrites."""
    managed: bool
    """Whether gwops owns the resource (its id is in the registry)."""


@dataclass(frozen=True)
class RegisteredRootStatus:
    """The registered public root as one public-mode pass left it.

    ``tg_ca_id`` is the tenant CA object for the root, or None when it is not known
    (no API key, or the pass failed before the registry or tenant yielded it). ``bound``
    is whether the gateway's X.509 CA fingerprint equals ``sha256``; None when the binding
    could not be read (no API key, TG-side failure).
    """

    name: str
    sha256: str
    """Lowercase hex SHA-256 of the root certificate's DER."""
    tg_ca_id: str | None
    bound: bool | None


@dataclass(frozen=True)
class PublicCertStatus:
    """One declared public certificate as the last pass left it.

    ``generation`` and ``not_after`` describe the material currently served (the last good
    install); a failing pass sets ``state`` to ``"invalid"`` and ``last_error`` and keeps
    both. ``state`` is ``"expiring"`` once less than one third of the lifetime remains
    , and ``"pending"`` when the certificate validated but was not installed this
    pass because another certificate failed (the install is all-or-nothing); a pending
    certificate with no ``generation`` is served by nothing yet. ``last_error`` is the
    refusal text (names the certificate and file, never contents).
    """

    name: str
    names: tuple[str, ...]
    not_after: datetime | None
    state: Literal["ok", "expiring", "invalid", "pending"]
    last_error: str | None
    generation: str | None
    """The store generation id (12 hex) now served; None until the first install."""
    source: Literal["file", "acme"] = "file"
    """The seed entry's ``source``. A ``source: acme`` certificate is ``pending`` (generation
    None) while nothing valid is installed: ``last_error`` is then None (not issued yet) or
    ``"awaiting reissue for changed names"`` (the installed leaf's SANs differ from the declared
    names). Installed material the validator refuses or that cannot be read is ``invalid``
    (generation None, ``last_error`` the refusal). Neither is rendered."""


@dataclass(frozen=True)
class AcmeError:
    """One ACME problem a pass observed; never part of ``errors``, ``ok`` or ``local_ok``.

    ``code`` is an :class:`~gwops.acme.state.AcmeErrorClass` value (``config``,
    ``invalid_output``, ``internal`` or the runner's recorded class). ``certificate`` is None
    for a problem that is not about one certificate (the runner's unusable state file, a
    missing token file). ``detail`` is bounded and token-free.
    """

    certificate: str | None
    code: str
    detail: str


@dataclass
class ReconcileResult:
    """One reconcile pass's outcome: what was done, and what went wrong.

    ``ok`` is the overall pass verdict (no errors of any kind) and drives ``/status`` and
    logging. ``local_ok`` is narrower: it is False only when a *local* step failed
    (credentials, cert material, render/validation, or gateway start/apply), and stays
    True when the only failures are TG-side sync errors (API key unset, a transient tenant
    outage, a single resource create/delete). ``/healthz`` gates on ``local_ok`` plus the
    gateway process state, so a tenant-side hiccup never marks the container unhealthy.

    ``tg_synced`` is positive confirmation: the ``kind/name`` keys of desired resources
    that ended this pass in sync on the tenant (created, corrected, or already matching),
    plus managed resources this pass deleted. ``tg_unavailable`` is True when TG sync was
    skipped wholesale (no API key, gateway unresolved, or the resource list failed). The
    admin API uses both to decide whether a mutation reached the tenant end to end.

    Once any write on this client during the pass is throttled (HTTP 429), every later TG
    write in that pass is skipped and each affected resource gets the per-resource error
    ``deferred: rate-limited`` (:data:`DEFERRED_RATE_LIMITED`); such a resource is not
    in ``tg_synced`` and is retried next pass. Reads are never skipped, but all 429 sleeping
    in a pass shares one budget (see :meth:`gwops.tgapi.client.TGClient.begin_pass`): once
    it is spent, a throttled call fails at once with ``TGRateLimited``, so a read takes the
    TG-unavailable path and a write is recorded as a per-resource error.
    """

    ok: bool
    trigger: str
    started_at: datetime
    local_ok: bool = True
    actions: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    tg_synced: set[str] = field(default_factory=set)
    tg_unavailable: bool = False
    resource_errors: dict[str, list[str]] = field(default_factory=dict)
    """TG-sync errors keyed ``<kind>/<name>`` (also included in ``errors``)."""
    gateway_mismatches: dict[str, GatewayMismatch] = field(default_factory=dict)
    """Managed resources the tenant attaches to another gateway, keyed ``<kind>/<name>``.
    Empty when TG sync did not list the tenant this pass."""
    remote_web_apps: list[RemoteWebApp] | None = None
    """Every web app this pass's tenant listing returned (any gateway, managed or not);
    None when the tenant was not listed."""
    remote_web_apps_error: str | None = None
    """Exception class name when the tenant was listed but the web-app snapshot failed;
    ``remote_web_apps`` is then None too. None otherwise, including when the tenant was not
    listed."""
    webapp_warnings: list[str] = field(default_factory=list)
    """The current web-app policy warnings; never part of ``errors`` or ``ok``."""
    housekeeping_errors: list[str] = field(default_factory=list)
    """Failed garbage-collection and legacy-cleanup steps (no exception text); never part
    of ``errors`` or ``ok``. A pass that did not run housekeeping carries the previous
    pass's errors forward."""
    housekeeping_ran: bool = False
    """Whether this pass ran garbage collection and legacy cleanup."""
    tg_attempted: bool | None = None
    """Whether the pass reached the TG sync step (it may still have skipped itself); None on a
    result a pass did not build, which readers then derive from ``errors``."""
    registered_root: RegisteredRootStatus | None = None
    """The registered public root's tenant state; None outside public mode and on a pass
    that did not resolve the root."""
    public_certs: list[PublicCertStatus] | None = None
    """Every declared public certificate's status in seed order; None in private mode (and
    before any public pass has run)."""
    acme_errors: list[AcmeError] = field(default_factory=list)
    """ACME problems seen this pass: the runner's unusable or absent state, each certificate's
    recorded error class, a missing DNS token file, installed material the validator refused.
    Never part of ``errors``, ``ok`` or ``local_ok``."""
    acme_pending: list[str] = field(default_factory=list)
    """``source: acme`` certificates (seed order) with nothing valid installed, so not rendered
    this pass. Their names are accepted as uncovered until material lands."""
    acme_hold: bool = False
    """True when this pass held the gateway down only because no certificate could be rendered
    and every certificate is a pending ``source: acme`` one (the none-renderable hold). Startup
    waits for ACME only in that case; any other hold or failure still aborts."""

    def resource_error(self, key: str, message: str) -> None:
        """Record a TG-sync error that belongs to one resource."""
        self.errors.append(f"TG sync: {key}: {message}")
        self.resource_errors.setdefault(key, []).append(message)


def tg_attribution(state: EffectiveState) -> tuple[list[str], list[str]]:
    """The User-Agent attribution sets for `state`: ``(kinds, tls)``.

    ``kinds`` is the key of every resource kind with at least one entry. ``tls`` is empty
    without a ``public_tls`` block (private-CA mode), else the sorted certificate sources
    (``file``, ``acme``).
    """
    kinds = [kind.key for kind in KINDS if kind.entries(state)]
    if state.public_tls is None:
        return kinds, []
    return kinds, sorted({cert.source for cert in state.public_tls.certificates})


def _restart_required_reasons(old_text: str, new_text: str) -> list[str]:
    """Which restart-required settings differ between two rendered configs.

    The listener port and the SSH CA path cannot change under a running daemon, so a
    change to either is called out explicitly in the drain-restart message.

    The SSH CA key path is read at ``ssh.ca.local.privateKeyFile``, where the renderer
    writes it.
    """

    def _extract(text: str) -> tuple[Any, Any, tuple[str, ...]]:
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            return None, None, ()
        if not isinstance(doc, dict):
            return None, None, ()
        ssh_ca = (
            doc.get("ssh", {}).get("ca", {}).get("local", {}).get("privateKeyFile")
            if isinstance(doc.get("ssh"), dict)
            else None
        )
        return doc.get("port"), ssh_ca, _certificate_files(doc)

    old_port, old_ssh_ca, old_certs = _extract(old_text)
    new_port, new_ssh_ca, new_certs = _extract(new_text)
    reasons: list[str] = []
    if old_port != new_port:
        reasons.append(f"listener port changed ({old_port} -> {new_port})")
    if old_ssh_ca != new_ssh_ca:
        reasons.append(f"SSH CA key path changed ({old_ssh_ca} -> {new_ssh_ca})")
    if old_certs != new_certs:
        reasons.append("TLS certificate set changed")
    return reasons


def _certificate_files(doc: dict[str, Any]) -> tuple[str, ...]:
    """The ``tls.certificates.files[*].certificateFile`` paths of a parsed config, in order.

    A content change at a stable path leaves them unchanged (the gateway hot-reloads); an
    added, removed or re-pathed entry changes them, and the gateway only reads its
    certificate entries at start.
    """
    tls = doc.get("tls")
    certificates = tls.get("certificates") if isinstance(tls, dict) else None
    files = certificates.get("files") if isinstance(certificates, dict) else None
    if not isinstance(files, list):
        return ()
    return tuple(str(entry.get("certificateFile")) for entry in files if isinstance(entry, dict))


def _opt_path(value: str | None) -> Path | None:
    return Path(value) if value else None


def _upstream_tls(value: object) -> UpstreamTLS:
    mode = str(value).lower()
    if mode not in get_args(UpstreamTLS):
        raise ValueError("web app node has an unknown upstream tlsMode")
    return cast(UpstreamTLS, mode)


def _downstream_tls(value: object) -> DownstreamTLS:
    mode = str(value).lower()
    if mode not in get_args(DownstreamTLS):
        raise ValueError("web app node has an unknown downstream tlsMode")
    return cast(DownstreamTLS, mode)


def _web_app_snapshot(
    actual: Iterable[ops.RemoteResource], owned_ids: set[str]
) -> list[RemoteWebApp]:
    """The listed web apps as :class:`RemoteWebApp` records (header names, never values)."""
    snapshot: list[RemoteWebApp] = []
    for remote in actual:
        if remote.kind != WEBAPP.key:
            continue
        extras = remote.extras
        snapshot.append(
            RemoteWebApp(
                id=remote.id,
                name=remote.name,
                gateway_id=remote.gateway_id,
                address=remote.address,
                upstream_port=remote.upstream_port,
                alias=extras["alias"],
                upstream_tls=_upstream_tls(extras["upstream_tls_mode"]),
                downstream_tls=_downstream_tls(extras["downstream_tls_mode"]),
                downstream_port=int(extras["downstream_port"]),
                header_rewrite_names=tuple(
                    name.lower() for name, _value in extras["request_header_rewrites"] or ()
                ),
                managed=remote.id in owned_ids,
            )
        )
    return snapshot


def _ok_status(
    cert: PublicCertificate, material: PublicMaterial, generation: str | None
) -> PublicCertStatus:
    """Status of a certificate whose material validated (``ok`` or ``expiring``)."""
    return PublicCertStatus(
        name=cert.name,
        names=tuple(cert.names),
        not_after=material.not_after,
        state=material.state.value,
        last_error=None,
        generation=generation,
        source=cert.source,
    )


def _invalid_status(
    cert: PublicCertificate, last: PublicCertStatus | None, error: str
) -> PublicCertStatus:
    """Status of a certificate that was refused: the last good generation stays served."""
    return PublicCertStatus(
        name=cert.name,
        names=tuple(cert.names),
        not_after=last.not_after if last is not None else None,
        state="invalid",
        last_error=error,
        generation=last.generation if last is not None else None,
        source=cert.source,
    )


_NOT_INSTALLED = "not installed: another certificate failed validation"
_LEAF_NOT_RELOADED = "leaf certificate: previous generation not removed; gateway has not reloaded"
_LEAF_NOT_RELOADED_AFTER_MINT = (
    "leaf certificate: installed but previous generation not removed; gateway has not reloaded"
)


def _pending_status(cert: PublicCertificate, last: PublicCertStatus | None) -> PublicCertStatus:
    """Status of a certificate that validated but was not installed this pass.

    It keeps the generation and expiry of the copy still served (the last install), or none
    when nothing was ever installed.
    """
    return PublicCertStatus(
        name=cert.name,
        names=tuple(cert.names),
        not_after=last.not_after if last is not None else None,
        state="pending",
        last_error=_NOT_INSTALLED,
        generation=last.generation if last is not None else None,
        source=cert.source,
    )


def _acme_pending_status(
    cert: PublicCertificate, refusal: str | None, *, refused: bool = False
) -> PublicCertStatus:
    """Status of a ``source: acme`` certificate with nothing valid installed.

    ``refusal`` is the validator's message when the store holds material that was refused or
    cannot be read (``refused`` True: state ``invalid``), the reissue note for changed names
    (state ``pending``), or None when nothing was issued yet (state ``pending``).
    """
    return PublicCertStatus(
        name=cert.name,
        names=tuple(cert.names),
        not_after=None,
        state="invalid" if refused else "pending",
        last_error=refusal,
        generation=None,
        source=cert.source,
    )


@dataclass(frozen=True)
class _GatewayUpdate:
    """A public-mode gateway rebind the pass has decided on but not yet sent.

    The rebind runs only after the pass rendered and applied its config successfully; the
    new SSH CA, when one was created in the same pass, rides along in the same update.
    """

    gateway_id: str
    root_ca_id: str
    root_name: str
    old_ca_id: str | None
    ssh_ca_id: str | None


class Reconciler:
    """Owns the reconcile loop over one seed/store/tenant/process/PKI quintet."""

    def __init__(
        self,
        *,
        settings: GwopsSettings,
        store: OverlayStore,
        tg: TGClient | None,
        certs: CertManager,
        process: GatewayProcess,
        registry: StateRegistry,
        caps: Capabilities,
        validate_timeout_seconds: float = _VALIDATE_TIMEOUT_SECONDS,
        paths: RuntimePaths | None = None,
        probe: ProbeRunner | None = None,
        webapp_index: WebAppIndex | None = None,
        acme: AcmeRunner | None = None,
        public_store: MaterialStore | None = None,
        acme_unavailable: str | None = None,
    ) -> None:
        """Wire the reconciler; `tg` is None when ``TWINGATE_API_KEY`` is not set
        (every TG-side step then records an error and is retried on later runs).

        `probe` is handed each pass's tenant listing and never awaited. `webapp_index` is
        updated from each pass's listing for the recording enrichment.

        `acme` is the ACME runner: each pass is handed the seed's ACME configuration through it
        (None when there is none) and reads its errors; a pass never awaits it. `public_store`
        is the atomic store of installed public certificates; pass the instance the runner
        installs through so its installs and this reconciler's sweep share one lock (default: a
        new store over ``RuntimePaths.public_tls_dir``). `acme_unavailable` is why `acme` is
        None when constructing the runner failed; every pass that declares ``source: acme``
        certificates then reports it in ``acme_errors``.

        `validate_timeout_seconds` bounds the render pre-flight's spawn.

        `paths` defaults to :meth:`RuntimePaths.from_settings`."""
        self._settings = settings
        self._store = store
        self._tg = tg
        self._certs = certs
        self._process = process
        self._registry = registry
        self._caps = caps
        self._validate_timeout_seconds = validate_timeout_seconds
        self._paths = paths if paths is not None else RuntimePaths.from_settings(settings)
        self._probe = probe
        self._webapp_index = webapp_index
        self._config_path = settings.runtime_dir / "config.yaml"
        self.last_result: ReconcileResult | None = None
        self._lock = asyncio.Lock()
        self._follower: asyncio.Future[ReconcileResult] | None = None
        # Set on shutdown: the apply step then stops starting/restarting the gateway.
        self._shutting_down = False
        # CAs created on the tenant whose gateway rebind has not succeeded yet; kept so a
        # rebind retry never creates a duplicate CA object.
        self._unbound_ca_ids: dict[str, str] = {}
        self._access_resolver = AccessResolver()
        # TGClient.write_throttle_count at the start of the current pass; a higher count
        # later in the pass means a write was throttled.
        self._pass_throttle_baseline = 0
        # Last-logged values, so each distinct value is logged once rather than every pass.
        self._logged_policy_warnings: tuple[str, ...] = ()
        self._logged_gateway_mismatches: dict[str, GatewayMismatch] = {}
        self._logged_readiness: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
        self._logged_unused_public_certs: tuple[str, ...] = ()
        # Per-certificate status is kept across passes so a failing pass can report the
        # last good generation.
        self._public_store = (
            public_store if public_store is not None else MaterialStore(self._paths.public_tls_dir)
        )
        self._public_cert_status: dict[str, PublicCertStatus] = {}
        self._acme = acme
        self._acme_unavailable = acme_unavailable
        self._acme_config: AcmeConfig | None = None
        self._acme_configured = False
        self._acme_pending: set[str] = set()
        self._acme_woken_for: frozenset[str] = frozenset()
        self._logged_acme_material: dict[str, str] = {}
        self._logged_acme_token: str | None = None
        self._logged_acme_unavailable: str | None = None
        self._logged_acme_config: str | None = None
        # The public-mode rebind decided on this pass, executed after a successful apply.
        self._pending_gateway_update: _GatewayUpdate | None = None
        # `ca.x509.on_demand_issuance` of the previous pass; None before the first one.
        self._last_on_demand: bool | None = None
        self._probe_skip_logged = False

    @property
    def lock(self) -> asyncio.Lock:
        """The lock every pass holds; hold it to keep a pass from running meanwhile."""
        return self._lock

    def _writes_throttled(self) -> bool:
        """True once a TG write in the current pass has been throttled (HTTP 429)."""
        return self._tg is not None and (
            self._tg.write_throttle_count > self._pass_throttle_baseline
        )

    def _require_write_budget(self) -> None:
        """Raise :class:`_WriteDeferred` if the current pass must skip further TG writes."""
        if self._writes_throttled():
            raise _WriteDeferred

    async def reconcile(self, trigger: str) -> ReconcileResult:
        """Run one single-flight reconcile pass; concurrent triggers coalesce.

        If a pass is already in flight, all triggers arriving during it share one
        follow-up pass (level-triggered: the follow-up re-reads the full state, so
        nothing any of them observed is lost).
        """
        if self._lock.locked():
            if self._follower is not None:
                return await self._follower
            loop = asyncio.get_running_loop()
            future: asyncio.Future[ReconcileResult] = loop.create_future()
            # Always consume the outcome so an unawaited follower never warns at GC.
            future.add_done_callback(lambda f: None if f.cancelled() else f.exception())
            self._follower = future
            try:
                async with self._lock:
                    # We are now the follow-up leader; later arrivals coalesce onto a
                    # fresh future, so clear ours only while it is still the shared one.
                    if self._follower is future:
                        self._follower = None
                    with attribution_via("reconcile"):
                        result = await self._run(trigger)
                    future.set_result(result)
                    return result
            except BaseException as exc:
                # Includes CancelledError raised while awaiting the lock: without this,
                # a cancelled follower would leave self._follower pointing at a future
                # that never resolves, wedging every later coalescing trigger forever.
                if self._follower is future:
                    self._follower = None
                if not future.done():
                    future.set_exception(exc)
                raise
        async with self._lock:
            with attribution_via("reconcile"):
                return await self._run(trigger)

    async def request_shutdown(self) -> None:
        """Quiesce for teardown: stop future gateway (re)starts, then wait out any
        in-flight pass so the supervisor's ``process.stop()`` cannot race a start.

        Callers must first cancel the trigger sources and stop the admin API so no new
        reconcile can begin; acquiring the lock here then guarantees the last pass has
        fully returned (its apply step observing the flag, or already complete).
        """
        self._shutting_down = True
        async with self._lock:
            pass

    # --- one pass ------------------------------------------------------------------

    async def _run(self, trigger: str) -> ReconcileResult:
        started = time.monotonic()
        result = ReconcileResult(
            ok=True, trigger=trigger, started_at=datetime.now(UTC), tg_attempted=False
        )
        logger.info("reconcile.started", trigger=trigger)
        self._pending_gateway_update = None
        if self._tg is not None:
            # Fresh 429-sleep budget for this pass, and a new baseline for write deferral.
            self._tg.begin_pass()
            self._pass_throttle_baseline = self._tg.write_throttle_count
        else:
            self._pass_throttle_baseline = 0

        try:
            state, _provenance = load_effective_state(self._settings.seed_path, self._store)
        except ConfigLoadError as exc:
            result.errors.append(f"effective state failed to load: {exc}")
            result.local_ok = False
            return self._finalize(result, started)

        if self._tg is not None:
            self._tg.set_attribution(*tg_attribution(state))
        self._log_on_demand_change(state)
        self._log_unused_public_certificates(state)
        if not self._check_webapp_policy(state, result):
            result.actions.append("kept previous gateway config (local step failed)")
            return self._finalize(result, started)

        # Certs and gateway resolution run before resource sync: creating the gateway needs
        # the registered X.509 CA id, and resources attach to the resolved gateway.
        local_ok, render_paths = self._materialize_credentials(state, result)
        ca_ok, render_paths = self._materialize_ca_bundles(state, result, render_paths)
        local_ok = local_ok and ca_ok
        cert_ok, leaf_changed, sans, gateway_id = await self._ensure_certs(state, result)
        local_ok = local_ok and cert_ok
        result.local_ok = local_ok
        await self._sync_tg(state, result, gateway_id)
        self._log_webapp_readiness(state, result, gateway_id)
        self._schedule_probe(state, result, render_paths, gateway_id, ca_ok=ca_ok)
        self._update_webapp_index(state, result)

        held = self._public_hold(state)
        result.acme_hold = held in _ACME_HOLDS
        if not local_ok:
            result.actions.append("kept previous gateway config (local step failed)")
            if held is not None:
                result.actions.append(held)
            await self._settle_gateway_update(result, "a local step failed this pass")
            return self._finalize(result, started)

        if held is not None:
            result.actions.append(held)
            await self._settle_gateway_update(result, "the gateway is held down")
            return self._finalize(result, started)

        if not sans:
            result.actions.append(
                "no upstreams configured; gateway held down until the first upstream arrives"
            )
            await self._settle_gateway_update(result, "no gateway config was applied")
            return self._finalize(result, started)

        if self._acme_pending:
            render_paths = render_paths.with_pending_public_certs(self._acme_pending)
        config_changed, old_text = await self._render_and_write(state, result, render_paths)
        await self._apply(config_changed, old_text, leaf_changed, result)
        await self._settle_gateway_update(
            result,
            None
            if result.local_ok and not self._shutting_down
            else "the config did not render and apply successfully this pass",
        )
        if result.local_ok:
            await self._collect_garbage(result, state)
            self._remove_legacy_credential_dirs(result)
            result.housekeeping_ran = True
        return self._finalize(result, started)

    def _log_on_demand_change(self, state: EffectiveState) -> None:
        """Log a change of on-demand issuance since the previous pass (not the first pass)."""
        current = state.ca.x509.on_demand_issuance
        previous, self._last_on_demand = self._last_on_demand, current
        if previous is None or previous == current:
            return
        if current:
            logger.warning("tls.on_demand_issuance_active", reason=state_tls_warning(state))
        else:
            logger.info("tls.on_demand_issuance_disabled")

    def _log_unused_public_certificates(self, state: EffectiveState) -> None:
        """Warn once per certificate that matches no served name, until the set changes.

        The startup pass and every pass after an overlay change see the state first, so
        this is where the set is (re)established; it is not logged on each validation.
        """
        unused = tuple(unused_public_certificates(state))
        if unused == self._logged_unused_public_certs:
            return
        for certificate in (c for c in unused if c not in self._logged_unused_public_certs):
            logger.warning("public_cert_unused", certificate=certificate)
        self._logged_unused_public_certs = unused

    def _check_webapp_policy(self, state: EffectiveState, result: ReconcileResult) -> bool:
        """Apply the web-app policy; False (with local errors recorded) when it refuses the state.

        The pass records the current warnings; they are logged once per distinct set.
        """
        result.webapp_warnings = webapp_policy.warnings(state)
        problems = webapp_policy.violations(state, self._caps)
        if problems:
            result.errors.extend(f"web-app policy: {problem}" for problem in problems)
            result.local_ok = False
            return False
        warned = tuple(result.webapp_warnings)
        if warned != self._logged_policy_warnings:
            self._logged_policy_warnings = warned
            if warned:
                logger.warning("reconcile.webapp_policy_warnings", warnings=list(warned))
        return True

    def _finalize(self, result: ReconcileResult, started: float) -> ReconcileResult:
        result.ok = not result.errors
        if self._public_cert_status:
            result.public_certs = list(self._public_cert_status.values())
        if not result.housekeeping_ran and self.last_result is not None:
            result.housekeeping_errors = list(self.last_result.housekeeping_errors)
        self.last_result = result
        log = logger.info if result.ok else logger.warning
        log(
            "reconcile.completed",
            trigger=result.trigger,
            ok=result.ok,
            actions=result.actions,
            errors=result.errors,
            duration=round(time.monotonic() - started, 3),
        )
        return result

    # --- step 1: TG sync -------------------------------------------------------------

    async def _sync_tg(
        self, state: EffectiveState, result: ReconcileResult, gateway_id: str | None
    ) -> None:
        result.tg_attempted = True
        if self._tg is None:
            result.errors.append(
                "TG sync skipped: TWINGATE_API_KEY is not set; declared upstreams were "
                "not synced to the Twingate tenant (local config still applies)"
            )
            result.tg_unavailable = True
            return
        if gateway_id is None:
            result.errors.append(
                "TG sync skipped: the gateway could not be resolved this pass "
                "(creation pending or failed); upstreams were not synced (retried next pass)"
            )
            result.tg_unavailable = True
            return
        desired = desired_tg_objects(state)
        managed = self._registry.managed_ids()
        # An unparseable node fails the listing loudly only when gwops owns it.
        owned_ids = {rid for key, rid in managed.items() if is_resource_key(key)}
        try:
            actual = await ops.list_resources(self._tg, managed_ids=owned_ids)
        except TGAPIError as exc:
            result.errors.append(f"TG sync failed: could not list resources: {exc}")
            result.tg_unavailable = True
            return
        actual_by_id = {resource.id: resource for resource in actual}
        try:
            result.remote_web_apps = _web_app_snapshot(actual, owned_ids)
        except Exception as exc:  # observation only: never fails the pass
            error_type = type(exc).__name__
            logger.warning("reconcile.webapp_snapshot_failed", error_type=error_type)
            result.remote_web_apps_error = error_type
            result.webapp_warnings.append(
                f"web-app snapshot of the tenant listing failed ({error_type}); "
                "web-app status is unavailable until a later pass succeeds"
            )
        result.gateway_mismatches = {
            want.key: GatewayMismatch(remote.gateway_id, corrected=False)
            for want in desired
            if (remote := actual_by_id.get(managed.get(want.key, ""))) is not None
            and remote.gateway_id != gateway_id
        }

        for want in desired:
            key = want.key
            recorded_id = managed.get(key)
            exists = recorded_id is not None and recorded_id in actual_by_id
            # An unresolvable access reference is a per-resource error. A resource that does
            # not exist yet is not created (it would come up with the wrong access); an
            # existing one keeps address/port sync but skips its access delta and is not
            # marked synced.
            resolved: ResolvedAccess | None = None
            try:
                resolved = await self._access_resolver.resolve(self._tg, want.access)
            except (AccessResolutionError, TGAPIError) as exc:
                result.resource_error(key, f"access: {exc}")
                if not exists:
                    continue
            try:
                if not exists:
                    assert resolved is not None
                    self._require_write_budget()
                    new_id = await ops.create_resource(
                        self._tg,
                        by_key(want.kind),
                        want.name,
                        want.address,
                        gateway_id,
                        upstream_port=want.upstream_port,
                        extras=want.extras,
                        group_ids=(
                            None if resolved.group_ids is None else sorted(resolved.group_ids)
                        ),
                        security_policy_id=resolved.security_policy_id,
                    )
                    self._registry.record(want.kind, want.name, new_id)
                    self._registry.record_access(
                        key,
                        AppliedAccess(
                            groups=resolved.group_ids or frozenset(),
                            security_policy=resolved.security_policy_id,
                        ),
                    )
                    verb = "created" if recorded_id is None else "recreated"
                    result.actions.append(f"{verb} {want.kind} resource {want.name!r} ({new_id})")
                else:
                    assert recorded_id is not None
                    remote = actual_by_id[recorded_id]
                    if by_key(want.kind).merged_update:
                        await self._sync_merged(
                            want, recorded_id, remote, resolved, gateway_id, result
                        )
                    else:
                        await self._sync_separately(want, recorded_id, remote, resolved, result)
            except _WriteDeferred:
                self._record_deferred(result, key)
            except TGAPIError as exc:
                result.resource_error(key, str(exc))
            except ValueError as exc:
                result.resource_error(key, str(exc))
            else:
                if resolved is not None:
                    result.tg_synced.add(key)

        desired_keys = {want.key for want in desired}
        for key, resource_id in managed.items():
            if not is_resource_key(key) or key in desired_keys:
                continue
            kind, _, name = key.partition("/")
            try:
                self._require_write_budget()
                await ops.delete_resource(self._tg, resource_id)
                self._registry.forget(kind, name)
                result.tg_synced.add(key)
                result.actions.append(f"deleted {kind} resource {name!r} ({resource_id})")
            except _WriteDeferred:
                self._record_deferred(result, key)
            except TGAPIError as exc:
                result.resource_error(key, f"delete: {exc}")
            except ValueError as exc:
                result.resource_error(key, f"delete: {exc}")

        self._log_gateway_mismatches(result, gateway_id)

    def _log_gateway_mismatches(self, result: ReconcileResult, gateway_id: str) -> None:
        """Log the pass's gateway mismatches when the set differs from the last one logged."""
        current = result.gateway_mismatches
        if current == self._logged_gateway_mismatches:
            return
        self._logged_gateway_mismatches = dict(current)
        if not current:
            logger.info("reconcile.gateway_mismatches_cleared", gateway_id=gateway_id)
            return
        logger.warning(
            "reconcile.gateway_mismatches",
            gateway_id=gateway_id,
            mismatches=[
                {
                    "resource": name,
                    "remote_gateway_id": mismatch.remote_gateway_id,
                    "corrected": mismatch.corrected,
                }
                for name, mismatch in sorted(current.items())
            ],
        )

    def _log_webapp_readiness(
        self, state: EffectiveState, result: ReconcileResult, gateway_id: str | None
    ) -> None:
        """Log the web-app readiness set when it differs from the last one logged.

        A pass that did not list the tenant says nothing and keeps the remembered set.
        Never fails a pass.
        """
        if result.remote_web_apps is None:
            return
        try:
            # The snapshot is taken on its own: a runner that raises degrades to one
            # `acme_failed:internal` reason, not to every entry being unverifiable.
            acme_snapshot, acme_snapshot_failed = webapp_readiness.acme_snapshot(self._acme)
            entries = webapp_readiness.compute_readiness(
                state,
                result,
                # Public mode never reads the gwops leaf (and has none to read).
                None if state.public_tls is not None else self._certs.leaf_sans(),
                ca_generated=state.ca.x509.generate,
                on_demand=state.ca.x509.on_demand_issuance,
                gateway_id=gateway_id,
                public=webapp_readiness.public_input(
                    state, result, acme_snapshot, acme_snapshot_failed=acme_snapshot_failed
                ),
            )
            current = tuple((e.name, e.state, tuple(e.reasons)) for e in entries)
            if current == self._logged_readiness:
                return
            self._logged_readiness = current
            logger.info(
                "reconcile.webapp_readiness",
                apps=[
                    {"name": e.name, "managed": e.managed, "state": e.state, "reasons": e.reasons}
                    for e in entries
                ],
            )
        except Exception as exc:  # observation only: never fails a pass
            logger.warning(
                "reconcile.webapp_readiness_failed",
                error_type=type(exc).__name__,
                exc_info=True,
            )

    def _update_webapp_index(self, state: EffectiveState, result: ReconcileResult) -> None:
        """Feed the pass's tenant listing to the enrichment index; never fails a pass."""
        if self._webapp_index is None:
            return
        try:
            managed = self._registry.managed_ids()
            self._webapp_index.update(
                result.remote_web_apps, gateway_id_for(managed, state), managed
            )
        except Exception as exc:  # observation only: never fails a pass
            error_type = type(exc).__name__
            logger.warning("reconcile.webapp_index_failed", error_type=error_type)
            result.webapp_warnings.append(
                f"web-app enrichment index update failed ({error_type}); gateway lines are "
                "enriched from the last successful listing"
            )
            self._webapp_index.mark_stale()

    def _schedule_probe(
        self,
        state: EffectiveState,
        result: ReconcileResult,
        paths: RuntimePaths,
        gateway_id: str | None,
        *,
        ca_ok: bool,
    ) -> None:
        """Hand the pass's tenant listing to the TLS probe; never blocks or fails a pass.

        A pass whose CA bundle step failed schedules nothing (the previous results stay):
        probing without the bundles would report private-CA upstreams as untrusted.
        """
        if self._probe is None:
            return
        if not ca_ok:
            if not self._probe_skip_logged:
                self._probe_skip_logged = True
                logger.warning("reconcile.probe_skipped", reason="ca_bundle_step_failed")
            return
        self._probe_skip_logged = False
        try:
            self._probe.schedule(state, result.remote_web_apps, gateway_id, paths=paths)
        except Exception as exc:  # observation only: never fails a pass
            logger.warning("reconcile.probe_schedule_failed", error_type=type(exc).__name__)

    async def _sync_separately(
        self,
        want: DesiredResource,
        resource_id: str,
        remote: ops.RemoteResource,
        resolved: ResolvedAccess | None,
        result: ReconcileResult,
    ) -> None:
        """Correct an existing resource with one mutation per drifted aspect.

        The gateway is never reassigned on this path; a mismatch is only recorded.
        """
        assert self._tg is not None
        # Computed first: an ``upstream`` settings drift supersedes the port-only update.
        settings = by_key(want.kind).settings_drift(
            want.upstream_port, want.extras, remote.upstream_port, remote.extras
        )
        if remote.address != want.address:
            self._require_write_budget()
            await ops.update_resource_address(self._tg, want.kind, resource_id, want.address)
            result.actions.append(
                f"updated {want.kind} resource {want.name!r} address "
                f"{remote.address!r} -> {want.address!r}"
            )
        # The gateway dials the resource's upstream port (it is not in the rendered
        # config), so drift here breaks the upstream connection.
        if remote.upstream_port != want.upstream_port and "upstream" not in settings:
            self._require_write_budget()
            await ops.update_resource_upstream_port(
                self._tg, want.kind, resource_id, want.upstream_port
            )
            result.actions.append(
                f"updated {want.kind} resource {want.name!r} upstream port "
                f"{remote.upstream_port} -> {want.upstream_port}"
            )
        # Action lines name fields, never values (header values and aliases are tenant config).
        if settings:
            self._require_write_budget()
            await ops.update_resource_settings(self._tg, want.kind, resource_id, settings)
            result.actions.append(
                f"updated {want.kind} resource {want.name!r} settings: "
                f"{', '.join(sorted(settings))}"
            )
        if resolved is not None:
            await self._apply_access_delta(want, resource_id, resolved, result)

    async def _sync_merged(
        self,
        want: DesiredResource,
        resource_id: str,
        remote: ops.RemoteResource,
        resolved: ResolvedAccess | None,
        gateway_id: str,
        result: ReconcileResult,
    ) -> None:
        """Correct an existing merged-update resource with at most one mutation.

        Address, settings, access and gateway reassignment share one write-budget unit.
        """
        assert self._tg is not None
        changes: dict[str, Any] = {}
        fields: list[str] = []
        if remote.address != want.address:
            changes["address"] = want.address
            fields.append("address")
        settings = by_key(want.kind).settings_drift(
            want.upstream_port, want.extras, remote.upstream_port, remote.extras
        )
        unknown = sorted(set(settings) - set(_MERGED_SETTING_ARGS))
        if unknown:
            raise ValueError(f"{want.kind!r} settings drift returned undeclared settings {unknown}")
        for name in sorted(settings):
            changes[_MERGED_SETTING_ARGS[name]] = settings[name]
            if name == "requestHeaderRewrites":
                names = _changed_header_names(
                    want.extras.get(REWRITES_KEY), remote.extras.get(REWRITES_KEY)
                )
                fields.append(f"request headers [{', '.join(names)}]")
            else:
                fields.append(name)
        delta = None if resolved is None else self._plan_access_delta(want.key, resolved)
        if delta is not None:
            changes["added_group_ids"] = delta.added
            changes["removed_group_ids"] = delta.removed
            if delta.policy is not None:
                changes["security_policy_id"] = delta.policy
            fields.append(f"access: {'; '.join(delta.describe())}")
        reassign = remote.gateway_id != gateway_id
        if reassign:
            changes["gateway_id"] = gateway_id
            fields.append(f"gateway {remote.gateway_id} -> {gateway_id}")
        if not changes:
            return

        self._require_write_budget()
        await ops.update_webapp_resource(self._tg, resource_id, **changes)
        if delta is not None:
            self._registry.record_access(want.key, delta.applied)
        if reassign:
            result.gateway_mismatches[want.key] = GatewayMismatch(remote.gateway_id, corrected=True)
        result.actions.append(
            f"updated {want.kind} resource {want.name!r}: {'; '.join(fields)} "
            "(the change re-issues access tokens)"
        )

    def _record_deferred(self, result: ReconcileResult, key: str) -> None:
        """Record that `key`'s pending TG write was skipped because this pass was throttled."""
        result.resource_error(key, DEFERRED_RATE_LIMITED)
        # Field is `resource`, not `key`: the log redactor masks any field named like a secret.
        logger.warning("reconcile.tg_write_deferred", resource=key, reason="rate-limited")

    async def _apply_access_delta(
        self,
        want: DesiredResource,
        resource_id: str,
        resolved: ResolvedAccess,
        result: ReconcileResult,
    ) -> None:
        """Move an existing resource's access from last-applied to desired, as a delta.

        Groups: add desired − last, remove last − desired, so a group an admin added in
        the console (never in last-applied) is never removed. Policy: set only when
        managed and different from last-applied; never reset to Default. An unmanaged key
        is left exactly as it is. Last-applied is recorded only after the mutation
        succeeds (a TGAPIError, or :class:`_WriteDeferred` when this pass was throttled,
        propagates to the caller's per-resource handler).
        """
        assert self._tg is not None
        delta = self._plan_access_delta(want.key, resolved)
        if delta is None:
            return
        self._require_write_budget()
        await ops.update_resource_access(
            self._tg,
            want.kind,
            resource_id,
            added_group_ids=delta.added,
            removed_group_ids=delta.removed,
            security_policy_id=delta.policy,
        )
        self._registry.record_access(want.key, delta.applied)
        result.actions.append(
            f"updated {want.kind} resource {want.name!r} access: {'; '.join(delta.describe())}"
        )

    def _plan_access_delta(self, key: str, resolved: ResolvedAccess) -> _AccessDelta | None:
        """The access change to send for `key`, or None when it already matches."""
        last = self._registry.last_access(key)
        desired_groups = last.groups if resolved.group_ids is None else resolved.group_ids
        added = sorted(desired_groups - last.groups)
        removed = sorted(last.groups - desired_groups)
        policy = resolved.security_policy_id
        set_policy = policy if policy is not None and policy != last.security_policy else None
        if not added and not removed and set_policy is None:
            return None
        return _AccessDelta(
            added=added,
            removed=removed,
            policy=set_policy,
            applied=AppliedAccess(
                groups=desired_groups,
                security_policy=set_policy if set_policy is not None else last.security_policy,
            ),
        )

    # --- step 2: credentials -----------------------------------------------------------

    def _materialize_credentials(
        self, state: EffectiveState, result: ReconcileResult
    ) -> tuple[bool, RuntimePaths]:
        """Copy each cluster's credential sources to content-addressed files.

        Returns ``(ok, paths)``; `paths` adds the copies written, which the render must
        reference. A source outside :attr:`RuntimePaths.k8s_source_root` is a local error.
        """
        ok = True
        copies: dict[str, K8sCredentialFiles] = {}
        root = self._paths.k8s_source_root
        dest_dir = self._paths.k8s_creds_dir
        for cluster in state.k8s_clusters:
            # (seed field, source path, copy stem, copy suffix, copy mode)
            sources = (
                (
                    "bearer_token_file",
                    cluster.bearer_token_file,
                    self._paths.k8s_token_stem(cluster.name),
                    "",
                    _TOKEN_MODE,
                ),
                (
                    "ca_file",
                    cluster.ca_file,
                    self._paths.k8s_ca_stem(cluster.name),
                    RuntimePaths.K8S_CA_SUFFIX,
                    _PUBLIC_MODE,
                ),
            )
            # Read both before writing either, so a refused source leaves no half-written cluster.
            loaded: list[tuple[bytes, str, str, int]] = []
            for field_name, source, stem, suffix, mode in sources:
                try:
                    loaded.append((read_confined(source, root), stem, suffix, mode))
                except ConfinedFileError as exc:
                    result.errors.append(
                        f"cluster {cluster.name!r}: credential file ({field_name}) {exc}; "
                        "mount it under the allowed root and point the seed at it, then "
                        "reconcile again"
                    )
                    ok = False
            if len(loaded) != len(sources):
                continue
            try:
                written: list[Path] = []
                for data, stem, suffix, mode in loaded:
                    dest = content_address(dest_dir, stem, data, suffix=suffix)
                    created = not dest.is_file()
                    write_content_addressed(dest_dir, stem, data, suffix=suffix, mode=mode)
                    written.append(dest)
                    if created:
                        result.actions.append(
                            f"materialized credential {dest.as_posix()} for cluster "
                            f"{cluster.name!r}"
                        )
            except (ConfinedFileError, OSError) as exc:
                result.errors.append(
                    f"cluster {cluster.name!r}: writing the credential copies under "
                    f"{dest_dir.as_posix()} failed: {exc}"
                )
                ok = False
                continue
            copies[cluster.name] = K8sCredentialFiles(token=written[0], ca=written[1])
        return ok, self._paths.with_k8s_credentials(copies)

    def _materialize_ca_bundles(
        self, state: EffectiveState, result: ReconcileResult, paths: RuntimePaths
    ) -> tuple[bool, RuntimePaths]:
        """Validate each web-app CA bundle and copy it to a content-addressed file.

        All bundles are validated before any copy is written; copies are written only when
        web apps are declared. Returns ``(ok, paths)`` with the copies added.
        """
        bundles = state.web_app_proxy.upstream_ca_bundles
        if not bundles:
            return True, paths
        loaded: list[tuple[str, bytes]] = []
        ok = True
        now = datetime.now(UTC)
        for bundle in bundles:
            try:
                data = read_confined(bundle.file, paths.webapp_ca_root)
                problems = webapp_policy.pem_violations(bundle.name, data, now)
            except ConfinedFileError as exc:
                result.errors.append(f"CA bundle {bundle.name!r}: {exc}")
                ok = False
                continue
            except Exception as exc:  # defence in depth: one bundle never aborts the pass
                result.errors.append(
                    f"CA bundle {bundle.name!r}: unexpected {type(exc).__name__} while checking it"
                )
                ok = False
                continue
            if problems:
                result.errors.append(f"CA bundle refused: {'; '.join(problems)}")
                ok = False
                continue
            loaded.append((bundle.name, data))
        if not ok:
            return False, paths
        if not state.web_apps:
            return True, paths

        dest_dir = paths.upstream_ca_dir
        copies: dict[str, Path] = {}
        current = ""
        try:
            for name, data in loaded:
                current = name
                suffix = RuntimePaths.UPSTREAM_CA_SUFFIX
                dest = content_address(dest_dir, name, data, suffix=suffix)
                created = not dest.is_file()
                write_content_addressed(dest_dir, name, data, suffix=suffix, mode=_PUBLIC_MODE)
                copies[name] = dest
                if created:
                    result.actions.append(f"materialized CA bundle {dest.as_posix()} for {name!r}")
        except (ConfinedFileError, OSError) as exc:
            result.errors.append(
                f"writing the CA bundle copies under {dest_dir.as_posix()} failed: {exc}"
            )
            return False, paths
        except Exception as exc:  # defence in depth: one bundle never aborts the pass
            result.errors.append(
                f"CA bundle {current!r}: unexpected {type(exc).__name__} while writing its copy"
            )
            return False, paths
        return True, paths.with_upstream_ca_files(copies)

    # --- post-apply: garbage collection ------------------------------------------------

    async def _collect_garbage(
        self, result: ReconcileResult, state: EffectiveState | None = None
    ) -> None:
        """Remove copies referenced by neither ``config.yaml`` nor its ``.last-good``.

        Also sweeps the public certificate store (see :meth:`_collect_public_garbage`) when
        `state` is given. Never fails a pass: an error is logged, recorded in
        ``housekeeping_errors`` (type name only) and the files stay for a later pass.
        """
        if state is not None:
            await self._collect_public_garbage(state, result)
        self._collect_legacy_leaf(result)
        configs = (self._config_path, last_good_path(self._config_path))
        for directory, label in (
            (self._paths.k8s_creds_dir, "credential"),
            (self._paths.upstream_ca_dir, "CA bundle"),
        ):
            try:
                outcome = collect_garbage(directory, configs)
            except Exception as exc:  # housekeeping never aborts a pass
                logger.warning(
                    "reconcile.gc_failed", directory=str(directory), reason=type(exc).__name__
                )
                result.housekeeping_errors.append(
                    f"garbage collection of the {label} copies failed ({type(exc).__name__})"
                )
                continue
            result.actions.extend(
                f"removed unreferenced {label} copy {path.as_posix()}" for path in outcome
            )
            result.housekeeping_errors.extend(
                f"{label} copy garbage collection: {failure}" for failure in outcome.failures
            )

    def _collect_legacy_leaf(self, result: ReconcileResult) -> None:
        """Remove the pre-store ``leaf.crt`` / ``leaf.key`` once no gateway config names them.

        A config written before the leaf moved into the store may still reference them, and
        ``.last-good`` is the rollback target after an upgrade, so they stay while either
        ``config.yaml`` or ``.last-good`` mentions the path. If either config cannot be read,
        nothing is removed. Never fails a pass: failures are housekeeping errors, type only.
        """
        present = [path for path in self._certs.legacy_leaf_paths if os.path.lexists(path)]
        if not present:
            return
        texts: list[str] = []
        for config in (self._config_path, last_good_path(self._config_path)):
            try:
                texts.append(config.read_text(encoding="utf-8"))
            except FileNotFoundError:
                continue
            except (OSError, UnicodeDecodeError) as exc:
                logger.warning(
                    "reconcile.gc_failed", directory=str(config.parent), reason=type(exc).__name__
                )
                result.housekeeping_errors.append(
                    "legacy leaf files kept: a gateway config could not be read "
                    f"({type(exc).__name__})"
                )
                return
        for path in present:
            if any(path.as_posix() in text for text in texts):
                continue
            try:
                path.unlink()
            except OSError as exc:
                logger.warning(
                    "reconcile.gc_failed", directory=str(path), reason=type(exc).__name__
                )
                result.housekeeping_errors.append(
                    f"removing the legacy leaf file {path.name!r} failed ({type(exc).__name__})"
                )
                continue
            result.actions.append(f"removed legacy leaf file {path.as_posix()}")

    async def _collect_public_garbage(self, state: EffectiveState, result: ReconcileResult) -> None:
        """Sweep the public certificate store; failures are housekeeping errors, type only.

        The store's own collection removes orphaned generations. A directory of a
        certificate no longer declared is removed only when neither ``config.yaml`` nor its
        ``.last-good`` names a path inside it; if either config cannot be read, nothing is
        removed.
        """
        root = self._paths.public_tls_dir
        try:
            # The sweep takes the store lock and does file I/O: keep it off the event loop.
            await asyncio.to_thread(self._public_store.gc)
        except Exception as exc:  # housekeeping never aborts a pass
            logger.warning("reconcile.gc_failed", directory=str(root), reason=type(exc).__name__)
            result.housekeeping_errors.append(
                f"garbage collection of the public certificate store failed ({type(exc).__name__})"
            )
        declared = (
            {c.name for c in state.public_tls.certificates}
            if state.public_tls is not None
            else set()
        )
        try:
            undeclared = sorted(
                entry
                for entry in root.iterdir()
                if entry.name not in declared and entry.is_dir() and not entry.is_symlink()
            )
        except FileNotFoundError:
            return
        except OSError as exc:
            logger.warning("reconcile.gc_failed", directory=str(root), reason=type(exc).__name__)
            result.housekeeping_errors.append(
                f"listing the public certificate store failed ({type(exc).__name__})"
            )
            return
        if not undeclared:
            return
        texts: list[str] = []
        for config in (self._config_path, last_good_path(self._config_path)):
            try:
                texts.append(config.read_text(encoding="utf-8"))
            except FileNotFoundError:
                continue
            except (OSError, UnicodeDecodeError) as exc:
                logger.warning(
                    "reconcile.gc_failed", directory=str(root), reason=type(exc).__name__
                )
                result.housekeeping_errors.append(
                    "public certificate directories kept: a gateway config could not be read "
                    f"({type(exc).__name__})"
                )
                return
        for entry in undeclared:
            if any(f"{entry.as_posix()}/" in text for text in texts):
                continue
            try:
                shutil.rmtree(entry)
            except OSError as exc:
                logger.warning(
                    "reconcile.gc_failed", directory=str(entry), reason=type(exc).__name__
                )
                result.housekeeping_errors.append(
                    f"removing the undeclared public certificate directory {entry.name!r} "
                    f"failed ({type(exc).__name__})"
                )
                continue
            result.actions.append(
                f"removed material of undeclared public certificate {entry.name!r}"
            )

    def _remove_legacy_credential_dirs(self, result: ReconcileResult) -> None:
        """Remove per-cluster credential directories no config references any more."""
        configs = (self._config_path, last_good_path(self._config_path))
        try:
            outcome = remove_legacy_credential_dirs(self._paths.k8s_creds_dir, configs)
        except Exception as exc:  # housekeeping never aborts a pass
            logger.warning("reconcile.legacy_cleanup_failed", reason=type(exc).__name__)
            result.housekeeping_errors.append(
                f"legacy credential directory cleanup failed ({type(exc).__name__})"
            )
            return
        result.actions.extend(
            f"removed legacy credential directory {path.as_posix()}" for path in outcome
        )
        result.housekeeping_errors.extend(
            f"legacy credential directory cleanup: {failure}" for failure in outcome.failures
        )

    # --- step 3: certs -------------------------------------------------------------------

    async def _ensure_certs(
        self, state: EffectiveState, result: ReconcileResult
    ) -> tuple[bool, bool, set[str], str | None]:
        """Ensure CAs, resolve/register the tenant gateway, keep the leaf current.

        Returns ``(local_ok, leaf_changed, sans, gateway_id)``. ``gateway_id`` is the
        resolved gateway (pinned, adopted, or created) that resource sync attaches to,
        or ``None`` when it could not be resolved this pass (no API key, or a TG-side
        failure) — resource sync then skips and retries next pass.
        """
        sans = required_sans(state)
        if state.public_tls is not None:
            return await self._ensure_public_certs(state, result, sans)
        self._public_cert_status.clear()
        self._acme_pending = set()
        self._sync_acme(None, None, result)
        try:
            x509_info = self._certs.ensure_x509_ca(
                generate=state.ca.x509.generate,
                cert_path=_opt_path(state.ca.x509.cert_path),
                key_path=_opt_path(state.ca.x509.key_path),
            )
            if state.ca.x509.on_demand_issuance:
                require_on_demand_ca(x509_info.cert_path, x509_info.key_path)
            ssh_info = self._certs.ensure_ssh_ca(
                generate=state.ca.ssh.generate,
                key_path=_opt_path(state.ca.ssh.key_path),
            )
        except _LOCAL_ERRORS as exc:
            result.errors.append(f"CA material is unusable: {exc}")
            return False, False, sans, None

        gateway_id = await self._ensure_tenant_gateway(state, x509_info, ssh_info, result)

        if not sans:
            return True, False, sans, gateway_id

        # The gateway reloads the leaf only when the previous generation's files are
        # unlinked, so a delete that failed at mint time is retried on every pass.
        try:
            removed = self._certs.collect_leaf_generations()
        except (StoreError, OSError):
            result.errors.append(_LEAF_NOT_RELOADED)
            return False, False, sans, gateway_id
        if removed:
            result.actions.append(
                f"removed {len(removed)} stale leaf generation(s); gateway reloads the leaf"
            )

        leaf_changed = False
        status = self._certs.leaf_status(sans)
        if status.state is not LeafState.OK:
            try:
                minted = self._certs.mint_leaf(sans)
            except _LOCAL_ERRORS as exc:
                result.errors.append(f"leaf mint failed: {exc}")
                return False, False, sans, gateway_id
            if minted.reload_pending:
                result.errors.append(_LEAF_NOT_RELOADED_AFTER_MINT)
                result.actions.append(
                    f"minted TLS leaf ({status.state}: {'; '.join(status.problems) or 'renewal'}) "
                    f"covering {len(sans)} SAN(s) (previous generation not removed; gateway "
                    "has not reloaded)"
                )
                return False, False, sans, gateway_id
            leaf_changed = True
            result.actions.append(
                f"minted TLS leaf ({status.state}: {'; '.join(status.problems) or 'renewal'}) "
                f"covering {len(sans)} SAN(s)"
            )
        return True, leaf_changed, sans, gateway_id

    # --- step 3, public mode -------------------------------------------------------------

    async def _ensure_public_certs(
        self, state: EffectiveState, result: ReconcileResult, sans: set[str]
    ) -> tuple[bool, bool, set[str], str | None]:
        """Public-mode certificate step: resolve the root, install, then register and bind.

        Order: resolve the registered root (a failure is a local error), run the public
        certificate step, ensure the SSH CA, then register the root on the tenant and
        resolve the gateway and decide any rebind. The rebind itself is sent by `_run` only
        after the pass rendered and applied its config successfully. Never mints a gwops CA
        or leaf.
        """
        public = state.public_tls
        assert public is not None
        self._acme_pending = set()
        try:
            root = resolve_registered_root(public.registered_root)
        except RegisteredRootError as exc:
            result.errors.append(f"registered root: {exc}")
            return False, False, sans, gateway_id_for(self._registry.managed_ids(), state)
        certs_ok = self._materialize_public_tls(state, result)
        self._sync_acme(public, root, result)
        try:
            ssh_info = self._certs.ensure_ssh_ca(
                generate=state.ca.ssh.generate,
                key_path=_opt_path(state.ca.ssh.key_path),
            )
        except _LOCAL_ERRORS as exc:
            result.errors.append(f"CA material is unusable: {exc}")
            return False, False, sans, None
        gateway_id = await self._ensure_public_tenant_gateway(state, root, ssh_info, result)
        return certs_ok, False, sans, gateway_id

    def _materialize_public_tls(self, state: EffectiveState, result: ReconcileResult) -> bool:
        """Validate every public certificate, then install them; True when all are installed.

        All-or-nothing per pass: every certificate is read (confined to
        :attr:`RuntimePaths.public_tls_root`) and validated first, each failure recorded as
        ``public certificate '<name>': <reason>`` in ``result.errors``. If any fails, nothing
        is installed and False is returned, so the last good generations keep serving.
        Otherwise each certificate is installed in seed order. A store or OS error is a local
        error, as is an install whose previous generation could not be deleted (the gateway
        reloads only on that delete). Before anything is installed, a served name that the
        leaf SANs of a certificate other than its covering one also match is refused.
        Per-certificate status is kept in ``self._public_cert_status`` and set on
        ``result.public_certs``; a certificate that validated but was not installed because
        another failed is ``pending``.
        """
        public = state.public_tls
        assert public is not None
        try:
            root = resolve_registered_root(public.registered_root)
        except RegisteredRootError as exc:
            result.errors.append(f"registered root: {exc}")
            return False
        previous = self._public_cert_status
        now = datetime.now(UTC)
        loaded: list[tuple[FilePublicCertificate, bytes, bytes, PublicMaterial]] = []
        failed: dict[str, str] = {}
        acme_statuses: dict[str, PublicCertStatus] = {}
        acme_materials: dict[str, PublicMaterial] = {}
        for cert in public.certificates:
            if isinstance(cert, AcmePublicCertificate):
                # Issued by the runner, never read from /config/public-tls/: judged on what
                # the store holds. Nothing valid there means pending, not an error.
                acme_statuses[cert.name], material = self._read_installed_acme(
                    cert, public, root, now, result
                )
                if material is not None:
                    acme_materials[cert.name] = material
                continue
            try:
                cert_pem, key_pem, material = read_public_material(
                    cert, self._paths.public_tls_root, zones=public.zones, root=root, now=now
                )
            except PublicMaterialError as exc:
                failed[cert.name] = str(exc)  # already "public certificate '<name>': ..."
            except Exception as exc:  # defence in depth: one certificate never aborts the pass
                failed[cert.name] = (
                    f"public certificate {cert.name!r}: unexpected {type(exc).__name__} "
                    "while validating it"
                )
            else:
                loaded.append((cert, cert_pem, key_pem, material))
        result.errors.extend(failed.values())

        # A served name that a certificate other than its covering one also matches by SAN
        # would be served by whichever entry loads first.
        materials = {c.name: m for c, _cp, _kp, m in loaded} | acme_materials
        for overlap in find_san_overlaps(required_sans(state), public.certificates, materials):
            result.errors.append(overlap.message)
            for name in (overlap.covering, overlap.other):
                failed.setdefault(name, overlap.message)

        statuses: dict[str, PublicCertStatus] = {}
        if failed:
            for cert in public.certificates:
                last = previous.get(cert.name)
                if cert.name in failed:
                    statuses[cert.name] = _invalid_status(cert, last, failed[cert.name])
                elif cert.name in acme_statuses:
                    statuses[cert.name] = acme_statuses[cert.name]
                else:
                    # Valid, but not installed this pass: it keeps what is served.
                    statuses[cert.name] = _pending_status(cert, last)
            self._set_public_status(result, statuses)
            return False

        installed_all = True
        for cert, cert_pem, key_pem, material in loaded:
            last = previous.get(cert.name)
            try:
                installed = self._public_store.install(cert.name, cert_pem, key_pem)
            except (StoreError, ValueError, OSError) as exc:
                message = f"public certificate {cert.name!r}: install failed: {exc}"
                result.errors.append(message)
                statuses[cert.name] = _invalid_status(cert, last, message)
                installed_all = False
                continue
            if installed.reload_pending:
                # The gateway reloads only when the previous generation is unlinked, so it
                # still serves the old pair; the next pass's install retries the delete.
                message = (
                    f"public certificate {cert.name!r}: installed but previous generation "
                    "not removed; gateway has not reloaded"
                )
                result.errors.append(message)
                result.actions.append(
                    f"installed public certificate {cert.name!r} generation "
                    f"{installed.generation} (previous generation not removed; gateway has "
                    "not reloaded)"
                )
                statuses[cert.name] = _invalid_status(cert, last, message)
                installed_all = False
                continue
            statuses[cert.name] = _ok_status(cert, material, installed.generation)
            if installed.changed:
                result.actions.append(
                    f"installed public certificate {cert.name!r} generation "
                    f"{installed.generation} (gateway hot-reloads)"
                )
        # Seed order, file and ACME entries together.
        self._set_public_status(
            result,
            {
                cert.name: acme_statuses[cert.name]
                if cert.name in acme_statuses
                else statuses[cert.name]
                for cert in public.certificates
            },
        )
        return installed_all

    def _read_installed_acme(
        self,
        cert: AcmePublicCertificate,
        public: PublicTlsSettings,
        root: x509.Certificate,
        now: datetime,
        result: ReconcileResult,
    ) -> tuple[PublicCertStatus, PublicMaterial | None]:
        """Judge a ``source: acme`` certificate by the material installed in the store.

        Valid material whose DNS SANs equal the declared ``names`` gives an ``ok`` or
        ``expiring`` status and is rendered. Nothing installed gives ``pending``. A leaf whose
        SANs differ from the declared names is ``pending`` with ``last_error`` "awaiting
        reissue for changed names". Material the validator refuses or that cannot be read is
        ``invalid``, logged once per distinct message and recorded in ``result.acme_errors``
        (code ``invalid_output``; ``internal`` for an unexpected exception). Every
        not-rendered certificate is added to ``self._acme_pending``; for refused, unreadable
        or mismatched material the runner is also told its store pair is invalid so it
        reissues. Nothing here sets ``local_ok`` false.
        """
        refusal: str | None = None
        code = "invalid_output"
        failure: Exception | None = None
        loaded: tuple[bytes, bytes, PublicMaterial, str] | None = None
        try:
            loaded = read_installed_public_material(
                cert, self._public_store, zones=public.zones, root=root, now=now
            )
        except PublicMaterialError as exc:
            refusal = str(exc)
        except Exception as exc:  # defence in depth: ACME material never aborts the pass
            code = "internal"
            failure = exc
            refusal = (
                f"public certificate {cert.name!r}: unexpected {type(exc).__name__} while "
                "validating the installed material"
            )
        names_changed = loaded is not None and set(leaf_dns_sans(loaded[2])) != set(cert.names)
        if loaded is not None and not names_changed:
            self._logged_acme_material.pop(cert.name, None)
            _cert_pem, _key_pem, material, generation = loaded
            return _ok_status(cert, material, generation), material
        self._acme_pending.add(cert.name)
        if refusal is not None or names_changed:
            self._mark_store_invalid(cert.name)
        if refusal is not None:
            result.acme_errors.append(AcmeError(cert.name, code, refusal))
            if self._logged_acme_material.get(cert.name) != refusal:
                self._logged_acme_material[cert.name] = refusal
                logger.error(
                    "reconcile.acme_installed_material_refused",
                    certificate=cert.name,
                    error=refusal,
                    exc_info=failure,
                )
            return _acme_pending_status(cert, refusal, refused=True), None
        self._logged_acme_material.pop(cert.name, None)
        if names_changed:
            return _acme_pending_status(cert, _ACME_NAMES_CHANGED), None
        return _acme_pending_status(cert, None), None

    def _mark_store_invalid(self, name: str) -> None:
        """Tell the runner the installed pair for `name` is unusable; never raises."""
        if self._acme is None:
            return
        try:
            self._acme.mark_store_invalid(name)
        except Exception:  # the pass never fails because of the runner
            logger.error(
                "reconcile.acme_mark_store_invalid_failed", certificate=name, exc_info=True
            )

    def _sync_acme(
        self,
        public: PublicTlsSettings | None,
        root: x509.Certificate | None,
        result: ReconcileResult,
    ) -> None:
        """Hand the runner the seed's ACME configuration and collect ACME problems.

        Never raises and never touches ``errors``, ``ok`` or ``local_ok``. Records
        ``result.acme_pending`` and ``result.acme_errors``. The runner is configured when the
        configuration (seed ACME block, ``source: acme`` entries, zones, registered root)
        differs from the last one handed over, including to None when the seed declares no
        ACME certificates, the token file is unusable or the configuration is invalid (the
        runner then runs nothing rather than a stale configuration). Otherwise it is woken
        only when the set of pending certificates changed. Without a runner, declared
        ``source: acme`` certificates are reported as ``internal`` errors carrying why it is
        unavailable.
        """
        try:
            if public is not None:
                result.acme_pending = [
                    c.name for c in public.certificates if c.name in self._acme_pending
                ]
                token_unusable = self._check_acme_token(public, result)
            else:
                token_unusable = False
                self._logged_acme_token = None
            runner = self._acme
            if runner is None:
                self._report_runner_unavailable(public, result)
                return
            config: AcmeConfig | None = None
            config_problem: str | None = None
            if public is not None and not token_unusable:
                try:
                    config = AcmeConfig.from_public_tls(public, root)
                except ValueError as exc:
                    config_problem = str(exc)
                    result.acme_errors.append(AcmeError(None, "config", config_problem))
                    if config_problem != self._logged_acme_config:
                        logger.error(
                            "reconcile.acme_config_invalid", error=config_problem, exc_info=True
                        )
            self._logged_acme_config = config_problem
            if not self._acme_configured or config != self._acme_config:
                runner.configure(config)
                self._acme_config = config
                self._acme_configured = True
            elif frozenset(self._acme_pending) != self._acme_woken_for:
                runner.wake()
            self._acme_woken_for = frozenset(self._acme_pending)
            snapshot = runner.snapshot()
            if snapshot.state_error is not None:
                result.acme_errors.append(AcmeError(None, "internal", snapshot.state_error))
                return
            result.acme_errors.extend(
                AcmeError(c.name, c.error_code.value, c.error_excerpt or "")
                for c in snapshot.certificates
                if c.error_code is not None
            )
            if snapshot.task_dead:
                result.acme_errors.append(
                    AcmeError(None, "internal", "the ACME runner task is not running")
                )
        except Exception as exc:  # ACME never fails a pass
            logger.error("reconcile.acme_sync_failed", error_type=type(exc).__name__, exc_info=True)
            result.acme_errors.append(
                AcmeError(None, "internal", f"ACME integration failed ({type(exc).__name__})")
            )

    def _report_runner_unavailable(
        self, public: PublicTlsSettings | None, result: ReconcileResult
    ) -> None:
        """Record that declared ``source: acme`` certificates have no runner to issue them."""
        if public is None or not any(
            isinstance(c, AcmePublicCertificate) for c in public.certificates
        ):
            self._logged_acme_unavailable = None
            return
        detail = f"ACME runner unavailable: {self._acme_unavailable or 'it was not started'}"
        result.acme_errors.append(AcmeError(None, "internal", detail))
        if detail != self._logged_acme_unavailable:
            self._logged_acme_unavailable = detail
            logger.error("reconcile.acme_runner_unavailable", detail=detail)

    def _check_acme_token(self, public: PublicTlsSettings, result: ReconcileResult) -> bool:
        """Record a missing or unusable DNS token file (existence only; never opened).

        Logged as an error once per distinct problem; recorded in ``result.acme_errors`` with
        code ``config`` on every pass while it lasts.

        Returns:
            True when the token file is unusable (the caller must not configure the runner).
        """
        if public.acme is None or not any(
            isinstance(c, AcmePublicCertificate) for c in public.certificates
        ):
            self._logged_acme_token = None
            return False
        problem = token_file_problem(public.acme)
        if problem is None:
            self._logged_acme_token = None
            return False
        result.acme_errors.append(AcmeError(None, "config", problem))
        if problem != self._logged_acme_token:
            self._logged_acme_token = problem
            logger.error("reconcile.acme_token_file_unusable", problem=problem)
        return True

    def _set_public_status(
        self, result: ReconcileResult, statuses: dict[str, PublicCertStatus]
    ) -> None:
        """Remember each certificate's status and expose it on this pass's result.

        Set here, not only in ``_finalize``, so the readiness log written mid-pass sees it.
        """
        self._public_cert_status = statuses
        result.public_certs = list(statuses.values())

    def _public_certs_missing(self, state: EffectiveState) -> bool:
        """True when a declared ``source: file`` certificate has nothing installed.

        ``source: acme`` certificates are not considered: a pending one is skipped from the
        render instead (see :meth:`_public_hold`).
        """
        public = state.public_tls
        if public is None:
            return False
        for cert in public.certificates:
            if not isinstance(cert, FilePublicCertificate):
                continue
            cert_file, key_file = self._public_store.stable_paths(cert.name)
            if not (cert_file.is_file() and key_file.is_file()):
                return True
        return False

    def _public_hold(self, state: EffectiveState) -> str | None:
        """The action line when the gateway must be held down this pass, else None.

        Held when a ``source: file`` certificate has nothing installed (the full hold-down),
        or when no certificate at all can be rendered (every one is a pending ``source: acme``
        certificate). A pending ACME certificate beside a renderable one is not a hold: it is
        left out of the render and its names stay uncovered until it lands.
        """
        public = state.public_tls
        if public is None:
            return None
        if self._public_certs_missing(state):
            return _PUBLIC_HELD_DOWN
        if all(c.name in self._acme_pending for c in public.certificates):
            staging = public.acme is not None and public.acme.is_staging
            return _PUBLIC_NONE_RENDERABLE_STAGING if staging else _PUBLIC_NONE_RENDERABLE
        return None

    async def _ensure_public_tenant_gateway(
        self,
        state: EffectiveState,
        root: x509.Certificate,
        ssh_info: SSHCAInfo,
        result: ReconcileResult,
    ) -> str | None:
        """Register the public root, resolve the gateway, and decide a rebind to the root.

        Sets ``result.registered_root`` on every pass. Returns the resolved gateway id, or
        None when it could not be resolved (no API key, or a TG-side failure). A needed
        rebind is stored in ``self._pending_gateway_update`` and sent by
        :meth:`_settle_gateway_update` after a successful apply. A TG-side failure is
        recorded as an error and never fails the local steps.
        """
        public = state.public_tls
        assert public is not None
        progress = _RootProgress()
        root_sha = root.fingerprint(hashes.SHA256()).hex()
        try:
            return await self._public_gateway_flow(
                state, root, root_sha, ssh_info, result, progress
            )
        finally:
            result.registered_root = RegisteredRootStatus(
                name=public.registered_root,
                sha256=root_sha,
                tg_ca_id=progress.ca_id,
                bound=progress.bound,
            )

    async def _public_gateway_flow(
        self,
        state: EffectiveState,
        root: x509.Certificate,
        root_sha: str,
        ssh_info: SSHCAInfo,
        result: ReconcileResult,
        progress: "_RootProgress",
    ) -> str | None:
        """The body of :meth:`_ensure_public_tenant_gateway`; fills ``progress`` as it goes."""
        public = state.public_tls
        assert public is not None
        if self._tg is None:
            return state.twingate.gateway_id
        tw = state.twingate
        root_name = public.registered_root
        managed = self._registry.managed_ids()
        ca_label = tw.gateway_id or tw.gateway_address or tw.network
        gateway_id = gateway_id_for(managed, state)
        root_ca_id = managed.get(PUBLIC_ROOT_KEY)
        progress.ca_id = root_ca_id
        ssh_ca_id = managed.get("ca/ssh")
        new_ssh_id: str | None = None

        # 1. SSH CA (shared with the private path).
        try:
            if state.ca.ssh.generate and ssh_ca_id is None:
                new_ssh_id = await self._register_ssh_ca(ssh_info, ca_label)
                ssh_ca_id = new_ssh_id
        except _WriteDeferred:
            self._record_gateway_deferred(result, "CA registration")
            return gateway_id
        except TGAPIError as exc:
            result.errors.append(f"CA registration: {exc}")
            return gateway_id

        # 2. Resolve an existing gateway (pin / registry / Mode B adopt). Read-only.
        rn_id: str | None = None
        try:
            if gateway_id is None:
                gateway_id, rn_id = await self._find_mode_b_gateway(state, result)
            elif managed.get("gateway/self") is None:
                self._registry.record("gateway", "self", gateway_id)
        except TGAPIError as exc:
            result.errors.append(f"gateway resolve/create: {exc}")
            return None

        # 3. The gateway's current binding, read fresh on every pass.
        binding: ops.GatewayCABinding | None = None
        if gateway_id is not None:
            try:
                binding = await ops.get_gateway_x509_ca(self._tg, gateway_id)
            except TGAPIError as exc:
                result.errors.append(
                    f"CA registration: reading the X.509 CA bound to gateway {gateway_id} "
                    f"failed: {exc}"
                )
                return gateway_id
            progress.bound = binding is not None and binding.fingerprint == root_sha

        # 4a. A recorded CA id is trusted only while a write is not about to use it: before a
        #     create-bind or a rebind it must still be in the tenant's list for the root's
        #     fingerprint (a CA deleted on the tenant would otherwise fail every pass). A
        #     bound gateway costs no extra read.
        if root_ca_id is not None and (gateway_id is None or progress.bound is False):
            try:
                if root_ca_id not in await ops.find_x509_ca_ids_by_fingerprint(self._tg, root_sha):
                    self._registry.forget("ca", "x509-public")
                    result.actions.append(
                        f"forgot recorded X.509 CA {root_ca_id}: no longer on the tenant with "
                        f"registered public root {root_name}'s fingerprint"
                    )
                    root_ca_id = None
                    progress.ca_id = None
            except TGAPIError as exc:
                result.errors.append(f"CA registration: {exc}")
                return gateway_id

        # 4. The root's tenant CA: registry, else the gateway's binding, else a fingerprint
        #    search, else create (re-searching once if the create fails).
        try:
            if root_ca_id is None:
                if binding is not None and binding.fingerprint == root_sha:
                    root_ca_id = binding.ca_id
                    result.actions.append(
                        f"adopted X.509 CA {root_ca_id} bound to the gateway as registered "
                        f"public root {root_name}"
                    )
                else:
                    root_ca_id = await self._adopt_or_create_public_root(
                        root, root_sha, f"gwops-{ca_label}-{root_name}", root_name, result
                    )
                self._registry.record("ca", "x509-public", root_ca_id)
                progress.ca_id = root_ca_id
        except _WriteDeferred:
            self._record_gateway_deferred(result, "CA registration")
            return gateway_id
        except TGAPIError as exc:
            result.errors.append(f"CA registration: {exc}")
            return gateway_id

        # 5. Mode B create, bound to the root.
        if gateway_id is None:
            assert rn_id is not None
            try:
                gateway_id = await self._create_mode_b_gateway(
                    state, result, rn_id, root_ca_id, ssh_ca_id
                )
            except _WriteDeferred:
                self._record_gateway_deferred(result, "gateway create")
                return None
            except TGAPIError as exc:
                result.errors.append(f"gateway resolve/create: {exc}")
                return None
            progress.bound = True
            self._record_registered_cas(None, new_ssh_id, result)
            return gateway_id

        # 6. Rebind an existing gateway. A rebind changes what every Client accepts, so it is
        #    only decided here; `_run` sends it (with a pending SSH CA binding) after the
        #    pass rendered and applied its config. With no rebind due, a new SSH CA is
        #    bound at once.
        if progress.bound is False:
            self._pending_gateway_update = _GatewayUpdate(
                gateway_id=gateway_id,
                root_ca_id=root_ca_id,
                root_name=root_name,
                old_ca_id=binding.ca_id if binding is not None else None,
                ssh_ca_id=new_ssh_id,
            )
            return gateway_id
        if new_ssh_id is None:
            return gateway_id
        try:
            self._require_write_budget()
            await ops.update_gateway(self._tg, gateway_id, x509_ca_id=None, ssh_ca_id=new_ssh_id)
        except _WriteDeferred:
            self._record_gateway_deferred(result, "CA registration")
            return gateway_id
        except TGAPIError as exc:
            result.errors.append(f"CA registration: {exc}")
            return gateway_id
        self._record_registered_cas(None, new_ssh_id, result)
        return gateway_id

    async def _settle_gateway_update(
        self, result: ReconcileResult, defer_reason: str | None
    ) -> None:
        """Send the pass's pending public-mode rebind, or record why it is deferred.

        Called once per pass after the apply step (or at the point the pass stops).
        `defer_reason` is None only when the pass's credentials, CA bundles, certificates,
        render and apply all succeeded; the rebind is then sent. Otherwise nothing but a
        pending SSH CA binding is sent (it does not depend on the local steps) and the action
        line says the rebind is deferred and why. After a sent rebind the registered root's
        ``bound`` is None until the next pass reads the binding back. A TG failure is a
        ``CA registration:`` error and never a local one.
        """
        update, self._pending_gateway_update = self._pending_gateway_update, None
        if update is None or self._tg is None:
            return
        rebind = defer_reason is None
        if not rebind:
            result.actions.append(
                f"deferred rebinding gateway {update.gateway_id} X.509 CA to registered public "
                f"root {update.root_name} ({update.root_ca_id}): {defer_reason}"
            )
            if update.ssh_ca_id is None:
                return
        try:
            self._require_write_budget()
            await ops.update_gateway(
                self._tg,
                update.gateway_id,
                x509_ca_id=update.root_ca_id if rebind else None,
                ssh_ca_id=update.ssh_ca_id,
            )
        except _WriteDeferred:
            self._record_gateway_deferred(result, "CA registration")
            return
        except TGAPIError as exc:
            result.errors.append(f"CA registration: {exc}")
            return
        self._record_registered_cas(None, update.ssh_ca_id, result)
        if rebind:
            if result.registered_root is not None:
                result.registered_root = replace(result.registered_root, bound=None)
            result.actions.append(
                f"rebound gateway {update.gateway_id} X.509 CA to registered public root "
                f"{update.root_name} ({update.root_ca_id}; was {update.old_ca_id or 'none'}); "
                "the binding is read back on the next pass"
            )

    async def _adopt_or_create_public_root(
        self,
        root: x509.Certificate,
        root_sha: str,
        ca_name: str,
        root_name: str,
        result: ReconcileResult,
    ) -> str:
        """Find the root's CA by fingerprint, else register it.

        If the create fails, search once more (a create that succeeded server-side but
        failed on the wire, or a tenant that refuses duplicates) before giving up.
        Raises :class:`_WriteDeferred` or :class:`TGAPIError`.
        """
        assert self._tg is not None
        existing = await ops.find_x509_ca_ids_by_fingerprint(self._tg, root_sha)
        if existing:
            result.actions.append(
                f"adopted X.509 CA {existing[0]} as registered public root {root_name}"
            )
            return existing[0]
        self._require_write_budget()
        pem = root.public_bytes(serialization.Encoding.PEM).decode("ascii")
        try:
            created = await ops.create_x509_ca(self._tg, ca_name, pem)
        except TGAPIError as create_error:
            try:
                existing = await ops.find_x509_ca_ids_by_fingerprint(self._tg, root_sha)
            except TGAPIError:
                raise create_error from None
            if not existing:
                raise
            result.actions.append(
                f"adopted X.509 CA {existing[0]} as registered public root {root_name} "
                "after the create failed"
            )
            return existing[0]
        result.actions.append(
            f"registered public root {root_name} as X.509 CA {created} ({ca_name})"
        )
        return created

    async def _ensure_tenant_gateway(
        self,
        state: EffectiveState,
        x509_info: CAInfo,
        ssh_info: SSHCAInfo,
        result: ReconcileResult,
    ) -> str | None:
        """Register gwops-generated CAs and resolve the gateway (pin / adopt / create).

        Returns the resolved gateway id, or ``None`` when it could not be resolved this
        pass (no API key, or a TG-side failure). Level-triggered on the registry:
        ``ca/*`` and ``gateway/self`` are recorded only after the tenant call that
        establishes them succeeds, so a failure is retried without duplicating
        (`_unbound_ca_ids` keeps a CA-create retry from making a second CA object).

        - **Mode A** (`twingate.gateway_id` set): use that gateway; rebind it to any
          newly registered CA. Bring-your-own CAs are never auto-registered.
        - **Mode B** (`gateway_id` absent): adopt an existing gateway at
          `twingate.gateway_address` in the remote network, else create one. Create
          needs a registered X.509 CA, so Mode B requires ``ca.x509.generate: true``.
        """
        if self._tg is None:
            # Without an API key only a pinned gateway id can be surfaced.
            return state.twingate.gateway_id
        tw = state.twingate
        managed = self._registry.managed_ids()
        ca_label = tw.gateway_id or tw.gateway_address or tw.network

        # 1. Register gwops-generated CAs (idempotent via registry + _unbound_ca_ids).
        x509_ca_id = managed.get("ca/x509")
        ssh_ca_id = managed.get("ca/ssh")
        new_x509_id: str | None = None
        new_ssh_id: str | None = None
        try:
            if state.ca.x509.generate and x509_ca_id is None:
                new_x509_id = self._unbound_ca_ids.get("x509")
                if new_x509_id is None:
                    self._require_write_budget()
                    new_x509_id = await ops.create_x509_ca(
                        self._tg, f"gwops-x509-{ca_label}", x509_info.pem
                    )
                self._unbound_ca_ids["x509"] = new_x509_id
                x509_ca_id = new_x509_id
            if state.ca.ssh.generate and ssh_ca_id is None:
                new_ssh_id = await self._register_ssh_ca(ssh_info, ca_label)
                ssh_ca_id = new_ssh_id
        except _WriteDeferred:
            self._record_gateway_deferred(result, "CA registration")
            return gateway_id_for(managed, state)
        except TGAPIError as exc:
            result.errors.append(f"CA registration: {exc}")
            return gateway_id_for(managed, state)

        # 2. Resolve the gateway (pin / adopt / create).
        gateway_id = gateway_id_for(managed, state)
        try:
            if gateway_id is None:
                gateway_id, rn_id = await self._find_mode_b_gateway(state, result)
                if gateway_id is None:
                    if x509_ca_id is None:
                        result.errors.append(
                            "cannot auto-create the gateway: no registered X.509 CA. "
                            "Remote-network mode requires ca.x509.generate: true (gwops "
                            "registers the CA it needs to create the gateway), or pin an "
                            "existing gateway with twingate.gateway_id."
                        )
                        return None
                    gateway_id = await self._create_mode_b_gateway(
                        state, result, rn_id, x509_ca_id, ssh_ca_id
                    )
                    # gatewayCreate bound the CA ids it was given.
                    self._record_registered_cas(new_x509_id, new_ssh_id, result)
                    return gateway_id
            elif managed.get("gateway/self") is None:
                self._registry.record("gateway", "self", gateway_id)
        except _WriteDeferred:
            self._record_gateway_deferred(result, "gateway create")
            return None
        except TGAPIError as exc:
            result.errors.append(f"gateway resolve/create: {exc}")
            return None

        # 3. Rebind an existing/adopted/pinned gateway to any newly registered CA.
        if new_x509_id is None and new_ssh_id is None:
            return gateway_id
        try:
            self._require_write_budget()
            await ops.update_gateway(
                self._tg, gateway_id, x509_ca_id=new_x509_id, ssh_ca_id=new_ssh_id
            )
        except _WriteDeferred:
            self._record_gateway_deferred(result, "CA registration")
            return gateway_id
        except TGAPIError as exc:
            result.errors.append(f"CA registration: {exc}")
            return gateway_id
        self._record_registered_cas(new_x509_id, new_ssh_id, result)
        return gateway_id

    async def _register_ssh_ca(self, ssh_info: SSHCAInfo, ca_label: str) -> str:
        """Create the SSH CA on the tenant once; a retry reuses the unbound id.

        Raises :class:`_WriteDeferred` or :class:`TGAPIError`; the caller records them.
        """
        assert self._tg is not None
        ssh_id = self._unbound_ca_ids.get("ssh")
        if ssh_id is None:
            self._require_write_budget()
            ssh_id = await ops.create_ssh_ca(
                self._tg, f"gwops-ssh-{ca_label}", ssh_info.public_key_openssh
            )
        self._unbound_ca_ids["ssh"] = ssh_id
        return ssh_id

    async def _find_mode_b_gateway(
        self, state: EffectiveState, result: ReconcileResult
    ) -> tuple[str | None, str]:
        """Mode B: resolve the remote network and adopt the gateway at the seed address.

        Returns ``(gateway_id, remote_network_id)``; ``gateway_id`` is None when no gateway
        has the address (the caller creates one). Records and logs an adoption. Raises
        :class:`TGAPIError`. The schema guarantees ``gateway_address`` and exactly one of
        ``remote_network`` / ``remote_network_id``.
        """
        assert self._tg is not None
        tw = state.twingate
        assert tw.gateway_address is not None
        rn_id = tw.remote_network_id
        if rn_id is None:
            assert tw.remote_network is not None
            rn_id = await ops.resolve_remote_network_id(self._tg, tw.remote_network)
        gateway_id = await ops.find_gateway_by_address(self._tg, rn_id, tw.gateway_address)
        if gateway_id is not None:
            self._registry.record("gateway", "self", gateway_id)
            result.actions.append(
                f"adopted existing gateway ({gateway_id}) at {tw.gateway_address}"
            )
        return gateway_id, rn_id

    async def _create_mode_b_gateway(
        self,
        state: EffectiveState,
        result: ReconcileResult,
        rn_id: str,
        x509_ca_id: str,
        ssh_ca_id: str | None,
    ) -> str:
        """Mode B: create the gateway bound to the given CAs and record it.

        Raises :class:`_WriteDeferred` or :class:`TGAPIError`.
        """
        assert self._tg is not None
        gateway_address = state.twingate.gateway_address
        assert gateway_address is not None
        self._require_write_budget()
        gateway_id = await ops.create_gateway(
            self._tg, gateway_address, rn_id, x509_ca_id, ssh_ca_id
        )
        self._registry.record("gateway", "self", gateway_id)
        result.actions.append(
            f"created gateway ({gateway_id}) at {gateway_address} in remote network {rn_id}"
        )
        return gateway_id

    def _record_gateway_deferred(self, result: ReconcileResult, step: str) -> None:
        """Record that a gateway/CA write was skipped because this pass was throttled."""
        result.errors.append(f"{step}: {DEFERRED_RATE_LIMITED}")
        logger.warning(
            "reconcile.tg_write_deferred", resource=f"gateway:{step}", reason="rate-limited"
        )

    def _record_registered_cas(
        self, new_x509_id: str | None, new_ssh_id: str | None, result: ReconcileResult
    ) -> None:
        """Record newly bound CAs in the registry and clear their unbound marker."""
        if new_x509_id is not None:
            self._registry.record("ca", "x509", new_x509_id)
            self._unbound_ca_ids.pop("x509", None)
            result.actions.append(f"registered X.509 CA ({new_x509_id}) and bound it to gateway")
        if new_ssh_id is not None:
            self._registry.record("ca", "ssh", new_ssh_id)
            self._unbound_ca_ids.pop("ssh", None)
            result.actions.append(f"registered SSH CA ({new_ssh_id}) and bound it to gateway")

    # --- step 4: render ----------------------------------------------------------------

    async def _render_and_write(
        self, state: EffectiveState, result: ReconcileResult, paths: RuntimePaths
    ) -> tuple[bool, str]:
        """Render a changed config, pre-flight it, and swap it in atomically.

        Returns ``(config_changed_and_applied, previous_config_text)``. The candidate is
        run through :func:`~gwops.supervisor.spawn.validate_config_by_spawn` and its
        outcome classified by :func:`~gwops.supervisor.spawn.classify_outcome` before the
        swap. While the gateway is running, only a schema break discards the candidate:
        the running gateway holds the listener ports, so a valid candidate would fail to
        bind. When the gateway is not running, anything other than a healthy start
        discards it. A candidate that is valid but cannot start at runtime is caught after
        the swap by the early-exit rollback in :mod:`gwops.supervisor.process`.
        """
        old_text = (
            self._config_path.read_text(encoding="utf-8") if self._config_path.is_file() else ""
        )
        try:
            rendered = render_gateway_config(state, self._caps, paths)
        except RenderError as exc:
            result.errors.append(f"render failed: {exc}; keeping previous config")
            result.local_ok = False
            return False, old_text

        if rendered.config_yaml == old_text:
            return False, old_text

        # Never re-apply a config that already failed to start and was rolled back.
        if rendered.config_yaml == self._process.last_rolled_back_config:
            result.errors.append(
                "rendered config matches one that was rolled back after a failed start; "
                "not re-applying — fix the seed/credentials that produce it"
            )
            result.local_ok = False
            return False, old_text

        candidate = self._config_path.with_name(self._config_path.name + ".next")
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_text(rendered.config_yaml, encoding="utf-8")

        outcome = await validate_config_by_spawn(
            self._settings.gateway_binary,
            candidate,
            timeout_seconds=self._validate_timeout_seconds,
        )
        # A running gateway holds the listener ports, so a valid candidate reports a
        # non-schema startup failure; reject only a schema break then. With the gateway
        # stopped the ports are free and the pre-flight is authoritative.
        classification = classify_outcome(outcome).classification
        gateway_running = self._process.state is ProcState.RUNNING
        reject = classification is Classification.SCHEMA_BREAK or (
            not gateway_running and classification is not Classification.HEALTHY
        )
        if reject:
            candidate.unlink(missing_ok=True)
            reason = outcome.stderr_text.strip() or "gateway rejected the config"
            result.errors.append(
                f"rendered config failed validation, keeping previous config: {reason}"
            )
            result.local_ok = False
            return False, old_text

        os.replace(candidate, self._config_path)
        result.actions.append(f"wrote gateway config {self._config_path.as_posix()}")
        return True, old_text

    # --- step 5: apply ---------------------------------------------------------------

    async def _apply(
        self,
        config_changed: bool,
        old_text: str,
        leaf_changed: bool,
        result: ReconcileResult,
    ) -> None:
        if self._shutting_down:
            result.actions.append("skipped gateway apply: shutting down")
            return
        process = self._process
        if process.state is ProcState.STOPPED:
            # Start rather than signal; the config on disk is the newest one that passed
            # validation.
            if not self._config_path.is_file():
                result.errors.append("gateway not started: no valid config has ever been produced")
                result.local_ok = False
                return
            try:
                await process.start()
            except (OSError, RuntimeError) as exc:
                result.errors.append(f"gateway start failed: {exc}")
                result.local_ok = False
                return
            result.actions.append("started gateway")
            return

        if config_changed:
            new_text = self._config_path.read_text(encoding="utf-8")
            reasons = _restart_required_reasons(old_text, new_text)
            if process.state is not ProcState.RUNNING:
                result.actions.append(
                    f"config updated while gateway is {process.state}; the pending "
                    "restart will pick it up"
                )
                return
            try:
                await process.drain_restart()
                if reasons:
                    result.actions.append(
                        f"drain-restarted gateway (restart-required: {'; '.join(reasons)})"
                    )
                else:
                    result.actions.append("drain-restarted gateway (config changed)")
            except (OSError, RuntimeError) as exc:
                result.errors.append(f"applying new config failed: {exc}")
                result.local_ok = False
            return

        if leaf_changed:
            result.actions.append(
                "leaf-only change: gateway hot-reloads certificate files, no action needed"
            )
