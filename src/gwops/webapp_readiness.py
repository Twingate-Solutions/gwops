"""Passive per-web-app readiness: what still stands between a tenant web app and a working session.

Pure and read-only: the entries come from the pass's tenant listing, the current leaf SANs and
the seed. Nothing is probed here; :func:`apply_probe` merges the opt-in probe's results into
the entries afterwards. Nothing here raises.

Reasons are ``<code>`` or ``<code>:<detail>``:

* ``san_missing:<name>``: the leaf lacks a client-facing name (action required).
* ``covered_on_demand:<name>``: the leaf lacks the DNS name but on-demand issuance covers it.
* ``on_demand_unavailable:<name>``: on-demand would cover the name but this pass's local steps
  failed (action required).
* ``leaf_unreadable``: the current leaf cannot be read, so names cannot be checked (unverifiable).
* ``operator_action``: a gwops-generated CA must be installed in browser trust stores.
* ``byo_ca``: a bring-your-own CA; browser trust is the operator's.
* ``public_cert_invalid:<cert>``: public mode: a certificate covering a client-facing name failed
  validation in the last pass (the last good copy, if any, is still served), validated but
  was never installed because another certificate failed, or (``source: acme``) the installed
  material was refused or could not be read (action required).
* ``public_cert_expiring:<cert>``: public mode: a certificate covering a client-facing name has
  less than a third of its lifetime left.
* ``public_cert_pending:<cert>``: public mode: a ``source: acme`` certificate covering a
  client-facing name has nothing valid installed yet (not issued, or staging dry run); in the
  meantime its names are uncovered (action required).
* ``acme_failed:<code>``: public mode: the ACME runner's last attempt for a ``source: acme``
  certificate covering a client-facing name failed with that class; ``acme_failed:config`` also
  when the DNS token file is unusable; ``acme_failed:internal`` also when the runner is
  unavailable, its task died, its state file is unusable, its snapshot could not be taken or the
  pass recorded another certificate-less ACME problem (action required).
* ``acme_staging_dry_run:<cert>``: public mode: a ``source: acme`` certificate covering a
  client-facing name uses a staging ACME directory, a dry run that never installs or serves a
  certificate; set ``public_tls.acme.directory: production`` to serve (action required).
* ``acme_backoff``: public mode: such a certificate is held back until its next attempt
  (informational).
* ``gateway_ca_unbound``: public mode: the gateway is not bound to the registered public root
  (action required; on every entry).
* ``plaintext_upstreams``: ``none``/``insecure`` upstream outside ``plaintext_upstreams``.
* ``unmanaged``: on this gateway but not declared in the seed.
* ``unserved``: on this gateway while the seed declares no web apps.
* ``gateway_mismatch``: a managed app still attached to another gateway.
* ``not_on_tenant``: declared in the seed, absent from the tenant listing.
* ``wildcard_address``: a wildcard name cannot be matched against the leaf (unverifiable).
* ``computation_failed``: the readiness computation failed (unverifiable).
* ``probe:<outcome>``: the active upstream TLS probe did not end ``ok`` (action required).
* ``probe_ca_unusable``: an upstream CA file could not be loaded, so the probe cannot judge
  (action required).
* ``probe_unverifiable``: the probe may not dial this app's address (unverifiable).
* ``probe_refused_address``: the name resolves to an address the probe never dials (unverifiable).
* ``probe_error:<ErrorType>``: the probe or its batch raised (unverifiable).
* ``probe_pending``: probing is on and this app has no result yet.

In public mode ``san_missing:<name>`` means no declared public certificate covers the name (the
check never reads the leaf), and neither ``operator_action`` nor ``byo_ca`` is reported.

``operator_action``, ``byo_ca``, ``covered_on_demand``, ``public_cert_expiring`` and
``probe_pending`` are informational.
A state is ``action_required`` if any reason is actionable, else ``unverifiable`` if any is
unverifiable, else ``ready``.
"""

import ipaddress
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Literal

import structlog

from gwops.access.allowlist import address_allowed
from gwops.configmodel.schema import EffectiveState, PublicCertificate
from gwops.kinds import WEBAPP
from gwops.renderer.sans import strip_port
from gwops.tlsnames import covering_certificate
from gwops.webapp_probe import ProbeResult

if TYPE_CHECKING:
    from gwops.acme.runner import AcmeRunner, AcmeSnapshot
    from gwops.reconciler.core import PublicCertStatus, ReconcileResult, RemoteWebApp

logger = structlog.get_logger(__name__)

ReadinessState = Literal["ready", "action_required", "unverifiable"]

_INFORMATIONAL = frozenset(
    {
        "acme_backoff",
        "byo_ca",
        "covered_on_demand",
        "operator_action",
        "probe_pending",
        "public_cert_expiring",
    }
)
_UNVERIFIABLE = frozenset(
    {
        "wildcard_address",
        "computation_failed",
        "leaf_unreadable",
        "probe_unverifiable",
        "probe_refused_address",
        "probe_error",
    }
)
_WEAK_UPSTREAM_MODES = frozenset({"none", "insecure"})
_PROBED_UPSTREAM_MODES = frozenset({"verify_full", "verify_ca"})


@dataclass(frozen=True)
class PublicReadinessInput:
    """What readiness needs in public mode: the declared certificates, the last pass's status
    of each, and whether the gateway is bound to the registered root (None when unknown)."""

    certificates: tuple[PublicCertificate, ...]
    statuses: tuple["PublicCertStatus", ...]
    bound: bool | None
    acme: "AcmeSnapshot | None" = None
    """The ACME runner's view (None without a runner); source of ``acme_failed:<code>`` and
    ``acme_backoff``."""
    acme_config_error: bool = False
    """The DNS token file (or the ACME configuration) is unusable: ``acme_failed:config``."""
    acme_internal_error: bool = False
    """A runner-level problem that names no certificate: the runner is unavailable, its task
    died, its state file is unusable, its snapshot failed, or the pass recorded a
    certificate-less ACME error other than ``config``: ``acme_failed:internal``."""
    acme_staging: bool = False
    """The seed's ACME directory is ``staging``: ``acme_staging_dry_run:<cert>``."""


@dataclass(frozen=True)
class ReadinessEntry:
    """One web app's readiness; ``probe`` is ``{outcome, checked_at, target, error_type,
    verify_code}`` when probed."""

    name: str
    id: str | None
    managed: bool
    upstream_tls: str | None
    downstream_tls: str | None
    state: ReadinessState
    reasons: list[str] = field(default_factory=list)
    probe: dict[str, str | int | None] | None = None


def _code(reason: str) -> str:
    return reason.partition(":")[0]


def _state_of(reasons: list[str]) -> ReadinessState:
    codes = {_code(reason) for reason in reasons}
    if codes - _INFORMATIONAL - _UNVERIFIABLE:
        return "action_required"
    return "unverifiable" if codes & _UNVERIFIABLE else "ready"


def unverifiable_entries(state: EffectiveState) -> list[ReadinessEntry]:
    """One ``computation_failed`` entry per declared web app, for a failed readiness computation."""
    return [
        ReadinessEntry(
            name=app.name,
            id=None,
            managed=True,
            upstream_tls=app.upstream_tls,
            downstream_tls=app.downstream.tls,
            state="unverifiable",
            reasons=["computation_failed"],
        )
        for app in state.web_apps
    ]


def _probe_key(entry: ReadinessEntry) -> str:
    """The key the probe stores this entry's result under: its tenant id, else its name."""
    return entry.id or entry.name


def apply_probe(
    entries: list[ReadinessEntry],
    results: Mapping[str, ProbeResult],
    unverifiable: Collection[str],
    *,
    failed: Mapping[str, str] | None = None,
    refused: Collection[str] = (),
    last_batch_error: str | None = None,
) -> list[ReadinessEntry]:
    """Merge probe results into ``entries``; a non-ok outcome needs action.

    An entry the probe could verify but has no result for gets ``probe_error:<type>`` when its
    probe or the last batch raised, else ``probe_pending``.
    """
    failures = failed or {}
    merged: list[ReadinessEntry] = []
    for entry in entries:
        key = _probe_key(entry)
        result = results.get(key)
        reasons = list(entry.reasons)
        probe: dict[str, str | int | None] | None = None
        if result is not None:
            probe = {
                "outcome": result.outcome,
                "checked_at": result.checked_at.isoformat(),
                "target": result.target,
                "error_type": result.error_type,
                "verify_code": result.verify_code,
            }
            if result.outcome == "ca_unusable":
                reasons.append("probe_ca_unusable")
            elif result.outcome != "ok":
                reasons.append(f"probe:{result.outcome}")
        elif key in refused:
            reasons.append("probe_refused_address")
        elif key in unverifiable:
            reasons.append("probe_unverifiable")
        elif entry.upstream_tls in _PROBED_UPSTREAM_MODES:
            if key in failures:
                reasons.append(f"probe_error:{failures[key]}")
            elif last_batch_error is not None:
                reasons.append(f"probe_error:{last_batch_error}")
            else:
                reasons.append("probe_pending")
        merged.append(replace(entry, probe=probe, reasons=reasons, state=_state_of(reasons)))
    return merged


def probe_failed_entries(entries: list[ReadinessEntry]) -> list[ReadinessEntry]:
    """`entries` marked ``unverifiable`` with ``computation_failed``, for a failed probe merge."""
    return [
        replace(entry, state="unverifiable", reasons=[*entry.reasons, "computation_failed"])
        for entry in entries
    ]


def _is_ip(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return False
    return True


def _name_reason(name: str, *, on_demand: bool, local_ok: bool) -> str:
    """The reason for a client-facing name missing from the leaf."""
    if not on_demand or _is_ip(name):
        return f"san_missing:{name}"
    return f"covered_on_demand:{name}" if local_ok else f"on_demand_unavailable:{name}"


def acme_snapshot(runner: "AcmeRunner | None") -> "tuple[AcmeSnapshot | None, bool]":
    """The runner's snapshot, taken on its own so a failing runner cannot fail readiness.

    Returns:
        ``(snapshot, failed)``: ``(None, False)`` without a runner, ``(None, True)`` (logged with
        its traceback) when ``snapshot()`` raised.
    """
    if runner is None:
        return None, False
    try:
        return runner.snapshot(), False
    except Exception:  # observation only: degrade to one acme_failed:internal reason
        logger.error("webapp_readiness.acme_snapshot_failed", exc_info=True)
        return None, True


def public_input(
    state: EffectiveState,
    result: "ReconcileResult",
    acme: "AcmeSnapshot | None" = None,
    *,
    acme_snapshot_failed: bool = False,
) -> PublicReadinessInput | None:
    """The public-mode readiness input for `state` and the pass `result`; None in private mode.

    `acme` is the runner's snapshot, when there is one; `acme_snapshot_failed` says taking it
    raised (see :func:`acme_snapshot`). A pass-level ACME ``config`` error with no certificate
    (unusable token file, invalid ACME configuration) sets ``acme_config_error``; any other
    certificate-less ACME error, a failed snapshot or a dead runner task sets
    ``acme_internal_error``.
    """
    if state.public_tls is None:
        return None
    root = result.registered_root
    return PublicReadinessInput(
        certificates=tuple(state.public_tls.certificates),
        statuses=tuple(result.public_certs or ()),
        bound=root.bound if root is not None else None,
        acme=acme,
        acme_config_error=any(
            e.certificate is None and e.code == "config" for e in result.acme_errors
        ),
        acme_internal_error=(
            acme_snapshot_failed
            or (acme is not None and acme.task_dead)
            or any(e.certificate is None and e.code != "config" for e in result.acme_errors)
        ),
        acme_staging=state.public_tls.acme is not None and state.public_tls.acme.is_staging,
    )


def _acme_reasons(public: PublicReadinessInput, cert_name: str) -> list[str]:
    """ACME reasons for one ``source: acme`` certificate: ``acme_failed:<code>``,
    ``acme_staging_dry_run:<cert>`` and ``acme_backoff``; each reported once."""
    reasons: list[str] = []
    if public.acme_config_error:
        reasons.append("acme_failed:config")
    if public.acme_internal_error:
        reasons.append("acme_failed:internal")
    if public.acme_staging:
        reasons.append(f"acme_staging_dry_run:{cert_name}")
    snapshot = public.acme.get(cert_name) if public.acme is not None else None
    if snapshot is not None:
        reasons.extend(
            code
            for code in snapshot.readiness_codes
            if not code.startswith("public_cert_pending:") and code not in reasons
        )
    return reasons


def _public_reasons(public: PublicReadinessInput, names: list[str]) -> list[str]:
    """Public-mode reasons for the client-facing `names`: uncovered names, then the invalid and
    expiring certificates that cover them (each reported once, in name order), then an
    unbound gateway."""
    reasons: list[str] = []
    status_by_cert = {status.name: status for status in public.statuses}
    flagged: list[str] = []
    for name in names:
        cert = covering_certificate(name, public.certificates)
        if cert is None:
            reasons.append(f"san_missing:{name}")
        elif cert.name not in flagged:
            flagged.append(cert.name)
    for cert_name in flagged:
        status = status_by_cert.get(cert_name)
        if status is None:
            continue
        match status.state:
            case "invalid":
                reasons.append(f"public_cert_invalid:{cert_name}")
            case "pending" if status.generation is None and status.source == "acme":
                # Not issued yet (or the store holds nothing the validator accepts).
                reasons.append(f"public_cert_pending:{cert_name}")
            case "pending" if status.generation is None:
                # Valid but never installed (another certificate failed): nothing serves it.
                reasons.append(f"public_cert_invalid:{cert_name}")
            case "expiring":
                reasons.append(f"public_cert_expiring:{cert_name}")
        if status.source == "acme":
            reasons.extend(r for r in _acme_reasons(public, cert_name) if r not in reasons)
    return reasons


def _entry(
    app: "RemoteWebApp",
    state: EffectiveState,
    leaf: set[str] | None,
    result: "ReconcileResult",
    *,
    ca_generated: bool,
    on_demand: bool,
    public: PublicReadinessInput | None = None,
) -> ReadinessEntry:
    reasons: list[str] = []
    host = strip_port(app.address).lower()
    names = [host] if not app.alias else [host, app.alias.lower()]
    if "*" in host:
        reasons.append("wildcard_address")
    elif public is not None:
        reasons.extend(_public_reasons(public, names))
    elif leaf is None:
        reasons.append("leaf_unreadable")
    else:
        reasons.extend(
            _name_reason(name, on_demand=on_demand, local_ok=result.local_ok)
            for name in names
            if name not in leaf
        )
    if public is not None and public.bound is False:
        reasons.append("gateway_ca_unbound")
    if app.downstream_tls == "tls13" and public is None:
        reasons.append("operator_action" if ca_generated else "byo_ca")
    if app.upstream_tls in _WEAK_UPSTREAM_MODES:
        allowed = state.web_app_proxy.plaintext_upstreams
        if allowed is None or not address_allowed(host, allowed):
            reasons.append("plaintext_upstreams")
    if not state.web_apps:
        reasons.append("unserved")
    elif not app.managed:
        reasons.append("unmanaged")
    mismatch = result.gateway_mismatches.get(WEBAPP.resource_key(app.name))
    if app.managed and mismatch is not None and not mismatch.corrected:
        reasons.append("gateway_mismatch")
    return ReadinessEntry(
        name=app.name,
        id=app.id,
        managed=app.managed,
        upstream_tls=app.upstream_tls,
        downstream_tls=app.downstream_tls,
        state=_state_of(reasons),
        reasons=reasons,
    )


def _not_on_tenant(state: EffectiveState, remote: "list[RemoteWebApp]") -> list[ReadinessEntry]:
    """An entry for each declared web app the tenant listing has no managed app for."""
    on_tenant = {app.name for app in remote if app.managed}
    return [
        ReadinessEntry(
            name=declared.name,
            id=None,
            managed=True,
            upstream_tls=declared.upstream_tls,
            downstream_tls=declared.downstream.tls,
            state="action_required",
            reasons=["not_on_tenant"],
        )
        for declared in state.web_apps
        if declared.name not in on_tenant
    ]


def compute_readiness(
    state: EffectiveState,
    result: "ReconcileResult",
    leaf_sans: set[str] | None,
    *,
    ca_generated: bool,
    on_demand: bool,
    gateway_id: str | None,
    on_failure: Callable[[BaseException], None] | None = None,
    public: PublicReadinessInput | None = None,
) -> list[ReadinessEntry]:
    """Readiness of every web app on ``gateway_id``, managed apps with a gateway mismatch and
    declared apps missing from the tenant.

    Empty when the pass did not list the tenant. `leaf_sans` is None when the leaf is
    unreadable. A failure inside the computation is passed to `on_failure` and degrades to
    ``unverifiable`` entries for the declared apps; this function never raises. In public mode
    (`public` set) names are checked against the public certificates instead of `leaf_sans`,
    and `ca_generated` and `on_demand` are ignored.
    """
    try:
        remote = result.remote_web_apps
        if remote is None:
            return []
        leaf = None if leaf_sans is None else {name.lower() for name in leaf_sans}
        in_scope = [
            app
            for app in remote
            if app.gateway_id == gateway_id
            or (app.managed and WEBAPP.resource_key(app.name) in result.gateway_mismatches)
        ]
        entries = [
            _entry(
                app,
                state,
                leaf,
                result,
                ca_generated=ca_generated,
                on_demand=on_demand,
                public=public,
            )
            for app in in_scope
        ]
        entries.extend(_not_on_tenant(state, remote))
        return sorted(entries, key=lambda entry: (entry.name, entry.id or ""))
    except Exception as exc:  # observation only: degrade, never raise
        logger.warning("webapp_readiness.failed", error_type=type(exc).__name__)
        if on_failure is not None:
            on_failure(exc)
        return unverifiable_entries(state)
