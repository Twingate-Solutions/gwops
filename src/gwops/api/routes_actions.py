"""Action routes: /reconcile, /certs/rotate-leaf, /certs/rotate-ca, /upstreams.

The upstream PUT/DELETE routes are sugar over ``POST /overlays``: they build the
equivalent patch and go through the exact same validate-before-persist path, so
there is no second way to mutate state. They are also the only routes the automation
token can reach, so they carry its namespace rules. CA rotation is the
two-phase operator flow from the cert manager (stage -> out-of-band trust updates ->
complete), with the tenant re-registration/rebind folded into ``complete``.
"""

import asyncio
from contextlib import nullcontext
from dataclasses import asdict
from typing import Annotated, Any, Literal, cast, get_args

import structlog
from fastapi import APIRouter, Body, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, ValidationError

from gwops.access.precedence import effective_access
from gwops.access.webapp_policy import FieldViolation
from gwops.acme.runner import IssueStatus
from gwops.acme.token import token_file_problem
from gwops.api.app import GwopsDeps
from gwops.api.ownership import entry_owner, seed_doc
from gwops.api.routes_state import (
    PolicyRefused,
    get_deps,
    load_state_or_409,
    persist_overlay,
    redact_tree,
    serialize_reconcile,
)
from gwops.configmodel.schema import (
    AcmePublicCertificate,
    EffectiveState,
    SeedConfig,
    UpstreamEntry,
)
from gwops.kinds import KINDS, ResourceKind, by_segment
from gwops.renderer.sans import required_sans, strip_port
from gwops.supervisor.process import ProcState
from gwops.tgapi import ops
from gwops.tgapi.client import attribution_via
from gwops.tgapi.errors import TGAPIError

logger = structlog.get_logger(__name__)

router = APIRouter()

_LOCAL_CERT_ERRORS = (ValueError, RuntimeError, FileNotFoundError, OSError)

_CONFLICT_REASON = "conflicts with an existing resource address or alias"

# Stands in for an omitted `address` when a body is validated on its own.
_BODY_CHECK_ADDRESS = "body-check.invalid"

_PUBLIC_MODE_REFUSAL = (
    "public certificate mode (public_tls): gwops does not mint or rotate the {what}"
)

_LOADS_ON_NEXT_START = "gateway loads the new CA on next start"

# Strong references to in-flight CA reload tasks (the loop keeps only weak ones).
_RELOAD_TASKS: set[asyncio.Task[None]] = set()

# The steps gwops cannot do for the operator; returned by both rotation phases.
_ROTATION_MANUAL_STEPS = [
    "Before 'complete': distribute the staged X.509 CA (ca_pem) to any client that "
    "pins or otherwise trusts the gateway's TLS CA. SSH upstream targets need no "
    "change: this rotation does not touch the SSH CA.",
    "After 'complete': the previous CA object remains registered on the Twingate "
    "tenant; delete it there once nothing trusts it anymore.",
]


@router.post("/reconcile")
async def reconcile(request: Request) -> dict[str, Any]:
    """Run (or coalesce into) one reconcile pass and return its result."""
    result = await get_deps(request).reconciler.reconcile("api")
    serialized = serialize_reconcile(result)
    assert serialized is not None  # reconcile() always returns a result
    return serialized


@router.post("/certs/rotate-leaf")
async def rotate_leaf(request: Request) -> dict[str, Any]:
    """Force-mint a fresh TLS leaf covering the current required SAN set."""
    deps = get_deps(request)
    state = load_state_or_409(deps)
    if state.public_tls is not None:
        raise HTTPException(status_code=409, detail=_PUBLIC_MODE_REFUSAL.format(what="leaf"))
    sans = required_sans(state)
    if not sans:
        raise HTTPException(
            status_code=409,
            detail=(
                "no upstreams configured, so the required SAN set is empty; add an "
                "upstream before minting a leaf"
            ),
        )
    try:
        deps.certs.mint_leaf(sans)
    except _LOCAL_CERT_ERRORS as exc:
        raise HTTPException(status_code=500, detail=f"leaf mint failed: {exc}") from exc
    leaf = deps.certs.leaf_status(sans)
    not_after = leaf.not_after
    return {
        "minted": True,
        "sans": sorted(sans),
        "not_after": not_after.isoformat() if not_after else None,
    }


class IssuePublicCertRequest(BaseModel):
    """POST /certs/public/{name}/issue body (optional): ``force`` skips the renewal window."""

    model_config = ConfigDict(extra="forbid")

    force: bool = False


# Status for "the ACME runner cannot take work" (runner absent or not yet configured, state
# file unusable, DNS token file unusable).
_ACME_UNAVAILABLE_STATUS = 409


@router.post("/certs/public/{name}/issue", status_code=202, response_model=None)
async def issue_public_cert(
    request: Request, name: str, body: Annotated[IssuePublicCertRequest | None, Body()] = None
) -> dict[str, Any] | JSONResponse:
    """Queue an immediate ACME issuance or renewal of the ``source: acme`` certificate `name`.

    Admin token only (the automation token is refused by the auth middleware and again
    here). ``force`` adds ``--renew-force``: it skips lego's renewal-window check and never
    the backoff. Answers 202 when queued; 404 when `name` is not a declared public
    certificate; 409 when it is declared with ``source: file``, when issuance for it is
    already running, or when the runner cannot take work (``detail`` says why); 429 with a
    ``Retry-After`` header (seconds) while the certificate is in backoff. The 429 body is
    ``{"detail", "reason", "error_code"}``: ``reason`` is ``backoff`` (a recorded failure),
    ``force_window`` or ``request_floor`` (the limiter between requests), and ``error_code`` is
    the recorded failure class or null.
    """
    if _is_automation(request):
        raise HTTPException(
            status_code=403, detail="the automation token may only use /upstreams/{kind}/{name}"
        )
    force = body.force if body is not None else False
    deps = get_deps(request)
    state = load_state_or_409(deps)
    public = state.public_tls
    cert = (
        next((c for c in public.certificates if c.name == name), None)
        if public is not None
        else None
    )
    if cert is None:
        raise HTTPException(
            status_code=404, detail=f"{name!r} is not a declared public certificate"
        )
    if not isinstance(cert, AcmePublicCertificate):
        raise HTTPException(
            status_code=409,
            detail=(
                f"public certificate {name!r} has source: file; gwops does not issue it "
                "(replace the mounted files instead)"
            ),
        )
    assert public is not None and public.acme is not None  # an acme entry requires the block
    runner = deps.acme
    if runner is None:
        _acme_refused(name, force, "runner_absent", _ACME_UNAVAILABLE_STATUS)
        raise HTTPException(
            status_code=_ACME_UNAVAILABLE_STATUS,
            detail=(
                "the ACME runner is not running"
                + (f" ({deps.acme_unavailable})" if deps.acme_unavailable else "")
                + "; check the gwops startup log"
            ),
        )
    if (problem := token_file_problem(public.acme)) is not None:
        _acme_refused(name, force, "token_file_unusable", _ACME_UNAVAILABLE_STATUS)
        raise HTTPException(status_code=_ACME_UNAVAILABLE_STATUS, detail=problem)
    outcome = runner.request_issue(name, force=force)
    logger.info(
        "api.acme_issue",
        certificate=name,
        force=force,
        outcome=outcome.status.value,
        reason=outcome.reason,
        error_code=outcome.error_code,
        principal=getattr(request.state, "principal", None),
    )
    match outcome.status:
        case IssueStatus.ACCEPTED:
            return {
                "certificate": name,
                "status": "scheduled",
                "force": force,
                "detail": outcome.detail,
            }
        case IssueStatus.ALREADY_RUNNING:
            raise HTTPException(status_code=409, detail=outcome.detail)
        case IssueStatus.IN_BACKOFF:
            seconds = outcome.retry_after_seconds or 1
            return JSONResponse(
                {
                    "detail": outcome.detail,
                    "reason": outcome.reason,
                    "error_code": outcome.error_code,
                },
                status_code=429,
                headers={"Retry-After": str(seconds)},
            )
        case IssueStatus.UNKNOWN_CERTIFICATE:
            # Declared in the seed, but the runner has not been configured with it yet.
            raise HTTPException(
                status_code=_ACME_UNAVAILABLE_STATUS,
                detail=(
                    f"the ACME runner has not picked up {name!r} yet; run POST /reconcile and retry"
                ),
            )
        case IssueStatus.UNAVAILABLE:
            raise HTTPException(status_code=_ACME_UNAVAILABLE_STATUS, detail=outcome.detail)


def _acme_refused(name: str, force: bool, reason: str, status: int) -> None:
    """Log a refusal that never reached the runner (the audit line records the status)."""
    logger.warning(
        "api.acme_issue_refused", certificate=name, force=force, reason=reason, status=status
    )


class RotateCARequest(BaseModel):
    """POST /certs/rotate-ca body: which phase of the staged rotation to run."""

    phase: Literal["stage", "complete"]


@router.post("/certs/rotate-ca")
async def rotate_ca(request: Request, body: Annotated[RotateCARequest, Body()]) -> dict[str, Any]:
    """Staged X.509 CA rotation: ``stage`` a new CA, then ``complete`` to promote it.

    ``complete`` archives the old CA, promotes the staged one, registers it with the
    Twingate tenant, rebinds the gateway, and re-mints the TLS leaf under the new CA.
    Rotation only applies to gwops-generated CAs — a bring-your-own CA's lifecycle
    belongs to the operator.
    """
    deps = get_deps(request)
    state = load_state_or_409(deps)
    if state.public_tls is not None:
        raise HTTPException(status_code=409, detail=_PUBLIC_MODE_REFUSAL.format(what="CA"))
    if not state.ca.x509.generate:
        raise HTTPException(
            status_code=409,
            detail=(
                "the X.509 CA is bring-your-own (ca.x509.generate=false); gwops does "
                "not rotate operator-owned CA material"
            ),
        )

    if body.phase == "stage":
        try:
            staged = deps.certs.stage_x509_rotation()
        except _LOCAL_CERT_ERRORS as exc:
            raise HTTPException(status_code=500, detail=f"staging failed: {exc}") from exc
        return {
            "phase": "stage",
            "ca_pem": staged.pem,
            "staged_cert_path": str(staged.cert_path),
            "manual_steps": _ROTATION_MANUAL_STEPS,
        }

    # phase == "complete"
    try:
        before = deps.certs.ensure_x509_ca(generate=True)
        deps.certs.complete_x509_rotation()
        after = deps.certs.ensure_x509_ca(generate=True)
    except _LOCAL_CERT_ERRORS as exc:
        raise HTTPException(status_code=500, detail=f"promotion failed: {exc}") from exc
    if after.pem == before.pem:
        raise HTTPException(
            status_code=409,
            detail="no staged CA rotation to complete; POST phase='stage' first",
        )

    actions = ["promoted staged X.509 CA (previous CA archived)"]
    errors: list[str] = []
    # Prefer the reconciler-resolved gateway (recorded under gateway/self when auto-created);
    # fall back to a pinned twingate.gateway_id.
    gateway_id = deps.registry.managed_ids().get("gateway/self") or state.twingate.gateway_id
    if deps.tg is None:
        errors.append(
            "TWINGATE_API_KEY is not set: the new CA was NOT registered with the "
            "Twingate tenant; register it and rebind the gateway manually"
        )
    elif gateway_id is None:
        errors.append(
            "the gateway has not been resolved yet (none pinned via gateway_id and "
            "none auto-created); run a reconcile (POST /reconcile) first, then retry"
        )
    else:
        try:
            with attribution_via("admin_api"):
                new_id = await ops.create_x509_ca(deps.tg, f"gwops-x509-{gateway_id}", after.pem)
                await ops.update_gateway(deps.tg, gateway_id, x509_ca_id=new_id)
            deps.registry.record("ca", "x509", new_id)
            actions.append(f"registered new X.509 CA ({new_id}) and rebound gateway")
        except TGAPIError as exc:
            errors.append(
                f"CA registration failed: {exc}; the local rotation is complete — "
                "register the new CA with Twingate manually, or run phase='stage' then "
                "phase='complete' again"
            )

    sans = required_sans(state)
    if sans:
        try:
            deps.certs.mint_leaf(sans)
            actions.append(f"re-minted TLS leaf under the new CA ({len(sans)} SAN(s))")
        except _LOCAL_CERT_ERRORS as exc:
            errors.append(f"leaf re-mint failed: {exc}")

    if state.ca.x509.on_demand_issuance:
        await _reload_on_demand_ca(deps, actions, errors)

    deps.api_event.set()
    log = logger.warning if errors else logger.info
    log("api.rotate_ca_completed", actions=actions, errors=errors)
    return {
        "phase": "complete",
        "actions": actions,
        "errors": errors,
        "manual_steps": _ROTATION_MANUAL_STEPS,
    }


async def _reload_on_demand_ca(deps: GwopsDeps, actions: list[str], errors: list[str]) -> None:
    """Get the gateway's on-demand issuer onto the promoted CA, or say why it is not yet.

    The issuer loads the CA once per file change, so a running gateway is drain-restarted
    under the mutation lock (skipped during shutdown); any other state picks the CA up on
    its next start, except a gateway that was still starting, which may have read the old one.
    The work runs in its own task, shielded from request cancellation: a cancel between the
    drain and the start would leave the gateway DRAINING with nothing to start it.
    """
    reload = _reload_on_demand_ca_locked(deps, actions, errors)
    task = asyncio.get_running_loop().create_task(reload)
    _RELOAD_TASKS.add(task)
    task.add_done_callback(_reload_task_done)
    await asyncio.shield(task)


def _reload_task_done(task: asyncio.Task[None]) -> None:
    """Drop the finished reload task; log (type only) a failure nobody awaited."""
    _RELOAD_TASKS.discard(task)
    if not task.cancelled() and (exc := task.exception()) is not None:
        logger.warning("api.rotate_ca_reload_failed", error_type=type(exc).__name__)


async def _reload_on_demand_ca_locked(
    deps: GwopsDeps, actions: list[str], errors: list[str]
) -> None:
    """The restart decision and the restart, under the mutation and pass locks."""
    # Lock order: mutation lock, then the reconciler's pass lock (mutations reconcile under it).
    pass_lock = getattr(deps.reconciler, "lock", None)
    async with deps.mutation_lock, pass_lock if pass_lock is not None else nullcontext():
        if deps.shutting_down.is_set():
            actions.append(_LOADS_ON_NEXT_START)
            return
        match deps.process.state:
            case ProcState.RUNNING:
                try:
                    await deps.process.drain_restart()
                    actions.append(
                        "drain-restarted gateway so the on-demand issuer loads the new CA"
                    )
                except (OSError, RuntimeError) as exc:
                    errors.append(f"gateway restart failed: {exc}; restart it to load the new CA")
            case ProcState.STARTING:
                errors.append("gateway was starting; restart it to load the new CA")
            case _:
                actions.append(_LOADS_ON_NEXT_START)


# --- upstream sugar ----------------------------------------------------------------------


def _kind_or_404(segment: str) -> ResourceKind:
    kind = by_segment(segment)
    if kind is None:
        known = ", ".join(k.api_segment for k in KINDS)
        raise HTTPException(
            status_code=404, detail=f"unknown upstream kind {segment!r} (known: {known})"
        )
    return kind


def _is_automation(request: Request) -> bool:
    return getattr(request.state, "principal", None) == "automation"


def _check_automation_reach(deps: GwopsDeps, kind: ResourceKind, name: str) -> None:
    """403 unless the automation token may manage `kind` and `name` has the prefix."""
    refused = HTTPException(
        status_code=403,
        detail=f"the automation token may not manage {kind.state_field} entries",
    )
    if not kind.automation_allowed:
        raise refused
    state = load_state_or_409(deps)
    if not kind.automation_enabled(state):
        raise refused
    prefix = state.admin_api.automation.name_prefix
    if prefix and not name.startswith(prefix):
        raise HTTPException(
            status_code=403,
            detail=f"automation upstream names must start with {prefix!r}",
        )


def _require_automation_owned(deps: GwopsDeps, kind: ResourceKind, name: str) -> None:
    """409 when `name` exists and is not owned by the automation token."""
    owner = entry_owner(deps, kind, name)
    if owner not in (None, "automation"):
        raise HTTPException(
            status_code=409,
            detail=(
                f"{kind.state_field} entry {name!r} is owned by {owner}; the automation "
                "token may only change entries it created"
            ),
        )


def _candidate_entry(kind: ResourceKind, name: str, state: EffectiveState) -> UpstreamEntry | None:
    return next((entry for entry in kind.entries(state) if entry.name == name), None)


def _require_candidate_entry(kind: ResourceKind, name: str, state: EffectiveState) -> UpstreamEntry:
    """The candidate's entry; 422 (fail closed) if the state does not hold it."""
    entry = _candidate_entry(kind, name, state)
    if entry is None:
        raise HTTPException(
            status_code=422,
            detail=f"{kind.state_field} entry {name!r} is absent from the resulting state",
        )
    return entry


def _refuse(kind: ResourceKind, name: str, violations: list[FieldViolation]) -> PolicyRefused:
    return PolicyRefused(f"automation policy refused {kind.state_field} entry {name!r}", violations)


def _check_field_policy(kind: ResourceKind, name: str, candidate: EffectiveState) -> None:
    """403 with every field violation of the effective entry."""
    entry = _require_candidate_entry(kind, name, candidate)
    violations = kind.automation_field_violations(entry, candidate)
    if violations:
        raise _refuse(kind, name, violations)


def _validate_body_alone(kind: ResourceKind, name: str, body: dict[str, Any]) -> None:
    """422 when the request body is invalid by itself, judged without any stored state.

    An omitted `address` is stood in for, so a partial update is judged on the fields it
    carries. Messages come from the caller's own body only.
    """
    model = cast(type[BaseModel], get_args(SeedConfig.model_fields[kind.state_field].annotation)[0])
    try:
        model.model_validate({"address": _BODY_CHECK_ADDRESS, **body, "name": name})
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join([kind.state_field, name, *(str(p) for p in err['loc'])])}: {err['msg']}"
            for err in exc.errors()
        )
        raise HTTPException(
            status_code=422, detail=f"request body is invalid:\n  {problems}"
        ) from exc


def _names(address: str, alias: object) -> set[str]:
    names = {strip_port(address.lower())}
    if isinstance(alias, str) and alias:
        names.add(alias.lower())
    return names


def _claimed_locally(
    deps: GwopsDeps, kind: ResourceKind, name: str, candidate: EffectiveState
) -> set[str]:
    """Addresses and aliases of every seed entry and of every other effective entry."""
    taken: set[str] = set()
    seed = seed_doc(deps)
    for other in KINDS:
        for item in seed.get(other.state_field) or []:
            if isinstance(item, dict) and isinstance(item.get("address"), str):
                taken |= _names(item["address"], item.get("alias"))
        for entry in other.entries(candidate):
            if not (other.key == kind.key and entry.name == name):
                taken.update(n.lower() for n in entry.san_names())
    return taken


async def _check_exclusivity(
    deps: GwopsDeps, kind: ResourceKind, name: str, candidate: EffectiveState
) -> None:
    """403 when the entry's address or alias is taken; 503 when that cannot be decided."""
    if deps.tg is None:
        raise HTTPException(
            status_code=503,
            detail="TWINGATE_API_KEY is not set: cannot check address exclusivity",
        )
    try:
        with attribution_via("admin_api"):
            tenant = await ops.list_all_resource_addresses(deps.tg)
    except TGAPIError as exc:
        raise HTTPException(
            status_code=503, detail=f"cannot check address exclusivity: {exc}"
        ) from exc
    own_id = deps.registry.managed_ids().get(kind.resource_key(name))
    taken = _claimed_locally(deps, kind, name, candidate)
    for resource in tenant:
        if resource.id != own_id:
            taken |= {resource.address, *([resource.alias] if resource.alias else [])}
    entry = _require_candidate_entry(kind, name, candidate)
    wanted = {"address": strip_port(entry.address.lower()), "alias": getattr(entry, "alias", None)}
    violations = [
        FieldViolation(field, _CONFLICT_REASON)
        for field, value in wanted.items()
        if value and value.lower() in taken
    ]
    if violations:
        raise _refuse(kind, name, violations)


@router.put("/upstreams/{segment}/{name}")
async def put_upstream(
    request: Request, segment: str, name: str, body: Annotated[dict[str, Any], Body()]
) -> dict[str, Any]:
    """Create/replace one upstream of the kind at `segment` (``ssh``, ``k8s``, ...)
    via an overlay, through the same validation path as ``POST /overlays``.

    The automation token is additionally limited to automation-allowed kinds, the
    seed's name prefix, and entries it owns (409 on a seed/admin entry). A body may not
    carry ``_delete``: removal is ``DELETE``."""
    deps = get_deps(request)
    kind = _kind_or_404(segment)
    if "_delete" in body:
        raise HTTPException(status_code=422, detail="use DELETE to remove an entry")
    if body.get("name", name) != name:
        raise HTTPException(
            status_code=422,
            detail=f"body name {body['name']!r} does not match path name {name!r}",
        )
    standalone = guard = field_policy = exclusivity = None
    if _is_automation(request):
        _check_automation_reach(deps, kind, name)

        def standalone() -> None:
            _validate_body_alone(kind, name, body)

        def guard() -> None:
            _require_automation_owned(deps, kind, name)

        def field_policy(candidate: EffectiveState) -> None:
            _check_field_policy(kind, name, candidate)

        if kind.automation_exclusive_addresses:

            async def exclusivity(candidate: EffectiveState) -> None:
                await _check_exclusivity(deps, kind, name, candidate)

    patch = {kind.state_field: [{**body, "name": name}]}
    return await persist_overlay(
        request,
        patch,
        f"api put {kind.state_field} {name}",
        standalone=standalone,
        guard=guard,
        field_policy=field_policy,
        exclusivity=exclusivity,
    )


@router.delete("/upstreams/{segment}/{name}")
async def delete_upstream(request: Request, segment: str, name: str) -> dict[str, Any]:
    """Remove one upstream via a ``_delete`` overlay.

    A missing entry is a 404 for the admin token, but succeeds with
    ``{"deleted": false}`` (and writes nothing) for the automation token, because
    webhooks retry. Automation may only delete entries it owns (409 otherwise).
    """
    deps = get_deps(request)
    kind = _kind_or_404(segment)
    automation = _is_automation(request)
    if automation:
        _check_automation_reach(deps, kind, name)
    state = load_state_or_409(deps)
    if name not in {entry.name for entry in kind.entries(state)}:
        if automation:
            return {"deleted": False}
        raise HTTPException(status_code=404, detail=f"no {kind.state_field} entry named {name!r}")
    guard = None
    if automation:

        def guard() -> None:
            _require_automation_owned(deps, kind, name)

    patch = {kind.state_field: [{"name": name, "_delete": True}]}
    result = await persist_overlay(
        request, patch, f"api delete {kind.state_field} {name}", guard=guard
    )
    return {**result, "deleted": True}


@router.get("/upstreams/{segment}/{name}")
async def get_upstream(request: Request, segment: str, name: str) -> dict[str, Any]:
    """One upstream's declared and applied state, for a caller confirming an outcome.

    Declared access (pinned references) and effective access after
    ``resource_defaults``; the TG resource id and the access gwops last applied (from
    the registry); the last reconcile time, that resource's errors and its gateway
    mismatch from it, plus the kind's own fields (see ``ResourceKind.detail``). The
    automation token sees only entries it owns (404 otherwise).
    """
    deps = get_deps(request)
    kind = _kind_or_404(segment)
    automation = _is_automation(request)
    if automation:
        _check_automation_reach(deps, kind, name)
    state = load_state_or_409(deps)
    entry = next((e for e in kind.entries(state) if e.name == name), None)
    owner = entry_owner(deps, kind, name)
    if entry is None or (automation and owner != "automation"):
        raise HTTPException(status_code=404, detail=f"no {kind.state_field} entry named {name!r}")
    key = kind.resource_key(name)
    effective = effective_access(entry.access, state.twingate.resource_defaults)
    applied = deps.registry.last_access(key)
    last = deps.reconciler.last_result
    mismatch = last.gateway_mismatches.get(key) if last is not None else None
    detail = kind.detail(entry, state, owner == "automation")
    return {
        "kind": kind.key,
        "name": name,
        "origin": owner,
        "address": entry.address,
        "declared_access": (
            entry.access.model_dump(mode="json", exclude_none=True) if entry.access else None
        ),
        "effective_access": {
            "groups": (None if effective.groups is None else [asdict(r) for r in effective.groups]),
            "security_policy": (
                None if effective.security_policy is None else asdict(effective.security_policy)
            ),
        },
        "tg_resource_id": deps.registry.managed_ids().get(key),
        "applied_access": {
            "groups": sorted(applied.groups),
            "security_policy": applied.security_policy,
        },
        "last_reconcile_at": last.started_at.isoformat() if last is not None else None,
        "errors": list(last.resource_errors.get(key, [])) if last is not None else [],
        "gateway_mismatch": (
            {"remote_gateway_id": mismatch.remote_gateway_id, "corrected": mismatch.corrected}
            if mismatch is not None
            else None
        ),
        **{k: redact_tree(k, v) for k, v in detail.items()},
    }
