"""Introspection + overlay CRUD: /healthz, /status, /state, /overlays.

Also home of the helpers the actions router shares: deps access, response
serialization, output redaction, and the validate-before-persist gate every
overlay-writing route goes through.
"""

from collections import Counter
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from functools import partial
from typing import Annotated, Any, cast

import structlog
from fastapi import APIRouter, Body, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from gwops.access.allowlist import access_violations, address_violations
from gwops.access.resolve import AccessResolutionError, AccessUnavailableError, pin_patch_access
from gwops.access.webapp_policy import FieldViolation, names_an_entry
from gwops.access.webapp_policy import violations as webapp_violations
from gwops.api.app import GwopsDeps
from gwops.api.status_webapps import (
    certs_block,
    gateway_mismatches_block,
    housekeeping_block,
    jwks_block,
    tls_block,
    web_apps_block,
)
from gwops.configmodel.loader import ConfigLoadError, load_effective_state
from gwops.configmodel.schema import EffectiveState
from gwops.configmodel.store import Origin, Overlay, OverlayStore
from gwops.kinds import KINDS, WEBAPP
from gwops.logging import looks_secret
from gwops.reconciler.core import ReconcileResult
from gwops.renderer.desired import DesiredResource, desired_tg_objects
from gwops.renderer.sans import required_sans
from gwops.supervisor.process import ProcState
from gwops.tgapi.client import attribution_via
from gwops.tgapi.errors import TGAPIError, TGGraphQLError

logger = structlog.get_logger(__name__)

router = APIRouter()

_REDACTED = "[REDACTED]"
# Keys with these suffixes name *locations* of credentials (mount paths the operator
# must be able to see to debug), never credential material itself.
_PATH_KEY_SUFFIXES = ("_file", "_path", "_dir")

# Prefix of the local errors a reconcile pass records when the web-app policy refuses the state.
_WEBAPP_POLICY_ERROR_PREFIX = "web-app policy:"
_WEBAPP_POLICY_REFUSED = "web-app policy refused the change"
# A pass that returned before TG sync leaves one of these (local errors, so never TG errors).
_PRE_SYNC_ABORT_PREFIXES = (_WEBAPP_POLICY_ERROR_PREFIX, "effective state failed to load")


class PolicyRefused(Exception):
    """A write refused by a per-kind policy; the app renders it as a 403 listing `violations`."""

    def __init__(self, detail: str, violations: list[FieldViolation]) -> None:
        super().__init__(detail)
        self.detail = detail
        self.violations = violations


class WebAppPolicyRefused(Exception):
    """A write whose candidate state carries web-app policy violations (HTTP 422)."""

    def __init__(self, violations: list[str], detail: Any = _WEBAPP_POLICY_REFUSED) -> None:
        super().__init__(_WEBAPP_POLICY_REFUSED)
        self.violations = violations
        self.detail = detail

    def response(self) -> JSONResponse:
        """The 422 body: ``detail`` and the violations (names, never values)."""
        return JSONResponse(
            {"detail": self.detail, "violations": self.violations}, status_code=422
        )


def get_deps(request: Request) -> GwopsDeps:
    """The GwopsDeps bundle create_app stashed on the application."""
    return cast(GwopsDeps, request.app.state.deps)


# --- shared serialization / redaction helpers -------------------------------------------


def redact_tree(key: str, value: Any) -> Any:
    """Redact every subtree under a secret-looking key, keeping `*_file`-style paths.

    Same taint-propagation rule as the structlog processor: a secret-named key
    redacts its ENTIRE value before recursion, so nothing hides one level down.
    """
    if key.endswith(_PATH_KEY_SUFFIXES):
        return value
    if looks_secret(key):
        return _REDACTED
    if isinstance(value, dict):
        return {k: redact_tree(str(k), v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_tree(key, item) for item in value]
    return value


def serialize_overlay(overlay: Overlay) -> dict[str, Any]:
    """JSON shape of one overlay; the patch passes through output redaction."""
    return {
        "id": overlay.id,
        "created_at": overlay.created_at.isoformat(),
        "comment": overlay.comment,
        "origin": overlay.origin,
        "patch": {k: redact_tree(k, v) for k, v in overlay.patch.items()},
    }


def serialize_reconcile(result: ReconcileResult | None) -> dict[str, Any] | None:
    """JSON shape of a ReconcileResult (or None if no pass has completed yet)."""
    if result is None:
        return None
    return {
        "ok": result.ok,
        "local_ok": result.local_ok,
        "trigger": result.trigger,
        "started_at": result.started_at.isoformat(),
        "actions": result.actions,
        "errors": result.errors,
    }


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def load_state_or_409(deps: GwopsDeps) -> EffectiveState:
    """Current effective state, or a 409 naming what is broken (routes that need it)."""
    try:
        state, _provenance = load_effective_state(deps.settings.seed_path, deps.store)
    except (ConfigLoadError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return state


class _PreviewStore:
    """An OverlayStore view with one extra, not-yet-persisted candidate overlay."""

    def __init__(self, store: OverlayStore, candidate: Overlay) -> None:
        self._store = store
        self._candidate = candidate

    def list(self) -> list[Overlay]:
        return [*self._store.list(), self._candidate]


# Overlays may only touch operational config. Identity/trust config (`twingate`, `ca`,
# `admin_api`) and `recording.receiver_url` are seed-only: letting an overlay redirect them
# or a credential file path would let the admin token exfiltrate the API key, the recordings
# or the CA private key.
_OVERLAY_ALLOWED_TOP_KEYS = frozenset({kind.state_field for kind in KINDS} | {"recording"})
_OVERLAY_FORBIDDEN_RECORDING_KEYS = frozenset({"receiver_url"})


def _reject_forbidden_overlay_keys(patch: dict[str, Any]) -> None:
    """Raise 422 if the patch sets any field an overlay is not allowed to change."""
    bad_top = sorted(set(patch) - _OVERLAY_ALLOWED_TOP_KEYS)
    if bad_top:
        raise HTTPException(
            status_code=422,
            detail=(
                f"overlay may not set {bad_top}: those keys are seed-only "
                f"(identity/trust config). Allowed top-level keys: "
                f"{sorted(_OVERLAY_ALLOWED_TOP_KEYS)}."
            ),
        )
    recording = patch.get("recording")
    if isinstance(recording, dict):
        bad_rec = sorted(set(recording) & _OVERLAY_FORBIDDEN_RECORDING_KEYS)
        if bad_rec:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"overlay may not set recording.{bad_rec[0]}: the recording "
                    "destination is seed-only (it carries the GWOPS_RECORDING_TOKEN on egress)."
                ),
            )


def validate_patch(deps: GwopsDeps, patch: dict[str, Any], comment: str) -> EffectiveState:
    """Reject (422) a patch that touches forbidden fields or fails schema validation.

    First an allowlist gate (`_reject_forbidden_overlay_keys`): an overlay may only set
    operational config, never identity/trust config. Then the candidate is merged on top
    of the real seed + persisted overlays and the result fully re-validated BEFORE
    anything is written, so a bad patch can never reach disk. The 422 detail carries the
    loader's dotted-path error, with the offending layer named ``candidate``. Returns the
    validated candidate state.
    """
    _reject_forbidden_overlay_keys(patch)
    candidate = Overlay(
        id="candidate", created_at=datetime.now(UTC), comment=comment, patch=patch
    )
    preview = cast(OverlayStore, _PreviewStore(deps.store, candidate))
    try:
        state, _provenance = load_effective_state(deps.settings.seed_path, preview)
    except (ConfigLoadError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return state


def _written_web_apps(patch: dict[str, Any]) -> set[str]:
    """Names of the web-app entries the patch writes (deletions excluded)."""
    entries = patch.get(WEBAPP.state_field) or []
    return {
        e["name"]
        for e in entries
        if isinstance(e, dict) and not e.get("_delete") and isinstance(e.get("name"), str)
    }


def _current_violations_or_none(deps: GwopsDeps) -> list[str] | None:
    """The violations of the current effective state; None (logged) when it does not load."""
    try:
        current, _provenance = load_effective_state(deps.settings.seed_path, deps.store)
    except (ConfigLoadError, ValueError) as exc:
        logger.warning(
            "api.webapp_policy_current_state_unloadable", error_type=type(exc).__name__
        )
        return None
    return webapp_violations(current, deps.caps)


def _current_violations(deps: GwopsDeps) -> list[str]:
    """The violations of the current effective state; empty when it does not load."""
    return _current_violations_or_none(deps) or []


def check_webapp_policy(deps: GwopsDeps, patch: dict[str, Any], candidate: EffectiveState) -> None:
    """Raise WebAppPolicyRefused for the violations the write is answerable for.

    Every violation of an entry the patch writes is reported, including one the entry
    already had (the write would carry it forward). Anything else, gateway-wide or on an
    untouched entry, is reported only when the current state does not already have it. If
    the current state does not load there is nothing to compare with: then no violation that
    names an untouched entry is reported, only gateway-wide ones and the written entries'.
    """
    written = _written_web_apps(patch)
    if not written:
        return
    current = _current_violations_or_none(deps)
    existing = set(current or ())
    untouched = candidate.model_copy(
        update={WEBAPP.state_field: [e for e in candidate.web_apps if e.name not in written]}
    )
    elsewhere = Counter(webapp_violations(untouched, deps.caps))
    reported: list[str] = []
    for violation in webapp_violations(candidate, deps.caps):
        if elsewhere[violation] > 0:  # not attributable to a written entry
            elsewhere[violation] -= 1
            if current is None:
                if names_an_entry(violation):
                    continue
            elif violation in existing:
                continue
        reported.append(violation)
    if reported:
        raise WebAppPolicyRefused(reported)


class _WithoutOverlayStore:
    """An OverlayStore view with one overlay removed."""

    def __init__(self, store: OverlayStore, overlay_id: str) -> None:
        self._store = store
        self._overlay_id = overlay_id

    def list(self) -> list[Overlay]:
        return [o for o in self._store.list() if o.id != self._overlay_id]


def check_webapp_policy_after_delete(deps: GwopsDeps, overlay: Overlay) -> None:
    """Raise WebAppPolicyRefused when removing `overlay` adds web-app violations."""
    if WEBAPP.state_field not in overlay.patch:
        return
    preview = cast(OverlayStore, _WithoutOverlayStore(deps.store, overlay.id))
    try:
        after, _provenance = load_effective_state(deps.settings.seed_path, preview)
    except (ConfigLoadError, ValueError):
        return  # the change-failure check reports a state that no longer loads
    budget = Counter(_current_violations(deps))
    added: list[str] = []
    for violation in webapp_violations(after, deps.caps):
        if budget[violation] > 0:
            budget[violation] -= 1
        else:
            added.append(violation)
    if added:
        raise WebAppPolicyRefused(added)


def _desired_by_key(deps: GwopsDeps) -> dict[str, DesiredResource] | None:
    """The desired TG objects of the current effective state keyed by ``kind/name``,
    or None if the state does not load."""
    try:
        state, _provenance = load_effective_state(deps.settings.seed_path, deps.store)
    except (ConfigLoadError, ValueError):
        return None
    return {d.key: d for d in desired_tg_objects(state)}


def _differs(before: DesiredResource | None, after: DesiredResource) -> bool:
    """Whether `after` changed from `before`, extras included (eq skips them)."""
    return before is None or before != after or before.extras != after.extras


def _policy_refused(result: ReconcileResult) -> bool:
    """Whether the pass failed locally because the web-app policy refused the state."""
    return not result.local_ok and any(
        error.startswith(_WEBAPP_POLICY_ERROR_PREFIX) for error in result.errors
    )


def _policy_violations(result: ReconcileResult) -> list[str]:
    """The pass's web-app policy refusals, without the error prefix."""
    return [
        error.removeprefix(_WEBAPP_POLICY_ERROR_PREFIX).strip()
        for error in result.errors
        if error.startswith(_WEBAPP_POLICY_ERROR_PREFIX)
    ]


def _change_failure(
    deps: GwopsDeps,
    before: dict[str, DesiredResource] | None,
    after: dict[str, DesiredResource] | None,
    local_ok_before: bool,
    result: ReconcileResult,
) -> tuple[int, str, list[str]] | None:
    """Why a just-applied overlay change did not succeed end to end, or None if it did.

    Returns ``(http_status, reason, unsynced_keys)``. A change fails when the state no
    longer loads, when any TG object it added/changed is not confirmed in sync (or one
    it removed is still owned on the tenant), or when it turned a locally healthy
    gateway unhealthy. Failures that pre-date the change are not attributed to it:
    other keys' TG errors are ignored, and an already-unhealthy local state does not
    block it. 503 when the tenant was unusable for the whole pass, else 422. A pass the
    web-app policy refused syncs nothing, so that is reported as the cause (always 422)
    rather than as a Twingate failure.
    """
    if after is None:
        return 422, "the resulting state does not load", []
    baseline = before or {}
    changed = sorted(k for k, want in after.items() if _differs(baseline.get(k), want))
    removed = sorted(set(baseline) - set(after))
    managed = deps.registry.managed_ids()
    unsynced = [k for k in changed if k not in result.tg_synced] + [
        k for k in removed if k in managed
    ]
    local_broken = local_ok_before and not result.local_ok
    if (unsynced or local_broken) and _policy_refused(result):
        return 422, _WEBAPP_POLICY_REFUSED, unsynced
    if unsynced:
        status = 503 if result.tg_unavailable else 422
        return status, f"Twingate sync did not complete for {unsynced}", unsynced
    if local_broken:
        return 422, "the change broke the local gateway config", []
    return None


async def apply_overlay_change[T](
    deps: GwopsDeps, change: Callable[[], Awaitable[tuple[T, Callable[[], None]]]]
) -> tuple[T, ReconcileResult]:
    """Apply one overlay change end to end, or roll it back.

    `change` performs the store mutation (validating first, raising HTTPException
    before writing anything on bad input) and returns ``(value, undo)``. The change is
    then reconciled synchronously; if :func:`_change_failure` attributes a failure to
    it, `undo` restores the store, a second reconcile converges the tenant back (e.g.
    deletes a resource the failed pass already created), and the request fails with the
    reconcile errors, so a failed change never leaves an orphaned overlay behind.
    Mutations are serialized on ``deps.mutation_lock`` so each one's before/after
    comparison sees only its own change.
    """
    async with deps.mutation_lock:
        before = _desired_by_key(deps)
        last = deps.reconciler.last_result
        local_ok_before = last is None or last.local_ok
        value, undo = await change()
        try:
            after = _desired_by_key(deps)
            result = await deps.reconciler.reconcile("api")
        except BaseException:
            undo()
            raise
        failure = _change_failure(deps, before, after, local_ok_before, result)
        if failure is None:
            return value, result
        status, reason, unsynced = failure
        undo()
        rollback = await deps.reconciler.reconcile("api-rollback")
        logger.warning(
            "api.change_rolled_back",
            reason=reason,
            unsynced=unsynced,
            errors=result.errors,
            rollback_ok=rollback.ok,
        )
        detail = {
            "message": f"change rolled back: {reason}",
            "rolled_back": True,
            "unsynced": unsynced,
            "errors": result.errors,
            "rollback": serialize_reconcile(rollback),
        }
        if reason == _WEBAPP_POLICY_REFUSED:
            raise WebAppPolicyRefused(_policy_violations(result), detail)
        raise HTTPException(status_code=status, detail=detail)


async def pin_access_or_http_error(deps: GwopsDeps, patch: dict[str, Any]) -> dict[str, Any]:
    """Pin the patch's access references to ``{id, name}``, mapping failures to HTTP.

    A bad reference (no match, several matches, unknown id, or a GraphQL-level rejection)
    is the caller's input: 422. No API key, or the tenant unreachable: 503. Either way
    nothing has been persisted yet.
    """
    try:
        with attribution_via("admin_api"):
            return await pin_patch_access(deps.tg, patch)
    except (AccessResolutionError, TGGraphQLError) as exc:
        raise HTTPException(status_code=422, detail=f"access reference: {exc}") from exc
    except AccessUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except TGAPIError as exc:
        raise HTTPException(
            status_code=503, detail=f"could not resolve access references: {exc}"
        ) from exc


async def check_allowlists(
    deps: GwopsDeps,
    patch: dict[str, Any],
    *,
    after_access: Callable[[], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Enforce the seed's address and access allowlists; returns the pinned patch.

    Address check first (no TG needed), then references are pinned to ids and checked
    against the access allowlist, then `after_access`. A violation is 403; an allowlist
    gwops cannot currently resolve (tenant unreachable, or a seed allowlist name that
    matches no single object) is 503 — nothing is persisted either way.
    """
    state = load_state_or_409(deps)
    violations = address_violations(patch, state.twingate.address_allowlist)
    if violations:
        raise HTTPException(status_code=403, detail=f"address allowlist: {violations}")
    pinned = await pin_access_or_http_error(deps, patch)
    try:
        with attribution_via("admin_api"):
            violations = await access_violations(
                deps.access_resolver, deps.tg, pinned, state.twingate.access_allowlist
            )
    except (AccessResolutionError, TGAPIError) as exc:
        raise HTTPException(
            status_code=503, detail=f"cannot evaluate twingate.access_allowlist: {exc}"
        ) from exc
    if violations:
        raise HTTPException(status_code=403, detail=f"access allowlist: {violations}")
    if after_access is not None:
        await after_access()
    return pinned


async def persist_overlay(
    request: Request,
    patch: dict[str, Any],
    comment: str,
    *,
    standalone: Callable[[], None] | None = None,
    guard: Callable[[], None] | None = None,
    field_policy: Callable[[EffectiveState], None] | None = None,
    exclusivity: Callable[[EffectiveState], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """The shared mutation path: standalone check -> guard -> merged validation ->
    web-app policy -> field policy -> address allowlist -> pin refs -> access allowlist ->
    exclusivity -> persist -> reconcile -> keep or roll back.

    `standalone`, `guard`, `field_policy` and `exclusivity` run under the mutation lock
    before anything is written (the upstream routes use them for the automation rules);
    the last two receive the validated candidate state. `standalone` validates the request
    body on its own and `guard` is the namespace check; both run before the body is merged
    with stored state, so a caller who fails the guard learns nothing about an entry's
    stored values from a validation error. The web-app policy (every principal) raises
    :class:`WebAppPolicyRefused` for the callers to render as 422, and exclusivity runs
    last because it lists the whole tenant. The overlay records the caller's principal as
    its origin.
    Returns the persisted overlay plus the reconcile pass that applied it.
    """
    deps = get_deps(request)
    origin: Origin = (
        "automation" if getattr(request.state, "principal", None) == "automation" else "admin"
    )

    async def change() -> tuple[Overlay, Callable[[], None]]:
        if standalone is not None:
            standalone()
        if guard is not None:
            guard()
        candidate = validate_patch(deps, patch, comment)
        check_webapp_policy(deps, patch, candidate)
        if field_policy is not None:
            field_policy(candidate)
        pinned = await check_allowlists(
            deps,
            patch,
            after_access=partial(exclusivity, candidate) if exclusivity is not None else None,
        )
        try:
            overlay = deps.store.add(pinned, comment, origin)
        except ValueError as exc:  # store-level bounds (patch too large / too deep)
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        request.state.overlay_id = overlay.id
        return overlay, lambda: deps.store.delete(overlay.id)

    overlay, result = await apply_overlay_change(deps, change)
    return {**serialize_overlay(overlay), "reconcile": serialize_reconcile(result)}


# --- routes ------------------------------------------------------------------------------


@router.get("/healthz")
async def healthz(request: Request) -> JSONResponse:
    """Composite health for Docker HEALTHCHECK: gateway process x last reconcile."""
    deps = get_deps(request)
    gateway_ok = deps.process.state in (ProcState.RUNNING, ProcState.STARTING)
    last = deps.reconciler.last_result
    # Only local reconcile health counts: a TG-side sync error must not mark the container
    # unhealthy while the gateway runs on a good local config. None = still starting.
    reconcile_ok = last is None or last.local_ok
    healthy = gateway_ok and reconcile_ok
    # Unauthenticated route: booleans and a timestamp only, since reconcile actions/errors
    # can name addresses, tenant ids and credential paths.
    body = {
        "status": "ok" if healthy else "unhealthy",
        "checks": {
            "gateway": {"ok": gateway_ok, "state": deps.process.state.value},
            "reconcile": {
                "ok": reconcile_ok,
                "last_at": _iso(last.started_at) if last is not None else None,
            },
        },
    }
    return JSONResponse(body, status_code=200 if healthy else 503)


@router.get("/status")
async def status(request: Request) -> dict[str, Any]:
    """Operational snapshot: process, capabilities, last reconcile, certs, TG, shipper."""
    deps = get_deps(request)
    state_error: str | None = None
    state: EffectiveState | None = None
    sans: set[str] = set()
    try:
        state, _provenance = load_effective_state(deps.settings.seed_path, deps.store)
        sans = required_sans(state)
    except (ConfigLoadError, ValueError) as exc:
        state_error = str(exc)

    last = deps.reconciler.last_result
    tg_errors = [
        e for e in (last.errors if last else []) if e.startswith(("TG sync", "CA registration"))
    ]
    tg_attempted = deps.tg is not None and _tg_attempted(last)
    tg_aborted = deps.tg is not None and last is not None and not tg_attempted
    return {
        "process": {"state": deps.process.state.value, "returncode": deps.process.returncode},
        # Template keys are policy input, not part of the /status contract.
        "capabilities": {"gateway_version": deps.caps.gateway_version},
        "last_reconcile": serialize_reconcile(last),
        "certs": certs_block(deps, state, sans, last),
        "tg": {
            "configured": deps.tg is not None,
            "attempted": tg_attempted,
            "ok": (
                None if tg_aborted else deps.tg is not None and last is not None and not tg_errors
            ),
            "errors": tg_errors,
            "gateway_mismatches": gateway_mismatches_block(last),
        },
        "web_apps": web_apps_block(deps, state, last),
        "tls": tls_block(state),
        "jwks": jwks_block(deps),
        "housekeeping": housekeeping_block(last),
        "shipper": _shipper_status(deps),
        "state_error": state_error,
    }


def _tg_attempted(last: ReconcileResult | None) -> bool:
    """Whether the last pass reached TG sync (its own `tg_attempted` wins when it has one)."""
    if last is None:
        return False
    reported = getattr(last, "tg_attempted", None)
    if isinstance(reported, bool):
        return reported
    return not any(error.startswith(_PRE_SYNC_ABORT_PREFIXES) for error in last.errors)


def _shipper_status(deps: GwopsDeps) -> dict[str, Any]:
    """The recording-path block of `/status`.

    The spool/shipper pair built at bootstrap, with live lag counters; ``shipping`` is
    False when ``GWOPS_RECORDING_TOKEN`` was missing (lines spool locally); ``dropped_lines``
    counts lines the filter did not spool, by reason; ``enrich_failed`` counts lines shipped
    unchanged because enrichment failed; ``enrichment`` reports the web-app index's freshness.
    ``disabled`` when recording is off.
    """
    if deps.spool is None:
        return {"mode": "disabled"}
    return {
        "mode": "spool",
        "shipping": deps.shipper is not None,
        "pending_lines": deps.spool.pending_lines,
        "pending_bytes": deps.spool.pending_bytes,
        "dropped_lines": deps.drops.snapshot(),
        "enrich_failed": deps.drops.enrich_failed,
        "enrichment": _enrichment_status(deps),
        "last_success_at": (
            _iso(deps.shipper.lag.last_success_at) if deps.shipper is not None else None
        ),
    }


def _enrichment_status(deps: GwopsDeps) -> dict[str, Any]:
    """Whether a tenant listing ever fed the enrichment index, when it last did, and its size."""
    index = deps.webapp_index
    if index is None:
        return {"active": False, "last_update_at": None, "apps": 0}
    return {
        "active": index.active,
        "last_update_at": _iso(index.last_update_at),
        "apps": index.apps,
    }


@router.get("/state")
async def get_state(request: Request) -> dict[str, Any]:
    """The merged effective state with per-field provenance, secrets redacted."""
    deps = get_deps(request)
    try:
        state, provenance = load_effective_state(deps.settings.seed_path, deps.store)
    except (ConfigLoadError, ValueError) as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    dump = state.model_dump(mode="json")
    return {
        "state": {k: redact_tree(k, v) for k, v in dump.items()},
        "provenance": provenance,
    }


@router.get("/overlays")
async def list_overlays(request: Request) -> list[dict[str, Any]]:
    """All persisted overlays, in application order."""
    return [serialize_overlay(o) for o in get_deps(request).store.list()]


class OverlayRequest(BaseModel):
    """POST /overlays body: the patch to apply on top of the current state."""

    patch: dict[str, Any]
    comment: str = ""


@router.post("/overlays", status_code=201)
async def create_overlay(
    request: Request, body: Annotated[OverlayRequest, Body()]
) -> dict[str, Any]:
    """Validate the patch, persist it, and apply it end to end (rolled back on failure)."""
    return await persist_overlay(request, body.patch, body.comment)


@router.delete("/overlays/{overlay_id}", status_code=204)
async def delete_overlay(request: Request, overlay_id: str) -> Response:
    """Remove one overlay by id and apply that end to end (restored on failure).

    422 on a malformed id or when the removal would add web-app policy violations; 404 on
    an unknown id.
    """
    deps = get_deps(request)

    async def change() -> tuple[None, Callable[[], None]]:
        overlay = deps.store.get(overlay_id)
        if overlay is not None:
            check_webapp_policy_after_delete(deps, overlay)
        try:
            deps.store.delete(overlay_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(
                status_code=404, detail=f"no overlay with id {overlay_id!r}"
            ) from exc
        assert overlay is not None  # delete() succeeded, so it existed
        request.state.overlay_id = overlay_id
        return None, lambda: deps.store.restore(overlay)

    await apply_overlay_change(deps, change)
    return Response(status_code=204)
