"""`create_app(deps)`: the gwops admin API application, auth, and audit trail.

The app is a plain function of its dependencies (`GwopsDeps`), so tests hand it
fakes and the supervisor hands it the live control plane. Two cross-cutting
concerns live here as middleware:

- **Bearer auth** on every route except ``GET /healthz`` (the Docker HEALTHCHECK
  target must work tokenless). The presented token is compared against
  ``GWOPS_ADMIN_TOKEN`` and ``GWOPS_AUTOMATION_TOKEN`` with
  :func:`secrets.compare_digest` (constant-time), and a missing/wrong/unparseable
  credential yields a bodiless 401 — the response never reveals *why* auth failed.
  With no token configured, every protected route is a 401: the API fails closed,
  loudly (one startup warning), never open. The matched principal (``admin`` or
  ``automation``) is stored on ``request.state.principal``.
- **Automation scope**: the automation principal may only call ``PUT``, ``DELETE`` and
  ``GET`` on ``/upstreams/{segment}/{name}``; anything else is a 403.
- **Audit trail**: every mutating request (POST/PUT/DELETE) emits exactly one
  structlog line — principal, route, method, status, and the overlay id the handler
  touched (via ``request.state.overlay_id``). Request bodies and credentials are never
  logged.
"""

import asyncio
import re
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from gwops.access.resolve import AccessResolver
from gwops.acme.runner import AcmeRunner
from gwops.certs.manager import CertManager
from gwops.configmodel.store import OverlayStore
from gwops.jwks import JwksMonitor
from gwops.reconciler.core import Reconciler
from gwops.reconciler.registry import StateRegistry
from gwops.renderer.capabilities import Capabilities
from gwops.settings import GwopsSettings
from gwops.shipper.counters import DropCounters
from gwops.shipper.enrich import WebAppIndex
from gwops.shipper.ship import Shipper
from gwops.shipper.spool import Spool
from gwops.supervisor.process import GatewayProcess
from gwops.tgapi.client import TGClient
from gwops.webapp_probe import ProbeRunner

logger = structlog.get_logger(__name__)

_MUTATING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})
_AUTOMATION_METHODS = frozenset({"PUT", "DELETE", "GET"})
_AUTOMATION_PATH = re.compile(r"^/upstreams/[^/]+/[^/]+$")


@dataclass
class GwopsDeps:
    """Everything the admin routes operate on, bundled at bootstrap.

    `tg` is None when ``TWINGATE_API_KEY`` is unset (tenant-side actions then report
    the gap instead of running). Overlay mutations reconcile synchronously under
    ``mutation_lock`` (applied end to end or rolled back); ``api_event`` is the
    background reconcile trigger for the other actions. ``spool``/``shipper`` are the
    recording path
    (None when recording is disabled, or — shipper only — when ``GWOPS_RECORDING_TOKEN`` is
    unset); `/status` reports their lag. ``jwks`` is the tenant JWKS reachability monitor
    (None when not wired); ``probe`` is the opt-in upstream TLS probe runner (None when not
    wired). ``drops`` counts the gateway lines the recording filter did not ship;
    ``webapp_index`` is the web-app enrichment index (None when not wired); `/status`
    reports both. ``shutting_down`` is set when teardown begins, so a route that would
    restart the gateway skips it. ``acme`` is the ACME runner (None in private mode or when
    it could not be built); ``POST /certs/public/{name}/issue`` and `/status` read it.
    ``acme_unavailable`` is why the runner could not be built (None when it was, or in private
    mode); `/status` reports it for ``source: acme`` certificates.
    """

    settings: GwopsSettings
    store: OverlayStore
    reconciler: Reconciler
    certs: CertManager
    process: GatewayProcess
    caps: Capabilities
    registry: StateRegistry
    tg: TGClient | None
    api_event: asyncio.Event
    spool: Spool | None = None
    shipper: Shipper | None = None
    jwks: JwksMonitor | None = None
    probe: ProbeRunner | None = None
    drops: DropCounters = field(default_factory=DropCounters)
    webapp_index: WebAppIndex | None = None
    acme: AcmeRunner | None = None
    acme_unavailable: str | None = None
    mutation_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    shutting_down: asyncio.Event = field(default_factory=asyncio.Event)
    # Resolves allowlist references at request time (cached for the process lifetime).
    access_resolver: AccessResolver = field(default_factory=AccessResolver)


def _token_matches(provided: str, expected: str) -> bool:
    """Constant-time token comparison (never `==` — that leaks length/prefix timing)."""
    return secrets.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def _bearer_token(authorization: str | None) -> str | None:
    """Extract the token from a ``Bearer <token>`` header, or None if unparseable."""
    if authorization is None:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def create_app(deps: GwopsDeps) -> FastAPI:
    """Build the admin API app around `deps`. Interactive docs are disabled on purpose."""
    # Imported here (not at module top) so the route modules can import GwopsDeps
    # from this module without a cycle.
    from gwops.api.routes_actions import router as actions_router
    from gwops.api.routes_state import PolicyRefused, WebAppPolicyRefused
    from gwops.api.routes_state import router as state_router

    app = FastAPI(title="gwops admin API", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.deps = deps

    @app.exception_handler(PolicyRefused)
    async def _policy_refused(request: Request, exc: PolicyRefused) -> JSONResponse:
        violations = [{"field": v.field, "reason": v.reason} for v in exc.violations]
        return JSONResponse({"detail": exc.detail, "violations": violations}, status_code=403)

    @app.exception_handler(WebAppPolicyRefused)
    async def _webapp_policy_refused(request: Request, exc: WebAppPolicyRefused) -> JSONResponse:
        return exc.response()

    if deps.settings.gwops_admin_token is None:
        logger.warning(
            "api.admin_token_unset",
            reason=(
                "GWOPS_ADMIN_TOKEN is not set; every admin route except GET /healthz "
                "will answer 401 until it is provided"
            ),
        )

    @app.middleware("http")
    async def _auth_and_audit(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Default to 500 so a handler that raises before producing a response is still audited.
        status_code = 500
        principal: str | None = None
        try:
            if request.method == "GET" and request.url.path == "/healthz":
                response = await call_next(request)
            elif (principal := _principal(request)) is None:
                # Bodiless 401: never explain whether the token was missing or wrong.
                response = Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})
            elif principal == "automation" and not (
                request.method in _AUTOMATION_METHODS and _AUTOMATION_PATH.match(request.url.path)
            ):
                response = JSONResponse(
                    {"detail": "the automation token may only use /upstreams/{kind}/{name}"},
                    status_code=403,
                )
            else:
                request.state.principal = principal
                response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            if request.method in _MUTATING_METHODS:
                logger.info(
                    "api.audit",
                    principal=principal,
                    method=request.method,
                    route=request.url.path,
                    status=status_code,
                    overlay_id=getattr(request.state, "overlay_id", None),
                )

    def _principal(request: Request) -> str | None:
        """``admin`` / ``automation`` for a matching bearer token, else None.

        Both comparisons always run, so timing does not reveal which token matched.
        """
        provided = _bearer_token(request.headers.get("authorization"))
        if provided is None:
            return None
        admin = deps.settings.gwops_admin_token
        automation = deps.settings.gwops_automation_token
        is_admin = admin is not None and _token_matches(provided, admin.get_secret_value())
        is_automation = automation is not None and _token_matches(
            provided, automation.get_secret_value()
        )
        if is_admin:
            return "admin"
        return "automation" if is_automation else None

    app.include_router(state_router)
    app.include_router(actions_router)
    return app
