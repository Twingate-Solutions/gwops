"""PID-1 entrypoint: wire the control plane, bring up the gateway, own the signals.

``bootstrap`` runs the fail-loud startup gate and returns the wired control plane
(process handle, reconciler, trigger event); ``main`` configures logging, runs
bootstrap, starts the reconcile trigger sources, installs signal handlers, and blocks
until asked to shut down.

Startup behaviour:

- **Degraded start.** A valid seed with no upstreams has an empty required-SAN set, so no
  TLS leaf can be minted. gwops stays up with the gateway child held down; the first
  upstream to arrive (seed change or admin API) mints the leaf and starts the child.
  Invalid config, unusable CA material, or a populated seed whose local steps cannot
  produce a startable gateway still fails loud (exit 1 in ``main``).
- **Rotation crash recovery.** :meth:`CertManager.recover_x509_rotation` runs before
  :meth:`CertManager.ensure_x509_ca`, so an interrupted CA rotation is finished (staged CA
  promoted) instead of a third CA being generated.
- **First reconcile.** ``reconcile("startup")`` owns Twingate sync, credentials,
  certs/SANs, render/validate and starting the child. Twingate-side failures are recorded
  and retried on later triggers; they do not block startup if the local pipeline produced
  a running gateway. SIGHUP triggers a reconcile.

``bootstrap`` also builds the FastAPI admin app, which ``main`` serves with uvicorn on the
seed's ``admin_api`` bind (default 127.0.0.1:8081).

When the seed enables recording, each gateway stderr line is classified; the audit and
session lines it keeps are appended (web-app lines enriched) to a bounded :class:`Spool`
under ``<data_dir>/spool``, and the rest are counted and dropped. A :class:`Shipper` task
(run by ``main``) delivers batches to the configured recording sink when
``GWOPS_RECORDING_TOKEN`` is set; without it, lines spool locally (with a warning) until a restart
supplies the token. Recording settings are read once at startup.

Independently of recording, every stderr line whose gateway logger is ``system`` is relayed to
gwops' stdout log as a ``gateway.system`` event (:func:`relay_system_line`); no other stderr
content is ever echoed.
"""

import asyncio
import os
import signal
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import httpx
import structlog
import uvicorn
from cryptography import x509
from fastapi import FastAPI

from gwops.access import webapp_policy
from gwops.access.allowlist import check_automation_startup
from gwops.acme.runner import AcmeRunner
from gwops.acme.token import token_file_problem
from gwops.api.app import GwopsDeps, create_app
from gwops.certs.manager import CertManager
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
from gwops.certs.store import MaterialStore
from gwops.configmodel.loader import ConfigLoadError, load_effective_state
from gwops.configmodel.schema import AcmePublicCertificate, EffectiveState
from gwops.configmodel.store import OverlayStore
from gwops.jwks import JwksMonitor, jwks_url, make_client
from gwops.logging import configure_logging
from gwops.reconciler.core import Reconciler
from gwops.reconciler.registry import StateRegistry
from gwops.reconciler.watch import run_triggers
from gwops.renderer.capabilities import Capabilities, gateway_capabilities
from gwops.renderer.render import RenderError, RuntimePaths
from gwops.renderer.sans import required_sans
from gwops.settings import GwopsSettings
from gwops.shipper.counters import DropCounters, FailureLog
from gwops.shipper.enrich import WebAppIndex
from gwops.shipper.filter import DropReason, classify, system_fields
from gwops.shipper.ship import Shipper
from gwops.shipper.spool import Spool
from gwops.supervisor.process import GatewayProcess, ProcState
from gwops.tgapi.client import TGClient
from gwops.webapp_probe import ProbeRunner

logger = structlog.get_logger(__name__)

# Upper bound on one JWKS probe, well above the client's 5 s timeout; a hung probe is cancelled.
_JWKS_CHECK_TIMEOUT_SECONDS = 30.0

# Period of the dropped-lines log.
_DROP_LOG_INTERVAL_SECONDS = 300.0

# Startup-gate failures that mean "abort loudly" — main() maps these to exit 1.
_STARTUP_ERRORS = (
    ConfigLoadError,
    RenderError,
    RegisteredRootError,
    ValueError,
    RuntimeError,
    FileNotFoundError,
    OSError,
)


@dataclass
class BootstrapResult:
    """What the startup gate produced: the gateway handle and the wired control plane."""

    process: GatewayProcess
    gateway_started: bool
    config_path: Path
    state: EffectiveState
    caps: Capabilities
    certs: CertManager
    store: OverlayStore
    registry: StateRegistry
    reconciler: Reconciler
    api_event: asyncio.Event
    tg: TGClient | None
    admin_app: FastAPI
    spool: Spool | None
    shipper: Shipper | None
    jwks: JwksMonitor | None = None
    jwks_client: httpx.AsyncClient | None = None
    probe: ProbeRunner | None = None
    deps: GwopsDeps | None = None
    drops: DropCounters = field(default_factory=DropCounters)
    webapp_index: WebAppIndex = field(default_factory=WebAppIndex)
    acme: AcmeRunner | None = None
    """The ACME runner; ``main`` starts it after bootstrap and closes it before the gateway
    child stops. None only when constructing it raised unexpectedly (logged, never fatal)."""
    acme_unavailable: str | None = None
    """Why `acme` is None: the exception type and text of the failed construction. None when the
    runner was built."""


# Keys the structlog pipeline owns; a gateway field with one of these names is kept under a
# `gateway_` prefix so it can neither overwrite them nor break the log call.
_RESERVED_EVENT_KEYS = frozenset(
    {"event", "level", "timestamp", "exc_info", "stack_info", "exception"}
)
_RELAY_LEVELS = {
    "warn": "warning",
    "warning": "warning",
    "error": "error",
    "dpanic": "error",
    "panic": "error",
    "fatal": "error",
}


def relay_system_line(raw: bytes) -> None:
    """Relay one gateway stderr line to gwops' stdout log if it is a `system` line.

    Emits a ``gateway.system`` event carrying every field of the gateway's JSON line
    (``ts``, ``levelname``, ``logger``, ``message``, ``caller``, ``version`` and any
    others). Audit, ``session_recording``, non-JSON and `asciicast`-bearing lines are never
    relayed (see :func:`gwops.shipper.filter.system_fields`). Never raises.
    """
    try:
        obj = system_fields(raw)
        if obj is None:
            return
        fields = {
            (f"gateway_{key}" if key in _RESERVED_EVENT_KEYS else key): value
            for key, value in obj.items()
        }
        level = _RELAY_LEVELS.get(str(obj.get("levelname", "")).lower(), "info")
        getattr(logger, level)("gateway.system", **fields)
    except Exception:  # the relay must never disturb the spool or the reader
        logger.warning("gateway.system_relay_failed")


def _default_line_sink(_line: str) -> None:
    """No-op child-output consumer; the reader already re-emits every line to our stdout."""


def _opt_path(value: str | None) -> Path | None:
    return Path(value) if value else None


_ACME_NAMES_CHANGED = "awaiting reissue for changed names"


def _acme_staging_certificates(state: EffectiveState) -> list[str]:
    """Names of the ``source: acme`` certificates when the seed's ACME directory is staging."""
    public = state.public_tls
    if public is None or public.acme is None or not public.acme.is_staging:
        return []
    return [c.name for c in public.certificates if isinstance(c, AcmePublicCertificate)]


def _warn_acme_startup(state: EffectiveState) -> None:
    """Startup warnings for ``source: acme``: a staging directory, and Cloudflare variables.

    A staging directory is a dry run that never installs a certificate. ``CF_*`` and
    ``CLOUDFLARE_*`` variables in gwops' own environment are never given to lego (the DNS token
    comes from the mounted token file only); only their names are logged.
    """
    public = state.public_tls
    if public is None or not any(isinstance(c, AcmePublicCertificate) for c in public.certificates):
        return
    if staging := _acme_staging_certificates(state):
        logger.warning(
            "supervisor.acme_staging_dry_run",
            certificates=staging,
            reason=(
                "public_tls.acme.directory is staging: certificates are issued and validated "
                "but never installed or served. Set public_tls.acme.directory: production to "
                "serve them."
            ),
        )
    ignored = sorted(name for name in os.environ if name.startswith(("CF_", "CLOUDFLARE_")))
    if ignored:
        logger.warning(
            "supervisor.acme_cloudflare_environment_ignored",
            variables=ignored,
            reason=(
                "these variables are in gwops' environment but lego never receives them: the "
                "DNS API token must come from the token file (public_tls.acme.token_file)"
            ),
        )


def _validate_public_material(
    state: EffectiveState, paths: RuntimePaths, root: x509.Certificate, store: MaterialStore
) -> list[str]:
    """Read and validate every public certificate; abort startup listing every failure.

    Only validates: nothing is installed here, the first reconcile pass installs. Each
    failure line names the certificate and the file or property, never contents.

    ``source: acme`` certificates are exempt from the abort, whatever goes wrong with them. They
    are checked from what `store` holds under ``/data/public-tls/<name>/`` (one generation read
    at a time): valid material whose DNS SANs equal the declared names is used for the
    SAN-overlap check, nothing installed is ``pending`` (logged, not an error), and installed
    material that the validator refuses, that cannot be read, that raised unexpectedly or whose
    SANs differ from the declared names is treated as ``pending`` (logged as an error, or as a
    warning for changed names) and left out of the overlap check. An overlap that involves an
    ``source: acme`` certificate is logged, not fatal. A missing or unusable DNS token file is
    logged as an error too.

    Returns:
        The names of the ``source: acme`` certificates whose installed material is refused,
        unreadable or does not match the declared names, so the caller can tell the runner.
    """
    public = state.public_tls
    assert public is not None
    now = datetime.now(UTC)
    failures: list[str] = []
    materials: dict[str, PublicMaterial] = {}
    invalid_acme: list[str] = []
    has_acme = any(isinstance(c, AcmePublicCertificate) for c in public.certificates)
    if (
        public.acme is not None
        and has_acme
        and (problem := token_file_problem(public.acme)) is not None
    ):
        logger.error("supervisor.acme_token_file_unusable", problem=problem)
    for cert in public.certificates:
        if isinstance(cert, AcmePublicCertificate):
            try:
                installed = read_installed_public_material(
                    cert, store, zones=public.zones, root=root, now=now
                )
            except PublicMaterialError as exc:
                logger.error(
                    "supervisor.acme_installed_material_refused",
                    certificate=cert.name,
                    error=str(exc),
                    status="pending",
                )
                invalid_acme.append(cert.name)
                continue
            except Exception as exc:  # startup never aborts for ACME material
                logger.error(
                    "supervisor.acme_installed_material_unexpected",
                    certificate=cert.name,
                    error_type=type(exc).__name__,
                    status="pending",
                    exc_info=True,
                )
                invalid_acme.append(cert.name)
                continue
            if installed is None:
                logger.warning("supervisor.acme_certificate_pending", certificate=cert.name)
            elif set(leaf_dns_sans(installed[2])) != set(cert.names):
                logger.warning(
                    "supervisor.acme_certificate_pending",
                    certificate=cert.name,
                    detail=_ACME_NAMES_CHANGED,
                )
                invalid_acme.append(cert.name)
            else:
                materials[cert.name] = installed[2]
            continue
        try:
            _cert_pem, _key_pem, materials[cert.name] = read_public_material(
                cert, paths.public_tls_root, zones=public.zones, root=root, now=now
            )
        except PublicMaterialError as exc:
            failures.append(str(exc))
    acme_names = {c.name for c in public.certificates if isinstance(c, AcmePublicCertificate)}
    for overlap in find_san_overlaps(required_sans(state), public.certificates, materials):
        if {overlap.covering, overlap.other} & acme_names:
            logger.error(
                "supervisor.acme_san_overlap", covering=overlap.covering, other=overlap.other
            )
        else:
            failures.append(overlap.message)
    if failures:
        raise ValueError(
            f"public certificate material refused ({len(failures)} certificate(s)):\n"
            + "\n".join(f"- {failure}" for failure in failures)
        )
    return invalid_acme


async def bootstrap(
    settings: GwopsSettings,
    *,
    on_stdout_line: Callable[[str], None] = _default_line_sink,
    on_stderr_line: Callable[[str], None] = _default_line_sink,
) -> BootstrapResult:
    """Run the fail-loud startup gate and bring the gateway up (or hold it down).

    Raises on any startup failure (invalid config, unusable CA, unspawnable binary,
    a populated seed whose local steps cannot produce a running gateway); ``main`` turns
    that into exit 1. Twingate-side errors alone never abort: they are recorded on the
    reconcile result and retried on later triggers. Returns a :class:`BootstrapResult`
    whose ``gateway_started`` is False in the degraded upstream-less case.
    """
    caps = gateway_capabilities()

    store = OverlayStore(settings.data_dir / "overlays")
    state, _provenance = load_effective_state(settings.seed_path, store)
    # The automation token is only safe behind both seed allowlists.
    check_automation_startup(settings, state)
    problems = webapp_policy.violations(state, caps)
    if problems:
        raise ValueError(
            f"web-app policy refused the configuration ({len(problems)} violation(s)):\n"
            + "\n".join(f"- {problem}" for problem in problems)
        )

    paths = RuntimePaths.from_settings(settings)
    certs = CertManager(paths.pki_dir)
    # One store instance for the startup read, the ACME runner's installs and the reconciler's
    # sweep, so they share one lock.
    public_store = MaterialStore(paths.public_tls_dir)
    invalid_acme: list[str] = []
    # Finish any interrupted CA rotation before ensuring the CA, so a half-completed
    # promotion does not lead to a third CA. The ensure_* calls make CA validity a startup
    # failure even for an upstream-less seed (the reconciler records errors instead).
    if state.public_tls is not None:
        # Public mode: no gwops X.509 CA to recover or ensure. The registered root must
        # resolve from the system trust store, otherwise startup aborts.
        public_root = resolve_registered_root(state.public_tls.registered_root)
        _warn_acme_startup(state)
        invalid_acme = _validate_public_material(state, paths, public_root, public_store)
    else:
        certs.recover_x509_rotation()
        x509_ca = certs.ensure_x509_ca(
            generate=state.ca.x509.generate,
            cert_path=_opt_path(state.ca.x509.cert_path),
            key_path=_opt_path(state.ca.x509.key_path),
        )
        if state.ca.x509.on_demand_issuance:
            require_on_demand_ca(x509_ca.cert_path, x509_ca.key_path)
            logger.warning("tls.on_demand_issuance_active", reason=state_tls_warning(state))
    certs.ensure_ssh_ca(
        generate=state.ca.ssh.generate,
        key_path=_opt_path(state.ca.ssh.key_path),
    )

    # Recording path: stderr -> filter -> [enrich] -> spool -> shipper.
    drops = DropCounters()
    webapp_index = WebAppIndex(on_enrich_failed=drops.count_enrich_failed)
    spool_failures = FailureLog("shipper.spool_append_failed")
    spool: Spool | None = None
    shipper: Shipper | None = None
    if state.recording.enabled:
        spool = Spool(settings.data_dir / "spool", state.recording.spool_max_bytes)
        spool.on_lost = lambda n: drops.count(DropReason.SPOOL_FAILED, n)
        receiver_url = state.recording.receiver_url
        assert receiver_url is not None  # schema: enabled=true requires the URL
        if settings.recording_token is not None:
            shipper = Shipper(spool, receiver_url, settings.recording_token.get_secret_value())
        else:
            logger.warning(
                "supervisor.shipper_token_missing",
                reason=(
                    "recording.enabled is true but GWOPS_RECORDING_TOKEN is "
                    "not set; recording lines spool locally (bounded, oldest evicted "
                    "loudly) and ship only after a restart provides the token"
                ),
            )

    # Enrichment needs only the delivery URL (not the token): lines spool enriched either way.
    enrich_active = spool is not None and bool(state.recording.receiver_url)

    def record(target: Spool, raw: bytes) -> None:
        """Spool a kept line (enriched when active); count a dropped one, never spool it."""
        verdict = classify(raw)
        if not verdict.keep:
            assert verdict.reason is not None  # Verdict refuses a drop without a reason
            drops.count(verdict.reason)
            return
        line = webapp_index.enrich(raw, verdict.obj) if enrich_active and verdict.obj else raw
        try:
            target.append(line)
        except (OSError, ValueError) as exc:
            drops.count(DropReason.SPOOL_FAILED)
            spool_failures.emit("spool", error_type=type(exc).__name__)

    def child_stderr(raw: bytes) -> None:
        try:
            if spool is not None:
                record(spool, raw)
        finally:  # the echo path sees every line, whatever the filter or spool did
            relay_system_line(raw)
            if on_stderr_line is not _default_line_sink:
                on_stderr_line(raw.decode("utf-8", errors="replace").rstrip("\r"))

    config_path = settings.runtime_dir / "config.yaml"
    process = GatewayProcess(
        settings.gateway_binary,
        config_path,
        on_stdout_line,
        child_stderr,
        # The renderer always enables the gateway's recording capability, so stderr may carry
        # session-recording payloads regardless of `recording.enabled` (which only controls
        # whether gwops spools and ships them). Never echo stderr content to our stdout log.
        echo_stderr_content=False,
        on_stderr_too_long=lambda: drops.count(DropReason.TOO_LONG),
    )

    registry = StateRegistry(settings.data_dir / "state.json")
    tg: TGClient | None = None
    if settings.twingate_api_key is not None:
        tg = TGClient(
            network=state.twingate.network,
            api_key=settings.twingate_api_key.get_secret_value(),
            host=state.twingate.host,
        )
    else:
        logger.warning(
            "supervisor.tg_sync_disabled",
            reason=(
                "TWINGATE_API_KEY is not set; declared upstreams will not be synced "
                "to the Twingate tenant until it is provided"
            ),
        )
    # Initial flag only: the runner re-reads it from the state on every schedule.
    probe = ProbeRunner(paths, enabled=state.web_app_proxy.upstream_tls_probe)
    api_event = asyncio.Event()
    # The ACME runner installs through the same store instance the reconciler sweeps, so the
    # two share one lock. It loads its own state file; an unusable one leaves it in its
    # state-error mode (issuance refused, never fatal). A landed certificate sets `api_event`
    # so the next pass renders it. `main` starts it after bootstrap.
    acme: AcmeRunner | None = None
    acme_unavailable: str | None = None
    try:
        acme = AcmeRunner(settings, store=public_store, on_installed=lambda _name: api_event.set())
    except Exception as exc:  # startup never aborts for ACME
        acme_unavailable = f"{type(exc).__name__}: {exc}"[:300]
        logger.error(
            "acme.runner_unavailable",
            error_type=type(exc).__name__,
            error=str(exc),
            exc_info=True,
        )
    if acme is not None:
        for name in invalid_acme:
            try:
                acme.mark_store_invalid(name)
            except Exception:  # startup never aborts for ACME
                logger.error("acme.mark_store_invalid_failed", certificate=name, exc_info=True)
    reconciler = Reconciler(
        settings=settings,
        store=store,
        tg=tg,
        certs=certs,
        process=process,
        registry=registry,
        caps=caps,
        probe=probe,
        webapp_index=webapp_index,
        acme=acme,
        public_store=public_store,
        acme_unavailable=acme_unavailable,
    )

    result = await reconciler.reconcile("startup")

    gateway_started = process.state is ProcState.RUNNING
    # Startup waits for ACME only while the pass held the gateway down because nothing at all
    # can render (every certificate pending); any other hold or local failure still aborts.
    waiting_for_acme = result.acme_hold and result.local_ok
    if required_sans(state) and not gateway_started and not waiting_for_acme:
        raise RuntimeError(
            "startup reconcile could not bring the gateway up: "
            + ("; ".join(result.errors) or "unknown failure")
        )
    if waiting_for_acme and not gateway_started:
        logger.warning(
            "supervisor.waiting_for_acme",
            certificates=result.acme_pending,
            reason=(
                "every public certificate is a source: acme certificate with nothing valid "
                "installed yet. The gateway starts once the first one is installed."
                + (
                    " The ACME directory is staging, a dry run that never installs a "
                    "certificate: set public_tls.acme.directory: production to serve."
                    if _acme_staging_certificates(state)
                    else ""
                )
            ),
        )
    elif not gateway_started:
        logger.warning(
            "supervisor.waiting_for_upstreams",
            reason=(
                "no upstreams configured; no TLS leaf is mintable yet. The gateway starts "
                "once the first upstream arrives."
            ),
        )

    # JWKS reachability is observation only; main() schedules the checks. A client that
    # cannot be built leaves the monitor unwired and never aborts startup.
    jwks_client: httpx.AsyncClient | None = None
    jwks: JwksMonitor | None = None
    try:
        jwks_client = make_client()
        jwks = JwksMonitor(jwks_client, jwks_url(state.twingate.network, state.twingate.host))
    except Exception as exc:
        logger.error("jwks.client_unavailable", error_type=type(exc).__name__)
        if jwks_client is not None:
            await jwks_client.aclose()
        jwks_client = None
        jwks = None

    # Built here, served by main().
    deps = GwopsDeps(
        settings=settings,
        store=store,
        reconciler=reconciler,
        certs=certs,
        process=process,
        caps=caps,
        registry=registry,
        tg=tg,
        api_event=api_event,
        spool=spool,
        shipper=shipper,
        jwks=jwks,
        probe=probe,
        drops=drops,
        webapp_index=webapp_index,
        acme=acme,
        acme_unavailable=acme_unavailable,
    )
    admin_app = create_app(deps)

    return BootstrapResult(
        process=process,
        gateway_started=gateway_started,
        config_path=config_path,
        state=state,
        caps=caps,
        certs=certs,
        store=store,
        registry=registry,
        reconciler=reconciler,
        api_event=api_event,
        tg=tg,
        admin_app=admin_app,
        spool=spool,
        shipper=shipper,
        jwks=jwks,
        jwks_client=jwks_client,
        probe=probe,
        deps=deps,
        drops=drops,
        webapp_index=webapp_index,
        acme=acme,
        acme_unavailable=acme_unavailable,
    )


@dataclass
class AdminServer:
    """A running uvicorn admin API server: the handle main() uses to stop it."""

    server: uvicorn.Server
    task: asyncio.Task[None]
    port: int

    async def stop(self) -> None:
        """Ask uvicorn to exit and wait for the serve task to finish."""
        self.server.should_exit = True
        await self.task


def start_admin_server(app: FastAPI, bind: str, port: int) -> AdminServer:
    """Bind the admin socket (fail-loud: OSError aborts startup) and serve `app`.

    The socket is created here rather than by uvicorn so a bind failure raises
    synchronously instead of dying inside the serve task. ``port=0`` binds an ephemeral
    port; the actual port is on the returned handle. uvicorn's logging config is disabled
    because gwops owns stdout.
    """
    sock = socket.create_server((bind, port))
    server = uvicorn.Server(uvicorn.Config(app, log_config=None, access_log=False))
    task = asyncio.get_running_loop().create_task(server.serve(sockets=[sock]))
    actual_port = int(sock.getsockname()[1])
    logger.info("api.serving", bind=bind, port=actual_port)
    return AdminServer(server=server, task=task, port=actual_port)


def _install_signal_handlers(
    loop: asyncio.AbstractEventLoop,
    reconciler: Reconciler,
    stop_event: asyncio.Event,
) -> None:
    """Install PID-1 signal handlers (POSIX only; a no-op where they are unavailable).

    SIGTERM/SIGINT unblock ``main``, which then runs the ordered teardown; SIGHUP
    triggers a reconcile. The child is not drained here so teardown cannot race an
    in-flight reconcile.
    """

    def _request_shutdown(signame: str) -> None:
        logger.info("supervisor.signal", signal=signame)
        stop_event.set()

    def _on_sighup() -> None:
        logger.info("supervisor.signal", signal="SIGHUP")
        loop.create_task(_sighup_reconcile(reconciler))

    for signame in ("SIGTERM", "SIGINT"):
        signum = getattr(signal, signame, None)
        if signum is None:
            continue
        try:
            loop.add_signal_handler(signum, _request_shutdown, signame)
        except NotImplementedError:  # e.g. Windows / restricted loop
            logger.warning("supervisor.signal_unavailable", signal=signame)

    sighup = getattr(signal, "SIGHUP", None)
    if sighup is not None:
        try:
            loop.add_signal_handler(sighup, _on_sighup)
        except NotImplementedError:
            logger.warning("supervisor.signal_unavailable", signal="SIGHUP")


async def _sighup_reconcile(reconciler: Reconciler) -> None:
    try:
        await reconciler.reconcile("sighup")
    except Exception:
        logger.exception("supervisor.sighup_reconcile_raised")


async def run_jwks_checks(
    monitor: JwksMonitor,
    interval_seconds: float,
    *,
    check_timeout: float = _JWKS_CHECK_TIMEOUT_SECONDS,
) -> None:
    """Check once now, then once per interval, sequentially so checks never stack.

    A failing or hung check is contained and never reaches a reconcile pass, /healthz or
    startup; it only updates the monitor's status (a timeout is marked ``degraded`` with
    reason ``check_timeout`` so a stale ok status never survives). Runs until cancelled.
    """
    while True:
        try:
            async with asyncio.timeout(check_timeout):
                await monitor.check()
        except TimeoutError:
            logger.warning("jwks.check_timeout", timeout_seconds=check_timeout)
            monitor.mark("degraded", "check_timeout")
        except Exception as exc:
            logger.error("jwks.check_failed", error_type=type(exc).__name__)
        await asyncio.sleep(interval_seconds)


def _log_drops(drops: DropCounters) -> None:
    """Log the drop counts (and enrichment failures) if any changed since the last log."""
    if (changed := drops.take_changed()) is not None:
        logger.info("shipper.lines_dropped", **changed)


async def run_drop_log(
    drops: DropCounters, interval_seconds: float = _DROP_LOG_INTERVAL_SECONDS
) -> None:
    """Every interval, log the drop counts by reason if any changed; runs until cancelled."""
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            _log_drops(drops)
        except Exception:
            logger.exception("shipper.drop_log_failed")


async def main() -> None:
    """PID-1 entrypoint (``python -m gwops``): bring up the control plane and run."""
    configure_logging()
    settings = GwopsSettings()
    try:
        result = await bootstrap(settings)
    except _STARTUP_ERRORS as exc:
        logger.error("supervisor.startup_failed", error=str(exc))
        raise SystemExit(1) from exc

    try:
        # Started before the signal handlers so ours win.
        admin = start_admin_server(
            result.admin_app, result.state.admin_api.bind, result.state.admin_api.port
        )
    except _STARTUP_ERRORS as exc:
        # bootstrap already started the child and opened the spool and TG client.
        logger.error("supervisor.startup_failed", error=str(exc))
        await _teardown(result, admin=None)
        raise SystemExit(1) from exc

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    _install_signal_handlers(loop, result.reconciler, stop_event)

    triggers_task = loop.create_task(
        run_triggers(
            result.reconciler,
            seed_path=settings.seed_path,
            tick_seconds=settings.reconcile_tick_seconds,
            api_event=result.api_event,
        )
    )
    shipper_task: asyncio.Task[None] | None = None
    if result.shipper is not None:
        shipper_task = loop.create_task(result.shipper.run())
    drop_log_task: asyncio.Task[None] | None = None
    if result.spool is not None:
        drop_log_task = loop.create_task(run_drop_log(result.drops))
    jwks_task: asyncio.Task[None] | None = None
    if result.jwks is not None:
        jwks_task = loop.create_task(run_jwks_checks(result.jwks, settings.reconcile_tick_seconds))
    if result.acme is not None:
        # Runs as its own task; a reconcile pass never awaits it.
        result.acme.start()
    logger.info(
        "supervisor.running",
        gateway_started=result.gateway_started,
        tick_seconds=settings.reconcile_tick_seconds,
        admin_port=admin.port,
        shipping=shipper_task is not None,
    )
    try:
        await stop_event.wait()
    finally:
        await _teardown(
            result,
            admin=admin,
            triggers_task=triggers_task,
            shipper_task=shipper_task,
            jwks_task=jwks_task,
            drop_log_task=drop_log_task,
        )
    logger.info("supervisor.exited")


async def _teardown(
    result: BootstrapResult,
    *,
    admin: AdminServer | None,
    triggers_task: asyncio.Task[None] | None = None,
    shipper_task: asyncio.Task[None] | None = None,
    jwks_task: asyncio.Task[None] | None = None,
    drop_log_task: asyncio.Task[None] | None = None,
) -> None:
    """Shut down in order, so no late reconcile spawns a child that is then orphaned.

    Cancel the trigger sources and stop the admin API first (no new reconcile can begin),
    quiesce the reconciler (wait out any in-flight pass), then drain the child, seal the
    spool and close the TG client.
    """
    if result.deps is not None:
        result.deps.shutting_down.set()
    if triggers_task is not None:
        triggers_task.cancel()
        await asyncio.gather(triggers_task, return_exceptions=True)
    if result.acme is not None:
        # Before the child stops: no lego process may outlive teardown or install material.
        try:
            await result.acme.aclose()
        except Exception as exc:
            logger.error("acme.close_failed", error_type=type(exc).__name__, exc_info=True)
    if jwks_task is not None:
        jwks_task.cancel()
        await asyncio.gather(jwks_task, return_exceptions=True)
    if drop_log_task is not None:
        drop_log_task.cancel()
        await asyncio.gather(drop_log_task, return_exceptions=True)
    if admin is not None:
        await admin.stop()
    await result.reconciler.request_shutdown()
    if result.probe is not None:
        await result.probe.aclose()
    if shipper_task is not None:
        shipper_task.cancel()
        await asyncio.gather(shipper_task, return_exceptions=True)
    if result.process.state is not ProcState.STOPPED:
        await result.process.stop()
    if result.spool is not None:
        # The child is drained, so no more lines arrive; persist what is undelivered.
        try:
            result.spool.close()
        finally:  # counts since the last periodic log, including lines lost in the final flush
            _log_drops(result.drops)
    if result.tg is not None:
        await result.tg.aclose()
    if result.jwks_client is not None:
        await result.jwks_client.aclose()
