"""Live web-app rig orchestrator: `make integration-webapp` runs `python -m ...webapp.run`."""

import argparse
import asyncio
import contextlib
import dataclasses
import os
import secrets
import shutil
import signal
import socket
import sys
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

from .rig import diagnose, dockerops, guards, logfilter, seedgen, teardown
from .rig.admin import AdminClient, AdminError
from .rig.checks import EXPECTED_ASSERTIONS, Checks, RigContext, RigHttp
from .rig.dockerops import COMPOSE_FILE, Docker, DockerError
from .rig.gatorcast import (
    GATORCAST_ASSERTIONS,
    SSH_ASSERTION,
    SSH_CLIENT_IMAGE,
    GatorcastEvidence,
    wait_ssh_ready,
)
from .rig.pki import generate_rig_pki
from .rig.redact import Redactor, RunLog, secret_values_from_env_text
from .rig.results import Outcome, ResultBook
from .rig.seedgen import ADMIN_TOKEN_FILE, GWOPS_ENV_FILE
from .rig.tenant import RigApiError, RigTenant, recovery_command, write_secret_file

DEFAULT_IMAGE = "gwops-gateway:dev"
CREATE_TIMEOUT_SECONDS = 900.0
RECONCILE_TIMEOUT_SECONDS = 420.0
RECORD_INTERVAL_SECONDS = 15.0
HOLD_MAX_SECONDS = 7200.0
HOLD_CAP_SECONDS = 14400.0
HOLD_HEARTBEAT_SECONDS = 300.0
HOLD_POLL_SECONDS = 2.0
HOLD_FILE = "HOLD"
LOG_TAIL_LINES = 120
DUMP_MAX_CHARS = 5_000_000


class RigError(Exception):
    """The rig could not reach a state in which assertions are meaningful."""


class RunFailed(Exception):
    """An error after the tenant was reached; the run state says how to sweep."""


def hold_seconds(value: str) -> float:
    """argparse type for --hold-max: a positive number of seconds, at most HOLD_CAP_SECONDS."""
    seconds = float(value)
    if not 0 < seconds <= HOLD_CAP_SECONDS:
        raise argparse.ArgumentTypeError(f"must be above 0 and at most {HOLD_CAP_SECONDS:.0f}")
    return seconds


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(prog="python -m tests.integration.webapp.run")
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="local gwops image (make image)")
    parser.add_argument(
        "--apply-timeout",
        type=float,
        default=None,
        help="seconds to wait for the rewrite change (default: the token's own expiry bound)",
    )
    parser.add_argument(
        "--hold",
        action="store_true",
        help="after the assertions, keep the rig up until <run dir>/HOLD is deleted",
    )
    parser.add_argument(
        "--hold-max",
        type=hold_seconds,
        default=HOLD_MAX_SECONDS,
        help=f"hold limit in seconds (default {HOLD_MAX_SECONDS:.0f}, cap {HOLD_CAP_SECONDS:.0f})",
    )
    parser.add_argument(
        "--gatorcast",
        action="store_true",
        help="add a real Gatorcast sink and its evidence assertions (default off)",
    )
    parser.add_argument(
        "--gatorcast-image",
        default=seedgen.DEFAULT_GATORCAST_IMAGE,
        help="Gatorcast image for --gatorcast (default %(default)s)",
    )
    parser.add_argument(
        "--gatorcast-build",
        type=Path,
        default=None,
        metavar="PATH",
        help="build Gatorcast from the source tree at PATH (read only); implies --gatorcast",
    )
    parser.add_argument(
        "--gatorcast-ssh",
        action="store_true",
        help="with --gatorcast: also prove an SSH recording arrives as capped segment lines "
        "plus a final line",
    )
    args = parser.parse_args(argv)
    args.gatorcast = args.gatorcast or args.gatorcast_ssh or args.gatorcast_build is not None
    return args


def free_port() -> int:
    """A currently free TCP port on loopback."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def prepare_dirs(run_dir: Path) -> None:
    """Create the bind-mount directories the compose file expects (world-readable, no secrets)."""
    for name in ("seed", "webapp-cas", "trust", "pki", seedgen.SSH_CA_DIR):
        directory = run_dir / name
        directory.mkdir(exist_ok=True)
        directory.chmod(0o755)
    tap = run_dir / seedgen.TAP_DIR
    tap.mkdir(exist_ok=True)
    tap.chmod(0o777)


def make_pki_readable(pki_dir: Path) -> None:
    """Let the echo and verifier users (uid 10001) read the throwaway leaf keys in `pki_dir`."""
    for path in pki_dir.iterdir():
        path.chmod(0o644)


def write_seed(run_dir: Path, text: str) -> None:
    """Replace seed.yaml atomically inside the mounted directory."""
    directory = run_dir / "seed"
    tmp = directory / "seed.yaml.tmp"
    tmp.write_text(text, encoding="utf-8", newline="\n")
    tmp.chmod(0o644)
    os.replace(tmp, directory / "seed.yaml")


def entry_for(status: dict[str, Any], name: str) -> dict[str, Any] | None:
    """The /status web_apps readiness entry named `name`."""
    entries = status.get("web_apps", {}).get("readiness") or []
    return next((entry for entry in entries if entry.get("name") == name), None)


def reconcile_actions(document: dict[str, Any]) -> list[str]:
    """The `actions` of a reconcile result, or of /status `last_reconcile`."""
    last = document.get("last_reconcile")
    source = last if isinstance(last, dict) else document
    actions = source.get("actions")
    return [a for a in actions if isinstance(a, str)] if isinstance(actions, list) else []


class CancelOnce:
    """Signal handler that cancels the main task once; later signals cannot interrupt cleanup."""

    def __init__(self, task: Any) -> None:
        """Bind the task to cancel."""
        self._task = task
        self.fired = False

    def __call__(self, *_args: object) -> None:
        """Cancel the task on the first call only."""
        if not self.fired:
            self.fired = True
            self._task.cancel()

    def begin_teardown(self) -> None:
        """Mark fired whatever signal came first, so no later signal can cancel the teardown."""
        self.fired = True


class TeardownShield:
    """While active, SIGINT is counted and ignored, and `shutdown` is marked fired."""

    def __init__(self, shutdown: CancelOnce | None) -> None:
        """Bind the one-shot handler (None when no SIGTERM handling was installed)."""
        self._shutdown = shutdown
        self._previous: Any = None
        self._installed = False
        self.ignored = 0

    def _ignore(self, *_args: object) -> None:
        self.ignored += 1

    def __enter__(self) -> Self:
        """Mark the shutdown handler fired and take over SIGINT."""
        if self._shutdown is not None:
            self._shutdown.begin_teardown()
        with contextlib.suppress(ValueError, OSError):
            self._previous = signal.signal(signal.SIGINT, self._ignore)
            self._installed = True
        return self

    def __exit__(self, *_exc: object) -> None:
        """Hand SIGINT back to whoever had it."""
        if self._installed:
            with contextlib.suppress(ValueError, OSError):
                signal.signal(signal.SIGINT, self._previous)


async def run_shielded(awaitable: Awaitable[None]) -> int:
    """Await `awaitable` to completion even if the current task is cancelled; returns cancels."""
    inner = asyncio.ensure_future(awaitable)
    task = asyncio.current_task()
    swallowed = 0
    while not inner.done():
        try:
            await asyncio.shield(inner)
        except asyncio.CancelledError:
            if inner.cancelled():
                raise
            swallowed += 1
            if task is not None:
                task.uncancel()
    inner.result()
    return swallowed


def install_cancel_handlers(loop: Any, task: Any) -> CancelOnce:
    """Route SIGTERM (and SIGBREAK on Windows) to a one-shot cancel of `task`."""
    handler = CancelOnce(task)
    for name in ("SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, handler)
        except NotImplementedError:
            with contextlib.suppress(ValueError, OSError):
                signal.signal(sig, lambda *_a: loop.call_soon_threadsafe(handler))
    return handler


class Rig:
    """One run: owns the tenant view, docker wrapper, admin client, log and results."""

    def __init__(
        self,
        env: guards.RigEnv,
        tenant: RigTenant,
        names: seedgen.RigNames,
        args: argparse.Namespace,
    ) -> None:
        """Build the run's collaborators; nothing is started here."""
        self.env = env
        self.tenant = tenant
        self.names = names
        self.args = args
        self.run_dir = tenant.run_dir
        self.redactor = Redactor([env.api_key])
        self.log = RunLog(self.run_dir / "run.log", self.redactor)
        self.book = ResultBook()
        self.admin_token = secrets.token_urlsafe(32)
        self.redactor.add(self.admin_token)
        self.gatorcast = bool(getattr(args, "gatorcast", False))
        self.ssh = bool(getattr(args, "gatorcast_ssh", False))
        self.ingest_token = secrets.token_urlsafe(32) if self.gatorcast else ""
        self.ui_password = secrets.token_urlsafe(24) if self.gatorcast else ""
        for secret in (self.ingest_token, self.ui_password):
            if secret:
                self.redactor.add(secret)
        self.docker_gatorcast_image: str = getattr(
            args, "gatorcast_image", seedgen.DEFAULT_GATORCAST_IMAGE
        )
        self.ssh_error: str | None = "SSH infrastructure was not set up"
        self.admin_port = free_port()
        compose_vars = seedgen.compose_env(
            names,
            run_dir=self.run_dir,
            network=env.network,
            admin_port=self.admin_port,
            gwops_image=args.image,
            gatorcast=self.gatorcast,
            gatorcast_image=self.docker_gatorcast_image,
        )
        self.docker = Docker(self.log, names, COMPOSE_FILE, compose_vars)
        self.admin = AdminClient(self.admin_port, self.admin_token)
        self.http = RigHttp(self.docker, self.log, self.book)

    def seed_text(self, *, phase_two: bool) -> str:
        """The seed for phase 1 (no bundle, insecure host not allowlisted) or phase 2."""
        return seedgen.render_seed(
            self.names,
            network=self.env.network,
            remote_network_id=self.env.remote_network_id,
            with_bundle=phase_two,
            allow_insecure_host=phase_two,
            receiver_url=seedgen.RECEIVER_URL if self.gatorcast else None,
            ssh=self.ssh,
        )

    def expected_assertions(self) -> list[tuple[str, str]]:
        """Every assertion this run should record, in order."""
        extra = list(GATORCAST_ASSERTIONS) if self.gatorcast else []
        if self.ssh:
            extra.append(SSH_ASSERTION)
        return [*EXPECTED_ASSERTIONS, *extra]

    # --- waiting ----------------------------------------------------------------------

    def _admin_retry(
        self, exc: AdminError, what: str, last: str | None, *, allow_404: bool = False
    ) -> str:
        """The error text if it is worth retrying (transport, or an expected 404); else RigError."""
        if exc.status in (401, 403):
            raise RigError(f"{what}: the admin API rejected the token (HTTP {exc.status})")
        if exc.status is None or (allow_404 and exc.status == 404):
            text = str(exc)
            if text != last:
                self.log.event("admin-retry", what=what, error=text)
            return text
        raise RigError(f"{what}: {exc}")

    async def wait_admin(self) -> None:
        """Wait for the admin API and a first reconcile pass; fail fast on a rejected seed."""
        deadline = time.monotonic() + 240
        last_error: str | None = None
        while time.monotonic() < deadline:
            try:
                status = await self.admin.status()
            except AdminError as exc:
                last_error = self._admin_retry(exc, "GET /status", last_error)
                await asyncio.sleep(3)
                continue
            if status.get("state_error"):
                raise RigError(f"gwops refused the seed: {status['state_error']}")
            guards.require_no_adoption(reconcile_actions(status))
            if status.get("last_reconcile"):
                self.log.event(
                    "gwops", version=status.get("capabilities", {}).get("gateway_version")
                )
                return
            await asyncio.sleep(3)
        raise RigError(
            f"gwops admin API reported no first reconcile in time (last admin error: {last_error})"
        )

    async def _nudge(self, last_error: str | None) -> str | None:
        """POST /reconcile; transport failures are logged and returned, other errors raise."""
        try:
            result = await self.admin.reconcile()
        except AdminError as exc:
            return self._admin_retry(exc, "POST /reconcile", last_error)
        self.log.event("reconcile", ok=result.get("ok"), errors=result.get("errors"))
        guards.require_no_adoption(reconcile_actions(result))
        return last_error

    async def wait_apps_created(self) -> dict[str, str]:
        """Wait until every seeded web app has a tg_resource_id; nudge with POST /reconcile."""
        suffixes = seedgen.APP_SUFFIXES
        deadline = time.monotonic() + CREATE_TIMEOUT_SECONDS
        ids: dict[str, str] = {}
        last_nudge = time.monotonic()
        last_record = float("-inf")
        last_error: str | None = None
        while time.monotonic() < deadline:
            if time.monotonic() - last_record > RECORD_INTERVAL_SECONDS:
                last_record = time.monotonic()
                await self.record_new()
            for suffix in suffixes:
                if suffix in ids:
                    continue
                try:
                    entry = await self.admin.get_webapp(self.names.app_name(suffix))
                except AdminError as exc:
                    last_error = self._admin_retry(exc, f"GET {suffix}", last_error, allow_404=True)
                    continue
                if entry.get("tg_resource_id"):
                    ids[suffix] = str(entry["tg_resource_id"])
            if len(ids) == len(suffixes):
                return ids
            if time.monotonic() - last_nudge > 40:
                last_nudge = time.monotonic()
                last_error = await self._nudge(last_error)
            await asyncio.sleep(5)
        missing = [s for s in suffixes if s not in ids]
        raise RigError(
            f"web apps never reached the tenant: {', '.join(missing)} "
            f"(last admin error: {last_error})"
        )

    async def wait_reconcile_settled(self, before: str | None) -> None:
        """After a HUP: wait for a newer pass that is ok, with the gateway running and stable."""
        deadline = time.monotonic() + RECONCILE_TIMEOUT_SECONDS
        stable_since: str | None = None
        stable_count = 0
        last_error: str | None = None
        while time.monotonic() < deadline:
            await asyncio.sleep(5)
            try:
                status = await self.admin.status()
            except AdminError as exc:
                last_error = self._admin_retry(exc, "GET /status", last_error)
                continue
            guards.require_no_adoption(reconcile_actions(status))
            last = status.get("last_reconcile") or {}
            started = last.get("started_at")
            running = status.get("process", {}).get("state") == "running"
            if started == before or not running or not last.get("ok"):
                if started != before and not last.get("ok"):
                    last_error = await self._nudge(last_error)
                continue
            stable_count = stable_count + 1 if started == stable_since else 1
            stable_since = started
            if stable_count >= 2 and await self.admin.healthz():
                return
        raise RigError(
            f"gwops did not settle after the seed change (last admin error: {last_error})"
        )

    # --- phases -----------------------------------------------------------------------

    async def record_new(self) -> None:
        """Record any run object gwops has created so far (a crash cannot orphan it)."""
        before = len(self.tenant.state.created)
        try:
            await self.tenant.record_discovered()
        except RigApiError as exc:
            self.log.event("record-failed", error=str(exc)[:200])
            return
        for entry in self.tenant.state.created[before:]:
            self.log.event("recorded", kind=entry.kind, id=entry.object_id)

    async def record_discovered(self) -> None:
        """Record everything gwops created and require the Gateway, both CAs and every app."""
        found = await self.tenant.record_discovered()
        counts = Counter(kind for kind, _id, _name in found)
        expected = {"gateway": 1, "ca": 1, "ssh_ca": 1, "web_app": len(seedgen.APP_SUFFIXES)}
        expected["ssh"] = 1 if self.ssh else 0
        for kind, want in expected.items():
            if counts[kind] != want:
                raise RigError(f"expected {want} new {kind} on the tenant, found {counts[kind]}")

    async def cross_check_ids(self, admin_ids: dict[str, str]) -> None:
        """The admin API's tg_resource_id must equal the id the tenant listing recorded."""
        recorded = {name: oid for oid, name in self._recorded_web_apps()}
        for suffix, admin_id in admin_ids.items():
            name = self.names.app_name(suffix)
            if recorded.get(name) != admin_id:
                raise RigError(f"admin API and tenant disagree on the id of {suffix}")

    def _recorded_web_apps(self) -> list[tuple[str, str]]:
        return [(o.object_id, o.name) for o in self.tenant.state.created if o.kind == "web_app"]

    async def apply_phase_two(self) -> None:
        """Rewrite the seed (bundle listed, insecure host allowlisted) and HUP gwops."""
        status = await self.admin.status()
        before = (status.get("last_reconcile") or {}).get("started_at")
        write_seed(self.run_dir, self.seed_text(phase_two=True))
        await self.docker.hup_gwops()
        self.log.event("seed", phase=2, signalled="gwops (PID 1)")
        await self.wait_reconcile_settled(before)

    async def bring_up(self) -> dict[str, str]:
        """Setup, PKI, seed and stage 1; returns the web-app ids once gwops created them."""
        setup = await self.tenant.setup()
        for path in (setup.connector_env_file, setup.client_env_file):
            text = path.read_text(encoding="utf-8")
            for value in secret_values_from_env_text(text, exclude={self.env.network}):
                self.log.add_secret(value)
        prepare_dirs(self.run_dir)
        sans = seedgen.pki_sans(self.names)
        pki = generate_rig_pki(
            self.run_dir / "pki",
            echo_sans=sans["echo_sans"],
            verifier_sans=sans["verifier_sans"],
            wrong_host_sans=sans["wrong_host_sans"],
        )
        make_pki_readable(self.run_dir / "pki")
        shutil.copyfile(pki.ca_bundle, self.run_dir / "webapp-cas" / "upstream-ca.pem")
        write_secret_file(
            self.run_dir / GWOPS_ENV_FILE,
            seedgen.gwops_env_lines(
                self.env.api_key, self.admin_token, self.ingest_token if self.gatorcast else None
            ),
        )
        if self.gatorcast:
            write_secret_file(
                self.run_dir / seedgen.GATORCAST_ENV_FILE,
                seedgen.gatorcast_env_lines(self.ingest_token, self.ui_password),
            )
        write_secret_file(self.run_dir / ADMIN_TOKEN_FILE, [self.admin_token])
        write_seed(self.run_dir, self.seed_text(phase_two=False))
        await self.tenant.assert_address_free()
        services = ["gwops", "connector", "echo-http", "echo-tls", "echo-wrong"]
        profiles: list[str] = []
        if self.gatorcast:
            services += [seedgen.GATORCAST_SERVICE, seedgen.TAP_SERVICE]
            profiles.append(seedgen.PROFILE_GATORCAST)
        self.log.event("stage1", services=" ".join(services))
        await self.docker.compose("up", "-d", "--build", *services, profile=profiles)
        if self.gatorcast:
            await self.wait_gatorcast_healthy()
        await self.wait_admin()
        ids = await self.wait_apps_created()
        if self.ssh:
            await self.wait_ssh_created()
        await self.record_discovered()
        await self.cross_check_ids(ids)
        return ids

    async def wait_gatorcast_healthy(self) -> None:
        """Wait for the Gatorcast container's healthcheck to pass."""
        container = self.docker.container(seedgen.GATORCAST_SERVICE)
        deadline = time.monotonic() + 180
        state = ""
        while time.monotonic() < deadline:
            result = await self.docker.run(
                "inspect", "-f", "{{.State.Health.Status}}", container, timeout=30, check=False
            )
            state = result.stdout.strip()
            if state == "healthy":
                self.log.event("gatorcast", state="healthy")
                return
            await asyncio.sleep(3)
        raise RigError(f"Gatorcast did not become healthy (last state {state or 'unknown'})")

    async def wait_ssh_created(self) -> None:
        """Wait until gwops has created the SSH resource (it has a tg_resource_id)."""
        name = self.names.app_name(seedgen.SSH_SUFFIX)
        deadline = time.monotonic() + CREATE_TIMEOUT_SECONDS
        last_error: str | None = None
        while time.monotonic() < deadline:
            try:
                entry = await self.admin.get_ssh(name)
            except AdminError as exc:
                last_error = self._admin_retry(exc, "GET ssh", last_error, allow_404=True)
                await asyncio.sleep(5)
                continue
            if entry.get("tg_resource_id"):
                return
            await asyncio.sleep(5)
        raise RigError(
            f"the SSH resource never reached the tenant (last admin error: {last_error})"
        )

    async def setup_ssh(self) -> None:
        """Export the SSH CA public key, build and start the sshd target, build the ssh client."""
        try:
            await self.docker.copy_from(
                self.docker.gwops_container,
                "/data/pki/ssh-ca.key.pub",
                self.run_dir / seedgen.SSH_CA_DIR / seedgen.SSH_CA_FILE,
            )
            (self.run_dir / seedgen.SSH_CA_DIR / seedgen.SSH_CA_FILE).chmod(0o644)
            await self.docker.build_image(SSH_CLIENT_IMAGE, COMPOSE_FILE.parent / "ssh-client")
            await self.docker.compose(
                "up", "-d", "--build", "ssh-target", profile=seedgen.PROFILE_SSH
            )
        except DockerError as exc:
            self.ssh_error = f"{type(exc).__name__}: {exc}"[:400]
            self.log.event("ssh-setup-failed", error=self.ssh_error)
            return
        self.ssh_error = None
        self.log.event("ssh-setup", target=self.names.ssh_host)

    async def start_stage_two(self, ids: dict[str, str]) -> None:
        """Grant access, export the gwops CA, then start verifiers, client and curl."""
        await self.tenant.grant_access(
            [*self.tenant.state.ids("web_app"), *self.tenant.state.ids("ssh")]
        )
        await self.docker.copy_from(
            self.docker.gwops_container,
            "/data/pki/x509-ca.crt",
            self.run_dir / "trust" / "gwops-ca.pem",
        )
        self.docker.set_compose_var("RIG_VERIFIER_EXPECTED_ID", ids["verifier-a"])
        self.log.event("stage2", services="verifier-a verifier-b client curl")
        await self.docker.compose(
            "up", "-d", "--build", "verifier-a", "verifier-b", "client", "curl", profile="stage2"
        )
        if self.ssh:
            await self.setup_ssh()

    async def assertions(self) -> None:
        """Run phase-1 assertions, the seed change, then phase-2 assertions."""
        ctx = RigContext(
            self.names,
            self.docker,
            self.admin,
            self.tenant,
            self.http,
            self.book,
            self.log,
            self.apply_phase_two,
            self.args.apply_timeout,
        )
        checks = Checks(ctx)
        titles = dict(self.expected_assertions())
        gates: list[Awaitable[object]] = [checks.wait_hosts_ready()]
        if self.ssh and self.ssh_error is None:
            gates.append(wait_ssh_ready(ctx))
        for outcome in await asyncio.gather(*gates, return_exceptions=True):
            if isinstance(outcome, Exception):
                self.log.event("host-gate-error", error=repr(outcome)[:200])
        phase_one = (
            ("1", checks.plain_http),
            ("7", checks.identity_headers),
            ("2a", checks.verify_full_no_bundle),
            ("6a", checks.tls13_untrusted),
            ("10a", checks.probe_untrusted),
            ("5a", checks.insecure_refused),
        )
        phase_two = (
            ("2b", checks.verify_full_bundle),
            ("3", checks.alias_host),
            ("4a", checks.verify_ca_wrong_host),
            ("4b", checks.verify_full_wrong_host),
            ("5b", checks.insecure_allowlisted),
            ("6b", checks.tls13_trusted),
            ("10b", checks.probe_ok),
            ("9a", checks.verifier_accepts_own),
            ("9b", checks.verifier_rejects_other),
            ("8", checks.rewrite_applies),
        )
        for number, check in phase_one:
            await self.run_check(number, titles[number], check)
        await self.apply_phase_two()
        for number, check in phase_two:
            await self.run_check(number, titles[number], check)
        if self.gatorcast:
            await self.gatorcast_assertions(ctx, titles)

    async def gatorcast_assertions(self, ctx: RigContext, titles: dict[str, str]) -> None:
        """The --gatorcast evidence: alias and SSH traffic first, then the readbacks."""
        evidence = GatorcastEvidence(
            ctx,
            self.run_dir / seedgen.TAP_DIR / seedgen.TAP_LOG_FILE,
            ssh_ready=lambda: self.ssh_error,
        )
        first = [("15", evidence.recording_alias_host)]
        if self.ssh:
            first.append(("16", evidence.recording_ssh))
        for number, check in first:
            await self.run_check(number, titles[number], check)
        await self.drain_for_evidence(evidence)
        readbacks = (
            ("12", evidence.recording_web_gwops),
            ("13", evidence.recording_no_service_lines),
            ("14", evidence.recording_counters),
        )
        for number, check in readbacks:
            await self.run_check(number, titles[number], check)

    async def drain_for_evidence(self, evidence: GatorcastEvidence) -> None:
        """Let the spool empty before the readbacks; a failure here is logged, not fatal."""
        try:
            await evidence.drain()
        except Exception as exc:
            self.log.event("drain-failed", error=f"{type(exc).__name__}: {exc}"[:200])

    async def run_check(
        self, number: str, title: str, check: Callable[[], Awaitable[str | None]]
    ) -> Outcome:
        """Run one assertion; a non-pass records diagnostics, which never change the result."""
        wall, mono = datetime.now(UTC), time.monotonic()
        outcome = await self.book.run(number, title, check)
        if outcome is not Outcome.PASS:
            await diagnose.diagnose_failure(
                self.docker, self.http, self.log, number, wall_start=wall, mono_start=mono
            )
        return outcome

    # --- hold -------------------------------------------------------------------------

    def hold_instructions(self, max_seconds: float) -> list[str]:
        """Console text for a hold: how to release it and commands to poke every app."""
        lines = [
            "",
            f"== HOLD: the rig stays up for up to {max_seconds:.0f}s ==",
            f"Delete {self.run_dir / HOLD_FILE} to tear down now (Ctrl+C also tears down).",
            f"Admin API: http://127.0.0.1:{self.admin_port} "
            f"(token in {self.run_dir / ADMIN_TOKEN_FILE}, 0600, deleted at teardown).",
            "Run these from any shell; each uses curl in the client's network namespace:",
        ]
        for title, command in seedgen.hold_commands(self.names):
            lines.extend(["", f"# {title}", command])
        lines.append("")
        return lines

    async def hold(
        self,
        max_seconds: float,
        *,
        heartbeat_seconds: float = HOLD_HEARTBEAT_SECONDS,
        poll_seconds: float = HOLD_POLL_SECONDS,
    ) -> str:
        """Hold until HOLD is deleted, `max_seconds` pass or an interrupt; returns which."""
        max_seconds = min(max_seconds, HOLD_CAP_SECONDS)
        marker = self.run_dir / HOLD_FILE
        marker.write_text("Delete this file to tear the rig down.\n", encoding="utf-8")
        self.log.event("hold", marker=marker, max_seconds=max_seconds)
        for line in self.hold_instructions(max_seconds):
            print(self.redactor.redact(line), flush=True)
        started = last_beat = time.monotonic()
        outcome = "expired"
        try:
            while True:
                now = time.monotonic()
                if not marker.exists():
                    outcome = "released"
                    break
                if now - started >= max_seconds:
                    break
                if now - last_beat >= heartbeat_seconds:
                    last_beat = now
                    remaining = max_seconds - (now - started)
                    self.log.event("hold-heartbeat", remaining_s=f"{remaining:.0f}")
                await asyncio.sleep(poll_seconds)
        except asyncio.CancelledError:
            outcome = "interrupted"
            task = asyncio.current_task()
            if task is not None:
                task.uncancel()
        finally:
            with contextlib.suppress(OSError):
                marker.unlink()
        self.log.event("hold", ended=outcome)
        return outcome

    # --- teardown ---------------------------------------------------------------------

    async def dump_logs(self) -> None:
        """Append container logs (redacted) to run.log.

        gwops and the client are dumped in full but filtered (gateway/supervisor/reconcile events
        and errors; client errors and authorize_flow lines); the rest keep a tail.
        """
        plans: tuple[tuple[str, Callable[[str], str] | None, int | None], ...] = (
            ("gwops", logfilter.filter_gwops_log, None),
            ("client", logfilter.filter_client_log, None),
            ("connector", None, LOG_TAIL_LINES),
            ("verifier-a", None, LOG_TAIL_LINES),
            ("verifier-b", None, LOG_TAIL_LINES),
            (seedgen.GATORCAST_SERVICE, None, LOG_TAIL_LINES),
            (seedgen.TAP_SERVICE, None, LOG_TAIL_LINES),
        )
        for service, keep, tail in plans:
            try:
                text = await self.docker.logs(self.docker.container(service), tail=tail)
            except DockerError:
                continue
            text = keep(text) if keep else text
            if text.strip():
                self.log.block(f"{service} log", text, max_chars=DUMP_MAX_CHARS, echo=False)

    async def teardown(self) -> None:
        """Stop gwops first, record, sweep, compose down; records assertion 11, never raises."""
        title = dict(EXPECTED_ASSERTIONS)["11"]
        recovery = recovery_command(self.tenant.state_path)
        try:
            result = await teardown.stop_sweep_down(
                self.tenant, self.docker, self.log, before_sweep=self.dump_logs
            )
        except Exception as exc:
            detail = f"teardown raised {type(exc).__name__}: {exc}"[:600]
            self.book.record("11", title, Outcome.FAIL, detail)
            self.book.infrastructure_errors.append(f"sweep incomplete; run: {recovery}")
            return
        if result.ok and result.report is not None:
            report = result.report
            detail = f"deleted {len(report.deleted)}, already gone {len(report.already_gone)}"
            if not report.inventory_compared:
                detail += "; nothing to compare (no pre-run inventory)"
            self.book.record("11", title, Outcome.PASS, detail)
            return
        detail = "; ".join(result.errors)[:600] or "tenant not confirmed clean"
        self.book.record("11", title, Outcome.FAIL, detail)
        self.book.infrastructure_errors.append(f"sweep incomplete; run: {recovery}")

    def finish(self) -> int:
        """Record SKIPPED for unrun assertions, print and log the summary, return the exit code."""
        self.book.skip_remaining(self.expected_assertions(), "not reached")
        for line in self.book.summary_lines():
            self.log.write(line)
        return self.book.exit_code()


async def preflight_local(image: str) -> dockerops.LocalEngine:
    """Refuse before any tenant call: remote docker, or the local gwops image is missing."""
    engine = await dockerops.require_local_engine()
    return dataclasses.replace(engine, image_id=await dockerops.local_image_id(image))


async def execute(
    env: guards.RigEnv, args: argparse.Namespace, shutdown: CancelOnce | None = None
) -> int:
    """Run the rig against the tenant; the caller has already passed the env guards."""
    engine = await preflight_local(args.image)
    if getattr(args, "gatorcast_build", None) is not None:
        args.gatorcast_image = await dockerops.build_local_gatorcast(args.gatorcast_build)
    run_id = guards.new_run_id()
    names = seedgen.build_names(run_id)
    tenant = await RigTenant.start(
        env,
        gateway_address=names.gateway_address,
        run_id=run_id,
        docker_endpoint=engine.endpoint,
    )
    try:
        rig = Rig(env, tenant, names, args)
    except Exception as exc:
        await tenant.aclose()
        raise RunFailed(
            f"setup failed after the tenant was reached ({type(exc).__name__}: {exc}); "
            f"if anything was created run: {recovery_command(tenant.state_path)}"
        ) from exc
    try:
        rig.log.event("run", id=run_id, prefix=tenant.prefix, gateway=names.gateway_address)
        rig.log.event("docker-context", name=engine.context, endpoint=engine.endpoint)
        rig.log.event("gwops-image", ref=args.image, id=engine.image_id)
        if getattr(args, "gatorcast", False):
            rig.log.event("gatorcast-image", ref=getattr(args, "gatorcast_image", ""))
        ids = await rig.bring_up()
        await rig.start_stage_two(ids)
        await rig.assertions()
        if getattr(args, "hold", False):
            if rig.book.infrastructure_errors:
                rig.log.event("hold", skipped="an infrastructure error occurred before the hold")
            else:
                await rig.hold(getattr(args, "hold_max", HOLD_MAX_SECONDS))
    except asyncio.CancelledError:
        if shutdown is not None:
            shutdown.begin_teardown()
        rig.book.infrastructure_errors.append("interrupted by a signal; cleaned up")
        task = asyncio.current_task()
        if task is not None:
            task.uncancel()
    except Exception as exc:
        rig.book.infrastructure_errors.append(f"{type(exc).__name__}: {exc}")
        rig.log.event("abort", error=f"{type(exc).__name__}: {exc}")
    finally:
        with TeardownShield(shutdown) as shield:
            try:
                rig.log.event("teardown", state="in progress; further signals are ignored")
                cancels = await run_shielded(rig.teardown())
                if shield.ignored or cancels:
                    ignored = {"ignored_signals": shield.ignored, "ignored_cancels": cancels}
                    rig.log.event("teardown", **ignored)
            except Exception as exc:
                recovery = recovery_command(tenant.state_path)
                rig.book.infrastructure_errors.append(
                    f"teardown failed: {type(exc).__name__}: {exc}; run: {recovery}"
                )
            finally:
                await close_quietly(rig, rig.admin.aclose, tenant.aclose)
    return rig.finish()


async def close_quietly(rig: Any, *closers: Callable[[], Awaitable[None]]) -> None:
    """Run every closer; a failing one is logged and does not stop the next."""
    for closer in closers:
        try:
            await closer()
        except Exception as exc:
            rig.log.event("close-failed", error=f"{type(exc).__name__}: {exc}"[:200])


async def run_with_signals(env: guards.RigEnv, args: argparse.Namespace) -> int:
    """`execute` with SIGTERM/SIGBREAK routed to a cancel, so cleanup still runs."""
    task = asyncio.current_task()
    shutdown = (
        install_cancel_handlers(asyncio.get_running_loop(), task) if task is not None else None
    )
    return await execute(env, args, shutdown)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; refuses (exit 2) before any docker or HTTP call on a bad environment."""
    args = parse_args(argv)
    try:
        env = guards.require_env()
        guards.require_local_image_ref(args.image)
    except guards.GuardError as exc:
        print(f"REFUSED {exc}")
        return 2
    try:
        return asyncio.run(run_with_signals(env, args))
    except RunFailed as exc:
        print(f"ERROR {Redactor([env.api_key]).redact(str(exc))}")
        return 1
    except (guards.GuardError, RigApiError, RigError, ValueError) as exc:
        print(f"REFUSED {Redactor([env.api_key]).redact(str(exc))}")
        return 2
    except asyncio.CancelledError:
        print("Interrupted before the run was set up.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
