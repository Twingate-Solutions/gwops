"""The ACME runner: drives lego for ``source: acme`` certificates.

:class:`AcmeRunner` is a background task, never awaited by a reconcile pass. It owns

* **scheduling**: a loop that finds the certificate that is due (missing, declared names
  changed, directory changed, an admin request, or the 12 h +/- 1 h check) and is not held
  back by backoff, then runs lego for it, one process at a time;
* **the subprocess**: argv and environment come from :func:`gwops.acme.lego.build_argv`; the
  process gets a closed stdin, one merged and bounded output stream, a wall-clock limit
  (``GwopsSettings.lego_timeout_seconds``, then SIGTERM, then SIGKILL, to the whole process
  group) and is terminated on shutdown;
* **classification** of a failed run into :class:`~gwops.acme.state.AcmeErrorClass` from lego's
  output (:func:`classify_output`);
* **landing**: after a clean exit the files under lego's ``--path`` are validated with
  :func:`~gwops.certs.public.validate_public_material` and, in production, installed through the
  :class:`~gwops.certs.store.MaterialStore`. Nothing lego wrote is ever served from
  ``--path``; refused material installs nothing;
* **state**: every transition goes through :class:`~gwops.acme.state.AcmeStateStore`, so a
  restart resumes the schedule from ``state.json``.

Lego behaviour relied on: ``run`` obtains or renews; every failure exits 1 with everything on
stdout; a renewal that is not due exits 0 and writes nothing (so exit 0 is compared against
the installed serial and fingerprint); lego owns renewal timing (ARI, one-third-lifetime
fallback), the runner only decides when to ask.

Staging (``AcmeSettings.is_staging``) is a dry run: the output is validated with every check
except the path to the registered root and is **never installed**. Production installs.

Secrets: gwops never reads the DNS token; lego reads ``CF_DNS_API_TOKEN_FILE`` itself.
No token reaches argv, the environment value space, state, logs or ``/status``. The only text
that can carry anything unexpected is lego's own output, which reaches state and logs solely
as a bounded excerpt that :func:`redact_output` has scrubbed: PEM blocks are replaced, lines
carrying an ``Authorization`` or ``Bearer`` credential or a Cloudflare auth header are
withheld, values of ``...token/secret/password/api_key/credential...`` assignments are
replaced, and Cloudflare-token-shaped strings are replaced. This is a defence in depth, not
the control: the control is that gwops never holds the token. Logs name the token file path
only.
"""

import asyncio
import contextlib
import json
import math
import os
import random
import re
import signal
import stat
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pydantic import AwareDatetime, BaseModel, ConfigDict

from gwops.acme.lego import build_argv
from gwops.acme.state import (
    AcmeErrorClass,
    AcmeStateError,
    AcmeStateStore,
    CertAcmeState,
    backoff_delay,
    bound_excerpt,
    limiter_not_before,
    names_hash,
    parse_retry_after,
)
from gwops.acme.token import resolve_token_file, token_file_signature
from gwops.certs.public import (
    PublicMaterialError,
    validate_public_material,
    validate_public_material_without_root,
)
from gwops.certs.store import MaterialStore, StoreError
from gwops.configmodel.schema import AcmePublicCertificate, AcmeSettings, PublicTlsSettings
from gwops.confined import ConfinedFileError, read_confined
from gwops.settings import GwopsSettings

__all__ = [
    "CHECK_INTERVAL",
    "CHECK_JITTER",
    "AcmeCertState",
    "AcmeConfig",
    "AcmeRunner",
    "AcmeSnapshot",
    "CertSnapshot",
    "InstallCallback",
    "IssueOutcome",
    "IssueStatus",
    "classify_output",
    "final_error",
    "redact_output",
    "summarize_output",
]

logger = structlog.get_logger(__name__)

CHECK_INTERVAL = timedelta(hours=12)
"""Time between ``lego run`` checks of a certificate that is otherwise not due."""

CHECK_JITTER = timedelta(hours=1)
"""Half-width of the uniform jitter added to :data:`CHECK_INTERVAL`."""

KILL_GRACE_SECONDS = 10.0
"""Wait after SIGTERM before SIGKILL."""

DRAIN_TIMEOUT_SECONDS = 5.0
"""Wait for the output pipe to reach end of file after the process has exited."""

MAX_CAPTURE_BYTES = 64 * 1024
"""Tail of lego's output kept in memory; earlier bytes are dropped."""

MAX_SLEEP_SECONDS = 3600.0
"""Longest the loop sleeps without re-planning (guards against clock changes)."""

REQUEST_FLOOR = timedelta(seconds=60)
"""Minimum gap between two accepted admin issue requests for one certificate."""

FORCE_WINDOW = timedelta(hours=24)
"""A production ``force`` is refused while the installed certificate is younger than this."""

RELOAD_RETRY_SECONDS = 60.0
"""Loop delay while a store cleanup after an install is still pending."""

STATE_RETRY_SECONDS = 60.0
"""Loop delay while ``state.json`` is unusable (the file is re-read each time)."""

LOOP_ERROR_DELAY_SECONDS = 60.0
"""Loop delay after an unexpected error in planning."""

_READ_CHUNK = 8192
_LINE_LIMIT = 8192
_TAIL_LINES = 3
_LEGO_FILES = (".crt", ".key", ".issuer.crt", ".json")
_RATE_LIMIT_TAIL_LINES = 20
_PERMISSION_LOG_LIMIT = 5
_OPERATOR_FIXABLE = frozenset(
    {AcmeErrorClass.CONFIG, AcmeErrorClass.DNS_AUTH, AcmeErrorClass.DNS_ZONE}
)
STILL_DUE_EXCERPT = "lego exited 0 but the certificate is still due"
RELOAD_PENDING_EXCERPT = "installed; gateway has not reloaded"
_UNSET: Any = object()
_CERT_BLOCK = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)
_CERT_BEGIN = b"-----BEGIN CERTIFICATE-----"

type InstallCallback = Callable[[str], None]
"""Called with the certificate name after new material was installed (or re-adopted)."""


# --- classification ---------------------------------------------------------------------

# First match wins. Patterns are substrings of lego v5.5.2's output; `final_error` text is
# matched when present, else the whole captured text. The
# rate-limit marker is handled separately (see classify_output): it only counts in the final
# error chain or the last lines of output.
_RATE_LIMIT_PATTERN = re.compile(r"urn:ietf:params:acme:error:ratelimited", re.IGNORECASE)
_CLOUDFLARE_NETWORK = (
    r"dial tcp|i/o timeout|connection refused|connection reset|no such host"
    r"|context deadline exceeded|unexpected eof|tls handshake"
)
_CLASSIFICATION: tuple[tuple[AcmeErrorClass, re.Pattern[str]], ...] = tuple(
    (error_class, re.compile(pattern, re.IGNORECASE))
    for error_class, pattern in (
        # Cloudflare 400/401/403: the request or token is wrong.
        (AcmeErrorClass.DNS_AUTH, r"cloudflare:[^\[\]]*\[status code (?:400|401|403)\]"),
        (
            AcmeErrorClass.DNS_ZONE,
            r"cloudflare: could not find zone for domain"
            r"|failed to find zone .{0,200}?zone could not be found",
        ),
        # Cloudflare 429/5xx or an unreachable api.cloudflare.com: transient; the closest
        # existing class is acme_unreachable (retry with backoff, nothing to fix).
        (
            AcmeErrorClass.ACME_UNREACHABLE,
            r"cloudflare:[^\[\]]*\[status code (?:429|5\d\d)\]"
            rf"|cloudflare: .{{0,300}}?(?:{_CLOUDFLARE_NETWORK})"
            rf"|api\.cloudflare\.com.{{0,300}}?(?:{_CLOUDFLARE_NETWORK})",
        ),
        (AcmeErrorClass.DNS_PROPAGATION, r"dns01: time limit exceeded"),
        # ACME problem documents only a configuration change fixes. Before `unauthorized`:
        # that row's generic "invalid authorization:" prefix would otherwise swallow them.
        (
            AcmeErrorClass.CONFIG,
            r"urn:ietf:params:acme:error:"
            r"(?:invalidContact|rejectedIdentifier|malformed|accountDoesNotExist"
            r"|userActionRequired)\b",
        ),
        (
            AcmeErrorClass.ACME_UNREACHABLE,
            r"urn:ietf:params:acme:error:(?:badNonce|serverInternal)\b",
        ),
        (
            AcmeErrorClass.UNAUTHORIZED,
            r"invalid (?:authorization|challenge):"
            r"|urn:ietf:params:acme:error:(?:unauthorized|dns|caa|connection)\b",
        ),
        (
            AcmeErrorClass.ACME_UNREACHABLE,
            r"unable to communicate with the api server|get directory at"
            r"|unexpected http status 5\d\d|tls: failed to verify certificate|x509: certificate",
        ),
        (
            AcmeErrorClass.CONFIG,
            r"flag provided but not defined|incorrect usage"
            r"|please specify '--cert\.name'|you did not accept the tos"
            r"|could not read from the console|read-only file system"
            r"|some credentials information are missing|unrecognized dns provider",
        ),
    )
)


def final_error(text: str) -> str | None:
    """The ``error`` chain of the last ERROR record in lego's JSON log, or ``None``.

    lego (run with ``--log.format json``) ends a failed run with
    ``{"level":"ERROR","msg":"Error","error":"<chain>"}``. Non-JSON lines are ignored.
    """
    found: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if (
            isinstance(record, dict)
            and str(record.get("level", "")).upper() == "ERROR"
            and isinstance(record.get("error"), str)
        ):
            found = record["error"]
    return found


def _tail_text(text: str, count: int) -> str:
    """The last `count` non-empty lines of `text`."""
    return "\n".join([ln for ln in text.splitlines() if ln.strip()][-count:])


def classify_output(text: str, *, timed_out: bool = False) -> AcmeErrorClass:
    """Classify a failed lego run from its captured output.

    Args:
        text: The captured stdout and stderr (merged).
        timed_out: The process was killed for exceeding its time limit.

    Returns:
        ``rate_limited`` when the ACME ``rateLimited`` marker appears in the final error chain
        or, without one, in the last 20 lines of output (a marker earlier in a long run does
        not count). A timed-out run is ``timeout`` unless that holds (lego sleeps out
        ``Retry-After`` without a cap, so the kill fires first). Otherwise the
        first matching row of the table: ``dns_auth``, ``dns_zone``, ``acme_unreachable``
        (including Cloudflare 429/5xx and network errors), ``dns_propagation``, ``config`` or
        ``unauthorized`` for ACME problem documents, then the plain lego messages; anything
        else is ``internal`` (``rate_limited`` if the marker is in the final chain or the
        output tail).
    """
    final = final_error(text)
    tail = _tail_text(text, _RATE_LIMIT_TAIL_LINES)
    marker_near_end = bool(
        _RATE_LIMIT_PATTERN.search(final or "") or _RATE_LIMIT_PATTERN.search(tail)
    )
    if timed_out:
        return AcmeErrorClass.RATE_LIMITED if marker_near_end else AcmeErrorClass.TIMEOUT
    if _RATE_LIMIT_PATTERN.search(final if final is not None else tail):
        return AcmeErrorClass.RATE_LIMITED
    subject = final or text
    for error_class, pattern in _CLASSIFICATION:
        if pattern.search(subject):
            return error_class
    return AcmeErrorClass.RATE_LIMITED if marker_near_end else AcmeErrorClass.INTERNAL


# --- redaction and excerpts -------------------------------------------------------------

_REDACTED = "[redacted]"
_PEM_BLOCK = re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?(?:-----END [A-Z0-9 ]+-----|\Z)", re.DOTALL)
# Header-shaped credentials only. lego's "invalid authorization: acme: error: ..." must survive,
# so a bare "authorization:" is not enough: it needs a scheme or a long token after it.
_WITHHELD_LINE = re.compile(
    r"^\s*authorization\s*:\s*(?:bearer|basic)\b"
    r"|authorization[\x22']?\s*[:=]\s*[\x22']?[A-Za-z0-9._~+/=-]{20,}"
    r"|\bbearer\s+\S|x-auth-(?:key|email)|cf-api-key",
    re.IGNORECASE,
)
_PEM_BODY_LINE = re.compile(r"^\s*[A-Za-z0-9+/]{48,}={0,2}\s*$")
_SECRET_ASSIGNMENT = re.compile(
    r"""(?P<key>["']?[\w.-]{0,64}(?:token|secret|password|passwd|api[_-]?key|credential)"""
    r"""[\w.-]{0,64}["']?\s*[:=]\s*)"""
    r"""(?P<value>"(?:[^"\\]|\\.){0,2048}"|'[^']{0,2048}'|[^\s,;}\]]{1,2048})""",
    re.IGNORECASE,
)
_CLOUDFLARE_TOKEN = re.compile(
    r"\bcf(?:ut|at|k)_[A-Za-z0-9_-]{16,}"
    r"|(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{40}(?![A-Za-z0-9_-])"
)
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)


def redact_output(text: str) -> str:
    """Scrub lego output of anything that looks like a credential (defence in depth).

    gwops never holds the DNS token, so none should appear; this guards the one
    channel that carries third-party text into state, logs and ``/status``. PEM blocks are
    replaced, lines with an ``Authorization: Bearer|Basic`` header, an ``authorization``
    followed by a 20+ character token, a ``Bearer`` credential or a Cloudflare auth header are
    replaced whole (a plain ``invalid authorization:`` message is kept), lines that look like
    a bare PEM body are replaced, values of ``token``/``secret``/``password``/``api_key``/
    ``credential`` assignments are replaced, and Cloudflare-token-shaped strings (``cfut_...``
    and 40-character legacy tokens) are replaced.
    """
    text = _PEM_BLOCK.sub("[redacted: PEM block]", text)
    kept: list[str] = []
    for line in text.split("\n"):
        if _PEM_BODY_LINE.match(line):
            kept.append("[line withheld: possible PEM body]")
            continue
        if _WITHHELD_LINE.search(line):
            kept.append("[line withheld: credential pattern]")
            continue
        line = _SECRET_ASSIGNMENT.sub(lambda m: m["key"] + _REDACTED, line)
        line = _BEARER.sub(f"Bearer {_REDACTED}", line)
        kept.append(_CLOUDFLARE_TOKEN.sub(_REDACTED, line))
    return "\n".join(kept)


def _render_line(line: str) -> str:
    """One lego log line as ``LEVEL msg: error`` when it is a JSON record, else verbatim."""
    stripped = line.strip()
    if stripped.startswith("{"):
        try:
            record = json.loads(stripped)
        except ValueError:
            return stripped[:_LINE_LIMIT]
        if isinstance(record, dict):
            parts = [str(record.get("level", "")), str(record.get("msg", ""))]
            rendered = " ".join(p for p in parts if p)
            if isinstance(record.get("error"), str):
                rendered += f": {record['error']}"
            return rendered[:_LINE_LIMIT]
    return stripped[:_LINE_LIMIT]


def summarize_output(
    text: str, *, exit_code: int | None, timed_out: bool, timeout_seconds: float
) -> str:
    """A bounded, redacted excerpt of a failed run for state, logs and ``/status``.

    The final ERROR chain when lego printed one, else its last three output lines (redacted
    over the whole output first, so a PEM body line cannot slip into the window). A timed out
    run is prefixed with the limit; a signal death with ``terminated by signal N``; an exit
    code other than 1 with the code. The result is at most
    :data:`~gwops.acme.state.MAX_EXCERPT_CHARS` characters on a single line.
    """
    final = final_error(text)
    if final is not None:
        core = redact_output(final[:_LINE_LIMIT])
    else:
        rendered = [_render_line(ln) for ln in text.splitlines() if ln.strip()]
        redacted = redact_output("\n".join(rendered)).splitlines()
        core = " | ".join(redacted[-_TAIL_LINES:])
    prefix = ""
    if timed_out:
        prefix = f"killed after {timeout_seconds:g}s without finishing; "
    elif exit_code is not None and exit_code < 0:
        prefix = f"terminated by signal {-exit_code}: "
    elif exit_code not in (None, 0, 1):
        prefix = f"exit {exit_code}: "
    return bound_excerpt(prefix + core)


# --- bounded capture --------------------------------------------------------------------


class _Capture:
    """The tail of a process's output, bounded."""

    def __init__(self, limit: int = MAX_CAPTURE_BYTES) -> None:
        self._limit = limit
        self._tail = bytearray()
        self.total = 0
        self.truncated = False

    def feed(self, chunk: bytes) -> None:
        """Append `chunk`; keep only the last ``limit`` bytes."""
        self.total += len(chunk)
        self._tail += chunk
        overflow = len(self._tail) - self._limit
        if overflow > 0:
            del self._tail[:overflow]
            self.truncated = True

    def text(self) -> str:
        """The kept tail as text; a cut first line is dropped."""
        raw = bytes(self._tail)
        if self.truncated and (newline := raw.find(b"\n")) != -1:
            raw = raw[newline + 1 :]
        return raw.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class _LegoRun:
    """What one lego process did."""

    exit_code: int | None
    timed_out: bool
    text: str
    output_bytes: int
    truncated: bool
    duration_seconds: float


# --- configuration, snapshots, outcomes ---------------------------------------------------


@dataclass(frozen=True)
class AcmeConfig:
    """What the runner needs from the seed, handed over by the reconciler each pass.

    Attributes:
        settings: The seed's ``public_tls.acme`` block.
        certificates: The ``source: acme`` certificates, in seed order.
        zones: ``public_tls.zones`` (the validator's zone rule).
        root: The registered root (``resolve_registered_root``). Required for production;
            staging validation does not use it.
    """

    settings: AcmeSettings
    certificates: tuple[AcmePublicCertificate, ...]
    zones: tuple[str, ...]
    root: x509.Certificate | None = None

    def __post_init__(self) -> None:
        """Refuse a production configuration without the registered root."""
        if not self.settings.is_staging and self.root is None:
            raise ValueError("production ACME needs the registered root to validate against")

    @classmethod
    def from_public_tls(
        cls, public: PublicTlsSettings, root: x509.Certificate | None
    ) -> "AcmeConfig | None":
        """The configuration for a seed's ``public_tls``, or ``None`` without ACME certificates."""
        certificates = tuple(c for c in public.certificates if isinstance(c, AcmePublicCertificate))
        if public.acme is None or not certificates:
            return None
        return cls(public.acme, certificates, tuple(public.zones), root)


class AcmeCertState(StrEnum):
    """``certs.public[].acme.state`` in ``/status``."""

    IDLE = "idle"
    """Nothing to do until the next check."""
    SCHEDULED = "scheduled"
    """An admin request is queued, or the certificate is due and waiting its turn."""
    ISSUING = "issuing"
    """lego is running for this certificate."""
    BACKOFF = "backoff"
    """Held back until ``next_attempt_at`` (a failure, the limiter, or an interrupted run)."""
    FAILED = "failed"
    """The last attempt failed and its backoff has elapsed; the next attempt is due."""
    DRY_RUN_OK = "dry_run_ok"
    """Staging: the last dry run issued and validated (never installed)."""


class CertSnapshot(BaseModel):
    """Read-only view of one ``source: acme`` certificate for ``/status`` and readiness."""

    model_config = ConfigDict(frozen=True)

    name: str
    names: tuple[str, ...]
    directory: str
    staging: bool
    state: AcmeCertState
    installed: bool
    """Whether the public store holds a certificate and key for this name.

    It reflects the store, not the directory. Staging never installs and never removes, so
    after a production-to-staging switch this stays true while the earlier production material
    keeps serving, until the certificate is no longer declared.
    """
    installed_at: AwareDatetime | None
    installed_serial: str | None
    last_attempt_at: AwareDatetime | None
    last_success_at: AwareDatetime | None
    next_attempt_at: AwareDatetime | None
    """Earliest time lego may start for this certificate (now when due)."""
    error_code: AcmeErrorClass | None
    error_excerpt: str | None
    renewal_reason: str | None
    consecutive_failures: int
    in_backoff: bool
    retry_after: AwareDatetime | None
    last_crash: str | None = None
    """Bounded, redacted excerpt of the last unexpected exception of an attempt (in memory)."""
    permissions_problem: str | None = None
    """Path-only text when a data directory could not be restricted to its owner."""

    @property
    def readiness_codes(self) -> tuple[str, ...]:
        """Readiness reasons for this certificate.

        ``public_cert_pending:<name>``, ``acme_failed:<code>`` and ``acme_backoff``.
        Pending is any certificate with nothing in the store (always the case for staging);
        failed is any recorded failure; backoff is informational.
        """
        codes: list[str] = []
        if not self.installed:
            codes.append(f"public_cert_pending:{self.name}")
        if self.error_code is not None:
            codes.append(f"acme_failed:{self.error_code.value}")
        if self.in_backoff:
            codes.append("acme_backoff")
        return tuple(codes)


class AcmeSnapshot(BaseModel):
    """Read-only view of the whole runner."""

    model_config = ConfigDict(frozen=True)

    configured: bool
    directory: str | None
    staging: bool | None
    running: str | None
    """Name of the certificate lego is running for, if any."""
    state_error: str | None
    """Why ``state.json`` is unusable; issuance is refused while set."""
    certificates: tuple[CertSnapshot, ...]
    task_dead: bool = False
    """The runner's loop task ended other than by shutdown; nothing is being scheduled."""

    def get(self, name: str) -> CertSnapshot | None:
        """The snapshot of certificate `name`."""
        return next((c for c in self.certificates if c.name == name), None)


class IssueStatus(StrEnum):
    """Result of :meth:`AcmeRunner.request_issue`."""

    ACCEPTED = "accepted"
    """Queued (202)."""
    UNKNOWN_CERTIFICATE = "unknown_certificate"
    """The runner has no such ``source: acme`` certificate configured.

    The route answers 404 for an undeclared name and 409 for ``source: file`` before asking
    the runner, so this means a declared certificate the runner has not been configured with
    yet; the route answers 409 and asks for a reconcile.
    """
    ALREADY_RUNNING = "already_running"
    """lego is running for this certificate now (409)."""
    IN_BACKOFF = "in_backoff"
    """Held back; see ``reason`` and ``retry_after_seconds`` (429 with ``Retry-After``)."""
    UNAVAILABLE = "unavailable"
    """The runner cannot accept work: ``state.json`` is unusable, or it is shut down (409)."""


@dataclass(frozen=True)
class IssueOutcome:
    """The answer to an admin issue request.

    Attributes:
        status: What happened.
        retry_after_seconds: For ``IN_BACKOFF``, whole seconds (at least 1) until a request
            may be accepted.
        detail: A one-line, token-free description for the response body.
        reason: For ``IN_BACKOFF``, ``backoff`` (failure backoff or limiter), ``force_window``
            (a forced issue within 24 h of the last install) or ``request_floor`` (less than
            60 s since the last accepted request).
        error_code: The certificate's current error class (persisted, or ``internal`` for an
            unexpected crash or an install awaiting gateway reload), if any.
    """

    status: IssueStatus
    retry_after_seconds: int | None = None
    detail: str = ""
    reason: str | None = None
    error_code: str | None = None

    @property
    def accepted(self) -> bool:
        """Whether the request was queued."""
        return self.status is IssueStatus.ACCEPTED


@dataclass(frozen=True)
class _Plan:
    """When and why a certificate is next attempted."""

    reason: str
    due_at: datetime
    priority: int
    force: bool = False


@dataclass(frozen=True)
class _Assessment:
    """The result of examining lego's output files after a clean exit."""

    kind: Literal["not_new", "installed", "dry_run", "refused", "install_failed"]
    detail: str = ""
    serial: str | None = None
    fingerprint: str | None = None
    signal_install: bool = False
    reload_pending: bool = False


_PRIORITY = {"forced": 0, "requested": 1, "missing": 2, "names_changed": 3, "directory_changed": 4}


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _kill_spawned(task: "asyncio.Future[asyncio.subprocess.Process]") -> None:
    """Kill the process a cancelled spawn produced anyway (done-callback)."""
    if task.cancelled() or task.exception() is not None:
        return
    _signal_group(task.result(), kill=True)


def _signal_group(proc: asyncio.subprocess.Process, *, kill: bool) -> None:
    """Send SIGTERM (or SIGKILL) to lego's whole process group; Windows terminates the child."""
    if sys.platform != "win32":
        try:
            os.killpg(proc.pid, signal.SIGKILL if kill else signal.SIGTERM)
        except ProcessLookupError:
            return  # the group is already gone
        except PermissionError:
            pass  # fall back to the child alone
        else:
            return
    with contextlib.suppress(ProcessLookupError):
        if kill:
            proc.kill()
        else:
            proc.terminate()


class AcmeRunner:
    """Issues and renews ``source: acme`` certificates with lego, one process at a time.

    Wiring: construct once in ``main()``, call :meth:`configure` after every pass
    with :meth:`AcmeConfig.from_public_tls`, :meth:`start` the loop, and :meth:`aclose` it at
    teardown. :meth:`snapshot` feeds ``/status`` and readiness; :meth:`request_issue` backs
    ``POST /certs/public/{name}/issue``; :meth:`mark_store_invalid` is the reconciler's way to
    say the installed pair was refused. Nothing here raises into a caller's pass: failures
    become state, log events and snapshot fields.

    Args:
        gwops: Runtime settings (lego binary, timeout, ``<data_dir>/acme``).
        store: The public :class:`MaterialStore` (``/data/public-tls``).
        on_installed: Called with the certificate name after new material was installed
            (production only). ``main()`` passes a callback that sets the ``api_event`` the
            reconcile trigger waits on, so the next pass renders it. Exceptions are logged and
            the loop is woken.
        clock: Current UTC time; a test seam.
        environ: The source environment for the lego child (default ``os.environ``).
        rng: Jitter source; a test seam.
    """

    def __init__(
        self,
        gwops: GwopsSettings,
        *,
        store: MaterialStore,
        on_installed: InstallCallback | None = None,
        clock: Callable[[], datetime] = _utcnow,
        environ: Mapping[str, str] | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self._gwops = gwops
        self._store = store
        self._on_installed = on_installed
        self._clock = clock
        self._environ = environ
        self._rng = rng if rng is not None else random.Random()
        self._config: AcmeConfig | None = None
        self._state: AcmeStateStore | None = None
        self._state_error: str | None = None
        self._requests: dict[str, bool] = {}
        self._cooldowns: dict[str, datetime] = {}
        self._crashes: dict[str, int] = {}
        self._last_crash: dict[str, str] = {}
        self._store_invalid: set[str] = set()
        self._reload_pending: set[str] = set()
        self._fingerprints: dict[str, str] = {}
        self._token_signature: Any = _UNSET
        self._prepare_problem: str | None = None
        self._tighten_problem: str | None = None
        self._running: str | None = None
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._task_dead = False
        self._closed = False
        self._ensure_state()

    # -- public API ---------------------------------------------------------------------

    @property
    def state_error(self) -> str | None:
        """Why ``state.json`` is unusable (issuance is refused), or ``None``."""
        return self._state_error

    @property
    def running(self) -> str | None:
        """Name of the certificate lego is running for, or ``None``."""
        return self._running

    def configure(self, config: AcmeConfig | None) -> None:
        """Adopt the seed's ACME configuration and wake the loop.

        ``None`` (no ACME certificates, or public mode off) stops scheduling without touching
        persisted state. A configuration retires state entries of certificates no longer
        declared (kept for 7 days, restored if declared again) and drops their queued
        requests. A changed effective configuration or token file clears the persisted backoff
        of a certificate whose last failure an operator can fix (``config``, ``dns_auth``,
        ``dns_zone``).
        """
        self._config = config
        if config is not None:
            declared = {c.name for c in config.certificates}
            for table in (
                self._requests,
                self._cooldowns,
                self._crashes,
                self._last_crash,
                self._fingerprints,
            ):
                for name in set(table) - declared:
                    del table[name]
            self._store_invalid &= declared
            self._reload_pending &= declared
            if (state := self._state) is not None:
                try:
                    state.prune(declared, now=self._clock())
                except OSError as exc:
                    logger.error(
                        "acme.runner.prune_failed", error_type=type(exc).__name__, error=str(exc)
                    )
                self._clear_fixed_backoff(config, state)
        self._wake.set()

    def wake(self) -> None:
        """Make the loop re-plan now (after a pass that may have changed what is due)."""
        self._wake.set()

    def mark_store_invalid(self, name: str) -> None:
        """Record that the installed pair for `name` was refused, unreadable or SAN-mismatched.

        Called by the reconciler. The certificate counts as ``missing`` (an immediate reason,
        still subject to backoff), and the next clean lego exit reinstalls lego's copy even
        when its serial matches the recorded install. Idempotent; unknown names are ignored.
        """
        cfg = self._config
        if cfg is None or name not in {c.name for c in cfg.certificates}:
            return
        if name not in self._store_invalid:
            logger.warning("acme.runner.store_marked_invalid", certificate=name)
        self._store_invalid.add(name)
        self._wake.set()

    def request_issue(self, name: str, force: bool = False) -> IssueOutcome:
        """Queue an immediate attempt for certificate `name` (the admin route's entry point).

        ``force`` adds ``--renew-force`` (skips lego's renewal-window check) and never skips
        backoff. A request for a certificate that is merely queued is accepted again (a
        forced request upgrades a plain one); a request for a certificate other than the one
        lego is running is accepted and waits its turn.

        Limits (all answered as ``IN_BACKOFF``; the latest applicable time is reported):
        failure backoff (``backoff``); in production, a forced request while the installed
        certificate is under 24 h old (``force_window``); and 60 s between two accepted
        requests for one certificate (``request_floor``, staging included).

        Returns:
            :class:`IssueOutcome`: ``ACCEPTED``, ``UNKNOWN_CERTIFICATE``, ``ALREADY_RUNNING``
            (lego is running for this certificate), ``IN_BACKOFF`` (with ``reason`` and the
            seconds until a request may be accepted) or ``UNAVAILABLE`` (state file unusable,
            or shut down).
        """
        cfg = self._config
        if self._closed:
            return IssueOutcome(IssueStatus.UNAVAILABLE, detail="the ACME runner is shut down")
        if cfg is None or name not in {c.name for c in cfg.certificates}:
            return IssueOutcome(
                IssueStatus.UNKNOWN_CERTIFICATE,
                detail=f"{name!r} is not a configured source: acme certificate",
            )
        state = self._ensure_state()
        if state is None:
            return IssueOutcome(
                IssueStatus.UNAVAILABLE,
                detail="ACME state file is unusable; issuance is refused until it is fixed",
            )
        now = self._clock()
        entry = state.get(name)
        error_code = self._effective_error(name, entry)[0]
        error_value = error_code.value if error_code is not None else None
        if self._running == name:
            return IssueOutcome(
                IssueStatus.ALREADY_RUNNING,
                detail=f"issuance for {name!r} is in progress",
                error_code=error_value,
            )
        production = not cfg.settings.is_staging
        holds: list[tuple[datetime, str, str]] = []
        if (hold := self._hold_until(name, entry, now, production=production)) is not None:
            holds.append((hold, "backoff", f"{name!r} is in backoff until {hold.isoformat()}"))
        if production and force and entry.installed_at is not None:
            until = entry.installed_at + FORCE_WINDOW
            if until > now:
                holds.append(
                    (
                        until,
                        "force_window",
                        f"a forced issue for {name!r} is refused until {until.isoformat()} "
                        "(24 h after the last install); a plain request is accepted",
                    )
                )
        if entry.last_request_at is not None:
            until = entry.last_request_at + REQUEST_FLOOR
            if until > now:
                holds.append(
                    (
                        until,
                        "request_floor",
                        f"an issue request for {name!r} was accepted less than "
                        f"{int(REQUEST_FLOOR.total_seconds())} s ago; retry after "
                        f"{until.isoformat()}",
                    )
                )
        if holds:
            until, reason, detail = max(holds, key=lambda item: item[0])
            return IssueOutcome(
                IssueStatus.IN_BACKOFF,
                retry_after_seconds=max(math.ceil((until - now).total_seconds()), 1),
                detail=detail,
                reason=reason,
                error_code=error_value,
            )
        try:
            state.record_request(name, now=now)
        except OSError as exc:
            logger.error(
                "acme.runner.request_not_persisted",
                certificate=name,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            return IssueOutcome(
                IssueStatus.UNAVAILABLE,
                detail="ACME state file cannot be written; issuance is refused until it is fixed",
                error_code=error_value,
            )
        self._requests[name] = self._requests.get(name, False) or force
        self._wake.set()
        logger.info("acme.runner.issue_requested", certificate=name, force=force)
        return IssueOutcome(
            IssueStatus.ACCEPTED, detail=f"issuance for {name!r} scheduled", error_code=error_value
        )

    def snapshot(self) -> AcmeSnapshot:
        """A read-only view per certificate for ``/status`` and readiness codes."""
        cfg = self._config
        if cfg is None:
            return AcmeSnapshot(
                configured=False,
                directory=None,
                staging=None,
                running=self._running,
                state_error=self._state_error,
                certificates=(),
                task_dead=self._task_dead,
            )
        now = self._clock()
        return AcmeSnapshot(
            configured=True,
            directory=cfg.settings.directory_url,
            staging=cfg.settings.is_staging,
            running=self._running,
            state_error=self._state_error,
            certificates=tuple(self._cert_snapshot(cfg, cert, now) for cert in cfg.certificates),
            task_dead=self._task_dead,
        )

    def start(self) -> asyncio.Task[None]:
        """Start the loop as a background task (idempotent) and return it.

        If the task ever ends other than by cancellation, an ERROR is logged and
        ``AcmeSnapshot.task_dead`` is set.
        """
        if self._task is None or self._task.done():
            self._task_dead = False
            self._task = asyncio.create_task(self.run(), name="acme-runner")
            self._task.add_done_callback(self._task_finished)
        return self._task

    def _task_finished(self, task: asyncio.Task[None]) -> None:
        """Done-callback: a loop that ended without being cancelled is a dead runner."""
        if task.cancelled():
            return
        self._task_dead = True
        exc = task.exception()
        logger.error(
            "acme.runner.task_died",
            error_type=type(exc).__name__ if exc is not None else None,
            error=bound_excerpt(redact_output(str(exc))) if exc is not None else "loop returned",
        )

    async def run(self) -> None:
        """The scheduling loop; runs until cancelled. Never raises except cancellation."""
        binary = self._gwops.lego_binary
        try:
            exists: bool | None = await asyncio.to_thread(binary.is_file)
        except OSError:
            exists = None
        logger.info("acme.runner.started", lego_binary=binary.as_posix(), lego_binary_exists=exists)
        try:
            while True:
                self._wake.clear()
                try:
                    delay = await self._step()
                except Exception as exc:
                    logger.error(
                        "acme.runner.loop_error", error_type=type(exc).__name__, error=str(exc)
                    )
                    delay = LOOP_ERROR_DELAY_SECONDS
                if delay is None:
                    continue
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._wake.wait(), timeout=delay)
        finally:
            logger.info("acme.runner.stopped")

    async def aclose(self) -> None:
        """Stop the loop and terminate a running lego (SIGTERM, then SIGKILL). Idempotent."""
        self._closed = True
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    # -- planning -----------------------------------------------------------------------

    async def _step(self) -> float | None:
        """Run the due certificate if any (``None``: re-plan now), else the delay to sleep."""
        state = self._ensure_state()
        cfg = self._config
        if state is None:
            return STATE_RETRY_SECONDS
        if cfg is None or not cfg.certificates:
            return MAX_SLEEP_SECONDS
        self._clear_fixed_backoff(cfg, state)
        await self._retry_store_cleanup()
        now = self._clock()
        plans = [(cert, self._plan(cfg, cert, state, now)) for cert in cfg.certificates]
        cert, plan = min(plans, key=lambda item: (item[1].due_at, item[1].priority))
        if plan.due_at > now:
            delay = min((plan.due_at - now).total_seconds(), MAX_SLEEP_SECONDS)
            return min(delay, RELOAD_RETRY_SECONDS) if self._reload_pending else delay
        try:
            await self._attempt(cfg, cert, plan, state)
        except Exception as exc:
            self._record_crash(cert.name, exc)
        return None

    def _record_crash(self, name: str, exc: Exception) -> None:
        """Remember an unexpected attempt exception; back off 15 min doubling to 24 h."""
        count = self._crashes.get(name, 0) + 1
        self._crashes[name] = count
        excerpt = bound_excerpt(redact_output(f"{type(exc).__name__}: {exc}"))
        self._last_crash[name] = excerpt
        self._cooldowns[name] = self._clock() + backoff_delay(count)
        logger.error(
            "acme.runner.attempt_crashed",
            certificate=name,
            error_type=type(exc).__name__,
            error=excerpt,
            consecutive_crashes=count,
        )

    def _note_success(self, name: str) -> None:
        """A clean attempt: forget crashes and the in-memory cooldown of `name`."""
        self._crashes.pop(name, None)
        self._last_crash.pop(name, None)
        self._cooldowns.pop(name, None)

    def _effective_error(
        self, name: str, entry: CertAcmeState
    ) -> tuple[AcmeErrorClass | None, str | None]:
        """The error shown for `name`: persisted, else a crash, else a pending reload."""
        if entry.error_code is not None:
            return entry.error_code, entry.error_excerpt
        if (crash := self._last_crash.get(name)) is not None:
            return AcmeErrorClass.INTERNAL, crash
        if name in self._reload_pending:
            return AcmeErrorClass.INTERNAL, RELOAD_PENDING_EXCERPT
        return None, None

    def _clear_fixed_backoff(self, cfg: AcmeConfig, state: AcmeStateStore) -> None:
        """Clear persisted backoff an operator may just have fixed (stat only, never opens a file).

        For a certificate whose last failure is ``config``, ``dns_auth`` or ``dns_zone``: a
        changed effective configuration for it, or a changed token file
        ``(st_ino, st_mtime_ns, st_size)``, drops ``consecutive_failures`` and
        ``next_attempt_at``. ``force`` still never bypasses backoff. The comparison
        baseline is in memory, so a change made while gwops was down is not seen.
        """
        signature = token_file_signature(cfg.settings)
        token_changed = self._token_signature is not _UNSET and signature != self._token_signature
        self._token_signature = signature
        for cert in cfg.certificates:
            fingerprint = f"{cfg.settings.model_dump_json()}|{cert.model_dump_json()}|{cfg.zones}"
            previous = self._fingerprints.get(cert.name)
            self._fingerprints[cert.name] = fingerprint
            config_changed = previous is not None and previous != fingerprint
            if not (token_changed or config_changed):
                continue
            if state.get(cert.name).error_code not in _OPERATOR_FIXABLE:
                continue
            try:
                cleared = state.clear_backoff(cert.name)
            except OSError as exc:
                logger.error(
                    "acme.runner.backoff_clear_failed",
                    certificate=cert.name,
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
                continue
            if cleared:
                logger.info(
                    "acme.runner.backoff_cleared",
                    certificate=cert.name,
                    reason="token_file_changed" if token_changed else "config_changed",
                )

    async def _retry_store_cleanup(self) -> None:
        """Retry ``store.gc`` for installs whose previous generation could not be deleted."""
        for name in sorted(self._reload_pending):
            try:
                await asyncio.to_thread(self._store.gc, name)
            except (StoreError, ValueError, OSError) as exc:
                logger.warning(
                    "acme.runner.store_gc_failed",
                    certificate=name,
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
            else:
                self._reload_pending.discard(name)
                logger.info("acme.runner.store_gc_cleared", certificate=name)

    def _plan(
        self, cfg: AcmeConfig, cert: AcmePublicCertificate, state: AcmeStateStore, now: datetime
    ) -> _Plan:
        """The reason for the next attempt of `cert` and the earliest time it may start."""
        name = cert.name
        entry = state.get(name)
        production = not cfg.settings.is_staging
        floor = self._hold_until(name, entry, now, production=production) or now
        if name in self._requests:
            force = self._requests[name]
            reason = "forced" if force else "requested"
            return _Plan(reason, floor, _PRIORITY[reason], force)
        if (reason_now := self._immediate_reason(cfg, cert, entry)) is not None:
            return _Plan(reason_now, floor, _PRIORITY[reason_now])
        due = max(entry.next_attempt_at or now, floor)
        return _Plan("retry" if entry.error_code is not None else "check_interval", due, 9)

    def _immediate_reason(
        self, cfg: AcmeConfig, cert: AcmePublicCertificate, entry: CertAcmeState
    ) -> str | None:
        """Why `cert` needs an attempt regardless of the check schedule, or ``None``."""
        url = cfg.settings.directory_url
        if cfg.settings.is_staging:
            if entry.last_success_at is None or entry.directory != url:
                return "missing"
            if entry.names and names_hash(entry.names) != names_hash(cert.names):
                return "names_changed"
            return None
        if (
            entry.installed_serial is None
            or not self._store_has(cert.name)
            or cert.name in self._store_invalid
        ):
            return "missing"
        if entry.issued_names_hash is not None and entry.issued_names_hash != names_hash(
            cert.names
        ):
            return "names_changed"
        if entry.directory and entry.directory != url:
            return "directory_changed"
        return None

    def _hold_until(
        self, name: str, entry: CertAcmeState, now: datetime, *, production: bool
    ) -> datetime | None:
        """When `name` may next start, if something holds it back now.

        Holds: the persisted failure backoff (``consecutive_failures`` or ``error_code`` set),
        the crash-loop guard of an attempt that never recorded an outcome, the production
        failed-validation limiter, and an in-memory cooldown (crashes). The persisted
        ``next_attempt_at`` after a *success* is the next scheduled check, not a hold.
        """
        holds: list[datetime] = []
        if entry.next_attempt_at is not None and entry.next_attempt_at > now:
            failing = entry.consecutive_failures > 0 or entry.error_code is not None
            interrupted = entry.last_attempt_at is not None and (
                entry.last_success_at is None or entry.last_success_at < entry.last_attempt_at
            )
            if failing or interrupted:
                holds.append(entry.next_attempt_at)
        if production and (floor := limiter_not_before(entry.validation_failures, now)) is not None:
            holds.append(floor)
        if (cooldown := self._cooldowns.get(name)) is not None and cooldown > now:
            holds.append(cooldown)
        return max(holds) if holds else None

    def _next_check(self, now: datetime) -> datetime:
        """The next scheduled ``lego run`` check: 12 h plus or minus 1 h."""
        spread = CHECK_JITTER.total_seconds()
        return now + CHECK_INTERVAL + timedelta(seconds=self._rng.uniform(-spread, spread))

    def _store_has(self, name: str) -> bool:
        """Whether the public store holds a certificate and key for `name`."""
        try:
            cert_path, key_path = self._store.stable_paths(name)
        except ValueError:
            return False
        return cert_path.is_file() and key_path.is_file()

    def _ensure_state(self) -> AcmeStateStore | None:
        """The state store, loading it if needed; ``None`` while the file is unusable.

        An unusable file is never overwritten or removed; it is re-read on every call so a
        repaired file recovers without a restart.
        """
        if self._state is None:
            try:
                self._state = AcmeStateStore(self._gwops.acme_dir)
            except AcmeStateError as exc:
                message = str(exc)
                if message != self._state_error:
                    logger.error("acme.runner.state_unusable", error=message)
                self._state_error = message
                return None
            if self._state_error is not None:
                logger.info("acme.runner.state_recovered")
            self._state_error = None
        return self._state

    # -- one attempt --------------------------------------------------------------------

    async def _attempt(
        self, cfg: AcmeConfig, cert: AcmePublicCertificate, plan: _Plan, state: AcmeStateStore
    ) -> None:
        """Run lego for `cert` and record the outcome."""
        name = cert.name
        settings = cfg.settings
        production = not settings.is_staging
        url = settings.directory_url
        storage = self._gwops.lego_storage_dir(url)
        self._requests.pop(name, None)
        self._running = name
        try:
            prior = state.get(name)
            if prior.directory and prior.directory != url:
                if self._gwops.lego_storage_dir(prior.directory) == storage:
                    removed = await asyncio.to_thread(self._reset_lego_material, name, storage)
                    logger.warning(
                        "acme.runner.lego_material_reset",
                        certificate=name,
                        reason="directory_changed",
                        previous_directory=prior.directory,
                        directory=url,
                        removed=removed,
                    )
            elif not prior.directory:
                # Files of unknown provenance (state lost or never written): start from a
                # fresh order rather than trusting them.
                removed = await asyncio.to_thread(self._reset_lego_material, name, storage)
                if removed:
                    logger.warning(
                        "acme.runner.lego_material_reset",
                        certificate=name,
                        reason="unknown_provenance",
                        directory=url,
                        removed=removed,
                    )
            await asyncio.to_thread(self._prepare_dirs, storage)
            state.record_attempt_start(
                name, now=self._clock(), names=cert.names, directory=url, reason=plan.reason
            )
            logger.info(
                "acme.runner.attempt_started",
                certificate=name,
                reason=plan.reason,
                forced=plan.force,
                directory=url,
                staging=not production,
                names=list(cert.names),
                token_file=settings.token_file,
            )
            token = await asyncio.to_thread(resolve_token_file, settings)
            if token.outside_root:
                self._record_failure(
                    state, name, AcmeErrorClass.CONFIG, token.problem or "token file refused",
                    production=production,
                )  # fmt: skip
                return
            argv, env = build_argv(
                settings,
                cert,
                gwops=self._gwops,
                force=plan.force,
                environ=self._environ,
                token_path=token.path,
            )
            try:
                run = await self._run_lego(argv, env)
            except OSError as exc:
                self._record_failure(
                    state, name, AcmeErrorClass.CONFIG,
                    f"cannot start lego at {self._gwops.lego_binary} ({type(exc).__name__})",
                    production=production,
                )  # fmt: skip
                return
            await asyncio.to_thread(self._tighten_permissions)
            logger.info(
                "acme.runner.lego_exited",
                certificate=name,
                exit_code=run.exit_code,
                timed_out=run.timed_out,
                duration_seconds=round(run.duration_seconds, 2),
                output_bytes=run.output_bytes,
                output_truncated=run.truncated,
            )
            if run.timed_out or run.exit_code != 0:
                self._record_run_failure(state, name, run, production=production)
                return
            await self._land(cfg, cert, state)
        finally:
            self._running = None

    def _record_run_failure(
        self, state: AcmeStateStore, name: str, run: _LegoRun, *, production: bool
    ) -> None:
        """Classify a timed-out or non-zero run and record it."""
        error_class = classify_output(run.text, timed_out=run.timed_out)
        excerpt = summarize_output(
            run.text,
            exit_code=run.exit_code,
            timed_out=run.timed_out,
            timeout_seconds=self._gwops.lego_timeout_seconds,
        )
        retry_after = (
            parse_retry_after(run.text, self._clock())
            if error_class is AcmeErrorClass.RATE_LIMITED
            else None
        )
        self._record_failure(
            state, name, error_class, excerpt, production=production, retry_after=retry_after
        )

    def _record_failure(
        self,
        state: AcmeStateStore,
        name: str,
        error_class: AcmeErrorClass,
        excerpt: str,
        *,
        production: bool,
        retry_after: datetime | None = None,
    ) -> None:
        """Persist a failure (backoff policy in the store) and log class and excerpt."""
        outcome = state.record_failure(
            name,
            now=self._clock(),
            error_class=error_class,
            excerpt=excerpt,
            production=production,
            retry_after=retry_after,
        )
        logger.warning(
            "acme.runner.attempt_failed",
            certificate=name,
            error_code=error_class.value,
            excerpt=bound_excerpt(excerpt),
            consecutive_failures=outcome.consecutive_failures,
            next_attempt_at=outcome.next_attempt_at.isoformat(),
        )

    async def _land(
        self, cfg: AcmeConfig, cert: AcmePublicCertificate, state: AcmeStateStore
    ) -> None:
        """After a clean exit: validate lego's files, install in production, record."""
        name = cert.name
        production = not cfg.settings.is_staging
        current = self._config
        if current is None or name not in {c.name for c in current.certificates}:
            logger.warning("acme.runner.config_changed_during_run", certificate=name)
            return
        assessment = await asyncio.to_thread(self._assess_material, cfg, cert, state, self._clock())
        now = self._clock()
        match assessment.kind:
            case "refused":
                self._record_failure(
                    state, name, AcmeErrorClass.INVALID_OUTPUT, assessment.detail,
                    production=production,
                )  # fmt: skip
                if production:
                    storage = self._gwops.lego_storage_dir(cfg.settings.directory_url)
                    removed = await asyncio.to_thread(self._reset_lego_material, name, storage)
                    logger.warning(
                        "acme.runner.lego_material_reset",
                        certificate=name,
                        reason="refused",
                        removed=removed,
                    )
                return
            case "install_failed":
                self._record_failure(
                    state, name, AcmeErrorClass.INTERNAL, assessment.detail, production=production
                )
                return
            case "not_new":
                state.record_success(
                    name, now=now, next_attempt_at=self._next_check(now), installed=False
                )
                logger.info("acme.runner.not_due", certificate=name)
            case "dry_run":
                state.record_success(
                    name, now=now, next_attempt_at=self._next_check(now), installed=False
                )
                logger.info(
                    "acme.runner.dry_run_ok",
                    certificate=name,
                    staging=True,
                    serial=assessment.serial,
                    installed=False,
                )
            case "installed":
                self._store_invalid.discard(name)
                if assessment.reload_pending:
                    self._reload_pending.add(name)
                    logger.warning("acme.runner.install_reload_pending", certificate=name)
                else:
                    self._reload_pending.discard(name)
                try:
                    state.record_success(
                        name,
                        now=now,
                        next_attempt_at=self._next_check(now),
                        installed=True,
                        serial=assessment.serial,
                        fingerprint=assessment.fingerprint,
                    )
                except Exception:
                    # The store already serves the new pair; the reconciler must still hear.
                    if assessment.signal_install:
                        self._notify_installed(name)
                    raise
                logger.info(
                    "acme.runner.installed",
                    certificate=name,
                    serial=assessment.serial,
                    fingerprint=assessment.fingerprint,
                )
                if assessment.signal_install:
                    self._notify_installed(name)
        self._note_success(name)
        if self._immediate_reason(cfg, cert, state.get(name)) is not None:
            # A clean run that leaves the certificate still due would loop on lego: back off.
            logger.warning("acme.runner.still_due_after_success", certificate=name)
            self._record_failure(
                state,
                name,
                AcmeErrorClass.INTERNAL,
                STILL_DUE_EXCERPT,
                production=production,
            )

    def _notify_installed(self, name: str) -> None:
        """Tell the reconciler's trigger that new material is in the store."""
        if self._on_installed is None:
            return
        try:
            self._on_installed(name)
        except Exception as exc:
            logger.error(
                "acme.runner.install_callback_failed",
                certificate=name,
                error_type=type(exc).__name__,
                exc_info=True,
            )
            self.wake()

    # -- material -----------------------------------------------------------------------

    def _read_store_pair(self, name: str) -> tuple[bytes, bytes] | None:
        """The installed ``(fullchain, key)`` bytes for `name`, or ``None`` if unavailable."""
        try:
            cert_path, key_path = self._store.stable_paths(name)
        except ValueError:
            return None
        root = cert_path.parent.parent
        try:
            return read_confined(cert_path, root), read_confined(key_path, root)
        except ConfinedFileError:
            return None

    def _assess_material(
        self, cfg: AcmeConfig, cert: AcmePublicCertificate, state: AcmeStateStore, now: datetime
    ) -> _Assessment:
        """Read, compare, validate and (production) install lego's output; runs in a thread."""
        name = cert.name
        production = not cfg.settings.is_staging
        certs_dir = self._gwops.lego_storage_dir(cfg.settings.directory_url) / "certificates"
        try:
            crt = read_confined(certs_dir / f"{name}.crt", certs_dir)
            key = read_confined(certs_dir / f"{name}.key", certs_dir)
        except ConfinedFileError as exc:
            return _Assessment(
                "refused", f"lego exited 0 but its certificate or key cannot be read: {exc}"
            )
        issuer_note = ""
        try:
            issuer: bytes | None = read_confined(certs_dir / f"{name}.issuer.crt", certs_dir)
        except ConfinedFileError as exc:
            issuer = None
            issuer_note = f" (the issuer file {name}.issuer.crt is unreadable: {exc})"
            logger.warning(
                "acme.runner.issuer_unreadable",
                certificate=name,
                file=f"{name}.issuer.crt",
                error=str(exc),
            )
        cert_pem = _with_issuer(crt, issuer)
        try:
            leaf = _first_certificate(cert_pem)
        except ValueError:
            return _Assessment(
                "refused", "lego's certificate file holds no parseable certificate" + issuer_note
            )
        serial = format(leaf.serial_number, "x")
        fingerprint = leaf.fingerprint(hashes.SHA256()).hex()
        had_installed = state.has_installed(name)
        was_invalid = name in self._store_invalid
        if production and not was_invalid:
            installed_pair = self._read_store_pair(name)
            store_is_current = (
                installed_pair is not None
                and _leaf_fingerprint(installed_pair[0]) == fingerprint
                and installed_pair[1].strip() == key.strip()
            )
            if store_is_current and not state.is_new_material(
                name, serial=serial, fingerprint=fingerprint
            ):
                return _Assessment("not_new", serial=serial, fingerprint=fingerprint)
        try:
            if production:
                if cfg.root is None:
                    raise RuntimeError("production ACME without a registered root")
                validate_public_material(
                    cert, cert_pem, key, zones=cfg.zones, root=cfg.root, now=now
                )
            else:
                validate_public_material_without_root(cert, cert_pem, key, zones=cfg.zones, now=now)
        except PublicMaterialError as exc:
            return _Assessment("refused", f"{exc}{issuer_note}")
        if not production:
            return _Assessment("dry_run", serial=serial, fingerprint=fingerprint)
        try:
            result = self._store.install(name, cert_pem, key)
        except (StoreError, ValueError, OSError) as exc:
            return _Assessment("install_failed", f"cannot install validated material: {exc}")
        return _Assessment(
            "installed",
            serial=serial,
            fingerprint=fingerprint,
            signal_install=result.changed or not had_installed or was_invalid,
            reload_pending=result.reload_pending,
        )

    def _reset_lego_material(self, name: str, storage: Path) -> list[str]:
        """Remove lego's stored certificate files for `name` under `storage`."""
        certs_dir = storage / "certificates"
        removed: list[str] = []
        for suffix in _LEGO_FILES:
            try:
                (certs_dir / f"{name}{suffix}").unlink()
            except FileNotFoundError:
                continue
            except OSError as exc:
                logger.warning(
                    "acme.runner.lego_material_unlink_failed",
                    certificate=name,
                    file=f"{name}{suffix}",
                    error=str(exc),
                )
                continue
            removed.append(suffix)
        return removed

    # -- directories and permissions ------------------------------------------------------

    def _prepare_dirs(self, storage: Path) -> None:
        """Create ``<data_dir>/acme``, lego's base and `storage` with mode 0700 (POSIX)."""
        unfixable: list[Path] = []
        for directory in (self._gwops.acme_dir, self._gwops.lego_path_dir, storage):
            directory.mkdir(parents=True, exist_ok=True)
            if os.name == "posix":
                try:
                    os.chmod(directory, 0o700)
                except OSError as exc:
                    unfixable.append(directory)
                    logger.error(
                        "acme.runner.permissions_unfixable",
                        path=os.fspath(directory),
                        error_type=type(exc).__name__,
                        error=str(exc),
                    )
        self._prepare_problem = _permissions_text(unfixable)

    def _tighten_permissions(self) -> None:
        """Make everything under lego's storage owner-only (the account key is 0600 already).

        lego writes 0600 files in 0700 directories; this verifies after the run and corrects
        any group or other access. Symbolic links are never followed or changed. Entries that
        cannot be fixed are logged at ERROR with their path and surfaced as
        ``CertSnapshot.permissions_problem``.
        """
        if os.name != "posix":
            return
        root = self._gwops.lego_path_dir
        fixed = 0
        unfixable: list[Path] = []
        try:
            paths = [root, *root.rglob("*")]
        except OSError as exc:
            self._log_unfixable(root, exc, unfixable)
            self._tighten_problem = _permissions_text(unfixable)
            return
        for path in paths:
            try:
                info = os.lstat(path)
                if stat.S_ISLNK(info.st_mode):
                    continue
                mode = stat.S_IMODE(info.st_mode)
                wanted = 0o700 if stat.S_ISDIR(info.st_mode) else 0o600
                if mode & 0o077:
                    os.chmod(path, wanted)
                    fixed += 1
            except FileNotFoundError:
                continue  # removed while scanning
            except OSError as exc:
                self._log_unfixable(path, exc, unfixable)
        if fixed:
            logger.warning("acme.runner.permissions_tightened", entries=fixed)
        self._tighten_problem = _permissions_text(unfixable)

    @staticmethod
    def _log_unfixable(path: Path, exc: OSError, unfixable: list[Path]) -> None:
        """Count an entry whose permissions could not be checked or fixed; log the first few."""
        unfixable.append(path)
        if len(unfixable) <= _PERMISSION_LOG_LIMIT:
            logger.error(
                "acme.runner.permissions_unfixable",
                path=os.fspath(path),
                error_type=type(exc).__name__,
                error=str(exc),
            )

    # -- subprocess ---------------------------------------------------------------------

    async def _run_lego(self, argv: list[str], env: dict[str, str]) -> _LegoRun:
        """Run lego once: closed stdin, merged bounded output, time limit, group kill."""
        started = time.monotonic()
        spawn_options: dict[str, Any] = {}
        if sys.platform != "win32":
            spawn_options["start_new_session"] = True  # own process group for the kill
        spawn = asyncio.ensure_future(
            asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
                cwd=self._gwops.acme_dir,
                **spawn_options,
            )
        )
        try:
            # Shielded: a cancellation during the spawn must not orphan the child it creates.
            proc = await asyncio.shield(spawn)
        except asyncio.CancelledError:
            spawn.add_done_callback(_kill_spawned)
            raise
        capture = _Capture()
        assert proc.stdout is not None
        pump = asyncio.create_task(self._pump(proc.stdout, capture))
        timed_out = False
        try:
            try:
                async with asyncio.timeout(self._gwops.lego_timeout_seconds):
                    await proc.wait()
            except TimeoutError:
                timed_out = True
                logger.warning(
                    "acme.runner.lego_timeout", timeout_seconds=self._gwops.lego_timeout_seconds
                )
                await self._stop(proc)
        except asyncio.CancelledError:
            await self._stop(proc)
            pump.cancel()
            raise
        try:
            await asyncio.wait_for(pump, DRAIN_TIMEOUT_SECONDS)
        except TimeoutError:
            pass  # wait_for cancelled the pump; keep what was captured
        except Exception as exc:
            logger.warning("acme.runner.output_read_failed", error_type=type(exc).__name__)
        return _LegoRun(
            exit_code=proc.returncode,
            timed_out=timed_out,
            text=capture.text(),
            output_bytes=capture.total,
            truncated=capture.truncated,
            duration_seconds=time.monotonic() - started,
        )

    @staticmethod
    async def _pump(stream: asyncio.StreamReader, capture: _Capture) -> None:
        """Copy the process's output into `capture` until end of file."""
        while chunk := await stream.read(_READ_CHUNK):
            capture.feed(chunk)

    @staticmethod
    async def _stop(proc: asyncio.subprocess.Process) -> None:
        """SIGTERM lego's process group, then SIGKILL it after the grace period."""
        if proc.returncode is not None:
            return
        _signal_group(proc, kill=False)
        try:
            await asyncio.wait_for(proc.wait(), KILL_GRACE_SECONDS)
        except TimeoutError:
            _signal_group(proc, kill=True)
            await proc.wait()

    # -- snapshot -----------------------------------------------------------------------

    def _permissions_problem(self) -> str | None:
        """Combined path-only text of the last directory preparation and permission check."""
        parts = [p for p in (self._prepare_problem, self._tighten_problem) if p]
        return "; ".join(parts) if parts else None

    def _cert_snapshot(
        self, cfg: AcmeConfig, cert: AcmePublicCertificate, now: datetime
    ) -> CertSnapshot:
        """Build the read-only view of one certificate."""
        name = cert.name
        staging = cfg.settings.is_staging
        url = cfg.settings.directory_url
        state = self._state
        entry = state.get(name) if state is not None else CertAcmeState()
        installed = self._store_has(name)
        hold: datetime | None = None
        due_at: datetime | None = None
        error_code, excerpt = self._effective_error(name, entry)
        if state is None:
            cert_state = AcmeCertState.FAILED
            error_code = AcmeErrorClass.INTERNAL
            excerpt = bound_excerpt(self._state_error or "ACME state file is unusable")
        else:
            hold = self._hold_until(name, entry, now, production=not staging)
            plan = self._plan(cfg, cert, state, now)
            due_at = plan.due_at
            dry_run_ok = (
                staging
                and entry.last_success_at is not None
                and entry.directory == url
                and error_code is None
            )
            if self._running == name:
                cert_state = AcmeCertState.ISSUING
            elif hold is not None:
                cert_state = AcmeCertState.BACKOFF
            elif name in self._requests:
                cert_state = AcmeCertState.SCHEDULED
            elif error_code is not None:
                cert_state = AcmeCertState.FAILED
            elif dry_run_ok:
                cert_state = AcmeCertState.DRY_RUN_OK
            elif plan.due_at <= now:
                cert_state = AcmeCertState.SCHEDULED
            else:
                cert_state = AcmeCertState.IDLE
        return CertSnapshot(
            name=name,
            names=tuple(cert.names),
            directory=url,
            staging=staging,
            state=cert_state,
            installed=installed,
            installed_at=entry.installed_at,
            installed_serial=entry.installed_serial,
            last_attempt_at=entry.last_attempt_at,
            last_success_at=entry.last_success_at,
            next_attempt_at=due_at,
            error_code=error_code,
            error_excerpt=excerpt,
            renewal_reason=entry.renewal_reason,
            consecutive_failures=entry.consecutive_failures,
            in_backoff=hold is not None,
            retry_after=(
                entry.retry_after if entry.retry_after and entry.retry_after > now else None
            ),
            last_crash=self._last_crash.get(name),
            permissions_problem=self._permissions_problem(),
        )


def _permissions_text(unfixable: list[Path]) -> str | None:
    """Path-only description of entries whose permissions could not be fixed."""
    if not unfixable:
        return None
    extra = f" and {len(unfixable) - 1} more" if len(unfixable) > 1 else ""
    return f"cannot restrict permissions of {os.fspath(unfixable[0])}{extra}"


def _leaf_fingerprint(pem: bytes) -> str | None:
    """SHA-256 fingerprint (hex) of the first certificate in `pem`, or ``None`` if unparsable."""
    try:
        return _first_certificate(pem).fingerprint(hashes.SHA256()).hex()
    except ValueError:
        return None


def _with_issuer(crt: bytes, issuer: bytes | None) -> bytes:
    """`crt` as the served chain: when it holds only the leaf, append lego's issuer file."""
    if issuer and crt.count(_CERT_BEGIN) == 1:
        return crt.rstrip() + b"\n" + issuer.strip() + b"\n"
    return crt


def _first_certificate(pem: bytes) -> x509.Certificate:
    """The first certificate in `pem`.

    Raises:
        ValueError: There is none, or it cannot be parsed.
    """
    match = _CERT_BLOCK.search(pem)
    if match is None:
        raise ValueError("no certificate block")
    return x509.load_pem_x509_certificate(match.group(0))
