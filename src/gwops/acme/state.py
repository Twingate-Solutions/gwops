"""Persistent per-certificate ACME state and the backoff policy that drives retries.

``<data_dir>/acme/state.json`` records, per ``source: acme`` certificate, what the runner last
tried, what it last installed and when it may try again, so that a restart resumes the schedule
instead of re-issuing (and re-hitting Let's Encrypt rate limits).

Two layers:

* Pure policy functions (:func:`backoff_delay`, :func:`next_attempt_after_failure`,
  :func:`limiter_not_before`, :func:`parse_retry_after`, :func:`names_hash`). They take ``now``
  as an argument and read no clock, so tests are deterministic.
* :class:`AcmeStateStore`: loads the file once, applies ``record_*`` transitions and persists
  every transition atomically (temporary file, fsync, rename; directory ``0700``, file ``0600``
  on POSIX). The store never reads a clock either: every method that records time takes ``now``.

The file never holds a secret. The DNS token is never read by gwops, and failure excerpts are
bounded to :data:`MAX_EXCERPT_CHARS`; the caller must pass only lego output already scrubbed
of token material.

Every lego failure exits 1, so classification is the runner's job. A renewal that is not due
exits 0 and writes nothing, so "exit 0" is distinguished from "new certificate" by comparing
the installed serial or fingerprint (:meth:`AcmeStateStore.is_new_material`).
"""

import hashlib
import json
import os
import re
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal

import structlog
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError, field_validator

logger = structlog.get_logger(__name__)

STATE_VERSION = 1
"""``version`` written to and required from ``state.json``."""

STATE_FILENAME = "state.json"
"""File name under the ACME directory."""

DIR_MODE = 0o700
"""Mode of ``<data_dir>/acme`` (POSIX)."""

FILE_MODE = 0o600
"""Mode of ``state.json`` (POSIX)."""

INITIAL_BACKOFF = timedelta(minutes=15)
"""Delay after the first consecutive failure."""

MAX_BACKOFF = timedelta(hours=24)
"""Cap of the doubling backoff."""

RATE_LIMIT_FLOOR = timedelta(hours=1)
"""Minimum wait after a ``rate_limited`` failure, whatever the backoff or retry-after says."""

MAX_RETRY_AFTER = timedelta(days=7)
"""Longest parsed retry-after honoured; Let's Encrypt's longest limit window is one week."""

VALIDATION_WINDOW = timedelta(hours=1)
"""Window of Let's Encrypt's failed-validation limit (5 per hostname per account per hour)."""

MAX_FAILED_VALIDATIONS_PER_WINDOW = 4
"""Failed validations tolerated inside :data:`VALIDATION_WINDOW`; one fewer than the CA's limit.

Every name of a certificate fails together, so counting failed attempts per certificate bounds
the per-name count. Certificates that share a name are counted separately (under-counts).
"""

MAX_EXCERPT_CHARS = 512
"""Bound of the stored error excerpt."""

PRUNE_RETENTION = timedelta(days=7)
"""How long the entry of an undeclared certificate is kept (re-declaring restores it)."""

_EXPONENT_CAP = 16
"""Stops ``2 ** n`` growing for absurd failure counts; far beyond what reaches the 24 h cap."""


class AcmeStateError(ValueError):
    """``state.json`` is unreadable, corrupt or of an unknown version; says how to recover."""


class AcmeErrorClass(StrEnum):
    """Failure classes of one lego run.

    Values are the stable codes stored in ``state.json``, shown as ``error_code`` in ``/status``
    and as ``acme_failed:<code>`` in readiness.
    """

    RATE_LIMITED = "rate_limited"
    """ACME ``rateLimited`` (HTTP 429), including a run killed while lego slept on Retry-After."""
    DNS_AUTH = "dns_auth"
    """Cloudflare refused the request: token rejected (401, 403) or bad request (400)."""
    DNS_ZONE = "dns_zone"
    """The Cloudflare zone could not be found (resolver problem or token cannot see the zone)."""
    DNS_PROPAGATION = "dns_propagation"
    """Timed out waiting for the TXT record to propagate."""
    UNAUTHORIZED = "unauthorized"
    """The CA's validation of the challenge failed; counts toward the failed-validation limit."""
    ACME_UNREACHABLE = "acme_unreachable"
    """The ACME directory or API could not be reached or answered 5xx (``badNonce`` and
    ``serverInternal`` included), or the Cloudflare API answered 429/5xx or could not be
    reached. Cloudflare transients land here because no class names a DNS provider
    outage."""
    TIMEOUT = "timeout"
    """The subprocess exceeded its timeout and was killed."""
    INVALID_OUTPUT = "invalid_output"
    """lego exited 0 but the material failed certificate validation; nothing was installed."""
    CONFIG = "config"
    """A lego usage, credentials, ToS or read-only-filesystem error, or an ACME problem
    document that only a configuration change fixes (``invalidContact``,
    ``rejectedIdentifier``, ``malformed``, ``accountDoesNotExist``,
    ``userActionRequired``)."""
    INTERNAL = "internal"
    """Anything else."""


def names_hash(names: Iterable[str]) -> str:
    """Stable digest of a certificate's declared names (case-folded, order-insensitive).

    Used to detect a changed name set, which lego treats as a reason to issue immediately.
    """
    canonical = "\n".join(sorted({name.strip().lower() for name in names}))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def bound_excerpt(text: str, limit: int = MAX_EXCERPT_CHARS) -> str:
    """Collapse whitespace and control characters and truncate to `limit` characters."""
    cleaned = " ".join("".join(c if c.isprintable() or c.isspace() else " " for c in text).split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: max(limit - 3, 0)] + "..."


def backoff_delay(consecutive_failures: int) -> timedelta:
    """Backoff after `consecutive_failures` failures in a row: 15 min doubling, capped at 24 h.

    ``1 -> 15 min, 2 -> 30 min, 3 -> 1 h, ... , >= 8 -> 24 h``. Zero or fewer returns zero.
    """
    if consecutive_failures <= 0:
        return timedelta(0)
    exponent = min(consecutive_failures - 1, _EXPONENT_CAP)
    return min(INITIAL_BACKOFF * (1 << exponent), MAX_BACKOFF)


def prune_validation_failures(failures: Iterable[datetime], now: datetime) -> list[datetime]:
    """Failures still inside :data:`VALIDATION_WINDOW` of `now`, oldest first."""
    cutoff = now - VALIDATION_WINDOW
    return sorted(f for f in failures if f > cutoff)


def limiter_not_before(failures: Iterable[datetime], now: datetime) -> datetime | None:
    """Earliest time another attempt keeps failed validations under the CA's limit.

    Returns ``None`` when fewer than :data:`MAX_FAILED_VALIDATIONS_PER_WINDOW` failures are
    inside the window (an attempt may start now).
    """
    recent = prune_validation_failures(failures, now)
    if len(recent) < MAX_FAILED_VALIDATIONS_PER_WINDOW:
        return None
    # Enough of the oldest entries must age out to leave one fewer than the maximum.
    return recent[len(recent) - MAX_FAILED_VALIDATIONS_PER_WINDOW] + VALIDATION_WINDOW


_RETRY_AFTER_DATE = re.compile(
    r"retry[ -]after:?\s+(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\s*(?:UTC|Z))?", re.IGNORECASE
)
_RETRY_AFTER_SECONDS = re.compile(
    r"retry[ -]after:?\s+(\d{1,9})(?![\d:-])\s*(?:s\b|sec|seconds)?", re.IGNORECASE
)


def parse_retry_after(text: str, now: datetime) -> datetime | None:
    """The retry-after instant in lego output, or ``None`` when absent, unparsable or past.

    Recognises Let's Encrypt's ``retry after 2026-10-20 12:34:56 UTC`` clause and a numeric
    ``Retry-After: <seconds>``. lego itself never prints the header, so the
    date clause comes from the CA's error detail. The result is capped at
    :data:`MAX_RETRY_AFTER` past `now`.
    """
    result: datetime | None = None
    if match := _RETRY_AFTER_DATE.search(text):
        try:
            result = datetime.fromisoformat(f"{match[1]}T{match[2]}").replace(tzinfo=UTC)
        except ValueError:
            result = None
    elif match := _RETRY_AFTER_SECONDS.search(text):
        result = now + timedelta(seconds=int(match[1]))
    if result is None or result <= now:
        return None
    return min(result, now + MAX_RETRY_AFTER)


def next_attempt_after_failure(
    *,
    now: datetime,
    error_class: AcmeErrorClass,
    consecutive_failures: int,
    retry_after: datetime | None = None,
    validation_failures: Sequence[datetime] = (),
    production: bool = True,
) -> datetime:
    """When the next attempt may start after a failure.

    The result is the latest of:

    * ``now + backoff_delay(consecutive_failures)``;
    * for ``rate_limited``: ``now + RATE_LIMIT_FLOOR`` and `retry_after` when given;
    * for production: the failed-validation limiter's earliest time
      (:func:`limiter_not_before`; `validation_failures` includes the failure just recorded).

    Args:
        now: Current time (timezone-aware).
        error_class: Class of the failure just observed.
        consecutive_failures: Failures in a row including this one (at least 1).
        retry_after: Parsed retry-after instant (:func:`parse_retry_after`), if any.
        validation_failures: Recent failed-validation timestamps.
        production: Apply the limiter. Staging has no meaningful limit for this purpose.
    """
    candidates = [now + backoff_delay(max(consecutive_failures, 1))]
    if error_class is AcmeErrorClass.RATE_LIMITED:
        candidates.append(now + RATE_LIMIT_FLOOR)
        if retry_after is not None:
            candidates.append(min(retry_after, now + MAX_RETRY_AFTER))
    if production and (floor := limiter_not_before(validation_failures, now)) is not None:
        candidates.append(floor)
    return max(candidates)


class CertAcmeState(BaseModel):
    """Persisted ACME state of one ``source: acme`` certificate."""

    model_config = ConfigDict(extra="forbid")

    names: list[str] = Field(default_factory=list, description="Names of the last attempt.")
    directory: str = Field(default="", description="ACME directory URL of the last attempt.")
    last_attempt_at: AwareDatetime | None = None
    last_success_at: AwareDatetime | None = Field(
        default=None, description="Last clean lego exit: an install, a not-due skip or a dry run."
    )
    next_attempt_at: AwareDatetime | None = Field(
        default=None,
        description="Earliest time the runner may start lego again; None means no limit.",
    )
    attempts: int = Field(default=0, ge=0, description="Lego runs started, lifetime of the entry.")
    consecutive_failures: int = Field(default=0, ge=0)
    error_code: AcmeErrorClass | None = Field(
        default=None, description="Class of the last failure."
    )
    error_excerpt: str | None = Field(
        default=None, description="Bounded, token-free output excerpt."
    )
    retry_after: AwareDatetime | None = Field(
        default=None, description="Rate-limit-until of the last rate_limited failure."
    )
    renewal_reason: str | None = Field(
        default=None, description="Why the last attempt was started."
    )
    issued_names_hash: str | None = Field(
        default=None, description="names_hash() of the names the installed certificate covers."
    )
    installed_serial: str | None = Field(
        default=None, description="Serial of the installed leaf (hex)."
    )
    installed_fingerprint: str | None = Field(
        default=None, description="SHA-256 fingerprint of the installed leaf (hex)."
    )
    installed_at: AwareDatetime | None = None
    validation_failures: list[AwareDatetime] = Field(
        default_factory=list, description="Production failed validations inside the last hour."
    )
    last_request_at: AwareDatetime | None = Field(
        default=None, description="When the last admin issue request was accepted."
    )
    pruned_at: AwareDatetime | None = Field(
        default=None,
        description="When the certificate stopped being declared; the entry is kept for 7 days.",
    )

    @field_validator("error_excerpt", mode="before")
    @classmethod
    def _bound(cls, value: object) -> object:
        """Re-bound a stored excerpt so a hand-edited file cannot exceed the limit."""
        return bound_excerpt(value) if isinstance(value, str) else value


class AcmeStateDocument(BaseModel):
    """The whole ``state.json`` document."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    certificates: dict[str, CertAcmeState] = Field(default_factory=dict)


class FailureOutcome(BaseModel):
    """What :meth:`AcmeStateStore.record_failure` decided, for logging and the 429 path."""

    model_config = ConfigDict(frozen=True)

    error_class: AcmeErrorClass
    consecutive_failures: int
    next_attempt_at: AwareDatetime
    retry_after: AwareDatetime | None


def _fsync_dir(path: Path) -> None:
    """Best-effort fsync of a directory so a rename is durable; no-op where unsupported."""
    if os.name == "nt":
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class AcmeStateStore:
    """Load, query and atomically persist the per-certificate ACME state.

    The constructor loads the file (a missing file is an empty state). Every ``record_*``
    method updates one certificate's entry, writes the whole document atomically and only then
    swaps it into memory, so a failed write leaves memory and disk agreeing. Methods are
    synchronous and cheap (one small file); an async caller may call them directly or through
    ``asyncio.to_thread``. The store is not safe for concurrent writers; the runner runs one
    lego process at a time and is the only writer.

    Args:
        acme_dir: ``GwopsSettings.acme_dir`` (``<data_dir>/acme``). Created ``0700`` on the
            first write, not on load.

    Raises:
        AcmeStateError: The file exists but is unreadable, not valid JSON, not the expected
            shape, or of an unknown version. The file is left untouched. The caller decides
            how to surface this (the runner must not let it abort startup, and must not
            overwrite the file).
    """

    def __init__(self, acme_dir: Path) -> None:
        self._dir = acme_dir
        self._warned: set[str] = set()
        self._path = acme_dir / STATE_FILENAME
        self._doc = self._load()

    @property
    def path(self) -> Path:
        """Location of ``state.json``."""
        return self._path

    # -- queries -----------------------------------------------------------------------

    def get(self, name: str) -> CertAcmeState:
        """A copy of the state of certificate `name` (a blank state when never recorded)."""
        entry = self._doc.certificates.get(name)
        return entry.model_copy(deep=True) if entry is not None else CertAcmeState()

    def certificate_names(self) -> list[str]:
        """Certificates with a live (not pruned) entry, sorted."""
        return sorted(n for n, e in self._doc.certificates.items() if e.pruned_at is None)

    def has_installed(self, name: str) -> bool:
        """Whether a successful install was ever recorded for `name`."""
        return self._doc.certificates.get(name, CertAcmeState()).installed_serial is not None

    def names_changed(self, name: str, declared_names: Iterable[str]) -> bool:
        """Whether `declared_names` differ from the names the installed certificate covers.

        ``False`` when nothing was ever installed (that case is "missing", not "changed").
        """
        issued = self._doc.certificates.get(name, CertAcmeState()).issued_names_hash
        return issued is not None and issued != names_hash(declared_names)

    def is_new_material(self, name: str, *, serial: str, fingerprint: str) -> bool:
        """Whether a leaf differs from the installed one (a renewal, not a not-due skip).

        Compares the lowercase hex `serial` and SHA-256 `fingerprint` against the recorded
        install; ``True`` when nothing is recorded.
        """
        entry = self._doc.certificates.get(name)
        if entry is None or entry.installed_serial is None:
            return True
        return (
            entry.installed_serial.lower() != serial.lower()
            or (entry.installed_fingerprint or "").lower() != fingerprint.lower()
        )

    # -- transitions -------------------------------------------------------------------

    def record_attempt_start(
        self,
        name: str,
        *,
        now: datetime,
        names: Sequence[str],
        directory: str,
        reason: str,
    ) -> CertAcmeState:
        """Record that a lego run is starting; persisted before the process is spawned.

        Counts the attempt and, as a crash-loop guard, sets ``next_attempt_at`` to
        ``now + INITIAL_BACKOFF``: if gwops dies mid-run, a restart waits instead of
        re-running immediately. The matching ``record_success`` or ``record_failure``
        replaces it.

        Args:
            name: Seed certificate name.
            now: Current time (timezone-aware).
            names: Declared names the run covers.
            directory: ACME directory URL in use.
            reason: Why the run started (``missing``, ``names_changed``, ``renewal_window``,
                ``forced``, ...), shown as ``renewal_reason``.
        """
        entry = self.get(name)
        entry.names = list(names)
        entry.directory = directory
        entry.last_attempt_at = now
        entry.attempts += 1
        entry.renewal_reason = reason
        entry.next_attempt_at = now + INITIAL_BACKOFF
        self._commit(name, entry)
        return entry.model_copy(deep=True)

    def record_request(self, name: str, *, now: datetime) -> None:
        """Record that an admin issue request was accepted (the 60 s request floor reads it)."""
        entry = self.get(name)
        entry.last_request_at = now
        self._commit(name, entry)

    def clear_backoff(self, name: str) -> bool:
        """Drop the persisted failure backoff of `name`; ``True`` when something changed.

        Clears ``consecutive_failures``, ``next_attempt_at`` and ``retry_after``. The
        failed-validation window, the error class and the excerpt stay (the next attempt
        replaces them), so the CA's limit is still respected.
        """
        if name not in self._doc.certificates:
            return False
        entry = self.get(name)
        if (
            entry.consecutive_failures == 0
            and entry.next_attempt_at is None
            and entry.retry_after is None
        ):
            return False
        entry.consecutive_failures = 0
        entry.next_attempt_at = None
        entry.retry_after = None
        self._commit(name, entry)
        return True

    def record_success(
        self,
        name: str,
        *,
        now: datetime,
        next_attempt_at: datetime | None,
        installed: bool,
        serial: str | None = None,
        fingerprint: str | None = None,
    ) -> CertAcmeState:
        """Record a clean lego exit and clear the failure state.

        Use ``installed=True`` only after the material passed validation and the
        store accepted it (`serial` and `fingerprint` then required). Use ``installed=False``
        for a not-due skip (exit 0, nothing written) and for a staging dry run; the
        installed serial, fingerprint and names hash are left as they were. The runner decides
        which case applies with :meth:`is_new_material`.

        Args:
            name: Seed certificate name.
            now: Current time (timezone-aware).
            next_attempt_at: When the runner should look again (its 12 h check), or ``None``.
            installed: Whether new material was installed.
            serial: Lowercase hex serial of the installed leaf.
            fingerprint: SHA-256 fingerprint of the installed leaf, lowercase hex.

        Raises:
            ValueError: ``installed`` is true without `serial` and `fingerprint`.
        """
        if installed and not (serial and fingerprint):
            raise ValueError("record_success(installed=True) requires serial and fingerprint")
        entry = self.get(name)
        entry.last_success_at = now
        entry.next_attempt_at = next_attempt_at
        entry.consecutive_failures = 0
        entry.error_code = None
        entry.error_excerpt = None
        entry.retry_after = None
        entry.validation_failures = prune_validation_failures(entry.validation_failures, now)
        if installed:
            entry.installed_serial = serial
            entry.installed_fingerprint = fingerprint
            entry.installed_at = now
            entry.issued_names_hash = names_hash(entry.names)
        self._commit(name, entry)
        return entry.model_copy(deep=True)

    def record_failure(
        self,
        name: str,
        *,
        now: datetime,
        error_class: AcmeErrorClass,
        excerpt: str = "",
        production: bool = True,
        retry_after: datetime | None = None,
    ) -> FailureOutcome:
        """Record a failed run and schedule the next attempt with the backoff policy.

        Increments ``consecutive_failures``; for ``unauthorized`` in production it also records
        a failed validation for the limiter. For ``rate_limited`` ``retry_after`` is stored as
        the effective rate-limit-until (the later of the floor, the backoff and the parsed
        value). The installed-material fields are never touched.

        Args:
            name: Seed certificate name.
            now: Current time (timezone-aware).
            error_class: Classification of the run.
            excerpt: Bounded, token-free output excerpt; truncated here to
                :data:`MAX_EXCERPT_CHARS`.
            production: Whether the directory is a production CA (enables the limiter).
            retry_after: Parsed retry-after instant, if the output carried one.

        Returns:
            The scheduling decision, also persisted.
        """
        entry = self.get(name)
        entry.consecutive_failures += 1
        failures = prune_validation_failures(entry.validation_failures, now)
        if production and error_class is AcmeErrorClass.UNAUTHORIZED:
            failures.append(now)
        entry.validation_failures = failures
        next_at = next_attempt_after_failure(
            now=now,
            error_class=error_class,
            consecutive_failures=entry.consecutive_failures,
            retry_after=retry_after,
            validation_failures=failures,
            production=production,
        )
        entry.next_attempt_at = next_at
        entry.error_code = error_class
        entry.error_excerpt = bound_excerpt(excerpt) or None
        entry.retry_after = next_at if error_class is AcmeErrorClass.RATE_LIMITED else None
        self._commit(name, entry)
        logger.warning(
            "acme.state.failure_recorded",
            certificate=name,
            error_code=error_class.value,
            consecutive_failures=entry.consecutive_failures,
            next_attempt_at=next_at.isoformat(),
        )
        return FailureOutcome(
            error_class=error_class,
            consecutive_failures=entry.consecutive_failures,
            next_attempt_at=next_at,
            retry_after=entry.retry_after,
        )

    def prune(self, declared: Iterable[str], *, now: datetime) -> list[str]:
        """Retire entries of certificates that are no longer declared.

        An undeclared entry is marked ``pruned_at = now`` and kept for
        :data:`PRUNE_RETENTION`; one pruned longer ago is deleted; a declared entry that was
        marked is restored with its history intact. Nothing is written when nothing changes.

        Returns:
            Names newly marked or deleted by this call, sorted.
        """
        keep = set(declared)
        doc = self._doc.model_copy(deep=True)
        retired: list[str] = []
        restored: list[str] = []
        for name, entry in list(doc.certificates.items()):
            if name in keep:
                if entry.pruned_at is not None:
                    entry.pruned_at = None
                    restored.append(name)
            elif entry.pruned_at is None:
                entry.pruned_at = now
                retired.append(name)
            elif now - entry.pruned_at >= PRUNE_RETENTION:
                del doc.certificates[name]
                retired.append(name)
        if not retired and not restored:
            return []
        self._write(doc)
        logger.info("acme.state.pruned", retired=sorted(retired), restored=sorted(restored))
        return sorted(retired)

    # -- persistence -------------------------------------------------------------------

    def _commit(self, name: str, entry: CertAcmeState) -> None:
        """Persist the document with `entry` for `name`, then adopt it in memory."""
        doc = self._doc.model_copy(deep=True)
        doc.certificates[name] = entry
        self._write(doc)

    def _load(self) -> AcmeStateDocument:
        """Read ``state.json``: missing is empty, anything unusable raises AcmeStateError."""
        path = self._path
        try:
            raw_bytes = path.read_bytes()
        except FileNotFoundError:
            return AcmeStateDocument()
        except OSError as exc:
            raise AcmeStateError(
                f"ACME state file {path} cannot be read ({exc}); fix its permissions or "
                "remove it to start with an empty ACME state."
            ) from exc
        try:
            raw = json.loads(raw_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AcmeStateError(
                f"ACME state file {path} is corrupt (invalid JSON: {exc}). Remove it to "
                "start with an empty ACME state; certificates already installed under "
                "/data/public-tls keep serving, and lego's account under /data/acme/lego "
                "is reused."
            ) from exc
        if isinstance(raw, dict) and raw.get("version") != STATE_VERSION:
            raise AcmeStateError(
                f"ACME state file {path} has unknown version {raw.get('version')!r} "
                f"(this gwops understands {STATE_VERSION}); refusing to guess its meaning."
            )
        try:
            return AcmeStateDocument.model_validate(raw)
        except ValidationError as exc:
            raise AcmeStateError(
                f"ACME state file {path} does not match the expected shape: "
                f"{exc.error_count()} problem(s), first at "
                f"{'.'.join(str(p) for p in exc.errors()[0]['loc'])}: {exc.errors()[0]['msg']}. "
                "Restore it or remove it to start with an empty ACME state."
            ) from exc

    def _write(self, doc: AcmeStateDocument) -> None:
        """Atomically write `doc`: tmp file (exact mode), fsync, rename, fsync the directory.

        Memory adopts `doc` right after the rename, so it never lags the file; a failed
        directory fsync (durability only) is logged once and does not raise.
        """
        self._ensure_dir()
        payload = (doc.model_dump_json(indent=2) + "\n").encode("utf-8")
        tmp_path = self._path.with_name(self._path.name + ".tmp")
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_path, FILE_MODE)  # exact bits regardless of umask (POSIX)
            os.replace(tmp_path, self._path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
        self._doc = doc
        try:
            _fsync_dir(self._dir)
        except OSError as exc:
            self._warn_once(
                "fsync_dir",
                "acme.state.fsync_dir_failed",
                directory=os.fspath(self._dir),
                error=str(exc),
            )

    def _warn_once(self, key: str, event: str, **fields: str) -> None:
        """Log `event` at WARNING the first time `key` is seen by this store."""
        if key not in self._warned:
            self._warned.add(key)
            logger.warning(event, **fields)

    def _ensure_dir(self) -> None:
        """Create the ACME directory and set it to ``0700``; the chmod is a no-op off POSIX.

        A chmod failure is logged once per store, not on every write.
        """
        self._dir.mkdir(parents=True, exist_ok=True)
        if os.name != "posix":
            return
        try:
            os.chmod(self._dir, DIR_MODE)
        except OSError as exc:
            self._warn_once(
                "chmod_dir",
                "acme.state.chmod_dir_failed",
                directory=os.fspath(self._dir),
                error=str(exc),
            )
