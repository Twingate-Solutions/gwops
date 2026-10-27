"""Atomic on-disk store for certificate + private-key pairs.

Layout under ``<root>/<name>/``::

    ..<sha12>/fullchain.pem (0644), privkey.pem (0600)   generation directories
    ..data -> ..<sha12>                                    relative symlink, current generation
    fullchain.pem -> ..data/fullchain.pem                  stable relative symlinks
    privkey.pem   -> ..data/privkey.pem

``<sha12>`` is the first 12 hex digits of ``sha256(cert + b"\\0" + key)``. Readers use the
stable paths only. An install writes a complete new generation, then swaps ``..data`` with a
single ``os.replace`` of a temporary symlink, so the stable paths always resolve to one whole
generation: the certificate and the key a reader sees always belong together.

The gateway binary reloads static certificates through fsnotify watches on the certificate
and key files. Renaming a symlink over ``..data`` raises no event; the reload fires when the
previous generation's files are unlinked, so :meth:`MaterialStore.install` deletes the
previous generation immediately after the swap.

Names are ``[a-z0-9-]{1,63}``. Key bytes never appear in log events or exception messages.
Symlinks are required, so this module is for POSIX hosts.
"""

import hashlib
import os
import re
import secrets
import shutil
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

CERT_FILE = "fullchain.pem"
KEY_FILE = "privkey.pem"

_NAME_PATTERN = re.compile(r"[a-z0-9-]{1,63}")
_GENERATION_PATTERN = re.compile(r"\.\.[0-9a-f]{12}")
_DATA_LINK = "..data"
_TEMP_PREFIX = "..data.tmp"
_CERT_MODE = 0o644
_KEY_MODE = 0o600
_DIR_MODE = 0o755
_MAX_READ_BYTES = 1024 * 1024


class StoreError(RuntimeError):
    """The store could not complete an operation (message carries no key material)."""


@dataclass(frozen=True)
class InstallResult:
    """Outcome of :meth:`MaterialStore.install`.

    Attributes:
        generation: The 12-hex id of the generation now current.
        changed: False when the identical pair was already current (nothing swapped).
        previous: Id of the generation this install deleted, or None.
        reload_pending: True when the previous generation could not be deleted. The gateway
            reloads only when that generation's files are unlinked, so it still serves the
            old pair until a later :meth:`MaterialStore.gc` or install removes it.
    """

    generation: str
    changed: bool
    previous: str | None = None
    reload_pending: bool = False


def _validate_name(name: str) -> None:
    if not _NAME_PATTERN.fullmatch(name):
        raise ValueError(f"invalid store name {name!r}: expected 1-63 characters of [a-z0-9-]")


def _generation_id(cert_pem: bytes, key_pem: bytes) -> str:
    return hashlib.sha256(cert_pem + b"\0" + key_pem).hexdigest()[:12]


def _current_generation(name_dir: Path) -> str | None:
    """The directory name (``..<sha12>``) ``..data`` points at, or None if not a valid link."""
    try:
        target = os.readlink(name_dir / _DATA_LINK)
    except OSError:
        return None
    return target if _GENERATION_PATTERN.fullmatch(target) else None


def _read_generation_file(path: Path) -> bytes:
    """Read one regular file of a generation without following a symlink, bounded in size."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_READ_BYTES:
            raise StoreError(f"store file {path.name!r} is not a regular file of bounded size")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            return handle.read(_MAX_READ_BYTES + 1)
    finally:
        os.close(fd)


def _remove_entry(path: Path) -> None:
    """Delete a file, symlink or directory tree without ever following a symlink."""
    if stat.S_ISDIR(os.lstat(path).st_mode):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def _write_file(path: Path, data: bytes, mode: int) -> None:
    """Create `path` exclusively (no link following), write, set exact `mode`, fsync."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        if sys.platform != "win32":
            os.fchmod(fd, mode)  # exact bits, independent of the umask
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _temp_link_path(name_dir: Path) -> Path:
    return name_dir / f"{_TEMP_PREFIX}-{secrets.token_hex(6)}"


class MaterialStore:
    """Atomic store of certificate/key pairs, one directory per name under `root`.

    The constructor performs no I/O. Installs and collections are serialised per store
    instance.
    """

    def __init__(self, root: Path) -> None:
        """Bind to `root` without touching the filesystem."""
        self._root = root
        self._lock = threading.Lock()

    def stable_paths(self, name: str) -> tuple[Path, Path]:
        """Return ``(fullchain.pem, privkey.pem)`` stable paths for `name`; pure, no I/O."""
        _validate_name(name)
        name_dir = self._root / name
        return name_dir / CERT_FILE, name_dir / KEY_FILE

    def install(self, name: str, cert_pem: bytes, key_pem: bytes) -> InstallResult:
        """Make `cert_pem` and `key_pem` the pair served at the stable paths for `name`.

        Stale temporaries and unreferenced generations are removed first. Identical content
        to what is current changes nothing (a missing stable link is recreated). Otherwise a
        new generation is written and fsynced, ``..data`` is swapped to it with one
        ``os.replace``, and the previous generation is deleted.

        Args:
            name: Store name, ``[a-z0-9-]{1,63}``.
            cert_pem: Certificate (full chain) PEM bytes, non-empty.
            key_pem: Private key PEM bytes, non-empty.

        Returns:
            The generation now current, whether anything changed, and the deleted generation.

        Raises:
            ValueError: `name` is invalid or `cert_pem` / `key_pem` is empty.
            StoreError: A filesystem operation failed; the previously current pair, if any,
                is still served.
        """
        _validate_name(name)
        if not cert_pem:
            raise ValueError("certificate PEM is empty")
        if not key_pem:
            raise ValueError("private key PEM is empty")
        generation = _generation_id(cert_pem, key_pem)
        with self._lock:
            try:
                result = self._install_locked(name, generation, cert_pem, key_pem)
            except OSError as exc:
                raise StoreError(f"cannot install material for {name!r}: {exc}") from exc
        if result.changed:
            logger.info(
                "store.installed",
                name=name,
                generation=result.generation,
                previous=result.previous,
            )
        return result

    def read_current(self, name: str) -> tuple[bytes, bytes, str] | None:
        """Read the current pair for `name` from one generation directory.

        The store lock is held while ``..data`` is resolved and both files are read, so an
        install cannot swap generations or delete the one being read in between: the
        certificate and key returned always belong together. A file that vanishes anyway is
        retried once against the then-current generation.

        Args:
            name: Store name, ``[a-z0-9-]{1,63}``.

        Returns:
            ``(cert_pem, key_pem, generation)`` with the 12-hex generation id, or None when
            nothing is installed for `name` (no valid ``..data`` link).

        Raises:
            ValueError: `name` is invalid.
            StoreError: The generation's files are missing after the retry, or not regular
                files.
            OSError: A file could not be read (for example a permission error).
        """
        _validate_name(name)
        name_dir = self._root / name
        for attempt in (1, 2):
            with self._lock:
                current = _current_generation(name_dir)
                if current is None:
                    return None
                try:
                    cert_pem = _read_generation_file(name_dir / current / CERT_FILE)
                    key_pem = _read_generation_file(name_dir / current / KEY_FILE)
                except FileNotFoundError:
                    if attempt == 2:
                        raise StoreError(
                            f"generation {current[2:]!r} of {name!r} is missing its files"
                        ) from None
                    continue
            return cert_pem, key_pem, current[2:]
        return None  # unreachable: the second attempt returns or raises

    def gc(self, name: str | None = None) -> list[str]:
        """Remove stale temporaries and unreferenced generations; return removed generation ids.

        With `name`, only that directory is swept. Without, every subdirectory of the root
        that holds a ``..data`` entry or a ``..<12 hex>`` entry is swept and nothing else is
        touched.

        Raises:
            ValueError: `name` is invalid.
            StoreError: A filesystem operation failed.
        """
        if name is not None:
            _validate_name(name)
        with self._lock:
            try:
                if name is not None:
                    return self._sweep(self._root / name)
                removed: list[str] = []
                for directory in self._store_directories():
                    removed.extend(self._sweep(directory))
                return removed
            except OSError as exc:
                raise StoreError(f"cannot collect store garbage: {exc}") from exc

    # --- internals (caller holds the lock) -----------------------------------------------

    def _store_directories(self) -> list[Path]:
        try:
            with os.scandir(self._root) as entries:
                candidates = sorted(e.name for e in entries if e.is_dir(follow_symlinks=False))
        except FileNotFoundError:
            return []
        found: list[Path] = []
        for candidate in candidates:
            directory = self._root / candidate
            try:
                listing = os.listdir(directory)
            except OSError:
                continue
            if any(n == _DATA_LINK or _GENERATION_PATTERN.fullmatch(n) for n in listing):
                found.append(directory)
        return found

    def _sweep(self, name_dir: Path) -> list[str]:
        """Remove ``..data.tmp*`` entries and unreferenced generations; return their ids."""
        try:
            entries = sorted(os.listdir(name_dir))
        except (FileNotFoundError, NotADirectoryError):
            return []
        current = _current_generation(name_dir)
        removed: list[str] = []
        for entry in entries:
            if entry.startswith(_TEMP_PREFIX):
                _remove_entry(name_dir / entry)
            elif _GENERATION_PATTERN.fullmatch(entry) and entry != current:
                _remove_entry(name_dir / entry)
                removed.append(entry[2:])
        if removed:
            logger.info("store.swept", generations=removed)
        return removed

    def _install_locked(
        self, name: str, generation: str, cert_pem: bytes, key_pem: bytes
    ) -> InstallResult:
        name_dir = self._root / name
        if not name_dir.is_dir():
            os.makedirs(name_dir, mode=_DIR_MODE, exist_ok=True)
        self._sweep(name_dir)

        generation_name = f"..{generation}"
        current = _current_generation(name_dir)

        if current is not None and self._generation_holds(name_dir / current, cert_pem, key_pem):
            self._ensure_stable_links(name_dir)
            return InstallResult(generation=current[2:], changed=False)
        if current == generation_name:
            # Same id, different bytes: the current generation was damaged on disk. The
            # repair is built as a new generation under a fresh id and swapped in like any
            # other install, so the stable paths never dangle; the damaged one is then
            # deleted as the previous generation.
            generation = secrets.token_hex(6)
            generation_name = f"..{generation}"
            logger.warning("store.generation_damaged", name=name, generation=current[2:])
        generation_dir = name_dir / generation_name

        os.mkdir(generation_dir, _DIR_MODE)
        temp_link = _temp_link_path(name_dir)
        try:
            os.chmod(generation_dir, _DIR_MODE)
            _write_file(generation_dir / CERT_FILE, cert_pem, _CERT_MODE)
            _write_file(generation_dir / KEY_FILE, key_pem, _KEY_MODE)
            _fsync_dir(generation_dir)
            self._ensure_stable_links(name_dir)
            os.symlink(generation_name, temp_link)
            os.replace(temp_link, name_dir / _DATA_LINK)
        except Exception:
            try:
                if os.path.lexists(temp_link):
                    os.unlink(temp_link)
                _remove_entry(generation_dir)
            except OSError:
                logger.warning("store.cleanup_failed", name=name, generation=generation)
            raise
        _fsync_dir(name_dir)

        previous: str | None = None
        reload_pending = False
        if current is not None:
            # Unlinking the previous generation's files is what makes the gateway's fsnotify
            # reloader pick up the new pair; renaming ..data raises no event.
            try:
                _remove_entry(name_dir / current)
                previous = current[2:]
            except OSError as exc:
                reload_pending = True
                logger.warning(
                    "store.previous_generation_not_deleted",
                    name=name,
                    generation=current[2:],
                    error=str(exc),
                )
        return InstallResult(
            generation=generation, changed=True, previous=previous, reload_pending=reload_pending
        )

    @staticmethod
    def _generation_holds(generation_dir: Path, cert_pem: bytes, key_pem: bytes) -> bool:
        try:
            return (generation_dir / CERT_FILE).read_bytes() == cert_pem and (
                generation_dir / KEY_FILE
            ).read_bytes() == key_pem
        except OSError:
            return False

    @staticmethod
    def _ensure_stable_links(name_dir: Path) -> None:
        """Create or repair ``fullchain.pem`` / ``privkey.pem`` as links through ``..data``."""
        for file_name in (CERT_FILE, KEY_FILE):
            link = name_dir / file_name
            target = f"{_DATA_LINK}/{file_name}"
            try:
                existing: str | None = os.readlink(link)
            except FileNotFoundError:
                os.symlink(target, link)
                continue
            except OSError:  # present but not a symlink
                existing = None
            if existing != target:
                temp_link = _temp_link_path(name_dir)
                os.symlink(target, temp_link)
                os.replace(temp_link, link)
