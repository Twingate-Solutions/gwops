"""Confined-root file reads and content-addressed copies (``<stem>-<sha12><suffix>``).

Errors name the path and the allowed root; they never include file contents.
"""

import hashlib
import os
import re
import stat
from collections.abc import Collection, Iterable
from pathlib import Path

import structlog
import yaml

logger = structlog.get_logger(__name__)

MAX_FILE_BYTES = 1024 * 1024
"""Largest file :func:`read_confined` will read (1 MiB)."""

ACME_ROOT = Path("/config/acme")
"""Read-only mounted root the ACME DNS ``token_file`` must resolve under.

gwops never reads the token (lego does, through its ``_FILE`` variables); it only checks the
file exists. Shared by the seed schema and the runtime paths.
"""

_DIGEST_CHARS = 12
_STEM_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_SUFFIX_RE = re.compile(r"\.[A-Za-z0-9]+")
# `<stem>-<sha12>[.<ext>][.tmp]`; anything else in a directory is never collected.
_COPY_NAME_RE = re.compile(
    rf"[A-Za-z0-9][A-Za-z0-9._-]*-[0-9a-f]{{{_DIGEST_CHARS}}}(?:\.[A-Za-z0-9]+)?(?:\.tmp)?"
)
_TMP_SUFFIX = ".tmp"
# Missing on Windows, where the flags are no-ops; O_BINARY stops newline translation there.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)


class ConfinedFileError(Exception):
    """A confined read or a content-addressed write was refused."""


class ConfinedReadError(ConfinedFileError):
    """A path was refused by :func:`read_confined`."""

    def __init__(self, path: Path, root: Path, reason: str) -> None:
        """Record the refused `path`, the allowed `root` and the human-readable `reason`."""
        self.path = path
        self.root = root
        self.reason = reason
        super().__init__(f"{path}: {reason} (allowed root: {root})")


def read_confined(path: Path | str, root: Path, *, max_bytes: int = MAX_FILE_BYTES) -> bytes:
    """Read the regular file at `path`, which must resolve to a location under `root`.

    Symlinks and ``..`` resolve before the containment check; the read itself is bounded.

    Raises:
        ConfinedReadError: outside `root`, missing, not a regular file, too large or unreadable.
    """
    requested = Path(path)
    resolved_root = root.resolve()
    try:
        resolved = requested.resolve()
    except ValueError:  # e.g. an embedded NUL
        raise ConfinedReadError(requested, root, "is not a valid path") from None
    except (OSError, RuntimeError) as exc:  # e.g. a symlink loop
        raise ConfinedReadError(
            requested, root, f"cannot be resolved ({type(exc).__name__})"
        ) from None
    if not resolved.is_relative_to(resolved_root):
        raise ConfinedReadError(requested, root, "resolves outside the allowed root")

    try:
        before = resolved.stat()
    except FileNotFoundError:
        raise ConfinedReadError(requested, root, "file not found") from None
    except ValueError:
        raise ConfinedReadError(requested, root, "is not a valid path") from None
    except OSError as exc:
        raise ConfinedReadError(
            requested, root, f"cannot be inspected ({type(exc).__name__})"
        ) from None
    if not stat.S_ISREG(before.st_mode):
        raise ConfinedReadError(requested, root, "not a regular file")

    try:
        fd = os.open(resolved, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_BINARY)
        try:
            handle = os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise
        with handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise ConfinedReadError(requested, root, "not a regular file")
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ConfinedReadError(requested, root, "changed while it was being opened")
            if opened.st_size > max_bytes:
                raise ConfinedReadError(
                    requested, root, f"file is larger than the {max_bytes}-byte size limit"
                )
            data = handle.read(max_bytes + 1)
    except ConfinedReadError:
        raise
    except OSError as exc:
        raise ConfinedReadError(
            requested, root, f"cannot be read ({type(exc).__name__})"
        ) from None
    if len(data) > max_bytes:
        raise ConfinedReadError(
            requested, root, f"file is larger than the {max_bytes}-byte size limit"
        )
    return data


def content_digest(data: bytes) -> str:
    """The first 12 hex characters of the SHA-256 of `data` (a content address)."""
    return hashlib.sha256(data).hexdigest()[:_DIGEST_CHARS]


def content_address(dest_dir: Path, stem: str, data: bytes, *, suffix: str = "") -> Path:
    """The path ``<dest_dir>/<stem>-<sha12><suffix>`` that :func:`write_content_addressed` uses.

    Raises:
        ValueError: `stem` or `suffix` is not a safe file-name fragment.
    """
    if not _STEM_RE.fullmatch(stem):
        raise ValueError(f"unsafe file stem {stem!r}: use letters, digits, '.', '_' and '-'")
    if suffix and not _SUFFIX_RE.fullmatch(suffix):
        raise ValueError(f"unsafe file suffix {suffix!r}: expected a dot plus letters or digits")
    return dest_dir / f"{stem}-{content_digest(data)}{suffix}"


def write_content_addressed(
    dest_dir: Path, stem: str, data: bytes, *, suffix: str = "", mode: int
) -> Path:
    """Write `data` to ``<dest_dir>/<stem>-<sha12><suffix>`` atomically and return the path.

    Identical content already at the address is left alone (only its mode is corrected).

    Raises:
        ValueError: `stem` or `suffix` is not a safe file-name fragment.
        ConfinedFileError: a file with different content already occupies the address.
        OSError: the write itself failed; no temporary file is left behind.
    """
    dest = content_address(dest_dir, stem, data, suffix=suffix)
    if dest.is_file():
        if dest.read_bytes() != data:
            raise ConfinedFileError(
                f"{dest}: a file with different content already exists at this content address"
            )
        if os.name == "posix" and stat.S_IMODE(dest.stat().st_mode) != mode:
            os.chmod(dest, mode)
        return dest

    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = dest.with_name(dest.name + _TMP_SUFFIX)
    fd = _create_temporary(tmp_path, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, dest)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    return dest


def _create_temporary(tmp_path: Path, mode: int) -> int:
    """Create `tmp_path` exclusively, discarding a stale one left by a killed write."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_BINARY
    try:
        return os.open(tmp_path, flags, mode)
    except FileExistsError:
        tmp_path.unlink()  # a symlink here is removed, never followed
        return os.open(tmp_path, flags, mode)


LEGACY_CREDENTIAL_FILES: frozenset[str] = frozenset({"token", "ca.crt"})
"""File names that mark a ``<cluster>/`` directory as a legacy credential directory."""


class CleanupResult(list[Path]):
    """Removed paths; ``failures`` lists failed or skipped steps (no exception text)."""

    def __init__(self, removed: Iterable[Path] = (), failures: Iterable[str] = ()) -> None:
        """Hold `removed`; `failures` are short descriptions safe to expose."""
        super().__init__(removed)
        self.failures: list[str] = list(failures)


def _read_configs(config_files: Iterable[Path]) -> tuple[list[str], Path | None, str]:
    """Read every existing config; return ``(texts, unreadable_config, reason)``.

    A missing config is skipped. On the first one that exists but cannot be read, `texts` is
    empty and the config and reason are set.
    """
    texts: list[str] = []
    for config in config_files:
        try:
            texts.append(config.read_text(encoding="utf-8"))
        except FileNotFoundError:
            continue
        except (OSError, UnicodeDecodeError) as exc:
            return [], config, type(exc).__name__
    return texts, None, ""


def _strings(node: object) -> Iterable[str]:
    """Every string value in a parsed YAML document."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)


def _config_values(texts: Iterable[str]) -> set[str]:
    """The string values of the parsed configs (folded scalars are rejoined by the parser).

    Raises:
        yaml.YAMLError: a config is not valid YAML.
    """
    return {value for text in texts for value in _strings(yaml.safe_load(text))}


def _read_references(
    config_files: Iterable[Path], *, require_one: bool = False
) -> tuple[set[str], str | None]:
    """The values the configs name, or ``(empty, reason)`` when nothing may be removed.

    The reason never carries exception text. With `require_one`, no readable config at all
    is also a reason.
    """
    texts, unreadable, reason = _read_configs(config_files)
    if unreadable is not None:
        logger.warning("confined.config_unreadable", config=str(unreadable), reason=reason)
        return set(), f"skipped: config {unreadable.name} unreadable ({reason})"
    if require_one and not texts:
        return set(), "skipped: no config readable"
    try:
        return _config_values(texts), None
    except yaml.YAMLError as exc:
        return set(), f"skipped: a config is not parseable ({type(exc).__name__})"


def _is_referenced(path: Path, values: Collection[str], *, tree: bool = False) -> bool:
    """Whether a config value names `path` (or, with `tree`, a file under it)."""
    target = path.as_posix()
    prefix = target.rstrip("/") + "/"
    return any(value == target or (tree and value.startswith(prefix)) for value in values)


def remove_legacy_credential_dirs(
    directory: Path,
    config_files: Iterable[Path],
    legacy_files: Collection[str] = LEGACY_CREDENTIAL_FILES,
) -> CleanupResult:
    """Remove legacy ``<cluster>/{token,ca.crt}`` subdirectories of `directory`.

    A subdirectory holding anything else is kept with a warning; links are never followed.
    A subdirectory that a config file names (itself or a file in it) is kept, and if an
    existing config is unreadable or unparseable nothing is removed: an unseen reference is
    not absent. Failed removals and a skipped pass are in ``failures``.
    """
    if not directory.is_dir():
        return CleanupResult()
    values, skipped = _read_references(config_files)
    if skipped is not None:
        logger.warning("confined.legacy_cleanup_skipped", directory=str(directory), reason=skipped)
        return CleanupResult(failures=[skipped])
    removed: list[Path] = []
    failures: list[str] = []
    for child in sorted(directory.iterdir()):
        if child.is_symlink() or child.is_junction():
            logger.warning(
                "confined.legacy_dir_kept", path=str(child), reason="symbolic link or junction"
            )
            continue
        if not child.is_dir():
            continue
        if _is_referenced(child, values, tree=True):
            logger.warning(
                "confined.legacy_dir_kept", path=str(child), reason="referenced by a config"
            )
            continue
        try:
            contents = sorted(child.iterdir())
        except OSError as exc:
            logger.warning(
                "confined.legacy_dir_kept", path=str(child), reason=type(exc).__name__
            )
            continue
        unexpected = [
            entry.name
            for entry in contents
            if entry.name not in legacy_files
            or entry.is_symlink()
            or entry.is_junction()
            or not entry.is_file()
        ]
        if unexpected:
            logger.warning(
                "confined.legacy_dir_kept",
                path=str(child),
                reason="unexpected contents",
                unexpected=unexpected,
            )
            continue
        try:
            for entry in contents:
                entry.unlink()
            os.rmdir(child)
        except OSError as exc:
            logger.warning(
                "confined.legacy_dir_remove_failed", path=str(child), reason=type(exc).__name__
            )
            failures.append(f"could not remove {child.name} ({type(exc).__name__})")
            continue
        removed.append(child)
        logger.info("confined.legacy_dir_removed", path=str(child))
    return CleanupResult(removed, failures)


def collect_garbage(directory: Path, config_files: Iterable[Path]) -> CleanupResult:
    """Remove content-addressed copies in `directory` that no config file references.

    If an existing config is unreadable or unparseable, nothing is removed: an unseen
    reference is not absent. Failed removals and a skipped pass are in ``failures``.
    """
    values, skipped = _read_references(config_files, require_one=True)
    if skipped is not None:
        logger.warning("confined.gc_skipped", directory=str(directory), reason=skipped)
        return CleanupResult(failures=[skipped])
    if not directory.is_dir():
        return CleanupResult()

    removed: list[Path] = []
    failures: list[str] = []
    for candidate in sorted(directory.iterdir()):
        if not _COPY_NAME_RE.fullmatch(candidate.name) or not candidate.is_file():
            continue
        if _is_referenced(candidate, values):
            continue
        try:
            candidate.unlink()
        except OSError as exc:
            logger.warning(
                "confined.gc_remove_failed", path=str(candidate), reason=type(exc).__name__
            )
            failures.append(f"could not remove {candidate.name} ({type(exc).__name__})")
            continue
        removed.append(candidate)
        logger.info("confined.gc_removed", path=str(candidate))
    return CleanupResult(removed, failures)
