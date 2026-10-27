"""Metadata-only checks of the ACME DNS token file; gwops never reads the token."""

import os
import stat
from dataclasses import dataclass

from gwops.configmodel.schema import AcmeSettings
from gwops.confined import ACME_ROOT

__all__ = [
    "ResolvedToken",
    "resolve_token_file",
    "token_file_problem",
    "token_file_signature",
]


@dataclass(frozen=True)
class ResolvedToken:
    """The token file after symlink resolution.

    Attributes:
        path: The resolved path (``os.path.realpath``); the value lego should be given.
        problem: Why the file is unusable (path-only text, never contents), or ``None``.
        outside_root: The resolved path is not under ``/config/acme``; never hand it to lego.
    """

    path: str
    problem: str | None
    outside_root: bool = False


def resolve_token_file(settings: AcmeSettings) -> ResolvedToken:
    """Resolve the token file and check it by metadata only.

    The configured path is resolved with ``os.path.realpath`` and must land under the
    resolved ``/config/acme`` root, so a symlink inside the mount cannot point lego at another
    file. The resolved target must exist, be a regular file and be non-empty. The file is
    never opened: lego reads it through ``CF_DNS_API_TOKEN_FILE``.
    """
    configured = settings.token_file
    resolved = os.path.realpath(configured)
    root = os.path.realpath(ACME_ROOT)
    try:
        inside = resolved != root and os.path.commonpath([resolved, root]) == root
    except ValueError:  # different drives
        inside = False
    if not inside:
        return ResolvedToken(
            resolved,
            f"ACME DNS token file {configured} resolves to {resolved}, outside {root}; "
            "mount the token itself (not a link to elsewhere) under /config/acme/",
            outside_root=True,
        )
    try:
        info = os.stat(resolved)
    except FileNotFoundError:
        return ResolvedToken(
            resolved,
            f"ACME DNS token file {configured} does not exist; mount it read-only under "
            "/config/acme/ (issuance cannot succeed until it is present)",
        )
    except OSError as exc:
        return ResolvedToken(
            resolved, f"ACME DNS token file {configured} cannot be examined ({type(exc).__name__})"
        )
    if not stat.S_ISREG(info.st_mode):
        return ResolvedToken(resolved, f"ACME DNS token file {configured} is not a regular file")
    if info.st_size <= 0:
        return ResolvedToken(resolved, f"ACME DNS token file {configured} is empty")
    return ResolvedToken(resolved, None)


def token_file_problem(settings: AcmeSettings) -> str | None:
    """Why the DNS token file is unusable, or ``None`` when it is a non-empty regular file.

    Metadata only (see :func:`resolve_token_file`); the message names paths, never contents.
    """
    return resolve_token_file(settings).problem


def token_file_signature(settings: AcmeSettings) -> tuple[int, int, int] | None:
    """``(st_ino, st_mtime_ns, st_size)`` of the resolved token file, or ``None`` if absent.

    Used to notice that an operator replaced the token. Stat only; never opens the file.
    """
    try:
        info = os.stat(os.path.realpath(settings.token_file))
    except OSError:
        return None
    return (info.st_ino, info.st_mtime_ns, info.st_size)
