"""Shared helpers for the atomic material store tests.

Contract these helpers assume (``gwops.certs.store``):

* ``MaterialStore(root)`` performs no I/O in the constructor.
* One directory per certificate name under ``root``; the gwops leaf is ``root/"leaf"``
  with ``root`` = the PKI directory, so its stable paths are
  ``<pki_dir>/leaf/fullchain.pem`` and ``<pki_dir>/leaf/privkey.pem``.
* A generation id is ``sha256(cert_pem + b"\\0" + key_pem).hexdigest()[:12]``; the
  generation directory is ``..<id>``.
* ``install`` swaps through ``os.symlink`` (temporary link) and ``os.replace`` (onto
  ``..data``), writes generation files through ``os.open`` and ``os.fsync``, and deletes
  through ``os.unlink`` / ``os.rmdir`` / ``shutil.rmtree``. The fault-injection probe below
  patches those module attributes, so the store must call them as ``os.<name>``.

``PlainFileStore`` is the Windows stand-in: same interface, plain files, no
symlinks, no atomicity. It lets the modules that mint a leaf run on a host that cannot
create symlinks.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

LEAF_NAME = "leaf"
CERT_FILE = "fullchain.pem"
KEY_FILE = "privkey.pem"


# --- paths and ids --------------------------------------------------------------------


def leaf_dir(pki_dir: Path) -> Path:
    """The leaf's store directory: ``<pki_dir>/leaf``."""
    return pki_dir / LEAF_NAME


def leaf_cert_path(pki_dir: Path) -> Path:
    """The leaf's stable certificate path (what the rendered config references)."""
    return leaf_dir(pki_dir) / CERT_FILE


def leaf_key_path(pki_dir: Path) -> Path:
    """The leaf's stable private-key path."""
    return leaf_dir(pki_dir) / KEY_FILE


def generation_id(cert_pem: bytes, key_pem: bytes) -> str:
    """The contract's generation id: first 12 hex of SHA-256 over cert, NUL, key."""
    return hashlib.sha256(cert_pem + b"\0" + key_pem).hexdigest()[:12]


# --- real key material ----------------------------------------------------------------


@dataclass(frozen=True)
class Pair:
    """A certificate PEM and the unencrypted PKCS#8 PEM key that belongs to it."""

    cert_pem: bytes
    key_pem: bytes

    @property
    def generation(self) -> str:
        """The generation id the store must assign to this pair."""
        return generation_id(self.cert_pem, self.key_pem)

    def key_body_lines(self) -> list[str]:
        """The base64 lines of the key PEM, for 'no key material in output' assertions."""
        return [
            line
            for line in self.key_pem.decode("ascii").splitlines()
            if line and not line.startswith("-----")
        ]


def make_pair(common_name: str = "gateway") -> Pair:
    """A fresh self-signed EC P-256 certificate and its key (a real, matching pair)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return Pair(
        cert_pem=cert.public_bytes(serialization.Encoding.PEM),
        key_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def pair_matches(cert_pem: bytes, key_pem: bytes) -> bool:
    """True when the private key belongs to the first certificate in `cert_pem`."""
    cert = x509.load_pem_x509_certificates(cert_pem)[0]
    key = serialization.load_pem_private_key(key_pem, password=None)
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    der = serialization.Encoding.DER
    return cert.public_key().public_bytes(der, spki) == key.public_key().public_bytes(der, spki)


def read_pair(cert_path: Path, key_path: Path) -> tuple[bytes, bytes]:
    """Read both files through the given (stable) paths."""
    return cert_path.read_bytes(), key_path.read_bytes()


def write_leaf(pki_dir: Path, cert_pem: bytes, key_pem: bytes) -> None:
    """Install a leaf for a test through the platform's store class (real, or the fake)."""
    store: Any
    if os.name == "nt":
        store = PlainFileStore(pki_dir)
    else:
        from gwops.certs.store import MaterialStore

        store = MaterialStore(pki_dir)
    store.install(LEAF_NAME, cert_pem, key_pem)


# --- the Windows stand-in --------------------------------------------------------------


@dataclass(frozen=True)
class FakeInstallResult:
    """Duck-typed twin of ``gwops.certs.store.InstallResult`` (attributes only)."""

    generation: str
    changed: bool
    previous: str | None = None
    reload_pending: bool = False


class PlainFileStore:
    """Same interface as ``MaterialStore``, plain files, no symlinks (Windows only).

    ``CertManager`` may use only ``install``, ``stable_paths`` and ``gc`` of the store.
    """

    def __init__(self, root: Path) -> None:
        self._root = root

    def stable_paths(self, name: str) -> tuple[Path, Path]:
        """``(<root>/<name>/fullchain.pem, <root>/<name>/privkey.pem)``."""
        return self._root / name / CERT_FILE, self._root / name / KEY_FILE

    def install(self, name: str, cert_pem: bytes, key_pem: bytes) -> FakeInstallResult:
        """Write both files; a no-op when both already hold exactly this content."""
        cert_path, key_path = self.stable_paths(name)
        generation = generation_id(cert_pem, key_pem)
        if (
            cert_path.is_file()
            and key_path.is_file()
            and cert_path.read_bytes() == cert_pem
            and key_path.read_bytes() == key_pem
        ):
            return FakeInstallResult(generation=generation, changed=False)
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)
        return FakeInstallResult(generation=generation, changed=True)

    def read_current(self, name: str) -> tuple[bytes, bytes, str] | None:
        """``(cert, key, generation)`` of the installed pair, or None when either file is absent.

        The generation is the contract id over the bytes read (there are no real generations).
        """
        cert_path, key_path = self._root / name / CERT_FILE, self._root / name / KEY_FILE
        if not (cert_path.is_file() and key_path.is_file()):
            return None
        cert_pem, key_pem = cert_path.read_bytes(), key_path.read_bytes()
        return cert_pem, key_pem, generation_id(cert_pem, key_pem)

    def gc(self, name: str | None = None) -> list[str]:
        """Nothing to collect: there are no generations."""
        return []


# --- filesystem probe (observe or fail the calls the store makes) ----------------------

PATCHED_OS_CALLS = (
    "open",
    "fsync",
    "symlink",
    "replace",
    "rename",
    "unlink",
    "remove",
    "rmdir",
    "mkdir",
    "chmod",
    "fchmod",
)
DELETION_CALLS = ("unlink", "remove", "rmdir", "rmtree")


class SimulatedCrash(BaseException):
    """Raised by a probe hook to model the process dying at that exact point.

    A BaseException, so no ``except Exception`` cleanup in the code under test runs.
    """


@dataclass(frozen=True)
class FsCall:
    """One intercepted filesystem call."""

    name: str
    args: tuple[Any, ...]
    kwargs: dict[str, Any]

    def path_arg(self, index: int = 0) -> Path | None:
        """The positional argument at `index` as a Path, or None when absent/not a path."""
        if index < len(self.args) and isinstance(self.args[index], (str, os.PathLike)):
            return Path(os.fspath(self.args[index]))
        return None


Hook = Callable[[FsCall], None]


class FsProbe:
    """Patches ``os.<call>`` and ``shutil.rmtree`` so tests can watch or fail them.

    ``before`` / ``after`` hooks run around the real call, per thread, with re-entrancy
    suppressed (a hook that touches the filesystem does not trigger more hooks). A hook
    may raise to inject a failure. ``calls`` records every call, in order.
    """

    def __init__(self) -> None:
        self.calls: list[FsCall] = []
        self._before: list[Hook] = []
        self._after: list[Hook] = []
        self._local = threading.local()
        self._lock = threading.Lock()
        self._monkeypatch = pytest.MonkeyPatch()
        self._started = False

    def start(self) -> None:
        """Begin intercepting. Call after the test's own setup so setup is not recorded."""
        if self._started:
            return
        self._started = True
        for name in PATCHED_OS_CALLS:
            self._wrap(os, name)
        self._wrap(shutil, "rmtree")

    def before(self, hook: Hook) -> None:
        """Run `hook` before every intercepted call."""
        self._before.append(hook)

    def after(self, hook: Hook) -> None:
        """Run `hook` after every intercepted call that returned."""
        self._after.append(hook)

    def named(self, *names: str) -> list[FsCall]:
        """The recorded calls whose name is in `names`."""
        return [call for call in self.calls if call.name in names]

    def stop(self) -> None:
        """Undo this probe's patches only (hooks stay registered but nothing calls them)."""
        self._monkeypatch.undo()
        self._started = False

    def _wrap(self, module: Any, name: str) -> None:
        real = getattr(module, name)

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if getattr(self._local, "active", False):
                return real(*args, **kwargs)
            call = FsCall(name, args, dict(kwargs))
            with self._lock:
                self.calls.append(call)
            self._run(self._before, call)
            result = real(*args, **kwargs)
            self._run(self._after, call)
            return result

        self._monkeypatch.setattr(module, name, wrapper)

    def _run(self, hooks: list[Hook], call: FsCall) -> None:
        self._local.active = True
        try:
            for hook in hooks:
                hook(call)
        finally:
            self._local.active = False


def is_inside(path: Path | None, directory: Path) -> bool:
    """True when `path` is `directory` or lies beneath it (lexically, no link following)."""
    if path is None:
        return False
    absolute = Path(os.path.abspath(path))
    base = Path(os.path.abspath(directory))
    return absolute == base or base in absolute.parents


def generation_dirs(name_dir: Path) -> list[Path]:
    """Real generation directories (``..<12 hex>``) directly under a certificate directory."""
    found = []
    for entry in sorted(name_dir.iterdir()):
        suffix = entry.name[2:]
        if (
            entry.name.startswith("..")
            and len(suffix) == 12
            and all(c in "0123456789abcdef" for c in suffix)
            and entry.is_dir()
            and not entry.is_symlink()
        ):
            found.append(entry)
    return found


def stray_temporaries(name_dir: Path) -> list[Path]:
    """Leftover ``..data.tmp*`` entries under a certificate directory."""
    return sorted(name_dir.glob("..data.tmp*"))


@contextmanager
def umask(value: int) -> Iterator[None]:
    """Run a block under the given umask."""
    previous = os.umask(value)
    try:
        yield
    finally:
        os.umask(previous)
