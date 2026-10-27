"""Python-owned PKI: X.509 + SSH CA lifecycle, TLS leaf minting, staged CA rotation.

`CertManager` owns a `pki_dir` on disk laid out as::

    pki/
      x509-ca.crt, x509-ca.key      # current X.509 CA (cert, EC P-256 key)
      ssh-ca.key, ssh-ca.key.pub    # current SSH CA (ed25519 key, OpenSSH pubkey)
      leaf/                         # atomic store directory (`gwops.certs.store`) for the
                                     # current TLS leaf; stable paths leaf/fullchain.pem
                                     # (leaf + CA) and leaf/privkey.pem resolve through a
                                     # `..data` symlink to one whole generation, so the
                                     # gateway always reads a matching pair
      staged/                       # a newly generated X.509 CA awaiting promotion,
                                     # plus a `.rotation-stamp` marker while a crash-safe
                                     # promotion is in flight (see `_promote_staged_ca`)
      archive/                      # X.509 CAs displaced by a completed rotation

CA key material is written 0600, atomically (tmp file + rename); the leaf pair is
installed through the store (key 0600, cert 0644, one atomic swap). Never overwrites
existing CA/leaf material outside the explicit rotation flow. Leaf minting happens here,
outside the gateway binary. Serving a CA certificate as the leaf fails with
`TLS handshake EOF`; :func:`gwops.certs.validate.validate_leaf` catches that loudly.
"""

import ipaddress
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from gwops.certs.store import MaterialStore
from gwops.certs.validate import (
    ProblemCategory,
    classify_san,
    evaluate_leaf,
    load_first_certificate,
    validate_x509_ca_material,
)

logger = structlog.get_logger(__name__)

_X509_CA_VALIDITY_DAYS = 3650
_LEAF_VALIDITY_DAYS = 90
_NOT_BEFORE_BACKDATE = timedelta(minutes=5)
_SSH_CA_COMMENT = "twingate-ssh-ca"
_KEY_MODE = 0o600
_PUBLIC_MODE = 0o644
_ROTATION_MARKER_NAME = ".rotation-stamp"
_LEAF_STORE_NAME = "leaf"


@dataclass(frozen=True)
class CAInfo:
    """An X.509 CA's on-disk location and certificate PEM.

    `pem` is the exact shape :func:`gwops.tgapi.ops.create_x509_ca` accepts as
    `certificate_pem`.
    """

    cert_path: Path
    key_path: Path
    pem: str


@dataclass(frozen=True)
class SSHCAInfo:
    """An SSH CA's on-disk key location and OpenSSH public key line.

    `public_key_openssh` is the exact shape :func:`gwops.tgapi.ops.create_ssh_ca`
    accepts as `public_key`.
    """

    key_path: Path
    public_key_openssh: str


@dataclass(frozen=True)
class LeafPaths:
    """Where the current TLS leaf's certificate (fullchain) and key live.

    ``reload_pending`` is True when the previous generation could not be deleted: the new
    pair is installed but the gateway has not reloaded it.
    """

    cert_path: Path
    key_path: Path
    reload_pending: bool = False


class LeafState(StrEnum):
    """Coarse health of the current TLS leaf, as reported by `CertManager.leaf_status`."""

    OK = "ok"
    MISSING = "missing"
    EXPIRING = "expiring"
    SANS_INCOMPLETE = "sans_incomplete"
    SANS_EXTRA = "sans_extra"
    INVALID = "invalid"


@dataclass
class LeafStatus:
    """The result of `CertManager.leaf_status`: state, actionable problems, expiry."""

    state: LeafState
    problems: list[str] = field(default_factory=list)
    not_after: datetime | None = None


def _atomic_write(path: Path, data: bytes, *, mode: int) -> None:
    """Write `data` to `path` atomically (tmp file + rename) with the exact `mode`.

    `os.open`'s mode is subject to umask, so `os.chmod` is applied to the tmp file
    before the rename to guarantee the exact bits on POSIX. On Windows, `os.chmod`
    can only toggle the read-only bit.

    The write is fsync'd before the rename, and on POSIX the parent directory is
    fsync'd after it, so a completed rotation survives a crash. `chmod` and `replace`
    run inside the failure guard: if either raises, the `.tmp` (which may hold an
    unencrypted private key) is unlinked rather than left on disk.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    # fsync the parent directory so the rename itself is durable. Opening a directory
    # fd is not supported on Windows, so this is POSIX-only; the rename is already
    # atomic there regardless.
    if os.name != "nt":
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def _generate_x509_ca_material() -> tuple[bytes, bytes]:
    """Generate a fresh EC P-256 self-signed CA. Returns (key_pem, cert_pem)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Twingate Gateway TLS CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _NOT_BEFORE_BACKDATE)
        .not_valid_after(now + timedelta(days=_X509_CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem


def _load_ec_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError(f"{path} does not contain an EC private key; the X.509 CA key must be EC.")
    return key


class CertManager:
    """Owns the on-disk PKI under `pki_dir`: CA lifecycle, leaf minting, rotation."""

    def __init__(self, pki_dir: Path) -> None:
        """Bind to `pki_dir`, creating it (and nothing inside it) if absent."""
        self._pki_dir = pki_dir
        self._pki_dir.mkdir(parents=True, exist_ok=True)
        self._staged_dir = pki_dir / "staged"
        self._archive_dir = pki_dir / "archive"
        self._default_x509_ca_cert_path = pki_dir / "x509-ca.crt"
        self._default_x509_ca_key_path = pki_dir / "x509-ca.key"
        self._ssh_ca_key_path = pki_dir / "ssh-ca.key"
        self._store = MaterialStore(pki_dir)
        self._leaf_cert_path, self._leaf_key_path = self._store.stable_paths(_LEAF_STORE_NAME)
        # Pre-store layout (two plain files at the PKI root); never read. Kept while a gateway
        # config on disk (live or `.last-good`) still names them, then removed by the
        # reconciler's garbage collection.
        self._legacy_leaf_paths = (pki_dir / "leaf.crt", pki_dir / "leaf.key")
        # The CA location `mint_leaf` signs against. Starts at the canonical pki_dir
        # paths and is updated by `ensure_x509_ca` (to whatever it resolved, including
        # a caller-supplied bring-your-own path) and reset to canonical by
        # `complete_x509_rotation` (a rotated CA always ends up under pki_dir).
        self._active_x509_ca_cert_path = self._default_x509_ca_cert_path
        self._active_x509_ca_key_path = self._default_x509_ca_key_path

    # --- X.509 CA ------------------------------------------------------------------

    def ensure_x509_ca(
        self, generate: bool, cert_path: Path | None = None, key_path: Path | None = None
    ) -> CAInfo:
        """Load the X.509 CA at `cert_path`/`key_path` (default: `pki_dir`), or generate one.

        Never overwrites existing CA material. If both files are already present they
        are loaded as-is regardless of `generate`, but only after
        :func:`gwops.certs.validate.validate_x509_ca_material` confirms they are usable —
        a non-CA cert, an expired/not-yet-valid cert, a non-EC key, or a key that does
        not match the cert raises `ValueError` here (fail loud at load) rather than
        exploding later in `mint_leaf` or at TLS time. This applies to both
        bring-your-own paths and pre-existing generated material at the default location.
        If only one of the pair is present, raises `RuntimeError` — that is a corrupted
        PKI directory, not a fresh one. If neither is present and `generate` is false,
        raises `FileNotFoundError`. Whichever location this call resolves to (default, or
        a caller-supplied bring-your-own path) becomes the CA `mint_leaf` signs against
        until the next `ensure_x509_ca` or `complete_x509_rotation` call.
        """
        effective_cert_path = cert_path or self._default_x509_ca_cert_path
        effective_key_path = key_path or self._default_x509_ca_key_path

        cert_exists = effective_cert_path.is_file()
        key_exists = effective_key_path.is_file()
        if cert_exists and key_exists:
            problems = validate_x509_ca_material(effective_cert_path, effective_key_path)
            if problems:
                raise ValueError(
                    f"X.509 CA material at {effective_cert_path} / {effective_key_path} is "
                    f"unusable: {' '.join(problems)}"
                )
            pem = effective_cert_path.read_text(encoding="ascii")
            logger.info("x509_ca.loaded", cert_path=str(effective_cert_path))
            self._active_x509_ca_cert_path = effective_cert_path
            self._active_x509_ca_key_path = effective_key_path
            return CAInfo(cert_path=effective_cert_path, key_path=effective_key_path, pem=pem)
        if cert_exists != key_exists:
            raise RuntimeError(
                f"X.509 CA is incomplete: exactly one of {effective_cert_path} / "
                f"{effective_key_path} exists. Restore the missing file or remove the "
                "other before continuing."
            )
        if not generate:
            raise FileNotFoundError(
                f"X.509 CA not found at {effective_cert_path} / {effective_key_path} and "
                "generate=false; provide existing CA material or enable generation."
            )

        key_pem, cert_pem = _generate_x509_ca_material()
        _atomic_write(effective_key_path, key_pem, mode=_KEY_MODE)
        _atomic_write(effective_cert_path, cert_pem, mode=_PUBLIC_MODE)
        logger.info("x509_ca.generated", cert_path=str(effective_cert_path))
        self._active_x509_ca_cert_path = effective_cert_path
        self._active_x509_ca_key_path = effective_key_path
        return CAInfo(
            cert_path=effective_cert_path,
            key_path=effective_key_path,
            pem=cert_pem.decode("ascii"),
        )

    # --- SSH CA ----------------------------------------------------------------------

    def ensure_ssh_ca(self, generate: bool, key_path: Path | None = None) -> SSHCAInfo:
        """Load the SSH CA at `key_path` (default: `pki_dir/ssh-ca.key`), or generate one.

        Never overwrites existing CA material. Raises `RuntimeError` if only the
        private or only the public half is present, and `FileNotFoundError` if
        neither is present and `generate` is false.
        """
        effective_key_path = key_path or self._ssh_ca_key_path
        pub_path = effective_key_path.with_name(effective_key_path.name + ".pub")

        key_exists = effective_key_path.is_file()
        pub_exists = pub_path.is_file()
        if key_exists and pub_exists:
            public_key_openssh = pub_path.read_text(encoding="ascii").strip()
            logger.info("ssh_ca.loaded", ssh_ca_path=str(effective_key_path))
            return SSHCAInfo(key_path=effective_key_path, public_key_openssh=public_key_openssh)
        if key_exists != pub_exists:
            raise RuntimeError(
                f"SSH CA is incomplete: exactly one of {effective_key_path} / {pub_path} "
                "exists. Restore the missing file or remove the other before continuing."
            )
        if not generate:
            raise FileNotFoundError(
                f"SSH CA not found at {effective_key_path} and generate=false; provide an "
                "existing CA key or enable generation."
            )

        private_key = ed25519.Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_line = (
            private_key.public_key()
            .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
            .decode("ascii")
            + f" {_SSH_CA_COMMENT}"
        )
        _atomic_write(effective_key_path, private_bytes, mode=_KEY_MODE)
        _atomic_write(pub_path, (public_line + "\n").encode("ascii"), mode=_PUBLIC_MODE)
        logger.info("ssh_ca.generated", ssh_ca_path=str(effective_key_path))
        return SSHCAInfo(key_path=effective_key_path, public_key_openssh=public_line)

    def x509_ca_not_after(self) -> datetime | None:
        """`not_valid_after` of the active X.509 CA certificate, or None.

        Read-only introspection for the admin API's ``/status``: returns None when the CA
        is absent or unparseable instead of raising, so a monitoring endpoint can never be
        taken down by bad PKI material.
        """
        if not self._active_x509_ca_cert_path.is_file():
            return None
        try:
            return load_first_certificate(self._active_x509_ca_cert_path).not_valid_after_utc
        except ValueError:
            return None

    # --- leaf --------------------------------------------------------------------------

    def leaf_sans(self) -> set[str] | None:
        """Lowercase DNS and IP SAN names of the current leaf; None when it is unreadable."""
        try:
            san = load_first_certificate(self._leaf_cert_path).extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
        except x509.ExtensionNotFound:
            return set()
        except ValueError as exc:
            logger.warning(
                "certs.leaf_sans_unreadable", error_type=type(exc.__cause__ or exc).__name__
            )
            return None
        names = {name.lower() for name in san.value.get_values_for_type(x509.DNSName)}
        names |= {str(ip) for ip in san.value.get_values_for_type(x509.IPAddress)}
        return names

    def mint_leaf(self, sans: set[str]) -> LeafPaths:
        """Mint a new EC P-256 TLS leaf signed by the current X.509 CA, covering `sans`.

        Installs the fullchain (leaf + CA, 0644) and the key (0600) through the atomic
        store as one generation, so the gateway's reloader never sees a mismatched pair.
        The returned paths are the store's stable paths. The pre-store `leaf.crt` /
        `leaf.key` at the PKI root are left in place (a `.last-good` config may still name
        them); the reconciler removes them once no config references them.
        Always uses whichever CA `ensure_x509_ca` most recently resolved to (the
        top-level `pki_dir` paths by default) — i.e. the CA in effect before
        `complete_x509_rotation()` promotes a staged one.
        Raises `ValueError` if `sans` is empty and `FileNotFoundError` if no X.509 CA
        has been established yet (call `ensure_x509_ca` first).
        """
        if not sans:
            raise ValueError("mint_leaf: sans is empty; the leaf must carry at least one SAN.")
        ca_cert_present = self._active_x509_ca_cert_path.is_file()
        ca_key_present = self._active_x509_ca_key_path.is_file()
        if not (ca_cert_present and ca_key_present):
            raise FileNotFoundError(
                f"mint_leaf: no X.509 CA at {self._active_x509_ca_cert_path}; "
                "call ensure_x509_ca() first."
            )

        ca_cert = load_first_certificate(self._active_x509_ca_cert_path)
        ca_key = _load_ec_private_key(self._active_x509_ca_key_path)

        general_names: list[x509.GeneralName] = []
        for value in sorted(sans):
            classified = classify_san(value)
            if isinstance(classified, ipaddress.IPv4Address):
                general_names.append(x509.IPAddress(classified))
            else:
                general_names.append(x509.DNSName(classified))

        leaf_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gateway")]))
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _NOT_BEFORE_BACKDATE)
            .not_valid_after(now + timedelta(days=_LEAF_VALIDITY_DAYS))
            .add_extension(x509.SubjectAlternativeName(general_names), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

        key_pem = leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        fullchain_pem = leaf_cert.public_bytes(
            serialization.Encoding.PEM
        ) + ca_cert.public_bytes(serialization.Encoding.PEM)

        installed = self._store.install(_LEAF_STORE_NAME, fullchain_pem, key_pem)
        logger.info(
            "leaf.minted",
            sans=sorted(sans),
            not_after=leaf_cert.not_valid_after_utc.isoformat(),
        )
        return LeafPaths(
            cert_path=self._leaf_cert_path,
            key_path=self._leaf_key_path,
            reload_pending=installed.reload_pending,
        )

    @property
    def legacy_leaf_paths(self) -> tuple[Path, Path]:
        """The pre-store ``leaf.crt`` / ``leaf.key`` at the PKI root (never read).

        A config written before the store existed may still name them, so the caller removes
        them only once neither the live config nor its ``.last-good`` references them.
        """
        return self._legacy_leaf_paths

    def collect_leaf_generations(self) -> list[str]:
        """Remove stale leaf generations and temporaries; return the removed generation ids.

        The gateway reloads the leaf only when the previous generation's files are unlinked,
        so the reconciler calls this every pass to retry a delete that failed at mint time.

        Raises:
            StoreError: A filesystem operation failed; the gateway has not reloaded.
        """
        return self._store.gc(_LEAF_STORE_NAME)

    def leaf_status(self, required_sans: set[str], min_days: int = 14) -> LeafStatus:
        """Report the leaf's health.

        One of OK / MISSING / EXPIRING / SANS_INCOMPLETE / SANS_EXTRA / INVALID.

        `SANS_INCOMPLETE` fires when the only problems found are missing required
        SANs; any other problem (expired, missing serverAuth EKU, CA:TRUE,
        broken chain, unparseable file, or a bundled CA that is not the active X.509
        CA) makes the whole certificate `INVALID`, even if some SANs are also missing.
        `SANS_EXTRA` fires for an otherwise-valid leaf whose SANs strictly contain the
        required set (a name was removed, so the leaf must be re-minted to shed it).
        `EXPIRING` only fires for an otherwise-healthy certificate whose `not_after`
        falls within `min_days` of now. Precedence: INVALID, SANS_INCOMPLETE,
        SANS_EXTRA, EXPIRING, OK.
        """
        if not self._leaf_cert_path.is_file():
            return LeafStatus(
                state=LeafState.MISSING,
                problems=[
                    f"no leaf certificate found at {self._leaf_cert_path}; call mint_leaf() "
                    "to create one."
                ],
                not_after=None,
            )

        try:
            active_ca: x509.Certificate | None = load_first_certificate(
                self._active_x509_ca_cert_path
            )
        except ValueError as exc:
            logger.warning(
                "certs.active_ca_unreadable", error_type=type(exc.__cause__ or exc).__name__
            )
            active_ca = None
        problems = evaluate_leaf(self._leaf_cert_path, required_sans, ca_cert=active_ca)
        try:
            not_after = load_first_certificate(self._leaf_cert_path).not_valid_after_utc
        except ValueError:
            not_after = None

        if problems:
            state = (
                LeafState.SANS_INCOMPLETE
                if all(p.category == ProblemCategory.SAN for p in problems)
                else LeafState.INVALID
            )
            return LeafStatus(
                state=state, problems=[p.message for p in problems], not_after=not_after
            )

        present = self.leaf_sans()
        wanted = {str(classify_san(value)).lower() for value in required_sans}
        if present is not None and present > wanted:
            extra = sorted(present - wanted)
            return LeafStatus(
                state=LeafState.SANS_EXTRA,
                problems=[
                    f"leaf certificate carries SAN(s) no longer required: {', '.join(extra)}; "
                    "re-mint the leaf to shed them."
                ],
                not_after=not_after,
            )

        if not_after is not None:
            days_left = (not_after - datetime.now(UTC)).days
            if days_left < min_days:
                return LeafStatus(
                    state=LeafState.EXPIRING,
                    problems=[
                        f"leaf certificate expires in {days_left} day(s) (on "
                        f"{not_after.isoformat()}), below the {min_days}-day renewal "
                        "threshold; rotate the leaf soon."
                    ],
                    not_after=not_after,
                )

        return LeafStatus(state=LeafState.OK, problems=[], not_after=not_after)

    # --- X.509 CA rotation -------------------------------------------------------------

    def stage_x509_rotation(self) -> CAInfo:
        """Generate a new X.509 CA into `staged/`, leaving the current CA untouched.

        Idempotent: if a staged CA already exists, it is returned as-is rather than
        regenerated, so retrying a partially-completed rotation does not churn keys.
        Call `complete_x509_rotation()` to promote it once it has been registered
        with the Twingate API and the gateway rebound to it.
        """
        staged_cert_path = self._staged_dir / "x509-ca.crt"
        staged_key_path = self._staged_dir / "x509-ca.key"
        if staged_cert_path.is_file() and staged_key_path.is_file():
            logger.info("x509_ca.stage_rotation.already_staged", cert_path=str(staged_cert_path))
            return CAInfo(
                cert_path=staged_cert_path,
                key_path=staged_key_path,
                pem=staged_cert_path.read_text(encoding="ascii"),
            )

        # A fresh rotation gets a fresh promotion marker; drop any stale one left behind
        # by a prior rotation so completion picks a new archive stamp rather than reusing
        # the previous rotation's.
        (self._staged_dir / _ROTATION_MARKER_NAME).unlink(missing_ok=True)
        key_pem, cert_pem = _generate_x509_ca_material()
        _atomic_write(staged_key_path, key_pem, mode=_KEY_MODE)
        _atomic_write(staged_cert_path, cert_pem, mode=_PUBLIC_MODE)
        logger.info("x509_ca.staged", cert_path=str(staged_cert_path))
        return CAInfo(
            cert_path=staged_cert_path, key_path=staged_key_path, pem=cert_pem.decode("ascii")
        )

    def complete_x509_rotation(self) -> None:
        """Archive the current X.509 CA and promote the staged one in its place.

        Idempotent: if there is no staged CA (rotation already completed, or never
        started), this is a no-op. After this returns, `mint_leaf()` signs against
        the newly promoted CA. Delegates to the crash-safe promotion core so that a
        crash at any point leaves a state :meth:`recover_x509_rotation` can finish.
        """
        self._promote_staged_ca()

    def recover_x509_rotation(self) -> None:
        """Finish an X.509 rotation interrupted mid-completion; a no-op otherwise.

        The startup entrypoint, safe to call on every boot.
        It does NOT promote merely because staged material exists: rotation
        is a deliberate two-phase operator flow (stage -> register the staged CA with
        the Twingate controller -> complete), and that window can be long. A boot inside
        it, with a valid default CA still in place, is *clean* state — force-promoting
        then would publish a CA the controller has not yet been told to trust, causing a
        TLS outage.

        Recovery therefore runs the crash-safe promotion only when a completion was
        actually interrupted, which the `.rotation-stamp` marker discriminates exactly:
        `stage_x509_rotation` clears it, and `_promote_staged_ca` writes it before
        touching the default location, so the marker exists iff `complete_x509_rotation`
        started and did not finish. A crash *before* the marker was written left nothing
        promoted or archived, so no-op is correct there too (the operator re-runs
        `complete_x509_rotation`). A missing/partial default with staged material present
        also triggers recovery, as a repair path.
        """
        staged_cert_path = self._staged_dir / "x509-ca.crt"
        staged_key_path = self._staged_dir / "x509-ca.key"
        marker_path = self._staged_dir / _ROTATION_MARKER_NAME
        if not (staged_cert_path.is_file() and staged_key_path.is_file()):
            marker_path.unlink(missing_ok=True)  # drop any marker orphaned after cleanup
            logger.info("x509_ca.recover.nothing_staged")
            return

        default_complete = (
            self._default_x509_ca_cert_path.is_file()
            and self._default_x509_ca_key_path.is_file()
        )
        if not marker_path.is_file() and default_complete:
            # Deliberate pending rotation (staged, awaiting operator complete): leave it.
            logger.info("x509_ca.recover.pending_staging_noop")
            return

        self._promote_staged_ca()

    def _promote_staged_ca(self) -> None:
        """Crash-safe core shared by `complete_x509_rotation` and `recover_x509_rotation`.

        Promotes `staged/x509-ca.{crt,key}` to the default location, archiving the
        displaced CA under `archive/x509-ca-<stamp>.{crt,key}` first.

        Ordering invariant (recoverable after a crash at any single step):

        1. **Marker first.** A `staged/.rotation-stamp` file records the archive stamp
           before any default-location file is touched. The old CA is only ever copied
           to `archive/` while the marker's archive files do **not** yet exist, so the
           archive is read from a CA the promotion has not begun to overwrite.
        2. **Archive by copy, then promote by atomic write, then delete staged.** The
           staged material is the durable source of truth and is removed only after the
           default location holds the new CA in full. Any crash therefore leaves either
           (a) staged present + marker/archive/default in some partial state, which a
           re-run completes idempotently — archiving is skipped once the stamped archive
           pair exists, and promotion simply rewrites identical bytes — or (b) staged
           gone, meaning promotion already finished.

        Because promotion only runs once the marker exists and archiving only runs while
        the stamped archive pair is absent, a crash mid-promote (default cert and key
        momentarily disagreeing) never causes the half-written default to be archived.
        A caller-supplied bring-your-own CA at a non-default path is never archived here;
        only the default-location CA participates.
        """
        staged_cert_path = self._staged_dir / "x509-ca.crt"
        staged_key_path = self._staged_dir / "x509-ca.key"
        marker_path = self._staged_dir / _ROTATION_MARKER_NAME
        if not (staged_cert_path.is_file() and staged_key_path.is_file()):
            marker_path.unlink(missing_ok=True)  # drop any marker orphaned after cleanup
            logger.info("x509_ca.promote.nothing_staged")
            return

        staged_cert_bytes = staged_cert_path.read_bytes()
        staged_key_bytes = staged_key_path.read_bytes()

        # Step 1: fix the archive stamp before touching the default location, reusing a
        # prior run's stamp so recovery archives under stable, overwrite-safe filenames.
        if marker_path.is_file():
            stamp = marker_path.read_text(encoding="ascii").strip()
        else:
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            _atomic_write(marker_path, stamp.encode("ascii"), mode=_PUBLIC_MODE)

        # Step 2a: archive the displaced CA, exactly once. Skipped once the stamped pair
        # exists (so a crash mid-promote can never archive the half-written default) and
        # when the default already equals the staged CA (promotion already happened).
        archived_cert_path = self._archive_dir / f"x509-ca-{stamp}.crt"
        archived_key_path = self._archive_dir / f"x509-ca-{stamp}.key"
        archive_pair_exists = archived_cert_path.is_file() and archived_key_path.is_file()
        default_complete = (
            self._default_x509_ca_cert_path.is_file()
            and self._default_x509_ca_key_path.is_file()
        )
        if not archive_pair_exists and default_complete:
            default_cert_bytes = self._default_x509_ca_cert_path.read_bytes()
            if default_cert_bytes != staged_cert_bytes:
                _atomic_write(
                    archived_cert_path, default_cert_bytes, mode=_PUBLIC_MODE
                )
                _atomic_write(
                    archived_key_path,
                    self._default_x509_ca_key_path.read_bytes(),
                    mode=_KEY_MODE,
                )
                logger.info("x509_ca.archived", stamp=stamp)

        # Step 2b: promote (atomic per file, idempotent on rerun — identical bytes).
        _atomic_write(self._default_x509_ca_key_path, staged_key_bytes, mode=_KEY_MODE)
        _atomic_write(self._default_x509_ca_cert_path, staged_cert_bytes, mode=_PUBLIC_MODE)

        # Step 3: the default location now holds the new CA in full; retire staged state.
        staged_cert_path.unlink(missing_ok=True)
        staged_key_path.unlink(missing_ok=True)
        marker_path.unlink(missing_ok=True)

        # A rotated CA always ends up canonical, even if the previously active CA was
        # a caller-supplied bring-your-own path (that file, if distinct, is left in
        # place — only the pki_dir-owned rotation state is managed here).
        self._active_x509_ca_cert_path = self._default_x509_ca_cert_path
        self._active_x509_ca_key_path = self._default_x509_ca_key_path
        logger.info("x509_ca.rotation_completed", cert_path=str(self._default_x509_ca_cert_path))
