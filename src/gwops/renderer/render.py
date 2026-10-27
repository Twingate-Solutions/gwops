"""Render EffectiveState into the gateway's config.yaml.

Base sections (Twingate identity, listener ports, TLS leaf, SSH gateway identity/CA,
recording cap) always render. The gateway's own ``ssh.upstreams`` list is never emitted
because the binary ignores it; upstream targets come from the synced Twingate resources.
``kubernetes`` renders a single-cluster upstream and raises :class:`RenderError` if more
than one cluster is configured, since the gateway's ``kubernetes.upstreams`` schema
consumes a single entry.

The output follows the gateway 2.0 config schema: ``tls`` nests the leaf under
``tls.certificates.files[0]``, the SSH CA key renders at ``ssh.ca.local.privateKeyFile``,
and the recording cap renders at ``log.sessionRecording.segment.maxSize``.

The recording cap sets the gateway's session-recording segment size for SSH and Kubernetes
sessions alike: a recording is emitted as `session recording` segment lines of about that
size (or every five minutes) and a final `session finished` line. The gateway validates
``segment.maxSize`` against a ceiling of 256 KiB (262,144 bytes); :data:`_SEGMENT_MAX_SIZE`
is 256,000, just under it.
"""

import itertools
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, ClassVar

import structlog
import yaml

from gwops.access.webapp_policy import (
    MAX_TRUSTED_HEADER_SEPARATORS,
    separator_count,
    trusted_gateway_header_names,
)
from gwops.certs.store import CERT_FILE, KEY_FILE
from gwops.configmodel.schema import EffectiveState
from gwops.confined import ACME_ROOT
from gwops.renderer.capabilities import Capabilities
from gwops.settings import GwopsSettings

logger = structlog.get_logger(__name__)

K8S_SOURCE_ROOT = Path("/config/k8s-creds")
"""Confined root every Kubernetes `bearer_token_file` and `ca_file` must resolve under."""

WEBAPP_CA_ROOT = Path("/config/webapp-cas")
"""Confined root every web-app CA bundle file must resolve under."""

PUBLIC_TLS_ROOT = Path("/config/public-tls")
"""Confined root every public-mode ``cert_file`` and ``key_file`` must resolve under."""

_GATEWAY_PORT = 8443
_METRICS_PORT = 9090
_SEPARATORS = "-_"

# `log.sessionRecording.segment.maxSize` must satisfy 0 < maxSize <= 256 KiB (262_144 bytes);
# 256_000 stays under that ceiling. The reader's line cap is gwops.shipper.limits.LINE_MAX_BYTES.
_SEGMENT_MAX_SIZE = 256_000

_SSH_GATEWAY_USERNAME = "gateway"
_SSH_KEY_TYPE = "ed25519"
_SSH_HOST_CERT_TTL = "24h"
_SSH_USER_CERT_TTL = "5m"


class RenderError(Exception):
    """The effective state cannot be rendered."""


@dataclass(frozen=True)
class K8sCredentialFiles:
    """The content-addressed copies of one cluster's credentials the gateway reads."""

    token: Path
    ca: Path


@dataclass(frozen=True)
class RuntimePaths:
    """Filesystem paths the rendered gateway config references.

    Everything gwops manages (generated CA material, the minted leaf, the recording
    spool, the content-addressed credential and CA-bundle copies) lives under
    :attr:`~gwops.settings.GwopsSettings.data_dir`.

    The ``*_root`` fields are the confined source roots operators mount files under.
    :attr:`k8s_credentials` and :attr:`upstream_ca_files` hold this pass's copies; their
    names embed a content digest, so the reconciler supplies them before rendering.
    """

    pki_dir: Path
    recording_spool_dir: Path
    k8s_creds_dir: Path
    upstream_ca_dir: Path
    k8s_source_root: Path
    webapp_ca_root: Path
    public_tls_root: Path
    public_tls_dir: Path
    k8s_credentials: Mapping[str, K8sCredentialFiles] = field(
        default_factory=lambda: MappingProxyType({})
    )
    upstream_ca_files: Mapping[str, Path] = field(default_factory=lambda: MappingProxyType({}))
    acme_root: Path = ACME_ROOT
    pending_public_certs: frozenset[str] = frozenset()
    """``source: acme`` certificates with nothing installed (or nothing valid): left out of the
    rendered ``tls.certificates.files``. The reconciler supplies them each pass."""

    K8S_CA_SUFFIX: ClassVar[str] = ".crt"
    """File suffix of a cluster-CA copy (the token copy has none)."""

    UPSTREAM_CA_SUFFIX: ClassVar[str] = ".pem"
    """File suffix of a web-app CA bundle copy (``<name>-<sha12>.pem``)."""

    @classmethod
    def from_settings(cls, settings: GwopsSettings) -> "RuntimePaths":
        """Derive the canonical runtime paths from `settings.data_dir`."""
        return cls(
            pki_dir=settings.data_dir / "pki",
            recording_spool_dir=settings.data_dir / "recording-spool",
            k8s_creds_dir=settings.data_dir / "k8s-creds",
            upstream_ca_dir=settings.data_dir / "upstream-ca",
            k8s_source_root=K8S_SOURCE_ROOT,
            webapp_ca_root=WEBAPP_CA_ROOT,
            public_tls_root=PUBLIC_TLS_ROOT,
            public_tls_dir=settings.data_dir / "public-tls",
        )

    def public_cert_files(self, name: str) -> tuple[Path, Path]:
        """Stable store paths ``(fullchain, privkey)`` of one public certificate; pure.

        These are the paths the rendered ``tls.certificates.files`` entry references. A
        content change installs a new generation behind them, so the path (and the config)
        stays the same.
        """
        directory = self.public_tls_dir / name
        return directory / CERT_FILE, directory / KEY_FILE

    @property
    def leaf_cert_file(self) -> Path:
        """Stable store path of the gwops-minted TLS leaf certificate (fullchain)."""
        return self.pki_dir / "leaf" / "fullchain.pem"

    @property
    def leaf_key_file(self) -> Path:
        """Stable store path of the gwops-minted TLS leaf private key."""
        return self.pki_dir / "leaf" / "privkey.pem"

    @property
    def x509_ca_cert_file(self) -> Path:
        """Where the gwops X.509 CA certificate lives unless the seed supplies a path."""
        return self.pki_dir / "x509-ca.crt"

    @property
    def x509_ca_key_file(self) -> Path:
        """Where the gwops X.509 CA private key lives unless the seed supplies a path."""
        return self.pki_dir / "x509-ca.key"

    @property
    def ssh_ca_key_file(self) -> Path:
        """Where a gwops-generated SSH CA private key lives (when `ca.ssh.generate`).

        Must match `CertManager`'s on-disk layout (`pki_dir / "ssh-ca.key"`); the rendered
        `ssh.ca.local.privateKeyFile` points here.
        """
        return self.pki_dir / "ssh-ca.key"

    def k8s_token_stem(self, cluster_name: str) -> str:
        """The file stem of a cluster's bearer-token copy: ``<cluster>-token``."""
        return f"{cluster_name}-token"

    def k8s_ca_stem(self, cluster_name: str) -> str:
        """The file stem of a cluster's CA copy: ``<cluster>-ca`` (suffix :attr:`K8S_CA_SUFFIX`)."""
        return f"{cluster_name}-ca"

    def with_k8s_credentials(self, credentials: Mapping[str, K8sCredentialFiles]) -> "RuntimePaths":
        """A copy of these paths that renders `credentials` (cluster name -> copies)."""
        return replace(self, k8s_credentials=MappingProxyType(dict(credentials)))

    def k8s_token_file(self, cluster_name: str) -> Path:
        """The content-addressed bearer-token copy for one cluster.

        Raises:
            RenderError: the credentials step has not materialized this cluster.
        """
        return self._k8s_files(cluster_name).token

    def k8s_ca_file(self, cluster_name: str) -> Path:
        """The content-addressed cluster-CA copy for one cluster (see `k8s_token_file`)."""
        return self._k8s_files(cluster_name).ca

    def with_pending_public_certs(self, names: Iterable[str]) -> "RuntimePaths":
        """A copy of these paths that renders no entry for the public certificates `names`."""
        return replace(self, pending_public_certs=frozenset(names))

    def with_upstream_ca_files(self, files: Mapping[str, Path]) -> "RuntimePaths":
        """A copy of these paths that renders `files` (bundle name -> copy)."""
        return replace(self, upstream_ca_files=MappingProxyType(dict(files)))

    def upstream_ca_file(self, bundle_name: str) -> Path:
        """The content-addressed copy of one CA bundle.

        Raises:
            RenderError: the CA bundle step has not materialized this bundle.
        """
        path = self.upstream_ca_files.get(bundle_name)
        if path is None:
            raise RenderError(
                f"CA bundle {bundle_name!r} has not been materialized; the CA bundle step "
                "must run before the render"
            )
        return path

    def _k8s_files(self, cluster_name: str) -> K8sCredentialFiles:
        files = self.k8s_credentials.get(cluster_name)
        if files is None:
            raise RenderError(
                f"credentials for Kubernetes cluster {cluster_name!r} have not been "
                "materialized; the credentials step must run before the render"
            )
        return files


@dataclass(frozen=True)
class RenderedConfig:
    """The rendered gateway config.yaml text."""

    config_yaml: str


def _render_tls(state: EffectiveState, paths: RuntimePaths) -> dict[str, Any]:
    """Render ``tls``.

    Private mode: the leaf under ``certificates.files[0]``, plus the opt-in local issuer.
    Public mode: one ``certificates.files`` entry per declared certificate at its stable
    store paths, sorted by name (the gateway picks the first certificate that supports the
    ClientHello, so order matters only without SNI); no leaf and no ``automation``. A
    ``source: acme`` certificate in ``paths.pending_public_certs`` has no installed material
    yet and gets no entry.

    Raises:
        RenderError: Public mode and every certificate is pending (nothing to render).
    """
    if state.public_tls is not None:
        entries: list[dict[str, str]] = []
        for certificate in sorted(state.public_tls.certificates, key=lambda c: c.name):
            if certificate.name in paths.pending_public_certs:
                continue
            cert_file, key_file = paths.public_cert_files(certificate.name)
            entries.append(
                {
                    "certificateFile": cert_file.as_posix(),
                    "privateKeyFile": key_file.as_posix(),
                }
            )
        if not entries:
            raise RenderError(
                "no public certificate is installed to render; every certificate is pending "
                "ACME issuance"
            )
        return {"certificates": {"files": entries}}
    tls: dict[str, Any] = {
        "certificates": {
            "files": [
                {
                    "certificateFile": paths.leaf_cert_file.as_posix(),
                    "privateKeyFile": paths.leaf_key_file.as_posix(),
                }
            ]
        }
    }
    x509_ca = state.ca.x509
    if x509_ca.on_demand_issuance:
        cert_file = Path(x509_ca.cert_path) if x509_ca.cert_path else paths.x509_ca_cert_file
        key_file = Path(x509_ca.key_path) if x509_ca.key_path else paths.x509_ca_key_file
        tls["automation"] = {
            "issuer": {
                "local": {
                    "certificateFile": cert_file.as_posix(),
                    "privateKeyFile": key_file.as_posix(),
                }
            }
        }
    return tls


def _render_base(state: EffectiveState, paths: RuntimePaths) -> dict[str, Any]:
    return {
        "twingate": {"network": state.twingate.network, "host": state.twingate.host},
        "port": _GATEWAY_PORT,
        "metricsPort": _METRICS_PORT,
        "tls": _render_tls(state, paths),
        "log": {"sessionRecording": {"segment": {"maxSize": _SEGMENT_MAX_SIZE}}},
    }


def _render_ssh(state: EffectiveState, paths: RuntimePaths) -> dict[str, Any]:
    ssh_ca_key_file = (
        paths.ssh_ca_key_file.as_posix() if state.ca.ssh.generate else state.ca.ssh.key_path
    )
    return {
        "gateway": {
            "username": _SSH_GATEWAY_USERNAME,
            "key": {"type": _SSH_KEY_TYPE},
            "hostCertificate": {"ttl": _SSH_HOST_CERT_TTL},
            "userCertificate": {"ttl": _SSH_USER_CERT_TTL},
        },
        "ca": {"local": {"privateKeyFile": ssh_ca_key_file}},
    }


def _render_kubernetes(state: EffectiveState, paths: RuntimePaths) -> dict[str, Any] | None:
    # Credential paths are the content-addressed copies, so a changed credential changes
    # the rendered path (and so the config).
    clusters = state.k8s_clusters
    if not clusters:
        return None

    if len(clusters) > 1:
        raise RenderError(
            f"{len(clusters)} Kubernetes clusters configured, but the gateway's "
            "'kubernetes.upstreams' schema only consumes a single entry. Reduce to one "
            "cluster."
        )

    cluster = clusters[0]
    return {
        "upstreams": [
            {
                "name": cluster.name,
                "bearerTokenFile": paths.k8s_token_file(cluster.name).as_posix(),
                "caFile": paths.k8s_ca_file(cluster.name).as_posix(),
            }
        ]
    }


def _separator_variants(name: str) -> list[str]:
    """Every spelling of `name` with ``-`` or ``_`` chosen at each separator, except `name`."""
    positions = [i for i, char in enumerate(name) if char in _SEPARATORS]
    variants: list[str] = []
    for choice in itertools.product(_SEPARATORS, repeat=len(positions)):
        chars = list(name)
        for position, separator in zip(positions, choice, strict=True):
            chars[position] = separator
        variant = "".join(chars)
        if variant != name:
            variants.append(variant)
    return variants


def _render_web_app_headers(state: EffectiveState) -> dict[str, str]:
    """Gateway-wide headers sorted by name, plus every separator spelling of each trusted one.

    Raises:
        RenderError: a value is empty, a trusted name has too many separators to expand, or a
            spelling collides with a header of a different value.
    """
    headers = state.web_app_proxy.request_headers
    for name, value in headers.items():
        if not value.strip():
            raise RenderError(
                f"web_app_proxy.request_headers: the value of header {name!r} is empty; "
                "set a value or remove the header"
            )

    rendered: dict[str, str] = dict(headers)
    by_lower: dict[str, str] = {name.lower(): name for name in rendered}
    for name in sorted(trusted_gateway_header_names(state), key=lambda n: (n.lower(), n)):
        if separator_count(name) > MAX_TRUSTED_HEADER_SEPARATORS:
            raise RenderError(
                f"web_app_proxy.request_headers: trusted header {name!r} has more than "
                f"{MAX_TRUSTED_HEADER_SEPARATORS} separators ('-' or '_'); every spelling "
                "cannot be rendered"
            )
        for variant in _separator_variants(name):
            existing = by_lower.get(variant.lower())
            if existing is None:
                rendered[variant] = headers[name]
                by_lower[variant.lower()] = variant
            elif rendered[existing] != headers[name]:
                raise RenderError(
                    f"web_app_proxy.request_headers: header {existing!r} is a separator "
                    f"spelling of trusted header {name!r} but carries a different value; a "
                    "client could spoof the identity header through that spelling. Remove it "
                    "or give it the same value"
                )
    return dict(sorted(rendered.items(), key=lambda item: (item[0].lower(), item[0])))


def _render_web_app(state: EffectiveState) -> dict[str, Any]:
    """The ``webApp`` block; empty when there are no gateway-wide headers."""
    headers = _render_web_app_headers(state)
    return {"requestHeaders": headers} if headers else {}


def _render_upstream_ca_bundles(state: EffectiveState, paths: RuntimePaths) -> list[dict[str, str]]:
    """``upstreamTrustedCABundles`` entries in seed order.

    Raises:
        RenderError: a bundle has no materialized copy, or two bundles share a file.
    """
    entries: list[dict[str, str]] = []
    owners: dict[str, str] = {}
    for bundle in state.web_app_proxy.upstream_ca_bundles:
        file = paths.upstream_ca_file(bundle.name).as_posix()
        if file in owners:
            raise RenderError(
                f"duplicate upstreamTrustedCABundles file {file} (bundles "
                f"{owners[file]!r} and {bundle.name!r}); the gateway requires a different "
                "file per bundle"
            )
        owners[file] = bundle.name
        entries.append({"file": file})
    return entries


def render_gateway_config(
    state: EffectiveState, caps: Capabilities, paths: RuntimePaths
) -> RenderedConfig:
    """Render the effective state into a gateway ``config.yaml``.

    Base sections always render. ``kubernetes`` raises :class:`RenderError` if more than
    one cluster is configured. ``webApp`` and ``upstreamTrustedCABundles`` render only when
    ``state.web_apps`` is non-empty. ``caps`` is unused; the rendered shape does not
    depend on it.
    """
    rendered = _render_base(state, paths)
    rendered["ssh"] = _render_ssh(state, paths)

    kubernetes = _render_kubernetes(state, paths)
    if kubernetes is not None:
        rendered["kubernetes"] = kubernetes

    if state.web_apps:
        rendered["webApp"] = _render_web_app(state)
        bundles = _render_upstream_ca_bundles(state, paths)
        if bundles:
            rendered["upstreamTrustedCABundles"] = bundles

    config_yaml = yaml.safe_dump(rendered, sort_keys=False)
    return RenderedConfig(config_yaml=config_yaml)
