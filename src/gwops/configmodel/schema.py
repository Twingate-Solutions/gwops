"""Pydantic models for the declarative seed file and the merged effective state.

Every model forbids unknown keys so config typos fail loud at load time instead of
being silently ignored.
"""

import ipaddress
import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Discriminator,
    Field,
    Tag,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import InitErrorDetails, PydanticCustomError

from gwops import tlsnames
from gwops.confined import ACME_ROOT
from gwops.kindhooks import EMPTY_EXTRAS
from gwops.shipper.limits import LINE_MAX_BYTES

_NAME_RE = re.compile(r"^[a-z0-9-]{1,63}$")
_ADDRESS_RE = re.compile(r"^(?P<host>[a-zA-Z0-9._-]+)(?::(?P<port>\d{1,5}))?$")

# RFC 9110 token characters: what a header field name may contain.
_HEADER_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_HEADER_NAME_MAX = 64
_HEADER_VALUE_MAX = 1024
# ASCII control characters: C0 (including CR, LF, NUL and TAB) and DEL.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")

Name = Annotated[str, Field(description="lowercase DNS-label-style identifier")]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _validate_name(name: str) -> str:
    if not _NAME_RE.fullmatch(name):
        raise ValueError(f"name {name!r} must match [a-z0-9-]{{1,63}}")
    return name


def _validate_address(address: str) -> str:
    m = _ADDRESS_RE.fullmatch(address)
    if m is None:
        raise ValueError(f"address {address!r} must be host or host:port")
    port = m.group("port")
    if port is not None and not 1 <= int(port) <= 65535:
        raise ValueError(f"address {address!r} port must be 1-65535")
    # Lowercased because the Twingate API lowercases addresses; keeping the original
    # case would make the seed permanently differ from what the API reports.
    return address.lower()


def _validate_gateway_address(address: str | None) -> str | None:
    """Validate a connector-reachable gateway address; a port is mandatory.

    Unlike upstream/cluster addresses, the gateway address always carries an
    explicit port (e.g. ``10.0.0.1:8443``), so a bare host is rejected.
    """
    if address is None:
        return None
    m = _ADDRESS_RE.fullmatch(address)
    if m is None or m.group("port") is None:
        raise ValueError(
            f"gateway_address {address!r} must be host:port with an explicit "
            "port (e.g. 10.0.0.1:8443)"
        )
    if not 1 <= int(m.group("port")) <= 65535:
        raise ValueError(f"gateway_address {address!r} port must be 1-65535")
    # Lowercased as in _validate_address: the Twingate API lowercases addresses.
    return address.lower()


def _check_header_name(name: str, where: str) -> None:
    """Raise ``ValueError`` unless ``name`` is a 1-64 character RFC 9110 token."""
    if not name or len(name) > _HEADER_NAME_MAX or not _HEADER_NAME_RE.fullmatch(name):
        shown = repr(name if len(name) <= _HEADER_NAME_MAX else name[:_HEADER_NAME_MAX] + "...")
        raise ValueError(
            f"{where}: header name {shown} must be 1-{_HEADER_NAME_MAX} RFC 9110 token "
            "characters (letters, digits and !#$%&'*+-.^_`|~)"
        )


def _check_unique_header_name(name: str, seen: dict[str, str], where: str) -> None:
    """Record ``name`` in ``seen`` (keyed by lowercase); raise if a case variant is there."""
    folded = name.lower()
    if folded in seen:
        raise ValueError(
            f"{where}: duplicate header name {seen[folded]!r} and {name!r} "
            "(names are case-insensitive)"
        )
    seen[folded] = name


def _check_header_map(headers: Mapping[str, str], where: str) -> None:
    """Validate a header map; errors never echo a value, since values can be secrets."""
    seen: dict[str, str] = {}
    for name, value in headers.items():
        _check_header_name(name, where)
        _check_unique_header_name(name, seen, where)
        if _CONTROL_CHAR_RE.search(value):
            raise ValueError(f"{where}: the value of header {name!r} contains a control character")
        if len(value) > _HEADER_VALUE_MAX:
            raise ValueError(
                f"{where}: the value of header {name!r} is longer than "
                f"{_HEADER_VALUE_MAX} characters"
            )


def _check_header_names(names: list[str], where: str) -> None:
    """Validate a list of header names: tokens, unique ignoring case."""
    seen: dict[str, str] = {}
    for name in names:
        _check_header_name(name, where)
        _check_unique_header_name(name, seen, where)


class ResourceRef(_StrictModel):
    """A reference to an existing Twingate group or security policy.

    A plain string is a **name** (exact match, resolved by gwops); ``{id: ...}`` is an
    explicit GraphQL id; ``{id, name}`` is the pinned form gwops persists after resolving
    an admin-API name (the id is authoritative, the name is for display). gwops never
    guesses whether a bare string is a name or an id.
    """

    id: str | None = None
    name: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _plain_string_is_a_name(cls, data: object) -> object:
        return {"name": data} if isinstance(data, str) else data

    @model_validator(mode="after")
    def _id_or_name(self) -> "ResourceRef":
        if not self.id and not self.name:
            raise ValueError("a reference needs a non-empty name or id")
        return self


class AccessSpec(_StrictModel):
    """Which groups and security policy a gwops-created resource is assigned.

    ``None`` (or an explicit ``null``) means *omitted* — fall back to
    ``twingate.resource_defaults``. ``groups: []`` is not omitted: it means no groups,
    even when defaults exist. Precedence lives in :mod:`gwops.access.precedence`.
    """

    groups: list[ResourceRef] | None = None
    security_policy: ResourceRef | None = None


class AccessAllowlist(_StrictModel):
    """Groups / security policies that overlay and API writes may reference (seed-only).

    Checked on **resolved ids**, so an ``{id}`` reference cannot bypass a name entry. An
    empty list allows nothing for that key. Seed entries and ``resource_defaults`` are
    admin-authored and implicitly allowed.
    """

    groups: list[ResourceRef] = []
    security_policies: list[ResourceRef] = []


class AddressAllowlist(_StrictModel):
    """Addresses that overlay and API writes may target (seed-only).

    An IP literal must fall inside one of `cidrs`; a DNS name must equal one of
    `dns_suffixes` or end with it at a label boundary (``apps.example.com`` allows
    ``x.apps.example.com`` but not ``xapps.example.com``). No DNS resolution is done.
    """

    cidrs: list[str] = []
    dns_suffixes: list[str] = []

    @field_validator("cidrs")
    @classmethod
    def _valid_cidrs(cls, cidrs: list[str]) -> list[str]:
        for cidr in cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ValueError(f"address_allowlist.cidrs: {cidr!r} is not a CIDR") from exc
        return cidrs

    @field_validator("dns_suffixes")
    @classmethod
    def _normalized_suffixes(cls, suffixes: list[str]) -> list[str]:
        normalized = [s.strip().lower().strip(".") for s in suffixes]
        if any(not s for s in normalized):
            raise ValueError("address_allowlist.dns_suffixes entries must be non-empty")
        return normalized


class TwingateRef(_StrictModel):
    """Which Twingate tenant and gateway object this container serves.

    Two mutually-exclusive modes:

    * **Mode A** — ``gateway_id`` pins a gateway object that already exists.
    * **Mode B** — ``remote_network`` (console name) *or* ``remote_network_id``
      (GraphQL id), together with a connector-reachable ``gateway_address``, so
      the control plane can auto-create the gateway object.
    """

    network: str
    host: str = "twingate.com"
    gateway_id: str | None = None
    remote_network: str | None = None
    remote_network_id: str | None = None
    gateway_address: str | None = None
    resource_defaults: AccessSpec | None = None
    """Access applied to every resource whose own ``access`` omits a key (seed-only)."""
    access_allowlist: AccessAllowlist | None = None
    """Absent: overlay/API writes may reference any group or policy."""
    address_allowlist: AddressAllowlist | None = None
    """Absent: overlay/API writes may target any address."""

    _gateway_address = field_validator("gateway_address")(_validate_gateway_address)

    @model_validator(mode="after")
    def _exactly_one_mode(self) -> "TwingateRef":
        mode_b_set = (
            self.remote_network is not None
            or self.remote_network_id is not None
            or self.gateway_address is not None
        )
        if self.gateway_id is not None:
            # Mode A: pin an existing gateway; no Mode B field may accompany it.
            if mode_b_set:
                raise ValueError(
                    "set either gateway_id (to pin an existing gateway) or "
                    "remote_network + gateway_address (to auto-create), not both"
                )
            return self
        # gateway_id is None -> Mode B, or nothing configured at all.
        if not mode_b_set:
            raise ValueError("provide gateway_id, or remote_network(_id) + gateway_address")
        if self.gateway_address is None:
            raise ValueError(
                "remote-network mode requires gateway_address (a connector-reachable "
                "host:port for the gateway, e.g. 10.0.0.1:8443)"
            )
        if self.remote_network is None and self.remote_network_id is None:
            raise ValueError(
                "remote-network mode requires exactly one of remote_network (console "
                "name) or remote_network_id (GraphQL id)"
            )
        if self.remote_network is not None and self.remote_network_id is not None:
            raise ValueError(
                "set exactly one of remote_network (console name) or "
                "remote_network_id (GraphQL id), not both"
            )
        return self


class X509CASettings(_StrictModel):
    """X.509 CA source: generate on first run, or bring-your-own file paths."""

    generate: bool = True
    cert_path: str | None = None
    key_path: str | None = None
    on_demand_issuance: bool = False

    @model_validator(mode="after")
    def _paths_required_when_not_generating(self) -> "X509CASettings":
        if not self.generate and (self.cert_path is None or self.key_path is None):
            raise ValueError("x509 CA with generate=false requires cert_path and key_path")
        return self


class SSHCASettings(_StrictModel):
    """SSH CA source: generate on first run, or bring-your-own private key path."""

    generate: bool = True
    key_path: str | None = None

    @model_validator(mode="after")
    def _path_required_when_not_generating(self) -> "SSHCASettings":
        if not self.generate and self.key_path is None:
            raise ValueError("ssh CA with generate=false requires key_path")
        return self


class CASettings(_StrictModel):
    """Certificate authority configuration for both PKI types (X.509 and SSH)."""

    x509: X509CASettings = X509CASettings()
    ssh: SSHCASettings = SSHCASettings()


class UpstreamEntry(_StrictModel):
    """Fields every upstream kind shares; one subclass per kind in `gwops.kinds`.

    `address` is ``host`` or ``host:port``; the Twingate resource address is always the
    portless host, and :meth:`upstream_port` is the port the gateway dials.
    """

    name: Name
    address: str
    access: AccessSpec | None = None

    _name = field_validator("name")(_validate_name)
    _address = field_validator("address")(_validate_address)

    def upstream_port(self) -> int:
        """The port the gateway dials: the address's ``:port``, else the kind default."""
        _host, sep, port = self.address.partition(":")
        return int(port) if sep else self.default_port()

    def default_port(self) -> int:
        """The kind's default upstream port when the address carries none."""
        raise NotImplementedError

    def tg_extras(self) -> Mapping[str, Any]:
        """Kind-specific Twingate resource settings beyond address and upstream port.

        Empty by default; a kind with more to sync (web apps) overrides it. The values
        feed ``DesiredResource.extras`` and the kind's ``create_variables`` hook.
        """
        return EMPTY_EXTRAS

    def san_names(self) -> list[str]:
        """The names this entry adds to the gateway leaf certificate's SANs.

        The portless address by default; a kind that clients also reach by another name
        (a web app's alias) overrides it.
        """
        return [self.address.partition(":")[0]]


class SSHUpstream(UpstreamEntry):
    """One SSH target the gateway fronts."""

    def default_port(self) -> int:
        """SSH listens on 22 unless the address names a port."""
        return 22


class K8sCluster(UpstreamEntry):
    """One Kubernetes API server the gateway fronts, with its credential files."""

    port: int = Field(default=443, ge=1, le=65535)
    bearer_token_file: str
    ca_file: str

    def upstream_port(self) -> int:
        """The cluster's `port` field (default 443), regardless of the address."""
        return self.port

    def default_port(self) -> int:
        """The API server default when `port` is not set."""
        return 443


UpstreamTLS = Literal["verify_full", "verify_ca", "insecure", "none"]
"""How the gateway verifies a web app's upstream (Twingate ``TLSClientMode``, lowercased)."""
DownstreamTLS = Literal["tls13", "none"]
"""Whether the browser-facing hop is TLS (Twingate ``TLSServerMode``, lowercased)."""

_TG_UPSTREAM_TLS_MODES: Mapping[str, str] = MappingProxyType(
    {mode: mode.upper() for mode in ("verify_full", "verify_ca", "insecure", "none")}
)
_TG_DOWNSTREAM_TLS_MODES: Mapping[str, str] = MappingProxyType({"tls13": "TLS13", "none": "NONE"})
_ALIAS_RE = re.compile(r"[a-zA-Z0-9._-]+")


class _HiddenInputModel(_StrictModel):
    """Base for models that can carry header values: validation errors hide their input."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class WebAppDownstream(_HiddenInputModel):
    """The client-facing leg of a web app."""

    tls: DownstreamTLS = "tls13"
    port: int | None = Field(default=None, ge=1, le=65535)

    def effective_port(self) -> int:
        """The browser-facing port: ``port``, else 443 (``tls13``) or 80 (``none``)."""
        if self.port is not None:
            return self.port
        return 443 if self.tls == "tls13" else 80


class WebApp(UpstreamEntry):
    """One HTTP(S) app the gateway fronts as an L7 proxy (a Twingate ``WebAppResource``).

    Cross-entry, capability and filesystem rules live in ``gwops.access.webapp_policy``.
    """

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    alias: str | None = None
    """Second client-facing host; always managed, so ``None`` clears it Twingate-side."""
    upstream_tls: UpstreamTLS = "verify_full"
    downstream: WebAppDownstream = WebAppDownstream()
    request_headers: dict[str, str] | None = None
    """``None``: unmanaged (never sent); ``{}``: managed and empty (sent as ``[]``)."""

    @model_validator(mode="after")
    def _check_alias_and_headers(self) -> "WebApp":
        where = f"web_apps entry {self.name!r}"
        if self.alias is not None:
            alias = self.alias
            if "*" in alias:
                raise ValueError(f"{where}: alias must be a concrete host, not a wildcard")
            if ":" in alias:
                raise ValueError(f"{where}: alias must not carry a port (host only)")
            if not _ALIAS_RE.fullmatch(alias):
                raise ValueError(
                    f"{where}: alias must be a host name or IP literal "
                    "(letters, digits, '.', '-' and '_')"
                )
            alias = alias.lower()
            if alias == self.address.partition(":")[0]:
                raise ValueError(f"{where}: alias must differ from address")
            self.alias = alias
        if self.request_headers is not None:
            _check_header_map(self.request_headers, f"{where}, request_headers")
        return self

    def default_port(self) -> int:
        """HTTPS (443) unless the upstream is plaintext (``upstream_tls: none``, then 80)."""
        return 80 if self.upstream_tls == "none" else 443

    def san_names(self) -> list[str]:
        """The portless address plus the alias, so the leaf covers every client-facing name."""
        names = super().san_names()
        return names if self.alias is None else [*names, self.alias]

    def tg_extras(self) -> Mapping[str, Any]:
        """Web-app settings Twingate stores (wire values); rewrites ``None`` when unmanaged."""
        rewrites = None if self.request_headers is None else tuple(self.request_headers.items())
        return MappingProxyType(
            {
                "downstream_port": self.downstream.effective_port(),
                "downstream_tls_mode": _TG_DOWNSTREAM_TLS_MODES[self.downstream.tls],
                "upstream_tls_mode": _TG_UPSTREAM_TLS_MODES[self.upstream_tls],
                "alias": self.alias,
                "request_header_rewrites": rewrites,
            }
        )


class CABundle(_StrictModel):
    """A PEM bundle of private CAs trusted for upstream TLS, added to the system roots.

    `file` must resolve under ``/config/webapp-cas/``; enforced where it is read, not here.
    """

    name: Name
    file: str = Field(min_length=1)

    _name = field_validator("name")(_validate_name)


class WebAppProxySettings(_HiddenInputModel):
    """Gateway-wide L7 proxy settings (seed-only; never overlay-writable)."""

    request_headers: dict[str, str] = {}
    """Rendered as ``webApp.requestHeaders``: applied to every web app on this gateway."""
    upstream_ca_bundles: list[CABundle] = []
    plaintext_upstreams: AddressAllowlist | None = None
    """The only hosts allowed ``upstream_tls`` ``none``/``insecure``; absent allows none."""
    upstream_tls_probe: bool = False
    """Opt-in active TLS handshake probe of web-app upstreams (``gwops.webapp_probe``)."""

    @model_validator(mode="after")
    def _check_headers_and_bundles(self) -> "WebAppProxySettings":
        _check_header_map(self.request_headers, "web_app_proxy.request_headers")
        where = "web_app_proxy.upstream_ca_bundles"
        names: set[str] = set()
        files: dict[str, str] = {}
        for bundle in self.upstream_ca_bundles:
            if bundle.name in names:
                raise ValueError(f"{where}: duplicate bundle name {bundle.name!r}")
            names.add(bundle.name)
            normalized = posixpath.normpath(bundle.file)
            if normalized in files:
                raise ValueError(
                    f"{where}: bundle {bundle.name!r} has the same file as bundle "
                    f"{files[normalized]!r}"
                )
            files[normalized] = bundle.name
        return self


class RecordingSettings(_StrictModel):
    """Session-recording delivery to a recording receiver; explicit opt-in."""

    enabled: bool = False
    receiver_url: str | None = None
    spool_max_bytes: int = 256 * 1024 * 1024

    @field_validator("spool_max_bytes")
    @classmethod
    def _holds_the_longest_line(cls, value: int) -> int:
        if value < LINE_MAX_BYTES:
            raise ValueError(
                f"recording.spool_max_bytes must be at least {LINE_MAX_BYTES} (16 MiB, "
                f"the longest gateway line the spool accepts); got {value}. "
                "Raise it, or omit it for the 268435456 (256 MiB) default"
            )
        return value

    @model_validator(mode="after")
    def _url_required_when_enabled(self) -> "RecordingSettings":
        if self.enabled and self.receiver_url is None:
            raise ValueError("recording.enabled=true requires receiver_url")
        if self.receiver_url is not None:
            scheme = urlsplit(self.receiver_url).scheme.lower()
            if scheme not in ("http", "https"):
                raise ValueError(
                    "recording.receiver_url must be an http:// or https:// URL "
                    f"(got {self.receiver_url!r}); prefer https:// — plain http "
                    "ships the GWOPS_RECORDING_TOKEN and recordings in cleartext"
                )
        return self


class AutomationWebAppSettings(_StrictModel):
    """Opt-in for the automation token to manage web apps, within a per-field policy."""

    enabled: bool = False
    """Absent or false: every web-app route answers 403 to the automation token."""
    request_header_names: list[str] = []
    """Rewrite names the automation token may set, matched case-insensitively; empty = none."""

    @field_validator("request_header_names")
    @classmethod
    def _valid_names(cls, names: list[str]) -> list[str]:
        _check_header_names(names, "admin_api.automation.web_apps.request_header_names")
        return names


class AutomationSettings(_StrictModel):
    """Namespace rules for the ``GWOPS_AUTOMATION_TOKEN`` caller."""

    name_prefix: str | None = None
    """If set, every upstream the automation token creates must be named with it."""
    web_apps: AutomationWebAppSettings = AutomationWebAppSettings()


class AdminAPISettings(_StrictModel):
    """gwops admin API bind address and port (localhost by default)."""

    bind: str = "127.0.0.1"
    port: int = Field(default=8081, ge=1, le=65535)
    automation: AutomationSettings = AutomationSettings()


_ACME_DIRECTORY_URLS: Mapping[str, str] = MappingProxyType(
    {
        "staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
        "production": "https://acme-v02.api.letsencrypt.org/directory",
    }
)
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def _raise_value(message: str) -> Any:
    """Raise the ``ValueError`` pydantic turns into a line error carrying `message`."""
    raise ValueError(message)


class AcmeSettings(_StrictModel):
    """The seed-only ``public_tls.acme`` block: how gwops drives lego for ``source: acme``.

    Unreachable from overlays and the automation token (``public_tls`` is outside the overlay
    allowlist). `token_file` is lexically confined to ``/config/acme/`` here; the file's
    existence is checked at startup and gwops never reads its content.
    """

    email: str
    """ACME account contact. A changed value registers a new account."""
    accept_tos: bool = Field(default=False, validate_default=True)
    """Must be true: the operator accepts the CA's terms of service."""
    directory: str = "staging"
    """``staging`` (dry run, the default), ``production`` or an ``https://`` directory URL."""
    provider: Literal["cloudflare"] = "cloudflare"
    """DNS-01 provider; Cloudflare is the only one."""
    propagation: Literal["resolver", "authoritative"] = "resolver"
    """``resolver`` checks recursive resolvers only; ``authoritative`` also needs port 53."""
    token_file: str = "/config/acme/cloudflare-token"
    """Mounted DNS API token file under ``/config/acme/``; read by lego, never by gwops."""

    @field_validator("email")
    @classmethod
    def _valid_email(cls, email: str) -> str:
        if not _EMAIL_RE.fullmatch(email) or email.startswith("-"):
            raise ValueError(
                "public_tls.acme.email must be a contact address such as ops@example.com "
                "(it is the ACME account contact)"
            )
        return email

    @field_validator("accept_tos")
    @classmethod
    def _tos_accepted(cls, accepted: bool) -> bool:
        if not accepted:
            raise ValueError(
                "public_tls.acme.accept_tos must be true: set it to true to accept the "
                "certificate authority's terms of service, or remove source: acme "
                "certificates"
            )
        return accepted

    @field_validator("directory")
    @classmethod
    def _valid_directory(cls, directory: str) -> str:
        if directory in _ACME_DIRECTORY_URLS:
            return directory
        parts = urlsplit(directory)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
            or _CONTROL_CHAR_RE.search(directory)
            or " " in directory
        ):
            raise ValueError(
                "public_tls.acme.directory must be 'staging', 'production' or an https:// "
                "ACME directory URL without credentials or a fragment "
                "(for example https://acme.example.com/directory)"
            )
        return directory

    @field_validator("provider", "propagation", mode="before")
    @classmethod
    def _known_choice(cls, value: object, info: Any) -> object:
        allowed = {"provider": ("cloudflare",), "propagation": ("resolver", "authoritative")}
        choices = allowed[info.field_name]
        if value not in choices:
            raise ValueError(
                f"public_tls.acme.{info.field_name} {value!r} is not supported; use "
                + " or ".join(repr(c) for c in choices)
            )
        return value

    @field_validator("token_file")
    @classmethod
    def _token_under_acme_root(cls, token_file: str) -> str:
        root = PurePosixPath(ACME_ROOT.as_posix())
        if _CONTROL_CHAR_RE.search(token_file):
            problem = "contains a control character"
        elif not token_file.startswith("/"):
            problem = "must be an absolute path"
        elif ".." in PurePosixPath(token_file).parts:
            problem = "must not contain '..' components"
        else:
            path = PurePosixPath(posixpath.normpath(token_file))
            if path != root and path.is_relative_to(root):
                return str(path)
            problem = f"must name a file under {root}/"
        raise ValueError(
            f"public_tls.acme.token_file {problem}: mount the DNS API token file under "
            f"{root}/ (for example {root}/cloudflare-token)"
        )

    @property
    def directory_url(self) -> str:
        """The ACME directory URL: the named shortcut's Let's Encrypt URL, or `directory`."""
        return _ACME_DIRECTORY_URLS.get(self.directory, self.directory)

    @property
    def is_staging(self) -> bool:
        """Whether the directory is Let's Encrypt staging (a dry run: never installed).

        True for the ``staging`` shortcut and for an explicit URL equal to the staging
        directory URL. An explicit URL equal to the production directory URL is production
        (``is_staging`` false), like the ``production`` shortcut.
        """
        return self.directory_url == _ACME_DIRECTORY_URLS["staging"]


class _PublicCertificateBase(_StrictModel):
    """Fields every public certificate declares: its `name` and the `names` it covers.

    `names` is the declared coverage: a concrete DNS name or a leftmost ``*.`` wildcard,
    each inside a zone of the enclosing :class:`PublicTlsSettings`.
    """

    name: Name
    names: list[str] = Field(min_length=1)

    _name = field_validator("name")(_validate_name)

    @field_validator("names")
    @classmethod
    def _lowercased(cls, names: list[str]) -> list[str]:
        # DNS names compare case-insensitively; keep one spelling (as for addresses).
        return [name.lower() for name in names]


class FilePublicCertificate(_PublicCertificateBase):
    """A public certificate the operator supplies as files (``source: file``, the default).

    `cert_file` and `key_file` must resolve under ``/config/public-tls/``; enforced where
    they are read.
    """

    source: Literal["file"] = "file"
    cert_file: str = Field(min_length=1)
    key_file: str = Field(min_length=1)

    @model_validator(mode="before")
    @classmethod
    def _no_acme_fields(cls, data: Any) -> Any:
        if isinstance(data, dict) and "challenge_alias" in data:
            _raise_value(
                "challenge_alias applies only to source: acme certificates; remove it or "
                "set source: acme"
            )
        return data


class AcmePublicCertificate(_PublicCertificateBase):
    """A public certificate issued and renewed by lego (``source: acme``, seed-only).

    Requires the ``public_tls.acme`` block. `challenge_alias` optionally names the zone that
    ``_acme-challenge.<name>`` is CNAME-delegated to; it is a documentation and validation
    concern only (lego follows the CNAME on its own), off by default.
    """

    source: Literal["acme"]
    challenge_alias: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _no_file_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            present = [key for key in ("cert_file", "key_file") if key in data]
            if present:
                _raise_value(
                    f"source: acme issues the certificate itself; remove {' and '.join(present)} "
                    "(or set source: file to supply your own files)"
                )
        return data

    @field_validator("challenge_alias")
    @classmethod
    def _valid_alias(cls, alias: str | None) -> str | None:
        if alias is None:
            return None
        alias = alias.lower()
        if not tlsnames.is_dns_name(alias):
            raise ValueError(
                f"challenge_alias {alias!r} must be a concrete lowercase DNS name (the zone "
                "that _acme-challenge.<name> is CNAME-delegated to), or omitted"
            )
        return alias


def _certificate_source(value: Any) -> str | None:
    """The discriminator tag: ``source``, which defaults to ``file`` when omitted."""
    if isinstance(value, dict):
        source = value.get("source", "file")
        return source if isinstance(source, str) else None
    return getattr(value, "source", None)


PublicCertificate = Annotated[
    Annotated[FilePublicCertificate, Tag("file")] | Annotated[AcmePublicCertificate, Tag("acme")],
    Discriminator(
        _certificate_source,
        custom_error_type="public_tls",
        custom_error_message="source must be 'file' (default) or 'acme'",
    ),
]
"""One public certificate, discriminated on ``source`` (``file`` when omitted, or ``acme``)."""

_PUBLIC_CERTIFICATE_ADAPTER: TypeAdapter[FilePublicCertificate | AcmePublicCertificate] = (
    TypeAdapter(PublicCertificate)
)


def parse_public_certificate(data: object) -> FilePublicCertificate | AcmePublicCertificate:
    """Validate one ``public_tls.certificates[]`` entry on its own (used by tests and tools)."""
    return _PUBLIC_CERTIFICATE_ADAPTER.validate_python(data)


def _line_error(loc: tuple[int | str, ...], message: str, value: object) -> InitErrorDetails:
    """A pydantic line error carrying `loc`, so the loader can attribute it to a layer."""
    return InitErrorDetails(
        type=PydanticCustomError("public_tls", "{message}", {"message": message}),
        loc=loc,
        input=value,
    )


def _raise_line_errors(title: str, errors: list[InitErrorDetails]) -> None:
    """Raise one :class:`ValidationError` holding every error, or nothing if there are none."""
    if errors:
        raise ValidationError.from_exception_data(title, errors)


class PublicTlsSettings(_StrictModel):
    """The seed-only ``public_tls`` block; its presence turns public mode on.

    Validates zones and certificate names. Checks that need the rest of the seed live on
    :class:`SeedConfig`.
    """

    zones: list[str] = Field(min_length=1)
    registered_root: Literal["isrg_root_x1"]
    certificates: list[PublicCertificate] = Field(min_length=1)
    acme: AcmeSettings | None = None
    """Seed-only ACME settings; required when any certificate has ``source: acme``."""

    @field_validator("zones")
    @classmethod
    def _valid_zones(cls, zones: list[str]) -> list[str]:
        seen: set[str] = set()
        for zone in zones:
            if not tlsnames.is_zone(zone):
                raise ValueError(
                    f"zone {zone!r} must be a lowercase ASCII DNS name of at least two "
                    "labels (A-label form, no wildcard, no trailing dot)"
                )
            if zone in seen:
                raise ValueError(f"duplicate zone {zone!r}")
            seen.add(zone)
        return zones

    @model_validator(mode="after")
    def _acme_block_present(self) -> "PublicTlsSettings":
        """`public_tls.acme` is required exactly when a certificate has ``source: acme``."""
        if self.acme is None:
            wanting = [c.name for c in self.certificates if c.source == "acme"]
            if wanting:
                owners = ", ".join(repr(n) for n in wanting)
                _raise_line_errors(
                    type(self).__name__,
                    [
                        _line_error(
                            ("acme",),
                            f"certificate(s) {owners} have source: acme but public_tls.acme is "
                            "missing; add a public_tls.acme block with email, accept_tos: true "
                            "and token_file (directory defaults to staging)",
                            None,
                        )
                    ],
                )
        return self

    @model_validator(mode="after")
    def _valid_certificates(self) -> "PublicTlsSettings":
        errors: list[InitErrorDetails] = []
        owners: dict[str, str] = {}
        cert_names: set[str] = set()
        for index, cert in enumerate(self.certificates):
            if cert.name in cert_names:
                errors.append(
                    _line_error(
                        ("certificates", index, "name"),
                        f"duplicate certificate name {cert.name!r}",
                        cert.name,
                    )
                )
            cert_names.add(cert.name)
            for name in cert.names:
                problem = self._name_problem(name)
                if problem is not None:
                    errors.append(
                        _line_error(
                            ("certificates", index, "names"),
                            f"certificate {cert.name!r}: name {name!r} {problem}",
                            name,
                        )
                    )
                owner = owners.setdefault(name, cert.name)
                if owner != cert.name:
                    errors.append(
                        _line_error(
                            ("certificates", index, "names"),
                            f"certificate {cert.name!r}: name {name!r} is also declared by "
                            f"certificate {owner!r}; each name belongs to one certificate",
                            name,
                        )
                    )
        _raise_line_errors(type(self).__name__, errors)
        return self

    def _name_problem(self, name: str) -> str | None:
        """Why `name` is not a valid certificate name for these zones, or ``None``."""
        if not tlsnames.is_certificate_name(name):
            return (
                "must be a concrete DNS name, or '*.' followed by one (a wildcard is only "
                "a leftmost '*.' label)"
            )
        if tlsnames.zone_of(tlsnames.wildcard_parent(name), self.zones) is None:
            return f"is outside every zone {self.zones}"
        return None


@dataclass(frozen=True)
class _ServedName:
    """One name the gateway serves, with where in the config it was declared."""

    field: str
    index: int
    entry: str
    label: Literal["address", "alias"]
    name: str


class SeedConfig(_StrictModel):
    """The full declarative seed (``/config/seed.yaml``), validated."""

    twingate: TwingateRef
    ca: CASettings = CASettings()
    ssh_upstreams: list[SSHUpstream] = []
    k8s_clusters: list[K8sCluster] = []
    web_apps: list[WebApp] = []
    web_app_proxy: WebAppProxySettings = WebAppProxySettings()
    recording: RecordingSettings = RecordingSettings()
    admin_api: AdminAPISettings = AdminAPISettings()
    public_tls: PublicTlsSettings | None = None
    """Seed-only; its presence turns public mode on and replaces ``ca.x509``."""

    @model_validator(mode="after")
    def _names_unique(self) -> "SeedConfig":
        # Every list of UpstreamEntry (one per resource kind) must have unique names.
        for field_name in type(self).model_fields:
            items = getattr(self, field_name)
            if not isinstance(items, list):
                continue
            seen: set[str] = set()
            for item in items:
                if not isinstance(item, UpstreamEntry):
                    break
                if item.name in seen:
                    raise ValueError(f"duplicate {field_name} name {item.name!r}")
                seen.add(item.name)
        return self

    @model_validator(mode="after")
    def _public_tls_replaces_ca_x509(self) -> "SeedConfig":
        """Refuse `public_tls` together with an explicit `ca.x509` block."""
        if self.public_tls is not None and "x509" in self.ca.model_fields_set:
            _raise_line_errors(
                type(self).__name__,
                [
                    _line_error(
                        ("ca", "x509"),
                        "public_tls and ca.x509 are mutually exclusive: public mode "
                        "registers a public root as the X.509 CA; remove the ca.x509 block",
                        None,
                    )
                ],
            )
        return self

    @model_validator(mode="after")
    def _public_tls_covers_served_names(self) -> "SeedConfig":
        """Require each served name to be a zone DNS name matching exactly one certificate.

        Errors carry the declaring entry's location (list field, index, ``address`` or
        ``alias``), so the loader attributes them to the layer that set that value.
        """
        if self.public_tls is None:
            return self
        zones = self.public_tls.zones
        served = _served_names(self)
        errors = [
            _line_error(
                (s.field, s.index, s.label),
                f"{s.field} entry {s.entry!r}: {s.label} {s.name!r} {problem}",
                s.name,
            )
            for s in served
            if (problem := _served_name_problem(s.name, zones)) is not None
        ]
        if not errors:  # a name that is not a zone DNS name would only add coverage noise
            for s in served:
                covering = tlsnames.covering_certificates(s.name, self.public_tls.certificates)
                if len(covering) == 1:
                    continue
                if covering:
                    owners = ", ".join(repr(c.name) for c in covering)
                    problem = f"is covered by several public_tls certificates ({owners})"
                else:
                    problem = "is covered by no public_tls certificate"
                errors.append(
                    _line_error(
                        (s.field, s.index, s.label),
                        f"{s.field} entry {s.entry!r}: {s.label} {s.name!r} {problem}; "
                        "each served name must match exactly one certificate's names",
                        s.name,
                    )
                )
        _raise_line_errors(type(self).__name__, errors)
        return self


def _served_names(config: SeedConfig) -> list[_ServedName]:
    """Every name the gateway serves, with its declaring entry and field.

    The same names as :func:`gwops.renderer.sans.required_sans` (the ``san_names()`` of every
    entry of every kind), but with provenance. That function cannot be called from here:
    ``renderer.sans`` imports ``gwops.kinds``, which imports this module.
    """
    served: list[_ServedName] = []
    for field_name in type(config).model_fields:
        items = getattr(config, field_name)
        if not isinstance(items, list):
            continue
        for index, item in enumerate(items):
            if not isinstance(item, UpstreamEntry):
                break
            host = item.address.partition(":")[0]
            served.extend(
                _ServedName(field_name, index, item.name, "address" if n == host else "alias", n)
                for n in item.san_names()
            )
    return served


def _served_name_problem(name: str, zones: list[str]) -> str | None:
    """Why `name` cannot be served in public mode, or ``None`` if it can."""
    if tlsnames.is_ip_literal(name):
        return "is an IP literal; public mode serves DNS names only"
    if tlsnames.is_in_cluster_name(name):
        return "is the in-cluster API name, which no public certificate covers"
    if "." not in name:
        return "is a single-label name; a served name needs at least two labels"
    if not tlsnames.is_dns_name(name):
        return "is not a valid DNS name (lowercase letters, digits and '-' in each label)"
    if tlsnames.zone_of(name, zones) is None:
        return f"is outside every public_tls zone {zones}"
    return None


def unused_public_certificates(state: SeedConfig) -> list[str]:
    """Names of the public certificates whose `names` match no served name, in list order.

    Pure and empty outside public mode. Callers choose where to log it; a validator that
    runs on every load must not.
    """
    if state.public_tls is None:
        return []
    served = [s.name for s in _served_names(state)]
    return [
        cert.name
        for cert in state.public_tls.certificates
        if not any(tlsnames.name_matches(p, name) for p in cert.names for name in served)
    ]


class EffectiveState(SeedConfig):
    """Seed ⊕ overlays, post-merge, fully validated — same shape as the seed."""
