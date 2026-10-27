"""Web-app policy: header rewrites, templates, TLS modes, CA bundles and automation fields.

Pure functions; no message ever carries a header value or PEM content. Must not import
``gwops.kinds``, ``gwops.tgapi`` or ``gwops.access.allowlist`` (import cycle).
Static-secret tripwire: a 20+ char token that is 32+ hex, or 3+ classes at 3.8+ bits/char.
"""

import ipaddress
import math
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import NamedTuple

from cryptography import x509

from gwops.configmodel.schema import AddressAllowlist, EffectiveState, WebApp
from gwops.logging import looks_secret
from gwops.renderer.capabilities import Capabilities

SECRET_MIN_LENGTH = 20
"""Shortest static token considered by the high-entropy secret rule."""
SECRET_MIN_ENTROPY = 3.8
"""Shannon entropy (bits per character) at or above which a mixed-class token is a secret."""
_HEX_SECRET_MIN_LENGTH = 32
MAX_TRUSTED_HEADER_SEPARATORS = 4
"""Most ``-``/``_`` separators a trusted gateway-wide header name may have (2^n render)."""

_GATEWAY_WIDE = "web_app_proxy.request_headers"
_JWT_RESTRICTED_MODES = frozenset({"none", "verify_ca", "insecure"})
_JWT_RISK: Mapping[str, str] = {
    "none": "the token would cross the network in plaintext",
    "verify_ca": "the upstream hostname is not checked, so any holder of a trusted certificate "
    "could receive the token",
    "insecure": "the upstream certificate is not verified, so anyone on the path could read "
    "the token",
}
_NAMES_FIELD = "admin_api.automation.web_apps.request_header_names"
_BUNDLES_FIELD = "web_app_proxy.upstream_ca_bundles"

# The upstream app trusts headers carrying these, so no per-resource override is allowed.
_IDENTITY_KEYS = frozenset({"jwt", "username", "groups"})

# Names compare lowercased with "_" folded to "-": WSGI/PHP/Rack treat both spellings as one.
_DENIED_EXACT: Mapping[str, str] = {
    "connection": "hop-by-hop or framing header",
    "keep-alive": "hop-by-hop or framing header",
    "te": "hop-by-hop or framing header",
    "trailer": "hop-by-hop or framing header",
    "transfer-encoding": "hop-by-hop or framing header",
    "upgrade": "hop-by-hop or framing header",
    "content-length": "hop-by-hop or framing header",
    "expect": "hop-by-hop or framing header",
    "forwarded": "forwarding header",
    "x-real-ip": "forwarding header",
    "via": "forwarding header",
    "x-original-url": "routing override header",
    "x-rewrite-url": "routing override header",
    "x-http-method-override": "routing override header",
    "cookie": "cookie header",
    "host": "Host header",
}
_DENIED_PREFIXES: tuple[tuple[str, str], ...] = (
    ("proxy-", "hop-by-hop or framing header"),
    ("x-forwarded-", "forwarding header"),
)

# Mirrors upstream template.go: Go's \s has no \v, and its $ is end-only (hence fullmatch).
_TEMPLATE_RE = re.compile(r"([^{}]*)\{\{[\t\n\f\r ]*([a-zA-Z0-9_-]+)[\t\n\f\r ]*\}\}([^{}]*)")
_JWT_ANYWHERE_RE = re.compile(r"\{\{[\t\n\f\r ]*jwt[\t\n\f\r ]*\}\}", re.IGNORECASE)
_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_PEM_BLOCK_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", re.DOTALL)


@dataclass(frozen=True)
class FieldViolation:
    """One automation field-policy refusal: the field path and a fixed reason (never a value)."""

    field: str
    reason: str


class _Parsed(NamedTuple):
    """A header value classified by the upstream template grammar."""

    kind: str  # "static" | "template" | "malformed"
    key: str = ""
    prefix: str = ""
    suffix: str = ""


def _parse(value: str) -> _Parsed:
    if "{" not in value and "}" not in value:
        return _Parsed("static", prefix=value)
    match = _TEMPLATE_RE.fullmatch(value)
    if match is None:
        return _Parsed("malformed")
    return _Parsed("template", key=match.group(2), prefix=match.group(1), suffix=match.group(3))


def _fold(name: str) -> str:
    return name.lower().replace("_", "-")


def separator_count(name: str) -> int:
    """How many ``-`` or ``_`` separators `name` contains."""
    return sum(char in "-_" for char in name)


def _denied_category(name: str) -> str | None:
    folded = _fold(name)
    if folded in _DENIED_EXACT:
        return _DENIED_EXACT[folded]
    for prefix, category in _DENIED_PREFIXES:
        if folded.startswith(prefix):
            return category
    return None


def is_denied_header_name(name: str) -> bool:
    """Whether ``name`` is a header gwops never lets a rewrite set (any case, ``_`` or ``-``)."""
    return _denied_category(name) is not None


def trusted_gateway_header_names(state: EffectiveState) -> frozenset[str]:
    """The gateway-wide header names whose template uses ``username``, ``groups`` or ``jwt``."""
    return frozenset(
        name
        for name, value in state.web_app_proxy.request_headers.items()
        if (parsed := _parse(value)).kind == "template" and parsed.key in _IDENTITY_KEYS
    )


def is_trusted_header_name(name: str, state: EffectiveState) -> bool:
    """Whether ``name`` is a gateway-wide identity header name (case and ``_``/``-`` folded)."""
    return _fold(name) in {_fold(n) for n in trusted_gateway_header_names(state)}


def _shannon_entropy(text: str) -> float:
    counts = Counter(text)
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def _classes(text: str) -> int:
    return sum(
        (
            any(c.islower() for c in text),
            any(c.isupper() for c in text),
            any(c.isdigit() for c in text),
            any(not c.isalnum() for c in text),
        )
    )


def _looks_like_secret_text(text: str) -> bool:
    """Whether static text holds a long all-hex token or a long mixed-class high-entropy one."""
    for token in text.split():
        if len(token) < SECRET_MIN_LENGTH:
            continue
        if (
            len(token) >= _HEX_SECRET_MIN_LENGTH
            and _HEX_RE.fullmatch(token)
            and any(c.isdigit() for c in token)
            and any(c.isalpha() for c in token)
        ):
            return True
        if _classes(token) >= 3 and _shannon_entropy(token) >= SECRET_MIN_ENTROPY:
            return True
    return False


def _host_allowed(host: str, allowlist: AddressAllowlist) -> bool:
    # Restates allowlist.address_allowed; importing it would form a cycle.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return any(host == s or host.endswith("." + s) for s in allowlist.dns_suffixes)
    return any(ip in ipaddress.ip_network(c, strict=False) for c in allowlist.cidrs)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _check_headers(
    headers: Mapping[str, str],
    where: str,
    caps: Capabilities,
    trusted: frozenset[str],
    *,
    gateway_wide: bool,
) -> list[str]:
    """Policy violations for one header map. ``where`` names the location; never a value."""
    found: list[str] = []
    trusted_folded = {_fold(n) for n in trusted}
    supported = ", ".join(sorted(caps.web_app_template_keys))
    for name, value in headers.items():
        if (category := _denied_category(name)) is not None:
            found.append(f"{where}: header {name!r} is denied ({category})")
        parsed = _parse(value)
        match parsed.kind:
            case "malformed":
                found.append(
                    f"{where}: the value of header {name!r} is not a valid template "
                    "(use static text, or text around one {{key}}; no other braces)"
                )
            case "template":
                if parsed.key not in caps.web_app_template_keys:
                    found.append(
                        f"{where}: the value of header {name!r} uses a template key the "
                        f"gateway does not support (supported, case-sensitive: {supported})"
                    )
                elif gateway_wide and parsed.key == "jwt":
                    found.append(
                        f"{where}: header {name!r} must not use {{{{jwt}}}} gateway-wide "
                        "(it would overwrite apps' Authorization headers and send the token to "
                        "every upstream); set it per web app instead"
                    )
                if _looks_like_secret_text(parsed.prefix + " " + parsed.suffix):
                    found.append(
                        f"{where}: the static text in the value of header {name!r} looks like "
                        "a secret (long, high-entropy)"
                    )
            case _:
                if not value.strip():
                    found.append(f"{where}: the value of header {name!r} is empty")
                elif looks_secret(name):
                    found.append(
                        f"{where}: header {name!r} has a static value under a secret-like "
                        "name; use a template key instead"
                    )
                elif _looks_like_secret_text(value):
                    found.append(
                        f"{where}: the static value of header {name!r} looks like a secret "
                        "(long, high-entropy); use a template key instead"
                    )
        if not gateway_wide and _fold(name) in trusted_folded:
            found.append(
                f"{where}: header {name!r} is a trusted gateway-wide name (it carries identity); "
                "a per-resource rewrite would override it"
            )
    return found


_ENTRY_WHERE_PREFIX = "web_apps entry "


def _entry_where(entry: WebApp) -> str:
    return f"{_ENTRY_WHERE_PREFIX}{entry.name!r}"


def names_an_entry(violation: str) -> bool:
    """Whether a violation message is about one web-app entry (and so names it)."""
    return violation.startswith(_ENTRY_WHERE_PREFIX)


def _jwt_header_names(headers: Mapping[str, str]) -> list[str]:
    return [
        name
        for name, value in headers.items()
        if (parsed := _parse(value)).kind == "template" and parsed.key == "jwt"
    ]


def _tls_violations(entry: WebApp, state: EffectiveState) -> list[str]:
    where = _entry_where(entry)
    host = entry.address.partition(":")[0]
    found: list[str] = []
    mode = entry.upstream_tls
    if mode in ("insecure", "none"):
        allowed = state.web_app_proxy.plaintext_upstreams
        if allowed is None or not _host_allowed(host, allowed):
            found.append(
                f"{where}: upstream_tls {mode!r} requires the address host to be allowed by "
                "web_app_proxy.plaintext_upstreams"
            )
    if mode in _JWT_RESTRICTED_MODES and not _is_loopback(host):
        jwt_names = _jwt_header_names(state.web_app_proxy.request_headers) + _jwt_header_names(
            entry.request_headers or {}
        )
        if jwt_names:
            shown = ", ".join(repr(n) for n in sorted(set(jwt_names)))
            found.append(
                f"{where}: upstream_tls {mode!r} must not carry a {{{{jwt}}}} header (header "
                f"{shown}) unless the upstream host is loopback: {_JWT_RISK[mode]}"
            )
    return found


def violations(state: EffectiveState, caps: Capabilities) -> list[str]:
    """Every web-app policy violation in ``state``, in stable order; empty means clean."""
    trusted = trusted_gateway_header_names(state)
    found = _check_headers(
        state.web_app_proxy.request_headers, _GATEWAY_WIDE, caps, trusted, gateway_wide=True
    )
    for entry in state.web_apps:
        where = f"{_entry_where(entry)}, request_headers"
        if entry.request_headers:
            found.extend(
                _check_headers(entry.request_headers, where, caps, trusted, gateway_wide=False)
            )
        found.extend(_tls_violations(entry, state))
    found.extend(_separator_limit_violations(trusted))
    found.extend(_automation_name_violations(state, trusted))
    return found


def _separator_limit_violations(trusted: frozenset[str]) -> list[str]:
    return [
        f"{_GATEWAY_WIDE}: trusted header {name!r} has more than "
        f"{MAX_TRUSTED_HEADER_SEPARATORS} separators ('-' or '_'); the limit is "
        f"{MAX_TRUSTED_HEADER_SEPARATORS} because every spelling of the name is rendered"
        for name in sorted(trusted, key=lambda n: (n.lower(), n))
        if separator_count(name) > MAX_TRUSTED_HEADER_SEPARATORS
    ]


def _automation_name_violations(state: EffectiveState, trusted: frozenset[str]) -> list[str]:
    trusted_folded = {_fold(n) for n in trusted}
    found: list[str] = []
    for name in state.admin_api.automation.web_apps.request_header_names:
        if (category := _denied_category(name)) is not None:
            found.append(f"{_NAMES_FIELD}: header name {name!r} is denied ({category})")
        elif _fold(name) in trusted_folded:
            found.append(
                f"{_NAMES_FIELD}: header name {name!r} is a trusted gateway-wide name "
                "(it carries identity)"
            )
    return found


def entry_warnings(entry: WebApp) -> list[str]:
    """Allowed settings of one web app that weaken security; surfaced, never refused."""
    found: list[str] = []
    where = _entry_where(entry)
    match entry.upstream_tls:
        case "verify_ca":
            found.append(f"{where}: upstream_tls 'verify_ca' does not check the upstream hostname")
        case "insecure":
            found.append(
                f"{where}: upstream_tls 'insecure' does not verify the upstream certificate"
            )
        case "none":
            found.append(f"{where}: upstream_tls 'none' sends upstream traffic in plaintext")
    if entry.downstream.tls == "none":
        found.append(
            f"{where}: downstream.tls 'none' serves the app over http:// "
            "(Secure cookies break; the hop is inside the Twingate tunnel)"
        )
    return found


def warnings(state: EffectiveState) -> list[str]:
    """Allowed web-app settings that weaken security; surfaced, never refused."""
    return [warning for entry in state.web_apps for warning in entry_warnings(entry)]


def pem_violations(bundle_name: str, data: bytes, now: datetime) -> list[str]:
    """Violations in a CA bundle's bytes; empty means the bundle may be rendered.

    Content outside PEM blocks is refused: Go's ``AppendCertsFromPEM`` would skip it silently.
    """
    where = f"{_BUNDLES_FIELD}: bundle {bundle_name!r}"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [f"{where} is not PEM text (binary or non-UTF-8 content)"]

    found: list[str] = []
    certificates: list[str] = []
    other_blocks = private_keys = 0
    for match in _PEM_BLOCK_RE.finditer(text):
        label = match.group(1)
        if label == "CERTIFICATE":
            certificates.append(match.group(0))
        elif "PRIVATE KEY" in label:
            private_keys += 1
        else:
            other_blocks += 1
    if private_keys:
        found.append(f"{where} contains a private key block; only CERTIFICATE blocks are accepted")
    if other_blocks:
        found.append(f"{where} contains a non-CERTIFICATE PEM block; only CERTIFICATE is accepted")
    if _PEM_BLOCK_RE.sub("", text).strip():
        found.append(
            f"{where} has content outside its PEM blocks (comments, text or an unterminated block)"
        )
    if not certificates:
        found.append(f"{where} contains no CERTIFICATE block")
    for position, block in enumerate(certificates, start=1):
        found.extend(_certificate_violations(where, position, block, now))
    return found


def _certificate_violations(where: str, position: int, block: str, now: datetime) -> list[str]:
    label = f"{where}: certificate #{position}"
    try:
        cert = x509.load_pem_x509_certificate(block.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return [f"{label} does not parse as an X.509 certificate"]
    found: list[str] = []
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        found.append(f"{label} has no BasicConstraints extension (CA:TRUE is required)")
    except Exception:  # the parser raises several unrelated types, and only on access
        return [f"{label} has malformed or duplicate extensions"]
    else:
        if not is_ca:
            found.append(f"{label} is not a CA (BasicConstraints CA:FALSE; CA:TRUE is required)")
    reference = now if now.tzinfo is not None else now.replace(tzinfo=UTC)
    if reference > cert.not_valid_after_utc:
        found.append(f"{label} has expired (notAfter {cert.not_valid_after_utc:%Y-%m-%d})")
    elif reference < cert.not_valid_before_utc:
        found.append(f"{label} is not yet valid (notBefore {cert.not_valid_before_utc:%Y-%m-%d})")
    return found


def automation_field_violations(entry: WebApp, state: EffectiveState) -> list[FieldViolation]:
    """The automation token's per-field refusals for an effective web-app entry.

    ``entry`` must be the stored entry merged with the request, so omission smuggles nothing.
    """
    found: list[FieldViolation] = []
    if entry.upstream_tls != "verify_full":
        found.append(
            FieldViolation("upstream_tls", "only verify_full is allowed for the automation token")
        )
    if not entry.request_headers:
        return found
    allowed = {n.lower() for n in state.admin_api.automation.web_apps.request_header_names}
    trusted = {_fold(n) for n in trusted_gateway_header_names(state)}
    for name, value in entry.request_headers.items():
        field = f"request_headers.{name}"
        if name.lower() not in allowed:
            found.append(
                FieldViolation(
                    field,
                    "header name not in admin_api.automation.web_apps.request_header_names",
                )
            )
        elif is_denied_header_name(name) or _fold(name) in trusted:
            found.append(
                FieldViolation(field, "header name is denied or carries identity; never allowed")
            )
        if _JWT_ANYWHERE_RE.search(value):
            found.append(
                FieldViolation(
                    field, "the jwt template key is not allowed for the automation token"
                )
            )
    return found
