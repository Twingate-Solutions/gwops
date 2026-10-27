"""Pure DNS-name predicates and certificate-coverage lookup for public mode.

Shared by the seed rules (``configmodel.schema``), material validation and the status and
readiness code. It imports nothing from gwops, so ``configmodel`` and ``certs`` can both
use it without importing each other.

Matching follows Go's ``crypto/x509`` ``VerifyHostname``, which is what the gateway
binary's TLS stack applies: a pattern's leftmost label may be exactly ``*``, which matches
exactly one non-empty label; ``*`` anywhere else, or as part of a label, matches nothing.
"""

import ipaddress
import re
from collections.abc import Iterable
from typing import Protocol

_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_IN_CLUSTER_NAME = "kubernetes.default.svc"


class _HasNames(Protocol):
    """Anything declaring the DNS names it covers (a ``PublicCertificate``)."""

    @property
    def names(self) -> list[str]: ...


def is_dns_label(label: str) -> bool:
    """Whether ``label`` is a lowercase ASCII LDH label of 1-63 characters.

    No leading or trailing hyphen and no underscore; internationalised names must already
    be in A-label (``xn--``) form.
    """
    return _LABEL_RE.fullmatch(label) is not None


def is_dns_name(name: str) -> bool:
    """Whether ``name`` is a concrete DNS name: two or more labels, each a valid label.

    No wildcard, no trailing dot, lowercase only.
    """
    labels = name.split(".")
    return len(labels) >= 2 and all(is_dns_label(label) for label in labels)


def is_zone(zone: str) -> bool:
    """Whether ``zone`` is a valid zone: a concrete DNS name (lowercase A-labels, two or more)."""
    return is_dns_name(zone)


def is_ip_literal(value: str) -> bool:
    """Whether ``value`` parses as an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_in_cluster_name(name: str) -> bool:
    """Whether ``name`` is the Kubernetes in-cluster API name, which no public zone holds."""
    return name == _IN_CLUSTER_NAME


def in_zone(name: str, zone: str) -> bool:
    """Whether ``name`` is the zone's apex or sits below it at a label boundary."""
    return name == zone or name.endswith("." + zone)


def zone_of(name: str, zones: Iterable[str]) -> str | None:
    """The first of ``zones`` that contains ``name``, or ``None``."""
    return next((zone for zone in zones if in_zone(name, zone)), None)


def is_certificate_name(name: str) -> bool:
    """Whether ``name`` is a valid certificate name: a concrete DNS name or ``*.<dns name>``."""
    return is_dns_name(name.removeprefix("*."))


def wildcard_parent(name: str) -> str:
    """The name a certificate name is anchored at: ``name`` without a leading ``*.``."""
    return name.removeprefix("*.")


def name_matches(pattern: str, name: str) -> bool:
    """Whether certificate name ``pattern`` covers the served ``name``.

    Case-insensitive, one trailing dot ignored. A literal ``*`` in ``name`` is never
    matched: ``name`` is a host being dialled, not a pattern.
    """
    pattern_labels = pattern.lower().removesuffix(".").split(".")
    name_labels = name.lower().removesuffix(".").split(".")
    if not all(pattern_labels) or not all(name_labels) or "*" in name:
        return False
    if len(pattern_labels) != len(name_labels):
        return False
    # Every other `*` placement (partial label, non-leftmost) can never equal a label of
    # `name`, which holds no `*`, so label equality refuses it without a special case.
    leftmost_wildcard = pattern_labels[0] == "*" and len(pattern_labels) > 1
    if leftmost_wildcard:
        return pattern_labels[1:] == name_labels[1:]
    return pattern_labels == name_labels


def covering_certificates[C: _HasNames](name: str, certs: Iterable[C]) -> list[C]:
    """Every certificate in ``certs`` with a declared name that covers ``name``, in order."""
    return [cert for cert in certs if any(name_matches(p, name) for p in cert.names)]


def covering_certificate[C: _HasNames](name: str, certs: Iterable[C]) -> C | None:
    """The first certificate in ``certs`` covering ``name``, or ``None``.

    Public mode refuses overlap, so a valid configuration has at most one.
    """
    return next(iter(covering_certificates(name, certs)), None)
