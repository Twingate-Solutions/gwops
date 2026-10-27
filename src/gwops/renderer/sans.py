"""Compute the SAN set the gateway's TLS leaf certificate must carry.

The Twingate Client terminates Client<->Gateway TLS and verifies hostname against the
leaf's SAN using the resource address it is dialing, not the gateway's own address.
So the leaf must list every upstream address and web-app alias the gateway fronts.
"""

from gwops.configmodel.schema import EffectiveState
from gwops.kinds import KINDS


def strip_port(address: str) -> str:
    """Drop a trailing ``:port`` from a schema-validated ``host[:port]`` address.

    Also used by :mod:`gwops.renderer.desired` for Twingate resource addresses.
    """
    host, _sep, _port = address.partition(":")
    return host


def required_sans(state: EffectiveState) -> set[str]:
    """Return every SAN (IPs and DNS names) the gateway's leaf must cover.

    The union of :meth:`~gwops.configmodel.schema.UpstreamEntry.san_names` over every
    entry of every resource kind (``gwops.kinds.KINDS``): by default the portless
    upstream address, plus a web app's alias, deduplicated. Whether a name becomes an IP
    or DNS SAN is decided when the certificate is minted; this returns the flat set.
    """
    return {
        name for kind in KINDS for entry in kind.entries(state) for name in entry.san_names()
    }
