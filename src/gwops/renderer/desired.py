"""Compute the desired Twingate resource objects for the effective state.

One :class:`DesiredResource` per upstream entry of every kind in :data:`gwops.kinds.KINDS`,
the shape :mod:`gwops.tgapi` reconciles against the network's actual resources.
Twingate resource addresses are portless, so any port suffix is stripped. The port the
gateway dials is carried separately as ``upstream_port``: the gateway takes it from the
Twingate resource's ``upstream.port``, not from the rendered config. ``access`` is the
entry's effective group and security-policy references after applying
``twingate.resource_defaults``; the reconciler resolves them to ids.
"""

from dataclasses import dataclass, field

from gwops.access.precedence import UNMANAGED, EffectiveAccess, effective_access
from gwops.configmodel.schema import EffectiveState
from gwops.kindhooks import EMPTY_EXTRAS, Extras, normalise_extras
from gwops.kinds import KINDS
from gwops.renderer.sans import strip_port


@dataclass(frozen=True)
class DesiredResource:
    """One Twingate resource gwops wants to exist, keyed by (kind, name)."""

    kind: str
    name: str
    address: str
    upstream_port: int
    access: EffectiveAccess = field(default=UNMANAGED)
    extras: Extras = field(default_factory=lambda: EMPTY_EXTRAS, compare=False, hash=False)
    """Normalised ``entry.tg_extras()``; excluded from eq/hash."""

    @property
    def key(self) -> str:
        """The ``<kind>/<name>`` registry key."""
        return f"{self.kind}/{self.name}"


def desired_tg_objects(state: EffectiveState) -> list[DesiredResource]:
    """Return the desired Twingate resource list, kind by kind in :data:`KINDS` order.

    Addresses are portless. ``upstream_port`` comes from the entry
    (:meth:`~gwops.configmodel.schema.UpstreamEntry.upstream_port`): an SSH address's
    ``:port`` (default 22), or a cluster's ``port`` field (default 443).
    """
    defaults = state.twingate.resource_defaults
    return [
        DesiredResource(
            kind=kind.key,
            name=entry.name,
            address=strip_port(entry.address),
            upstream_port=entry.upstream_port(),
            access=effective_access(entry.access, defaults),
            extras=normalise_extras(entry.tg_extras()),
        )
        for kind in KINDS
        for entry in kind.entries(state)
    ]
