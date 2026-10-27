"""Effective access for one resource: its own ``access`` block over the seed defaults.

Applied independently to ``groups`` and to ``security_policy``:

========================  ==============================================================
Per-upstream value        Result
========================  ==============================================================
present, non-empty        used as-is; **replaces** the default (never merged with it)
``groups: []``            no groups, even when a default exists
omitted (or ``null``)     the ``twingate.resource_defaults`` value
omitted, no default       not managed: gwops sends nothing and never changes it
========================  ==============================================================
"""

from dataclasses import dataclass

from gwops.configmodel.schema import AccessSpec, ResourceRef


@dataclass(frozen=True)
class Ref:
    """A hashable copy of a :class:`ResourceRef` (``id`` wins when both are set)."""

    id: str | None
    name: str | None

    @classmethod
    def of(cls, ref: ResourceRef) -> "Ref":
        """Copy a config-model reference."""
        return cls(id=ref.id or None, name=ref.name or None)

    def __str__(self) -> str:
        if self.id and self.name:
            return f"{self.name!r} ({self.id})"
        return repr(self.name) if self.name else f"id {self.id}"


@dataclass(frozen=True)
class EffectiveAccess:
    """The access gwops manages on one resource.

    ``groups`` is ``None`` when groups are not managed at all (as opposed to ``()``,
    managed and empty); ``security_policy`` is ``None`` when the policy is not managed.
    """

    groups: tuple[Ref, ...] | None = None
    security_policy: Ref | None = None


UNMANAGED = EffectiveAccess()


def effective_access(entry: AccessSpec | None, defaults: AccessSpec | None) -> EffectiveAccess:
    """Apply the precedence table to one resource's `entry` access and the seed `defaults`."""
    groups_src = entry.groups if entry is not None and entry.groups is not None else None
    if groups_src is None and defaults is not None:
        groups_src = defaults.groups
    policy_src = entry.security_policy if entry is not None else None
    if policy_src is None and defaults is not None:
        policy_src = defaults.security_policy
    return EffectiveAccess(
        groups=None if groups_src is None else tuple(Ref.of(r) for r in groups_src),
        security_policy=None if policy_src is None else Ref.of(policy_src),
    )
