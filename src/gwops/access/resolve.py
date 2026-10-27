"""Turn group / security-policy references into Twingate ids.

Two entry points, matching the two places references come from:

- :func:`pin_patch_access` — **request time**, for admin-API overlay writes. Every
  reference in the patch's upstream entries is resolved against the tenant and rewritten
  to the pinned ``{id, name}`` form *before* the overlay is persisted, so a typo is a
  synchronous 422 and a group created later under the same name can never capture the
  access. Explicit ids are verified to exist (and their name refreshed).
- :class:`AccessResolver` — **reconcile time**, for seed-declared entries and
  ``twingate.resource_defaults`` (the seed is read-only, so its names cannot be pinned on
  disk). Pinned/explicit ids pass straight through; successful name lookups are cached
  for the process lifetime, failures are not cached so a fix in the console is picked up
  on the next pass.

Names match exactly; zero or more than one match is an :class:`AccessResolutionError`.
"""

from collections.abc import Awaitable, Callable
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from gwops.access.precedence import EffectiveAccess, Ref
from gwops.kinds import KINDS
from gwops.tgapi import ops
from gwops.tgapi.client import TGClient

GROUP = "group"
SECURITY_POLICY = "security policy"

_FIND_BY_NAME: dict[str, Callable[[TGClient, str], Awaitable[list[str]]]] = {
    GROUP: ops.find_group_ids_by_name,
    SECURITY_POLICY: ops.find_security_policy_ids_by_name,
}
_NAME_BY_ID: dict[str, Callable[[TGClient, str], Awaitable[str | None]]] = {
    GROUP: ops.get_group_name,
    SECURITY_POLICY: ops.get_security_policy_name,
}


class AccessResolutionError(ValueError):
    """A reference names no object, more than one object, or a missing id (bad input)."""


class AccessUnavailableError(RuntimeError):
    """References need resolving but there is no Twingate API client (no API key)."""


@dataclass(frozen=True)
class ResolvedAccess:
    """:class:`EffectiveAccess` with every reference resolved to an id.

    ``group_ids`` is ``None`` when groups are not managed; ``security_policy_id`` is
    ``None`` when the policy is not managed.
    """

    group_ids: frozenset[str] | None
    security_policy_id: str | None


async def lookup_by_name(tg: TGClient, what: str, name: str) -> str:
    """The id of the one `what` (group / security policy) named exactly `name`."""
    ids = await _FIND_BY_NAME[what](tg, name)
    if not ids:
        raise AccessResolutionError(f"no {what} named {name!r}")
    if len(ids) > 1:
        raise AccessResolutionError(
            f"{len(ids)} {what}s are named {name!r}; reference it by id ({{id: ...}})"
        )
    return ids[0]


class AccessResolver:
    """Reconcile-time resolution with a process-lifetime name -> id cache."""

    def __init__(self) -> None:
        self._cache: dict[tuple[str, str], str] = {}

    async def resolve(self, tg: TGClient, access: EffectiveAccess) -> ResolvedAccess:
        """Resolve every reference in `access`; raises on the first unresolvable one."""
        group_ids = (
            None
            if access.groups is None
            else frozenset([await self._id(tg, GROUP, ref) for ref in access.groups])
        )
        policy_id = (
            None
            if access.security_policy is None
            else await self._id(tg, SECURITY_POLICY, access.security_policy)
        )
        return ResolvedAccess(group_ids=group_ids, security_policy_id=policy_id)

    async def ids(self, tg: TGClient, what: str, refs: list[Ref]) -> frozenset[str]:
        """Resolve a list of references of one type (e.g. an allowlist) to ids."""
        return frozenset([await self._id(tg, what, ref) for ref in refs])

    async def _id(self, tg: TGClient, what: str, ref: Ref) -> str:
        if ref.id:
            return ref.id
        assert ref.name  # ResourceRef guarantees an id or a name
        key = (what, ref.name)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        resolved = await lookup_by_name(tg, what, ref.name)
        self._cache[key] = resolved
        return resolved


def _has_refs(patch: dict[str, Any]) -> bool:
    for _items, access in _access_blocks(patch):
        if access.get("groups") or access.get("security_policy") is not None:
            return True
    return False


def _access_blocks(patch: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """(entry, access) for every upstream entry in `patch` that carries an access block."""
    blocks = []
    for kind in KINDS:
        for entry in patch.get(kind.state_field) or []:
            if isinstance(entry, dict) and isinstance(entry.get("access"), dict):
                blocks.append((entry, entry["access"]))
    return blocks


async def _pin(tg: TGClient, what: str, raw: Any) -> dict[str, str]:
    """Resolve one raw (schema-valid) reference to its pinned ``{id, name}`` form."""
    if isinstance(raw, str):
        raw = {"name": raw}
    ref_id, name = raw.get("id"), raw.get("name")
    if ref_id:
        current = await _NAME_BY_ID[what](tg, ref_id)
        if current is None:
            raise AccessResolutionError(f"no {what} with id {ref_id!r}")
        return {"id": ref_id, "name": current}
    return {"id": await lookup_by_name(tg, what, name), "name": name}


async def pin_patch_access(tg: TGClient | None, patch: dict[str, Any]) -> dict[str, Any]:
    """Return `patch` with every access reference pinned to ``{id, name}``.

    A patch with no references is returned unchanged without any TG call. Raises
    :class:`AccessUnavailableError` when references are present but `tg` is None,
    :class:`AccessResolutionError` for a bad reference, and lets
    :class:`~gwops.tgapi.errors.TGAPIError` (tenant unreachable) propagate.
    """
    if not _has_refs(patch):
        return patch
    if tg is None:
        raise AccessUnavailableError(
            "access references need the Twingate API to resolve, but TWINGATE_API_KEY "
            "is not set"
        )
    pinned = deepcopy(patch)
    for _entry, access in _access_blocks(pinned):
        if access.get("groups"):
            access["groups"] = [await _pin(tg, GROUP, raw) for raw in access["groups"]]
        if access.get("security_policy") is not None:
            access["security_policy"] = await _pin(
                tg, SECURITY_POLICY, access["security_policy"]
            )
    return pinned
