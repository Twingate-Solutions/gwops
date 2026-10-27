"""`StateRegistry`: which Twingate objects gwops created, keyed ``"<kind>/<name>"``.

The registry is the reconciler's ownership ledger (``/data/state.json``): only object
ids recorded here are ever updated or deleted on the Twingate side, which is what keeps
gwops from ever touching resources a human created in the admin console. Keys are
``<kind>/<name>`` for synced resources (``ssh/web-1``, ``kubernetes/prod``, ... — see
`gwops.kinds`), plus ``ca/x509`` and ``ca/ssh`` for the CA registrations bound to the
gateway and ``gateway/self`` for the resolved gateway.

It also records, per resource, the last-applied access (group ids and security-policy id
gwops itself set). Access changes are applied as a delta against that record, so gwops
only ever removes a group it added. On disk::

    {"version": 2,
     "ids": {"ssh/web-1": "<id>", ...},
     "access": {"ssh/web-1": {"groups": ["<id>", ...], "security_policy": "<id>" | null}}}

A flat ``{key: id}`` file (version 1) loads as ``ids`` with no access records and is
rewritten as version 2 on the next write.

Writes are atomic (tmp file + rename) and synchronous, so a crash between a Twingate
create and the next reconcile never forgets an object gwops already owns. A corrupt file
or an unknown version raises at load rather than guessing about ownership.
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_VERSION = 2


@dataclass(frozen=True)
class AppliedAccess:
    """The access gwops last applied to one resource."""

    groups: frozenset[str] = frozenset()
    security_policy: str | None = None


def _is_str_map(value: Any) -> bool:
    return isinstance(value, dict) and all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    )


def _parse_access(path: Path, raw: Any) -> dict[str, AppliedAccess]:
    if not isinstance(raw, dict):
        raise ValueError(f"state registry {path}: 'access' must be a JSON object")
    parsed: dict[str, AppliedAccess] = {}
    for key, record in raw.items():
        groups = record.get("groups") if isinstance(record, dict) else None
        policy = record.get("security_policy") if isinstance(record, dict) else None
        if not (
            isinstance(groups, list)
            and all(isinstance(g, str) for g in groups)
            and (policy is None or isinstance(policy, str))
        ):
            raise ValueError(
                f"state registry {path}: access record {key!r} must be "
                '{"groups": [ids], "security_policy": id|null}'
            )
        parsed[key] = AppliedAccess(groups=frozenset(groups), security_policy=policy)
    return parsed


class StateRegistry:
    """Durable ownership ledger: ``"<kind>/<name>" -> TG object id`` + last-applied access."""

    def __init__(self, path: Path) -> None:
        """Bind to `path`, loading existing state; a missing file is an empty registry.

        Raises `ValueError` if the file exists but is neither a legacy flat mapping nor
        a well-formed v2 document — fail loud rather than mis-guess ownership.
        """
        self._path = path
        self._ids: dict[str, str] = {}
        self._access: dict[str, AppliedAccess] = {}
        if not path.is_file():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"state registry {path} is corrupt (invalid JSON: {exc}); refusing to "
                "guess which Twingate objects gwops owns. Restore or remove the file."
            ) from exc
        if isinstance(raw, dict) and "version" in raw:
            if raw["version"] != _VERSION:
                raise ValueError(
                    f"state registry {path} has unknown version {raw['version']!r} "
                    f"(this gwops understands {_VERSION}); refusing to guess ownership."
                )
            if not _is_str_map(raw.get("ids")):
                raise ValueError(
                    f"state registry {path}: 'ids' must map string keys to string ids; "
                    "refusing to guess which Twingate objects gwops owns."
                )
            self._ids = dict(raw["ids"])
            self._access = _parse_access(path, raw.get("access", {}))
            return
        if not _is_str_map(raw):
            raise ValueError(
                f"state registry {path} must be a flat JSON mapping of string keys to "
                "string ids; refusing to guess which Twingate objects gwops owns."
            )
        self._ids = dict(raw)

    def managed_ids(self) -> dict[str, str]:
        """Return a copy of every managed ``"<kind>/<name>" -> id`` entry."""
        return dict(self._ids)

    def record(self, kind: str, name: str, resource_id: str) -> None:
        """Record (or overwrite) ownership of one Twingate object; immediately durable."""
        self._ids[f"{kind}/{name}"] = resource_id
        self._save()
        logger.info("registry.recorded", kind=kind, name=name, resource_id=resource_id)

    def forget(self, kind: str, name: str) -> None:
        """Drop ownership (and last-applied access) of one object; no-op if unrecorded."""
        key = f"{kind}/{name}"
        removed = self._ids.pop(key, None)
        had_access = self._access.pop(key, None) is not None
        if removed is None and not had_access:
            return
        self._save()
        logger.info("registry.forgotten", kind=kind, name=name, resource_id=removed)

    def last_access(self, key: str) -> AppliedAccess:
        """The access gwops last applied to `key` (empty when never recorded)."""
        return self._access.get(key, AppliedAccess())

    def record_access(self, key: str, access: AppliedAccess) -> None:
        """Record what gwops just applied to `key`; immediately durable."""
        self._access[key] = access
        self._save()
        logger.info(
            "registry.access_recorded",
            key=key,
            groups=sorted(access.groups),
            security_policy=access.security_policy,
        )

    def _save(self) -> None:
        """Atomically persist the v2 document (tmp file + rename, fsync'd)."""
        document = {
            "version": _VERSION,
            "ids": self._ids,
            "access": {
                key: {"groups": sorted(a.groups), "security_policy": a.security_policy}
                for key, a in sorted(self._access.items())
            },
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._path.with_name(self._path.name + ".tmp")
        try:
            with tmp_path.open("w", encoding="utf-8") as handle:
                json.dump(document, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self._path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
