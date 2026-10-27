"""OverlayStore: one JSON file per overlay, atomic writes, lexical ordering.

Overlay ids are ``<zero-padded counter>-<slug>`` so lexical filename order equals
application order. Writes go to a ``.tmp`` sibling first and are renamed into
place; a leftover ``.tmp`` from a crash is ignored by :meth:`OverlayStore.list`.
"""

import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

Origin = Literal["admin", "automation"]

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_ID_COUNTER_RE = re.compile(r"^(\d{4})-")
_MAX_SLUG_LEN = 40

# Overlay ids are `<4-digit counter>-<slug>`. `delete` validates caller-supplied ids
# against this so a traversal or absolute-path id can never resolve outside the store.
_VALID_ID_RE = re.compile(r"^\d{4}-[a-z0-9-]+$")

# `add` rejects patches beyond these bounds: excess nesting would overflow the
# recursion in `merge` at every startup.
_MAX_PATCH_DEPTH = 32
_MAX_PATCH_BYTES = 256 * 1024


def _patch_depth(value: Any, _depth: int = 1) -> int:
    """Return the maximum nesting depth of dicts/lists within ``value``.

    A scalar has depth 0; ``{"a": 1}`` has depth 1; ``{"a": {"b": 1}}`` has depth 2.
    Bounded internally by :data:`_MAX_PATCH_DEPTH` + 1 so a pathological input cannot
    itself overflow the stack while being measured.
    """
    if _depth > _MAX_PATCH_DEPTH + 1:
        return _depth
    if isinstance(value, dict):
        return max((_patch_depth(v, _depth + 1) for v in value.values()), default=_depth)
    if isinstance(value, list):
        return max((_patch_depth(v, _depth + 1) for v in value), default=_depth)
    return _depth - 1


def _slugify(comment: str) -> str:
    slug = _SLUG_RE.sub("-", comment.lower()).strip("-")[:_MAX_SLUG_LEN].rstrip("-")
    return slug or "overlay"


@dataclass
class Overlay:
    """One persisted admin-API mutation, applied on top of the seed."""

    id: str
    created_at: datetime
    comment: str
    patch: dict[str, Any]
    origin: Origin = "admin"
    """Which credential wrote it; files without an origin read as ``admin``."""


class OverlayStore:
    """Persistent, ordered collection of overlays under a single directory."""

    def __init__(self, dir: Path) -> None:
        self._dir = dir
        self._dir.mkdir(parents=True, exist_ok=True)

    def list(self) -> list[Overlay]:
        """Return all overlays in application order (lexical by filename)."""
        overlays: list[Overlay] = []
        for path in sorted(self._dir.glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            overlays.append(
                Overlay(
                    id=data["id"],
                    created_at=datetime.fromisoformat(data["created_at"]),
                    comment=data["comment"],
                    patch=data["patch"],
                    origin="automation" if data.get("origin") == "automation" else "admin",
                )
            )
        return overlays

    def add(
        self, patch: dict[str, Any], comment: str = "", origin: Origin = "admin"
    ) -> Overlay:
        """Persist a new overlay atomically and return it.

        Rejects with `ValueError` (before persisting anything) a patch nested deeper
        than :data:`_MAX_PATCH_DEPTH` or whose serialized JSON exceeds
        :data:`_MAX_PATCH_BYTES`.
        """
        serialized = json.dumps(patch, indent=2)
        size = len(serialized.encode("utf-8"))
        if size > _MAX_PATCH_BYTES:
            raise ValueError(
                f"overlay patch is too large: {size} bytes exceeds the "
                f"{_MAX_PATCH_BYTES}-byte limit; split or trim the patch."
            )
        depth = _patch_depth(patch)
        if depth > _MAX_PATCH_DEPTH:
            raise ValueError(
                f"overlay patch is nested too deeply: depth {depth} exceeds the "
                f"{_MAX_PATCH_DEPTH}-level limit; flatten the patch."
            )
        overlay = Overlay(
            id=f"{self._next_counter():04d}-{_slugify(comment)}",
            created_at=datetime.now(UTC),
            comment=comment,
            patch=patch,
            origin=origin,
        )
        self._write(overlay)
        return overlay

    def restore(self, overlay: Overlay) -> None:
        """Re-persist a previously deleted overlay under its ORIGINAL id.

        Used to roll back a failed delete: keeping the id keeps the overlay's place in
        application order, which re-adding via :meth:`add` (a fresh, highest id) would
        not. Raises `ValueError` for a malformed id and `FileExistsError` if an overlay
        with that id is already on disk.
        """
        if not _VALID_ID_RE.match(overlay.id):
            raise ValueError(f"invalid overlay id {overlay.id!r}")
        if (self._dir / f"{overlay.id}.json").exists():
            raise FileExistsError(overlay.id)
        self._write(overlay)

    def get(self, overlay_id: str) -> Overlay | None:
        """Return the overlay with `overlay_id`, or None if there is none."""
        return next((o for o in self.list() if o.id == overlay_id), None)

    def _write(self, overlay: Overlay) -> None:
        """Write one overlay file atomically (tmp + rename)."""
        final = self._dir / f"{overlay.id}.json"
        tmp = final.with_suffix(final.suffix + ".tmp")
        payload = {
            "id": overlay.id,
            "created_at": overlay.created_at.isoformat(),
            "comment": overlay.comment,
            "patch": overlay.patch,
            "origin": overlay.origin,
        }
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, final)

    def delete(self, overlay_id: str) -> None:
        """Remove an overlay by id.

        Raises `ValueError` for an id that does not match the overlay-id grammar
        (:data:`_VALID_ID_RE`) — a guard against path traversal or absolute-path ids
        forwarded from the admin API — and `KeyError` for a well-formed id with no
        matching overlay on disk. The id is validated before any filesystem access.
        """
        if not _VALID_ID_RE.match(overlay_id):
            raise ValueError(
                f"invalid overlay id {overlay_id!r}: must match "
                f"{_VALID_ID_RE.pattern} (a 4-digit counter and a lowercase slug)."
            )
        path = self._dir / f"{overlay_id}.json"
        if not path.is_file():
            raise KeyError(overlay_id)
        path.unlink()

    def _next_counter(self) -> int:
        """One past the highest counter ever seen on disk (deleted ids not reused
        unless they were the highest — good enough for a single-writer store)."""
        highest = 0
        for path in self._dir.glob("*.json"):
            m = _ID_COUNTER_RE.match(path.stem)
            if m:
                highest = max(highest, int(m.group(1)))
        return highest + 1
