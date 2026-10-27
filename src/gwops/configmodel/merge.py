"""Deterministic layered merge of seed + overlays, with per-path provenance.

Merge rules:

- maps recurse;
- **top-level** lists whose items are all dicts carrying a ``name`` key (the per-kind
  upstream lists) merge **by name** — a patch item ``{"name": ..., "_delete": true}``
  removes the named entry;
- every other value (scalars, plain lists, and nested lists even of named dicts, such as
  an upstream's ``access.groups`` refs) is replaced wholesale, last layer wins. A nested
  list merged by name would union a pinned ``{id, name}`` group list across overlays,
  so a later declaration could never drop a group;
- except :data:`_ITEM_REPLACED_KEYS` maps inside a named-list item, which an overlay
  replaces wholesale so it can remove a header.

``Provenance`` maps dotted paths to the layer that last set them: ``"seed"`` or an
overlay id. Named-list items are addressed by name (``k8s_clusters.prod.port``),
never by index, so paths stay stable as lists grow and shrink.
"""

from copy import deepcopy
from typing import Any, TypeGuard

from gwops.configmodel.store import Overlay

Provenance = dict[str, str]

_DELETE_KEY = "_delete"
# Map-valued fields of a named-list item that an overlay replaces instead of deep-merging.
_ITEM_REPLACED_KEYS = frozenset({"request_headers"})
_SEED_LAYER = "seed"

# Depth guard for overlays already on disk: an over-deep one would raise an uncaught
# RecursionError at every startup. Kept above OverlayStore's _MAX_PATCH_DEPTH so any
# patch that add() accepted merges without tripping it.
_MAX_MERGE_DEPTH = 64


class MergeDepthError(ValueError):
    """A patch (or the seed) is nested deeper than :data:`_MAX_MERGE_DEPTH`."""


def _check_depth(depth: int, path: str) -> None:
    if depth > _MAX_MERGE_DEPTH:
        raise MergeDepthError(
            f"merge exceeded the maximum nesting depth of {_MAX_MERGE_DEPTH} at "
            f"{path or '<root>'!r}; the seed or an overlay patch is too deeply nested."
        )


def _verify_depth(value: Any, depth: int, path: str) -> None:
    """Raise :class:`MergeDepthError` if ``value`` nests beyond the cap.

    Called up front, before any ``deepcopy`` or merge recursion, so an over-deep
    seed or overlay surfaces as a clear ``ValueError`` instead of a ``RecursionError``
    from ``deepcopy`` (which the guards inside the merge recursion could not pre-empt).
    ``_check_depth`` runs at the top of every frame, so this itself stops descending
    one level past the cap rather than overflowing the stack.
    """
    _check_depth(depth, path)
    if isinstance(value, dict):
        for k, v in value.items():
            _verify_depth(v, depth + 1, _join(path, str(k)))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _verify_depth(item, depth + 1, _join(path, str(i)))


def _is_named_list(value: Any) -> TypeGuard[list[dict[str, Any]]]:
    return (
        isinstance(value, list)
        and len(value) > 0
        and all(isinstance(item, dict) and "name" in item for item in value)
    )


def _join(prefix: str, key: str) -> str:
    return f"{prefix}.{key}" if prefix else key


def _record_tree(
    value: Any, layer: str, path: str, prov: Provenance, depth: int = 0
) -> None:
    """Record provenance for every leaf under ``value`` as belonging to ``layer``."""
    _check_depth(depth, path)
    if isinstance(value, dict) and value:
        for k, v in value.items():
            _record_tree(v, layer, _join(path, str(k)), prov, depth + 1)
    elif _is_named_list(value) and "." not in path:
        for item in value:
            _record_tree(item, layer, _join(path, str(item["name"])), prov, depth + 1)
    else:
        prov[path] = layer


def _drop_subtree(path: str, prov: Provenance) -> None:
    """Remove provenance entries at ``path`` and everything beneath it."""
    child_prefix = path + "."
    for key in [k for k in prov if k == path or k.startswith(child_prefix)]:
        del prov[key]


def _merge_named_list(
    dst: list[dict[str, Any]],
    patch: list[dict[str, Any]],
    layer: str,
    path: str,
    prov: Provenance,
    depth: int = 0,
) -> list[dict[str, Any]]:
    _check_depth(depth, path)
    by_name = {item["name"]: item for item in dst}
    order = [item["name"] for item in dst]
    for patch_item in patch:
        name = patch_item["name"]
        item_path = _join(path, str(name))
        if patch_item.get(_DELETE_KEY):
            if name in by_name:
                del by_name[name]
                order.remove(name)
                _drop_subtree(item_path, prov)
        elif name in by_name:
            # "name" is the item's identity, not data — don't re-merge or re-attribute it
            data = {k: v for k, v in patch_item.items() if k not in ("name", _DELETE_KEY)}
            _merge_dict(by_name[name], data, layer, item_path, prov, depth + 1, is_item=True)
        else:
            new_item = deepcopy(
                {k: v for k, v in patch_item.items() if k != _DELETE_KEY}
            )
            by_name[name] = new_item
            order.append(name)
            _record_tree(new_item, layer, item_path, prov, depth + 1)
    return [by_name[name] for name in order]


def _merge_dict(
    dst: dict[str, Any],
    patch: dict[str, Any],
    layer: str,
    path: str,
    prov: Provenance,
    depth: int = 0,
    is_item: bool = False,
) -> None:
    """Merge ``patch`` into ``dst``; ``is_item`` marks ``dst`` as a named-list item."""
    _check_depth(depth, path)
    for key, value in patch.items():
        key_path = _join(path, str(key))
        existing = dst.get(key)
        if is_item and key in _ITEM_REPLACED_KEYS:
            _drop_subtree(key_path, prov)
            dst[key] = deepcopy(value)
            _record_tree(dst[key], layer, key_path, prov, depth + 1)
        elif isinstance(value, dict) and isinstance(existing, dict):
            _merge_dict(existing, value, layer, key_path, prov, depth + 1)
        elif not path and _is_named_list(value) and (
            _is_named_list(existing) or existing is None or existing == []
        ):
            # Merging by name even against an empty/absent list strips `_delete` markers
            # instead of copying them into the config.
            base = existing if _is_named_list(existing) else []
            dst[key] = _merge_named_list(base, value, layer, key_path, prov, depth + 1)
        else:
            _drop_subtree(key_path, prov)
            dst[key] = deepcopy(value)
            _record_tree(dst[key], layer, key_path, prov, depth + 1)


def merge_layers(
    seed: dict[str, Any], overlays: list[Overlay]
) -> tuple[dict[str, Any], Provenance]:
    """Merge overlays onto the seed in order; return the result and its provenance."""
    _verify_depth(seed, 0, "")
    merged = deepcopy(seed)
    prov: Provenance = {}
    _record_tree(merged, _SEED_LAYER, "", prov)
    for overlay in overlays:
        _verify_depth(overlay.patch, 0, "")
        _merge_dict(merged, overlay.patch, overlay.id, "", prov)
    return merged, prov
