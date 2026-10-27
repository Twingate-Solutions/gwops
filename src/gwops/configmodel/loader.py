"""Load and validate the effective state: YAML seed → overlay merge → EffectiveState.

Fails loud: every failure raises :class:`ConfigLoadError` whose message names the
dotted config path and the layer (``seed`` or an overlay id) that set the offending
value, so a bad deploy is diagnosable from the error alone.
"""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from gwops.configmodel.merge import Provenance, merge_layers
from gwops.configmodel.schema import EffectiveState
from gwops.configmodel.store import OverlayStore


class ConfigLoadError(Exception):
    """The seed/overlay stack could not be loaded into a valid EffectiveState."""


def _dotted_path(merged: dict[str, Any], loc: tuple[int | str, ...]) -> str:
    """Convert a pydantic error location to a provenance-style dotted path.

    List indices are translated to the item's ``name`` when the item has one, so
    the path matches what :func:`merge_layers` records (e.g. ``k8s_clusters.prod.port``).
    """
    parts: list[str] = []
    node: Any = merged
    for part in loc:
        if isinstance(part, int) and isinstance(node, list) and part < len(node):
            item = node[part]
            node = item
            if isinstance(item, dict) and "name" in item:
                parts.append(str(item["name"]))
            else:
                parts.append(str(part))
        else:
            parts.append(str(part))
            node = node.get(part) if isinstance(node, dict) else None
    return ".".join(parts)


def _layer_for(path: str, prov: Provenance) -> str:
    """Find the layer that set ``path``, walking up ancestors if needed."""
    candidate = path
    while candidate:
        if candidate in prov:
            return prov[candidate]
        # a failing leaf inside a subtree set wholesale maps to that subtree's layer
        children = [v for k, v in prov.items() if k.startswith(candidate + ".")]
        if children:
            return children[0] if len(set(children)) == 1 else "multiple layers"
        candidate = candidate.rpartition(".")[0]
    return "seed"


def load_effective_state(
    seed_path: Path, store: OverlayStore
) -> tuple[EffectiveState, Provenance]:
    """Read the seed, apply overlays, and validate the merged result."""
    try:
        raw_text = seed_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigLoadError(f"cannot read seed file {seed_path}: {exc}") from exc

    try:
        seed_raw = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigLoadError(f"seed file {seed_path} is not valid YAML: {exc}") from exc

    if not isinstance(seed_raw, dict):
        raise ConfigLoadError(f"seed file {seed_path} must be a YAML mapping at top level")

    merged, prov = merge_layers(seed_raw, store.list())

    try:
        state = EffectiveState.model_validate(merged)
    except ValidationError as exc:
        problems = []
        for err in exc.errors():
            path = _dotted_path(merged, tuple(err["loc"]))
            layer = _layer_for(path, prov)
            problems.append(f"{path}: {err['msg']} (set by layer: {layer})")
        raise ConfigLoadError(
            "effective config is invalid:\n  " + "\n  ".join(problems)
        ) from exc

    return state, prov
