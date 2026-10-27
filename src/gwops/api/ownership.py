"""Who owns an upstream entry: the seed, the admin token or the automation token."""

from typing import Any, Literal

import yaml

from gwops.api.app import GwopsDeps
from gwops.configmodel.store import Origin
from gwops.kinds import ResourceKind

Owner = Origin | Literal["seed"]


def seed_doc(deps: GwopsDeps) -> dict[str, Any]:
    """The raw seed document, or an empty dict when it is not a mapping."""
    doc = yaml.safe_load(deps.settings.seed_path.read_text(encoding="utf-8")) or {}
    return doc if isinstance(doc, dict) else {}


def entry_owners(deps: GwopsDeps, kind: ResourceKind) -> dict[str, Owner]:
    """The owner of every current entry of `kind`, from one seed parse and one overlay listing.

    A name declared in the seed is always ``seed``. Otherwise the overlays are replayed:
    the overlay that creates the entry sets its owner, an admin overlay touching it makes
    it ``admin`` (an operator took it over), and a ``_delete`` ends that incarnation.
    """
    found: dict[str, Origin] = {}
    for overlay in deps.store.list():
        for item in overlay.patch.get(kind.state_field) or []:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                continue
            name = item["name"]
            if item.get("_delete"):
                found.pop(name, None)
            elif name not in found or overlay.origin == "admin":
                found[name] = overlay.origin
    owners: dict[str, Owner] = dict(found)
    for item in seed_doc(deps).get(kind.state_field) or []:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            owners[item["name"]] = "seed"
    return owners


def entry_owner(deps: GwopsDeps, kind: ResourceKind, name: str) -> Owner | None:
    """Who owns the current `name` entry of `kind`: ``seed``, ``admin``, ``automation``,
    or None when it does not exist. See :func:`entry_owners` for the rules.
    """
    return entry_owners(deps, kind).get(name)
