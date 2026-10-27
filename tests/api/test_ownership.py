"""entry_owners: every entry's owner from one seed parse and one overlay listing."""

from pathlib import Path

import pytest
import yaml

from gwops.api import ownership
from gwops.api.ownership import entry_owner, entry_owners
from gwops.kinds import WEBAPP

from .conftest import make_deps


def _seed() -> str:
    return yaml.safe_dump(
        {
            "twingate": {"network": "acme", "gateway_id": "g-1"},
            "ssh_upstreams": [{"name": "host1", "address": "10.0.0.5:22"}],
            "web_apps": [{"name": "seeded", "address": "seeded.corp.internal"}],
        }
    )


def _entry(name: str) -> dict[str, str]:
    return {"name": name, "address": f"{name}.corp.internal"}


def test_owners_cover_seed_admin_automation_and_deleted_entries(tmp_path: Path) -> None:
    """Seed wins, an admin touch takes over, a delete ends the incarnation."""
    bundle = make_deps(tmp_path, seed=_seed())
    store = bundle.store
    store.add({"web_apps": [_entry("auto-a")]}, origin="automation")
    store.add({"web_apps": [_entry("auto-b")]}, origin="automation")
    store.add({"web_apps": [_entry("auto-b")]}, origin="admin")
    store.add({"web_apps": [_entry("admin-a")]}, origin="admin")
    store.add({"web_apps": [_entry("gone")]}, origin="automation")
    store.add({"web_apps": [{"name": "gone", "_delete": True}]}, origin="admin")
    store.add({"web_apps": [_entry("seeded")]}, origin="automation")

    owners = entry_owners(bundle.deps, WEBAPP)

    assert owners == {
        "seeded": "seed",
        "auto-a": "automation",
        "auto-b": "admin",
        "admin-a": "admin",
    }
    for name in (*owners, "gone", "absent"):
        assert entry_owner(bundle.deps, WEBAPP, name) == owners.get(name)


def test_one_seed_parse_and_one_overlay_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cost does not grow with the number of entries."""
    bundle = make_deps(tmp_path, seed=_seed())
    for index in range(5):
        bundle.store.add({"web_apps": [_entry(f"auto-{index}")]}, origin="automation")
    calls = {"seed": 0, "list": 0}
    real_seed_doc, real_list = ownership.seed_doc, bundle.store.list

    def counting_seed_doc(deps: object) -> object:
        calls["seed"] += 1
        return real_seed_doc(deps)  # type: ignore[arg-type]

    def counting_list() -> object:
        calls["list"] += 1
        return real_list()

    monkeypatch.setattr(ownership, "seed_doc", counting_seed_doc)
    monkeypatch.setattr(bundle.store, "list", counting_list)

    entry_owners(bundle.deps, WEBAPP)

    assert calls == {"seed": 1, "list": 1}
