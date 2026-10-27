"""Tests for gwops.configmodel.store.OverlayStore."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from gwops.configmodel.store import Overlay, OverlayStore


@pytest.fixture
def store(tmp_path: Path) -> OverlayStore:
    return OverlayStore(tmp_path / "overlays")


class TestAdd:
    def test_add_returns_overlay_with_counter_slug_id(self, store: OverlayStore) -> None:
        ov = store.add({"admin_api": {"port": 9001}}, comment="Bump admin port")
        assert ov.id == "0001-bump-admin-port"
        assert ov.comment == "Bump admin port"
        assert ov.patch == {"admin_api": {"port": 9001}}
        assert ov.created_at.tzinfo is not None

    def test_ids_increment_and_sort_lexically(self, store: OverlayStore) -> None:
        first = store.add({"a": 1}, comment="first")
        second = store.add({"b": 2}, comment="second")
        third = store.add({"c": 3})
        assert first.id.startswith("0001-")
        assert second.id.startswith("0002-")
        assert third.id.startswith("0003-")
        assert sorted([third.id, first.id, second.id]) == [first.id, second.id, third.id]

    def test_empty_comment_gets_default_slug(self, store: OverlayStore) -> None:
        ov = store.add({"a": 1})
        assert ov.id == "0001-overlay"

    def test_writes_one_json_file_per_overlay(self, store: OverlayStore, tmp_path: Path) -> None:
        ov = store.add({"a": 1}, comment="hello")
        files = list((tmp_path / "overlays").glob("*.json"))
        assert len(files) == 1
        data = json.loads(files[0].read_text(encoding="utf-8"))
        assert data["id"] == ov.id
        assert data["patch"] == {"a": 1}
        assert data["comment"] == "hello"
        datetime.fromisoformat(data["created_at"])  # parseable timestamp


class TestListAndOrdering:
    def test_round_trip(self, store: OverlayStore) -> None:
        a = store.add({"x": 1}, comment="one")
        b = store.add({"y": 2}, comment="two")
        listed = store.list()
        assert [o.id for o in listed] == [a.id, b.id]
        assert listed[0].patch == {"x": 1}
        assert listed[1].patch == {"y": 2}
        assert all(isinstance(o, Overlay) for o in listed)

    def test_empty_store_lists_nothing(self, store: OverlayStore) -> None:
        assert store.list() == []

    def test_list_order_is_lexical_by_filename(self, store: OverlayStore) -> None:
        for i in range(11):
            store.add({"n": i}, comment=f"c{i}")
        listed = store.list()
        assert [o.patch["n"] for o in listed] == list(range(11))


class TestAtomicity:
    def test_leftover_tmp_file_is_ignored(self, store: OverlayStore, tmp_path: Path) -> None:
        store.add({"a": 1}, comment="real")
        # simulate a crash mid-write: a temp file that never got renamed
        (tmp_path / "overlays" / "0002-crashed.json.tmp").write_text("{corrupt", encoding="utf-8")
        listed = store.list()
        assert len(listed) == 1
        assert listed[0].id == "0001-real"

    def test_counter_skips_past_existing_files(self, store: OverlayStore) -> None:
        store.add({"a": 1})
        store.add({"b": 2})
        store.delete("0001-overlay")
        ov = store.add({"c": 3})
        assert ov.id.startswith("0003-")


class TestDelete:
    def test_delete_removes_overlay(self, store: OverlayStore) -> None:
        ov = store.add({"a": 1}, comment="gone soon")
        store.delete(ov.id)
        assert store.list() == []

    def test_delete_unknown_id_raises_keyerror(self, store: OverlayStore) -> None:
        with pytest.raises(KeyError):
            store.delete("9999-nope")


class TestDeleteIdValidation:
    @pytest.mark.parametrize(
        "bad_id",
        [
            "../../../../etc/foo",
            "0001-../../etc/foo",
            "0001-foo/bar",
            "/etc/passwd",
            "C:\\Windows\\System32",
            "",
            "foo",
            "1-short",
            "0001-UPPER",
        ],
    )
    def test_malformed_id_rejected_without_filesystem_effect(
        self, store: OverlayStore, tmp_path: Path, bad_id: str
    ) -> None:
        real = store.add({"a": 1}, comment="keep me")
        before = sorted(p.name for p in (tmp_path / "overlays").iterdir())
        with pytest.raises(ValueError):
            store.delete(bad_id)
        after = sorted(p.name for p in (tmp_path / "overlays").iterdir())
        assert before == after  # nothing created or removed
        assert store.list() == [real] or [o.id for o in store.list()] == [real.id]

    def test_well_formed_but_absent_id_still_raises_keyerror(
        self, store: OverlayStore
    ) -> None:
        with pytest.raises(KeyError):
            store.delete("9999-does-not-exist")


class TestPatchLimits:
    def test_deep_patch_rejected_by_add(self, store: OverlayStore, tmp_path: Path) -> None:
        # Build a patch nested well beyond the depth cap.
        patch: dict[str, Any] = {}
        node = patch
        for _ in range(200):
            child: dict[str, Any] = {}
            node["k"] = child
            node = child
        node["k"] = 1
        with pytest.raises(ValueError, match="[Dd]epth"):
            store.add(patch, comment="too deep")
        # Nothing persisted.
        assert list((tmp_path / "overlays").glob("*.json")) == []

    def test_oversized_patch_rejected_by_add(
        self, store: OverlayStore, tmp_path: Path
    ) -> None:
        # A large-but-shallow patch that exceeds the serialized-size cap.
        patch = {"blob": "x" * (300 * 1024)}
        with pytest.raises(ValueError, match="[Ss]ize|[Bb]yte"):
            store.add(patch, comment="too big")
        assert list((tmp_path / "overlays").glob("*.json")) == []

    def test_patch_at_limits_is_accepted(self, store: OverlayStore) -> None:
        ov = store.add({"admin_api": {"port": 9001}}, comment="normal")
        assert ov.patch == {"admin_api": {"port": 9001}}


class TestRestoreAndGet:
    def test_restore_keeps_original_id_and_order(self, store: OverlayStore) -> None:
        first = store.add({"a": 1}, comment="first")
        second = store.add({"b": 2}, comment="second")
        store.delete(first.id)

        store.restore(first)

        assert [o.id for o in store.list()] == [first.id, second.id]
        assert store.get(first.id) == first

    def test_restore_refuses_to_overwrite(self, store: OverlayStore) -> None:
        ov = store.add({"a": 1})
        with pytest.raises(FileExistsError):
            store.restore(ov)

    def test_restore_rejects_malformed_id(self, store: OverlayStore) -> None:
        bad = Overlay(id="../evil", created_at=datetime.now(UTC), comment="", patch={})
        with pytest.raises(ValueError):
            store.restore(bad)

    def test_get_unknown_is_none(self, store: OverlayStore) -> None:
        assert store.get("0001-nope") is None


class TestOrigin:
    def test_origin_defaults_to_admin_and_persists(self, store: OverlayStore) -> None:
        admin = store.add({"a": 1})
        auto = store.add({"b": 2}, origin="automation")
        by_id = {o.id: o.origin for o in store.list()}
        assert by_id == {admin.id: "admin", auto.id: "automation"}

    def test_legacy_file_without_origin_reads_as_admin(
        self, store: OverlayStore, tmp_path: Path
    ) -> None:
        legacy = {"id": "0001-old", "created_at": datetime.now(UTC).isoformat(),
                  "comment": "", "patch": {}}
        (tmp_path / "overlays" / "0001-old.json").write_text(json.dumps(legacy), "utf-8")
        assert [o.origin for o in store.list()] == ["admin"]

    def test_restore_keeps_origin(self, store: OverlayStore) -> None:
        auto = store.add({"b": 2}, origin="automation")
        store.delete(auto.id)
        store.restore(auto)
        assert store.list()[0].origin == "automation"


class TestTimestamps:
    def test_created_at_is_utc_and_recent(self, store: OverlayStore) -> None:
        ov = store.add({"a": 1})
        age = datetime.now(UTC) - ov.created_at
        assert 0 <= age.total_seconds() < 60
