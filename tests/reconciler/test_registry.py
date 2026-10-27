"""Tests for gwops.reconciler.registry: the managed-TG-object id registry.

The registry (`/data/state.json`) is the reconciler's memory of which Twingate
objects *it* created. Its one safety-critical property: only ids recorded here are
ever updated or deleted, so a corrupt or lost registry must fail loud (corrupt) or
degrade to creating-new (lost), never guess at ownership of unmanaged resources.
"""

import json
from pathlib import Path

import pytest

from gwops.reconciler.registry import AppliedAccess, StateRegistry


@pytest.fixture
def registry_path(tmp_path: Path) -> Path:
    return tmp_path / "state.json"


class TestFreshRegistry:
    def test_missing_file_means_empty_registry(self, registry_path: Path) -> None:
        registry = StateRegistry(registry_path)
        assert registry.managed_ids() == {}
        # Absence of managed objects is not persisted eagerly; no file appears
        # until something is recorded.
        assert not registry_path.exists()


class TestRecordAndForget:
    def test_record_is_readable_and_persisted(self, registry_path: Path) -> None:
        registry = StateRegistry(registry_path)
        registry.record("ssh", "web-1", "r-100")
        registry.record("kubernetes", "prod", "r-200")
        registry.record("ca", "x509", "ca-1")
        assert registry.managed_ids() == {
            "ssh/web-1": "r-100",
            "kubernetes/prod": "r-200",
            "ca/x509": "ca-1",
        }
        # A fresh instance over the same file sees the same state (durable).
        assert StateRegistry(registry_path).managed_ids() == registry.managed_ids()

    def test_record_overwrites_existing_key(self, registry_path: Path) -> None:
        registry = StateRegistry(registry_path)
        registry.record("ssh", "web-1", "r-100")
        registry.record("ssh", "web-1", "r-999")
        assert registry.managed_ids() == {"ssh/web-1": "r-999"}

    def test_forget_removes_and_persists(self, registry_path: Path) -> None:
        registry = StateRegistry(registry_path)
        registry.record("ssh", "web-1", "r-100")
        registry.forget("ssh", "web-1")
        assert registry.managed_ids() == {}
        assert StateRegistry(registry_path).managed_ids() == {}

    def test_forget_unknown_key_is_a_noop(self, registry_path: Path) -> None:
        # Level-triggered callers retry freely; forgetting twice must not raise.
        registry = StateRegistry(registry_path)
        registry.forget("ssh", "never-recorded")
        assert registry.managed_ids() == {}

    def test_managed_ids_returns_a_copy(self, registry_path: Path) -> None:
        registry = StateRegistry(registry_path)
        registry.record("ssh", "web-1", "r-100")
        snapshot = registry.managed_ids()
        snapshot["ssh/injected"] = "evil"
        assert "ssh/injected" not in registry.managed_ids()


class TestFailLoud:
    def test_corrupt_json_raises_value_error(self, registry_path: Path) -> None:
        registry_path.write_text("{not json", encoding="utf-8")
        with pytest.raises(ValueError, match=str(registry_path.name)):
            StateRegistry(registry_path)

    def test_non_object_json_raises_value_error(self, registry_path: Path) -> None:
        registry_path.write_text('["a", "b"]', encoding="utf-8")
        with pytest.raises(ValueError, match="mapping"):
            StateRegistry(registry_path)

    def test_non_string_values_raise_value_error(self, registry_path: Path) -> None:
        registry_path.write_text('{"ssh/web-1": 42}', encoding="utf-8")
        with pytest.raises(ValueError, match="mapping"):
            StateRegistry(registry_path)


class TestOnDiskShape:
    def test_file_is_a_v2_document(self, registry_path: Path) -> None:
        registry = StateRegistry(registry_path)
        registry.record("kubernetes", "prod", "r-200")
        registry.record_access("kubernetes/prod", AppliedAccess(frozenset({"g-2", "g-1"}), "p-1"))
        on_disk = json.loads(registry_path.read_text(encoding="utf-8"))
        assert on_disk == {
            "version": 2,
            "ids": {"kubernetes/prod": "r-200"},
            "access": {"kubernetes/prod": {"groups": ["g-1", "g-2"], "security_policy": "p-1"}},
        }

    def test_write_is_atomic_no_tmp_left_behind(self, registry_path: Path) -> None:
        registry = StateRegistry(registry_path)
        registry.record("ssh", "web-1", "r-100")
        leftovers = [p for p in registry_path.parent.iterdir() if p.suffix == ".tmp"]
        assert leftovers == []


class TestLegacyMigration:
    def test_flat_v1_file_loads_and_is_rewritten_as_v2(self, registry_path: Path) -> None:
        registry_path.write_text('{"ssh/web-1": "r-100", "ca/x509": "ca-1"}', encoding="utf-8")
        registry = StateRegistry(registry_path)
        assert registry.managed_ids() == {"ssh/web-1": "r-100", "ca/x509": "ca-1"}
        assert registry.last_access("ssh/web-1") == AppliedAccess()

        registry.record("ssh", "web-2", "r-101")

        on_disk = json.loads(registry_path.read_text(encoding="utf-8"))
        assert on_disk["version"] == 2
        assert on_disk["ids"] == {"ssh/web-1": "r-100", "ca/x509": "ca-1", "ssh/web-2": "r-101"}

    def test_unknown_version_raises(self, registry_path: Path) -> None:
        registry_path.write_text('{"version": 3, "ids": {}}', encoding="utf-8")
        with pytest.raises(ValueError, match="unknown version"):
            StateRegistry(registry_path)

    def test_malformed_access_record_raises(self, registry_path: Path) -> None:
        registry_path.write_text(
            '{"version": 2, "ids": {}, "access": {"ssh/a": {"groups": "g-1"}}}',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="access record"):
            StateRegistry(registry_path)


class TestAccessRecords:
    def test_missing_record_is_empty(self, registry_path: Path) -> None:
        assert StateRegistry(registry_path).last_access("ssh/x") == AppliedAccess()

    def test_record_access_is_durable_and_forget_drops_it(self, registry_path: Path) -> None:
        registry = StateRegistry(registry_path)
        registry.record("ssh", "web-1", "r-100")
        applied = AppliedAccess(frozenset({"g-1"}), "p-1")
        registry.record_access("ssh/web-1", applied)
        assert StateRegistry(registry_path).last_access("ssh/web-1") == applied

        registry.forget("ssh", "web-1")

        assert StateRegistry(registry_path).last_access("ssh/web-1") == AppliedAccess()
