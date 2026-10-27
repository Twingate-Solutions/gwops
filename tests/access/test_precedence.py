"""Tests for gwops.access.precedence: the precedence table, per key.

Each row is checked separately for `groups` and for `security_policy`, because the two
keys fall back to the seed defaults independently.
"""

from typing import Any

import pytest
from pydantic import ValidationError

from gwops.access.precedence import EffectiveAccess, Ref, effective_access
from gwops.configmodel.schema import AccessSpec, ResourceRef

_DEFAULTS = AccessSpec.model_validate({"groups": ["App Users"], "security_policy": "Standard"})


def _access(data: dict[str, Any] | None) -> AccessSpec | None:
    return None if data is None else AccessSpec.model_validate(data)


class TestGroups:
    def test_present_non_empty_replaces_the_default(self) -> None:
        result = effective_access(_access({"groups": ["Platform"]}), _DEFAULTS)
        assert result.groups == (Ref(id=None, name="Platform"),)

    def test_empty_list_means_no_groups_even_with_a_default(self) -> None:
        assert effective_access(_access({"groups": []}), _DEFAULTS).groups == ()

    @pytest.mark.parametrize("entry", [None, {}, {"groups": None}])
    def test_omitted_or_null_uses_the_default(self, entry: dict[str, Any] | None) -> None:
        result = effective_access(_access(entry), _DEFAULTS)
        assert result.groups == (Ref(id=None, name="App Users"),)

    def test_omitted_without_default_is_unmanaged(self) -> None:
        assert effective_access(None, None).groups is None
        policy_only = AccessSpec(security_policy=ResourceRef(name="x"))
        assert effective_access(None, policy_only).groups is None


class TestSecurityPolicy:
    def test_present_replaces_the_default(self) -> None:
        result = effective_access(_access({"security_policy": "MFA"}), _DEFAULTS)
        assert result.security_policy == Ref(id=None, name="MFA")

    @pytest.mark.parametrize("entry", [None, {}, {"security_policy": None}])
    def test_omitted_or_null_uses_the_default(self, entry: dict[str, Any] | None) -> None:
        result = effective_access(_access(entry), _DEFAULTS)
        assert result.security_policy == Ref(id=None, name="Standard")

    def test_omitted_without_default_is_unmanaged(self) -> None:
        assert effective_access(_access({"groups": ["a"]}), None).security_policy is None


class TestKeysAreIndependent:
    def test_groups_from_entry_policy_from_default(self) -> None:
        result = effective_access(_access({"groups": ["Platform"]}), _DEFAULTS)
        assert result == EffectiveAccess(
            groups=(Ref(id=None, name="Platform"),),
            security_policy=Ref(id=None, name="Standard"),
        )


class TestResourceRef:
    def test_plain_string_is_a_name(self) -> None:
        assert ResourceRef.model_validate("Platform") == ResourceRef(name="Platform")

    def test_explicit_id_and_pinned_forms(self) -> None:
        assert ResourceRef.model_validate({"id": "R3JvdXA6MQ=="}).id == "R3JvdXA6MQ=="
        pinned = ResourceRef.model_validate({"id": "g-1", "name": "Platform"})
        assert Ref.of(pinned) == Ref(id="g-1", name="Platform")

    @pytest.mark.parametrize("raw", [{}, {"name": ""}, {"id": ""}, {"name": "a", "x": 1}])
    def test_invalid_refs_are_rejected(self, raw: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            ResourceRef.model_validate(raw)
