"""Unit tests for gwops.access.allowlist: address matching and the startup rule."""

from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from gwops.access import allowlist as allowlist_module
from gwops.access.allowlist import address_allowed, address_violations, check_automation_startup
from gwops.configmodel.schema import AddressAllowlist, EffectiveState
from gwops.kinds import KINDS, ResourceKind
from gwops.settings import GwopsSettings

_ALLOW = AddressAllowlist(cidrs=["10.20.0.0/16"], dns_suffixes=["apps.example.com"])


@pytest.mark.parametrize(
    ("host", "allowed"),
    [
        ("10.20.1.5", True),
        ("x.apps.example.com", True),
        ("apps.example.com", True),
        ("10.30.0.1", False),
        ("xapps.example.com", False),
        ("apps.example.com.evil.net", False),
    ],
)
def test_address_matching(host: str, allowed: bool) -> None:
    assert address_allowed(host, _ALLOW) is allowed


def test_violations_strip_the_port_and_skip_deletes() -> None:
    patch = {
        "ssh_upstreams": [
            {"name": "ok", "address": "10.20.0.9:2222"},
            {"name": "bad", "address": "10.30.0.1"},
            {"name": "gone", "_delete": True},
        ]
    }
    assert address_violations(patch, _ALLOW) == ["'bad': address '10.30.0.1' is not allowlisted"]
    assert address_violations(patch, None) == []


def test_empty_allowlist_allows_nothing() -> None:
    patch = {"ssh_upstreams": [{"name": "a", "address": "10.20.0.1"}]}
    assert address_violations(patch, AddressAllowlist()) != []


# Alias checks run against a stand-in web-app descriptor spliced into the module's KINDS.

_TEST_WEBAPP_KIND = ResourceKind(
    key="webapp",
    state_field="web_apps",
    api_segment="webapp",
    tg_type="WebAppResource",
    tg_field_prefix="webAppResource",
    tg_upstream_input="WebAppUpstreamInput",
    gateway_id_required=True,
    automation_allowed=True,
)


@pytest.fixture
def webapp_kind(monkeypatch: pytest.MonkeyPatch) -> None:
    kinds = (*(k for k in KINDS if k.state_field != "web_apps"), _TEST_WEBAPP_KIND)
    monkeypatch.setattr(allowlist_module, "KINDS", kinds)


@pytest.mark.usefixtures("webapp_kind")
class TestAlias:
    def test_disallowed_alias_names_entry_and_field(self) -> None:
        patch = {
            "web_apps": [{"name": "grafana", "address": "g.apps.example.com", "alias": "10.30.0.1"}]
        }
        assert address_violations(patch, _ALLOW) == [
            "'grafana': alias '10.30.0.1' is not allowlisted"
        ]

    def test_allowed_address_and_alias_pass(self) -> None:
        patch = {
            "web_apps": [
                {"name": "grafana", "address": "g.apps.example.com", "alias": "10.20.0.7"},
                {"name": "wiki", "address": "wiki.apps.example.com", "alias": "w.apps.example.com"},
            ]
        }
        assert address_violations(patch, _ALLOW) == []

    def test_bad_address_and_bad_alias_are_both_reported(self) -> None:
        patch = {"web_apps": [{"name": "x", "address": "10.30.0.2", "alias": "evil.example.net"}]}
        assert address_violations(patch, _ALLOW) == [
            "'x': address '10.30.0.2' is not allowlisted",
            "'x': alias 'evil.example.net' is not allowlisted",
        ]

    def test_absent_alias_is_not_checked(self) -> None:
        patch = {"web_apps": [{"name": "x", "address": "x.apps.example.com"}]}
        assert address_violations(patch, _ALLOW) == []

    def test_null_alias_clears_and_is_not_checked(self) -> None:
        patch = {"web_apps": [{"name": "x", "address": "x.apps.example.com", "alias": None}]}
        assert address_violations(patch, _ALLOW) == []

    def test_alias_only_patch_is_checked(self) -> None:
        patch = {"web_apps": [{"name": "x", "alias": "other.example.net"}]}
        assert address_violations(patch, _ALLOW) == [
            "'x': alias 'other.example.net' is not allowlisted"
        ]

    def test_alias_is_lowercased_before_matching(self) -> None:
        patch = {"web_apps": [{"name": "x", "alias": "W.Apps.Example.COM"}]}
        assert address_violations(patch, _ALLOW) == []

    def test_deleted_entry_alias_is_skipped(self) -> None:
        patch = {"web_apps": [{"name": "x", "_delete": True, "alias": "evil.example.net"}]}
        assert address_violations(patch, _ALLOW) == []

    def test_no_allowlist_leaves_alias_unrestricted(self) -> None:
        patch = {"web_apps": [{"name": "x", "alias": "anything.example.net"}]}
        assert address_violations(patch, None) == []

    def test_empty_allowlist_rejects_any_alias(self) -> None:
        patch = {"web_apps": [{"name": "x", "alias": "a.example.net"}]}
        assert address_violations(patch, AddressAllowlist()) != []


def test_suffixes_are_normalized_and_cidrs_validated() -> None:
    assert AddressAllowlist(dns_suffixes=[".Apps.Example.com"]).dns_suffixes == ["apps.example.com"]
    with pytest.raises(ValidationError):
        AddressAllowlist(cidrs=["10.20.0.0/99"])


def _state(**twingate: Any) -> EffectiveState:
    return EffectiveState.model_validate(
        {"twingate": {"network": "acme", "gateway_id": "g-1", **twingate}}
    )


def _settings(tmp_path: Path, automation: str | None, admin: str = "admin") -> GwopsSettings:
    return GwopsSettings(
        seed_path=tmp_path / "seed.yaml",
        **{"GWOPS_ADMIN_TOKEN": admin, "GWOPS_AUTOMATION_TOKEN": automation},  # type: ignore[arg-type]
    )


_BOTH = {"access_allowlist": {"groups": []}, "address_allowlist": {"cidrs": []}}


class TestStartupRule:
    def test_no_automation_token_needs_nothing(self, tmp_path: Path) -> None:
        check_automation_startup(_settings(tmp_path, None), _state())

    def test_token_with_both_allowlists_is_fine(self, tmp_path: Path) -> None:
        check_automation_startup(_settings(tmp_path, "auto"), _state(**_BOTH))

    @pytest.mark.parametrize("missing", ["access_allowlist", "address_allowlist"])
    def test_token_without_an_allowlist_aborts(self, tmp_path: Path, missing: str) -> None:
        present = {k: v for k, v in _BOTH.items() if k != missing}
        with pytest.raises(ValueError, match=f"twingate.{missing}"):
            check_automation_startup(_settings(tmp_path, "auto"), _state(**present))

    def test_token_equal_to_admin_token_aborts(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, "same", admin="same")
        assert isinstance(settings.gwops_automation_token, SecretStr)
        with pytest.raises(ValueError, match="must differ"):
            check_automation_startup(settings, _state(**_BOTH))
