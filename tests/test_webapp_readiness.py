"""Tests for gwops.webapp_readiness: the passive per-web-app readiness report.

Interface under test:

* ``compute_readiness(state, result, leaf_sans, *, ca_generated, on_demand, gateway_id)``
  returns one entry per web app on ``gateway_id`` (managed or not), plus managed apps with a
  recorded gateway mismatch. An entry is a dataclass or mapping with ``name``, ``id``,
  ``managed``, ``upstream_tls``, ``downstream_tls`` (lowercase seed spellings), ``state``
  (``ready`` | ``action_required`` | ``unverifiable``), ``reasons`` and ``probe`` (None).
* Reasons are ``<code>`` or ``<code>:<detail>``: ``san_missing:<name>``,
  ``covered_on_demand:<name>``, ``operator_action``, ``byo_ca``, ``plaintext_upstreams``,
  ``unmanaged``, ``unserved``, ``gateway_mismatch``, ``wildcard_address``,
  ``computation_failed``, ``leaf_unreadable``, ``on_demand_unavailable:<name>``,
  ``not_on_tenant``.
* State: any actionable reason is ``action_required``; else any unverifiable reason is
  ``unverifiable``; else ``ready``. ``operator_action``, ``byo_ca`` and ``covered_on_demand``
  are informational.
* ``result.remote_web_apps is None`` (tenant not listed) yields ``[]``.
* ``leaf_sans is None`` (leaf unreadable) makes every entry ``leaf_unreadable``.
"""

import dataclasses
from datetime import UTC, datetime
from typing import Any

import pytest

from gwops.configmodel.schema import EffectiveState
from gwops.reconciler.core import GatewayMismatch, ReconcileResult, RemoteWebApp
from gwops.webapp_readiness import compute_readiness

GW = "g-1"
GRAFANA = "grafana.corp.internal"
ALIAS = "grafana.alt.internal"
STRANGER = "stranger.corp.internal"
_ENTRY_KEYS = {
    "name", "id", "managed", "upstream_tls", "downstream_tls", "state", "reasons", "probe",
}
_STATES = {"ready", "action_required", "unverifiable"}
_ALLOW_CORP = {"dns_suffixes": ["corp.internal"]}


def _state(
    web_apps: list[dict[str, Any]] | None = None, *, plaintext: dict[str, Any] | None = None
) -> EffectiveState:
    doc: dict[str, Any] = {
        "twingate": {"network": "acme", "gateway_id": GW},
        "web_apps": web_apps or [],
    }
    if plaintext is not None:
        doc["web_app_proxy"] = {"plaintext_upstreams": plaintext}
    return EffectiveState.model_validate(doc)


def _declared(**fields: Any) -> EffectiveState:
    return _state([{"name": "grafana", "address": GRAFANA, **fields}])


def _remote(name: str = "grafana", **fields: Any) -> RemoteWebApp:
    values: dict[str, Any] = {
        "id": f"r-{name}",
        "name": name,
        "gateway_id": GW,
        "address": GRAFANA if name == "grafana" else f"{name}.corp.internal",
        "upstream_port": 443,
        "alias": None,
        "upstream_tls": "verify_full",
        "downstream_tls": "tls13",
        "downstream_port": 443,
        "header_rewrite_names": (),
        "managed": True,
    }
    values.update(fields)
    return RemoteWebApp(**values)


def _result(
    remote: list[RemoteWebApp] | None,
    mismatches: dict[str, GatewayMismatch] | None = None,
    *,
    local_ok: bool = True,
) -> ReconcileResult:
    return ReconcileResult(
        ok=True,
        trigger="tick",
        started_at=datetime.now(UTC),
        local_ok=local_ok,
        remote_web_apps=remote,
        gateway_mismatches=mismatches or {},
    )


def _as_dict(entry: Any) -> dict[str, Any]:
    return dataclasses.asdict(entry) if dataclasses.is_dataclass(entry) else dict(entry)


def _run(
    state: EffectiveState,
    remote: list[RemoteWebApp] | None,
    leaf: tuple[str, ...] | None = (GRAFANA,),
    *,
    mismatches: dict[str, GatewayMismatch] | None = None,
    ca_generated: bool = False,
    on_demand: bool = False,
    gateway_id: str = GW,
    local_ok: bool = True,
) -> dict[str, dict[str, Any]]:
    entries = compute_readiness(
        state,
        _result(remote, mismatches, local_ok=local_ok),
        None if leaf is None else set(leaf),
        ca_generated=ca_generated,
        on_demand=on_demand,
        gateway_id=gateway_id,
    )
    return {_as_dict(e)["name"]: _as_dict(e) for e in entries}


def _has(entry: dict[str, Any], code: str) -> bool:
    return any(r == code or r.startswith(f"{code}:") for r in entry["reasons"])


class TestEntryShape:
    def test_a_managed_app_reports_every_documented_field(self) -> None:
        """One managed, declared app yields one entry with exactly the documented keys."""
        entries = _run(_declared(), [_remote()])

        assert set(entries) == {"grafana"}
        entry = entries["grafana"]
        assert set(entry) == _ENTRY_KEYS
        assert entry["id"] == "r-grafana"
        assert entry["managed"] is True
        assert (entry["upstream_tls"], entry["downstream_tls"]) == ("verify_full", "tls13")
        assert entry["state"] in _STATES
        assert isinstance(entry["reasons"], list)
        assert entry["probe"] is None

    @pytest.mark.parametrize("upstream", ["verify_full", "verify_ca", "insecure", "none"])
    @pytest.mark.parametrize("downstream", ["tls13", "none"])
    def test_both_tls_modes_are_reported_verbatim(self, upstream: str, downstream: str) -> None:
        """The entry echoes the tenant's upstream and downstream modes."""
        state = _state(
            [
                {
                    "name": "grafana",
                    "address": GRAFANA,
                    "upstream_tls": upstream,
                    "downstream": {"tls": downstream},
                }
            ],
            plaintext=_ALLOW_CORP,
        )
        remote = _remote(upstream_tls=upstream, downstream_tls=downstream)

        entry = _run(state, [remote])["grafana"]

        assert (entry["upstream_tls"], entry["downstream_tls"]) == (upstream, downstream)

    def test_an_unlisted_tenant_yields_no_entries(self) -> None:
        """With no tenant listing there is nothing to report."""
        assert _run(_declared(), None) == {}


class TestReady:
    def test_a_covered_byo_ca_app_is_ready(self) -> None:
        """A name in the leaf, a BYO CA and verify_full/tls13 leave nothing to do."""
        entry = _run(_declared(), [_remote()])["grafana"]

        assert entry["state"] == "ready"
        assert not _has(entry, "san_missing")

    def test_a_covered_alias_is_ready(self) -> None:
        """Address and alias both in the leaf is ready."""
        entry = _run(_declared(alias=ALIAS), [_remote(alias=ALIAS)], (GRAFANA, ALIAS))["grafana"]

        assert entry["state"] == "ready"

    def test_leaf_matching_ignores_case(self) -> None:
        """A mixed-case tenant address still matches the lowercase leaf name."""
        entry = _run(_declared(), [_remote(address="Grafana.Corp.Internal")])["grafana"]

        assert entry["state"] == "ready"


class TestSanCoverage:
    def test_an_address_missing_from_the_leaf_is_action_required(self) -> None:
        """A name the leaf lacks is a san_missing reason naming it."""
        entry = _run(_declared(), [_remote()], leaf=("other.corp.internal",))["grafana"]

        assert entry["state"] == "action_required"
        assert _has(entry, "san_missing")
        assert any(GRAFANA in r for r in entry["reasons"] if r.startswith("san_missing"))

    def test_only_the_missing_alias_is_named(self) -> None:
        """With the address covered, the alias alone is reported."""
        entry = _run(_declared(alias=ALIAS), [_remote(alias=ALIAS)], (GRAFANA,))["grafana"]

        missing = [r for r in entry["reasons"] if r.startswith("san_missing")]
        assert entry["state"] == "action_required"
        assert len(missing) == 1
        assert ALIAS in missing[0]
        assert GRAFANA not in missing[0]

    def test_on_demand_turns_a_missing_name_into_covered_on_demand(self) -> None:
        """On-demand issuance covers a name the leaf lacks, so it is not a failure."""
        entry = _run(_declared(), [_remote()], leaf=(), on_demand=True)["grafana"]

        assert _has(entry, "covered_on_demand")
        assert not _has(entry, "san_missing")
        assert entry["state"] == "ready"

    def test_on_demand_with_a_covered_name_reports_nothing_extra(self) -> None:
        """A name already in the leaf needs no on-demand coverage."""
        entry = _run(_declared(), [_remote()], on_demand=True)["grafana"]

        assert not _has(entry, "covered_on_demand")
        assert not _has(entry, "san_missing")

    @pytest.mark.parametrize("on_demand", [False, True])
    def test_an_ip_literal_is_never_covered_on_demand(self, on_demand: bool) -> None:
        """On-demand issuance mints names, not IPs: a missing IP SAN is always san_missing."""
        remote = _remote(address="10.0.0.5")

        entry = _run(_declared(), [remote], leaf=(), on_demand=on_demand)["grafana"]

        assert "san_missing:10.0.0.5" in entry["reasons"]
        assert not _has(entry, "covered_on_demand")
        assert entry["state"] == "action_required"

    def test_an_ip_alias_is_never_covered_on_demand_either(self) -> None:
        """The same rule applies to an IP-literal alias beside a DNS address."""
        entry = _run(
            _declared(), [_remote(alias="10.0.0.6")], (GRAFANA,), on_demand=True
        )["grafana"]

        assert "san_missing:10.0.0.6" in entry["reasons"]

    def test_covered_on_demand_needs_a_locally_ok_pass(self) -> None:
        """A pass whose local steps failed cannot promise on-demand coverage."""
        entry = _run(_declared(), [_remote()], leaf=(), on_demand=True, local_ok=False)["grafana"]

        assert f"on_demand_unavailable:{GRAFANA}" in entry["reasons"]
        assert not _has(entry, "covered_on_demand")
        assert entry["state"] == "action_required"

    def test_an_unreadable_leaf_is_unverifiable_not_missing_names(self) -> None:
        """No readable leaf: one leaf_unreadable reason, not a san_missing per name."""
        entries = _run(
            _declared(), [_remote(), _remote("wiki", managed=False)], leaf=None, on_demand=True
        )

        for entry in entries.values():
            assert "leaf_unreadable" in entry["reasons"]
            assert not _has(entry, "san_missing")
            assert not _has(entry, "covered_on_demand")
        assert entries["grafana"]["state"] == "unverifiable"

    def test_on_demand_names_only_the_alias_that_is_missing(self) -> None:
        """Address in the leaf, alias not: covered_on_demand names the alias."""
        entry = _run(
            _declared(alias=ALIAS), [_remote(alias=ALIAS)], (GRAFANA,), on_demand=True
        )["grafana"]

        [covered] = [r for r in entry["reasons"] if r.startswith("covered_on_demand")]
        assert ALIAS in covered
        assert entry["state"] == "ready"


class TestBrowserTrust:
    def test_a_generated_ca_with_tls13_notes_operator_action_and_stays_ready(self) -> None:
        """The operator must distribute a gwops-generated CA to browsers; informational."""
        entry = _run(_declared(), [_remote()], ca_generated=True)["grafana"]

        assert _has(entry, "operator_action")
        assert not _has(entry, "byo_ca")
        assert entry["state"] == "ready"

    def test_operator_action_does_not_hide_a_real_problem(self) -> None:
        """An actionable reason beside operator_action still needs action."""
        entry = _run(_declared(), [_remote()], leaf=(), ca_generated=True)["grafana"]

        assert _has(entry, "operator_action")
        assert entry["state"] == "action_required"

    def test_a_byo_ca_with_tls13_is_noted_and_not_a_failure(self) -> None:
        """A BYO CA's browser trust is the operator's; reported as byo_ca, still ready."""
        entry = _run(_declared(), [_remote()], ca_generated=False)["grafana"]

        assert _has(entry, "byo_ca")
        assert not _has(entry, "operator_action")
        assert entry["state"] == "ready"

    @pytest.mark.parametrize("ca_generated", [True, False])
    def test_a_plaintext_downstream_has_no_browser_trust_reason(self, ca_generated: bool) -> None:
        """Downstream none involves no certificate, so neither trust reason applies."""
        state = _declared(downstream={"tls": "none"})
        entry = _run(state, [_remote(downstream_tls="none")], ca_generated=ca_generated)["grafana"]

        assert not _has(entry, "operator_action")
        assert not _has(entry, "byo_ca")
        assert entry["state"] == "ready"


class TestPlaintextUpstreams:
    @pytest.mark.parametrize("mode", ["none", "insecure"])
    def test_a_weak_mode_outside_the_allowlist_is_action_required(self, mode: str) -> None:
        """none/insecure to a host plaintext_upstreams does not allow is a violation."""
        state = _declared(upstream_tls=mode)

        entry = _run(state, [_remote(upstream_tls=mode)])["grafana"]

        assert _has(entry, "plaintext_upstreams")
        assert entry["state"] == "action_required"

    @pytest.mark.parametrize("mode", ["none", "insecure"])
    def test_a_weak_mode_inside_the_allowlist_is_not_a_violation(self, mode: str) -> None:
        """The same mode to an allowed host raises no plaintext_upstreams reason."""
        state = _state(
            [{"name": "grafana", "address": GRAFANA, "upstream_tls": mode}],
            plaintext=_ALLOW_CORP,
        )

        entry = _run(state, [_remote(upstream_tls=mode)])["grafana"]

        assert not _has(entry, "plaintext_upstreams")

    def test_verify_ca_needs_no_allowlist(self) -> None:
        """verify_ca is a warning elsewhere, not a plaintext_upstreams violation."""
        entry = _run(_declared(upstream_tls="verify_ca"), [_remote(upstream_tls="verify_ca")])[
            "grafana"
        ]

        assert not _has(entry, "plaintext_upstreams")

    def test_an_unmanaged_app_is_judged_on_its_tenant_mode(self) -> None:
        """An unmanaged none-mode app outside the allowlist is flagged from the snapshot."""
        stranger = _remote("stranger", managed=False, upstream_tls="none")

        entry = _run(_state(), [stranger], leaf=())["stranger"]

        assert _has(entry, "plaintext_upstreams")


class TestUnmanagedAndUnserved:
    def test_an_unmanaged_app_on_this_gateway_is_reported_as_unmanaged(self) -> None:
        """An undeclared app is covered, flagged unmanaged and needs action."""
        stranger = _remote("stranger", managed=False)

        entries = _run(_declared(), [_remote(), stranger])

        entry = entries["stranger"]
        assert entry["managed"] is False
        assert _has(entry, "unmanaged")
        assert not _has(entry, "unserved")
        assert entry["state"] == "action_required"
        assert entries["grafana"]["managed"] is True

    def test_with_no_declared_web_apps_every_app_is_unserved(self) -> None:
        """No declaration means the gateway serves none of them."""
        stranger = _remote("stranger", managed=False)

        entry = _run(_state(), [stranger], leaf=())["stranger"]

        assert _has(entry, "unserved")
        assert entry["state"] == "action_required"

    def test_an_unmanaged_app_on_another_gateway_is_not_reported(self) -> None:
        """Only apps on this gateway are covered."""
        stranger = _remote("stranger", managed=False, gateway_id="g-other")

        assert "stranger" not in _run(_declared(), [_remote(), stranger])


class TestGatewayMismatch:
    def test_an_uncorrected_mismatch_is_action_required(self) -> None:
        """A managed app still on another gateway is covered and flagged."""
        remote = _remote(gateway_id="g-other")
        mismatches = {"webapp/grafana": GatewayMismatch("g-other", corrected=False)}

        entry = _run(_declared(), [remote], mismatches=mismatches)["grafana"]

        assert _has(entry, "gateway_mismatch")
        assert entry["state"] == "action_required"

    def test_without_a_mismatch_record_a_foreign_managed_app_is_ignored(self) -> None:
        """Gateway scope is by the tenant's gateway id unless a mismatch says otherwise."""
        remote = _remote(gateway_id="g-other")

        assert _run(_declared(), [remote]) == {}


class TestWildcard:
    def test_a_wildcard_address_is_unverifiable(self) -> None:
        """A wildcard name cannot be matched against the leaf, so it is unverifiable."""
        entry = _run(_declared(), [_remote(address="*.corp.internal")])["grafana"]

        assert entry["state"] == "unverifiable"
        assert _has(entry, "wildcard_address")

    def test_an_actionable_reason_wins_over_a_wildcard(self) -> None:
        """An unmanaged wildcard app has a reason that needs action, which outranks unverifiable."""
        stranger = _remote("stranger", managed=False, address="*.corp.internal")

        entry = _run(_declared(), [_remote(), stranger])["stranger"]

        assert entry["state"] == "action_required"
        assert _has(entry, "wildcard_address")
        assert _has(entry, "unmanaged")

    def test_a_wildcard_app_does_not_change_its_neighbours(self) -> None:
        """Other apps in the same listing are still assessed normally."""
        stranger = _remote("stranger", managed=False, address="*.corp.internal")

        entries = _run(_declared(), [_remote(), stranger])

        assert entries["grafana"]["state"] == "ready"


class _Poisoned(ReconcileResult):
    """A result whose snapshot raises when read."""

    @property  # type: ignore[override]
    def remote_web_apps(self) -> list[RemoteWebApp]:
        raise RuntimeError("snapshot unreadable")

    @remote_web_apps.setter
    def remote_web_apps(self, value: object) -> None:
        return None


class TestComputationFailure:
    def test_an_internal_error_degrades_to_unverifiable_entries(self) -> None:
        """A failure inside the computation never raises; declared apps become unverifiable."""
        poisoned = _Poisoned(ok=True, trigger="tick", started_at=datetime.now(UTC))

        entries = compute_readiness(
            _declared(), poisoned, {GRAFANA}, ca_generated=False, on_demand=False, gateway_id=GW
        )

        by_name = {_as_dict(e)["name"]: _as_dict(e) for e in entries}
        assert set(by_name) == {"grafana"}
        assert by_name["grafana"]["state"] == "unverifiable"
        assert _has(by_name["grafana"], "computation_failed")


class TestNotOnTenant:
    def test_a_declared_app_with_no_tenant_match_gets_an_entry(self) -> None:
        """The tenant was listed and has no managed app of that name."""
        entries = _run(_declared(), [])

        entry = entries["grafana"]
        assert entry["managed"] is True
        assert entry["id"] is None
        assert entry["state"] == "action_required"
        assert entry["reasons"] == ["not_on_tenant"]
        assert (entry["upstream_tls"], entry["downstream_tls"]) == ("verify_full", "tls13")

    def test_a_declared_app_on_the_tenant_gets_no_such_entry(self) -> None:
        entries = _run(_declared(), [_remote()])

        assert not _has(entries["grafana"], "not_on_tenant")
        assert len(entries) == 1

    def test_a_managed_app_on_another_gateway_counts_as_on_the_tenant(self) -> None:
        """Only absence from the listing is not_on_tenant; a gateway mismatch is its own reason."""
        entries = _run(_declared(), [_remote(gateway_id="g-other")])

        assert entries == {}

    def test_an_unlisted_tenant_has_no_not_on_tenant_entries(self) -> None:
        assert _run(_declared(), None) == {}
