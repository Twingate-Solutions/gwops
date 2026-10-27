"""The upstream TLS probe's merge into GET /status ``web_apps.readiness``.

* Flag off (no runner, or ``enabled`` False): ``probe`` is null and no ``probe*`` reason appears,
  whatever the runner holds.
* Flag on: ``probe`` is ``{outcome, checked_at, target, error_type, verify_code}``; a non-ok
  outcome adds ``probe:<outcome>`` and makes the entry ``action_required``; keys the selection
  reported unverifiable get ``probe_unverifiable``, which only outranks ``ready``: an entry with
  an actionable reason stays ``action_required``.
* Results are keyed by tenant resource id (the name when the app has no id).
* A verifiable entry without a result gets ``probe_pending`` (informational), or
  ``probe_error:<type>`` (unverifiable) when its probe or the last batch raised.
* A merge that raises marks every entry ``unverifiable`` with ``computation_failed``.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from gwops import webapp_readiness
from gwops.api.app import create_app
from gwops.reconciler.core import ReconcileResult
from gwops.renderer.render import RuntimePaths
from gwops.webapp_probe import ProbeOutcome, ProbeResult, ProbeRunner

from .conftest import ADMIN_TOKEN, DepsBundle, make_deps

GW = "g-1"
GRAFANA = "grafana.corp.internal"
CHECKED_AT = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
_BYO_CA = {
    "x509": {"generate": False, "cert_path": "/config/ca/ca.crt", "key_path": "/config/ca/ca.key"}
}


def _seed() -> str:
    return yaml.safe_dump(
        {
            "twingate": {"network": "acme", "gateway_id": GW},
            "ssh_upstreams": [{"name": "host1", "address": "10.0.0.5:22"}],
            "web_apps": [{"name": "grafana", "address": GRAFANA}],
            "ca": _BYO_CA,
        },
        sort_keys=False,
    )


def _remote(name: str, *, managed: bool, address: str) -> Any:
    from gwops.reconciler.core import RemoteWebApp

    return RemoteWebApp(
        id=f"r-{name}", name=name, gateway_id=GW, address=address, upstream_port=443,
        alias=None, upstream_tls="verify_full", downstream_tls="tls13", downstream_port=443,
        header_rewrite_names=(),
        managed=managed,
    )


def _result(outcome: ProbeOutcome, target: str = f"{GRAFANA}:443") -> ProbeResult:
    return ProbeResult(outcome, CHECKED_AT, target)


def _bundle(tmp_path: Path, runner: ProbeRunner | None) -> DepsBundle:
    bundle = make_deps(tmp_path, seed=_seed(), admin_token=ADMIN_TOKEN)
    bundle.reconciler.last_result = ReconcileResult(
        ok=True,
        trigger="tick",
        started_at=datetime.now(UTC),
        remote_web_apps=[
            _remote("grafana", managed=True, address=GRAFANA),
            _remote("stranger", managed=False, address="stranger.example.net"),
        ],
    )
    bundle.certs.mint_leaf({GRAFANA, "stranger.example.net"})
    bundle.deps.probe = runner
    return bundle


def _runner(root: Path, *, enabled: bool = True) -> ProbeRunner:
    paths = RuntimePaths(
        pki_dir=root / "pki",
        recording_spool_dir=root / "spool",
        k8s_creds_dir=root / "k8s-creds",
        upstream_ca_dir=root / "upstream-ca",
        k8s_source_root=root / "k8s-src",
        webapp_ca_root=root / "webapp-cas",
        public_tls_root=root / "public-tls-src",
        public_tls_dir=root / "public-tls",
    )
    return ProbeRunner(paths, enabled=enabled)


async def _entries(bundle: DepsBundle) -> dict[str, dict[str, Any]]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(bundle.deps)),
        base_url="http://gwops",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    ) as client:
        response = await client.get("/status")
    assert response.status_code == 200, response.text
    return {e["name"]: e for e in response.json()["web_apps"]["readiness"]}


class TestFlagOff:
    async def test_no_runner_leaves_probe_null(self, tmp_path: Path) -> None:
        """Without a runner every entry's probe is null and no probe reason is added."""
        entries = await _entries(_bundle(tmp_path, None))

        assert entries["grafana"]["probe"] is None
        assert not any(r.startswith("probe") for e in entries.values() for r in e["reasons"])

    async def test_a_disabled_runner_is_ignored_even_with_results(self, tmp_path: Path) -> None:
        """Results and unverifiable names on a disabled runner never reach /status."""
        runner = _runner(tmp_path, enabled=False)
        runner.results["r-grafana"] = _result("untrusted_issuer")
        runner.unverifiable = frozenset({"r-stranger"})

        entries = await _entries(_bundle(tmp_path, runner))

        assert all(e["probe"] is None for e in entries.values())
        assert not any(r.startswith("probe") for e in entries.values() for r in e["reasons"])


class TestFlagOn:
    async def test_an_ok_result_fills_probe_and_keeps_the_state(self, tmp_path: Path) -> None:
        """An ok probe reports its fields and adds no reason."""
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        without = await _entries(_bundle(tmp_path / "a", None))
        runner = _runner(tmp_path)
        runner.results["r-grafana"] = _result("ok")

        entries = await _entries(_bundle(tmp_path / "b", runner))

        assert entries["grafana"]["probe"] == {
            "outcome": "ok", "checked_at": CHECKED_AT.isoformat(), "target": f"{GRAFANA}:443",
            "error_type": None, "verify_code": None,
        }
        assert entries["grafana"]["state"] == without["grafana"]["state"]
        assert entries["grafana"]["reasons"] == without["grafana"]["reasons"]

    @pytest.mark.parametrize(
        "outcome", ["untrusted_issuer", "hostname", "tls12_only", "unreachable"]
    )
    async def test_a_failed_outcome_adds_a_reason_and_needs_action(
        self, tmp_path: Path, outcome: ProbeOutcome
    ) -> None:
        """A non-ok outcome adds ``probe:<outcome>`` and the entry is action_required."""
        runner = _runner(tmp_path)
        runner.results["r-grafana"] = _result(outcome)

        entries = await _entries(_bundle(tmp_path, runner))

        entry = entries["grafana"]
        assert entry["probe"]["outcome"] == outcome
        assert f"probe:{outcome}" in entry["reasons"]
        assert entry["state"] == "action_required"

    async def test_the_error_type_and_verify_code_reach_status(self, tmp_path: Path) -> None:
        runner = _runner(tmp_path)
        runner.results["r-grafana"] = ProbeResult(
            "untrusted_issuer", CHECKED_AT, f"{GRAFANA}:443", "SSLCertVerificationError", 20
        )

        entries = await _entries(_bundle(tmp_path, runner))

        assert entries["grafana"]["probe"]["error_type"] == "SSLCertVerificationError"
        assert entries["grafana"]["probe"]["verify_code"] == 20

    async def test_an_unusable_ca_is_its_own_reason_and_needs_action(self, tmp_path: Path) -> None:
        runner = _runner(tmp_path)
        runner.results["r-grafana"] = _result("ca_unusable")

        entries = await _entries(_bundle(tmp_path, runner))

        assert "probe_ca_unusable" in entries["grafana"]["reasons"]
        assert not any(r.startswith("probe:") for r in entries["grafana"]["reasons"])
        assert entries["grafana"]["state"] == "action_required"

    async def test_an_unverifiable_unmanaged_app_keeps_its_actionable_reason(
        self, tmp_path: Path
    ) -> None:
        """An unmanaged app outside the allowlist: probe_unverifiable and unmanaged, action wins."""
        runner = _runner(tmp_path)
        runner.unverifiable = frozenset({"r-stranger"})

        entries = await _entries(_bundle(tmp_path, runner))

        assert "probe_unverifiable" in entries["stranger"]["reasons"]
        assert "unmanaged" in entries["stranger"]["reasons"]
        assert entries["stranger"]["state"] == "action_required"
        assert entries["stranger"]["probe"] is None
        assert "probe_unverifiable" not in entries["grafana"]["reasons"]

    async def test_a_name_collision_does_not_share_a_result(self, tmp_path: Path) -> None:
        """A result stored under the name never reaches an entry that has a tenant id."""
        runner = _runner(tmp_path)
        runner.results["grafana"] = _result("untrusted_issuer")

        entries = await _entries(_bundle(tmp_path, runner))

        assert entries["grafana"]["probe"] is None

    async def test_a_pending_batch_marks_verifiable_entries_pending_and_changes_no_state(
        self, tmp_path: Path
    ) -> None:
        """With the flag on and no result yet, probe is null and probe_pending is informational."""
        without = await _entries(_bundle(tmp_path, None))
        (tmp_path / "b").mkdir()
        entries = await _entries(_bundle(tmp_path / "b", _runner(tmp_path / "b")))

        for name in ("grafana", "stranger"):
            assert entries[name]["probe"] is None
            assert "probe_pending" in entries[name]["reasons"]
            assert entries[name]["state"] == without[name]["state"]

    async def test_a_failed_probe_is_a_probe_error_and_unverifiable(self, tmp_path: Path) -> None:
        runner = _runner(tmp_path)
        runner.failed["r-grafana"] = "RuntimeError"

        entries = await _entries(_bundle(tmp_path, runner))

        assert "probe_error:RuntimeError" in entries["grafana"]["reasons"]
        assert "probe_pending" not in entries["grafana"]["reasons"]
        assert "probe_pending" in entries["stranger"]["reasons"]

    async def test_a_failed_batch_marks_every_unanswered_entry(self, tmp_path: Path) -> None:
        runner = _runner(tmp_path)
        runner.last_batch_error = "OSError"

        entries = await _entries(_bundle(tmp_path, runner))

        assert all("probe_error:OSError" in e["reasons"] for e in entries.values())

    async def test_a_refused_address_is_reported_without_an_outcome(self, tmp_path: Path) -> None:
        runner = _runner(tmp_path)
        runner.refused.add("r-grafana")

        entries = await _entries(_bundle(tmp_path, runner))

        assert "probe_refused_address" in entries["grafana"]["reasons"]
        assert entries["grafana"]["probe"] is None

    async def test_status_reads_a_snapshot_not_the_mutable_dicts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = _runner(tmp_path)
        runner.results["r-grafana"] = _result("ok")
        calls = {"n": 0}
        real = runner.snapshot

        def counting() -> Any:
            calls["n"] += 1
            return real()

        monkeypatch.setattr(runner, "snapshot", counting)

        entries = await _entries(_bundle(tmp_path, runner))

        assert calls["n"] == 1
        assert entries["grafana"]["probe"]["outcome"] == "ok"

    async def test_a_failing_merge_marks_every_entry_unverifiable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An exception in the merge leaves /status 200, never silently unmerged entries."""
        runner = _runner(tmp_path)
        runner.results["r-grafana"] = _result("ok")

        def boom(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("merge exploded")

        monkeypatch.setattr(webapp_readiness, "apply_probe", boom)

        entries = await _entries(_bundle(tmp_path, runner))

        assert all(e["state"] == "unverifiable" for e in entries.values())
        assert all("computation_failed" in e["reasons"] for e in entries.values())
        assert entries["grafana"]["probe"] is None


class TestApplyProbe:
    @staticmethod
    def _entry(
        name: str, state: webapp_readiness.ReadinessState = "ready", *, id: str | None = None,
        upstream_tls: str = "verify_full",
    ) -> Any:
        return webapp_readiness.ReadinessEntry(
            name=name, id=id, managed=True, upstream_tls=upstream_tls,
            downstream_tls="tls13", state=state, reasons=["byo_ca"],
        )

    def test_results_are_looked_up_by_id_then_name(self) -> None:
        """An entry with a tenant id reads its id's result; one without reads its name's."""
        results = {"id-a": _result("hostname"), "b": _result("ok")}

        merged = webapp_readiness.apply_probe(
            [self._entry("a", id="id-a"), self._entry("b")], results, set()
        )

        assert [m.probe["outcome"] for m in merged if m.probe] == ["hostname", "ok"]

    def test_an_insecure_upstream_is_never_pending(self) -> None:
        """Only entries whose upstream verifies are probe-eligible."""
        [merged] = webapp_readiness.apply_probe(
            [self._entry("a", upstream_tls="insecure")], {}, set()
        )

        assert merged.reasons == ["byo_ca"]

    def test_a_pending_entry_stays_ready(self) -> None:
        [merged] = webapp_readiness.apply_probe([self._entry("a")], {}, set())

        assert merged.reasons == ["byo_ca", "probe_pending"]
        assert merged.state == "ready"

    def test_a_probe_error_outranks_ready_but_not_an_actionable_reason(self) -> None:
        ready = self._entry("a")
        needs = webapp_readiness.ReadinessEntry(
            "b", None, True, "verify_full", "tls13", "action_required", ["san_missing:b"]
        )

        merged = webapp_readiness.apply_probe(
            [ready, needs], {}, set(), failed={"a": "OSError", "b": "OSError"}
        )

        assert [m.state for m in merged] == ["unverifiable", "action_required"]

    def test_a_result_wins_over_failure_refusal_and_unverifiable(self) -> None:
        [merged] = webapp_readiness.apply_probe(
            [self._entry("a")], {"a": _result("ok")}, {"a"}, failed={"a": "X"}, refused={"a"},
            last_batch_error="Y",
        )

        assert merged.reasons == ["byo_ca"]

    def test_a_probe_failure_overrides_an_informational_state(self) -> None:
        """A ready entry (informational reasons only) becomes action_required on a failed probe."""
        [merged] = webapp_readiness.apply_probe(
            [self._entry("a")], {"a": _result("hostname")}, set()
        )

        assert merged.state == "action_required"
        assert merged.reasons == ["byo_ca", "probe:hostname"]

    def test_entries_are_not_mutated(self) -> None:
        """apply_probe returns new entries and leaves its input alone."""
        entry = self._entry("a")

        webapp_readiness.apply_probe([entry], {"a": _result("unreachable")}, {"a"})

        assert entry.reasons == ["byo_ca"]
        assert entry.probe is None
        assert entry.state == "ready"

    def test_a_result_wins_over_an_unverifiable_listing(self) -> None:
        """A name with a result is probed; the unverifiable reason is only for unprobed names."""
        [merged] = webapp_readiness.apply_probe([self._entry("a")], {"a": _result("ok")}, {"a"})

        assert merged.probe is not None
        assert "probe_unverifiable" not in merged.reasons
        assert merged.state == "ready"
