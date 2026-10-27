"""GET /status web-app surface: web_apps, tg.gateway_mismatches, tls, jwks, housekeeping.

Pinned shapes (see tests/test_webapp_readiness.py for the readiness reason codes):

* ``web_apps.counts``: ``{declared, managed_on_tenant, unmanaged_on_this_gateway}``; the last two,
  ``unmanaged`` and ``unserved`` are null when the last pass did not list the tenant.
* ``web_apps.readiness_status``: ``ok`` | ``tenant_unlisted`` | ``computation_failed`` (with
  ``error_type``). ``web_apps.automation_off_policy``: ``{entries, computation_failed}``.
* ``web_apps.warnings``: ``last_reconcile`` result's ``webapp_warnings``, verbatim.
* ``web_apps.unmanaged``: undeclared apps on this gateway, ``{name, id, flags}``; flags are
  ``trusted_name_rewrite``, ``invalid_rewrite``, ``plaintext_mode`` (upstream or downstream none).
* ``web_apps.unserved``: ``[{name, id}]`` for every app on this gateway when none is declared.
* ``web_apps.readiness``: the entries of ``compute_readiness`` for the current state.
"""

import dataclasses
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx
import yaml

from gwops.access import webapp_policy
from gwops.acme.runner import AcmeCertState
from gwops.acme.state import AcmeErrorClass
from gwops.api.app import create_app
from gwops.configmodel.loader import load_effective_state
from gwops.jwks import JwksMonitor, JwksStatus
from gwops.reconciler.core import (
    AcmeError,
    GatewayMismatch,
    PublicCertStatus,
    ReconcileResult,
    RegisteredRootStatus,
)
from gwops.tgapi.client import TGClient
from tests.public_tls_support import ZONE

from .acme_support import (
    ACME_CERT,
    ACME_HOST,
    StubAcmeRunner,
    acme_bundle,
    acme_seed,
    acme_snapshot,
    cert_snapshot,
)
from .conftest import ADMIN_TOKEN, DepsBundle, make_deps

GW = "g-1"
GRAFANA = "grafana.corp.internal"
ALIAS = "grafana.alt.internal"
_JWKS_URL = "https://acme.twingate.com/api/v1/jwk/ec"
_JWKS_FIXTURE = Path(__file__).parent.parent / "fixtures" / "tg" / "jwks_acme.json"
_NAME_NOT_ALLOWED = "header name not in admin_api.automation.web_apps.request_header_names"
_NOT_VERIFY_FULL = "only verify_full is allowed for the automation token"
_BYO_CA = {
    "x509": {"generate": False, "cert_path": "/config/ca/ca.crt", "key_path": "/config/ca/ca.key"}
}
_BLOCKS = {
    "counts", "warnings", "browser_trust", "unmanaged", "unserved", "automation_off_policy",
    "readiness", "readiness_status",
}
_ENTRY_KEYS = {
    "name", "id", "managed", "upstream_tls", "downstream_tls", "state", "reasons", "probe",
}


def _seed(
    *,
    web_apps: list[dict[str, Any]] | None = None,
    ca: dict[str, Any] | None = None,
    proxy: dict[str, Any] | None = None,
    names: list[str] | None = None,
) -> str:
    doc: dict[str, Any] = {
        "twingate": {"network": "acme", "gateway_id": GW},
        "ssh_upstreams": [{"name": "host1", "address": "10.0.0.5:22"}],
        "web_apps": web_apps or [],
        "admin_api": {
            "automation": {
                "name_prefix": "auto-",
                "web_apps": {
                    "enabled": True,
                    "request_header_names": ["X-Team", "x-env"] if names is None else names,
                },
            }
        },
    }
    if ca is not None:
        doc["ca"] = ca
    if proxy is not None:
        doc["web_app_proxy"] = proxy
    return yaml.safe_dump(doc, sort_keys=False)


def _remote(name: str = "grafana", **fields: Any) -> Any:
    from gwops.reconciler.core import RemoteWebApp

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


def _result(**fields: Any) -> ReconcileResult:
    return ReconcileResult(ok=True, trigger="tick", started_at=datetime.now(UTC), **fields)


def _bundle(tmp_path: Path, seed: str, result: ReconcileResult | None = None) -> DepsBundle:
    bundle = make_deps(tmp_path, seed=seed, admin_token=ADMIN_TOKEN)
    bundle.reconciler.last_result = result
    return bundle


async def _get(bundle: DepsBundle, path: str = "/status", *, auth: bool = True) -> httpx.Response:
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"} if auth else {}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(bundle.deps)),
        base_url="http://gwops",
        headers=headers,
    ) as client:
        return await client.get(path)


async def _status(bundle: DepsBundle) -> dict[str, Any]:
    response = await _get(bundle)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _break_readiness(monkeypatch: pytest.MonkeyPatch) -> None:
    import gwops.api.routes_state as routes_state
    import gwops.reconciler.core as core
    import gwops.webapp_readiness as readiness

    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("readiness exploded")

    for module in (readiness, routes_state, core):
        if hasattr(module, "compute_readiness"):
            monkeypatch.setattr(module, "compute_readiness", boom)


class TestNoResultYet:
    async def test_every_block_is_present_with_empty_values(self, tmp_path: Path) -> None:
        """Before the first pass the blocks exist and are empty, not missing and not a 500."""
        body = await _status(_bundle(tmp_path, _seed(), None))

        web_apps = body["web_apps"]
        assert set(web_apps) >= _BLOCKS
        assert web_apps["counts"] == {
            "declared": 0, "managed_on_tenant": None, "unmanaged_on_this_gateway": None,
        }
        assert web_apps["warnings"] == []
        assert web_apps["unmanaged"] is None
        assert web_apps["unserved"] is None
        assert web_apps["automation_off_policy"] == {"entries": [], "computation_failed": False}
        assert web_apps["readiness"] == []
        assert web_apps["readiness_status"] == "tenant_unlisted"
        assert body["tg"]["gateway_mismatches"] == {}
        assert body["tls"] == {"mode": "static", "warning": None}
        assert body["jwks"] is None
        assert body["housekeeping"] == {"errors": [], "ran": False}
        assert body["last_reconcile"] is None

    async def test_a_result_without_tenant_data_gives_empty_remote_blocks(
        self, tmp_path: Path
    ) -> None:
        """A pass that never listed the tenant (snapshot None) reports empty remote blocks."""
        seed = _seed(web_apps=[{"name": "grafana", "address": GRAFANA}])
        body = await _status(_bundle(tmp_path, seed, _result(remote_web_apps=None)))

        web_apps = body["web_apps"]
        assert web_apps["counts"]["declared"] == 1
        assert web_apps["counts"]["managed_on_tenant"] is None
        assert web_apps["counts"]["unmanaged_on_this_gateway"] is None
        assert web_apps["unmanaged"] is None
        assert web_apps["unserved"] is None
        assert web_apps["readiness"] == []
        assert web_apps["readiness_status"] == "tenant_unlisted"


class TestSnapshotFailure:
    async def test_a_listed_tenant_whose_snapshot_failed_is_computation_failed(
        self, tmp_path: Path
    ) -> None:
        """Not `tenant_unlisted`: the tenant was listed, gwops failed to read it."""
        seed = _seed(web_apps=[{"name": "grafana", "address": GRAFANA}])
        result = _result(remote_web_apps=None, remote_web_apps_error="KeyError")

        web_apps = (await _status(_bundle(tmp_path, seed, result)))["web_apps"]

        assert web_apps["readiness_status"] == "computation_failed"
        assert web_apps["error_type"] == "KeyError"
        assert web_apps["readiness"] == []
        assert web_apps["counts"]["managed_on_tenant"] is None

    async def test_an_unlisted_tenant_without_an_error_stays_tenant_unlisted(
        self, tmp_path: Path
    ) -> None:
        """An outage is still reported as `tenant_unlisted`, with no error type."""
        web_apps = (await _status(_bundle(tmp_path, _seed(), _result(remote_web_apps=None))))[
            "web_apps"
        ]

        assert web_apps["readiness_status"] == "tenant_unlisted"
        assert "error_type" not in web_apps


class TestCounts:
    async def test_counts_split_declared_managed_and_unmanaged_on_this_gateway(
        self, tmp_path: Path
    ) -> None:
        """Unmanaged apps on other gateways are not counted."""
        seed = _seed(
            web_apps=[
                {"name": "grafana", "address": GRAFANA},
                {"name": "wiki", "address": "wiki.corp.internal"},
            ]
        )
        result = _result(
            remote_web_apps=[
                _remote("grafana"),
                _remote("wiki"),
                _remote("stranger", managed=False),
                _remote("elsewhere", managed=False, gateway_id="g-other"),
            ]
        )

        body = await _status(_bundle(tmp_path, seed, result))

        assert body["web_apps"]["counts"] == {
            "declared": 2, "managed_on_tenant": 2, "unmanaged_on_this_gateway": 1,
        }


class TestWarnings:
    async def test_the_current_policy_warnings_are_reported_verbatim(self, tmp_path: Path) -> None:
        """All four warning classes surface exactly as the policy words them."""
        web_apps = [
            {"name": "ca-only", "address": "ca.corp.internal", "upstream_tls": "verify_ca"},
            {"name": "weak", "address": "weak.corp.internal", "upstream_tls": "insecure"},
            {"name": "plain-up", "address": "up.corp.internal", "upstream_tls": "none"},
            {"name": "plain-down", "address": "down.corp.internal", "downstream": {"tls": "none"}},
        ]
        proxy = {"plaintext_upstreams": {"dns_suffixes": ["corp.internal"]}}
        bundle = _bundle(tmp_path, _seed(web_apps=web_apps, proxy=proxy))
        state, _provenance = load_effective_state(bundle.seed_path, bundle.store)
        expected = webapp_policy.warnings(state)
        assert len(expected) == 4
        bundle.reconciler.last_result = _result(remote_web_apps=[], webapp_warnings=expected)

        body = await _status(bundle)

        assert body["web_apps"]["warnings"] == expected
        joined = " ".join(expected)
        for needle in ("verify_ca", "insecure", "upstream_tls 'none'", "downstream.tls 'none'"):
            assert needle in joined

    async def test_a_clean_result_reports_no_warnings(self, tmp_path: Path) -> None:
        """No warnings on the result means an empty list."""
        body = await _status(_bundle(tmp_path, _seed(), _result(remote_web_apps=[])))

        assert body["web_apps"]["warnings"] == []


class TestBrowserTrust:
    async def test_a_generated_x509_ca_carries_a_note(self, tmp_path: Path) -> None:
        """The default (gwops-generated) CA yields a non-empty browser-trust note."""
        seed = _seed(web_apps=[{"name": "grafana", "address": GRAFANA}])
        body = await _status(_bundle(tmp_path, seed, _result(remote_web_apps=[])))

        note = body["web_apps"]["browser_trust"]
        assert isinstance(note, str)
        assert note

    async def test_a_byo_x509_ca_has_no_note(self, tmp_path: Path) -> None:
        """A bring-your-own CA is the operator's to distribute: the note is null."""
        seed = _seed(web_apps=[{"name": "grafana", "address": GRAFANA}], ca=_BYO_CA)
        body = await _status(_bundle(tmp_path, seed, _result(remote_web_apps=[])))

        assert body["web_apps"]["browser_trust"] is None


class TestUnmanaged:
    _PROXY = {"request_headers": {"X-Twingate-User": "{{username}}"}}

    async def _unmanaged(self, tmp_path: Path, *apps: Any) -> dict[str, dict[str, Any]]:
        seed = _seed(web_apps=[{"name": "grafana", "address": GRAFANA}], proxy=self._PROXY)
        result = _result(remote_web_apps=[_remote("grafana"), *apps])
        body = await _status(_bundle(tmp_path, seed, result))
        return {entry["name"]: entry for entry in body["web_apps"]["unmanaged"]}

    async def test_an_app_with_nothing_wrong_is_listed_without_flags(
        self, tmp_path: Path
    ) -> None:
        """An undeclared app on this gateway is listed even when nothing is flagged."""
        entries = await self._unmanaged(tmp_path, _remote("stranger", managed=False))

        assert set(entries) == {"stranger"}
        assert entries["stranger"]["id"] == "r-stranger"
        assert entries["stranger"]["flags"] == []

    async def test_a_rewrite_of_a_trusted_gateway_header_name_is_flagged(
        self, tmp_path: Path
    ) -> None:
        """A per-app rewrite of a gateway-wide identity header name is flagged."""
        stranger = _remote("stranger", managed=False, header_rewrite_names=("x-twingate-user",))

        entries = await self._unmanaged(tmp_path, stranger)

        assert set(entries["stranger"]["flags"]) == {"trusted_name_rewrite"}

    @pytest.mark.parametrize("name", ["host", "x-forwarded-for", "transfer-encoding"])
    async def test_a_rewrite_of_a_denied_header_name_is_flagged_invalid(
        self, tmp_path: Path, name: str
    ) -> None:
        """A rewrite the policy would refuse (hop-by-hop, forwarding, Host) is flagged."""
        stranger = _remote("stranger", managed=False, header_rewrite_names=(name,))

        entries = await self._unmanaged(tmp_path, stranger)

        assert set(entries["stranger"]["flags"]) == {"invalid_rewrite"}

    @pytest.mark.parametrize(
        "modes",
        [{"upstream_tls": "none"}, {"downstream_tls": "none"}],
        ids=["upstream", "downstream"],
    )
    async def test_a_plaintext_mode_is_flagged(
        self, tmp_path: Path, modes: dict[str, str]
    ) -> None:
        """Plaintext on either leg is flagged."""
        stranger = _remote("stranger", managed=False, **modes)

        entries = await self._unmanaged(tmp_path, stranger)

        assert set(entries["stranger"]["flags"]) == {"plaintext_mode"}

    async def test_several_problems_give_several_flags(self, tmp_path: Path) -> None:
        """Each category is reported independently."""
        stranger = _remote(
            "stranger",
            managed=False,
            upstream_tls="none",
            header_rewrite_names=("x-twingate-user", "host"),
        )

        entries = await self._unmanaged(tmp_path, stranger)

        assert set(entries["stranger"]["flags"]) == {
            "trusted_name_rewrite", "invalid_rewrite", "plaintext_mode",
        }

    async def test_managed_and_foreign_gateway_apps_are_not_listed(self, tmp_path: Path) -> None:
        """Only undeclared apps on this gateway appear."""
        elsewhere = _remote("elsewhere", managed=False, gateway_id="g-other")

        entries = await self._unmanaged(tmp_path, elsewhere)

        assert entries == {}

    async def test_header_values_are_never_reported(self, tmp_path: Path) -> None:
        """The block carries names only; the snapshot has no values to leak."""
        stranger = _remote("stranger", managed=False, header_rewrite_names=("x-twingate-user",))
        seed = _seed(web_apps=[{"name": "grafana", "address": GRAFANA}], proxy=self._PROXY)
        body = await _status(
            _bundle(tmp_path, seed, _result(remote_web_apps=[_remote("grafana"), stranger]))
        )

        assert "{{username}}" not in json.dumps(body["web_apps"])


class TestUnserved:
    async def test_with_nothing_declared_every_app_on_this_gateway_is_unserved(
        self, tmp_path: Path
    ) -> None:
        """No declared web apps: every app on this gateway is listed, others are not."""
        result = _result(
            remote_web_apps=[
                _remote("one", managed=False),
                _remote("two", managed=False),
                _remote("elsewhere", managed=False, gateway_id="g-other"),
            ]
        )

        body = await _status(_bundle(tmp_path, _seed(), result))

        unserved = body["web_apps"]["unserved"]
        assert {e["name"] for e in unserved} == {"one", "two"}
        assert {e["id"] for e in unserved} == {"r-one", "r-two"}

    async def test_with_a_declared_web_app_nothing_is_unserved(self, tmp_path: Path) -> None:
        """Declaring any web app empties the unserved list."""
        seed = _seed(web_apps=[{"name": "grafana", "address": GRAFANA}])
        result = _result(remote_web_apps=[_remote("grafana"), _remote("one", managed=False)])

        body = await _status(_bundle(tmp_path, seed, result))

        assert body["web_apps"]["unserved"] == []


class TestAutomationOffPolicy:
    @staticmethod
    def _automation_entry(bundle: DepsBundle, name: str = "auto-a", **fields: Any) -> None:
        entry = {"name": name, "address": f"{name}.apps.example.com", **fields}
        bundle.store.add({"web_apps": [entry]}, comment="automation", origin="automation")

    async def test_an_entry_within_the_field_policy_is_not_listed(self, tmp_path: Path) -> None:
        """In-policy automation entries produce an empty list."""
        bundle = _bundle(tmp_path, _seed(), _result(remote_web_apps=[]))
        self._automation_entry(
            bundle, request_headers={"X-Team": "{{username}}", "x-env": "{{groups}}"}
        )

        body = await _status(bundle)

        assert body["web_apps"]["automation_off_policy"]["entries"] == []

    async def test_narrowing_the_seed_lists_the_entry_with_its_violations(
        self, tmp_path: Path
    ) -> None:
        """Dropping a header name from the seed puts the automation entry off policy."""
        bundle = _bundle(tmp_path, _seed(), _result(remote_web_apps=[]))
        self._automation_entry(
            bundle, request_headers={"X-Team": "{{username}}", "x-env": "{{groups}}"}
        )
        bundle.seed_path.write_text(_seed(names=["X-Team"]), encoding="utf-8")

        body = await _status(bundle)

        assert body["web_apps"]["automation_off_policy"]["entries"] == [
            {
                "name": "auto-a",
                "violations": [{"field": "request_headers.x-env", "reason": _NAME_NOT_ALLOWED}],
            }
        ]

    async def test_an_upstream_mode_other_than_verify_full_is_listed(self, tmp_path: Path) -> None:
        """A weakened upstream mode on an automation entry is an upstream_tls violation."""
        bundle = _bundle(tmp_path, _seed(), _result(remote_web_apps=[]))
        self._automation_entry(bundle, upstream_tls="verify_ca")

        body = await _status(bundle)

        assert body["web_apps"]["automation_off_policy"]["entries"] == [
            {
                "name": "auto-a",
                "violations": [{"field": "upstream_tls", "reason": _NOT_VERIFY_FULL}],
            }
        ]

    async def test_seed_and_admin_entries_are_never_listed(self, tmp_path: Path) -> None:
        """Only automation-owned entries are checked against the automation field policy."""
        seed = _seed(
            web_apps=[
                {"name": "seed-ca", "address": "seed.corp.internal", "upstream_tls": "verify_ca"}
            ]
        )
        bundle = _bundle(tmp_path, seed, _result(remote_web_apps=[]))
        bundle.store.add(
            {"web_apps": [{"name": "admin-ca", "address": "a.corp.internal",
                           "upstream_tls": "verify_ca"}]},
            comment="admin",
            origin="admin",
        )

        body = await _status(bundle)

        assert body["web_apps"]["automation_off_policy"]["entries"] == []

    async def test_every_off_policy_entry_is_listed_once(self, tmp_path: Path) -> None:
        """Two off-policy automation entries produce two list items."""
        bundle = _bundle(tmp_path, _seed(), _result(remote_web_apps=[]))
        self._automation_entry(bundle, "auto-a", upstream_tls="verify_ca")
        self._automation_entry(bundle, "auto-b", upstream_tls="insecure")

        body = await _status(bundle)

        assert sorted(e["name"] for e in body["web_apps"]["automation_off_policy"]["entries"]) == [
            "auto-a", "auto-b",
        ]


class TestReadiness:
    _WEB_APPS = [{"name": "grafana", "address": GRAFANA}]

    async def test_a_covered_byo_ca_app_is_ready_with_every_documented_key(
        self, tmp_path: Path
    ) -> None:
        """The /status entry carries the readiness fields and a null probe slot."""
        bundle = _bundle(
            tmp_path,
            _seed(web_apps=self._WEB_APPS, ca=_BYO_CA),
            _result(remote_web_apps=[_remote()]),
        )
        bundle.certs.mint_leaf({GRAFANA})

        body = await _status(bundle)

        [entry] = body["web_apps"]["readiness"]
        assert set(entry) == _ENTRY_KEYS
        assert (entry["name"], entry["id"], entry["managed"]) == ("grafana", "r-grafana", True)
        assert (entry["upstream_tls"], entry["downstream_tls"]) == ("verify_full", "tls13")
        assert entry["state"] == "ready"
        assert entry["probe"] is None

    async def test_a_name_missing_from_the_current_leaf_is_action_required(
        self, tmp_path: Path
    ) -> None:
        """The leaf's real SANs decide coverage; the on-demand excuse is off in static mode."""
        bundle = _bundle(
            tmp_path,
            _seed(web_apps=self._WEB_APPS, ca=_BYO_CA),
            _result(remote_web_apps=[_remote()]),
        )
        bundle.certs.mint_leaf({"other.corp.internal"})

        body = await _status(bundle)

        [entry] = body["web_apps"]["readiness"]
        assert entry["state"] == "action_required"
        assert any(r.startswith("san_missing") for r in entry["reasons"])
        assert not any(r.startswith("covered_on_demand") for r in entry["reasons"])

    async def test_a_generated_ca_with_tls13_notes_operator_action_and_stays_ready(
        self, tmp_path: Path
    ) -> None:
        """The seed's CA source decides operator_action versus byo_ca; neither blocks."""
        bundle = _bundle(
            tmp_path, _seed(web_apps=self._WEB_APPS), _result(remote_web_apps=[_remote()])
        )
        bundle.certs.mint_leaf({GRAFANA})

        body = await _status(bundle)

        [entry] = body["web_apps"]["readiness"]
        assert entry["state"] == "ready"
        assert "operator_action" in entry["reasons"]

    async def test_unmanaged_apps_on_this_gateway_get_entries(self, tmp_path: Path) -> None:
        """Readiness covers undeclared apps on this gateway and skips other gateways."""
        bundle = _bundle(
            tmp_path,
            _seed(web_apps=self._WEB_APPS, ca=_BYO_CA),
            _result(
                remote_web_apps=[
                    _remote(),
                    _remote("stranger", managed=False),
                    _remote("elsewhere", managed=False, gateway_id="g-other"),
                ]
            ),
        )
        bundle.certs.mint_leaf({GRAFANA})

        body = await _status(bundle)

        entries = {e["name"]: e for e in body["web_apps"]["readiness"]}
        assert set(entries) == {"grafana", "stranger"}
        assert entries["stranger"]["managed"] is False
        assert entries["stranger"]["state"] == "action_required"

    async def test_a_registry_recorded_gateway_id_scopes_the_report(self, tmp_path: Path) -> None:
        """In remote-network mode the gateway id comes from the registry, not the seed."""
        seed = yaml.safe_dump(
            {
                "twingate": {
                    "network": "acme",
                    "remote_network_id": "rn-1",
                    "gateway_address": "203.0.113.10:8443",
                },
                "web_apps": self._WEB_APPS,
                "ca": _BYO_CA,
            },
            sort_keys=False,
        )
        bundle = _bundle(
            tmp_path, seed, _result(remote_web_apps=[_remote(gateway_id="gw-real")])
        )
        bundle.deps.registry.record("gateway", "self", "gw-real")
        bundle.certs.mint_leaf({GRAFANA})

        body = await _status(bundle)

        assert [e["name"] for e in body["web_apps"]["readiness"]] == ["grafana"]


    async def test_a_listed_tenant_reports_ok(self, tmp_path: Path) -> None:
        bundle = _bundle(
            tmp_path,
            _seed(web_apps=self._WEB_APPS, ca=_BYO_CA),
            _result(remote_web_apps=[_remote()]),
        )
        bundle.certs.mint_leaf({GRAFANA})

        body = await _status(bundle)

        assert body["web_apps"]["readiness_status"] == "ok"
        assert "error_type" not in body["web_apps"]

    async def test_a_declared_app_missing_from_the_tenant_is_not_on_tenant(
        self, tmp_path: Path
    ) -> None:
        bundle = _bundle(
            tmp_path,
            _seed(web_apps=self._WEB_APPS, ca=_BYO_CA),
            _result(remote_web_apps=[]),
        )
        bundle.certs.mint_leaf({GRAFANA})

        body = await _status(bundle)

        [entry] = body["web_apps"]["readiness"]
        assert (entry["name"], entry["id"], entry["managed"]) == ("grafana", None, True)
        assert entry["state"] == "action_required"
        assert entry["reasons"] == ["not_on_tenant"]

    async def test_a_missing_leaf_is_leaf_unreadable_not_a_san_per_app(
        self, tmp_path: Path
    ) -> None:
        bundle = _bundle(
            tmp_path,
            _seed(web_apps=self._WEB_APPS, ca=_BYO_CA),
            _result(remote_web_apps=[_remote()]),
        )

        body = await _status(bundle)

        [entry] = body["web_apps"]["readiness"]
        assert "leaf_unreadable" in entry["reasons"]
        assert not any(r.startswith(("san_missing", "covered_on_demand")) for r in entry["reasons"])
        assert entry["state"] == "unverifiable"

    async def test_owners_are_computed_once_however_many_entries_are_declared(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from gwops.api import status_webapps

        calls = {"n": 0}
        real = status_webapps.entry_owners

        def counting(*args: Any, **kwargs: Any) -> Any:
            calls["n"] += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(status_webapps, "entry_owners", counting)
        web_apps = [{"name": f"app{i}", "address": f"app{i}.corp.internal"} for i in range(6)]

        await _status(_bundle(tmp_path, _seed(web_apps=web_apps), _result(remote_web_apps=[])))

        assert calls["n"] == 1


class TestGatewayMismatches:
    @pytest.mark.parametrize("corrected", [False, True])
    async def test_every_kind_is_reported_with_its_corrected_flag(
        self, tmp_path: Path, corrected: bool
    ) -> None:
        """ssh, kubernetes and webapp mismatches all appear under tg.gateway_mismatches."""
        keys = ["ssh/host1", "kubernetes/prod", "webapp/grafana"]
        mismatches = {
            k: GatewayMismatch(f"gw-{i}", corrected=corrected) for i, k in enumerate(keys)
        }

        body = await _status(_bundle(tmp_path, _seed(), _result(gateway_mismatches=mismatches)))

        assert body["tg"]["gateway_mismatches"] == {
            k: {"remote_gateway_id": f"gw-{i}", "corrected": corrected}
            for i, k in enumerate(keys)
        }

    async def test_a_mismatch_is_report_only(self, tmp_path: Path) -> None:
        """Uncorrected mismatches add no tg error and leave ok untouched."""
        mismatches = {"ssh/host1": GatewayMismatch("gw-other", corrected=False)}
        bundle = _bundle(tmp_path, _seed(), _result(gateway_mismatches=mismatches))
        tg = TGClient(network="acme", api_key="test-key")
        bundle.deps = dataclasses.replace(bundle.deps, tg=tg)
        try:
            body = await _status(bundle)
        finally:
            await tg.aclose()

        assert body["tg"]["gateway_mismatches"] == {
            "ssh/host1": {"remote_gateway_id": "gw-other", "corrected": False}
        }
        assert body["tg"]["ok"] is True
        assert body["tg"]["errors"] == []
        assert body["last_reconcile"]["ok"] is True

    async def test_no_mismatch_is_an_empty_object(self, tmp_path: Path) -> None:
        """No mismatches reports an empty mapping, not null."""
        body = await _status(_bundle(tmp_path, _seed(), _result()))

        assert body["tg"]["gateway_mismatches"] == {}


class TestTls:
    async def test_the_certificate_mode_is_static_without_a_warning(self, tmp_path: Path) -> None:
        """This task reports static mode with no warning."""
        body = await _status(_bundle(tmp_path, _seed(), _result()))

        assert body["tls"] == {"mode": "static", "warning": None}


class TestJwks:
    @staticmethod
    def _with_jwks(bundle: DepsBundle, monitor: Any) -> None:
        bundle.deps = dataclasses.replace(bundle.deps, jwks=monitor)

    async def test_it_is_null_when_no_monitor_is_wired(self, tmp_path: Path) -> None:
        """deps.jwks is None -> null."""
        body = await _status(_bundle(tmp_path, _seed(), _result()))

        assert body["jwks"] is None

    async def test_it_is_null_before_the_first_check(self, tmp_path: Path) -> None:
        """A monitor with no status yet -> null."""
        bundle = _bundle(tmp_path, _seed(), _result())
        self._with_jwks(bundle, SimpleNamespace(status=None))

        assert (await _status(bundle))["jwks"] is None

    async def test_an_ok_status_is_reported(self, tmp_path: Path) -> None:
        """ok, checked_at (ISO 8601) and a null error_class."""
        checked = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
        bundle = _bundle(tmp_path, _seed(), _result())
        status = JwksStatus(ok=True, checked_at=checked, error_class=None)
        self._with_jwks(bundle, SimpleNamespace(status=status))

        body = await _status(bundle)

        assert body["jwks"] == {
            "ok": True, "checked_at": checked.isoformat(), "error_class": None, "reason": None,
        }

    async def test_a_reason_and_the_internal_error_class_pass_through(
        self, tmp_path: Path
    ) -> None:
        """A mark's reason is reported beside the error class."""
        checked = datetime(2026, 10, 7, 12, 6, tzinfo=UTC)
        bundle = _bundle(tmp_path, _seed(), _result())
        status = JwksStatus(
            ok=False, checked_at=checked, error_class="internal_error", reason="probe crashed"
        )
        self._with_jwks(bundle, SimpleNamespace(status=status))

        body = await _status(bundle)

        assert body["jwks"] == {
            "ok": False,
            "checked_at": checked.isoformat(),
            "error_class": "internal_error",
            "reason": "probe crashed",
        }

    @pytest.mark.parametrize("error_class", ["unreachable", "degraded", "invalid"])
    async def test_a_failure_reports_its_class(self, tmp_path: Path, error_class: str) -> None:
        """Each failure class passes through with ok false."""
        checked = datetime(2026, 10, 7, 12, 5, tzinfo=UTC)
        bundle = _bundle(tmp_path, _seed(), _result())
        self._with_jwks(
            bundle,
            SimpleNamespace(
                status=JwksStatus(ok=False, checked_at=checked, error_class=error_class)  # type: ignore[arg-type]
            ),
        )

        body = await _status(bundle)

        assert body["jwks"] == {
            "ok": False, "checked_at": checked.isoformat(), "error_class": error_class,
            "reason": None,
        }

    async def test_a_real_monitor_reports_the_fixture_document_as_ok(
        self, tmp_path: Path
    ) -> None:
        """End to end with the real monitor and the captured JWKS document."""
        document = json.loads(_JWKS_FIXTURE.read_text(encoding="utf-8"))
        async with httpx.AsyncClient() as client:
            monitor = JwksMonitor(client, _JWKS_URL)
            with respx.mock(assert_all_called=False) as router:
                router.get(_JWKS_URL).mock(return_value=httpx.Response(200, json=document))
                await monitor.check()
            bundle = _bundle(tmp_path, _seed(), _result())
            self._with_jwks(bundle, monitor)

            body = await _status(bundle)

        assert monitor.status is not None
        assert body["jwks"] == {
            "ok": True, "checked_at": monitor.status.checked_at.isoformat(), "error_class": None,
            "reason": None,
        }


class TestHousekeeping:
    async def test_housekeeping_errors_are_surfaced(self, tmp_path: Path) -> None:
        """The result's housekeeping errors appear under housekeeping.errors."""
        errors = ["garbage collection of the credential copies failed (PermissionError)"]

        body = await _status(_bundle(tmp_path, _seed(), _result(housekeeping_errors=errors)))

        assert body["housekeeping"] == {"errors": errors, "ran": False}

    async def test_ran_reports_whether_the_last_pass_ran_housekeeping(
        self, tmp_path: Path
    ) -> None:
        body = await _status(_bundle(tmp_path, _seed(), _result(housekeeping_ran=True)))

        assert body["housekeeping"] == {"errors": [], "ran": True}

    async def test_housekeeping_errors_do_not_change_the_pass_verdict(
        self, tmp_path: Path
    ) -> None:
        """They are a separate signal: last_reconcile and tg stay as the pass left them."""
        result = _result(housekeeping_errors=["legacy credential directory cleanup failed"])

        body = await _status(_bundle(tmp_path, _seed(), result))

        assert body["last_reconcile"]["ok"] is True
        assert body["last_reconcile"]["errors"] == []


class TestNeverFailing:
    async def test_a_readiness_failure_leaves_status_serving(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If the readiness computation raises, /status is still 200 and the rest is intact."""
        seed = _seed(web_apps=[{"name": "grafana", "address": GRAFANA}])
        mismatches = {"ssh/host1": GatewayMismatch("gw-other", corrected=False)}
        bundle = _bundle(
            tmp_path, seed, _result(remote_web_apps=[_remote()], gateway_mismatches=mismatches)
        )
        _break_readiness(monkeypatch)

        body = await _status(bundle)

        readiness = body["web_apps"]["readiness"]
        assert isinstance(readiness, list)
        assert all(entry["state"] == "unverifiable" for entry in readiness)
        assert body["web_apps"]["readiness_status"] == "computation_failed"
        assert body["web_apps"]["error_type"] == "RuntimeError"
        assert set(body["web_apps"]) >= _BLOCKS - {"readiness"}
        assert body["tg"]["gateway_mismatches"] == {
            "ssh/host1": {"remote_gateway_id": "gw-other", "corrected": False}
        }

    async def test_a_readiness_failure_with_nothing_declared_is_still_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Empty readiness is not mistaken for a healthy empty report."""
        bundle = _bundle(tmp_path, _seed(), _result(remote_web_apps=[_remote("s", managed=False)]))
        _break_readiness(monkeypatch)

        body = await _status(bundle)

        assert body["web_apps"]["readiness"] == []
        assert body["web_apps"]["readiness_status"] == "computation_failed"
        assert body["web_apps"]["error_type"] == "RuntimeError"

    async def test_a_failing_web_apps_block_degrades_without_a_500(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from gwops.api import status_webapps

        def boom(*_a: object, **_k: object) -> None:
            raise RuntimeError("flags exploded")

        monkeypatch.setattr(status_webapps, "_unmanaged_flags", boom)
        bundle = _bundle(
            tmp_path, _seed(), _result(remote_web_apps=[_remote("s", managed=False)])
        )

        body = await _status(bundle)

        web_apps = body["web_apps"]
        assert web_apps["computation_failed"] is True
        assert web_apps["error_type"] == "RuntimeError"
        assert web_apps["readiness_status"] == "computation_failed"
        assert set(web_apps) >= _BLOCKS
        assert body["tg"]["gateway_mismatches"] == {}

    async def test_a_failing_tls_block_degrades_without_a_500(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from gwops.api import status_webapps

        def boom(*_a: object, **_k: object) -> None:
            raise ValueError("mode exploded")

        monkeypatch.setattr(status_webapps, "tls_mode", boom)

        body = await _status(_bundle(tmp_path, _seed(), _result()))

        assert body["tls"] == {
            "mode": None, "warning": None, "computation_failed": True, "error_type": "ValueError",
        }

    async def test_a_failing_automation_policy_is_marked_not_hidden(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from gwops.api import status_webapps

        def boom(*_a: object, **_k: object) -> None:
            raise OSError("overlays unreadable")

        monkeypatch.setattr(status_webapps, "entry_owners", boom)

        body = await _status(_bundle(tmp_path, _seed(), _result(remote_web_apps=[])))

        assert body["web_apps"]["automation_off_policy"] == {
            "entries": [], "computation_failed": True, "error_type": "OSError",
        }
        assert "computation_failed" not in body["web_apps"]

    async def test_an_unloadable_state_is_marked_not_reported_as_healthy(
        self, tmp_path: Path
    ) -> None:
        """With no effective state, tls and automation_off_policy say so instead of defaulting."""
        bundle = _bundle(tmp_path, _seed(), _result())
        bundle.seed_path.write_text("not: [valid", encoding="utf-8")

        body = await _status(bundle)

        assert body["state_error"] is not None
        assert body["tls"] == {
            "mode": None,
            "warning": None,
            "computation_failed": True,
            "error_type": "StateUnavailable",
        }
        assert body["web_apps"]["automation_off_policy"] == {
            "entries": [],
            "computation_failed": True,
            "error_type": "StateUnavailable",
        }

    async def test_healthz_is_unaffected_by_a_readiness_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """/healthz never depends on the readiness computation."""
        seed = _seed(web_apps=[{"name": "grafana", "address": GRAFANA}])
        bundle = _bundle(tmp_path, seed, _result(remote_web_apps=[_remote()]))
        _break_readiness(monkeypatch)

        response = await _get(bundle, "/healthz", auth=False)

        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_status_requires_the_admin_token(self, tmp_path: Path) -> None:
        """These blocks are admin-only like the rest of /status."""
        bundle = _bundle(tmp_path, _seed(), _result())

        anonymous = await _get(bundle, auth=False)

        assert anonymous.status_code == 401
        assert anonymous.content == b""


# --- readiness reasons for source: acme ---------------------------------------------


def _acme_pass(*, installed: bool = False, **fields: Any) -> ReconcileResult:
    """A pass that listed the tenant (grafana on this gateway) and left the ACME cert as given."""
    from gwops.certs.public import KNOWN_ROOTS

    status = PublicCertStatus(
        name=ACME_CERT,
        names=(f"*.apps.{ZONE}",),
        not_after=datetime(2027, 1, 1, tzinfo=UTC) if installed else None,
        state="ok" if installed else "pending",
        last_error=None,
        generation="0123456789ab" if installed else None,
        source="acme",
    )
    return _result(
        remote_web_apps=[_remote(address=ACME_HOST)],
        public_certs=[status],
        registered_root=RegisteredRootStatus(
            name="isrg_root_x1", sha256=KNOWN_ROOTS["isrg_root_x1"], tg_ca_id="ca-1", bound=True
        ),
        **fields,
    )


def _production_bundle(
    tmp_path: Path, runner: StubAcmeRunner | None, **kwargs: Any
) -> DepsBundle:
    """An ACME gateway whose seed uses the production directory, so no staging reason applies."""
    return acme_bundle(tmp_path, runner, seed=acme_seed("production"), **kwargs)


async def _acme_readiness(bundle: DepsBundle) -> dict[str, Any]:
    body = await _status(bundle)
    web_apps: dict[str, Any] = body["web_apps"]
    assert web_apps["readiness_status"] == "ok", web_apps
    [entry] = web_apps["readiness"]
    assert entry["name"] == "grafana"
    result: dict[str, Any] = entry
    return result


class TestAcmeReadiness:
    async def test_a_pending_acme_certificate_is_action_required_on_the_app_it_covers(
        self, tmp_path: Path
    ) -> None:
        runner = StubAcmeRunner(snapshot=acme_snapshot(cert_snapshot(installed=False)))
        bundle = _production_bundle(tmp_path, runner)
        bundle.reconciler.last_result = _acme_pass()

        entry = await _acme_readiness(bundle)

        assert entry["reasons"] == ["public_cert_pending:issued"]
        assert entry["state"] == "action_required"

    async def test_a_failing_certificate_reports_the_class_and_the_backoff(
        self, tmp_path: Path
    ) -> None:
        runner = StubAcmeRunner(
            snapshot=acme_snapshot(
                cert_snapshot(
                    state=AcmeCertState.BACKOFF,
                    error_code=AcmeErrorClass.RATE_LIMITED,
                    in_backoff=True,
                )
            )
        )
        bundle = _production_bundle(tmp_path, runner)
        bundle.reconciler.last_result = _acme_pass(installed=True)

        entry = await _acme_readiness(bundle)

        assert entry["reasons"] == ["acme_failed:rate_limited", "acme_backoff"]
        assert entry["state"] == "action_required"

    async def test_backoff_alone_leaves_the_app_ready(self, tmp_path: Path) -> None:
        runner = StubAcmeRunner(
            snapshot=acme_snapshot(cert_snapshot(state=AcmeCertState.BACKOFF, in_backoff=True))
        )
        bundle = _production_bundle(tmp_path, runner)
        bundle.reconciler.last_result = _acme_pass(installed=True)

        entry = await _acme_readiness(bundle)

        assert entry["reasons"] == ["acme_backoff"]
        assert entry["state"] == "ready"

    async def test_a_pass_level_config_error_is_acme_failed_config(self, tmp_path: Path) -> None:
        runner = StubAcmeRunner(snapshot=acme_snapshot())
        bundle = _production_bundle(tmp_path, runner)
        bundle.reconciler.last_result = _acme_pass(
            installed=True, acme_errors=[AcmeError(None, "config", "token file missing")]
        )

        entry = await _acme_readiness(bundle)

        assert entry["reasons"] == ["acme_failed:config"]
        assert entry["state"] == "action_required"

    async def test_without_a_runner_the_certificate_is_pending_and_nothing_else(
        self, tmp_path: Path
    ) -> None:
        bundle = _production_bundle(tmp_path, None)
        bundle.reconciler.last_result = _acme_pass()

        entry = await _acme_readiness(bundle)

        assert entry["reasons"] == ["public_cert_pending:issued"]

    async def test_a_raising_snapshot_degrades_to_one_internal_reason_and_readiness_stays_ok(
        self, tmp_path: Path
    ) -> None:
        runner = StubAcmeRunner(snapshot_error=RuntimeError("boom"))
        bundle = _production_bundle(tmp_path, runner)
        bundle.reconciler.last_result = _acme_pass()

        response = await _get(bundle)

        assert response.status_code == 200
        web_apps = response.json()["web_apps"]
        assert web_apps["readiness_status"] == "ok"
        assert "error_type" not in web_apps
        [entry] = web_apps["readiness"]
        assert entry["reasons"] == ["public_cert_pending:issued", "acme_failed:internal"]
        assert entry["state"] == "action_required"
        assert "boom" not in response.text

    async def test_file_certificate_readiness_ignores_the_runner(self, tmp_path: Path) -> None:
        """The app served by the file cert `wild` stays ready whatever the runner reports."""
        from gwops.certs.public import KNOWN_ROOTS

        runner = StubAcmeRunner(
            snapshot=acme_snapshot(
                cert_snapshot(error_code=AcmeErrorClass.DNS_AUTH, in_backoff=True)
            )
        )
        bundle = acme_bundle(tmp_path, runner)
        file_status = PublicCertStatus(
            name="wild",
            names=(f"*.{ZONE}",),
            not_after=datetime(2027, 1, 1, tzinfo=UTC),
            state="ok",
            last_error=None,
            generation="0123456789ab",
        )
        bundle.reconciler.last_result = _result(
            remote_web_apps=[_remote(address=f"host1.{ZONE}", name="grafana")],
            public_certs=[file_status],
            registered_root=RegisteredRootStatus(
                name="isrg_root_x1",
                sha256=KNOWN_ROOTS["isrg_root_x1"],
                tg_ca_id="ca-1",
                bound=True,
            ),
            acme_errors=[AcmeError(None, "config", "token file missing")],
        )

        entry = await _acme_readiness(bundle)

        assert entry["reasons"] == []
        assert entry["state"] == "ready"

    async def test_healthz_ignores_acme_failures_and_a_raising_snapshot(
        self, tmp_path: Path
    ) -> None:
        runner = StubAcmeRunner(snapshot_error=RuntimeError("boom"))
        bundle = acme_bundle(tmp_path, runner)
        bundle.reconciler.last_result = _acme_pass(
            acme_errors=[
                AcmeError(None, "config", "token file missing"),
                AcmeError(ACME_CERT, "dns_auth", "token rejected"),
            ]
        )

        response = await _get(bundle, "/healthz", auth=False)

        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert runner.snapshot_calls == 0


class TestAcmeReadinessInternalAndStaging:
    """acme_failed:internal, acme_staging_dry_run and public_cert_invalid as /status serves them."""

    async def test_a_staging_seed_adds_the_dry_run_reason_to_a_pending_certificate(
        self, tmp_path: Path
    ) -> None:
        runner = StubAcmeRunner(snapshot=acme_snapshot(cert_snapshot(installed=False)))
        bundle = acme_bundle(tmp_path, runner)  # the default seed's directory is staging
        bundle.reconciler.last_result = _acme_pass()

        entry = await _acme_readiness(bundle)

        assert entry["reasons"] == ["public_cert_pending:issued", "acme_staging_dry_run:issued"]
        assert entry["state"] == "action_required"

    async def test_a_staging_seed_is_actionable_even_with_an_installed_certificate(
        self, tmp_path: Path
    ) -> None:
        runner = StubAcmeRunner(snapshot=acme_snapshot(cert_snapshot()))
        bundle = acme_bundle(tmp_path, runner)
        bundle.reconciler.last_result = _acme_pass(installed=True)

        entry = await _acme_readiness(bundle)

        assert entry["reasons"] == ["acme_staging_dry_run:issued"]
        assert entry["state"] == "action_required"

    async def test_a_production_seed_has_no_dry_run_reason(self, tmp_path: Path) -> None:
        runner = StubAcmeRunner(snapshot=acme_snapshot(cert_snapshot()))
        bundle = _production_bundle(tmp_path, runner)
        bundle.reconciler.last_result = _acme_pass(installed=True)

        entry = await _acme_readiness(bundle)

        assert entry["reasons"] == []
        assert entry["state"] == "ready"

    async def test_a_dead_runner_task_is_acme_failed_internal(self, tmp_path: Path) -> None:
        runner = StubAcmeRunner(snapshot=acme_snapshot(cert_snapshot(), task_dead=True))
        bundle = _production_bundle(tmp_path, runner)
        bundle.reconciler.last_result = _acme_pass(installed=True)

        entry = await _acme_readiness(bundle)

        assert entry["reasons"] == ["acme_failed:internal"]
        assert entry["state"] == "action_required"

    async def test_an_unavailable_runner_the_pass_recorded_is_acme_failed_internal(
        self, tmp_path: Path
    ) -> None:
        bundle = _production_bundle(tmp_path, None, acme_unavailable="OSError: x")
        bundle.reconciler.last_result = _acme_pass(
            acme_errors=[AcmeError(None, "internal", "ACME runner unavailable: OSError: x")]
        )

        entry = await _acme_readiness(bundle)

        assert entry["reasons"] == ["public_cert_pending:issued", "acme_failed:internal"]

    async def test_a_state_file_error_the_pass_recorded_is_acme_failed_internal(
        self, tmp_path: Path
    ) -> None:
        runner = StubAcmeRunner(snapshot=acme_snapshot(cert_snapshot()))
        bundle = _production_bundle(tmp_path, runner)
        bundle.reconciler.last_result = _acme_pass(
            installed=True,
            acme_errors=[AcmeError(None, "internal", "state.json is not valid JSON")],
        )

        entry = await _acme_readiness(bundle)

        assert entry["reasons"] == ["acme_failed:internal"]

    async def test_an_error_naming_a_certificate_is_not_a_runner_level_internal_reason(
        self, tmp_path: Path
    ) -> None:
        runner = StubAcmeRunner(snapshot=acme_snapshot(cert_snapshot()))
        bundle = _production_bundle(tmp_path, runner)
        bundle.reconciler.last_result = _acme_pass(
            installed=True, acme_errors=[AcmeError(ACME_CERT, "internal", "per certificate")]
        )

        entry = await _acme_readiness(bundle)

        assert entry["reasons"] == []

    async def test_refused_installed_material_is_public_cert_invalid_not_pending(
        self, tmp_path: Path
    ) -> None:
        from gwops.certs.public import KNOWN_ROOTS

        runner = StubAcmeRunner(snapshot=acme_snapshot(cert_snapshot()))
        bundle = _production_bundle(tmp_path, runner)
        invalid = PublicCertStatus(
            name=ACME_CERT,
            names=(f"*.apps.{ZONE}",),
            not_after=None,
            state="invalid",
            last_error="public certificate 'issued': cert_file: chain: no valid path",
            generation=None,
            source="acme",
        )
        bundle.reconciler.last_result = _result(
            remote_web_apps=[_remote(address=ACME_HOST)],
            public_certs=[invalid],
            registered_root=RegisteredRootStatus(
                name="isrg_root_x1", sha256=KNOWN_ROOTS["isrg_root_x1"], tg_ca_id="ca-1", bound=True
            ),
        )

        entry = await _acme_readiness(bundle)

        assert entry["reasons"] == ["public_cert_invalid:issued"]
        assert entry["state"] == "action_required"

    async def test_an_app_a_file_certificate_covers_ignores_internal_and_staging(
        self, tmp_path: Path
    ) -> None:
        from gwops.certs.public import KNOWN_ROOTS

        runner = StubAcmeRunner(snapshot=acme_snapshot(cert_snapshot(), task_dead=True))
        bundle = acme_bundle(tmp_path, runner)  # staging seed
        file_status = PublicCertStatus(
            name="wild",
            names=(f"*.{ZONE}",),
            not_after=datetime(2027, 1, 1, tzinfo=UTC),
            state="ok",
            last_error=None,
            generation="0123456789ab",
        )
        bundle.reconciler.last_result = _result(
            remote_web_apps=[_remote(address=f"host1.{ZONE}", name="grafana")],
            public_certs=[file_status],
            registered_root=RegisteredRootStatus(
                name="isrg_root_x1", sha256=KNOWN_ROOTS["isrg_root_x1"], tg_ca_id="ca-1", bound=True
            ),
            acme_errors=[AcmeError(None, "internal", "ACME runner unavailable: x")],
        )

        entry = await _acme_readiness(bundle)

        assert entry["reasons"] == []
        assert entry["state"] == "ready"

    async def test_a_raising_snapshot_still_serves_the_acme_block_of_status(
        self, tmp_path: Path
    ) -> None:
        runner = StubAcmeRunner(snapshot_error=RuntimeError("boom"))
        bundle = _production_bundle(tmp_path, runner)
        bundle.reconciler.last_result = _acme_pass()

        body = await _status(bundle)

        [cert] = [c for c in body["certs"]["public"] if c["name"] == ACME_CERT]
        assert cert["acme"]["state"] == "failed"
        assert cert["acme"]["computation_failed"] is True
        assert body["web_apps"]["readiness_status"] == "ok"
