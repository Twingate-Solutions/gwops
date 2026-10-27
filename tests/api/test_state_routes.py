"""State/introspection routes: /healthz, /status, /state, /overlays CRUD."""

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from gwops.api.app import GwopsDeps, create_app
from gwops.reconciler.core import ReconcileResult, RemoteWebApp
from gwops.renderer.capabilities import Capabilities
from gwops.shipper.enrich import WebAppIndex
from gwops.shipper.filter import DropReason
from gwops.shipper.ship import Shipper
from gwops.shipper.spool import Spool
from gwops.supervisor.process import ProcState

from .conftest import ADMIN_TOKEN, DepsBundle


def _app_client(deps: GwopsDeps) -> httpx.AsyncClient:
    """An authorized client against an app built from a customized deps bundle."""
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(deps)),
        base_url="http://gwops",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )


def _failed_result() -> ReconcileResult:
    """A pass that failed on a LOCAL step (render) — local_ok is False."""
    return ReconcileResult(
        ok=False,
        trigger="tick",
        started_at=datetime.now(UTC),
        local_ok=False,
        actions=[],
        errors=["render failed: boom"],
    )


def _tg_sync_failed_result() -> ReconcileResult:
    """A pass whose only failure is TG-side sync — local_ok stays True."""
    return ReconcileResult(
        ok=False,
        trigger="tick",
        started_at=datetime.now(UTC),
        local_ok=True,
        actions=[],
        errors=["TG sync failed: could not list resources: boom"],
    )


class TestHealthz:
    """Composite truth table: gateway process state x last reconcile outcome."""

    async def test_running_and_reconcile_ok_is_200(
        self, anon_client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        bundle.process.state = ProcState.RUNNING
        response = await anon_client.get("/healthz")
        assert response.status_code == 200
        body = response.json()
        assert body["checks"]["gateway"]["ok"] is True
        assert body["checks"]["reconcile"]["ok"] is True

    async def test_running_but_last_reconcile_failed_is_503(
        self, anon_client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        bundle.process.state = ProcState.RUNNING
        bundle.reconciler.last_result = _failed_result()
        response = await anon_client.get("/healthz")
        assert response.status_code == 503
        body = response.json()
        assert body["checks"]["gateway"]["ok"] is True
        assert body["checks"]["reconcile"]["ok"] is False

    async def test_running_with_only_tg_sync_error_is_200(
        self, anon_client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        # A TG-side sync failure must NOT flip the container unhealthy: the gateway is
        # running on a good local config, so /healthz stays 200 (local_ok is True).
        bundle.process.state = ProcState.RUNNING
        bundle.reconciler.last_result = _tg_sync_failed_result()
        response = await anon_client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["checks"]["reconcile"]["ok"] is True

    async def test_gateway_down_is_503_even_with_reconcile_ok(
        self, anon_client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        bundle.process.state = ProcState.STOPPED
        response = await anon_client.get("/healthz")
        assert response.status_code == 503
        assert response.json()["checks"]["gateway"]["ok"] is False

    async def test_still_starting_counts_as_healthy(
        self, anon_client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        # STARTING process + no completed reconcile yet: give the container time.
        bundle.process.state = ProcState.STARTING
        bundle.reconciler.last_result = None
        response = await anon_client.get("/healthz")
        assert response.status_code == 200

    async def test_backoff_is_503(
        self, anon_client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        bundle.process.state = ProcState.BACKOFF
        response = await anon_client.get("/healthz")
        assert response.status_code == 503

    async def test_healthz_does_not_disclose_reconcile_detail(
        self, anon_client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        # /healthz is unauthenticated, so it must not leak actions/errors (they name
        # upstream addresses, tenant ids, credential paths, gateway stderr).
        bundle.process.state = ProcState.RUNNING
        bundle.reconciler.last_result = _failed_result()
        text = (await anon_client.get("/healthz")).text
        assert "render failed" not in text  # the error string in _failed_result
        body = (await anon_client.get("/healthz")).json()
        reconcile = body["checks"]["reconcile"]
        assert "actions" not in reconcile
        assert "errors" not in reconcile
        assert "last" not in reconcile  # the full serialized record is gone


def _remote_app(gateway_id: str) -> RemoteWebApp:
    return RemoteWebApp(
        id=f"r-{gateway_id}",
        name=f"app-{gateway_id}",
        gateway_id=gateway_id,
        address=f"{gateway_id}.example.test",
        upstream_port=443,
        alias=None,
        upstream_tls="verify_full",
        downstream_tls="tls13",
        downstream_port=443,
        header_rewrite_names=(),
        managed=False,
    )


class TestStatus:
    async def test_status_reports_the_baked_gateway_version(
        self, bundle: DepsBundle
    ) -> None:
        # Reported verbatim and never enforced: a 1.x value is shown, not refused.
        for version in ("2.0.0-dev-5ed8e12", "1.1.0"):
            deps = replace(bundle.deps, caps=Capabilities(gateway_version=version))
            async with _app_client(deps) as client:
                body = (await client.get("/status")).json()
            assert body["capabilities"] == {"gateway_version": version}

    async def test_status_reports_all_sections(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        response = await client.get("/status")
        assert response.status_code == 200
        body = response.json()
        assert body["process"]["state"] == "running"
        # Capabilities reports only the gateway version; the bundle fixture builds a
        # plain Capabilities() default, so the version is empty.
        assert body["capabilities"] == {"gateway_version": ""}
        assert "schema_variant" not in body["capabilities"]
        assert body["last_reconcile"]["trigger"] == "startup"
        assert body["last_reconcile"]["ok"] is True
        # CA was generated by the fixture; leaf has never been minted.
        assert body["certs"]["x509_ca_not_after"] is not None
        assert body["certs"]["leaf_not_after"] is None
        assert body["certs"]["leaf_state"] == "missing"
        assert body["tg"]["configured"] is False
        # No spool wired: recording is off.
        assert body["shipper"] == {"mode": "disabled"}

    async def test_status_reports_spool_lag_when_recording(
        self, bundle: DepsBundle, tmp_path: Path
    ) -> None:
        spool = Spool(tmp_path / "spool", max_bytes=1024 * 1024)
        shipper = Shipper(spool, "http://gatorcast.test:8000", "tok")
        spool.append(b'{"a":1}')
        spool.append(b'{"b":2}')
        deps = replace(bundle.deps, spool=spool, shipper=shipper)
        async with _app_client(deps) as client:
            body = (await client.get("/status")).json()
        assert body["shipper"]["mode"] == "spool"
        assert body["shipper"]["shipping"] is True
        assert body["shipper"]["pending_lines"] == 2
        assert body["shipper"]["pending_bytes"] > 0
        assert body["shipper"]["last_success_at"] is None

    async def test_status_reports_dropped_lines_by_reason_in_spool_mode(
        self, bundle: DepsBundle, tmp_path: Path
    ) -> None:
        spool = Spool(tmp_path / "spool", max_bytes=1024 * 1024)
        deps = replace(bundle.deps, spool=spool, shipper=None)
        async with _app_client(deps) as client:
            fresh = (await client.get("/status")).json()["shipper"]["dropped_lines"]
            deps.drops.count(DropReason.NOT_JSON)
            deps.drops.count(DropReason.TOO_LONG)
            deps.drops.count(DropReason.TOO_LONG)
            counted = (await client.get("/status")).json()["shipper"]["dropped_lines"]
        assert fresh == {"not_json": 0, "not_allowlisted": 0, "too_long": 0, "spool_failed": 0}
        assert counted == {"not_json": 1, "not_allowlisted": 0, "too_long": 2, "spool_failed": 0}

    async def test_status_reports_spool_failures_and_enrich_failures(
        self, bundle: DepsBundle, tmp_path: Path
    ) -> None:
        spool = Spool(tmp_path / "spool", max_bytes=1024 * 1024)
        deps = replace(bundle.deps, spool=spool, shipper=None)
        deps.drops.count(DropReason.SPOOL_FAILED)
        deps.drops.count_enrich_failed()
        deps.drops.count_enrich_failed()
        async with _app_client(deps) as client:
            shipper = (await client.get("/status")).json()["shipper"]
        assert shipper["dropped_lines"]["spool_failed"] == 1
        assert shipper["enrich_failed"] == 2

    async def test_status_reports_enrichment_without_an_index(
        self, bundle: DepsBundle, tmp_path: Path
    ) -> None:
        spool = Spool(tmp_path / "spool", max_bytes=1024 * 1024)
        deps = replace(bundle.deps, spool=spool, shipper=None)
        async with _app_client(deps) as client:
            shipper = (await client.get("/status")).json()["shipper"]
        assert shipper["enrich_failed"] == 0
        assert shipper["enrichment"] == {"active": False, "last_update_at": None, "apps": 0}

    async def test_status_reports_enrichment_freshness_from_the_index(
        self, bundle: DepsBundle, tmp_path: Path
    ) -> None:
        spool = Spool(tmp_path / "spool", max_bytes=1024 * 1024)
        index = WebAppIndex()
        deps = replace(bundle.deps, spool=spool, shipper=None, webapp_index=index)
        async with _app_client(deps) as client:
            before = (await client.get("/status")).json()["shipper"]["enrichment"]
            index.update([_remote_app("g-1"), _remote_app("g-2")], "g-1")
            after = (await client.get("/status")).json()["shipper"]["enrichment"]
        assert before == {"active": False, "last_update_at": None, "apps": 0}
        assert after == {
            "active": True,
            "last_update_at": index.last_update_at.isoformat() if index.last_update_at else None,
            "apps": 1,
        }
        assert after["last_update_at"] is not None and after["last_update_at"].endswith("+00:00")

    async def test_status_has_no_dropped_lines_when_recording_is_off(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        bundle.deps.drops.count(DropReason.NOT_JSON)
        body = (await client.get("/status")).json()
        assert body["shipper"] == {"mode": "disabled"}

    async def test_status_flags_spool_without_token_as_not_shipping(
        self, bundle: DepsBundle, tmp_path: Path
    ) -> None:
        spool = Spool(tmp_path / "spool", max_bytes=1024 * 1024)
        deps = replace(bundle.deps, spool=spool, shipper=None)
        async with _app_client(deps) as client:
            body = (await client.get("/status")).json()
        assert body["shipper"]["mode"] == "spool"
        assert body["shipper"]["shipping"] is False

    async def test_status_reflects_tg_sync_errors(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        result = _failed_result()
        result.errors = ["TG sync failed: could not list resources: boom"]
        bundle.reconciler.last_result = result
        response = await client.get("/status")
        body = response.json()
        assert body["tg"]["ok"] is False
        assert "TG sync failed" in body["tg"]["errors"][0]


class TestState:
    async def test_state_shows_merged_state_with_provenance(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        bundle.store.add(
            {"ssh_upstreams": [{"name": "host2", "address": "10.0.0.6:22"}]}, "add host2"
        )
        response = await client.get("/state")
        assert response.status_code == 200
        body = response.json()
        names = [u["name"] for u in body["state"]["ssh_upstreams"]]
        assert names == ["host1", "host2"]
        assert body["provenance"]["ssh_upstreams.host1.address"] == "seed"
        assert body["provenance"]["ssh_upstreams.host2.address"] == "0001-add-host2"

    async def test_overlays_redact_secret_looking_keys(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        # Every EffectiveState field is a fixed, strictly-typed name — none of them can
        # hold an arbitrary secret-looking key and still pass schema validation, so
        # GET /state (which re-validates the full merged state) cannot exercise this path.
        # `GET /overlays` echoes back each persisted overlay's raw patch via the same
        # `redact_tree` helper without re-validating it against EffectiveState, so it
        # still exercises the shared redaction machinery end to end.
        bundle.store.add({"upstream_auth": {"token": "hunter2"}}, "oops")
        response = await client.get("/overlays")
        text = response.text
        assert "hunter2" not in text
        assert "[REDACTED]" in text

    async def test_state_keeps_credential_file_paths_visible(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        # *_file keys are locations of credentials, not credentials — operators need
        # to see them to debug mounts.
        bundle.store.add(
            {
                "k8s_clusters": [
                    {
                        "name": "prod",
                        "address": "prod.k8s.internal",
                        "bearer_token_file": "/secrets/prod.token",
                        "ca_file": "/secrets/prod-ca.crt",
                    }
                ]
            },
            "add prod",
        )
        response = await client.get("/state")
        body = response.json()
        cluster = body["state"]["k8s_clusters"][0]
        assert cluster["bearer_token_file"] == "/secrets/prod.token"

    async def test_state_never_serializes_a_secretstr(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        # The settings SecretStr values (admin token, API key) must never appear in
        # any API response body.
        for route in ("/state", "/status", "/overlays"):
            response = await client.get(route)
            assert "test-admin-token" not in response.text, route


class TestOverlays:
    async def test_list_starts_empty(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/overlays")
        assert response.status_code == 200
        assert response.json() == []

    async def test_post_validates_persists_and_reconciles_synchronously(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        response = await client.post(
            "/overlays",
            json={
                "patch": {"ssh_upstreams": [{"name": "host2", "address": "10.0.0.6:22"}]},
                "comment": "add host2",
            },
        )
        assert response.status_code == 201
        body = response.json()
        assert body["id"] == "0001-add-host2"
        assert body["reconcile"]["ok"] is True
        assert [o.id for o in bundle.store.list()] == ["0001-add-host2"]
        assert bundle.reconciler.triggers == ["api"]

    async def test_bad_patch_is_422_with_dotted_path_and_store_untouched(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        response = await client.post(
            "/overlays",
            json={
                "patch": {"ssh_upstreams": [{"name": "host2", "address": "not a host!"}]},
                "comment": "bad",
            },
        )
        assert response.status_code == 422
        assert "ssh_upstreams.host2.address" in response.json()["detail"]
        assert bundle.store.list() == []
        assert bundle.reconciler.triggers == []

    async def test_unknown_key_is_422(self, client: httpx.AsyncClient) -> None:
        response = await client.post("/overlays", json={"patch": {"no_such_key": 1}})
        assert response.status_code == 422
        assert "no_such_key" in response.json()["detail"]

    @pytest.mark.parametrize(
        "patch",
        [
            {"twingate": {"host": "attacker.example"}},
            {"twingate": {"network": "attacker"}},
            {"ca": {"x509": {"key_path": "/data/pki/x509-ca.key"}}},
            {"admin_api": {"port": 9000}},
        ],
    )
    async def test_overlay_rejects_identity_trust_keys(
        self, client: httpx.AsyncClient, bundle: DepsBundle, patch: dict[str, object]
    ) -> None:
        # Identity/trust config is seed-only: an overlay must not be able to redirect the
        # API key's destination, the CA key path, or the admin bind.
        response = await client.post("/overlays", json={"patch": patch})
        assert response.status_code == 422
        assert bundle.store.list() == []  # nothing persisted
        assert bundle.reconciler.triggers == []

    async def test_overlay_rejects_recording_receiver_url(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        # recording is overlayable, but its destination URL (which carries GWOPS_RECORDING_TOKEN
        # on egress) is not — that would let the admin token exfiltrate recordings.
        response = await client.post(
            "/overlays",
            json={"patch": {"recording": {"receiver_url": "https://attacker.example/"}}},
        )
        assert response.status_code == 422
        assert "receiver_url" in response.json()["detail"]
        assert bundle.store.list() == []

    async def test_overlay_still_allows_operational_recording_keys(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await client.post(
            "/overlays", json={"patch": {"recording": {"enabled": False}}}
        )
        assert response.status_code == 201

    async def test_delete_known_overlay_reconciles_synchronously(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        overlay = bundle.store.add({"gateway_passthrough": {"x": 1}}, "tweak")
        response = await client.delete(f"/overlays/{overlay.id}")
        assert response.status_code == 204
        assert bundle.store.list() == []
        assert bundle.reconciler.triggers == ["api"]

    async def test_post_whose_tg_sync_fails_is_rolled_back(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        bundle.reconciler.fail_keys = {"ssh/host2"}
        response = await client.post(
            "/overlays",
            json={"patch": {"ssh_upstreams": [{"name": "host2", "address": "10.0.0.6"}]}},
        )
        assert response.status_code == 422
        detail = response.json()["detail"]
        assert detail["rolled_back"] is True
        assert detail["unsynced"] == ["ssh/host2"]
        assert "TG sync: ssh/host2: rejected" in detail["errors"]
        assert bundle.store.list() == []  # no orphaned overlay
        assert bundle.reconciler.triggers == ["api", "api-rollback"]

    async def test_unrelated_preexisting_tg_failure_does_not_block_a_change(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        bundle.reconciler.fail_keys = {"ssh/host1"}  # the seed upstream, not ours
        response = await client.post(
            "/overlays",
            json={"patch": {"ssh_upstreams": [{"name": "host2", "address": "10.0.0.6"}]}},
        )
        assert response.status_code == 201
        assert len(bundle.store.list()) == 1

    async def test_delete_overlay_whose_tg_sync_fails_is_restored_in_place(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        first = bundle.store.add(
            {"ssh_upstreams": [{"name": "host2", "address": "10.0.0.6"}]}, "add host2"
        )
        second = bundle.store.add({"recording": {"enabled": False}}, "tweak")
        bundle.reconciler.fail_keys = {"ssh/host2"}  # the delete cannot be confirmed
        bundle.deps.registry.record("ssh", "host2", "r-2")  # still owned on the tenant

        response = await client.delete(f"/overlays/{first.id}")

        assert response.status_code == 422
        # Restored under its original id, so application order is unchanged.
        assert [o.id for o in bundle.store.list()] == [first.id, second.id]

    async def test_delete_unknown_overlay_is_404(self, client: httpx.AsyncClient) -> None:
        response = await client.delete("/overlays/0042-never-existed")
        assert response.status_code == 404

    async def test_delete_malformed_id_is_422(self, client: httpx.AsyncClient) -> None:
        # Fails the overlay-id grammar (no counter prefix, uppercase) -> rejected
        # before any filesystem access.
        response = await client.delete("/overlays/NOT-A-VALID-ID")
        assert response.status_code == 422

    async def test_list_returns_overlays_in_order(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        bundle.store.add({"gateway_passthrough": {"a": 1}}, "first")
        bundle.store.add({"gateway_passthrough": {"b": 2}}, "second")
        response = await client.get("/overlays")
        assert [o["id"] for o in response.json()] == ["0001-first", "0002-second"]


class TestStateLoadFailure:
    async def test_status_degrades_gracefully_when_state_is_unloadable(
        self, client: httpx.AsyncClient, bundle: DepsBundle, app: FastAPI
    ) -> None:
        bundle.seed_path.write_text("not: [valid", encoding="utf-8")
        response = await client.get("/status")
        assert response.status_code == 200
        assert response.json()["state_error"] is not None

    async def test_state_route_reports_the_load_error(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        bundle.seed_path.write_text("not: [valid", encoding="utf-8")
        response = await client.get("/state")
        assert response.status_code == 500
        assert "seed" in response.json()["detail"]
