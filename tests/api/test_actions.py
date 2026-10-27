"""Action routes: /reconcile, /certs/rotate-leaf, /certs/rotate-ca, /upstreams sugar."""

from pathlib import Path

import httpx

from gwops.api.app import create_app
from gwops.tgapi.client import TGClient
from tests.store_support import leaf_cert_path

from .conftest import ADMIN_TOKEN, DepsBundle, FakeCARegistrar, make_deps


class TestReconcile:
    async def test_post_reconcile_runs_a_pass_and_returns_the_result(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        response = await client.post("/reconcile")
        assert response.status_code == 200
        body = response.json()
        assert body["trigger"] == "api"
        assert body["ok"] is True
        assert bundle.reconciler.triggers == ["api"]


class TestRotateLeaf:
    async def test_rotate_leaf_mints_a_leaf_covering_required_sans(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        response = await client.post("/certs/rotate-leaf")
        assert response.status_code == 200
        body = response.json()
        assert body["minted"] is True
        assert "10.0.0.5" in body["sans"]
        assert body["not_after"] is not None
        assert bundle.certs.leaf_status({"10.0.0.5"}).state.value == "ok"

    async def test_rotate_leaf_with_no_upstreams_is_409(
        self, tmp_path: Path
    ) -> None:
        seed = "twingate:\n  network: acme\n  gateway_id: g-1\n"
        bundle = make_deps(tmp_path, seed=seed)
        app = create_app(bundle.deps)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://gwops",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        ) as client:
            response = await client.post("/certs/rotate-leaf")
        assert response.status_code == 409


class TestRotateCA:
    async def test_stage_generates_a_staged_ca_and_documents_manual_steps(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        response = await client.post("/certs/rotate-ca", json={"phase": "stage"})
        assert response.status_code == 200
        body = response.json()
        assert body["phase"] == "stage"
        assert "BEGIN CERTIFICATE" in body["ca_pem"]
        assert body["manual_steps"]  # the out-of-band trust-update instructions
        before_complete = body["manual_steps"][0]
        assert "ca_pem" in before_complete and "TLS CA" in before_complete
        # The SSH CA is untouched by X.509 rotation, so no step may ask for SSH target changes
        # (the text may only say that targets need none).
        assert "TrustedUserCAKeys" not in "".join(body["manual_steps"])
        assert "SSH upstream targets need no change" in before_complete
        pki = bundle.deps.settings.data_dir / "pki"
        assert (pki / "staged" / "x509-ca.crt").exists()

    async def test_complete_without_a_staged_ca_is_409(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await client.post("/certs/rotate-ca", json={"phase": "complete"})
        assert response.status_code == 409

    async def test_bad_phase_is_422(self, client: httpx.AsyncClient) -> None:
        response = await client.post("/certs/rotate-ca", json={"phase": "yolo"})
        assert response.status_code == 422

    async def test_complete_promotes_reregisters_rebinds_and_reminst_leaf(
        self, tmp_path: Path, ca_registrar: FakeCARegistrar
    ) -> None:
        bundle = make_deps(tmp_path)
        bundle.deps.tg = TGClient(network="acme", api_key="k")
        old_pem = (bundle.deps.settings.data_dir / "pki" / "x509-ca.crt").read_text(
            encoding="utf-8"
        )
        app = create_app(bundle.deps)
        headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gwops", headers=headers
        ) as client:
            stage = await client.post("/certs/rotate-ca", json={"phase": "stage"})
            assert stage.status_code == 200
            complete = await client.post("/certs/rotate-ca", json={"phase": "complete"})
        assert complete.status_code == 200
        body = complete.json()
        assert body["phase"] == "complete"
        assert body["errors"] == []
        # The default CA is now the staged one, registered and bound on the tenant.
        new_pem = (bundle.deps.settings.data_dir / "pki" / "x509-ca.crt").read_text(
            encoding="utf-8"
        )
        assert new_pem != old_pem
        assert ca_registrar.created_ca_pems == [new_pem]
        assert ca_registrar.gateway_bindings[0]["x509CAId"] == "ca-x-new"
        # The registry records the new CA id, and the leaf was re-minted under it.
        assert bundle.deps.registry.managed_ids()["ca/x509"] == "ca-x-new"
        assert leaf_cert_path(bundle.deps.settings.data_dir / "pki").exists()
        assert bundle.deps.api_event.is_set()
        await bundle.deps.tg.aclose()

    async def test_complete_without_tg_still_promotes_but_reports_the_gap(
        self, tmp_path: Path
    ) -> None:
        bundle = make_deps(tmp_path)
        app = create_app(bundle.deps)
        headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gwops", headers=headers
        ) as client:
            await client.post("/certs/rotate-ca", json={"phase": "stage"})
            complete = await client.post("/certs/rotate-ca", json={"phase": "complete"})
        assert complete.status_code == 200
        body = complete.json()
        assert any("TWINGATE_API_KEY" in e for e in body["errors"])


class TestUpstreamSugar:
    async def test_put_ssh_upstream_writes_an_overlay_and_reconciles(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        response = await client.put(
            "/upstreams/ssh/host2", json={"address": "10.0.0.6:22"}
        )
        assert response.status_code == 200
        overlays = bundle.store.list()
        assert len(overlays) == 1
        assert overlays[0].patch == {
            "ssh_upstreams": [{"name": "host2", "address": "10.0.0.6:22"}]
        }
        assert response.json()["reconcile"]["ok"] is True
        assert bundle.reconciler.triggers == ["api"]

    async def test_put_ssh_upstream_body_name_mismatch_is_422(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        response = await client.put(
            "/upstreams/ssh/host2", json={"name": "other", "address": "10.0.0.6:22"}
        )
        assert response.status_code == 422
        assert bundle.store.list() == []

    async def test_put_ssh_upstream_invalid_body_is_422_via_state_validation(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        response = await client.put(
            "/upstreams/ssh/host2", json={"address": "10.0.0.6:22", "bogus": True}
        )
        assert response.status_code == 422
        assert bundle.store.list() == []

    async def test_put_k8s_cluster_writes_an_overlay(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        response = await client.put(
            "/upstreams/k8s/prod",
            json={
                "address": "prod.k8s.internal",
                "port": 6443,
                "bearer_token_file": "/secrets/prod.token",
                "ca_file": "/secrets/prod-ca.crt",
            },
        )
        assert response.status_code == 200
        overlays = bundle.store.list()
        assert overlays[0].patch["k8s_clusters"][0]["name"] == "prod"
        assert bundle.reconciler.triggers == ["api"]

    async def test_delete_ssh_upstream_writes_a_delete_overlay(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        response = await client.delete("/upstreams/ssh/host1")
        assert response.status_code == 200
        overlays = bundle.store.list()
        assert overlays[0].patch == {"ssh_upstreams": [{"name": "host1", "_delete": True}]}
        assert bundle.reconciler.triggers == ["api"]
        # The merged state no longer contains host1.
        state = await client.get("/state")
        assert state.json()["state"]["ssh_upstreams"] == []

    async def test_delete_unknown_upstream_is_404(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        response = await client.delete("/upstreams/ssh/never-existed")
        assert response.status_code == 404
        assert bundle.store.list() == []

    async def test_delete_unknown_k8s_cluster_is_404(
        self, client: httpx.AsyncClient
    ) -> None:
        response = await client.delete("/upstreams/k8s/never-existed")
        assert response.status_code == 404

    async def test_unknown_upstream_kind_is_404(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        response = await client.put("/upstreams/postgres/db-1", json={"address": "10.0.0.9"})
        assert response.status_code == 404
        assert "unknown upstream kind 'postgres'" in response.json()["detail"]
        assert bundle.store.list() == []

    async def test_access_refs_without_api_key_are_503_and_not_persisted(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        response = await client.put(
            "/upstreams/ssh/host2",
            json={"address": "10.0.0.6", "access": {"groups": ["Platform Engineers"]}},
        )
        assert response.status_code == 503
        assert "TWINGATE_API_KEY" in response.json()["detail"]
        assert bundle.store.list() == []

