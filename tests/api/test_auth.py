"""Admin API auth middleware: bearer token on everything except GET /healthz."""

import httpx
import pytest
import structlog.testing
from fastapi import FastAPI

import gwops.api.app as app_module
from gwops.api.app import create_app

from .conftest import ADMIN_TOKEN, DepsBundle, make_deps


def _anon(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gwops")


class TestBearerAuth:
    async def test_healthz_needs_no_token(self, anon_client: httpx.AsyncClient) -> None:
        response = await anon_client.get("/healthz")
        assert response.status_code in (200, 503)  # health verdict, not auth

    async def test_missing_token_is_401_with_no_detail(
        self, anon_client: httpx.AsyncClient
    ) -> None:
        response = await anon_client.get("/status")
        assert response.status_code == 401
        # No detail: the body must not reveal whether the token was missing or wrong.
        assert response.content in (b"", b"{}")

    async def test_wrong_token_is_401(self, app: FastAPI) -> None:
        async with _anon(app) as client:
            response = await client.get(
                "/status", headers={"Authorization": "Bearer wrong-token"}
            )
        assert response.status_code == 401

    async def test_non_bearer_scheme_is_401(self, app: FastAPI) -> None:
        async with _anon(app) as client:
            response = await client.get(
                "/status", headers={"Authorization": f"Basic {ADMIN_TOKEN}"}
            )
        assert response.status_code == 401

    async def test_right_token_passes(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/status")
        assert response.status_code == 200

    async def test_mutations_are_protected_too(self, anon_client: httpx.AsyncClient) -> None:
        response = await anon_client.post("/reconcile")
        assert response.status_code == 401

    async def test_unset_admin_token_rejects_everything_but_healthz(
        self, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        bundle = make_deps(tmp_path_factory.mktemp("no-token"), admin_token=None)
        app = create_app(bundle.deps)
        async with _anon(app) as client:
            assert (await client.get("/healthz")).status_code in (200, 503)
            response = await client.get(
                "/status", headers={"Authorization": "Bearer anything"}
            )
        assert response.status_code == 401

    async def test_comparison_is_timing_safe(
        self, client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The token check must go through secrets.compare_digest, not ==."""
        calls: list[tuple[bytes, bytes]] = []
        real = app_module.secrets.compare_digest

        def spy(a: bytes, b: bytes) -> bool:
            calls.append((a, b))
            return real(a, b)

        monkeypatch.setattr(app_module.secrets, "compare_digest", spy)
        response = await client.get("/status")
        assert response.status_code == 200
        assert calls, "auth accepted a token without calling secrets.compare_digest"


class TestAuditLog:
    async def test_mutating_requests_emit_exactly_one_audit_line(
        self, client: httpx.AsyncClient, bundle: DepsBundle
    ) -> None:
        with structlog.testing.capture_logs() as logs:
            response = await client.post(
                "/overlays",
                json={"patch": {"recording": {"enabled": False}}, "comment": "audit test"},
            )
        assert response.status_code == 201
        audit = [entry for entry in logs if entry["event"] == "api.audit"]
        assert len(audit) == 1
        assert audit[0]["method"] == "POST"
        assert audit[0]["route"] == "/overlays"
        assert audit[0]["status"] == 201
        assert audit[0]["overlay_id"] == response.json()["id"]
        assert audit[0]["principal"] == "admin"

    async def test_reads_emit_no_audit_line(self, client: httpx.AsyncClient) -> None:
        with structlog.testing.capture_logs() as logs:
            assert (await client.get("/status")).status_code == 200
            assert (await client.get("/state")).status_code == 200
        assert not [entry for entry in logs if entry["event"] == "api.audit"]

    async def test_rejected_mutation_still_audits_with_outcome(
        self, app: FastAPI
    ) -> None:
        async with _anon(app) as client:
            with structlog.testing.capture_logs() as logs:
                response = await client.post("/reconcile")
        assert response.status_code == 401
        audit = [entry for entry in logs if entry["event"] == "api.audit"]
        assert len(audit) == 1
        assert audit[0]["status"] == 401

    async def test_mutation_raising_unhandled_error_is_still_audited(
        self, app: FastAPI
    ) -> None:
        # A handler that raises before producing a response (e.g. an OSError persisting
        # an overlay) must still leave an audit line — the case an operator most wants
        # recorded — with status 500 and without the exception detail leaking.
        @app.post("/_boom")
        async def _boom() -> None:
            raise RuntimeError("kaboom-secret-detail")

        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://gwops"
        ) as client:
            with structlog.testing.capture_logs() as logs:
                response = await client.post(
                    "/_boom", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}
                )
        assert response.status_code == 500
        audit = [entry for entry in logs if entry["event"] == "api.audit"]
        assert len(audit) == 1
        assert audit[0]["status"] == 500
        assert "kaboom-secret-detail" not in str(audit[0])

    async def test_audit_lines_never_carry_request_secrets(
        self, client: httpx.AsyncClient
    ) -> None:
        with structlog.testing.capture_logs() as logs:
            await client.post(
                "/overlays",
                json={"patch": {"recording": {"receiver_url": "https://s3cr3t-body.example/"}}},
            )
        for entry in logs:
            assert "s3cr3t-body" not in str(entry)
            assert ADMIN_TOKEN not in str(entry)
