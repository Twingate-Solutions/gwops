"""GET /status in public mode: null leaf keys, `certs.public[]`, `certs.registered_root`.

Also pins that no block can fail `/status` or `/healthz`, and that private mode's `certs`
block carries none of the new keys.
"""

import dataclasses
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import structlog.testing
import yaml

from gwops.acme.runner import AcmeCertState
from gwops.acme.state import AcmeErrorClass
from gwops.api import status_webapps
from gwops.api.app import create_app
from gwops.certs.public import KNOWN_ROOTS
from gwops.reconciler.core import (
    AcmeError,
    PublicCertStatus,
    ReconcileResult,
    RegisteredRootStatus,
)
from tests.public_tls_support import ZONE, public_cert, public_seed, ssh, tls_block

from .acme_support import (
    ACME_CERT,
    FILE_CERT,
    PRODUCTION_URL,
    STAGING_URL,
    StubAcmeRunner,
    acme_bundle,
    acme_seed,
    acme_snapshot,
    cert_snapshot,
)
from .conftest import ADMIN_TOKEN, DepsBundle, make_deps

_ROOT = "isrg_root_x1"
_NOT_AFTER = datetime(2027, 1, 1, 12, 0, tzinfo=UTC)
_TWO_CERTS = tls_block(
    certificates=[
        public_cert("wild", [f"*.{ZONE}"]),
        public_cert("api", [f"api.{ZONE}"]),
    ]
)


def _client(bundle: DepsBundle) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(bundle.deps)),
        base_url="http://gwops",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )


def _cert_status(
    name: str,
    state: str = "ok",
    *,
    last_error: str | None = None,
    generation: str | None = "0123456789ab",
    not_after: datetime | None = _NOT_AFTER,
) -> PublicCertStatus:
    return PublicCertStatus(
        name=name,
        names=(f"{name}.{ZONE}",),
        not_after=not_after,
        state=state,  # type: ignore[arg-type]
        last_error=last_error,
        generation=generation,
    )


def _root(bound: bool | None, tg_ca_id: str | None = "ca-1") -> RegisteredRootStatus:
    return RegisteredRootStatus(
        name=_ROOT, sha256=KNOWN_ROOTS[_ROOT], tg_ca_id=tg_ca_id, bound=bound
    )


@pytest.fixture
def public_bundle(tmp_path: Path) -> DepsBundle:
    seed = public_seed(_TWO_CERTS, ssh_upstreams=[ssh("host1", f"host1.{ZONE}:22")])
    return make_deps(tmp_path, seed=yaml.safe_dump(seed, sort_keys=False), ensure_cas=False)


@pytest.fixture
async def public_client(public_bundle: DepsBundle) -> AsyncIterator[httpx.AsyncClient]:
    async with _client(public_bundle) as client:
        yield client


def _set_result(
    bundle: DepsBundle,
    *,
    certs: list[PublicCertStatus] | None = None,
    root: RegisteredRootStatus | None = None,
    **fields: Any,
) -> None:
    bundle.reconciler.last_result = ReconcileResult(
        ok=True,
        trigger="tick",
        started_at=datetime.now(UTC),
        public_certs=certs,
        registered_root=root,
        **fields,
    )


class TestPublicKeys:
    async def test_the_private_keys_are_null_and_leaf_status_is_not_called(
        self,
        public_client: httpx.AsyncClient,
        public_bundle: DepsBundle,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def boom(*_: object) -> None:
            raise AssertionError("leaf_status must not be called in public mode")

        monkeypatch.setattr(public_bundle.certs, "leaf_status", boom)
        _set_result(public_bundle, certs=[_cert_status("wild")], root=_root(True))

        body = (await public_client.get("/status")).json()

        certs = body["certs"]
        assert certs["x509_ca_not_after"] is None
        assert certs["leaf_not_after"] is None
        assert certs["leaf_state"] is None
        assert set(certs) == {
            "x509_ca_not_after", "leaf_not_after", "leaf_state", "public", "public_acme_errors",
            "registered_root",
        }  # fmt: skip
        assert certs["public_acme_errors"] == []

    async def test_status_never_reads_the_gwops_leaf_in_public_mode(
        self,
        public_client: httpx.AsyncClient,
        public_bundle: DepsBundle,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """With the tenant listed, readiness is computed, and it must not read a leaf that
        does not exist (that logged certs.leaf_sans_unreadable on every /status call)."""
        reads: list[str] = []
        monkeypatch.setattr(public_bundle.certs, "leaf_sans", lambda: reads.append("read"))
        _set_result(
            public_bundle, certs=[_cert_status("wild")], root=_root(True), remote_web_apps=[]
        )

        with structlog.testing.capture_logs() as logs:
            response = await public_client.get("/status")

        assert response.status_code == 200
        assert reads == []
        assert not [e for e in logs if e["event"] == "certs.leaf_sans_unreadable"]

    async def test_tls_mode_is_public_with_no_warning(
        self, public_client: httpx.AsyncClient
    ) -> None:
        body = (await public_client.get("/status")).json()

        assert body["tls"] == {"mode": "public", "warning": None}
        assert body["web_apps"]["browser_trust"] is None


class TestPublicCerts:
    async def test_each_state_is_reported_with_its_fields(
        self, public_client: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        _set_result(
            public_bundle,
            certs=[
                _cert_status("wild", "ok"),
                _cert_status("api", "expiring", generation="aaaaaaaaaaaa"),
            ],
            root=_root(True),
        )

        listed = (await public_client.get("/status")).json()["certs"]["public"]

        assert listed == [
            {
                "name": "wild",
                "names": [f"wild.{ZONE}"],
                "not_after": _NOT_AFTER.isoformat(),
                "state": "ok",
                "last_error": None,
                "generation": "0123456789ab",
            },
            {
                "name": "api",
                "names": [f"api.{ZONE}"],
                "not_after": _NOT_AFTER.isoformat(),
                "state": "expiring",
                "last_error": None,
                "generation": "aaaaaaaaaaaa",
            },
        ]

    async def test_an_invalid_certificate_keeps_the_last_good_generation_and_expiry(
        self, public_client: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        error = "public_tls certificate 'wild': cert_file: leaf has expired"
        _set_result(
            public_bundle,
            certs=[_cert_status("wild", "invalid", last_error=error, generation="bbbbbbbbbbbb")],
            root=_root(True),
        )

        entry = (await public_client.get("/status")).json()["certs"]["public"][0]

        assert entry["state"] == "invalid"
        assert entry["last_error"] == error
        assert entry["generation"] == "bbbbbbbbbbbb"
        assert entry["not_after"] == _NOT_AFTER.isoformat()

    async def test_a_pending_certificate_reports_the_served_copy_and_why_it_is_pending(
        self, public_client: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        reason = "not installed: another certificate failed validation"
        _set_result(
            public_bundle,
            certs=[
                _cert_status("wild", "pending", last_error=reason, generation="cccccccccccc"),
                _cert_status(
                    "api", "pending", last_error=reason, generation=None, not_after=None
                ),
            ],
            root=_root(True),
        )

        listed = (await public_client.get("/status")).json()["certs"]["public"]

        assert [(e["name"], e["state"], e["last_error"], e["generation"]) for e in listed] == [
            ("wild", "pending", reason, "cccccccccccc"),
            ("api", "pending", reason, None),
        ]
        assert listed[0]["not_after"] == _NOT_AFTER.isoformat()
        assert listed[1]["not_after"] is None

    async def test_a_certificate_never_installed_has_null_expiry_and_generation(
        self, public_client: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        _set_result(
            public_bundle,
            certs=[
                _cert_status("wild", "invalid", last_error="x", generation=None, not_after=None)
            ],
            root=_root(None, tg_ca_id=None),
        )

        entry = (await public_client.get("/status")).json()["certs"]["public"][0]

        assert entry["generation"] is None
        assert entry["not_after"] is None

    async def test_the_list_is_empty_before_the_first_pass(
        self, public_client: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        public_bundle.reconciler.last_result = None

        certs = (await public_client.get("/status")).json()["certs"]

        assert certs["public"] == []

    async def test_the_list_is_empty_when_the_pass_recorded_no_certificates(
        self, public_client: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        _set_result(public_bundle, certs=None)

        assert (await public_client.get("/status")).json()["certs"]["public"] == []


class TestRegisteredRoot:
    @pytest.mark.parametrize("bound", [True, False, None])
    async def test_bound_is_reported_as_the_pass_left_it(
        self, public_client: httpx.AsyncClient, public_bundle: DepsBundle, bound: bool | None
    ) -> None:
        _set_result(public_bundle, certs=[], root=_root(bound))

        root = (await public_client.get("/status")).json()["certs"]["registered_root"]

        assert root == {
            "name": _ROOT, "sha256": KNOWN_ROOTS[_ROOT], "tg_ca_id": "ca-1", "bound": bound,
        }

    async def test_before_the_first_pass_it_is_the_seed_root_with_unknowns(
        self, public_client: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        public_bundle.reconciler.last_result = None

        root = (await public_client.get("/status")).json()["certs"]["registered_root"]

        assert root == {
            "name": _ROOT, "sha256": KNOWN_ROOTS[_ROOT], "tg_ca_id": None, "bound": None,
        }

    async def test_a_pass_that_did_not_resolve_the_root_falls_back_to_the_default(
        self, public_client: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        _set_result(public_bundle, certs=[], root=None)

        root = (await public_client.get("/status")).json()["certs"]["registered_root"]

        assert root["tg_ca_id"] is None
        assert root["bound"] is None
        assert root["sha256"] == KNOWN_ROOTS[_ROOT]


class TestFailureContainment:
    async def test_a_broken_public_block_degrades_the_certs_block_only(
        self,
        public_client: httpx.AsyncClient,
        public_bundle: DepsBundle,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def boom(*_: object) -> None:
            raise RuntimeError("secret-looking detail must not leak")

        monkeypatch.setattr(status_webapps, "_public_certs_block", boom)
        _set_result(public_bundle, certs=[_cert_status("wild")], root=_root(True))

        response = await public_client.get("/status")

        assert response.status_code == 200
        body = response.json()
        assert body["certs"] == {"computation_failed": True, "error_type": "RuntimeError"}
        assert "leak" not in response.text
        assert body["tls"]["mode"] == "public"
        assert body["process"]["state"] == "running"

    async def test_a_broken_private_certs_block_degrades_too(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bundle = make_deps(tmp_path)

        def boom(*_: object) -> None:
            raise OSError("unreadable")

        monkeypatch.setattr(bundle.certs, "leaf_status", boom)
        async with _client(bundle) as client:
            response = await client.get("/status")

        assert response.status_code == 200
        assert response.json()["certs"] == {"computation_failed": True, "error_type": "OSError"}

    async def test_healthz_follows_local_ok_in_public_mode_and_a_broken_block_does_not_matter(
        self,
        public_client: httpx.AsyncClient,
        public_bundle: DepsBundle,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A refused certificate is a local failure (the reconciler sets local_ok False), so
        /healthz reads 503 exactly as for any local failure; the public blocks add nothing."""
        monkeypatch.setattr(
            status_webapps, "_public_certs_block", lambda *_: (_ for _ in ()).throw(ValueError())
        )
        error = "public certificate 'wild': key_file: public key: refused (secret-ish detail)"
        public_bundle.reconciler.last_result = ReconcileResult(
            ok=False,
            trigger="tick",
            started_at=datetime.now(UTC),
            local_ok=False,
            errors=[error],
            public_certs=[_cert_status("wild", "invalid", last_error=error)],
            registered_root=_root(False),
        )

        response = await public_client.get("/healthz")

        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "unhealthy"
        assert body["checks"]["gateway"] == {"ok": True, "state": "running"}
        assert body["checks"]["reconcile"]["ok"] is False
        assert "secret-ish" not in response.text  # /healthz never carries reconcile detail

    async def test_healthz_is_ok_in_public_mode_when_the_pass_was_locally_healthy(
        self, public_client: httpx.AsyncClient, public_bundle: DepsBundle
    ) -> None:
        # Unbound is TG-side.
        _set_result(public_bundle, certs=[_cert_status("wild")], root=_root(False))

        response = await public_client.get("/healthz")

        assert response.status_code == 200
        assert response.json()["status"] == "ok"


class TestPrivateModeUnchanged:
    async def test_private_status_has_no_new_keys(self, tmp_path: Path) -> None:
        bundle = make_deps(tmp_path)
        async with _client(bundle) as client:
            body = (await client.get("/status")).json()

        assert set(body["certs"]) == {"x509_ca_not_after", "leaf_not_after", "leaf_state"}
        assert body["certs"]["x509_ca_not_after"] is not None
        assert body["certs"]["leaf_state"] == "missing"
        assert body["tls"]["mode"] == "static"


# --- certs.public[].acme ------------------------------------------------------------

_ACME_KEYS = {
    "state", "directory", "staging", "installed", "installed_at", "installed_serial",
    "last_attempt_at", "last_success_at", "next_attempt_at", "error_code", "error_excerpt",
    "renewal_reason", "consecutive_failures", "in_backoff", "retry_after", "last_crash",
    "permissions_problem", "task_dead", "state_error", "config_error",
}  # fmt: skip
_AT = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
_LATER = datetime(2026, 10, 20, 13, 30, tzinfo=UTC)


def _acme_status(
    name: str = ACME_CERT,
    state: str = "pending",
    *,
    generation: str | None = None,
    not_after: datetime | None = None,
    last_error: str | None = None,
) -> PublicCertStatus:
    return PublicCertStatus(
        name=name,
        names=(f"*.apps.{ZONE}",),
        not_after=not_after,
        state=state,  # type: ignore[arg-type]
        last_error=last_error,
        generation=generation,
        source="acme",
    )


def _entry_named(body: dict[str, Any], name: str = ACME_CERT) -> dict[str, Any]:
    entry: dict[str, Any] = next(e for e in body["certs"]["public"] if e["name"] == name)
    return entry


@pytest.fixture
def runner() -> StubAcmeRunner:
    return StubAcmeRunner(snapshot=acme_snapshot(cert_snapshot()))


@pytest.fixture
def acme_deps(tmp_path: Path, runner: StubAcmeRunner) -> DepsBundle:
    return acme_bundle(tmp_path, runner)


async def _status_of(bundle: DepsBundle) -> dict[str, Any]:
    async with _client(bundle) as client:
        response = await client.get("/status")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


class TestAcmeBlock:
    async def test_only_source_acme_certificates_carry_an_acme_block(
        self, acme_deps: DepsBundle
    ) -> None:
        _set_result(
            acme_deps,
            certs=[_cert_status(FILE_CERT), _acme_status(generation="aaaaaaaaaaaa")],
            root=_root(True),
        )

        listed = (await _status_of(acme_deps))["certs"]["public"]

        by_name = {e["name"]: e for e in listed}
        assert set(by_name[ACME_CERT]["acme"]) == _ACME_KEYS
        assert set(by_name[FILE_CERT]) == {
            "name", "names", "not_after", "state", "last_error", "generation",
        }  # fmt: skip

    async def test_a_gateway_with_only_file_certificates_has_no_acme_block_and_no_snapshot(
        self, public_bundle: DepsBundle
    ) -> None:
        runner = StubAcmeRunner(snapshot_error=RuntimeError("must not be called"))
        public_bundle.deps = dataclasses.replace(
            public_bundle.deps,
            acme=runner,  # type: ignore[arg-type]
        )
        _set_result(public_bundle, certs=[_cert_status("wild"), _cert_status("api")])

        listed = (await _status_of(public_bundle))["certs"]["public"]

        assert all("acme" not in e for e in listed)
        assert runner.snapshot_calls == 0

    async def test_every_field_is_reported_from_the_snapshot(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        runner.snapshot_value = acme_snapshot(
            cert_snapshot(
                state=AcmeCertState.BACKOFF,
                directory=PRODUCTION_URL,
                staging=False,
                installed=True,
                installed_at=_AT,
                installed_serial="0abc",
                last_attempt_at=_AT,
                last_success_at=_AT - timedelta(days=30),
                next_attempt_at=_LATER,
                error_code=AcmeErrorClass.RATE_LIMITED,
                error_excerpt="too many certificates",
                renewal_reason="check_interval",
                consecutive_failures=3,
                in_backoff=True,
                retry_after=_LATER,
                last_crash="KeyError: 'serial' at runner.py:812",
                permissions_problem="/data/acme/lego is not owned by uid 10001",
            ),
            state_error="state.json is unreadable",
            task_dead=True,
        )
        _set_result(acme_deps, certs=[_acme_status(generation="aaaaaaaaaaaa")], root=_root(True))

        acme = _entry_named(await _status_of(acme_deps))["acme"]

        assert acme == {
            "state": "backoff",
            "directory": PRODUCTION_URL,
            "staging": False,
            "installed": True,
            "installed_at": _AT.isoformat(),
            "installed_serial": "0abc",
            "last_attempt_at": _AT.isoformat(),
            "last_success_at": (_AT - timedelta(days=30)).isoformat(),
            "next_attempt_at": _LATER.isoformat(),
            "error_code": "rate_limited",
            "error_excerpt": "too many certificates",
            "renewal_reason": "check_interval",
            "consecutive_failures": 3,
            "in_backoff": True,
            "retry_after": _LATER.isoformat(),
            "last_crash": "KeyError: 'serial' at runner.py:812",
            "permissions_problem": "/data/acme/lego is not owned by uid 10001",
            "task_dead": True,
            "state_error": "state.json is unreadable",
            "config_error": None,
        }

    @pytest.mark.parametrize("state", list(AcmeCertState))
    async def test_every_runner_state_is_reported_by_its_value(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner, state: AcmeCertState
    ) -> None:
        runner.snapshot_value = acme_snapshot(cert_snapshot(state=state))
        _set_result(acme_deps, certs=[_acme_status()], root=_root(True))

        acme = _entry_named(await _status_of(acme_deps))["acme"]

        assert acme["state"] == state.value

    async def test_a_quiet_certificate_reports_nulls_not_missing_keys(
        self, acme_deps: DepsBundle
    ) -> None:
        _set_result(acme_deps, certs=[_acme_status(generation="aaaaaaaaaaaa")], root=_root(True))

        acme = _entry_named(await _status_of(acme_deps))["acme"]

        assert acme["state"] == "idle"
        assert acme["error_code"] is None
        assert acme["error_excerpt"] is None
        assert acme["retry_after"] is None
        assert acme["state_error"] is None
        assert acme["config_error"] is None
        assert acme["consecutive_failures"] == 0
        assert acme["in_backoff"] is False

    async def test_a_staging_dry_run_is_reported_as_not_installed(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        runner.snapshot_value = acme_snapshot(
            cert_snapshot(
                state=AcmeCertState.DRY_RUN_OK,
                directory=STAGING_URL,
                staging=True,
                installed=False,
                last_success_at=_AT,
            )
        )
        _set_result(acme_deps, certs=[_acme_status()], root=_root(True))

        acme = _entry_named(await _status_of(acme_deps))["acme"]

        assert (acme["state"], acme["staging"], acme["installed"]) == ("dry_run_ok", True, False)
        assert acme["directory"] == STAGING_URL

    async def test_each_acme_certificate_gets_its_own_snapshot_entry(
        self, tmp_path: Path
    ) -> None:
        other = "other-acme"
        doc = yaml.safe_load(acme_seed())
        doc["public_tls"]["certificates"].append(
            {"name": other, "names": [f"api.apps.{ZONE}"], "source": "acme"}
        )
        runner = StubAcmeRunner(
            snapshot=acme_snapshot(
                cert_snapshot(state=AcmeCertState.IDLE),
                cert_snapshot(
                    other, state=AcmeCertState.FAILED, error_code=AcmeErrorClass.DNS_ZONE
                ),
            )
        )
        bundle = acme_bundle(tmp_path, runner, seed=yaml.safe_dump(doc, sort_keys=False))
        _set_result(bundle, certs=[_acme_status(), _acme_status(other)], root=_root(True))

        body = await _status_of(bundle)

        assert _entry_named(body)["acme"]["error_code"] is None
        assert _entry_named(body, other)["acme"]["error_code"] == "dns_zone"
        assert runner.snapshot_calls == 1


class TestAcmeFallback:
    """No snapshot entry for the certificate: the seed's directory, nulls, and the config error."""

    async def test_a_certificate_the_runner_does_not_hold_reports_the_seed_directory(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        runner.snapshot_value = acme_snapshot()  # configured, but holds no certificates
        _set_result(acme_deps, certs=[_acme_status()], root=_root(True))

        acme = _entry_named(await _status_of(acme_deps))["acme"]

        assert acme == {
            "state": None,
            "directory": STAGING_URL,
            "staging": True,
            "installed": False,
            "installed_at": None,
            "installed_serial": None,
            "last_attempt_at": None,
            "last_success_at": None,
            "next_attempt_at": None,
            "error_code": None,
            "error_excerpt": None,
            "renewal_reason": None,
            "consecutive_failures": 0,
            "in_backoff": False,
            "retry_after": None,
            "last_crash": None,
            "permissions_problem": None,
            "task_dead": False,
            "state_error": None,
            "config_error": None,
        }

    async def test_no_runner_at_all_is_failed_internal_with_the_seed_directory(
        self, tmp_path: Path
    ) -> None:
        bundle = acme_bundle(tmp_path, None)
        _set_result(bundle, certs=[_acme_status()], root=_root(True))

        acme = _entry_named(await _status_of(bundle))["acme"]

        assert acme["state"] == "failed"
        assert acme["error_code"] == "internal"
        assert acme["error_excerpt"] == "ACME runner unavailable: it was not started"
        assert acme["directory"] == STAGING_URL
        assert acme["staging"] is True
        assert acme["state_error"] is None
        assert set(acme) == _ACME_KEYS

    async def test_the_fallback_reports_a_production_seed_directory(self, tmp_path: Path) -> None:
        bundle = acme_bundle(tmp_path, None, seed=acme_seed("production"))
        _set_result(bundle, certs=[_acme_status()], root=_root(True))

        acme = _entry_named(await _status_of(bundle))["acme"]

        assert acme["directory"] == PRODUCTION_URL
        assert acme["staging"] is False

    async def test_the_fallback_reports_installed_from_the_pass_generation(
        self, tmp_path: Path
    ) -> None:
        bundle = acme_bundle(tmp_path, None)
        _set_result(
            bundle,
            certs=[_acme_status(state="ok", generation="aaaaaaaaaaaa", not_after=_NOT_AFTER)],
            root=_root(True),
        )

        acme = _entry_named(await _status_of(bundle))["acme"]

        assert acme["installed"] is True

    async def test_a_config_error_with_no_snapshot_entry_is_failed_with_code_config(
        self, tmp_path: Path
    ) -> None:
        bundle = acme_bundle(tmp_path, StubAcmeRunner(snapshot=acme_snapshot()))
        detail = "ACME DNS token file /config/acme/cloudflare-token does not exist"
        _set_result(
            bundle,
            certs=[_acme_status()],
            root=_root(True),
            acme_errors=[AcmeError(certificate=None, code="config", detail=detail)],
        )

        acme = _entry_named(await _status_of(bundle))["acme"]

        assert acme["state"] == "failed"
        assert acme["error_code"] == "config"
        assert acme["error_excerpt"] == detail
        assert acme["config_error"] == detail

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(AcmeError(ACME_CERT, "config", "about one certificate"), id="per-cert"),
            pytest.param(AcmeError(None, "internal", "state file"), id="other-code"),
            pytest.param(AcmeError(None, "invalid_output", "refused"), id="invalid-output"),
        ],
    )
    async def test_only_a_pass_level_config_error_counts_as_config_error(
        self, tmp_path: Path, error: AcmeError
    ) -> None:
        bundle = acme_bundle(tmp_path, StubAcmeRunner(snapshot=acme_snapshot()))
        _set_result(bundle, certs=[_acme_status()], root=_root(True), acme_errors=[error])

        acme = _entry_named(await _status_of(bundle))["acme"]

        assert acme["config_error"] is None
        assert acme["state"] is None
        assert acme["error_code"] is None


class TestAcmeRunnerLevelErrors:
    async def test_state_error_is_reported_with_the_snapshot_entry(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        runner.snapshot_value = acme_snapshot(
            cert_snapshot(state=AcmeCertState.FAILED, error_code=AcmeErrorClass.INTERNAL),
            state_error="ACME state file is unusable",
        )
        _set_result(acme_deps, certs=[_acme_status()], root=_root(True))

        acme = _entry_named(await _status_of(acme_deps))["acme"]

        assert acme["state_error"] == "ACME state file is unusable"
        assert acme["state"] == "failed"
        assert acme["error_code"] == "internal"

    async def test_state_error_is_reported_even_without_a_snapshot_entry(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        runner.snapshot_value = acme_snapshot(state_error="ACME state file is unusable")
        _set_result(acme_deps, certs=[_acme_status()], root=_root(True))

        acme = _entry_named(await _status_of(acme_deps))["acme"]

        assert acme["state_error"] == "ACME state file is unusable"
        assert acme["state"] is None

    async def test_config_error_rides_along_with_a_snapshot_entry(
        self, acme_deps: DepsBundle
    ) -> None:
        detail = "ACME DNS token file /config/acme/cloudflare-token is not a regular file"
        _set_result(
            acme_deps,
            certs=[_acme_status(state="ok", generation="aaaaaaaaaaaa", not_after=_NOT_AFTER)],
            root=_root(True),
            acme_errors=[AcmeError(None, "config", detail)],
        )

        acme = _entry_named(await _status_of(acme_deps))["acme"]

        assert acme["config_error"] == detail
        # The snapshot's own view is kept: the config error is reported beside it.
        assert acme["state"] == "idle"
        assert acme["error_code"] is None

    async def test_the_first_pass_level_config_error_wins(self, tmp_path: Path) -> None:
        bundle = acme_bundle(tmp_path, None)
        _set_result(
            bundle,
            certs=[_acme_status()],
            root=_root(True),
            acme_errors=[
                AcmeError(ACME_CERT, "config", "per certificate"),
                AcmeError(None, "config", "first pass-level"),
                AcmeError(None, "config", "second pass-level"),
            ],
        )

        acme = _entry_named(await _status_of(bundle))["acme"]

        assert acme["config_error"] == "first pass-level"


class TestAcmeFailureContainment:
    async def test_a_raising_snapshot_degrades_the_acme_block_only(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        runner.snapshot_error = RuntimeError("secret-looking detail must not leak")
        _set_result(
            acme_deps,
            certs=[_cert_status(FILE_CERT), _acme_status(state="ok", generation="aaaaaaaaaaaa")],
            root=_root(True),
        )

        async with _client(acme_deps) as client:
            response = await client.get("/status")

        assert response.status_code == 200
        assert "leak" not in response.text
        listed = {e["name"]: e for e in response.json()["certs"]["public"]}
        assert listed[ACME_CERT]["acme"] == {
            "state": "failed",
            "directory": STAGING_URL,
            "staging": True,
            "installed": True,
            "installed_at": None,
            "installed_serial": None,
            "last_attempt_at": None,
            "last_success_at": None,
            "next_attempt_at": None,
            "error_code": "internal",
            "error_excerpt": "ACME runner snapshot failed (RuntimeError)",
            "renewal_reason": None,
            "consecutive_failures": 0,
            "in_backoff": False,
            "retry_after": None,
            "last_crash": None,
            "permissions_problem": None,
            "task_dead": False,
            "state_error": None,
            "config_error": None,
            "computation_failed": True,
            "error_type": "RuntimeError",
        }
        assert listed[ACME_CERT]["generation"] == "aaaaaaaaaaaa"
        assert listed[ACME_CERT]["state"] == "ok"
        assert "acme" not in listed[FILE_CERT]
        assert listed[FILE_CERT]["state"] == "ok"

    async def test_a_raising_snapshot_does_not_degrade_the_whole_certs_block(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        runner.snapshot_error = OSError("disk")
        _set_result(acme_deps, certs=[_acme_status()], root=_root(True))

        certs = (await _status_of(acme_deps))["certs"]

        assert "computation_failed" not in certs
        assert certs["registered_root"]["bound"] is True

    async def test_a_raising_snapshot_is_logged_by_type_only(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        runner.snapshot_error = ValueError("token-ish detail")
        _set_result(acme_deps, certs=[_acme_status()], root=_root(True))

        with structlog.testing.capture_logs() as logs:
            await _status_of(acme_deps)

        failed = [
            e
            for e in logs
            if e["event"] == "status.block_failed" and e["block"] == "certs.public.acme"
        ]
        assert [e["error_type"] for e in failed] == ["ValueError"]
        assert "token-ish" not in str(logs)

    async def test_an_acme_error_never_changes_healthz(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        runner.snapshot_error = RuntimeError("boom")
        _set_result(
            acme_deps,
            certs=[_acme_status()],
            root=_root(True),
            acme_errors=[AcmeError(None, "config", "token file missing")],
        )

        async with _client(acme_deps) as client:
            response = await client.get("/healthz")

        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert runner.snapshot_calls == 0


# --- unavailable runner, snapshot failure shape, task_dead, public_acme_errors


class TestAcmeRunnerUnavailable:
    """No runner (construction failed or never started): every ACME entry says so."""

    async def test_the_construction_failure_is_the_error_excerpt(self, tmp_path: Path) -> None:
        bundle = acme_bundle(tmp_path, None, acme_unavailable="OSError: cannot create /data/acme")
        _set_result(bundle, certs=[_acme_status()], root=_root(True))

        acme = _entry_named(await _status_of(bundle))["acme"]

        assert acme["state"] == "failed"
        assert acme["error_code"] == "internal"
        assert acme["error_excerpt"] == "ACME runner unavailable: OSError: cannot create /data/acme"

    async def test_the_entry_keeps_the_full_key_set_and_null_history(self, tmp_path: Path) -> None:
        bundle = acme_bundle(tmp_path, None, acme_unavailable="OSError: x")
        _set_result(bundle, certs=[_acme_status()], root=_root(True))

        acme = _entry_named(await _status_of(bundle))["acme"]

        assert set(acme) == _ACME_KEYS
        for key in (
            "installed_at", "installed_serial", "last_attempt_at", "last_success_at",
            "next_attempt_at", "renewal_reason", "retry_after", "last_crash",
            "permissions_problem", "state_error", "config_error",
        ):  # fmt: skip
            assert acme[key] is None, key
        assert acme["consecutive_failures"] == 0
        assert acme["in_backoff"] is False
        assert acme["task_dead"] is False

    async def test_installed_follows_the_pass_generation(self, tmp_path: Path) -> None:
        bundle = acme_bundle(tmp_path, None, acme_unavailable="OSError: x")
        _set_result(
            bundle,
            certs=[_acme_status(state="ok", generation="aaaaaaaaaaaa", not_after=_NOT_AFTER)],
            root=_root(True),
        )

        acme = _entry_named(await _status_of(bundle))["acme"]

        assert acme["installed"] is True
        assert acme["error_code"] == "internal"

    async def test_a_pass_level_config_error_is_reported_beside_it(self, tmp_path: Path) -> None:
        bundle = acme_bundle(tmp_path, None, acme_unavailable="OSError: x")
        _set_result(
            bundle,
            certs=[_acme_status()],
            root=_root(True),
            acme_errors=[AcmeError(None, "config", "token file missing")],
        )

        acme = _entry_named(await _status_of(bundle))["acme"]

        assert acme["config_error"] == "token file missing"
        assert acme["error_code"] == "internal"  # the runner problem is the primary one

    async def test_file_certificates_are_untouched_by_a_missing_runner(
        self, tmp_path: Path
    ) -> None:
        bundle = acme_bundle(tmp_path, None, acme_unavailable="OSError: x")
        _set_result(
            bundle,
            certs=[_cert_status(FILE_CERT), _acme_status()],
            root=_root(True),
        )

        listed = {e["name"]: e for e in (await _status_of(bundle))["certs"]["public"]}

        assert "acme" not in listed[FILE_CERT]
        assert listed[FILE_CERT]["state"] == "ok"

    async def test_a_gateway_with_only_file_certificates_reports_no_runner_problem(
        self, public_bundle: DepsBundle
    ) -> None:
        _set_result(public_bundle, certs=[_cert_status("wild"), _cert_status("api")])

        body = await _status_of(public_bundle)

        assert all("acme" not in e for e in body["certs"]["public"])
        assert body["certs"]["public_acme_errors"] == []

    async def test_a_present_runner_ignores_the_unavailable_text(self, tmp_path: Path) -> None:
        runner = StubAcmeRunner(snapshot=acme_snapshot(cert_snapshot()))
        bundle = acme_bundle(tmp_path, runner, acme_unavailable="stale text")
        _set_result(bundle, certs=[_acme_status(generation="aaaaaaaaaaaa")], root=_root(True))

        body = await _status_of(bundle)

        assert "stale text" not in str(body)
        assert _entry_named(body)["acme"]["state"] == "idle"

    async def test_the_excerpt_is_the_same_text_the_reconciler_records(
        self, tmp_path: Path
    ) -> None:
        detail = "ACME runner unavailable: OSError: cannot create /data/acme"
        bundle = acme_bundle(tmp_path, None, acme_unavailable="OSError: cannot create /data/acme")
        _set_result(
            bundle,
            certs=[_acme_status()],
            root=_root(True),
            acme_errors=[AcmeError(None, "internal", detail)],
        )

        body = await _status_of(bundle)

        assert _entry_named(body)["acme"]["error_excerpt"] == detail
        assert body["certs"]["public_acme_errors"] == [{"code": "internal", "detail": detail}]


class TestAcmeSnapshotFailureShape:
    async def test_the_entry_keeps_every_key_and_adds_the_failure_markers(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        runner.snapshot_error = RuntimeError("secret-looking detail must not leak")
        _set_result(acme_deps, certs=[_acme_status()], root=_root(True))

        acme = _entry_named(await _status_of(acme_deps))["acme"]

        assert set(acme) == _ACME_KEYS | {"computation_failed", "error_type"}
        assert (acme["state"], acme["error_code"]) == ("failed", "internal")
        assert acme["computation_failed"] is True
        assert acme["error_type"] == "RuntimeError"
        assert acme["error_excerpt"] == "ACME runner snapshot failed (RuntimeError)"
        assert "leak" not in str(acme)

    async def test_a_pass_level_config_error_is_carried_through(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        runner.snapshot_error = OSError("disk")
        _set_result(
            acme_deps,
            certs=[_acme_status()],
            root=_root(True),
            acme_errors=[AcmeError(None, "config", "token file missing")],
        )

        acme = _entry_named(await _status_of(acme_deps))["acme"]

        assert acme["config_error"] == "token file missing"
        assert acme["error_code"] == "internal"
        assert acme["error_type"] == "OSError"

    async def test_every_acme_certificate_gets_the_same_failure_entry(self, tmp_path: Path) -> None:
        other = "other-acme"
        doc = yaml.safe_load(acme_seed())
        doc["public_tls"]["certificates"].append(
            {"name": other, "names": [f"api.apps.{ZONE}"], "source": "acme"}
        )
        runner = StubAcmeRunner(snapshot_error=ValueError("x"))
        bundle = acme_bundle(tmp_path, runner, seed=yaml.safe_dump(doc, sort_keys=False))
        _set_result(bundle, certs=[_acme_status(), _acme_status(other)], root=_root(True))

        body = await _status_of(bundle)

        assert _entry_named(body)["acme"] == _entry_named(body, other)["acme"]
        assert runner.snapshot_calls == 1

    async def test_the_four_entry_shapes_share_one_key_set(self, tmp_path: Path) -> None:
        shapes: dict[str, dict[str, Any]] = {}
        runners: dict[str, StubAcmeRunner | None] = {
            "snapshot": StubAcmeRunner(snapshot=acme_snapshot(cert_snapshot())),
            "fallback": StubAcmeRunner(snapshot=acme_snapshot()),
            "unavailable": None,
            "failed": StubAcmeRunner(snapshot_error=RuntimeError("x")),
        }
        for label, shape_runner in runners.items():
            (tmp_path / label).mkdir()
            bundle = acme_bundle(tmp_path / label, shape_runner)
            _set_result(bundle, certs=[_acme_status()], root=_root(True))
            shapes[label] = _entry_named(await _status_of(bundle))["acme"]

        for label, acme in shapes.items():
            assert set(acme) >= _ACME_KEYS, label
        assert set(shapes["snapshot"]) == set(shapes["fallback"]) == set(shapes["unavailable"])
        assert set(shapes["failed"]) - _ACME_KEYS == {"computation_failed", "error_type"}


class TestAcmeTaskDeadAndCrash:
    async def test_task_dead_is_reported_on_each_entry_built_from_a_snapshot(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        runner.snapshot_value = acme_snapshot(cert_snapshot(), task_dead=True)
        _set_result(acme_deps, certs=[_acme_status(generation="aaaaaaaaaaaa")], root=_root(True))

        acme = _entry_named(await _status_of(acme_deps))["acme"]

        assert acme["task_dead"] is True
        assert acme["state"] == "idle"  # the snapshot's own view of the certificate is kept

    async def test_task_dead_is_reported_on_a_certificate_the_snapshot_does_not_hold(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        runner.snapshot_value = acme_snapshot(task_dead=True)
        _set_result(acme_deps, certs=[_acme_status()], root=_root(True))

        acme = _entry_named(await _status_of(acme_deps))["acme"]

        assert acme["task_dead"] is True
        assert acme["state"] is None

    async def test_a_live_runner_reports_task_dead_false(
        self, acme_deps: DepsBundle
    ) -> None:
        _set_result(acme_deps, certs=[_acme_status(generation="aaaaaaaaaaaa")], root=_root(True))

        assert _entry_named(await _status_of(acme_deps))["acme"]["task_dead"] is False

    async def test_last_crash_and_permissions_problem_come_from_the_certificate_snapshot(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        runner.snapshot_value = acme_snapshot(
            cert_snapshot(
                state=AcmeCertState.FAILED,
                error_code=AcmeErrorClass.INTERNAL,
                last_crash="ValueError: bad serial",
                permissions_problem="/data/acme/state.json is not writable",
            )
        )
        _set_result(acme_deps, certs=[_acme_status()], root=_root(True))

        acme = _entry_named(await _status_of(acme_deps))["acme"]

        assert acme["last_crash"] == "ValueError: bad serial"
        assert acme["permissions_problem"] == "/data/acme/state.json is not writable"
        assert acme["error_code"] == "internal"

    async def test_a_task_death_is_not_an_unhealthy_gateway(
        self, acme_deps: DepsBundle, runner: StubAcmeRunner
    ) -> None:
        runner.snapshot_value = acme_snapshot(cert_snapshot(), task_dead=True)
        _set_result(
            acme_deps,
            certs=[_acme_status()],
            root=_root(True),
            acme_errors=[AcmeError(None, "internal", "the ACME runner task is not running")],
        )

        async with _client(acme_deps) as client:
            response = await client.get("/healthz")

        assert response.status_code == 200
        assert response.json()["status"] == "ok"


class TestPublicAcmeErrors:
    """``certs.public_acme_errors``: certificate-less ACME problems other than ``config``."""

    def _errors(self, body: dict[str, Any]) -> list[dict[str, str]]:
        errors: list[dict[str, str]] = body["certs"]["public_acme_errors"]
        return errors

    async def test_a_certificate_less_internal_error_is_listed_with_code_and_detail(
        self, acme_deps: DepsBundle
    ) -> None:
        _set_result(
            acme_deps,
            certs=[_acme_status()],
            root=_root(True),
            acme_errors=[AcmeError(None, "internal", "ACME state file is unusable")],
        )

        body = await _status_of(acme_deps)

        assert self._errors(body) == [{"code": "internal", "detail": "ACME state file is unusable"}]

    async def test_every_entry_is_exactly_code_and_detail(self, acme_deps: DepsBundle) -> None:
        _set_result(
            acme_deps,
            certs=[_acme_status()],
            root=_root(True),
            acme_errors=[AcmeError(None, "internal", "x")],
        )

        [entry] = self._errors(await _status_of(acme_deps))

        assert set(entry) == {"code", "detail"}

    async def test_config_errors_are_not_listed_they_ride_on_each_certificate(
        self, acme_deps: DepsBundle
    ) -> None:
        _set_result(
            acme_deps,
            certs=[_acme_status()],
            root=_root(True),
            acme_errors=[AcmeError(None, "config", "token file missing")],
        )

        body = await _status_of(acme_deps)

        assert self._errors(body) == []
        assert _entry_named(body)["acme"]["config_error"] == "token file missing"

    async def test_errors_that_name_a_certificate_are_not_listed(
        self, acme_deps: DepsBundle
    ) -> None:
        _set_result(
            acme_deps,
            certs=[_acme_status()],
            root=_root(True),
            acme_errors=[
                AcmeError(ACME_CERT, "dns_auth", "token rejected"),
                AcmeError(ACME_CERT, "invalid_output", "refused"),
                AcmeError(ACME_CERT, "internal", "unexpected"),
            ],
        )

        assert self._errors(await _status_of(acme_deps)) == []

    async def test_several_errors_keep_the_passes_order(self, acme_deps: DepsBundle) -> None:
        _set_result(
            acme_deps,
            certs=[_acme_status()],
            root=_root(True),
            acme_errors=[
                AcmeError(None, "internal", "first"),
                AcmeError(None, "config", "skipped"),
                AcmeError(ACME_CERT, "dns_auth", "skipped too"),
                AcmeError(None, "invalid_output", "second"),
            ],
        )

        assert self._errors(await _status_of(acme_deps)) == [
            {"code": "internal", "detail": "first"},
            {"code": "invalid_output", "detail": "second"},
        ]

    async def test_it_is_empty_before_the_first_pass(self, acme_deps: DepsBundle) -> None:
        acme_deps.reconciler.last_result = None

        assert self._errors(await _status_of(acme_deps)) == []

    async def test_it_is_empty_for_a_quiet_pass(self, acme_deps: DepsBundle) -> None:
        _set_result(acme_deps, certs=[_acme_status(generation="aaaaaaaaaaaa")], root=_root(True))

        assert self._errors(await _status_of(acme_deps)) == []

    async def test_it_is_listed_even_when_no_certificate_is_acme(
        self, public_bundle: DepsBundle
    ) -> None:
        """A problem the pass saw that names no certificate is shown whatever the seed holds."""
        _set_result(
            public_bundle,
            certs=[_cert_status("wild")],
            root=_root(True),
            acme_errors=[AcmeError(None, "internal", "ACME runner unavailable: x")],
        )

        body = await _status_of(public_bundle)

        assert self._errors(body) == [
            {"code": "internal", "detail": "ACME runner unavailable: x"}
        ]

    async def test_it_does_not_change_healthz(self, acme_deps: DepsBundle) -> None:
        _set_result(
            acme_deps,
            certs=[_acme_status()],
            root=_root(True),
            acme_errors=[AcmeError(None, "internal", "ACME runner unavailable: x")],
        )

        async with _client(acme_deps) as client:
            response = await client.get("/healthz")

        assert response.status_code == 200

    async def test_a_broken_public_block_degrades_with_the_certs_block(
        self, acme_deps: DepsBundle, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*_: object) -> None:
            raise RuntimeError("secret-looking")

        monkeypatch.setattr(status_webapps, "_public_acme_errors", boom)
        _set_result(acme_deps, certs=[_acme_status()], root=_root(True))

        async with _client(acme_deps) as client:
            response = await client.get("/status")

        assert response.status_code == 200
        assert response.json()["certs"] == {
            "computation_failed": True,
            "error_type": "RuntimeError",
        }
