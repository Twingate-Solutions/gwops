"""Shared fixtures for admin API tests: stubbed deps bundle + ASGI test clients.

The API is tested against `httpx.ASGITransport` (no sockets) with fakes for the
runtime pieces: a stub gateway process, a stub reconciler recording triggers, a real
`CertManager`/`OverlayStore`/`StateRegistry` on tmp_path (they are cheap and the
routes exercise their real validation), and `tg=None` unless a test opts into the
respx-backed fake tenant.
"""

import asyncio
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import respx
from fastapi import FastAPI

from gwops.api.app import GwopsDeps, create_app
from gwops.certs.manager import CertManager
from gwops.configmodel.loader import ConfigLoadError, load_effective_state
from gwops.configmodel.store import OverlayStore
from gwops.reconciler.core import ReconcileResult
from gwops.reconciler.registry import StateRegistry
from gwops.renderer.capabilities import Capabilities
from gwops.renderer.desired import desired_tg_objects
from gwops.settings import GwopsSettings
from gwops.supervisor.process import ProcState

ADMIN_TOKEN = "test-admin-token"

SEED = """\
twingate:
  network: acme
  gateway_id: g-1
ssh_upstreams:
  - name: host1
    address: 10.0.0.5:22
"""


class StubProcess:
    """Records GatewayProcess lifecycle calls without spawning anything."""

    def __init__(self) -> None:
        self.state = ProcState.RUNNING
        self.returncode: int | None = None
        self.calls: list[str] = []

    async def start(self) -> None:
        self.calls.append("start")
        self.state = ProcState.RUNNING

    async def drain_restart(self, timeout: float = 30.0) -> None:
        self.calls.append("drain_restart")

    async def stop(self, timeout: float = 30.0) -> None:
        self.calls.append("stop")
        self.state = ProcState.STOPPED


def ok_result(trigger: str = "startup") -> ReconcileResult:
    return ReconcileResult(
        ok=True,
        trigger=trigger,
        started_at=datetime.now(UTC),
        actions=["did things"],
        errors=[],
    )


class StubReconciler:
    """Records reconcile triggers and returns a canned result.

    Like the real reconciler, the result confirms every desired TG key of the current
    effective state as synced (``tg_synced``), so the API's end-to-end check passes;
    keys in `fail_keys` are reported unsynced to exercise the rollback path.
    """

    def __init__(self, seed_path: Path | None = None, store: OverlayStore | None = None) -> None:
        self.triggers: list[str] = []
        self.last_result: ReconcileResult | None = ok_result()
        self.fail_keys: set[str] = set()
        self._seed_path = seed_path
        self._store = store

    async def reconcile(self, trigger: str) -> ReconcileResult:
        self.triggers.append(trigger)
        result = ok_result(trigger)
        if self._seed_path is not None and self._store is not None:
            try:
                state, _provenance = load_effective_state(self._seed_path, self._store)
            except (ConfigLoadError, ValueError):
                result.ok = result.local_ok = False
                result.errors = ["effective state failed to load"]
            else:
                keys = {f"{d.kind}/{d.name}" for d in desired_tg_objects(state)}
                result.tg_synced = keys - self.fail_keys
                result.errors = [f"TG sync: {k}: rejected" for k in sorted(keys & self.fail_keys)]
                result.ok = not result.errors
        self.last_result = result
        return result


@dataclass
class DepsBundle:
    """The GwopsDeps handed to create_app plus the raw fakes for assertions."""

    deps: GwopsDeps
    process: StubProcess
    reconciler: StubReconciler
    store: OverlayStore
    certs: CertManager
    seed_path: Path


def make_deps(tmp_path: Path, *, seed: str = SEED, admin_token: str | None = ADMIN_TOKEN,
              ensure_cas: bool = True) -> DepsBundle:
    seed_path = tmp_path / "seed.yaml"
    seed_path.write_text(seed, encoding="utf-8")
    settings = GwopsSettings(
        seed_path=seed_path,
        data_dir=tmp_path / "data",
        runtime_dir=tmp_path / "run",
        gateway_binary=tmp_path / "gateway-unused",
        **{"TWINGATE_API_KEY": None, "GWOPS_ADMIN_TOKEN": admin_token},  # type: ignore[arg-type]
    )
    store = OverlayStore(settings.data_dir / "overlays")
    certs = CertManager(settings.data_dir / "pki")
    if ensure_cas:
        certs.ensure_x509_ca(generate=True)
        certs.ensure_ssh_ca(generate=True)
    process = StubProcess()
    reconciler = StubReconciler(seed_path, store)
    deps = GwopsDeps(
        settings=settings,
        store=store,
        reconciler=reconciler,  # type: ignore[arg-type]
        certs=certs,
        process=process,  # type: ignore[arg-type]
        caps=Capabilities(),
        registry=StateRegistry(settings.data_dir / "state.json"),
        tg=None,
        api_event=asyncio.Event(),
    )
    return DepsBundle(
        deps=deps, process=process, reconciler=reconciler, store=store, certs=certs,
        seed_path=seed_path,
    )


@pytest.fixture
def bundle(tmp_path: Path) -> DepsBundle:
    return make_deps(tmp_path)


@pytest.fixture
def app(bundle: DepsBundle) -> FastAPI:
    return create_app(bundle.deps)


def _client(app: FastAPI, token: str | None) -> httpx.AsyncClient:
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gwops", headers=headers
    )


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """A client presenting the correct bearer token."""
    async with _client(app, ADMIN_TOKEN) as client:
        yield client


@pytest.fixture
async def anon_client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """A client presenting no Authorization header at all."""
    async with _client(app, None) as client:
        yield client


# --- minimal fake TG tenant for the rotate-ca complete path -----------------------------

_TG_URL = "https://acme.twingate.com/api/graphql/"


@dataclass
class FakeCARegistrar:
    """Answers just the CreateX509CA / UpdateGateway operations rotate-ca uses."""

    created_ca_pems: list[str] = field(default_factory=list)
    gateway_bindings: list[dict[str, object]] = field(default_factory=list)
    fail: bool = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        import json

        body = json.loads(request.content)
        query = str(body["query"])
        variables = body.get("variables") or {}
        if self.fail:
            return httpx.Response(400, json={"errors": [{"message": "tenant unreachable"}]})
        if "GatewayRemoteNetwork" in query:
            return httpx.Response(
                200, json={"data": {"gateway": {"remoteNetwork": {"id": "rn-1"}}}}
            )
        if "CreateX509CA" in query:
            self.created_ca_pems.append(str(variables["certificate"]))
            return httpx.Response(
                200,
                json={
                    "data": {
                        "x509CertificateAuthorityCreate": {
                            "ok": True, "error": None, "entity": {"id": "ca-x-new"}
                        }
                    }
                },
            )
        if "UpdateGateway" in query:
            self.gateway_bindings.append(dict(variables))
            return httpx.Response(
                200, json={"data": {"gatewayUpdate": {"ok": True, "error": None}}}
            )
        raise AssertionError(f"fake CA registrar got an unexpected operation: {query[:80]}")


@pytest.fixture
def ca_registrar() -> Iterator[FakeCARegistrar]:
    server = FakeCARegistrar()
    with respx.mock(assert_all_called=False) as router:
        router.post(_TG_URL).mock(side_effect=server.handler)
        yield server
