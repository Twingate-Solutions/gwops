"""`POST /certs/rotate-ca` `complete` restarts the gateway when on-demand issuance is active."""

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import structlog.testing
from cryptography import x509

from gwops.api.app import create_app
from gwops.supervisor.process import ProcState
from gwops.tgapi.client import TGClient
from tests.store_support import leaf_cert_path

from .conftest import ADMIN_TOKEN, SEED, DepsBundle, FakeCARegistrar, StubProcess, make_deps

_ON_SEED = SEED + "ca:\n  x509:\n    on_demand_issuance: true\n"
_OFF_SEED = SEED + "ca:\n  x509:\n    on_demand_issuance: false\n"


class _SnapshotProcess(StubProcess):
    """A stub process that records the PKI files as they are when drain_restart runs."""

    def __init__(self, pki_dir: Path) -> None:
        super().__init__()
        self._pki_dir = pki_dir
        self.snapshots: list[dict[str, bytes]] = []

    async def drain_restart(self, timeout: float = 30.0) -> None:
        await super().drain_restart(timeout)
        self.snapshots.append(
            {
                "ca": (self._pki_dir / "x509-ca.crt").read_bytes(),
                "leaf": leaf_cert_path(self._pki_dir).read_bytes(),
            }
        )


def _client(bundle: DepsBundle) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(bundle.deps)),
        base_url="http://gwops",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )


async def _rotate(client: httpx.AsyncClient) -> httpx.Response:
    stage = await client.post("/certs/rotate-ca", json={"phase": "stage"})
    assert stage.status_code == 200
    return await client.post("/certs/rotate-ca", json={"phase": "complete"})


class TestModeOn:
    async def test_complete_drain_restarts_the_gateway_exactly_once(self, tmp_path: Path) -> None:
        """Promoting the CA with the mode on calls process.drain_restart once."""
        bundle = make_deps(tmp_path, seed=_ON_SEED)

        async with _client(bundle) as client:
            complete = await _rotate(client)

        assert complete.status_code == 200
        assert bundle.process.calls.count("drain_restart") == 1
        assert "stop" not in bundle.process.calls

    async def test_stage_alone_does_not_restart_the_gateway(self, tmp_path: Path) -> None:
        """Only the promoting phase restarts; staging leaves the running CA untouched."""
        bundle = make_deps(tmp_path, seed=_ON_SEED)

        async with _client(bundle) as client:
            stage = await client.post("/certs/rotate-ca", json={"phase": "stage"})

        assert stage.status_code == 200
        assert bundle.process.calls == []

    async def test_complete_without_a_staged_ca_does_not_restart(self, tmp_path: Path) -> None:
        """The 409 no-op path leaves the gateway alone."""
        bundle = make_deps(tmp_path, seed=_ON_SEED)

        async with _client(bundle) as client:
            response = await client.post("/certs/rotate-ca", json={"phase": "complete"})

        assert response.status_code == 409
        assert bundle.process.calls == []

    async def test_complete_restarts_once_with_the_tenant_registration_succeeding(
        self, tmp_path: Path, ca_registrar: FakeCARegistrar
    ) -> None:
        """Registration and rebind succeed, and the restart still happens exactly once."""
        bundle = make_deps(tmp_path, seed=_ON_SEED)
        bundle.deps.tg = TGClient(network="acme", api_key="k")

        async with _client(bundle) as client:
            complete = await _rotate(client)
        await bundle.deps.tg.aclose()

        assert complete.json()["errors"] == []
        assert ca_registrar.created_ca_pems
        assert bundle.process.calls.count("drain_restart") == 1

    async def test_the_restart_runs_after_the_new_ca_and_leaf_are_on_disk(
        self, tmp_path: Path
    ) -> None:
        """At drain_restart time the CA file is the promoted CA and the leaf chains to it."""
        bundle = make_deps(tmp_path, seed=_ON_SEED)
        pki = bundle.deps.settings.data_dir / "pki"
        process = _SnapshotProcess(pki)
        bundle.deps.process = process  # type: ignore[assignment]
        old_ca = (pki / "x509-ca.crt").read_bytes()

        async with _client(bundle) as client:
            complete = await _rotate(client)

        assert complete.status_code == 200
        [snapshot] = process.snapshots
        new_ca = x509.load_pem_x509_certificate(snapshot["ca"])
        assert snapshot["ca"] != old_ca
        chain = x509.load_pem_x509_certificates(snapshot["leaf"])
        assert chain[-1] == new_ca


class TestModeOff:
    async def test_complete_does_not_restart_the_gateway(self, tmp_path: Path) -> None:
        """With the mode absent the route leaves the process alone."""
        bundle = make_deps(tmp_path)

        async with _client(bundle) as client:
            complete = await _rotate(client)

        assert complete.status_code == 200
        assert bundle.process.calls == []

    async def test_complete_does_not_restart_with_the_mode_explicitly_false(
        self, tmp_path: Path
    ) -> None:
        """An explicit false behaves like an absent key."""
        bundle = make_deps(tmp_path, seed=_OFF_SEED)

        async with _client(bundle) as client:
            complete = await _rotate(client)

        assert complete.status_code == 200
        assert bundle.process.calls == []


_LOADS_ON_NEXT_START = "gateway loads the new CA on next start"
_STARTING_ERROR = "gateway was starting; restart it to load the new CA"


async def _registered(bundle: DepsBundle) -> AsyncIterator[DepsBundle]:
    bundle.deps.tg = TGClient(network="acme", api_key="k")
    yield bundle
    await bundle.deps.tg.aclose()


@pytest.fixture
async def on_bundle(tmp_path: Path, ca_registrar: FakeCARegistrar) -> AsyncIterator[DepsBundle]:
    """Mode on, with a fake tenant so registration succeeds and `errors` starts empty."""
    async for bundle in _registered(make_deps(tmp_path, seed=_ON_SEED)):
        yield bundle


@pytest.fixture
async def off_bundle(tmp_path: Path, ca_registrar: FakeCARegistrar) -> AsyncIterator[DepsBundle]:
    """Mode off, with a fake tenant."""
    async for bundle in _registered(make_deps(tmp_path)):
        yield bundle


class _RaisingProcess(StubProcess):
    """A stub whose drain_restart fails with the configured exception."""

    def __init__(self, error: Exception) -> None:
        super().__init__()
        self._error = error

    async def drain_restart(self, timeout: float = 30.0) -> None:
        self.calls.append("drain_restart")
        raise self._error


class _LockProbeProcess(StubProcess):
    """A stub that records whether the mutation lock was held during drain_restart."""

    def __init__(self, lock: asyncio.Lock) -> None:
        super().__init__()
        self._lock = lock
        self.lock_held: list[bool] = []

    async def drain_restart(self, timeout: float = 30.0) -> None:
        self.lock_held.append(self._lock.locked())
        await super().drain_restart(timeout)


def _completed(logs: list[dict[str, Any]]) -> dict[str, Any]:
    [entry] = [e for e in logs if e["event"] == "api.rotate_ca_completed"]
    return entry


class TestRestartFailure:
    @pytest.mark.parametrize("error", [RuntimeError("spawn failed"), OSError("no such file")])
    async def test_a_failing_restart_is_reported_and_logged_at_warning(
        self, on_bundle: DepsBundle, error: Exception
    ) -> None:
        bundle = on_bundle
        bundle.deps.process = _RaisingProcess(error)  # type: ignore[assignment]

        with structlog.testing.capture_logs() as logs:
            async with _client(bundle) as client:
                complete = await _rotate(client)

        assert complete.status_code == 200
        [message] = complete.json()["errors"]
        assert message.startswith("gateway restart failed:") and str(error) in message
        assert message.endswith("restart it to load the new CA")
        assert _completed(logs)["log_level"] == "warning"

    async def test_a_clean_rotation_logs_at_info(self, on_bundle: DepsBundle) -> None:
        bundle = on_bundle

        with structlog.testing.capture_logs() as logs:
            async with _client(bundle) as client:
                complete = await _rotate(client)

        assert complete.json()["errors"] == []
        assert _completed(logs)["log_level"] == "info"


class TestProcessNotRunning:
    async def test_starting_is_an_error_and_not_restarted(self, on_bundle: DepsBundle) -> None:
        bundle = on_bundle
        bundle.process.state = ProcState.STARTING

        with structlog.testing.capture_logs() as logs:
            async with _client(bundle) as client:
                complete = await _rotate(client)

        assert complete.status_code == 200
        assert complete.json()["errors"] == [_STARTING_ERROR]
        assert bundle.process.calls == []
        assert _completed(logs)["log_level"] == "warning"

    @pytest.mark.parametrize("state", [ProcState.DRAINING, ProcState.BACKOFF, ProcState.STOPPED])
    async def test_other_states_load_the_ca_on_next_start(
        self, on_bundle: DepsBundle, state: ProcState
    ) -> None:
        bundle = on_bundle
        bundle.process.state = state

        with structlog.testing.capture_logs() as logs:
            async with _client(bundle) as client:
                complete = await _rotate(client)

        body = complete.json()
        assert body["errors"] == []
        assert _LOADS_ON_NEXT_START in body["actions"]
        assert bundle.process.calls == []
        assert _completed(logs)["log_level"] == "info"

    @pytest.mark.parametrize("state", [ProcState.STARTING, ProcState.STOPPED])
    async def test_mode_off_ignores_the_process_state(
        self, off_bundle: DepsBundle, state: ProcState
    ) -> None:
        bundle = off_bundle
        bundle.process.state = state

        async with _client(bundle) as client:
            complete = await _rotate(client)

        body = complete.json()
        assert body["errors"] == []
        assert _LOADS_ON_NEXT_START not in body["actions"]


class TestRestartCoordination:
    async def test_the_restart_runs_under_the_mutation_lock(self, on_bundle: DepsBundle) -> None:
        bundle = on_bundle
        process = _LockProbeProcess(bundle.deps.mutation_lock)
        bundle.deps.process = process  # type: ignore[assignment]

        async with _client(bundle) as client:
            await _rotate(client)

        assert process.lock_held == [True]
        assert not bundle.deps.mutation_lock.locked()

    async def test_the_restart_waits_for_an_in_flight_mutation(
        self, on_bundle: DepsBundle
    ) -> None:
        bundle = on_bundle

        async with _client(bundle) as client:
            async with bundle.deps.mutation_lock:
                task = asyncio.create_task(_rotate(client))
                await asyncio.sleep(0.2)
                assert not task.done()
                assert bundle.process.calls == []
            complete = await task

        assert complete.status_code == 200
        assert bundle.process.calls.count("drain_restart") == 1

    async def test_no_restart_during_shutdown(self, on_bundle: DepsBundle) -> None:
        bundle = on_bundle
        bundle.deps.shutting_down.set()

        async with _client(bundle) as client:
            complete = await _rotate(client)

        body = complete.json()
        assert complete.status_code == 200
        assert bundle.process.calls == []
        assert body["errors"] == []
        assert _LOADS_ON_NEXT_START in body["actions"]


class _SlowRestartProcess(StubProcess):
    """A stub whose drain_restart is DRAINING until released, then ends RUNNING."""

    def __init__(self) -> None:
        super().__init__()
        self.draining = asyncio.Event()
        self.release = asyncio.Event()

    async def drain_restart(self, timeout: float = 30.0) -> None:
        self.calls.append("drain_restart")
        self.state = ProcState.DRAINING
        self.draining.set()
        await self.release.wait()
        self.state = ProcState.RUNNING
        self.calls.append("start")


class TestRestartCancellation:
    async def test_a_cancelled_request_cannot_strand_the_gateway_draining(
        self, on_bundle: DepsBundle
    ) -> None:
        """Cancelling the request between drain and start still ends RUNNING, locks released."""
        bundle = on_bundle
        process = _SlowRestartProcess()
        bundle.deps.process = process  # type: ignore[assignment]

        async with _client(bundle) as client:
            request = asyncio.create_task(_rotate(client))
            await asyncio.wait_for(process.draining.wait(), timeout=5)
            request.cancel()
            await asyncio.gather(request, return_exceptions=True)
            assert process.state is ProcState.DRAINING
            process.release.set()
            for _ in range(100):
                if process.state is ProcState.RUNNING and not bundle.deps.mutation_lock.locked():
                    break
                await asyncio.sleep(0.01)

        assert process.state is ProcState.RUNNING
        assert process.calls == ["drain_restart", "start"]
        assert not bundle.deps.mutation_lock.locked()


class TestRegistrationFailureMessage:
    async def test_the_message_states_the_real_recovery(
        self, on_bundle: DepsBundle, ca_registrar: FakeCARegistrar
    ) -> None:
        """A failed registration says register manually or stage then complete again."""
        ca_registrar.fail = True

        async with _client(on_bundle) as client:
            complete = await _rotate(client)

        [message] = [e for e in complete.json()["errors"] if e.startswith("CA registration failed")]
        assert "register the new CA with Twingate manually" in message
        assert "phase='stage' then phase='complete'" in message
        assert "reconcile" not in message and "re-run" not in message
