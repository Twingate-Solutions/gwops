"""Registered public root on the tenant: registration, adoption, binding and rebind.

Drives ``Reconciler._ensure_certs`` (the step-3 entry) against the fake TG tenant with
``resolve_registered_root`` pinned to the committed ISRG Root X1. ``_materialize_public_tls``
(the certificate step, covered by ``test_public_certs.py``) is patched: to True for a passing
local step, or to a failing step that records a local error.
"""

import types
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from gwops.certs.public import RegisteredRootError
from gwops.configmodel.loader import load_effective_state
from gwops.reconciler import core
from gwops.reconciler.core import (
    DEFERRED_RATE_LIMITED,
    Reconciler,
    ReconcileResult,
    RegisteredRootStatus,
)
from gwops.renderer.capabilities import Capabilities
from gwops.renderer.render import RenderError
from gwops.tgapi.client import TGClient
from tests.public_tls_support import public_seed

from .conftest import FakeTGServer
from .public_certs_support import ROOT as GENERATED_ROOT
from .public_certs_support import PublicEnv, host
from .test_core import Env

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "tls"
ROOT = x509.load_pem_x509_certificate((_FIXTURES / "isrg-root-x1.pem").read_bytes())
ROOT_SHA = "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6"
ROOT_PEM = ROOT.public_bytes(serialization.Encoding.PEM).decode("ascii")
FOREIGN_SHA = "ab" * 32
NAME = "isrg_root_x1"
SSH_CA = "ca-s-known"
GATEWAY_ADDRESS = "gw.example.com:8443"


@pytest.fixture
def tg_client() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="test-key")


@pytest.fixture(autouse=True)
def _pin_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve the registered root to the committed ISRG Root X1, never the host's store."""
    monkeypatch.setattr(core, "resolve_registered_root", lambda name: ROOT)


def _certs_ok(monkeypatch: pytest.MonkeyPatch, value: bool = True) -> None:
    monkeypatch.setattr(
        Reconciler, "_materialize_public_tls", lambda self, state, result: value
    )


def _certs_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the certificate step fail the way a refused certificate does."""

    def _fail(self: Reconciler, state: object, result: ReconcileResult) -> bool:
        result.errors.append("public certificate 'wildcard': refused")
        return False

    monkeypatch.setattr(Reconciler, "_materialize_public_tls", _fail)


def _seed(*, mode_b: bool = False) -> str:
    twingate: dict[str, Any] = {"network": "acme"}
    if mode_b:
        twingate.update(remote_network="Prod DC", gateway_address=GATEWAY_ADDRESS)
    else:
        twingate["gateway_id"] = "g-1"
    return yaml.safe_dump(public_seed(twingate=twingate), sort_keys=False)


@dataclass
class Outcome:
    """What one ``_ensure_certs`` call returned and recorded."""

    certs_ok: bool
    leaf_changed: bool
    gateway_id: str | None
    result: ReconcileResult
    env: Env

    @property
    def root(self) -> RegisteredRootStatus | None:
        return self.result.registered_root


@pytest.fixture
def make_env(
    tmp_path: Path, gateway_binary: Callable[..., Path], tg_client: TGClient
) -> Callable[..., Env]:
    def _make(*, mode_b: bool = False, tg: TGClient | None | str = "client") -> Env:
        client = tg_client if tg == "client" else None
        env = Env(tmp_path, _seed(mode_b=mode_b), gateway_binary(), Capabilities(), client)
        env.registry.record("ca", "ssh", SSH_CA)  # keep SSH CA traffic out of these tests
        return env

    return _make


async def _step(env: Env, *, apply_ok: bool = True) -> Outcome:
    """One certificate step, then what `_run` does after apply: settle the pending rebind.

    The rebind is sent only when the certificate step passed and `apply_ok` (the pass's
    render and apply succeeded); otherwise it is deferred with that reason.
    """
    state, _provenance = load_effective_state(env.seed_path, env.store)
    result = ReconcileResult(ok=True, trigger="test", started_at=datetime.now(UTC))
    tg = env.reconciler._tg
    if tg is not None:
        tg.begin_pass()
        env.reconciler._pass_throttle_baseline = tg.write_throttle_count
    certs_ok, leaf_changed, _sans, gateway_id = await env.reconciler._ensure_certs(
        state, result
    )
    if not certs_ok:
        reason: str | None = "the local certificate step failed"
    elif not apply_ok:
        reason = "the config did not render and apply successfully this pass"
    else:
        reason = None
    await env.reconciler._settle_gateway_update(result, reason)
    return Outcome(certs_ok, leaf_changed, gateway_id, result, env)


def _updates(tg_server: FakeTGServer) -> list[dict[str, Any]]:
    return tg_server.gateway_bindings


class TestFirstRegistration:
    async def test_the_root_is_created_recorded_and_bound_to_a_gateway_on_a_foreign_ca(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        foreign = tg_server.add_x509_ca("gwops-x509-g-1", FOREIGN_SHA, "ca-foreign")
        tg_server.bind_gateway("g-1", foreign)
        env = make_env()

        out = await _step(env)

        assert (out.certs_ok, out.leaf_changed, out.gateway_id) == (True, False, "g-1")
        assert out.result.errors == []
        [created] = tg_server.created_x509_cas
        assert created == {"name": f"gwops-g-1-{NAME}", "certificate": ROOT_PEM}
        new_id = env.registry.managed_ids()["ca/x509-public"]
        assert tg_server.x509_cas[new_id][0] == f"gwops-g-1-{NAME}"
        assert _updates(tg_server) == [
            {"id": "g-1", "remoteNetworkId": "rn-1", "x509CAId": new_id}
        ]
        assert tg_server.gateway_x509["g-1"] == new_id
        assert (
            f"rebound gateway g-1 X.509 CA to registered public root {NAME} "
            f"({new_id}; was ca-foreign); the binding is read back on the next pass"
        ) in out.result.actions
        # The binding is read back on the next pass, never assumed after a rebind.
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, new_id, None)

    async def test_no_gwops_ca_or_leaf_is_ever_touched(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        env = make_env()

        def _forbidden(*args: object, **kwargs: object) -> None:
            raise AssertionError("public mode must not use the gwops X.509 CA or leaf")

        for attribute in ("ensure_x509_ca", "mint_leaf", "leaf_status"):
            monkeypatch.setattr(env.certs, attribute, _forbidden)

        out = await _step(env)

        assert out.result.errors == []
        assert "ca/x509" not in env.registry.managed_ids()
        assert not (env.paths.pki_dir / "x509-ca.crt").exists()


class TestRegistryHit:
    async def test_a_recorded_root_is_neither_searched_nor_created(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        known = tg_server.add_x509_ca("gwops-g-1-isrg_root_x1", ROOT_SHA, "ca-known")
        tg_server.bind_gateway("g-1", known)
        env = make_env()
        env.registry.record("ca", "x509-public", "ca-known")

        out = await _step(env)

        assert tg_server.calls == ["GetGatewayX509CA"]
        assert out.result.errors == []
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, "ca-known", True)

    async def test_a_recorded_root_is_revalidated_once_before_it_is_used_to_rebind(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.add_x509_ca("gwops-g-1-isrg_root_x1", ROOT_SHA, "ca-known")
        tg_server.add_x509_ca("gwops-x509-g-1", FOREIGN_SHA, "ca-foreign")
        tg_server.bind_gateway("g-1", "ca-foreign")
        env = make_env()
        env.registry.record("ca", "x509-public", "ca-known")

        out = await _step(env)

        assert tg_server.calls.count("FindX509CAsByFingerprint") == 1  # the re-validation
        assert "CreateX509CA" not in tg_server.calls
        assert _updates(tg_server)[0]["x509CAId"] == "ca-known"
        assert out.result.actions == [
            f"rebound gateway g-1 X.509 CA to registered public root {NAME} "
            "(ca-known; was ca-foreign); the binding is read back on the next pass"
        ]
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, "ca-known", None)

    async def test_a_recorded_root_deleted_on_the_tenant_is_forgotten_and_registered_again(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The registry id is not trusted for a write once the tenant no longer lists it."""
        _certs_ok(monkeypatch)
        tg_server.add_x509_ca("gwops-x509-g-1", FOREIGN_SHA, "ca-foreign")
        tg_server.bind_gateway("g-1", "ca-foreign")
        env = make_env()
        env.registry.record("ca", "x509-public", "ca-gone")  # not on the tenant

        out = await _step(env)

        new_id = env.registry.managed_ids()["ca/x509-public"]
        assert new_id not in ("ca-gone", "ca-foreign")
        assert tg_server.calls.count("CreateX509CA") == 1
        assert _updates(tg_server)[0]["x509CAId"] == new_id
        assert any(a.startswith("forgot recorded X.509 CA ca-gone") for a in out.result.actions)
        assert out.result.errors == []
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, new_id, None)

    async def test_a_stale_recorded_root_is_replaced_by_an_existing_ca_with_the_fingerprint(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.add_x509_ca("someone-elses-copy", ROOT_SHA, "ca-listed")
        tg_server.add_x509_ca("gwops-x509-g-1", FOREIGN_SHA, "ca-foreign")
        tg_server.bind_gateway("g-1", "ca-foreign")
        env = make_env()
        env.registry.record("ca", "x509-public", "ca-gone")

        out = await _step(env)

        assert "CreateX509CA" not in tg_server.calls
        assert env.registry.managed_ids()["ca/x509-public"] == "ca-listed"
        assert _updates(tg_server)[0]["x509CAId"] == "ca-listed"
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, "ca-listed", None)

    async def test_a_stale_recorded_root_is_not_used_to_create_a_mode_b_gateway(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        env = make_env(mode_b=True)
        env.registry.record("ca", "x509-public", "ca-gone")

        await _step(env)

        [created] = tg_server.created_gateways
        assert created["x509CAId"] not in ("ca-gone", "")
        assert created["x509CAId"] == env.registry.managed_ids()["ca/x509-public"]

    async def test_a_bound_gateway_with_a_recorded_root_costs_no_validation_read(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No write is about to happen, so the recorded id is left alone even if it is stale."""
        _certs_ok(monkeypatch)
        tg_server.add_x509_ca("by-hand", ROOT_SHA, "ca-bound")
        tg_server.bind_gateway("g-1", "ca-bound")
        env = make_env()
        env.registry.record("ca", "x509-public", "ca-recorded")

        out = await _step(env)

        assert tg_server.calls == ["GetGatewayX509CA"]
        assert env.registry.managed_ids()["ca/x509-public"] == "ca-recorded"
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, "ca-recorded", True)

    async def test_a_validation_read_failure_is_a_tg_error_that_uses_the_recorded_id_for_nothing(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.add_x509_ca("gwops-x509-g-1", FOREIGN_SHA, "ca-foreign")
        tg_server.bind_gateway("g-1", "ca-foreign")
        tg_server.fail_ops = {"FindX509CAsByFingerprint"}
        env = make_env()
        env.registry.record("ca", "x509-public", "ca-known")

        out = await _step(env)

        [error] = out.result.errors
        assert error.startswith("CA registration:")
        assert _updates(tg_server) == []
        assert env.registry.managed_ids()["ca/x509-public"] == "ca-known"
        assert out.certs_ok is True

    async def test_the_binding_is_read_on_every_pass(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.add_x509_ca("gwops-g-1-isrg_root_x1", ROOT_SHA, "ca-known")
        tg_server.bind_gateway("g-1", "ca-known")
        env = make_env()
        env.registry.record("ca", "x509-public", "ca-known")

        await _step(env)
        await _step(env)

        assert tg_server.calls == ["GetGatewayX509CA", "GetGatewayX509CA"]


class TestAdoptByFingerprint:
    async def test_an_existing_ca_with_the_roots_fingerprint_is_adopted_not_created(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.add_x509_ca("gwops-x509-g-1", FOREIGN_SHA, "ca-foreign")
        tg_server.add_x509_ca("someone-elses-copy", ROOT_SHA, "ca-listed")
        tg_server.bind_gateway("g-1", "ca-foreign")
        env = make_env()

        out = await _step(env)

        assert "CreateX509CA" not in tg_server.calls
        assert env.registry.managed_ids()["ca/x509-public"] == "ca-listed"
        assert _updates(tg_server)[0]["x509CAId"] == "ca-listed"
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, "ca-listed", None)

    async def test_the_first_listed_match_wins_when_several_cas_share_the_fingerprint(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.add_x509_ca("first", ROOT_SHA, "ca-first")
        tg_server.add_x509_ca("second", ROOT_SHA, "ca-second")
        env = make_env()

        out = await _step(env)

        assert out.root is not None and out.root.tg_ca_id == "ca-first"

    async def test_a_gateway_already_bound_to_an_equivalent_ca_adopts_it_with_no_extra_read(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.add_x509_ca("by-hand", ROOT_SHA, "ca-by-hand")
        tg_server.bind_gateway("g-1", "ca-by-hand")
        env = make_env()  # empty registry

        out = await _step(env)

        assert tg_server.calls == ["GetGatewayX509CA"]
        assert env.registry.managed_ids()["ca/x509-public"] == "ca-by-hand"
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, "ca-by-hand", True)
        assert out.result.errors == []

    async def test_a_failed_create_is_followed_by_one_more_search_and_adopts_the_result(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.fail_ops = {"CreateX509CA"}
        search = AsyncMock(side_effect=[[], ["ca-late"]])
        monkeypatch.setattr(core.ops, "find_x509_ca_ids_by_fingerprint", search)
        env = make_env()

        out = await _step(env)

        assert search.await_count == 2
        assert out.result.errors == []
        assert env.registry.managed_ids()["ca/x509-public"] == "ca-late"
        assert _updates(tg_server)[0]["x509CAId"] == "ca-late"
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, "ca-late", None)

    async def test_a_failed_create_with_nothing_found_is_a_tg_error_and_registers_nothing(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.fail_ops = {"CreateX509CA"}
        env = make_env()

        out = await _step(env)

        assert tg_server.calls.count("FindX509CAsByFingerprint") == 2
        [error] = out.result.errors
        assert error.startswith("CA registration:") and "CreateX509CA" in error
        assert "ca/x509-public" not in env.registry.managed_ids()
        assert _updates(tg_server) == []
        assert out.certs_ok is True  # a TG-side failure never fails the local steps
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, None, False)


class TestRebindGate:
    async def test_the_rebind_is_skipped_when_the_local_step_failed(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_fail(monkeypatch)
        tg_server.add_x509_ca("gwops-x509-g-1", FOREIGN_SHA, "ca-foreign")
        tg_server.bind_gateway("g-1", "ca-foreign")
        env = make_env()

        out = await _step(env)

        assert out.certs_ok is False
        assert out.result.errors == ["public certificate 'wildcard': refused"]
        assert "UpdateGateway" not in tg_server.calls
        assert tg_server.gateway_x509["g-1"] == "ca-foreign"
        [deferred] = [a for a in out.result.actions if "deferred rebinding" in a]
        assert "local certificate step failed" in deferred
        # The root is still registered, so the pass that does succeed can rebind at once.
        new_id = env.registry.managed_ids()["ca/x509-public"]
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, new_id, False)

    async def test_a_full_pass_with_a_failing_certificate_step_is_a_local_failure_without_tg_errors(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_client: TGClient,
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_fail(monkeypatch)
        env = Env(tmp_path, _seed(), gateway_binary(), Capabilities(), tg_client)
        env.registry.record("ca", "ssh", SSH_CA)
        tg_server.bind_gateway("g-1", tg_server.add_x509_ca("c", FOREIGN_SHA, "ca-foreign"))

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        assert "public certificate 'wildcard': refused" in result.errors
        assert not [e for e in result.errors if e.startswith("CA registration")]
        assert "UpdateGateway" not in tg_server.calls
        assert result.registered_root is not None
        assert result.registered_root.bound is False
        assert not env.config_path.exists()  # nothing rendered or applied


class TestModeB:
    async def test_the_gateway_is_created_bound_to_the_root_even_when_the_local_step_failed(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_fail(monkeypatch)
        env = make_env(mode_b=True)

        out = await _step(env)

        assert out.certs_ok is False
        root_id = env.registry.managed_ids()["ca/x509-public"]
        [created] = tg_server.created_gateways
        assert created["x509CAId"] == root_id
        assert created["sshCAId"] == SSH_CA
        assert created["address"] == GATEWAY_ADDRESS
        assert tg_server.x509_cas[root_id][0] == f"gwops-{GATEWAY_ADDRESS}-{NAME}"
        gateway_id = out.gateway_id
        assert gateway_id is not None
        assert env.registry.managed_ids()["gateway/self"] == gateway_id
        assert "UpdateGateway" not in tg_server.calls
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, root_id, True)

    async def test_an_adopted_gateway_on_a_foreign_ca_is_rebound_when_the_local_step_passed(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.add_x509_ca("gwops-x509-old", FOREIGN_SHA, "ca-foreign")
        tg_server.add_gateway(GATEWAY_ADDRESS, "gw-existing")
        tg_server.bind_gateway("gw-existing", "ca-foreign")
        env = make_env(mode_b=True)

        out = await _step(env)

        assert out.gateway_id == "gw-existing"
        assert tg_server.created_gateways == []
        assert env.registry.managed_ids()["gateway/self"] == "gw-existing"
        root_id = env.registry.managed_ids()["ca/x509-public"]
        assert _updates(tg_server)[0]["id"] == "gw-existing"
        assert _updates(tg_server)[0]["x509CAId"] == root_id
        assert any(a.startswith("adopted existing gateway") for a in out.result.actions)
        assert (
            f"rebound gateway gw-existing X.509 CA to registered public root {NAME} "
            f"({root_id}; was ca-foreign); the binding is read back on the next pass"
        ) in out.result.actions
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, root_id, None)

    async def test_an_adopted_gateway_is_not_rebound_when_the_local_step_failed(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_fail(monkeypatch)
        tg_server.add_x509_ca("gwops-x509-old", FOREIGN_SHA, "ca-foreign")
        tg_server.add_gateway(GATEWAY_ADDRESS, "gw-existing")
        tg_server.bind_gateway("gw-existing", "ca-foreign")
        env = make_env(mode_b=True)

        out = await _step(env)

        assert out.gateway_id == "gw-existing"
        assert "UpdateGateway" not in tg_server.calls
        assert out.root is not None and out.root.bound is False

    async def test_a_new_ssh_ca_is_bound_in_the_same_update_as_the_rebind(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_client: TGClient,
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.add_x509_ca("gwops-x509-old", FOREIGN_SHA, "ca-foreign")
        tg_server.bind_gateway("g-1", "ca-foreign")
        env = Env(tmp_path, _seed(), gateway_binary(), Capabilities(), tg_client)  # no ca/ssh

        out = await _step(env)

        assert out.result.errors == []
        [update] = _updates(tg_server)
        assert update["x509CAId"] == env.registry.managed_ids()["ca/x509-public"]
        assert update["sshCAId"] == env.registry.managed_ids()["ca/ssh"]
        assert tg_server.calls.count("CreateSSHCA") == 1


class TestTenantFailures:
    async def test_a_tenant_outage_is_a_tg_error_and_the_local_step_still_passes(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.fail = True
        env = make_env()

        out = await _step(env)

        assert out.certs_ok is True
        assert out.gateway_id == "g-1"
        [error] = out.result.errors
        assert error.startswith("CA registration:")
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, None, None)

    async def test_an_outage_keeps_the_recorded_ca_id_in_the_status(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.fail = True
        env = make_env()
        env.registry.record("ca", "x509-public", "ca-known")

        out = await _step(env)

        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, "ca-known", None)

    async def test_a_failed_rebind_is_a_tg_error_with_bound_false(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.add_x509_ca("by-hand", ROOT_SHA, "ca-known")
        tg_server.add_x509_ca("old", FOREIGN_SHA, "ca-foreign")
        tg_server.bind_gateway("g-1", "ca-foreign")
        tg_server.fail_ops = {"UpdateGateway"}
        env = make_env()

        out = await _step(env)

        assert out.certs_ok is True
        [error] = out.result.errors
        assert error.startswith("CA registration:") and "UpdateGateway" in error
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, "ca-known", False)
        assert not [a for a in out.result.actions if a.startswith("rebound")]

    async def test_a_binding_read_failure_is_a_tg_error_with_bound_none(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.fail_ops = {"GetGatewayX509CA"}
        env = make_env()

        out = await _step(env)

        [error] = out.result.errors
        assert error.startswith("CA registration:") and "g-1" in error
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, None, None)
        assert "CreateX509CA" not in tg_server.calls

    async def test_the_registration_errors_reach_the_status_tg_errors_filter(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.fail = True
        env = make_env()

        out = await _step(env)

        # The /status handler keeps errors starting with these prefixes (routes_state.py).
        assert all(e.startswith(("TG sync", "CA registration")) for e in out.result.errors)
        assert out.result.errors


class TestThrottledTenant:
    @pytest.fixture(autouse=True)
    def _client_sleep(self, monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
        fake_sleep = AsyncMock()
        monkeypatch.setattr(
            "gwops.tgapi.client.asyncio", types.SimpleNamespace(sleep=fake_sleep)
        )
        return fake_sleep

    async def test_a_throttled_create_defers_the_rebind_and_the_root_stays_recorded(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.add_x509_ca("old", FOREIGN_SHA, "ca-foreign")
        tg_server.bind_gateway("g-1", "ca-foreign")
        tg_server.throttle_ops = {"CreateX509CA": 1}
        env = make_env()

        out = await _step(env)

        assert tg_server.calls.count("CreateX509CA") == 2  # throttled once, then applied
        assert "UpdateGateway" not in tg_server.calls
        assert out.result.errors == [f"CA registration: {DEFERRED_RATE_LIMITED}"]
        created_id = env.registry.managed_ids()["ca/x509-public"]
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, created_id, False)
        assert out.certs_ok is True

    async def test_a_throttled_mode_b_create_is_deferred_and_the_gateway_stays_unresolved(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        tg_server.throttle_ops = {"CreateX509CA": 1}
        env = make_env(mode_b=True)

        out = await _step(env)

        assert tg_server.created_gateways == []
        assert out.gateway_id is None
        assert out.result.errors == [f"gateway create: {DEFERRED_RATE_LIMITED}"]
        assert "gateway/self" not in env.registry.managed_ids()
        assert "ca/x509-public" in env.registry.managed_ids()  # not created twice next pass


class TestWithoutApiKey:
    async def test_the_status_carries_the_root_with_nothing_known_from_the_tenant(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _certs_ok(monkeypatch)
        env = make_env(tg=None)

        out = await _step(env)

        assert out.certs_ok is True
        assert out.gateway_id == "g-1"  # the pinned id, so a later keyed pass syncs
        assert out.result.errors == []
        assert tg_server.calls == []
        assert out.root == RegisteredRootStatus(NAME, ROOT_SHA, None, None)


class TestRegisteredRootResolution:
    async def test_an_unresolvable_root_is_a_local_error_that_skips_everything_else(
        self,
        make_env: Callable[..., Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def _refuse(name: str) -> x509.Certificate:
            raise RegisteredRootError(f"registered root {name!r} is not in the trust store")

        monkeypatch.setattr(core, "resolve_registered_root", _refuse)
        called: list[str] = []
        monkeypatch.setattr(
            Reconciler,
            "_materialize_public_tls",
            lambda self, state, result: called.append("materialize") or True,
        )
        env = make_env()
        env.registry.record("gateway", "self", "gw-recorded")

        out = await _step(env)

        assert (out.certs_ok, out.leaf_changed, out.gateway_id) == (False, False, "gw-recorded")
        assert out.result.errors == [
            f"registered root: registered root {NAME!r} is not in the trust store"
        ]
        assert called == []
        assert tg_server.calls == []
        assert out.root is None


def _raise_render_error(*args: object, **kwargs: object) -> str:
    raise RenderError("simulated render failure")


ROOT_SHA_OF_GENERATED = GENERATED_ROOT.fingerprint(hashes.SHA256()).hex()


class TestRebindAfterApply:
    """M1/F1: the rebind is sent only after the pass rendered and applied its config."""

    @pytest.fixture
    def pub(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_client: TGClient,
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> PublicEnv:
        """A public-mode reconciler with real material and a tenant, gateway bound elsewhere."""
        monkeypatch.setattr(core, "resolve_registered_root", lambda name: GENERATED_ROOT)
        env = PublicEnv(tmp_path, gateway_binary(), {"alpha": [host("alpha")]})
        env.write_all()
        env.env.reconciler._tg = tg_client
        env.env.registry.record("ca", "ssh", SSH_CA)
        tg_server.add_x509_ca("gwops-x509-g-1", FOREIGN_SHA, "ca-foreign")
        tg_server.bind_gateway("g-1", "ca-foreign")
        return env

    async def test_the_rebind_is_sent_after_the_config_is_written_and_the_gateway_started(
        self,
        pub: PublicEnv,
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seen: list[tuple[bool, list[str]]] = []
        real_update = core.ops.update_gateway

        async def _spy(*args: Any, **kwargs: Any) -> Any:
            seen.append((pub.env.config_path.is_file(), list(pub.env.process.calls)))
            return await real_update(*args, **kwargs)

        monkeypatch.setattr(core.ops, "update_gateway", _spy)

        result = await pub.run()

        assert result.local_ok is True
        assert seen == [(True, ["start"])]
        [update] = _updates(tg_server)
        assert update["x509CAId"] == pub.env.registry.managed_ids()["ca/x509-public"]
        [action] = [a for a in result.actions if a.startswith("rebound gateway")]
        assert action.endswith("the binding is read back on the next pass")
        assert result.registered_root is not None and result.registered_root.bound is None

    async def test_the_next_pass_reads_the_binding_back_and_sends_nothing_more(
        self, pub: PublicEnv, tg_server: FakeTGServer
    ) -> None:
        await pub.run()

        second = await pub.run()

        assert len(_updates(tg_server)) == 1
        assert second.registered_root is not None and second.registered_root.bound is True
        assert not [a for a in second.actions if "rebound" in a or "deferred" in a]

    async def test_a_render_failure_sends_no_update_gateway(
        self, pub: PublicEnv, tg_server: FakeTGServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(core, "render_gateway_config", _raise_render_error)

        result = await pub.run()

        assert result.local_ok is False
        assert any(e.startswith("render failed") for e in result.errors)
        assert "UpdateGateway" not in tg_server.calls
        assert tg_server.gateway_x509["g-1"] == "ca-foreign"
        [deferred] = [a for a in result.actions if a.startswith("deferred rebinding")]
        assert "did not render and apply" in deferred
        assert result.registered_root is not None and result.registered_root.bound is False
        assert not [e for e in result.errors if e.startswith("CA registration")]

    async def test_an_apply_failure_sends_no_update_gateway(
        self, pub: PublicEnv, tg_server: FakeTGServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _fail() -> None:
            raise RuntimeError("simulated start failure")

        monkeypatch.setattr(pub.env.process, "start", _fail)

        result = await pub.run()

        assert result.local_ok is False
        assert any(e.startswith("gateway start failed") for e in result.errors)
        assert "UpdateGateway" not in tg_server.calls
        assert any(a.startswith("deferred rebinding") for a in result.actions)

    async def test_the_rebind_goes_out_on_the_first_pass_that_applies(
        self, pub: PublicEnv, tg_server: FakeTGServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with monkeypatch.context() as patch:
            patch.setattr(core, "render_gateway_config", _raise_render_error)
            failed = await pub.run()
        assert "UpdateGateway" not in tg_server.calls
        assert failed.local_ok is False

        result = await pub.run()

        assert result.local_ok is True
        assert len(_updates(tg_server)) == 1

    async def test_a_held_down_pass_defers_the_rebind(
        self, pub: PublicEnv, tg_server: FakeTGServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(Reconciler, "_public_certs_missing", lambda self, state: True)

        result = await pub.run()

        assert "UpdateGateway" not in tg_server.calls
        [deferred] = [a for a in result.actions if a.startswith("deferred rebinding")]
        assert deferred.endswith("the gateway is held down")

    async def test_a_new_ssh_ca_is_still_bound_when_the_rebind_is_deferred(
        self, pub: PublicEnv, tg_server: FakeTGServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pub.env.registry.forget("ca", "ssh")  # a new SSH CA is created and must be bound
        monkeypatch.setattr(core, "render_gateway_config", _raise_render_error)

        result = await pub.run()

        [update] = _updates(tg_server)
        assert update["sshCAId"] == pub.env.registry.managed_ids()["ca/ssh"]
        assert "x509CAId" not in update  # the rebind itself waits
        assert tg_server.gateway_x509["g-1"] == "ca-foreign"
        assert any(a.startswith("deferred rebinding") for a in result.actions)
        assert any(a.startswith("registered SSH CA") for a in result.actions)

    async def test_a_new_ssh_ca_rides_along_in_the_one_update_when_the_pass_applies(
        self, pub: PublicEnv, tg_server: FakeTGServer
    ) -> None:
        pub.env.registry.forget("ca", "ssh")

        await pub.run()

        [update] = _updates(tg_server)
        assert update["x509CAId"] == pub.env.registry.managed_ids()["ca/x509-public"]
        assert update["sshCAId"] == pub.env.registry.managed_ids()["ca/ssh"]

    async def test_a_new_ssh_ca_alone_is_bound_at_once_when_no_rebind_is_due(
        self, pub: PublicEnv, tg_server: FakeTGServer
    ) -> None:
        pub.env.registry.forget("ca", "ssh")
        tg_server.bind_gateway(
            "g-1", tg_server.add_x509_ca("by-hand", ROOT_SHA_OF_GENERATED, "ca-bound")
        )

        await pub.run()

        [update] = _updates(tg_server)
        assert "x509CAId" not in update
        assert update["sshCAId"] == pub.env.registry.managed_ids()["ca/ssh"]

    async def test_a_throttled_earlier_write_defers_the_rebind_and_is_never_a_local_failure(
        self, pub: PublicEnv, tg_server: FakeTGServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "gwops.tgapi.client.asyncio", types.SimpleNamespace(sleep=AsyncMock())
        )
        pub.env.registry.forget("ca", "ssh")
        tg_server.throttle_ops = {"CreateSSHCA": 1}  # throttled once, which spends the write budget

        result = await pub.run()

        assert result.local_ok is True
        assert f"CA registration: {DEFERRED_RATE_LIMITED}" in result.errors
        assert "UpdateGateway" not in tg_server.calls
        assert tg_server.gateway_x509["g-1"] == "ca-foreign"
