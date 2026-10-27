"""Tests for gwops.reconciler.core: the level-triggered reconcile loop.

Covers the reconcile loop end to end against the fake TG tenant
(respx), the stub/real gateway process, and real on-disk state under tmp dirs:
declaring an upstream in the seed is sufficient; every failure path keeps the
gateway on its last good config and says why; unmanaged TG resources are never
touched; concurrent triggers coalesce.
"""

import asyncio
import dataclasses
import stat
import sys
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography import x509

from gwops.certs.manager import CertManager
from gwops.configmodel.store import OverlayStore
from gwops.reconciler import core
from gwops.reconciler.core import Reconciler, ReconcileResult, _restart_required_reasons
from gwops.reconciler.registry import StateRegistry
from gwops.renderer.capabilities import Capabilities
from gwops.renderer.render import RuntimePaths
from gwops.settings import GwopsSettings
from gwops.shipper.enrich import WebAppIndex
from gwops.supervisor.process import GatewayProcess, ProcState, last_good_path
from gwops.supervisor.spawn import SpawnOutcome, SpawnVerdict
from gwops.tgapi.client import TGClient
from tests.store_support import leaf_cert_path

from .conftest import FakeTGServer, StubProcess

_posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="requires POSIX signal semantics"
)

# The pre-flight spawns a real (fake) binary on every config-changing reconcile;
# a small timeout keeps the suite fast without waiting out the 5s production default.
_FAST_VALIDATE_TIMEOUT = 0.2

_SSH_SEED = """\
twingate:
  network: acme
  gateway_id: g-1
ssh_upstreams:
  - name: web-1
    address: 10.0.0.5:22
"""

_TWO_SSH_SEED = """\
twingate:
  network: acme
  gateway_id: g-1
ssh_upstreams:
  - name: web-1
    address: 10.0.0.5:22
  - name: web-2
    address: 10.0.0.6:22
"""

_EMPTY_SEED = """\
twingate:
  network: acme
  gateway_id: g-1
"""


@pytest.fixture
def tg_client() -> Iterator[TGClient]:
    client = TGClient(network="acme", api_key="test-key")
    yield client
    # Closed asynchronously by pytest-asyncio's loop via the test body if needed;
    # respx intercepts every request so no real connections are ever opened.


class Env:
    """One assembled reconciler environment over tmp dirs."""

    def __init__(
        self,
        tmp_path: Path,
        seed_text: str,
        binary: Path,
        caps: Capabilities,
        tg: TGClient | None,
        process: StubProcess | GatewayProcess | None = None,
        validate_timeout: float = _FAST_VALIDATE_TIMEOUT,
        webapp_index: WebAppIndex | None = None,
    ) -> None:
        self.seed_path = tmp_path / "seed.yaml"
        self.seed_path.write_text(seed_text, encoding="utf-8")
        self.settings = GwopsSettings(
            seed_path=self.seed_path,
            data_dir=tmp_path / "data",
            runtime_dir=tmp_path / "run",
            gateway_binary=binary,
        )
        # Point the confined source roots into the tmp tree.
        self.paths = dataclasses.replace(
            RuntimePaths.from_settings(self.settings),
            k8s_source_root=tmp_path / "k8s-creds-src",
            webapp_ca_root=tmp_path / "webapp-cas-src",
        )
        self.store = OverlayStore(self.settings.data_dir / "overlays")
        self.certs = CertManager(self.paths.pki_dir)
        self.registry = StateRegistry(self.settings.data_dir / "state.json")
        self.process = process if process is not None else StubProcess()
        self.reconciler = Reconciler(
            settings=self.settings,
            store=self.store,
            tg=tg,
            certs=self.certs,
            process=self.process,  # type: ignore[arg-type]
            registry=self.registry,
            caps=caps,
            validate_timeout_seconds=validate_timeout,
            paths=self.paths,
            webapp_index=webapp_index,
        )
        self.config_path = self.settings.runtime_dir / "config.yaml"

    def write_k8s_source(self, name: str, *, token: str, ca: str = "PEM") -> tuple[Path, Path]:
        """Write a cluster's source credential files under the confined root."""
        root = self.paths.k8s_source_root
        root.mkdir(parents=True, exist_ok=True)
        token_file = root / f"{name}.token"
        ca_file = root / f"{name}-ca.crt"
        token_file.write_text(token, encoding="utf-8")
        ca_file.write_text(ca, encoding="utf-8")
        return token_file, ca_file

    def rendered_k8s_files(self) -> tuple[Path, Path]:
        """The (token, CA) copy paths the rendered config currently references."""
        doc = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        [upstream] = doc["kubernetes"]["upstreams"]
        return Path(upstream["bearerTokenFile"]), Path(upstream["caFile"])

    def k8s_copies(self) -> list[str]:
        """Names of every file in the gwops-managed credential copy directory."""
        directory = self.paths.k8s_creds_dir
        return sorted(p.name for p in directory.iterdir()) if directory.is_dir() else []

    def add_k8s_cluster_overlay(self, name: str = "prod") -> None:
        token, ca = self.write_k8s_source(name, token="secret-token")
        self.store.add(
            {
                "k8s_clusters": [
                    {
                        "name": name,
                        "address": f"{name}.k8s.internal",
                        "port": 6443,
                        "bearer_token_file": token.as_posix(),
                        "ca_file": ca.as_posix(),
                    }
                ]
            },
            comment=f"add {name}",
        )


def _leaf_sans(pki_dir: Path) -> set[str]:
    pem = leaf_cert_path(pki_dir).read_bytes()
    cert = x509.load_pem_x509_certificate(pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return {str(v) for v in san.get_values_for_type(x509.DNSName)} | {
        str(v) for v in san.get_values_for_type(x509.IPAddress)
    }


class TestHappyPath:
    async def test_declaring_upstreams_in_seed_is_sufficient(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        env.add_k8s_cluster_overlay()

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []
        assert result.ok is True
        # TG sync: one ssh + one kubernetes resource, portless lowercase addresses.
        by_name = {r.name: r for r in tg_server.resources.values()}
        assert by_name["web-1"].kind == "ssh"
        assert by_name["web-1"].address == "10.0.0.5"
        assert by_name["web-1"].gateway_id == "g-1"
        assert by_name["prod"].kind == "kubernetes"
        assert by_name["prod"].address == "prod.k8s.internal"
        managed = env.registry.managed_ids()
        assert managed["ssh/web-1"] == by_name["web-1"].id
        assert managed["kubernetes/prod"] == by_name["prod"].id
        # Credentials materialized at the content-addressed paths the render references.
        token_copy, ca_copy = env.rendered_k8s_files()
        assert token_copy.read_text(encoding="utf-8") == "secret-token"
        assert ca_copy.read_text(encoding="utf-8") == "PEM"
        assert token_copy.parent == env.paths.k8s_creds_dir
        assert token_copy.name.startswith("prod-token-")
        assert ca_copy.name.startswith("prod-ca-") and ca_copy.suffix == ".crt"
        # Leaf covers both upstream addresses.
        assert _leaf_sans(env.paths.pki_dir) == {"10.0.0.5", "prod.k8s.internal"}
        # Rendered config on disk references the managed credential paths.
        doc = yaml.safe_load(env.config_path.read_text(encoding="utf-8"))
        [upstream] = doc["kubernetes"]["upstreams"]
        assert upstream["bearerTokenFile"] == token_copy.as_posix()
        # First-ever reconcile starts the process (instead of reload/restart).
        assert env.process.calls == ["start"]

    async def test_second_reconcile_is_a_quiet_noop(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        await env.reconciler.reconcile("startup")
        creates_before = [c for c in tg_server.calls if c.startswith("Create")]

        result = await env.reconciler.reconcile("tick")

        assert result.ok is True
        assert result.actions == []
        assert [c for c in tg_server.calls if c.startswith("Create")] == creates_before
        assert env.process.calls == ["start"]

    @_posix_only
    async def test_real_gateway_child_reaches_running(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        binary = gateway_binary()
        config_path = tmp_path / "run" / "config.yaml"
        process = GatewayProcess(
            binary, config_path, lambda _line: None, lambda _line: None
        )
        env = Env(tmp_path, _SSH_SEED, binary, Capabilities(), tg_client, process=process)
        try:
            result = await env.reconciler.reconcile("startup")
            assert result.ok is True
            assert process.state is ProcState.RUNNING
            assert env.config_path.is_file()
        finally:
            await process.stop(timeout=5.0)


class TestApplyChangeClasses:
    async def test_added_cluster_extends_sans_reminits_leaf_and_drain_restarts(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        # Note: a new *SSH upstream* is deliberately not a config change (the renderer
        # never emits ssh.upstreams; targets come from the synced TG resources), so the
        # config-changing case here is the first k8s cluster.
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        await env.reconciler.reconcile("startup")
        assert _leaf_sans(env.paths.pki_dir) == {"10.0.0.5"}

        env.add_k8s_cluster_overlay()
        result = await env.reconciler.reconcile("api")

        assert result.ok is True
        assert any(r.name == "prod" for r in tg_server.resources.values())
        assert _leaf_sans(env.paths.pki_dir) == {"10.0.0.5", "prod.k8s.internal"}
        assert "kubernetes" in yaml.safe_load(env.config_path.read_text(encoding="utf-8"))
        assert env.process.calls == ["start", "drain_restart"]

    async def test_restart_required_ssh_ca_change_drain_restarts(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        await env.reconciler.reconcile("startup")

        # The SSH CA key path is one of the two settings `_restart_required_reasons`
        # flags (it cannot change under a running daemon): switch from the
        # gwops-generated CA to a bring-your-own one at a different path.
        byo = CertManager(tmp_path / "byo")
        ssh_info = byo.ensure_ssh_ca(generate=True)
        env.store.add(
            {"ca": {"ssh": {"generate": False, "key_path": ssh_info.key_path.as_posix()}}},
            comment="byo ssh ca",
        )
        result = await env.reconciler.reconcile("api")

        assert result.ok is True
        assert env.process.calls == ["start", "drain_restart"]
        assert any("SSH CA key path changed" in a for a in result.actions)

    async def test_leaf_only_change_needs_no_gateway_action(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        await env.reconciler.reconcile("startup")

        # Simulate an expired/rotated-away leaf: the file disappears, config is
        # otherwise unchanged. The gateway hot-reloads cert files by itself.
        leaf_cert_path(env.paths.pki_dir).unlink()
        result = await env.reconciler.reconcile("tick")

        assert result.ok is True
        assert leaf_cert_path(env.paths.pki_dir).is_file()
        assert env.process.calls == ["start"]  # no reload, no restart
        assert any("leaf" in action for action in result.actions)


class TestRestartRequiredReasons:
    """`_restart_required_reasons` reads the SSH CA key path at `ssh.ca.local`, where the
    renderer writes it, so an SSH-CA change triggers a drain-restart."""

    def test_ssh_ca_local_change_is_detected(self) -> None:
        old_text = "port: 8443\nssh:\n  ca:\n    local:\n      privateKeyFile: /a\n"
        new_text = "port: 8443\nssh:\n  ca:\n    local:\n      privateKeyFile: /b\n"

        reasons = _restart_required_reasons(old_text, new_text)

        assert any("SSH CA key path changed" in r for r in reasons)

    def test_unchanged_ssh_ca_and_port_yield_no_reasons(self) -> None:
        text = "port: 8443\nssh:\n  ca:\n    local:\n      privateKeyFile: /a\n"

        assert _restart_required_reasons(text, text) == []

    def test_port_change_is_detected(self) -> None:
        reasons = _restart_required_reasons("port: 8443\n", "port: 9443\n")

        assert any("listener port changed" in r for r in reasons)

    def test_other_ca_key_names_are_not_read(self) -> None:
        # Only `ssh.ca.local` is read; a change under any other key is not an SSH CA
        # path change.
        old_text = "port: 8443\nssh:\n  ca:\n    other:\n      privateKeyFile: /a\n"
        new_text = "port: 8443\nssh:\n  ca:\n    other:\n      privateKeyFile: /b\n"

        reasons = _restart_required_reasons(old_text, new_text)

        assert not any("SSH CA key path changed" in r for r in reasons)


class TestTGFailureIsNotLocalFailure:
    async def test_tg_down_still_applies_local_steps_and_recovers_next_run(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        tg_server.fail = True
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)

        result = await env.reconciler.reconcile("startup")

        # Remote sync failed loudly...
        assert result.ok is False
        assert any("TG" in e or "sync" in e for e in result.errors)
        assert tg_server.resources == {}
        # ...but local correctness won: leaf minted, config written, gateway started.
        assert leaf_cert_path(env.paths.pki_dir).is_file()
        assert env.config_path.is_file()
        assert env.process.calls == ["start"]

        # Next tick with the tenant back: the same declaration syncs cleanly.
        tg_server.fail = False
        result = await env.reconciler.reconcile("tick")
        assert result.ok is True
        assert any(r.name == "web-1" for r in tg_server.resources.values())
        assert "ssh/web-1" in env.registry.managed_ids()

    async def test_no_api_key_records_error_and_continues(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
    ) -> None:
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg=None)
        result = await env.reconciler.reconcile("startup")
        assert result.ok is False
        assert any("TWINGATE_API_KEY" in e for e in result.errors)
        assert env.process.calls == ["start"]


class TestValidateFailureKeepsOldConfig:
    async def test_rejected_render_is_never_applied(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        good_binary = gateway_binary()
        env = Env(tmp_path, _SSH_SEED, good_binary, Capabilities(), tg_client)
        await env.reconciler.reconcile("startup")
        old_config = env.config_path.read_text(encoding="utf-8")

        # Same dirs, but the binary now rejects every candidate config.
        # A rejecting binary exits on its own; the long timeout only stops a slow
        # interpreter start being read as "still running, so valid".
        bad_binary = gateway_binary(reject=True)
        env2 = Env(
            tmp_path, _SSH_SEED, bad_binary, Capabilities(), tg_client, validate_timeout=10.0
        )
        env2.process.state = ProcState.RUNNING  # gateway already up on old config
        env2.add_k8s_cluster_overlay()  # a real config-content change
        result = await env2.reconciler.reconcile("api")

        assert result.ok is False
        assert any("validat" in e.lower() for e in result.errors)
        assert result.local_ok is False  # a schema break is a local failure
        assert env2.config_path.read_text(encoding="utf-8") == old_config
        assert env2.process.calls == []  # neither reloaded nor restarted

    async def test_non_schema_startup_failure_is_applied(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A pre-flight spawn that fails to *start* without a schema-break marker (the
        # canonical case: the candidate can't bind :8443 because the LIVE gateway still
        # holds it — EADDRINUSE) must NOT block the config change. Rejecting it would
        # reject every legitimate config change made while the gateway is up.
        good_binary = gateway_binary()
        env = Env(tmp_path, _SSH_SEED, good_binary, Capabilities(), tg_client)
        await env.reconciler.reconcile("startup")
        old_config = env.config_path.read_text(encoding="utf-8")

        env2 = Env(tmp_path, _SSH_SEED, good_binary, Capabilities(), tg_client)
        env2.process.state = ProcState.RUNNING  # gateway already up, holding its ports

        async def _bind_failure(*_args: object, **_kwargs: object) -> SpawnOutcome:
            return SpawnOutcome(
                verdict=SpawnVerdict.REJECTED,
                stderr_text="listen tcp :8443: bind: address already in use",
            )

        monkeypatch.setattr(core, "validate_config_by_spawn", _bind_failure)
        env2.add_k8s_cluster_overlay()  # a real config-content change
        result = await env2.reconciler.reconcile("api")

        # The change is applied (config swapped, gateway drain-restarted), not rejected.
        assert env2.config_path.read_text(encoding="utf-8") != old_config
        assert "drain_restart" in env2.process.calls
        assert not any("validat" in e.lower() for e in result.errors)

    async def test_stopped_gateway_rejects_non_healthy_preflight(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # When the gateway is NOT running the ports are free, so the pre-flight is
        # authoritative: a candidate that fails to start (even without a schema marker) is
        # rejected and the previous config kept — this is what lets a rollback recover to
        # last-good instead of re-applying a valid-but-unstartable config.
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        await env.reconciler.reconcile("startup")
        old_config = env.config_path.read_text(encoding="utf-8")

        env2 = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        env2.process.state = ProcState.STOPPED  # ports free -> pre-flight authoritative

        async def _runtime_failure(*_a: object, **_k: object) -> SpawnOutcome:
            return SpawnOutcome(
                verdict=SpawnVerdict.REJECTED, stderr_text="failed to create proxy: bad cert"
            )

        monkeypatch.setattr(core, "validate_config_by_spawn", _runtime_failure)
        env2.add_k8s_cluster_overlay()
        result = await env2.reconciler.reconcile("api")

        assert env2.config_path.read_text(encoding="utf-8") == old_config  # kept previous
        assert result.local_ok is False

    async def test_rolled_back_config_is_not_reapplied(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        # A config the supervisor rolled back after a failed start must not be re-applied,
        # or the gateway flaps every reconcile. The reconciler compares the render against
        # process.last_rolled_back_config and refuses.
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        await env.reconciler.reconcile("startup")
        rendered_text = env.config_path.read_text(encoding="utf-8")

        # On-disk differs from the desired render (simulating a restored last-good), and
        # the desired render equals what was rolled back.
        env.config_path.write_text(rendered_text + "\n# restored last-good\n", encoding="utf-8")
        env.process.last_rolled_back_config = rendered_text
        env.process.state = ProcState.RUNNING
        result = await env.reconciler.reconcile("tick")

        assert env.config_path.read_text(encoding="utf-8").endswith("# restored last-good\n")
        assert result.local_ok is False
        assert any("rolled back" in e for e in result.errors)
        assert "drain_restart" not in env.process.calls


class TestKubernetesCredentials:
    """Credential sources are confined to /config/k8s-creds; copies are content-addressed."""

    @staticmethod
    def _env(tmp_path: Path, binary: Path, tg_client: TGClient) -> Env:
        return Env(tmp_path, _SSH_SEED, binary, Capabilities(), tg_client)

    @staticmethod
    def _overlay(env: Env, *, token: Path, ca: Path, name: str = "prod") -> None:
        env.store.add(
            {
                "k8s_clusters": [
                    {
                        "name": name,
                        "address": f"{name}.k8s.internal",
                        "port": 6443,
                        "bearer_token_file": token.as_posix(),
                        "ca_file": ca.as_posix(),
                    }
                ]
            },
            comment=f"add {name}",
        )

    async def test_token_outside_the_root_fails_loud_naming_the_root(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = self._env(tmp_path, gateway_binary(), tg_client)
        await env.reconciler.reconcile("startup")
        # A CA private key must never be copied out as a cluster bearer token.
        ca_key = env.paths.pki_dir / "x509-ca.key"
        assert ca_key.is_file()
        _token, ca = env.write_k8s_source("prod", token="unused")
        self._overlay(env, token=ca_key, ca=ca)
        old_config = env.config_path.read_text(encoding="utf-8")

        result = await env.reconciler.reconcile("api")

        assert result.local_ok is False
        [error] = [e for e in result.errors if "bearer_token_file" in e]
        assert "prod" in error
        assert str(env.paths.k8s_source_root) in error
        assert ca_key.name in error
        assert "outside" in error
        # Nothing copied, config untouched.
        assert env.k8s_copies() == []
        assert env.config_path.read_text(encoding="utf-8") == old_config

    async def test_ca_outside_the_root_fails_loud_naming_the_root(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = self._env(tmp_path, gateway_binary(), tg_client)
        token, _ca = env.write_k8s_source("prod", token="t")
        stray = tmp_path / "stray-ca.crt"
        stray.write_text("PEM", encoding="utf-8")
        self._overlay(env, token=token, ca=stray)

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        [error] = [e for e in result.errors if "ca_file" in e]
        assert str(env.paths.k8s_source_root) in error
        assert env.k8s_copies() == []

    async def test_dotdot_traversal_out_of_the_root_is_refused(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = self._env(tmp_path, gateway_binary(), tg_client)
        _token, ca = env.write_k8s_source("prod", token="t")
        (tmp_path / "outside.token").write_text("stolen", encoding="utf-8")
        traversal = env.paths.k8s_source_root / ".." / "outside.token"
        self._overlay(env, token=traversal, ca=ca)

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        assert any("bearer_token_file" in e and "outside" in e for e in result.errors)
        assert not any("stolen" in e for e in result.errors)
        assert env.k8s_copies() == []

    async def test_an_oversized_credential_is_refused_without_echoing_contents(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = self._env(tmp_path, gateway_binary(), tg_client)
        token, ca = env.write_k8s_source("prod", token="X" * (1024 * 1024 + 1))
        self._overlay(env, token=token, ca=ca)

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        assert any("size limit" in e for e in result.errors)
        assert not any("XXXX" in e for e in result.errors)

    async def test_copies_are_content_addressed_with_the_documented_modes(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = self._env(tmp_path, gateway_binary(), tg_client)
        env.add_k8s_cluster_overlay()

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []
        token_copy, ca_copy = env.rendered_k8s_files()
        assert env.k8s_copies() == sorted([token_copy.name, ca_copy.name])
        assert any(
            a.startswith("materialized credential") and "prod" in a for a in result.actions
        )
        if sys.platform != "win32":
            assert stat.S_IMODE(token_copy.stat().st_mode) == 0o600
            assert stat.S_IMODE(ca_copy.stat().st_mode) == 0o644

    async def test_unchanged_credentials_make_no_new_copy_and_no_action(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = self._env(tmp_path, gateway_binary(), tg_client)
        env.add_k8s_cluster_overlay()
        await env.reconciler.reconcile("startup")
        before = env.k8s_copies()

        result = await env.reconciler.reconcile("tick")

        assert result.ok is True
        assert result.actions == []
        assert env.k8s_copies() == before

    async def test_changed_cluster_ca_changes_the_rendered_path_and_restarts_the_gateway(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = self._env(tmp_path, gateway_binary(), tg_client)
        env.add_k8s_cluster_overlay()
        await env.reconciler.reconcile("startup")
        _token_v1, ca_v1 = env.rendered_k8s_files()
        assert env.process.calls == ["start"]

        (env.paths.k8s_source_root / "prod-ca.crt").write_text("PEM-ROTATED", encoding="utf-8")
        result = await env.reconciler.reconcile("tick")

        assert result.ok is True
        _token_v2, ca_v2 = env.rendered_k8s_files()
        assert ca_v2 != ca_v1
        assert ca_v2.read_text(encoding="utf-8") == "PEM-ROTATED"
        assert env.process.calls == ["start", "drain_restart"]

    async def test_changed_token_changes_the_rendered_path(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = self._env(tmp_path, gateway_binary(), tg_client)
        env.add_k8s_cluster_overlay()
        await env.reconciler.reconcile("startup")
        token_v1, _ca = env.rendered_k8s_files()

        (env.paths.k8s_source_root / "prod.token").write_text("rotated", encoding="utf-8")
        await env.reconciler.reconcile("tick")

        token_v2, _ca = env.rendered_k8s_files()
        assert token_v2 != token_v1
        assert token_v2.read_text(encoding="utf-8") == "rotated"
        assert env.process.calls == ["start", "drain_restart"]

    async def test_superseded_copy_is_removed_once_neither_config_references_it(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = self._env(tmp_path, gateway_binary(), tg_client)
        env.add_k8s_cluster_overlay()
        await env.reconciler.reconcile("startup")
        _token_v1, ca_v1 = env.rendered_k8s_files()

        (env.paths.k8s_source_root / "prod-ca.crt").write_text("PEM-ROTATED", encoding="utf-8")
        result = await env.reconciler.reconcile("tick")

        # StubProcess writes no last-good sidecar, so only config.yaml references copies.
        assert not ca_v1.exists()
        assert any("removed unreferenced" in a and ca_v1.name in a for a in result.actions)
        token_copy, ca_copy = env.rendered_k8s_files()
        assert env.k8s_copies() == sorted([token_copy.name, ca_copy.name])

    async def test_copy_referenced_only_by_last_good_survives_gc(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = self._env(tmp_path, gateway_binary(), tg_client)
        env.add_k8s_cluster_overlay()
        await env.reconciler.reconcile("startup")
        _token_v1, ca_v1 = env.rendered_k8s_files()
        # The supervisor promotes the running config to the last-good sidecar.
        sidecar = last_good_path(env.config_path)
        sidecar.write_text(env.config_path.read_text(encoding="utf-8"), encoding="utf-8")

        (env.paths.k8s_source_root / "prod-ca.crt").write_text("PEM-ROTATED", encoding="utf-8")
        result = await env.reconciler.reconcile("tick")

        assert result.ok is True
        assert ca_v1.is_file()  # the rollback target still needs it
        _token_v2, ca_v2 = env.rendered_k8s_files()
        assert ca_v2.is_file()

    async def test_gc_leaves_unrelated_files_and_waits_for_a_successful_pass(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = self._env(tmp_path, gateway_binary(), tg_client)
        env.add_k8s_cluster_overlay()
        await env.reconciler.reconcile("startup")
        stale = env.paths.k8s_creds_dir / "gone-token-0123456789ab"
        stale.write_text("old", encoding="utf-8")
        unrelated = env.paths.k8s_creds_dir / "README"
        unrelated.write_text("keep", encoding="utf-8")

        # A pass that fails locally never reaches the post-apply GC.
        (env.paths.k8s_source_root / "prod.token").unlink()
        failed = await env.reconciler.reconcile("tick")
        assert failed.local_ok is False
        assert stale.is_file()

        (env.paths.k8s_source_root / "prod.token").write_text("secret-token", encoding="utf-8")
        recovered = await env.reconciler.reconcile("tick")

        assert recovered.ok is True
        assert not stale.exists()
        assert unrelated.read_text(encoding="utf-8") == "keep"

    async def test_removing_the_cluster_collects_its_copies(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = self._env(tmp_path, gateway_binary(), tg_client)
        env.add_k8s_cluster_overlay()
        await env.reconciler.reconcile("startup")
        assert env.k8s_copies()

        env.store.add({"k8s_clusters": [{"name": "prod", "_delete": True}]}, comment="drop prod")
        result = await env.reconciler.reconcile("api")

        assert result.ok is True
        assert env.k8s_copies() == []

    async def test_secret_contents_never_reach_errors_or_actions(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = self._env(tmp_path, gateway_binary(), tg_client)
        env.add_k8s_cluster_overlay()  # token contents: "secret-token"

        result = await env.reconciler.reconcile("startup")

        assert "secret-token" not in " ".join(result.actions + result.errors)


class TestUnmanagedResourcesAreNeverTouched:
    async def test_stranger_resources_survive_sync_untouched(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        # A stranger with an unrelated name, and one squatting on a desired name
        # with a different address — neither is in the registry, so neither may
        # ever be updated or deleted.
        stranger_id = tg_server.add_resource("ssh", "someone-elses", "10.99.0.1", "g-9")
        squatter_id = tg_server.add_resource("ssh", "web-1", "10.99.0.2", "g-1")

        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        result = await env.reconciler.reconcile("startup")

        assert result.ok is True
        assert tg_server.resources[stranger_id].address == "10.99.0.1"
        assert tg_server.resources[squatter_id].address == "10.99.0.2"
        assert "UpdateResourceAddress" not in tg_server.calls
        assert "DeleteResource" not in tg_server.calls
        # gwops created its own resource for web-1 rather than adopting the squatter.
        assert env.registry.managed_ids()["ssh/web-1"] not in (stranger_id, squatter_id)

    async def test_removed_upstream_deletes_only_the_managed_object(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        stranger_id = tg_server.add_resource("ssh", "someone-elses", "10.99.0.1", "g-9")
        env = Env(tmp_path, _TWO_SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        await env.reconciler.reconcile("startup")
        web2_id = env.registry.managed_ids()["ssh/web-2"]

        env.seed_path.write_text(_SSH_SEED, encoding="utf-8")  # web-2 removed
        result = await env.reconciler.reconcile("seed-change")

        assert result.ok is True
        assert web2_id not in tg_server.resources
        assert "ssh/web-2" not in env.registry.managed_ids()
        assert stranger_id in tg_server.resources  # the stranger is still there
        assert "ssh/web-1" in env.registry.managed_ids()

    async def test_drifted_address_of_managed_resource_is_corrected(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        await env.reconciler.reconcile("startup")
        web1_id = env.registry.managed_ids()["ssh/web-1"]

        tg_server.resources[web1_id].address = "10.9.9.9"  # drift on the TG side
        result = await env.reconciler.reconcile("tick")

        assert result.ok is True
        assert tg_server.resources[web1_id].address == "10.0.0.5"


_SSH_2222_SEED = """\
twingate:
  network: acme
  gateway_id: g-1
ssh_upstreams:
  - name: web-1
    address: 10.0.0.5:2222
  - name: web-2
    address: 10.0.0.6
"""


class TestUpstreamPortSync:
    """The gateway dials the TG resource's ``upstream.port``, so gwops owns it."""

    async def test_creates_resources_with_declared_upstream_ports(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = Env(tmp_path, _SSH_2222_SEED, gateway_binary(), Capabilities(), tg_client)
        env.add_k8s_cluster_overlay()  # port: 6443

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []
        by_name = {r.name: r for r in tg_server.resources.values()}
        assert by_name["web-1"].address == "10.0.0.5"
        assert by_name["web-1"].upstream_port == 2222
        assert by_name["web-2"].upstream_port == 22
        assert by_name["prod"].address == "prod.k8s.internal"
        assert by_name["prod"].upstream_port == 6443

    async def test_drifted_upstream_port_is_corrected(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        env.add_k8s_cluster_overlay()
        await env.reconciler.reconcile("startup")
        managed = env.registry.managed_ids()
        web1_id, prod_id = managed["ssh/web-1"], managed["kubernetes/prod"]

        # The live failure: the k8s resource reverted to 443 on the TG side.
        tg_server.resources[prod_id].upstream_port = 443
        tg_server.resources[web1_id].upstream_port = 2200
        result = await env.reconciler.reconcile("tick")

        assert result.ok is True
        assert tg_server.resources[prod_id].upstream_port == 6443
        assert tg_server.resources[web1_id].upstream_port == 22
        assert "updated kubernetes resource 'prod' upstream port 443 -> 6443" in result.actions
        assert "updated ssh resource 'web-1' upstream port 2200 -> 22" in result.actions
        # Port drift alone never touches the address.
        assert "UpdateResourceAddress" not in tg_server.calls

    async def test_matching_upstream_port_is_left_alone(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        env.add_k8s_cluster_overlay()
        await env.reconciler.reconcile("startup")

        result = await env.reconciler.reconcile("tick")

        assert result.ok is True
        assert not any("upstream port" in action for action in result.actions)
        assert "UpdateSSHResourceUpstream" not in tg_server.calls
        assert "UpdateKubernetesResourceUpstream" not in tg_server.calls


class TestCARegistration:
    async def test_generated_cas_registered_and_gateway_rebound_once(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        result = await env.reconciler.reconcile("startup")

        assert result.ok is True
        assert tg_server.calls.count("CreateX509CA") == 1
        assert tg_server.calls.count("CreateSSHCA") == 1
        managed = env.registry.managed_ids()
        [binding] = tg_server.gateway_bindings
        assert binding["id"] == "g-1"
        assert binding["x509CAId"] == managed["ca/x509"]
        assert binding["sshCAId"] == managed["ca/ssh"]

        # Level-triggered but recorded: the second reconcile does not re-register.
        await env.reconciler.reconcile("tick")
        assert tg_server.calls.count("CreateX509CA") == 1
        assert tg_server.calls.count("CreateSSHCA") == 1
        assert len(tg_server.gateway_bindings) == 1

    async def test_byo_cas_are_never_auto_registered(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        # Materialize bring-your-own CA files in a separate PKI dir.
        byo = CertManager(tmp_path / "byo")
        x509_info = byo.ensure_x509_ca(generate=True)
        ssh_info = byo.ensure_ssh_ca(generate=True)
        seed = f"""\
twingate:
  network: acme
  gateway_id: g-1
ca:
  x509:
    generate: false
    cert_path: {x509_info.cert_path.as_posix()}
    key_path: {x509_info.key_path.as_posix()}
  ssh:
    generate: false
    key_path: {ssh_info.key_path.as_posix()}
ssh_upstreams:
  - name: web-1
    address: 10.0.0.5:22
"""
        env = Env(tmp_path, seed, gateway_binary(), Capabilities(), tg_client)
        result = await env.reconciler.reconcile("startup")

        assert result.ok is True
        assert "CreateX509CA" not in tg_server.calls
        assert "CreateSSHCA" not in tg_server.calls
        assert tg_server.gateway_bindings == []


class TestLocalFailurePaths:
    async def test_empty_seed_holds_gateway_down_without_error(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = Env(tmp_path, _EMPTY_SEED, gateway_binary(), Capabilities(), tg_client)
        result = await env.reconciler.reconcile("startup")

        assert result.ok is True
        assert env.process.calls == []
        assert not leaf_cert_path(env.paths.pki_dir).exists()
        assert any("upstream" in action for action in result.actions)

    async def test_missing_credential_file_names_cluster_and_path(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        root = tmp_path / "k8s-creds-src"
        root.mkdir()
        missing = (root / "nope.token").as_posix()
        ca = root / "prod-ca.crt"
        ca.write_text("PEM", encoding="utf-8")
        seed = f"""\
twingate:
  network: acme
  gateway_id: g-1
k8s_clusters:
  - name: prod
    address: prod.k8s.internal
    port: 6443
    bearer_token_file: {missing}
    ca_file: {ca.as_posix()}
"""
        env = Env(tmp_path, seed, gateway_binary(), Capabilities(), tg_client)
        result = await env.reconciler.reconcile("startup")

        assert result.ok is False
        assert any("prod" in e and "nope.token" in e for e in result.errors)
        # Local failure: no config applied, gateway not started.
        assert not env.config_path.exists()
        assert env.process.calls == []

    async def test_invalid_seed_records_error_and_keeps_running(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        await env.reconciler.reconcile("startup")
        old_config = env.config_path.read_text(encoding="utf-8")

        env.seed_path.write_text("twingate: {network: acme}\n", encoding="utf-8")
        result = await env.reconciler.reconcile("seed-change")

        assert result.ok is False
        assert result.errors
        assert env.config_path.read_text(encoding="utf-8") == old_config
        assert env.process.calls == ["start"]  # untouched by the bad seed


class TestSingleFlight:
    async def test_concurrent_triggers_coalesce_into_one_follow_up(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_client: TGClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        env = Env(tmp_path, _EMPTY_SEED, gateway_binary(), Capabilities(), tg_client)
        runs: list[str] = []

        async def slow_run(trigger: str) -> ReconcileResult:
            runs.append(trigger)
            await asyncio.sleep(0.05)
            return ReconcileResult(
                ok=True, trigger=trigger, started_at=datetime.now(UTC), actions=[], errors=[]
            )

        monkeypatch.setattr(env.reconciler, "_run", slow_run)

        leader = asyncio.create_task(env.reconciler.reconcile("startup"))
        await asyncio.sleep(0.01)  # let the leader take the lock
        followers = [
            asyncio.create_task(env.reconciler.reconcile(trigger))
            for trigger in ("tick", "api", "seed-change")
        ]
        results: list[Any] = await asyncio.gather(leader, *followers)

        # One in-flight run + exactly one coalesced follow-up, not four runs.
        assert len(runs) == 2
        assert runs[0] == "startup"
        assert all(isinstance(r, ReconcileResult) for r in results)

    async def test_cancelled_follower_does_not_wedge_coalescing(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_client: TGClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A follower cancelled while awaiting the lock must not leave
        # self._follower pointing at a future that never resolves — that would hang
        # every later coalescing trigger forever. After the cancellation, an
        # overlapping reconcile must still complete.
        env = Env(tmp_path, _EMPTY_SEED, gateway_binary(), Capabilities(), tg_client)
        release = asyncio.Event()

        async def blocking_run(trigger: str) -> ReconcileResult:
            await release.wait()
            return ReconcileResult(
                ok=True, trigger=trigger, started_at=datetime.now(UTC)
            )

        monkeypatch.setattr(env.reconciler, "_run", blocking_run)

        leader = asyncio.create_task(env.reconciler.reconcile("startup"))
        await asyncio.sleep(0.01)  # leader takes the lock and blocks in _run
        follower = asyncio.create_task(env.reconciler.reconcile("api"))
        await asyncio.sleep(0.01)  # follower registers itself and awaits the lock
        follower.cancel()
        with pytest.raises(asyncio.CancelledError):
            await follower

        # Let the leader finish, then a fresh overlapping pair must still coalesce
        # and complete rather than hang on the dead follower future.
        release.set()
        assert (await leader).ok is True

        release2 = asyncio.Event()

        async def blocking_run2(trigger: str) -> ReconcileResult:
            await release2.wait()
            return ReconcileResult(
                ok=True, trigger=trigger, started_at=datetime.now(UTC)
            )

        monkeypatch.setattr(env.reconciler, "_run", blocking_run2)
        leader2 = asyncio.create_task(env.reconciler.reconcile("tick"))
        await asyncio.sleep(0.01)
        follower2 = asyncio.create_task(env.reconciler.reconcile("api"))
        await asyncio.sleep(0.01)
        release2.set()
        results = await asyncio.wait_for(asyncio.gather(leader2, follower2), timeout=2.0)
        assert all(r.ok for r in results)


class TestShutdown:
    async def test_request_shutdown_makes_apply_skip_gateway_start(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_client: TGClient,
    ) -> None:
        # Once shutting down, a reconcile must not (re)start the gateway, so a
        # late trigger cannot spawn a child the supervisor then orphans.
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)
        await env.reconciler.request_shutdown()
        result = await env.reconciler.reconcile("api")
        assert "start" not in env.process.calls
        assert any("shutting down" in a for a in result.actions)


_MODE_B_SEED = """\
twingate:
  network: acme
  remote_network: Prod DC
  gateway_address: 203.0.113.10:8443
ssh_upstreams:
  - name: web-1
    address: 10.0.0.5:22
"""


class TestGatewayModes:
    """Mode B (auto-create/adopt the gateway) alongside Mode A (pinned gateway_id)."""

    async def test_mode_b_creates_gateway_when_absent(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = Env(tmp_path, _MODE_B_SEED, gateway_binary(), Capabilities(), tg_client)

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []
        assert result.ok is True
        # Exactly one gateway created, at the seed address, in the resolved network.
        assert len(tg_server.created_gateways) == 1
        created = tg_server.created_gateways[0]
        assert created["address"] == "203.0.113.10:8443"
        assert created["remoteNetworkId"] == "rn-1"
        assert created["x509CAId"]  # a real CA id — registered BEFORE the gateway
        # Resolved id recorded and every synced resource attaches to it.
        gw_id = env.registry.managed_ids()["gateway/self"]
        assert gw_id in tg_server.gateways
        assert tg_server.resources
        assert all(r.gateway_id == gw_id for r in tg_server.resources.values())
        assert any("created gateway" in a for a in result.actions)
        # Ordering guard: the X.509 CA must be registered before the gateway is created.
        assert tg_server.calls.index("CreateX509CA") < tg_server.calls.index("CreateGateway")

    async def test_mode_b_creates_gateway_by_remote_network_id(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        seed = (
            "twingate:\n"
            "  network: acme\n"
            "  remote_network_id: rn-1\n"
            "  gateway_address: 203.0.113.10:8443\n"
            "ssh_upstreams:\n"
            "  - name: web-1\n"
            "    address: 10.0.0.5:22\n"
        )
        env = Env(tmp_path, seed, gateway_binary(), Capabilities(), tg_client)

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []
        # remote_network_id given directly -> no name resolution round trip.
        assert "ResolveRemoteNetwork" not in tg_server.calls
        assert len(tg_server.created_gateways) == 1
        assert tg_server.created_gateways[0]["remoteNetworkId"] == "rn-1"

    async def test_mode_b_adopts_existing_gateway_by_address(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        tg_server.add_gateway("203.0.113.10:8443", "gw-existing")
        env = Env(tmp_path, _MODE_B_SEED, gateway_binary(), Capabilities(), tg_client)

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []
        assert tg_server.created_gateways == []  # adopted, not created
        assert env.registry.managed_ids()["gateway/self"] == "gw-existing"
        assert all(r.gateway_id == "gw-existing" for r in tg_server.resources.values())
        assert any("adopted existing gateway" in a for a in result.actions)
        # Adopted gateway is rebound to the gwops-generated CAs registered this pass.
        assert any(b.get("id") == "gw-existing" for b in tg_server.gateway_bindings)

    async def test_mode_b_reuses_recorded_gateway(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        env = Env(tmp_path, _MODE_B_SEED, gateway_binary(), Capabilities(), tg_client)
        env.registry.record("gateway", "self", "gw-known")

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []
        # A recorded gateway/self short-circuits resolution entirely.
        assert "CreateGateway" not in tg_server.calls
        assert "ListGateways" not in tg_server.calls
        assert "ResolveRemoteNetwork" not in tg_server.calls
        assert all(r.gateway_id == "gw-known" for r in tg_server.resources.values())

    async def test_mode_a_pin_records_gateway_self_without_create(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        # gateway_id: g-1 (Mode A, pinned)
        env = Env(tmp_path, _SSH_SEED, gateway_binary(), Capabilities(), tg_client)

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []
        assert env.registry.managed_ids()["gateway/self"] == "g-1"
        assert tg_server.created_gateways == []
        assert "ListGateways" not in tg_server.calls  # never adopts/creates in Mode A
        assert all(r.gateway_id == "g-1" for r in tg_server.resources.values())

    async def test_mode_b_requires_generated_x509_ca(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        tg_server: FakeTGServer,
        tg_client: TGClient,
    ) -> None:
        # Bring-your-own X.509 CA: gwops loads it locally but does not register it, so
        # it has no CA id to create the gateway with -> fail loud, no gateway created.
        info = CertManager(tmp_path / "byo").ensure_x509_ca(generate=True)
        seed = (
            "twingate:\n"
            "  network: acme\n"
            "  remote_network: Prod DC\n"
            "  gateway_address: 203.0.113.10:8443\n"
            "ca:\n"
            "  x509:\n"
            "    generate: false\n"
            f"    cert_path: {info.cert_path.as_posix()}\n"
            f"    key_path: {info.key_path.as_posix()}\n"
            "  ssh:\n"
            "    generate: true\n"
            "ssh_upstreams:\n"
            "  - name: web-1\n"
            "    address: 10.0.0.5:22\n"
        )
        env = Env(tmp_path, seed, gateway_binary(), Capabilities(), tg_client)

        result = await env.reconciler.reconcile("startup")

        assert result.ok is False
        assert any(
            "auto-create" in e and "ca.x509.generate" in e for e in result.errors
        )
        assert tg_server.created_gateways == []
        assert "gateway/self" not in env.registry.managed_ids()
