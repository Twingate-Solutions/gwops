"""Reconcile-time handling of a throttled (HTTP 429) tenant.

Once one TG write in a pass is throttled, every later TG write in that pass is skipped
and each affected resource gets the per-resource error ``deferred: rate-limited``; the
next pass retries. Reads are unaffected. The fake tenant answers 429 (with a 1 s
Retry-After) for the operations named in ``FakeTGServer.throttle_ops``; the client's
sleep is replaced so no test waits.
"""

import json
import types
from collections.abc import Callable, Iterator
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import structlog

from gwops.certs.manager import CertManager
from gwops.reconciler.core import DEFERRED_RATE_LIMITED
from gwops.renderer.capabilities import Capabilities
from gwops.tgapi.client import TGClient

from .conftest import FakeTGServer
from .test_core import Env

_API_KEY = "test-key"


@pytest.fixture
def tg_client() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key=_API_KEY)


@pytest.fixture(autouse=True)
def client_sleep(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Replace only the TG client's sleep (not asyncio.sleep globally) so throttle waits
    are instant and recorded."""
    fake_sleep = AsyncMock()
    monkeypatch.setattr(
        "gwops.tgapi.client.asyncio", types.SimpleNamespace(sleep=fake_sleep)
    )
    return fake_sleep


@pytest.fixture
def byo_ca_block(tmp_path: Path) -> str:
    """Seed `ca:` block with bring-your-own CAs, so the pass makes no CA/gateway writes."""
    byo = CertManager(tmp_path / "byo")
    x509_info = byo.ensure_x509_ca(generate=True)
    ssh_info = byo.ensure_ssh_ca(generate=True)
    return f"""\
ca:
  x509:
    generate: false
    cert_path: {x509_info.cert_path.as_posix()}
    key_path: {x509_info.key_path.as_posix()}
  ssh:
    generate: false
    key_path: {ssh_info.key_path.as_posix()}
"""


def _seed(ca_block: str, upstreams: dict[str, str], groups: dict[str, str] | None = None) -> str:
    """A Mode A seed with the given `name -> address` SSH upstreams (and optional group)."""
    lines = ["twingate:", "  network: acme", "  gateway_id: g-1", ca_block, "ssh_upstreams:"]
    for name, address in upstreams.items():
        lines += [f"  - name: {name}", f"    address: {address}"]
        if groups and name in groups:
            lines += ["    access:", f'      groups: ["{groups[name]}"]']
    return "\n".join(lines) + "\n"


@pytest.fixture
def make_env(
    tmp_path: Path, gateway_binary: Callable[..., Path], tg_client: TGClient
) -> Callable[[str], Env]:
    def _make(seed: str) -> Env:
        return Env(tmp_path, seed, gateway_binary(), Capabilities(), tg_client)

    return _make


_THREE = {"web-1": "10.0.0.5:22", "web-2": "10.0.0.6:22", "web-3": "10.0.0.7:22"}


class TestThrottledCreateDefersTheRestOfThePass:
    async def test_later_writes_are_deferred_per_resource_and_reads_proceed(
        self,
        make_env: Callable[[str], Env],
        byo_ca_block: str,
        tg_server: FakeTGServer,
        client_sleep: AsyncMock,
    ) -> None:
        # One group per upstream, so each resource needs its own name lookup (a read).
        for name in ("G1", "G2", "G3"):
            tg_server.add_group(name)
        env = make_env(
            _seed(byo_ca_block, _THREE, {"web-1": "G1", "web-2": "G2", "web-3": "G3"})
        )
        tg_server.throttle_ops = {"CreateSSHResource": 1}

        result = await env.reconciler.reconcile("startup")

        # web-1's create was throttled once, waited out (the Retry-After hint of 1 s plus
        # jitter), and then succeeded.
        [wait] = [c.args[0] for c in client_sleep.await_args_list]
        assert 1.0 <= wait <= 2.0
        assert {r.name for r in tg_server.resources.values()} == {"web-1"}
        assert "ssh/web-1" in result.tg_synced
        assert "ssh/web-1" not in result.resource_errors
        # The other two are skipped, not attempted: one 429 + one success for web-1 only.
        assert tg_server.calls.count("CreateSSHResource") == 2
        assert result.resource_errors == {
            "ssh/web-2": [DEFERRED_RATE_LIMITED],
            "ssh/web-3": [DEFERRED_RATE_LIMITED],
        }
        assert DEFERRED_RATE_LIMITED == "deferred: rate-limited"
        assert "TG sync: ssh/web-2: deferred: rate-limited" in result.errors
        assert result.tg_synced == {"ssh/web-1"}
        assert result.ok is False
        # Reads were not deferred: every group was still resolved after the throttle.
        assert tg_server.calls.count("FindGroupsByName") == 3
        assert set(env.registry.managed_ids()) >= {"ssh/web-1"}
        assert "ssh/web-2" not in env.registry.managed_ids()
        # A throttled tenant is a TG-side failure, never a local one.
        assert result.local_ok is True

    async def test_next_pass_retries_the_deferred_resources(
        self,
        make_env: Callable[[str], Env],
        byo_ca_block: str,
        tg_server: FakeTGServer,
    ) -> None:
        env = make_env(_seed(byo_ca_block, _THREE))
        tg_server.throttle_ops = {"CreateSSHResource": 1}
        first = await env.reconciler.reconcile("startup")
        assert set(first.resource_errors) == {"ssh/web-2", "ssh/web-3"}

        second = await env.reconciler.reconcile("tick")

        assert second.errors == []
        assert second.ok is True
        assert second.resource_errors == {}
        assert second.tg_synced == {"ssh/web-1", "ssh/web-2", "ssh/web-3"}
        assert {r.name for r in tg_server.resources.values()} == set(_THREE)
        # web-1 was not created again: 429 + success, then web-2 and web-3 once each.
        assert tg_server.calls.count("CreateSSHResource") == 4

    async def test_exhausted_retries_error_the_throttled_resource_and_defer_the_rest(
        self,
        make_env: Callable[[str], Env],
        byo_ca_block: str,
        tg_server: FakeTGServer,
        client_sleep: AsyncMock,
    ) -> None:
        env = make_env(_seed(byo_ca_block, _THREE))
        tg_server.throttle_ops = {"CreateSSHResource": 99}

        result = await env.reconciler.reconcile("startup")

        # web-1 used up every attempt (6 requests, 5 waits) and carries the client's own
        # error; web-2 and web-3 were never attempted.
        assert tg_server.calls.count("CreateSSHResource") == 6
        assert client_sleep.await_count == 5
        assert tg_server.resources == {}
        assert [m for m in result.resource_errors["ssh/web-1"] if "rate-limited" in m]
        assert result.resource_errors["ssh/web-1"] != [DEFERRED_RATE_LIMITED]
        assert result.resource_errors["ssh/web-2"] == [DEFERRED_RATE_LIMITED]
        assert result.resource_errors["ssh/web-3"] == [DEFERRED_RATE_LIMITED]
        assert result.tg_synced == set()


class TestThrottledUpdatesAndDeletes:
    async def test_updates_and_deletes_after_a_throttled_write_are_deferred(
        self,
        make_env: Callable[[str], Env],
        byo_ca_block: str,
        tg_server: FakeTGServer,
    ) -> None:
        env = make_env(_seed(byo_ca_block, _THREE))
        assert (await env.reconciler.reconcile("startup")).ok is True
        managed = env.registry.managed_ids()

        # web-1 and web-2 move to new addresses and web-3 is dropped from the seed.
        env.seed_path.write_text(
            _seed(byo_ca_block, {"web-1": "10.0.1.5:22", "web-2": "10.0.1.6:22"}),
            encoding="utf-8",
        )
        tg_server.calls.clear()
        tg_server.throttle_ops = {"UpdateResourceAddress": 1}

        result = await env.reconciler.reconcile("tick")

        by_name = {r.name: r for r in tg_server.resources.values()}
        assert by_name["web-1"].address == "10.0.1.5"  # throttled once, then applied
        assert by_name["web-2"].address == "10.0.0.6"  # deferred
        assert "web-3" in by_name  # delete deferred
        assert tg_server.calls.count("UpdateResourceAddress") == 2
        assert "DeleteResource" not in tg_server.calls
        assert result.resource_errors == {
            "ssh/web-2": [DEFERRED_RATE_LIMITED],
            "ssh/web-3": [DEFERRED_RATE_LIMITED],
        }
        assert result.tg_synced == {"ssh/web-1"}
        # The deferred delete left web-3 owned, so the next pass still sees it.
        assert env.registry.managed_ids()["ssh/web-3"] == managed["ssh/web-3"]

        third = await env.reconciler.reconcile("tick")

        assert third.errors == []
        assert third.tg_synced == {"ssh/web-1", "ssh/web-2", "ssh/web-3"}
        by_name = {r.name: r for r in tg_server.resources.values()}
        assert by_name["web-2"].address == "10.0.1.6"
        assert "web-3" not in by_name
        assert "ssh/web-3" not in env.registry.managed_ids()

    async def test_a_resource_with_nothing_to_write_is_not_marked_deferred(
        self,
        make_env: Callable[[str], Env],
        byo_ca_block: str,
        tg_server: FakeTGServer,
    ) -> None:
        env = make_env(_seed(byo_ca_block, _THREE))
        assert (await env.reconciler.reconcile("startup")).ok is True
        # Only web-1 drifts; web-2 and web-3 already match the tenant.
        env.seed_path.write_text(
            _seed(byo_ca_block, {**_THREE, "web-1": "10.0.1.5:22"}), encoding="utf-8"
        )
        tg_server.throttle_ops = {"UpdateResourceAddress": 1}

        result = await env.reconciler.reconcile("tick")

        assert result.errors == []
        assert result.resource_errors == {}
        assert result.tg_synced == {"ssh/web-1", "ssh/web-2", "ssh/web-3"}


class TestThrottledAccessDelta:
    async def test_access_delta_after_a_throttled_write_is_deferred_not_sent(
        self,
        make_env: Callable[[str], Env],
        byo_ca_block: str,
        tg_server: FakeTGServer,
    ) -> None:
        tg_server.add_group("ops", "g-ops")
        two = {"web-1": "10.0.0.5:22", "web-2": "10.0.0.6:22"}
        env = make_env(_seed(byo_ca_block, two))
        assert (await env.reconciler.reconcile("startup")).ok is True

        # web-1's address drifts (its write is throttled once); web-2 gains a group.
        env.seed_path.write_text(
            _seed(byo_ca_block, {**two, "web-1": "10.0.1.5:22"}, groups={"web-2": "ops"}),
            encoding="utf-8",
        )
        tg_server.calls.clear()
        tg_server.throttle_ops = {"UpdateResourceAddress": 1}

        result = await env.reconciler.reconcile("tick")

        assert "UpdateResourceAccess" not in tg_server.calls
        assert result.resource_errors == {"ssh/web-2": [DEFERRED_RATE_LIMITED]}

        third = await env.reconciler.reconcile("tick")

        assert third.errors == []
        assert tg_server.calls.count("UpdateResourceAccess") == 1
        by_name = {r.name: r for r in tg_server.resources.values()}
        assert by_name["web-2"].groups == {"g-ops"}


class TestReadsAreNeverCounted:
    async def test_a_throttled_read_is_retried_and_does_not_defer_writes(
        self,
        make_env: Callable[[str], Env],
        byo_ca_block: str,
        tg_server: FakeTGServer,
        client_sleep: AsyncMock,
    ) -> None:
        env = make_env(_seed(byo_ca_block, _THREE))
        tg_server.throttle_ops = {"ListResources": 1}

        result = await env.reconciler.reconcile("startup")

        assert client_sleep.await_count == 1
        assert result.errors == []
        assert result.resource_errors == {}
        assert {r.name for r in tg_server.resources.values()} == set(_THREE)


class TestThrottledGatewayWrites:
    async def test_throttled_ca_registration_defers_later_writes_and_resumes(
        self,
        make_env: Callable[[str], Env],
        tg_server: FakeTGServer,
    ) -> None:
        # Default seed generates both CAs and (Mode A) rebinds the gateway to them.
        seed = _seed("", {"web-1": "10.0.0.5:22"})
        env = make_env(seed)
        tg_server.throttle_ops = {"CreateX509CA": 1}

        first = await env.reconciler.reconcile("startup")

        # The X.509 CA create was throttled, then succeeded; everything after it is deferred.
        assert tg_server.calls.count("CreateX509CA") == 2
        assert "CreateSSHCA" not in tg_server.calls
        assert tg_server.gateway_bindings == []
        assert "CA registration: deferred: rate-limited" in first.errors
        assert first.resource_errors == {"ssh/web-1": [DEFERRED_RATE_LIMITED]}
        assert tg_server.resources == {}

        second = await env.reconciler.reconcile("tick")

        assert second.errors == []
        # The already-created X.509 CA is reused (not duplicated) and bound with the SSH CA.
        assert tg_server.calls.count("CreateX509CA") == 2
        assert tg_server.calls.count("CreateSSHCA") == 1
        [binding] = tg_server.gateway_bindings
        managed = env.registry.managed_ids()
        assert binding["x509CAId"] == managed["ca/x509"]
        assert binding["sshCAId"] == managed["ca/ssh"]
        assert {r.name for r in tg_server.resources.values()} == {"web-1"}


class TestDeferralLogging:
    @pytest.fixture(autouse=True)
    def restore_logging(self) -> Iterator[None]:
        """`configure_logging()` rebinds structlog to the test's captured stdout; put the
        previous global configuration back so no later test inherits a closed stream."""
        saved = structlog.get_config()
        yield
        structlog.configure(**saved)

    async def test_deferral_is_logged_per_resource_and_secrets_stay_out(
        self,
        make_env: Callable[[str], Env],
        byo_ca_block: str,
        tg_server: FakeTGServer,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from gwops.logging import configure_logging

        configure_logging()
        env = make_env(_seed(byo_ca_block, _THREE))
        tg_server.throttle_ops = {"CreateSSHResource": 1}

        await env.reconciler.reconcile("startup")

        out = capsys.readouterr().out
        assert _API_KEY not in out
        records = [json.loads(line) for line in out.splitlines() if line.strip()]
        deferred = [r for r in records if r["event"] == "reconcile.tg_write_deferred"]
        # The resource name must survive the log redactor (a field named `key` would not).
        assert sorted(r["resource"] for r in deferred) == ["ssh/web-2", "ssh/web-3"]
        assert {r["reason"] for r in deferred} == {"rate-limited"}
        [throttled] = [r for r in records if r["event"] == "tgapi.throttled"]
        assert throttled["query_name"] == "CreateSSHResource"
        assert throttled["is_write"] is True
        assert throttled["wait_source"] == "retry-after"


class TestPassThrottleBudget:
    """All 429 sleeping in one pass shares a budget; once spent, throttled calls fail at once."""

    @pytest.fixture(autouse=True)
    def exact_waits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No jitter, so every throttle wait is exactly the fake tenant's 1 s hint."""
        monkeypatch.setattr("gwops.tgapi.client.random.uniform", lambda lo, hi: 0.0)

    async def test_a_throttled_read_after_exhaustion_takes_the_tg_unavailable_path(
        self,
        make_env: Callable[[str], Env],
        byo_ca_block: str,
        tg_server: FakeTGServer,
        client_sleep: AsyncMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("gwops.tgapi.client._PASS_THROTTLE_BUDGET_SECONDS", 0.0)
        env = make_env(_seed(byo_ca_block, _THREE))
        tg_server.throttle_ops = {"ListResources": 99}

        result = await env.reconciler.reconcile("startup")

        # One request, no sleep, no retry: the read fails fast instead of waiting.
        assert tg_server.calls.count("ListResources") == 1
        assert client_sleep.await_count == 0
        assert result.tg_unavailable is True
        assert any("could not list resources" in e and "budget" in e for e in result.errors)
        assert result.tg_synced == set()
        # TG-side failure only: the local render and apply still ran.
        assert result.local_ok is True
        assert env.config_path.is_file()
        assert "started gateway" in result.actions
        assert env.process.calls == ["start"]

    async def test_a_throttled_write_after_exhaustion_defers_the_rest(
        self,
        make_env: Callable[[str], Env],
        byo_ca_block: str,
        tg_server: FakeTGServer,
        client_sleep: AsyncMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("gwops.tgapi.client._PASS_THROTTLE_BUDGET_SECONDS", 0.0)
        env = make_env(_seed(byo_ca_block, _THREE))
        tg_server.throttle_ops = {"CreateSSHResource": 99}

        result = await env.reconciler.reconcile("startup")

        assert tg_server.calls.count("CreateSSHResource") == 1
        assert client_sleep.await_count == 0
        [web1_error] = result.resource_errors["ssh/web-1"]
        assert "rate-limited" in web1_error
        assert "budget" in web1_error
        assert result.resource_errors["ssh/web-2"] == [DEFERRED_RATE_LIMITED]
        assert result.resource_errors["ssh/web-3"] == [DEFERRED_RATE_LIMITED]
        assert tg_server.resources == {}
        assert result.local_ok is True
        assert "started gateway" in result.actions

    async def test_the_budget_is_consumed_across_calls_in_one_pass(
        self,
        make_env: Callable[[str], Env],
        byo_ca_block: str,
        tg_server: FakeTGServer,
        client_sleep: AsyncMock,
        tg_client: TGClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("gwops.tgapi.client._PASS_THROTTLE_BUDGET_SECONDS", 2.5)
        # Two 1 s waits on the list read leave 0.5 s; the create's 1 s wait no longer fits.
        env = make_env(_seed(byo_ca_block, {"web-1": "10.0.0.5:22"}))
        tg_server.throttle_ops = {"ListResources": 2, "CreateSSHResource": 1}

        result = await env.reconciler.reconcile("startup")

        assert [c.args[0] for c in client_sleep.await_args_list] == [1.0, 1.0]
        assert tg_server.calls.count("ListResources") == 3
        assert tg_server.calls.count("CreateSSHResource") == 1
        assert tg_server.resources == {}
        assert "budget" in "".join(result.resource_errors["ssh/web-1"])
        assert tg_client.throttle_budget_remaining == 0.5

    async def test_each_pass_starts_with_the_full_budget(
        self,
        make_env: Callable[[str], Env],
        byo_ca_block: str,
        tg_server: FakeTGServer,
        client_sleep: AsyncMock,
        tg_client: TGClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("gwops.tgapi.client._PASS_THROTTLE_BUDGET_SECONDS", 2.5)
        env = make_env(_seed(byo_ca_block, {"web-1": "10.0.0.5:22"}))
        tg_server.throttle_ops = {"ListResources": 3}  # 1 + 1 s fit, the third wait does not

        first = await env.reconciler.reconcile("startup")

        assert first.tg_unavailable is True
        assert tg_client.throttle_budget_remaining == 0.5

        # Two more 1 s waits (2.0 s) fit only if the pass began with a fresh 2.5 s budget.
        tg_server.throttle_ops = {"ListResources": 2}
        second = await env.reconciler.reconcile("tick")

        assert second.tg_unavailable is False
        assert second.errors == []
        assert second.tg_synced == {"ssh/web-1"}
        assert client_sleep.await_count == 4
        assert tg_client.throttle_budget_remaining == 0.5
