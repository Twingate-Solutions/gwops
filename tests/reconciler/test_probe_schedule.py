"""The reconciler hands each pass to the upstream TLS probe without ever failing the pass.

``Reconciler(probe=...)``: after the tenant sync, ``probe.schedule(state, remote_web_apps,
gateway_id, paths=...)`` is called with the pass's listing, the registry's gateway id (seed id as
fallback) and the pass's paths (including the validated upstream CA bundle copies). A raising
runner is logged and ignored.
"""

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import structlog.testing
import yaml

from gwops.reconciler.core import RemoteWebApp
from gwops.renderer.capabilities import Capabilities
from gwops.renderer.render import RuntimePaths
from gwops.tgapi.client import TGClient

from .conftest import FakeTGServer
from .test_core import Env


class _Recorder:
    def __init__(self, *, raises: bool = False) -> None:
        self.calls: list[tuple[Any, list[RemoteWebApp] | None, str | None, RuntimePaths]] = []
        self._raises = raises

    def schedule(
        self,
        state: Any,
        remote: list[RemoteWebApp] | None,
        gateway_id: str | None,
        *,
        paths: RuntimePaths,
    ) -> None:
        self.calls.append((state, remote, gateway_id, paths))
        if self._raises:
            raise RuntimeError("schedule exploded")


@pytest.fixture
def tg_client() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="test-key")


@pytest.fixture
def make_env(
    tmp_path: Path, gateway_binary: Callable[..., Path], tg_client: TGClient
) -> Callable[[str], Env]:
    def _make(seed_text: str) -> Env:
        return Env(
            tmp_path, seed_text, gateway_binary(), Capabilities(gateway_version="2.0.0"), tg_client
        )

    return _make


def _seed() -> str:
    return yaml.safe_dump(
        {
            "twingate": {"network": "acme", "gateway_id": "g-1"},
            "web_apps": [{"name": "grafana", "address": "grafana.corp.internal"}],
        },
        sort_keys=False,
    )


def _seed_with_missing_bundle(tmp_path: Path) -> str:
    missing = (tmp_path / "webapp-cas-src" / "missing.pem").as_posix()
    return yaml.safe_dump(
        {
            "twingate": {"network": "acme", "gateway_id": "g-1"},
            "web_app_proxy": {"upstream_ca_bundles": [{"name": "corp", "file": missing}]},
            "web_apps": [{"name": "grafana", "address": "grafana.corp.internal"}],
        },
        sort_keys=False,
    )


def _skips(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in logs if e["event"] == "reconcile.probe_skipped"]


class TestProbeScheduling:
    async def test_each_pass_schedules_the_probe_with_its_listing(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """The probe receives the pass's remote listing, this gateway's id and the pass paths."""
        env = make_env(_seed())
        recorder = _Recorder()
        env.reconciler._probe = recorder  # type: ignore[assignment]

        await env.reconciler.reconcile("startup")
        result = await env.reconciler.reconcile("tick")

        assert len(recorder.calls) == 2
        state, remote, gateway_id, paths = recorder.calls[-1]
        assert [app.name for app in state.web_apps] == ["grafana"]
        assert remote == result.remote_web_apps
        assert gateway_id == "g-1"
        assert paths.upstream_ca_dir == env.paths.upstream_ca_dir

    async def test_a_raising_probe_never_fails_the_pass(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """A schedule that raises is contained: the pass still completes with no new error."""
        env = make_env(_seed())
        baseline = await env.reconciler.reconcile("startup")
        recorder = _Recorder(raises=True)
        env.reconciler._probe = recorder  # type: ignore[assignment]

        result = await env.reconciler.reconcile("tick")

        assert recorder.calls
        assert result.errors == baseline.errors
        assert result.ok == baseline.ok

    async def test_a_reconciler_without_a_probe_is_unaffected(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """The default (no runner) schedules nothing and passes as before."""
        env = make_env(_seed())

        result = await env.reconciler.reconcile("startup")

        assert env.reconciler._probe is None
        assert result.trigger == "startup"


class TestProbeWithFailedCaBundles:
    async def test_a_failed_ca_bundle_step_schedules_no_batch_and_logs_once(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer, tmp_path: Path
    ) -> None:
        """Without this pass's CA copies a probe would blame private upstreams; keep old results."""
        env = make_env(_seed_with_missing_bundle(tmp_path))
        recorder = _Recorder()
        env.reconciler._probe = recorder  # type: ignore[assignment]

        with structlog.testing.capture_logs() as logs:
            first = await env.reconciler.reconcile("startup")
            await env.reconciler.reconcile("tick")

        assert any(e.startswith("CA bundle") for e in first.errors)
        assert recorder.calls == []
        [event] = _skips(logs)
        assert event["log_level"] == "warning"
        assert "ca_bundle" in event["reason"]

    async def test_the_probe_resumes_when_the_ca_step_recovers_and_a_new_failure_logs_again(
        self,
        make_env: Callable[[str], Env],
        tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Scheduling returns with the bundles; the next failure is reported afresh."""
        env = make_env(_seed())
        recorder = _Recorder()
        env.reconciler._probe = recorder  # type: ignore[assignment]
        real = env.reconciler._materialize_ca_bundles

        def failing(state: Any, result: Any, paths: RuntimePaths) -> tuple[bool, RuntimePaths]:
            return False, paths

        with structlog.testing.capture_logs() as logs:
            monkeypatch.setattr(env.reconciler, "_materialize_ca_bundles", failing)
            await env.reconciler.reconcile("startup")
            assert recorder.calls == []
            monkeypatch.setattr(env.reconciler, "_materialize_ca_bundles", real)
            await env.reconciler.reconcile("tick")
            assert len(recorder.calls) == 1
            monkeypatch.setattr(env.reconciler, "_materialize_ca_bundles", failing)
            await env.reconciler.reconcile("tick")

        assert len(recorder.calls) == 1
        assert len(_skips(logs)) == 2
