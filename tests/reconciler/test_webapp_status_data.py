"""Reconcile-pass data behind /status: remote web-app snapshot, warnings, housekeeping.

Pinned on ``ReconcileResult``:

* ``remote_web_apps``: ``list[RemoteWebApp] | None``. The pass's tenant listing of web apps
  (managed or not, any gateway; ``None`` when the tenant was not listed). It is the listing, so
  a resource created or gateway-corrected in the same pass appears as it was listed.
  ``RemoteWebApp`` fields: ``id, name, gateway_id, address, alias, upstream_tls, downstream_tls``
  (lowercase seed spellings), ``upstream_port``, ``downstream_port``, ``header_rewrite_names``
  (lowercase names, never values), ``managed``.
* ``webapp_warnings``: the current ``webapp_policy.warnings`` set, on every pass.
* ``housekeeping_errors``: one message per failed GC directory and one for a failed legacy
  directory cleanup; no exception text. The list never feeds ``errors`` or ``ok``.
"""

from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import structlog
import yaml

from gwops import confined
from gwops.confined import CleanupResult
from gwops.reconciler import core
from gwops.reconciler.core import ReconcileResult
from gwops.renderer.capabilities import Capabilities
from gwops.tgapi.client import TGClient

from .conftest import FakeTGServer
from .test_core import Env

_HEADER_VALUE = "internal-marker-value"
_STRANGER_VALUE = "stranger-marker-value"
_PEM_MARKER = "-----BEGIN PRIVATE KEY----- marker-secret"
_ALLOW_CORP = {"web_app_proxy": {"plaintext_upstreams": {"dns_suffixes": ["corp.internal"]}}}


@pytest.fixture
def tg_client() -> Iterator[TGClient]:
    yield TGClient(network="acme", api_key="test-key")


def _seed(
    *,
    web_apps: list[dict[str, Any]] | None = None,
    ssh: bool = False,
    extra: dict[str, Any] | None = None,
) -> str:
    doc: dict[str, Any] = {"twingate": {"network": "acme", "gateway_id": "g-1"}}
    if ssh:
        doc["ssh_upstreams"] = [{"name": "web-1", "address": "10.0.0.5:22"}]
    doc["web_apps"] = [] if web_apps is None else web_apps
    doc.update(extra or {})
    return yaml.safe_dump(doc, sort_keys=False)


def _grafana(**fields: Any) -> dict[str, Any]:
    return {"name": "grafana", "address": "grafana.corp.internal", **fields}


@pytest.fixture
def make_env(
    tmp_path: Path, gateway_binary: Callable[..., Path], tg_client: TGClient
) -> Callable[[str], Env]:
    def _make(seed_text: str) -> Env:
        return Env(
            tmp_path, seed_text, gateway_binary(), Capabilities(gateway_version="2.0.0"), tg_client
        )

    return _make


def _only_resource(server: FakeTGServer, kind: str) -> Any:
    [resource] = [r for r in server.resources.values() if r.kind == kind]
    return resource


def _readiness_logs(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in logs if e["event"] == "reconcile.webapp_readiness"]


async def _settled(env: Env) -> ReconcileResult:
    """Two passes: the first creates, the second lists what the first created."""
    await env.reconciler.reconcile("startup")
    return await env.reconciler.reconcile("tick")


def _break_readiness(monkeypatch: pytest.MonkeyPatch) -> None:
    import gwops.webapp_readiness as readiness

    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("readiness exploded")

    for module in (readiness, core):
        if hasattr(module, "compute_readiness"):
            monkeypatch.setattr(module, "compute_readiness", boom)


def _raise_os_error(*args: object, **kwargs: object) -> None:
    raise OSError(f"permission denied {_PEM_MARKER}")


class TestRemoteSnapshot:
    async def test_a_settled_pass_snapshots_the_managed_web_app(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """Every setting the listing reports is in the snapshot, header names only."""
        env = make_env(
            _seed(
                web_apps=[
                    _grafana(
                        alias="grafana.alt.internal",
                        upstream_tls="verify_ca",
                        downstream={"tls": "none", "port": 8080},
                        request_headers={"X-Env": _HEADER_VALUE},
                    )
                ]
            )
        )

        result = await _settled(env)

        assert result.remote_web_apps is not None
        [app] = result.remote_web_apps
        web = _only_resource(tg_server, "webapp")
        assert app.id == web.id
        assert app.name == "grafana"
        assert app.gateway_id == "g-1"
        assert app.address == "grafana.corp.internal"
        assert app.alias == "grafana.alt.internal"
        assert app.upstream_tls == "verify_ca"
        assert app.downstream_tls == "none"
        assert app.downstream_port == 8080
        assert tuple(app.header_rewrite_names) == ("x-env",)
        assert app.managed is True
        assert _HEADER_VALUE not in repr(result.remote_web_apps)

    async def test_unmanaged_apps_on_any_gateway_are_listed_as_unmanaged(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """Strangers appear with managed False and their own gateway and modes."""
        tg_server.add_web_app(
            "stranger", "stranger.corp.internal", "g-other", upstream_port=8443,
            upstream_tls="INSECURE", downstream_tls="NONE", downstream_port=80,
            rewrites=[{"key": "X-Trusted", "value": _STRANGER_VALUE}],
        )
        env = make_env(_seed(web_apps=[_grafana()]))

        result = await _settled(env)

        assert result.remote_web_apps is not None
        by_name = {app.name: app for app in result.remote_web_apps}
        assert set(by_name) == {"grafana", "stranger"}
        stranger = by_name["stranger"]
        assert stranger.managed is False
        assert stranger.gateway_id == "g-other"
        assert stranger.address == "stranger.corp.internal"
        assert stranger.upstream_port == 8443
        assert by_name["grafana"].upstream_port == 443
        assert (stranger.upstream_tls, stranger.downstream_tls) == ("insecure", "none")
        assert (stranger.downstream_port, by_name["grafana"].downstream_port) == (80, 443)
        assert tuple(stranger.header_rewrite_names) == ("x-trusted",)
        assert _STRANGER_VALUE not in repr(result.remote_web_apps)

    async def test_other_resource_kinds_are_not_in_the_snapshot(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """SSH and Kubernetes resources never appear in the web-app snapshot."""
        tg_server.add_resource("ssh", "stranger-ssh", "10.9.9.9", "g-1")
        env = make_env(_seed(web_apps=[_grafana()], ssh=True))

        result = await _settled(env)

        assert result.remote_web_apps is not None
        assert [app.name for app in result.remote_web_apps] == ["grafana"]

    async def test_the_snapshot_is_the_listing_so_a_corrected_gateway_shows_its_old_value(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """A gateway corrected during the pass is still listed on the gateway it was found on."""
        env = make_env(_seed(web_apps=[_grafana()]))
        await _settled(env)
        _only_resource(tg_server, "webapp").gateway_id = "g-other"

        result = await env.reconciler.reconcile("tick")

        assert result.gateway_mismatches["webapp/grafana"].corrected is True
        assert result.remote_web_apps is not None
        [app] = result.remote_web_apps
        assert app.gateway_id == "g-other"

    async def test_an_outage_leaves_the_snapshot_none_and_the_local_steps_running(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """The tenant not being listed means None, never an empty list, and no exception."""
        env = make_env(_seed(web_apps=[_grafana()]))
        await _settled(env)
        tg_server.fail = True

        result = await env.reconciler.reconcile("tick")

        assert result.remote_web_apps is None
        assert result.tg_unavailable is True
        assert result.local_ok is True
        assert env.reconciler.last_result is result

    @pytest.mark.parametrize("error", [KeyError("k"), RuntimeError("r"), IndexError("i")])
    async def test_a_failing_snapshot_is_recorded_distinctly_and_never_fails_the_pass(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch, error: Exception,
    ) -> None:
        """The tenant listed but the snapshot raised: None plus the error type, pass untouched."""
        env = make_env(_seed(web_apps=[_grafana()]))
        baseline = await _settled(env)
        assert baseline.remote_web_apps_error is None

        def boom(*_args: object, **_kwargs: object) -> None:
            raise error

        monkeypatch.setattr(core, "_web_app_snapshot", boom)

        result = await env.reconciler.reconcile("tick")

        assert result.remote_web_apps is None
        assert result.remote_web_apps_error == type(error).__name__
        assert result.tg_unavailable is False
        assert result.errors == []
        assert result.ok is True
        assert result.local_ok is True
        assert "webapp/grafana" in result.tg_synced
        assert any(type(error).__name__ in w for w in result.webapp_warnings)

    async def test_an_outage_is_not_a_snapshot_error(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """No listing at all leaves the snapshot error unset."""
        env = make_env(_seed(web_apps=[_grafana()]))
        await _settled(env)
        tg_server.fail = True

        result = await env.reconciler.reconcile("tick")

        assert result.remote_web_apps is None
        assert result.remote_web_apps_error is None

    async def test_a_pass_with_no_api_key_has_no_snapshot(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        """Without a TG client there is no listing at all."""
        env = Env(
            tmp_path, _seed(web_apps=[_grafana()]), gateway_binary(),
            Capabilities(gateway_version="2.0.0"), None,
        )

        result = await env.reconciler.reconcile("startup")

        assert result.remote_web_apps is None


class TestWebappWarnings:
    @pytest.mark.parametrize(
        ("fields", "needle"),
        [
            ({"upstream_tls": "verify_ca"}, "verify_ca"),
            ({"upstream_tls": "insecure"}, "insecure"),
            ({"upstream_tls": "none"}, "upstream_tls 'none'"),
            ({"downstream": {"tls": "none"}}, "downstream.tls 'none'"),
        ],
        ids=["verify_ca", "insecure", "upstream-none", "downstream-none"],
    )
    async def test_each_warning_class_is_reported_and_does_not_fail_the_pass(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer,
        fields: dict[str, Any], needle: str,
    ) -> None:
        """Weakening settings surface as warnings; the pass stays ok."""
        env = make_env(_seed(web_apps=[_grafana(**fields)], extra=_ALLOW_CORP))

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []
        assert result.ok is True
        [warning] = result.webapp_warnings
        assert needle in warning
        assert "'grafana'" in warning

    async def test_a_clean_seed_has_no_warnings(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """verify_full over tls13 warns about nothing."""
        env = make_env(_seed(web_apps=[_grafana()]))

        result = await env.reconciler.reconcile("startup")

        assert result.webapp_warnings == []

    async def test_the_set_is_reported_on_every_pass_not_only_when_it_changes(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """Unlike the log line, the result carries the full current set each pass."""
        env = make_env(_seed(web_apps=[_grafana(upstream_tls="verify_ca")]))

        first = await env.reconciler.reconcile("startup")
        second = await env.reconciler.reconcile("tick")
        third = await env.reconciler.reconcile("tick")

        assert first.webapp_warnings
        assert second.webapp_warnings == first.webapp_warnings
        assert third.webapp_warnings == first.webapp_warnings

    async def test_removing_the_weak_setting_clears_the_set(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """The set tracks the current state, not a history."""
        env = make_env(_seed(web_apps=[_grafana(upstream_tls="verify_ca")]))
        await env.reconciler.reconcile("startup")
        env.seed_path.write_text(_seed(web_apps=[_grafana()]), encoding="utf-8")

        result = await env.reconciler.reconcile("tick")

        assert result.webapp_warnings == []


class TestPassVerdictUnaffected:
    async def test_warnings_mismatches_and_unmanaged_apps_do_not_fail_a_pass(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """Warnings, an uncorrected SSH mismatch and an unmanaged web app leave ok True."""
        env = make_env(_seed(web_apps=[_grafana(upstream_tls="verify_ca")], ssh=True))
        await _settled(env)
        _only_resource(tg_server, "ssh").gateway_id = "g-other"
        tg_server.add_web_app("stranger", "stranger.corp.internal", "g-1")

        result = await env.reconciler.reconcile("tick")

        assert result.errors == []
        assert result.ok is True
        assert result.local_ok is True
        assert result.gateway_mismatches["ssh/web-1"].corrected is False
        assert result.webapp_warnings

    async def test_a_failing_readiness_computation_does_not_fail_a_pass(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An exception in the readiness step is contained."""
        env = make_env(_seed(web_apps=[_grafana()]))
        await _settled(env)
        _break_readiness(monkeypatch)

        result = await env.reconciler.reconcile("tick")

        assert result.errors == []
        assert result.ok is True
        assert result.local_ok is True
        assert env.reconciler.last_result is result


class TestHousekeepingErrors:
    async def test_a_clean_pass_has_none(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """No failure, no entries."""
        env = make_env(_seed(web_apps=[_grafana()]))

        result = await env.reconciler.reconcile("startup")

        assert result.housekeeping_errors == []

    async def test_a_gc_failure_is_recorded_per_directory_without_the_exception_text(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Both garbage-collected directories fail: two messages, no secrets, pass still ok."""
        env = make_env(_seed(web_apps=[_grafana()]))
        monkeypatch.setattr(core, "collect_garbage", _raise_os_error)

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []
        assert result.ok is True
        assert result.local_ok is True
        assert len(result.housekeeping_errors) == 2
        assert len(set(result.housekeeping_errors)) == 2
        for message in result.housekeeping_errors:
            assert message
            assert "BEGIN" not in message
            assert "marker-secret" not in message

    async def test_a_legacy_cleanup_failure_is_recorded(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failed legacy credential directory cleanup adds one message."""
        env = make_env(_seed(web_apps=[_grafana()]))
        monkeypatch.setattr(core, "remove_legacy_credential_dirs", _raise_os_error)

        result = await env.reconciler.reconcile("startup")

        assert result.errors == []
        assert result.ok is True
        [message] = result.housekeeping_errors
        assert "marker-secret" not in message

    async def test_both_failures_add_up(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """GC (two directories) plus legacy cleanup is three messages."""
        env = make_env(_seed(web_apps=[_grafana()]))
        monkeypatch.setattr(core, "collect_garbage", _raise_os_error)
        monkeypatch.setattr(core, "remove_legacy_credential_dirs", _raise_os_error)

        result = await env.reconciler.reconcile("startup")

        assert len(result.housekeeping_errors) == 3

    async def test_the_next_clean_pass_clears_them(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The list reflects the latest pass only."""
        env = make_env(_seed(web_apps=[_grafana()]))
        with monkeypatch.context() as patched:
            patched.setattr(core, "collect_garbage", _raise_os_error)
            failed = await env.reconciler.reconcile("startup")
        assert failed.housekeeping_errors

        result = await env.reconciler.reconcile("tick")

        assert result.housekeeping_errors == []

    async def test_returned_gc_failures_are_recorded_per_directory(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A GC that reports a skipped or failed step puts it in housekeeping_errors."""
        env = make_env(_seed(web_apps=[_grafana()]))
        reported = CleanupResult([], ["could not remove corp-0123456789ab.pem (PermissionError)"])
        monkeypatch.setattr(core, "collect_garbage", lambda *_a, **_k: reported)

        result = await env.reconciler.reconcile("startup")

        assert result.ok is True
        assert len(result.housekeeping_errors) == 2
        assert len(set(result.housekeeping_errors)) == 2
        assert all("PermissionError" in m for m in result.housekeeping_errors)

    async def test_returned_legacy_cleanup_failures_are_recorded(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A legacy cleanup that skipped itself is a housekeeping error, not silence."""
        env = make_env(_seed(web_apps=[_grafana()]))
        reported = CleanupResult([], ["skipped: config config.yaml unreadable (PermissionError)"])
        monkeypatch.setattr(core, "remove_legacy_credential_dirs", lambda *_a, **_k: reported)

        result = await env.reconciler.reconcile("startup")

        [message] = result.housekeeping_errors
        assert "skipped" in message

    @pytest.mark.parametrize("error", [ValueError("boom"), RuntimeError("boom"), TypeError("boom")])
    async def test_a_non_oserror_in_housekeeping_is_contained_and_recorded_by_type(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch, error: Exception,
    ) -> None:
        """A parser failure that is not a YAMLError never aborts the pass or deletes anything."""
        env = make_env(_seed(web_apps=[_grafana()]))
        await env.reconciler.reconcile("startup")
        stale = env.paths.upstream_ca_dir / "corp-0123456789ab.pem"
        stale.parent.mkdir(parents=True, exist_ok=True)
        stale.write_text("unreferenced", encoding="utf-8")

        def boom(*_args: object, **_kwargs: object) -> None:
            raise error

        # Only confined's view of yaml: the seed loader keeps the real parser.
        monkeypatch.setattr(
            confined, "yaml", SimpleNamespace(safe_load=boom, YAMLError=yaml.YAMLError)
        )

        result = await env.reconciler.reconcile("tick")

        assert result.errors == []
        assert result.ok is True
        assert result.housekeeping_ran is True
        assert stale.exists()
        assert result.housekeeping_errors
        assert all(type(error).__name__ in m for m in result.housekeeping_errors)
        assert not any("boom" in m for m in result.housekeeping_errors)

    async def test_a_pass_that_ran_housekeeping_says_so(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """housekeeping_ran is True after a fully local-ok pass."""
        env = make_env(_seed(web_apps=[_grafana()]))

        result = await env.reconciler.reconcile("startup")

        assert result.housekeeping_ran is True

    async def test_a_pass_without_housekeeping_carries_the_previous_errors_forward(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When GC did not run this pass, the last known errors are still reported."""
        env = make_env(_seed(web_apps=[_grafana()]))
        with monkeypatch.context() as patched:
            patched.setattr(core, "collect_garbage", _raise_os_error)
            failed = await env.reconciler.reconcile("startup")
        assert failed.housekeeping_errors
        env.seed_path.write_text("not: [valid", encoding="utf-8")

        result = await env.reconciler.reconcile("tick")

        assert result.local_ok is False
        assert result.housekeeping_ran is False
        assert result.housekeeping_errors == failed.housekeeping_errors


class TestReadinessLogging:
    async def test_it_is_logged_once_when_the_set_changes_and_not_on_every_pass(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """Identical passes log nothing; an appearing and a disappearing app log once each."""
        env = make_env(_seed(web_apps=[_grafana()]))
        await _settled(env)

        with structlog.testing.capture_logs() as logs:
            for _ in range(3):
                await env.reconciler.reconcile("tick")
        assert _readiness_logs(logs) == []

        stranger = tg_server.add_web_app("stranger", "stranger.corp.internal", "g-1")
        with structlog.testing.capture_logs() as logs:
            for _ in range(3):
                await env.reconciler.reconcile("tick")
        assert len(_readiness_logs(logs)) == 1

        del tg_server.resources[stranger]
        with structlog.testing.capture_logs() as logs:
            for _ in range(2):
                await env.reconciler.reconcile("tick")
        assert len(_readiness_logs(logs)) == 1

    async def test_the_first_report_of_a_new_app_is_logged(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """The declared app is first reported as not on the tenant, then as the listed app."""
        env = make_env(_seed(web_apps=[_grafana()]))

        with structlog.testing.capture_logs() as logs:
            await _settled(env)
            await env.reconciler.reconcile("tick")

        first, second = _readiness_logs(logs)
        assert first["apps"][0]["reasons"] == ["not_on_tenant"]
        assert "not_on_tenant" not in second["apps"][0]["reasons"]

    async def test_an_outage_pass_neither_logs_nor_resets_the_remembered_set(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """A pass that could not list the tenant says nothing; recovery is not a change."""
        env = make_env(_seed(web_apps=[_grafana()]))
        await _settled(env)

        with structlog.testing.capture_logs() as logs:
            tg_server.fail = True
            await env.reconciler.reconcile("tick")
            tg_server.fail = False
            await env.reconciler.reconcile("tick")
        assert _readiness_logs(logs) == []

        tg_server.add_web_app("stranger", "stranger.corp.internal", "g-1")
        with structlog.testing.capture_logs() as logs:
            await env.reconciler.reconcile("tick")
        assert len(_readiness_logs(logs)) == 1

    async def test_the_log_carries_no_header_values(
        self, make_env: Callable[[str], Env], tg_server: FakeTGServer
    ) -> None:
        """Neither declared nor tenant-side header values reach the readiness log."""
        tg_server.add_web_app(
            "stranger", "stranger.corp.internal", "g-1",
            rewrites=[{"key": "X-Trusted", "value": _STRANGER_VALUE}],
        )
        env = make_env(_seed(web_apps=[_grafana(request_headers={"X-Env": _HEADER_VALUE})]))

        with structlog.testing.capture_logs() as logs:
            await _settled(env)

        assert _readiness_logs(logs)
        assert _HEADER_VALUE not in repr(logs)
        assert _STRANGER_VALUE not in repr(logs)
