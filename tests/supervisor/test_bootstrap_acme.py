"""``bootstrap`` and teardown with ``source: acme`` certificates.

ACME certificates are exempt from the public-mode startup abort: nothing installed is
``pending``, installed material the validator refuses is logged and treated as pending, and a
missing DNS token file is logged. A ``source: file`` certificate that is refused still aborts.
The runner shares the reconciler's public store, sets ``api_event`` when material lands, and is
closed before the gateway child stops.
"""

import dataclasses
import os
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import structlog.testing
import yaml

import gwops.renderer.render as render_module
import gwops.supervisor.main as main_module
from gwops.configmodel.loader import load_effective_state
from gwops.configmodel.schema import EffectiveState
from gwops.configmodel.store import OverlayStore
from gwops.reconciler import core
from gwops.reconciler.core import AcmeError, Reconciler, ReconcileResult
from gwops.renderer.render import RuntimePaths
from gwops.supervisor.main import BootstrapResult, bootstrap
from gwops.supervisor.process import ProcState
from tests.public_chain_support import (
    Issued,
    ec_key,
    key_pem_of,
    other_hierarchy,
    rsa_hierarchy,
)
from tests.public_tls_support import ZONE, load, public_cert, public_seed, ssh, tls_block
from tests.reconciler.public_certs_support import DAY

from .test_main import _settings

ROOT = rsa_hierarchy().root
ACME_BLOCK = {"email": "ops@example.com", "accept_tos": True, "directory": "staging"}
HOST = f"alpha.{ZONE}"

type Boot = Callable[..., Awaitable[BootstrapResult]]

# Tests that start the real fake-gateway child stop it at teardown, which needs POSIX signal
# semantics (the same condition tests/supervisor/test_main.py uses).
_posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="requires POSIX signal semantics"
)


@pytest.fixture(autouse=True)
def _public_mode_stubs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The generated root, a tmp confined source root, and (win32) the symlink-free store."""
    monkeypatch.setattr(main_module, "resolve_registered_root", lambda name: ROOT)
    monkeypatch.setattr(core, "resolve_registered_root", lambda name: ROOT)
    source_root = tmp_path / "public-tls-src"
    source_root.mkdir()
    monkeypatch.setattr(render_module, "PUBLIC_TLS_ROOT", source_root)
    if sys.platform == "win32":
        from tests.store_support import PlainFileStore

        monkeypatch.setattr(main_module, "MaterialStore", PlainFileStore)
    # The Cloudflare-environment warning reads os.environ: start every test without them.
    for name in [n for n in os.environ if n.startswith(("CF_", "CLOUDFLARE_"))]:
        monkeypatch.delenv(name)


@pytest.fixture
def source_root(tmp_path: Path) -> Path:
    return tmp_path / "public-tls-src"


@pytest.fixture
async def boot() -> AsyncIterator[Boot]:
    """``bootstrap`` that tears each result down after the test (child stopped, clients closed)."""
    results: list[BootstrapResult] = []

    async def _boot(settings: Any) -> BootstrapResult:
        result = await bootstrap(settings)
        results.append(result)
        return result

    yield _boot
    for result in results:
        await main_module._teardown(result, admin=None)


def _leaf(names: list[str] | None = None, *, issuer_other: bool = False) -> Issued:
    now = datetime.now(UTC)
    hierarchy = other_hierarchy() if issuer_other else rsa_hierarchy()
    return hierarchy.issue(
        names if names is not None else [HOST],
        not_before=now - 10 * DAY,
        not_after=now + 80 * DAY,
    )


def _acme_seed(
    extra_certs: list[dict[str, Any]] | None = None,
    *,
    directory: str = "staging",
    upstream_hosts: list[str] | None = None,
) -> str:
    entries = [
        {"name": "alpha", "names": [HOST], "source": "acme"},
        *(extra_certs or []),
    ]
    seed = public_seed(
        {**tls_block(certificates=entries), "acme": {**ACME_BLOCK, "directory": directory}},
        ssh_upstreams=[
            ssh(f"h{i}", f"{h}:22")
            for i, h in enumerate([HOST] if upstream_hosts is None else upstream_hosts)
        ],
    )
    return yaml.safe_dump(seed, sort_keys=False)


def _install(settings: Any, issued: Issued, name: str = "alpha") -> None:
    """Put material in the store the way a finished ACME run would have left it."""
    store = main_module.MaterialStore(settings.data_dir / "public-tls")
    store.install(name, issued.cert_pem, issued.key_pem)


class TestFreshAcmeOnlySeed:
    async def test_it_bootstraps_without_raising_and_waits_for_acme(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, boot: Boot
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())

        with structlog.testing.capture_logs() as logs:
            result = await boot(settings)

        assert result.gateway_started is False
        assert result.process.state is ProcState.STOPPED
        assert not (settings.runtime_dir / "config.yaml").exists()
        assert result.reconciler.last_result is not None
        assert result.reconciler.last_result.local_ok is True
        assert result.reconciler.last_result.acme_pending == ["alpha"]
        [waiting] = [e for e in logs if e["event"] == "supervisor.waiting_for_acme"]
        assert waiting["certificates"] == ["alpha"]
        assert not [e for e in logs if e["event"] == "supervisor.waiting_for_upstreams"]

    async def test_the_runner_is_built_and_shares_the_reconcilers_store(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, boot: Boot
    ) -> None:
        result = await boot(_settings(tmp_path, fake_gateway(), _acme_seed()))

        assert result.acme is not None
        assert result.acme._store is result.reconciler._public_store  # type: ignore[attr-defined]

    async def test_an_installed_certificate_makes_the_runner_set_the_api_event(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        captured: dict[str, Any] = {}
        real = main_module.AcmeRunner

        class Recording(real):  # type: ignore[valid-type, misc]
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                captured.update(kwargs)
                super().__init__(*args, **kwargs)

        monkeypatch.setattr(main_module, "AcmeRunner", Recording)
        result = await boot(_settings(tmp_path, fake_gateway(), _acme_seed()))
        assert not result.api_event.is_set()

        captured["on_installed"]("alpha")

        assert result.api_event.is_set()

    @_posix_only
    async def test_installed_valid_material_lets_the_gateway_start(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, boot: Boot
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())
        _install(settings, _leaf())

        result = await boot(settings)

        assert result.gateway_started is True
        assert result.reconciler.last_result is not None
        assert result.reconciler.last_result.acme_pending == []


class TestInstalledMaterialRefused:
    async def test_it_is_logged_as_pending_and_does_not_abort_startup(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, boot: Boot
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())
        _install(settings, _leaf(issuer_other=True))

        with structlog.testing.capture_logs() as logs:
            result = await boot(settings)

        [refused] = [
            e for e in logs if e["event"] == "supervisor.acme_installed_material_refused"
        ]
        assert refused["log_level"] == "error"
        assert refused["certificate"] == "alpha"
        assert refused["status"] == "pending"
        assert result.gateway_started is False
        assert result.reconciler.last_result is not None
        assert result.reconciler.last_result.local_ok is True
        assert result.reconciler.last_result.acme_pending == ["alpha"]

    async def test_the_log_carries_no_key_or_certificate_contents(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, boot: Boot
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())
        bad = _leaf(issuer_other=True)
        _install(settings, bad)

        with structlog.testing.capture_logs() as logs:
            await boot(settings)

        [refused] = [
            e for e in logs if e["event"] == "supervisor.acme_installed_material_refused"
        ]
        assert "BEGIN" not in refused["error"] and "PRIVATE KEY" not in refused["error"]

    async def test_a_pending_certificate_is_logged_as_a_warning_not_an_error(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, boot: Boot
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())

        with structlog.testing.capture_logs() as logs:
            await boot(settings)

        [pending] = [e for e in logs if e["event"] == "supervisor.acme_certificate_pending"]
        assert pending["log_level"] == "warning"
        assert pending["certificate"] == "alpha"
        assert not [e for e in logs if e["event"] == "supervisor.acme_installed_material_refused"]


class TestFileCertificateStillAborts:
    async def test_a_refused_file_certificate_aborts_startup_and_names_only_it(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, source_root: Path
    ) -> None:
        file_leaf = _leaf([f"beta.{ZONE}"])
        (source_root / "beta").mkdir()
        (source_root / "beta" / "fullchain.pem").write_bytes(file_leaf.cert_pem)
        (source_root / "beta" / "privkey.pem").write_bytes(key_pem_of(ec_key()))  # wrong key
        beta = public_cert(
            "beta",
            [f"beta.{ZONE}"],
            cert_file=str(source_root / "beta" / "fullchain.pem"),
            key_file=str(source_root / "beta" / "privkey.pem"),
        )
        settings = _settings(tmp_path, fake_gateway(), _acme_seed([beta]))
        _install(settings, _leaf(issuer_other=True))  # the ACME side is refused too

        with pytest.raises(ValueError) as caught:
            await bootstrap(settings)

        lines = str(caught.value).splitlines()
        assert lines[0] == "public certificate material refused (1 certificate(s)):"
        assert len(lines) == 2
        assert lines[1].startswith("- public certificate 'beta':")
        assert "alpha" not in str(caught.value)
        assert not (settings.runtime_dir / "config.yaml").exists()

    @_posix_only
    async def test_a_valid_file_certificate_beside_a_pending_acme_one_starts_the_gateway(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, source_root: Path, boot: Boot
    ) -> None:
        file_leaf = _leaf([f"beta.{ZONE}"])
        (source_root / "beta").mkdir()
        (source_root / "beta" / "fullchain.pem").write_bytes(file_leaf.cert_pem)
        (source_root / "beta" / "privkey.pem").write_bytes(file_leaf.key_pem)
        beta = public_cert(
            "beta",
            [f"beta.{ZONE}"],
            cert_file=str(source_root / "beta" / "fullchain.pem"),
            key_file=str(source_root / "beta" / "privkey.pem"),
        )
        settings = _settings(tmp_path, fake_gateway(), _acme_seed([beta]))

        result = await boot(settings)

        assert result.gateway_started is True
        assert result.reconciler.last_result is not None
        assert result.reconciler.last_result.acme_pending == ["alpha"]


class TestTokenFile:
    async def test_a_missing_token_file_is_logged_and_does_not_abort_startup(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, boot: Boot
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())  # /config/acme/ is absent

        with structlog.testing.capture_logs() as logs:
            result = await boot(settings)

        [problem] = [e for e in logs if e["event"] == "supervisor.acme_token_file_unusable"]
        assert problem["log_level"] == "error"
        assert "/config/acme/cloudflare-token" in problem["problem"]
        assert "does not exist" in problem["problem"]
        assert result.gateway_started is False
        assert result.reconciler.last_result is not None
        assert result.reconciler.last_result.local_ok is True

    async def test_a_token_file_that_exists_logs_no_problem(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        monkeypatch.setattr(main_module, "token_file_problem", lambda settings: None)
        monkeypatch.setattr(core, "token_file_problem", lambda settings: None)
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())

        with structlog.testing.capture_logs() as logs:
            await boot(settings)

        assert not [e for e in logs if "token_file_unusable" in e["event"]]

    @_posix_only
    async def test_a_seed_without_acme_certificates_never_checks_the_token(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        source_root: Path,
        boot: Boot,
    ) -> None:
        def _forbidden(settings: object) -> None:
            raise AssertionError("no source: acme certificate, so no token check")

        monkeypatch.setattr(main_module, "token_file_problem", _forbidden)
        file_leaf = _leaf([HOST])
        (source_root / "alpha").mkdir()
        (source_root / "alpha" / "fullchain.pem").write_bytes(file_leaf.cert_pem)
        (source_root / "alpha" / "privkey.pem").write_bytes(file_leaf.key_pem)
        alpha = public_cert(
            "alpha",
            [HOST],
            cert_file=str(source_root / "alpha" / "fullchain.pem"),
            key_file=str(source_root / "alpha" / "privkey.pem"),
        )
        seed = public_seed(
            tls_block(certificates=[alpha]), ssh_upstreams=[ssh("h0", f"{HOST}:22")]
        )
        settings = _settings(tmp_path, fake_gateway(), yaml.safe_dump(seed, sort_keys=False))

        result = await boot(settings)

        assert result.gateway_started is True


class _Recorder:
    """Appends to a shared list so the order of teardown steps can be asserted."""

    def __init__(self, order: list[str]) -> None:
        self.order = order


class _FakeAcme(_Recorder):
    def __init__(self, order: list[str], *, raises: bool = False) -> None:
        super().__init__(order)
        self.raises = raises

    async def aclose(self) -> None:
        self.order.append("acme.aclose")
        if self.raises:
            raise RuntimeError("close failed")


class _FakeAdmin(_Recorder):
    async def stop(self) -> None:
        self.order.append("admin.stop")


class _FakeProcess(_Recorder):
    state = ProcState.RUNNING

    async def stop(self, timeout: float = 30.0) -> None:
        self.order.append("process.stop")
        self.state = ProcState.STOPPED


class TestTeardown:
    async def _teardown(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, *, close_raises: bool = False
    ) -> list[str]:
        result = await bootstrap(_settings(tmp_path, fake_gateway(), _acme_seed()))
        order: list[str] = []
        result.acme = _FakeAcme(order, raises=close_raises)  # type: ignore[assignment]
        result.process = _FakeProcess(order)  # type: ignore[assignment]
        await main_module._teardown(result, admin=_FakeAdmin(order))  # type: ignore[arg-type]
        return order

    async def test_the_runner_is_closed_before_the_admin_server_and_the_gateway_stop(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        order = await self._teardown(fake_gateway, tmp_path)

        assert order == ["acme.aclose", "admin.stop", "process.stop"]

    async def test_a_runner_that_fails_to_close_does_not_stop_the_rest_of_teardown(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        with structlog.testing.capture_logs() as logs:
            order = await self._teardown(fake_gateway, tmp_path, close_raises=True)

        assert order == ["acme.aclose", "admin.stop", "process.stop"]
        [failed] = [e for e in logs if e["event"] == "acme.close_failed"]
        assert failed["error_type"] == "RuntimeError"

    async def test_teardown_without_a_runner_still_stops_the_gateway(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        result = await bootstrap(_settings(tmp_path, fake_gateway(), _acme_seed()))
        order: list[str] = []
        result.acme = None
        result.process = _FakeProcess(order)  # type: ignore[assignment]

        await main_module._teardown(result, admin=_FakeAdmin(order))  # type: ignore[arg-type]

        assert order == ["admin.stop", "process.stop"]


class TestRunnerConstructionFailure:
    async def test_the_runner_is_none_and_startup_continues(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        def _broken(*args: object, **kwargs: object) -> None:
            raise OSError("cannot create /data/acme")

        monkeypatch.setattr(main_module, "AcmeRunner", _broken)

        with structlog.testing.capture_logs() as logs:
            result = await boot(_settings(tmp_path, fake_gateway(), _acme_seed()))

        assert result.acme is None
        [unavailable] = [e for e in logs if e["event"] == "acme.runner_unavailable"]
        assert unavailable["log_level"] == "error"
        assert unavailable["error_type"] == "OSError"
        assert result.reconciler.last_result is not None
        assert result.reconciler.last_result.local_ok is True
        assert result.reconciler.last_result.acme_pending == ["alpha"]
        assert result.gateway_started is False

    async def test_the_reason_is_carried_to_the_result_the_deps_and_the_reconciler(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        def _broken(*args: object, **kwargs: object) -> None:
            raise OSError("cannot create /data/acme")

        monkeypatch.setattr(main_module, "AcmeRunner", _broken)

        result = await boot(_settings(tmp_path, fake_gateway(), _acme_seed()))

        assert result.acme_unavailable == "OSError: cannot create /data/acme"
        assert result.deps is not None
        assert result.deps.acme is None
        assert result.deps.acme_unavailable == "OSError: cannot create /data/acme"
        assert result.reconciler._acme_unavailable == "OSError: cannot create /data/acme"  # type: ignore[attr-defined]

    async def test_the_first_pass_reports_it_as_an_internal_acme_error(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        def _broken(*args: object, **kwargs: object) -> None:
            raise OSError("cannot create /data/acme")

        monkeypatch.setattr(main_module, "AcmeRunner", _broken)

        with structlog.testing.capture_logs() as logs:
            result = await boot(_settings(tmp_path, fake_gateway(), _acme_seed()))

        last = result.reconciler.last_result
        assert last is not None
        assert (
            AcmeError(
                None, "internal", "ACME runner unavailable: OSError: cannot create /data/acme"
            )
            in last.acme_errors
        )
        assert last.local_ok is True
        assert len([e for e in logs if e["event"] == "reconcile.acme_runner_unavailable"]) == 1

    async def test_a_long_reason_is_cut_to_three_hundred_characters(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        def _broken(*args: object, **kwargs: object) -> None:
            raise OSError("x" * 500)

        monkeypatch.setattr(main_module, "AcmeRunner", _broken)

        result = await boot(_settings(tmp_path, fake_gateway(), _acme_seed()))

        assert result.acme_unavailable is not None
        assert len(result.acme_unavailable) == 300
        assert result.acme_unavailable.startswith("OSError: xxx")

    async def test_a_runner_that_was_built_leaves_the_reason_empty(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, boot: Boot
    ) -> None:
        result = await boot(_settings(tmp_path, fake_gateway(), _acme_seed()))

        assert result.acme is not None
        assert result.acme_unavailable is None
        assert result.deps is not None and result.deps.acme_unavailable is None
        last = result.reconciler.last_result
        assert last is not None
        assert not any("runner unavailable" in e.detail for e in last.acme_errors)

    @_posix_only
    async def test_an_installed_certificate_still_starts_the_gateway_without_a_runner(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        def _broken(*args: object, **kwargs: object) -> None:
            raise OSError("cannot create /data/acme")

        monkeypatch.setattr(main_module, "AcmeRunner", _broken)
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())
        _install(settings, _leaf())

        result = await boot(settings)

        assert result.acme is None
        assert result.gateway_started is True


# --- stale or mismatched installed material --------------------------------------------------

BETA_HOST = f"beta.{ZONE}"
GAMMA_HOST = f"gamma.{ZONE}"
DELTA_HOST = f"delta.{ZONE}"


def _state_of(settings: Any) -> EffectiveState:
    state, _provenance = load_effective_state(
        settings.seed_path, OverlayStore(settings.data_dir / "overlays")
    )
    return state


def _file_cert(source_root: Path, name: str, issued: Issued, names: list[str]) -> dict[str, Any]:
    """Write `issued` under the confined source root and return its ``source: file`` entry."""
    directory = source_root / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "fullchain.pem").write_bytes(issued.cert_pem)
    (directory / "privkey.pem").write_bytes(issued.key_pem)
    return public_cert(
        name,
        names,
        cert_file=str(directory / "fullchain.pem"),
        key_file=str(directory / "privkey.pem"),
    )


def _validate(
    settings: Any, source_root: Path, store: Any = None
) -> tuple[list[str], Any]:
    """Run the startup material check directly; returns ``(invalid ACME names, the store)``."""
    paths = dataclasses.replace(RuntimePaths.from_settings(settings), public_tls_root=source_root)
    store = store if store is not None else main_module.MaterialStore(paths.public_tls_dir)
    invalid = main_module._validate_public_material(_state_of(settings), paths, ROOT, store)
    return invalid, store


def _events(logs: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    return [e for e in logs if e["event"] == name]


class TestValidatePublicMaterialForAcme:
    """``_validate_public_material``: ACME certificates are judged from the store, never fatal."""

    def test_nothing_installed_is_pending_and_flags_nothing_invalid(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, source_root: Path
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())

        with structlog.testing.capture_logs() as logs:
            invalid, _store = _validate(settings, source_root)

        assert invalid == []
        [pending] = _events(logs, "supervisor.acme_certificate_pending")
        assert pending["log_level"] == "warning"
        assert "detail" not in pending

    def test_valid_material_flags_nothing_and_logs_no_problem(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, source_root: Path
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())
        _install(settings, _leaf())

        with structlog.testing.capture_logs() as logs:
            invalid, _store = _validate(settings, source_root)

        assert invalid == []
        for event in (
            "supervisor.acme_certificate_pending",
            "supervisor.acme_installed_material_refused",
            "supervisor.acme_installed_material_unexpected",
            "supervisor.acme_san_overlap",
        ):
            assert not _events(logs, event), event

    def test_refused_material_is_flagged_for_the_runner_and_never_raises(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, source_root: Path
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())
        _install(settings, _leaf(issuer_other=True))

        with structlog.testing.capture_logs() as logs:
            invalid, _store = _validate(settings, source_root)

        assert invalid == ["alpha"]
        [refused] = _events(logs, "supervisor.acme_installed_material_refused")
        assert (refused["log_level"], refused["status"]) == ("error", "pending")

    def test_unreadable_store_material_is_flagged_like_a_refusal(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, source_root: Path
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())
        _install(settings, _leaf())
        store = main_module.MaterialStore(settings.data_dir / "public-tls")

        def _denied(name: str) -> None:
            raise PermissionError(13, "Permission denied", "/data/public-tls/alpha")

        store.read_current = _denied  # type: ignore[method-assign]

        with structlog.testing.capture_logs() as logs:
            invalid, _store = _validate(settings, source_root, store)

        assert invalid == ["alpha"]
        [refused] = _events(logs, "supervisor.acme_installed_material_refused")
        assert "the store cannot be read (PermissionError)" in refused["error"]
        assert "Permission denied" not in refused["error"]

    def test_an_unexpected_exception_is_flagged_logged_by_type_and_never_raises(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        source_root: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())
        _install(settings, _leaf())

        def _boom(*args: object, **kwargs: object) -> None:
            raise RuntimeError("secret-looking detail")

        monkeypatch.setattr(main_module, "read_installed_public_material", _boom)

        with structlog.testing.capture_logs() as logs:
            invalid, _store = _validate(settings, source_root)

        assert invalid == ["alpha"]
        [unexpected] = _events(logs, "supervisor.acme_installed_material_unexpected")
        assert unexpected["log_level"] == "error"
        assert unexpected["error_type"] == "RuntimeError"
        assert unexpected["status"] == "pending"
        assert unexpected["exc_info"] is True
        assert "secret-looking" not in str(unexpected)

    def test_material_for_changed_names_is_pending_flagged_and_logged_as_a_warning(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, source_root: Path
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())
        _install(settings, _leaf([HOST, GAMMA_HOST]))  # the seed declares only HOST now

        with structlog.testing.capture_logs() as logs:
            invalid, _store = _validate(settings, source_root)

        assert invalid == ["alpha"]
        [pending] = _events(logs, "supervisor.acme_certificate_pending")
        assert pending["log_level"] == "warning"
        assert pending["detail"] == "awaiting reissue for changed names"
        assert not _events(logs, "supervisor.acme_installed_material_refused")

    def test_old_acme_material_that_overlaps_a_file_certificate_never_aborts_startup(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, source_root: Path
    ) -> None:
        """SAN-mismatched old ACME material is left out of the overlap check."""
        beta_leaf = _leaf([BETA_HOST])
        beta = _file_cert(source_root, "beta", beta_leaf, [BETA_HOST])
        settings = _settings(
            tmp_path,
            fake_gateway(),
            _acme_seed([beta], upstream_hosts=[HOST, BETA_HOST]),
        )
        _install(settings, _leaf([HOST, BETA_HOST]))  # old leaf also matches beta's name

        with structlog.testing.capture_logs() as logs:
            invalid, _store = _validate(settings, source_root)  # must not raise

        assert invalid == ["alpha"]
        assert not _events(logs, "supervisor.acme_san_overlap")
        assert [e["detail"] for e in _events(logs, "supervisor.acme_certificate_pending")] == [
            "awaiting reissue for changed names"
        ]

    def test_a_file_leaf_over_an_acme_name_is_logged_as_an_overlap_not_fatal(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, source_root: Path
    ) -> None:
        beta_leaf = _leaf([BETA_HOST, HOST])  # beta's leaf also matches alpha's served name
        beta = _file_cert(source_root, "beta", beta_leaf, [BETA_HOST])
        settings = _settings(
            tmp_path, fake_gateway(), _acme_seed([beta], upstream_hosts=[HOST, BETA_HOST])
        )
        _install(settings, _leaf())

        with structlog.testing.capture_logs() as logs:
            invalid, _store = _validate(settings, source_root)  # must not raise

        assert invalid == []
        [overlap] = _events(logs, "supervisor.acme_san_overlap")
        assert overlap["log_level"] == "error"
        assert (overlap["covering"], overlap["other"]) == ("alpha", "beta")

    def test_an_overlap_between_two_file_certificates_still_aborts(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, source_root: Path
    ) -> None:
        gamma = _file_cert(source_root, "gamma", _leaf([GAMMA_HOST, DELTA_HOST]), [GAMMA_HOST])
        delta = _file_cert(source_root, "delta", _leaf([DELTA_HOST]), [DELTA_HOST])
        settings = _settings(
            tmp_path,
            fake_gateway(),
            _acme_seed([gamma, delta], upstream_hosts=[HOST, GAMMA_HOST, DELTA_HOST]),
        )

        with pytest.raises(ValueError, match="also matches it") as caught:
            _validate(settings, source_root)

        assert "alpha" not in str(caught.value)

    def test_each_certificate_is_read_once_from_one_generation_never_through_the_stable_paths(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, source_root: Path
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())
        _install(settings, _leaf())
        store = main_module.MaterialStore(settings.data_dir / "public-tls")
        real = store.read_current
        reads: list[str] = []

        def _counting(name: str) -> Any:
            reads.append(name)
            return real(name)

        def _forbidden(name: str) -> None:
            raise AssertionError("the stable paths must not be read: two reads can mix generations")

        store.read_current = _counting  # type: ignore[method-assign]
        store.stable_paths = _forbidden  # type: ignore[method-assign]

        invalid, _store = _validate(settings, source_root, store)

        assert invalid == []
        assert reads == ["alpha"]


class TestAcmeStartupWarnings:
    """``_warn_acme_startup``: a staging directory and ignored Cloudflare variables."""

    def _state(self, tmp_path: Path, *, directory: str = "staging", acme: bool = True) -> Any:
        entries: list[dict[str, Any]] = (
            [{"name": "alpha", "names": [HOST], "source": "acme"}]
            if acme
            else [public_cert("alpha", [HOST])]
        )
        block = tls_block(certificates=entries)
        if acme:
            block["acme"] = {**ACME_BLOCK, "directory": directory}
        seed = public_seed(block, ssh_upstreams=[ssh("h0", f"{HOST}:22")])
        return load(tmp_path, seed)

    def test_a_staging_directory_is_warned_once_naming_the_certificates(
        self, tmp_path: Path
    ) -> None:
        state = self._state(tmp_path)

        with structlog.testing.capture_logs() as logs:
            main_module._warn_acme_startup(state)

        [warned] = _events(logs, "supervisor.acme_staging_dry_run")
        assert warned["log_level"] == "warning"
        assert warned["certificates"] == ["alpha"]
        assert "never installed or served" in warned["reason"]
        assert "public_tls.acme.directory: production" in warned["reason"]

    def test_the_staging_url_spelled_out_is_warned_too(self, tmp_path: Path) -> None:
        state = self._state(
            tmp_path, directory="https://acme-staging-v02.api.letsencrypt.org/directory"
        )

        with structlog.testing.capture_logs() as logs:
            main_module._warn_acme_startup(state)

        assert len(_events(logs, "supervisor.acme_staging_dry_run")) == 1

    @pytest.mark.parametrize(
        "directory",
        ["production", "https://acme-v02.api.letsencrypt.org/directory"],
    )
    def test_a_production_directory_is_not_warned(self, tmp_path: Path, directory: str) -> None:
        state = self._state(tmp_path, directory=directory)

        with structlog.testing.capture_logs() as logs:
            main_module._warn_acme_startup(state)

        assert not _events(logs, "supervisor.acme_staging_dry_run")

    def test_a_seed_without_acme_certificates_warns_about_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CF_API_TOKEN", "sentinel")
        state = self._state(tmp_path, acme=False)

        with structlog.testing.capture_logs() as logs:
            main_module._warn_acme_startup(state)

        assert logs == []

    def test_private_mode_warns_about_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CLOUDFLARE_API_KEY", "sentinel")
        state = load(tmp_path, {"twingate": {"network": "acme", "gateway_id": "g-1"}})

        with structlog.testing.capture_logs() as logs:
            main_module._warn_acme_startup(state)

        assert logs == []

    def test_cloudflare_variables_in_the_environment_are_warned_by_name_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CLOUDFLARE_DNS_API_TOKEN", "sentinel-value-one")
        monkeypatch.setenv("CF_API_EMAIL", "sentinel@example.com")
        monkeypatch.setenv("CF_ZONE_API_TOKEN_FILE", "/run/secrets/sentinel-path")
        state = self._state(tmp_path, directory="production")

        with structlog.testing.capture_logs() as logs:
            main_module._warn_acme_startup(state)

        [warned] = _events(logs, "supervisor.acme_cloudflare_environment_ignored")
        assert warned["log_level"] == "warning"
        assert warned["variables"] == [
            "CF_API_EMAIL",
            "CF_ZONE_API_TOKEN_FILE",
            "CLOUDFLARE_DNS_API_TOKEN",
        ]
        assert "token file" in warned["reason"]
        for secret in ("sentinel-value-one", "sentinel@example.com", "sentinel-path"):
            assert secret not in str(logs)

    def test_unrelated_variables_are_not_listed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CFX_NOT_CLOUDFLARE", "1")
        monkeypatch.setenv("MY_CF_TOKEN", "1")
        monkeypatch.setenv("CF_TOKEN", "1")
        state = self._state(tmp_path, directory="production")

        with structlog.testing.capture_logs() as logs:
            main_module._warn_acme_startup(state)

        [warned] = _events(logs, "supervisor.acme_cloudflare_environment_ignored")
        assert warned["variables"] == ["CF_TOKEN"]

    def test_no_cloudflare_variables_means_no_such_warning(self, tmp_path: Path) -> None:
        state = self._state(tmp_path, directory="production")

        with structlog.testing.capture_logs() as logs:
            main_module._warn_acme_startup(state)

        assert logs == []

    def test_both_warnings_can_fire_together(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CF_API_TOKEN", "sentinel")
        state = self._state(tmp_path)

        with structlog.testing.capture_logs() as logs:
            main_module._warn_acme_startup(state)

        assert [e["event"] for e in logs] == [
            "supervisor.acme_staging_dry_run",
            "supervisor.acme_cloudflare_environment_ignored",
        ]

    async def test_bootstrap_logs_them_before_anything_else_happens(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        monkeypatch.setenv("CF_API_TOKEN", "sentinel")

        with structlog.testing.capture_logs() as logs:
            await boot(_settings(tmp_path, fake_gateway(), _acme_seed()))

        names = [e["event"] for e in logs]
        assert names.count("supervisor.acme_staging_dry_run") == 1
        assert names.count("supervisor.acme_cloudflare_environment_ignored") == 1
        assert names.index("supervisor.acme_staging_dry_run") < names.index(
            "supervisor.waiting_for_acme"
        )
        assert "sentinel" not in str(logs)

    async def test_bootstrap_of_a_production_seed_logs_no_staging_warning(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, boot: Boot
    ) -> None:
        with structlog.testing.capture_logs() as logs:
            await boot(_settings(tmp_path, fake_gateway(), _acme_seed(directory="production")))

        assert not _events(logs, "supervisor.acme_staging_dry_run")


def _stub_reconcile(monkeypatch: pytest.MonkeyPatch, **fields: Any) -> None:
    async def _reconcile(self: Reconciler, trigger: str) -> ReconcileResult:
        return ReconcileResult(ok=True, trigger=trigger, started_at=datetime.now(UTC), **fields)

    monkeypatch.setattr(Reconciler, "reconcile", _reconcile)


class TestWaitingForAcme:
    """Startup waits for ACME only when ``acme_hold`` and ``local_ok``; anything else aborts."""

    async def test_the_staging_hint_is_in_the_waiting_log(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, boot: Boot
    ) -> None:
        with structlog.testing.capture_logs() as logs:
            await boot(_settings(tmp_path, fake_gateway(), _acme_seed()))

        [waiting] = _events(logs, "supervisor.waiting_for_acme")
        assert waiting["log_level"] == "warning"
        assert "staging, a dry run that never installs a certificate" in waiting["reason"]
        assert "set public_tls.acme.directory: production to serve" in waiting["reason"]

    async def test_a_production_seed_has_no_staging_hint(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, boot: Boot
    ) -> None:
        with structlog.testing.capture_logs() as logs:
            await boot(_settings(tmp_path, fake_gateway(), _acme_seed(directory="production")))

        [waiting] = _events(logs, "supervisor.waiting_for_acme")
        assert "staging" not in waiting["reason"]
        assert "dry run" not in waiting["reason"]
        assert "starts once the first one is installed" in waiting["reason"]

    async def test_an_acme_hold_with_local_ok_waits_instead_of_aborting(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        _stub_reconcile(monkeypatch, acme_hold=True, local_ok=True, acme_pending=["alpha"])

        with structlog.testing.capture_logs() as logs:
            result = await boot(_settings(tmp_path, fake_gateway(), _acme_seed()))

        assert result.gateway_started is False
        [waiting] = _events(logs, "supervisor.waiting_for_acme")
        assert waiting["certificates"] == ["alpha"]
        assert not _events(logs, "supervisor.waiting_for_upstreams")

    async def test_an_acme_hold_beside_a_local_failure_aborts_startup(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _stub_reconcile(
            monkeypatch,
            acme_hold=True,
            local_ok=False,
            errors=["CA material is unusable: ssh key unreadable"],
        )

        with pytest.raises(RuntimeError) as caught:
            await bootstrap(_settings(tmp_path, fake_gateway(), _acme_seed()))

        assert "startup reconcile could not bring the gateway up" in str(caught.value)
        assert "CA material is unusable: ssh key unreadable" in str(caught.value)

    async def test_a_hold_that_is_not_the_acme_one_aborts_startup(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """For example the ``source: file`` hold-down: served names with no gateway is an abort."""
        _stub_reconcile(monkeypatch, acme_hold=False, local_ok=True)

        with pytest.raises(RuntimeError, match="unknown failure"):
            await bootstrap(_settings(tmp_path, fake_gateway(), _acme_seed()))

    async def test_nothing_to_serve_is_the_upstream_wait_not_the_acme_one(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        _stub_reconcile(monkeypatch, acme_hold=False, local_ok=True)

        with structlog.testing.capture_logs() as logs:
            await boot(_settings(tmp_path, fake_gateway(), _acme_seed(upstream_hosts=[])))

        assert _events(logs, "supervisor.waiting_for_upstreams")
        assert not _events(logs, "supervisor.waiting_for_acme")

    async def test_the_real_pass_reports_the_hold_for_a_fresh_acme_only_seed(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, boot: Boot
    ) -> None:
        result = await boot(_settings(tmp_path, fake_gateway(), _acme_seed()))

        last = result.reconciler.last_result
        assert last is not None
        assert (last.acme_hold, last.local_ok) == (True, True)


class TestStartupMarksTheRunner:
    """After the runner is built, the names whose installed material is bad are marked once.

    The first reconcile pass is stubbed so only the startup call is recorded; a real runner
    ignores a mark until the pass has configured it, and the reconciler marks again each pass
    (covered in ``tests/reconciler/test_acme_integration.py``).
    """

    @staticmethod
    def _recording(
        monkeypatch: pytest.MonkeyPatch, *, raises: Exception | None = None
    ) -> list[str]:
        marked: list[str] = []
        real = main_module.AcmeRunner

        class Recording(real):  # type: ignore[valid-type, misc]
            def mark_store_invalid(self, name: str) -> None:
                if raises is not None:
                    raise raises
                marked.append(name)
                super().mark_store_invalid(name)

        monkeypatch.setattr(main_module, "AcmeRunner", Recording)
        _stub_reconcile(monkeypatch, acme_hold=True, acme_pending=["alpha"])
        return marked

    async def test_refused_material_marks_the_runner_once(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        marked = self._recording(monkeypatch)
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())
        _install(settings, _leaf(issuer_other=True))

        await boot(settings)

        assert marked == ["alpha"]

    async def test_material_for_changed_names_marks_the_runner_once(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        marked = self._recording(monkeypatch)
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())
        _install(settings, _leaf([HOST, GAMMA_HOST]))

        await boot(settings)

        assert marked == ["alpha"]

    async def test_nothing_installed_marks_nothing(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        marked = self._recording(monkeypatch)

        await boot(_settings(tmp_path, fake_gateway(), _acme_seed()))

        assert marked == []

    async def test_valid_material_marks_nothing(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        marked = self._recording(monkeypatch)
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())
        _install(settings, _leaf())

        await boot(settings)

        assert marked == []

    async def test_an_unexpected_validation_failure_marks_the_runner(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        marked = self._recording(monkeypatch)

        def _boom(*args: object, **kwargs: object) -> None:
            raise RuntimeError("unexpected")

        monkeypatch.setattr(main_module, "read_installed_public_material", _boom)

        await boot(_settings(tmp_path, fake_gateway(), _acme_seed()))

        assert marked == ["alpha"]

    async def test_a_runner_that_cannot_be_marked_never_aborts_startup(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        boot: Boot,
    ) -> None:
        self._recording(monkeypatch, raises=RuntimeError("runner is broken"))
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())
        _install(settings, _leaf(issuer_other=True))

        with structlog.testing.capture_logs() as logs:
            result = await boot(settings)

        [failed] = _events(logs, "acme.mark_store_invalid_failed")
        assert failed["log_level"] == "error"
        assert failed["certificate"] == "alpha"
        assert result.acme is not None


class TestStaleAcmeMaterialNeverAbortsStartup:
    """End to end: old ACME material whose SANs no longer match."""

    @_posix_only
    async def test_a_valid_file_certificate_still_starts_the_gateway(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        source_root: Path,
        boot: Boot,
    ) -> None:
        beta = _file_cert(source_root, "beta", _leaf([BETA_HOST]), [BETA_HOST])
        settings = _settings(
            tmp_path, fake_gateway(), _acme_seed([beta], upstream_hosts=[HOST, BETA_HOST])
        )
        _install(settings, _leaf([HOST, BETA_HOST]))  # old leaf also matches beta's name

        with structlog.testing.capture_logs() as logs:
            result = await boot(settings)

        last = result.reconciler.last_result
        assert result.gateway_started is True
        assert last is not None
        assert last.local_ok is True
        assert last.acme_pending == ["alpha"]
        assert not _events(logs, "supervisor.acme_san_overlap")

    async def test_a_lone_stale_certificate_waits_for_reissue_and_never_aborts(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, boot: Boot
    ) -> None:
        settings = _settings(tmp_path, fake_gateway(), _acme_seed())
        _install(settings, _leaf([HOST, GAMMA_HOST]))

        result = await boot(settings)

        last = result.reconciler.last_result
        assert result.gateway_started is False
        assert last is not None
        assert (last.local_ok, last.acme_hold) == (True, True)
        assert last.acme_pending == ["alpha"]
        # Only the (absent) DNS token file is reported; the stale material is not an error.
        assert [e for e in last.acme_errors if e.code != "config"] == []
