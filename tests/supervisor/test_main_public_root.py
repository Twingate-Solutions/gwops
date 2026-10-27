"""``bootstrap`` in public mode: no gwops X.509 CA, and the registered root must resolve.

The first reconcile is replaced by a stub, and the certificate material check is stubbed out,
so these tests cover only the root-resolution part of the startup gate in
``gwops.supervisor.main``.
"""

import functools
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

import gwops.supervisor.main as main_module
from gwops.certs.manager import CertManager
from gwops.certs.public import RegisteredRootError, resolve_registered_root
from gwops.reconciler.core import Reconciler, ReconcileResult
from gwops.supervisor.main import bootstrap
from tests.public_tls_support import public_seed

from .test_main import _EMPTY_SEED, _settings

_TLS_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "tls"
_ISRG_BUNDLE = _TLS_FIXTURES / "isrg-root-x1.pem"
_NOT_THE_ROOT_BUNDLE = _TLS_FIXTURES / "le-rsa-community.letsencrypt.org-chain.pem"

_PUBLIC_SEED = yaml.safe_dump(public_seed(), sort_keys=False)


@pytest.fixture(autouse=True)
def _stub_first_reconcile(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace the first reconcile so only the startup gate under test runs."""
    triggers: list[str] = []

    async def _reconcile(self: Reconciler, trigger: str) -> ReconcileResult:
        triggers.append(trigger)
        return ReconcileResult(ok=True, trigger=trigger, started_at=datetime.now(UTC))

    monkeypatch.setattr(Reconciler, "reconcile", _reconcile)
    return triggers


@pytest.fixture(autouse=True)
def _skip_material_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """The seed's certificate files do not exist here; material is covered elsewhere.

    ``tests/supervisor/test_main_public_material.py`` exercises the real read and validation.
    """
    # It returns the names of ACME certificates whose installed material is invalid.
    monkeypatch.setattr(main_module, "_validate_public_material", lambda *args, **kwargs: [])


def _resolve_against(
    monkeypatch: pytest.MonkeyPatch, trust_store: Path
) -> list[str]:
    """Make the startup gate resolve roots from `trust_store`; returns the names it asked for."""
    asked: list[str] = []
    real = functools.partial(resolve_registered_root, trust_store_path=trust_store)

    def _resolve(name: str) -> object:
        asked.append(name)
        return real(name)

    monkeypatch.setattr(main_module, "resolve_registered_root", _resolve)
    return asked


def _forbid_gwops_x509_ca(monkeypatch: pytest.MonkeyPatch) -> None:
    def _forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("public mode must not recover or ensure a gwops X.509 CA")

    monkeypatch.setattr(CertManager, "recover_x509_rotation", _forbidden)
    monkeypatch.setattr(CertManager, "ensure_x509_ca", _forbidden)


def _snapshot(directory: Path) -> dict[str, bytes]:
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


class TestPublicModeBootstrap:
    async def test_the_gwops_x509_ca_is_neither_recovered_nor_ensured(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        _stub_first_reconcile: list[str],
    ) -> None:
        asked = _resolve_against(monkeypatch, _ISRG_BUNDLE)
        _forbid_gwops_x509_ca(monkeypatch)
        settings = _settings(tmp_path, fake_gateway(), _PUBLIC_SEED)

        result = await bootstrap(settings)

        assert asked == ["isrg_root_x1"]
        assert _stub_first_reconcile == ["startup"]
        assert result.gateway_started is False
        pki = settings.data_dir / "pki"
        assert not (pki / "x509-ca.crt").exists()
        assert not (pki / "x509-ca.key").exists()
        assert (pki / "ssh-ca.key").is_file()  # the SSH CA is ensured as in private mode

    async def test_staged_ca_files_from_an_earlier_private_run_are_left_untouched(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pki = tmp_path / "data" / "pki"
        previous = CertManager(pki)
        previous.ensure_x509_ca(generate=True)
        previous.stage_x509_rotation()
        (pki / "staged" / ".rotation-stamp").write_text("20260722T000000Z", encoding="utf-8")
        before = _snapshot(pki)
        assert any(name.startswith("staged/") for name in before)
        _resolve_against(monkeypatch, _ISRG_BUNDLE)
        _forbid_gwops_x509_ca(monkeypatch)

        await bootstrap(_settings(tmp_path, fake_gateway(), _PUBLIC_SEED))

        after = _snapshot(pki)
        assert {name: after[name] for name in before} == before


class TestRegisteredRootAbort:
    async def test_a_trust_store_that_cannot_be_read_aborts_startup(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        _stub_first_reconcile: list[str],
    ) -> None:
        _resolve_against(monkeypatch, tmp_path / "missing" / "ca-certificates.crt")
        settings = _settings(tmp_path, fake_gateway(), _PUBLIC_SEED)

        with pytest.raises(RegisteredRootError, match="ca-certificates.crt"):
            await bootstrap(settings)

        assert _stub_first_reconcile == []
        assert not (settings.runtime_dir / "config.yaml").exists()

    async def test_a_trust_store_without_the_pinned_root_aborts_startup(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        _stub_first_reconcile: list[str],
    ) -> None:
        _resolve_against(monkeypatch, _NOT_THE_ROOT_BUNDLE)
        settings = _settings(tmp_path, fake_gateway(), _PUBLIC_SEED)

        with pytest.raises(RegisteredRootError, match="isrg_root_x1.*not in the trust store"):
            await bootstrap(settings)

        assert _stub_first_reconcile == []
        assert not (settings.data_dir / "pki" / "ssh-ca.key").exists()


class TestPrivateModeUnchanged:
    async def test_private_mode_ensures_the_gwops_ca_and_never_resolves_a_root(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def _refuse(name: str) -> object:
            raise AssertionError("private mode must not resolve a registered root")

        monkeypatch.setattr(main_module, "resolve_registered_root", _refuse)
        settings = _settings(tmp_path, fake_gateway(), _EMPTY_SEED)

        await bootstrap(settings)

        assert (settings.data_dir / "pki" / "x509-ca.crt").is_file()
