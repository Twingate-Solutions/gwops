"""``bootstrap`` in public mode validates every certificate's material.

Startup reads each certificate's files through the confined reader and validates them against
the registered root. Any failure aborts startup with one error listing every failing
certificate by file and property. Bootstrap only validates: nothing is installed, the first
reconcile pass installs.
"""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

import gwops.renderer.render as render_module
import gwops.supervisor.main as main_module
from gwops.reconciler.core import Reconciler, ReconcileResult
from gwops.supervisor.main import bootstrap
from tests.public_chain_support import ec_key, key_pem_of, pem_bodies, rsa_hierarchy
from tests.public_tls_support import ZONE, public_cert, public_seed, tls_block

from .test_main import _EMPTY_SEED, _settings

ROOT = rsa_hierarchy().root
NAMES = ("alpha", "beta", "gamma")


@pytest.fixture
def source_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The confined public-tls root, redirected into tmp for ``RuntimePaths.from_settings``."""
    root = tmp_path / "public-tls-src"
    root.mkdir()
    monkeypatch.setattr(render_module, "PUBLIC_TLS_ROOT", root)
    return root


@pytest.fixture(autouse=True)
def _startup_stubs(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Resolve the generated test root, and replace the first reconcile with a recorder."""
    monkeypatch.setattr(main_module, "resolve_registered_root", lambda name: ROOT)
    triggers: list[str] = []

    async def _reconcile(self: Reconciler, trigger: str) -> ReconcileResult:
        triggers.append(trigger)
        return ReconcileResult(ok=True, trigger=trigger, started_at=datetime.now(UTC))

    monkeypatch.setattr(Reconciler, "reconcile", _reconcile)
    return triggers


def _write(root: Path, name: str) -> None:
    now = datetime.now(UTC)
    issued = rsa_hierarchy().issue(
        [f"{name}.{ZONE}"], not_before=now - timedelta(days=10), not_after=now + timedelta(days=80)
    )
    (root / name).mkdir(exist_ok=True)
    (root / name / "fullchain.pem").write_bytes(issued.cert_pem)
    (root / name / "privkey.pem").write_bytes(issued.key_pem)


def _seed(root: Path, names: tuple[str, ...] = NAMES) -> str:
    entries = [
        public_cert(
            name,
            [f"{name}.{ZONE}"],
            cert_file=str(root / name / "fullchain.pem"),
            key_file=str(root / name / "privkey.pem"),
        )
        for name in names
    ]
    # No upstreams: the stubbed first reconcile cannot start a gateway, and the startup gate
    # would abort on that for a populated seed.
    seed = public_seed(tls_block(certificates=entries))
    return yaml.safe_dump(seed, sort_keys=False)


class TestStartupMaterial:
    async def test_valid_material_lets_startup_proceed_and_installs_nothing(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        source_root: Path,
        _startup_stubs: list[str],
    ) -> None:
        for name in NAMES:
            _write(source_root, name)
        settings = _settings(tmp_path, fake_gateway(), _seed(source_root))

        await bootstrap(settings)

        assert _startup_stubs == ["startup"]
        assert not (settings.data_dir / "public-tls").exists()  # the first pass installs

    async def test_every_failure_is_listed_in_one_startup_error(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        source_root: Path,
        _startup_stubs: list[str],
    ) -> None:
        for name in NAMES:
            _write(source_root, name)
        (source_root / "alpha" / "privkey.pem").write_bytes(key_pem_of(ec_key()))
        (source_root / "gamma" / "fullchain.pem").unlink()
        settings = _settings(tmp_path, fake_gateway(), _seed(source_root))

        with pytest.raises(ValueError) as caught:
            await bootstrap(settings)

        lines = str(caught.value).splitlines()
        assert lines[0] == "public certificate material refused (2 certificate(s)):"
        assert len(lines) == 3
        assert lines[1].startswith("- public certificate 'alpha':") and "key_file" in lines[1]
        assert lines[2].startswith("- public certificate 'gamma':") and "cert_file" in lines[2]
        assert "'beta'" not in str(caught.value)  # the valid certificate is not listed
        assert _startup_stubs == []
        assert not (settings.runtime_dir / "config.yaml").exists()
        assert not (settings.data_dir / "pki" / "ssh-ca.key").exists()  # aborted before any CA
        assert not (settings.data_dir / "public-tls").exists()

    async def test_a_served_name_matched_by_two_leaves_aborts_startup_naming_both(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        source_root: Path,
        _startup_stubs: list[str],
    ) -> None:
        """Rule 5 on the actual SANs: beta's leaf also carries alpha's name, which alpha serves."""
        _write(source_root, "alpha")
        now = datetime.now(UTC)
        issued = rsa_hierarchy().issue(
            [f"beta.{ZONE}", f"alpha.{ZONE}"],
            not_before=now - timedelta(days=10),
            not_after=now + timedelta(days=80),
        )
        (source_root / "beta").mkdir()
        (source_root / "beta" / "fullchain.pem").write_bytes(issued.cert_pem)
        (source_root / "beta" / "privkey.pem").write_bytes(issued.key_pem)
        seed = yaml.safe_load(_seed(source_root, ("alpha", "beta")))
        seed["ssh_upstreams"] = [
            {"name": "a", "address": f"alpha.{ZONE}:22"},
            {"name": "b", "address": f"beta.{ZONE}:22"},
        ]
        settings = _settings(tmp_path, fake_gateway(), yaml.safe_dump(seed, sort_keys=False))

        with pytest.raises(ValueError) as caught:
            await bootstrap(settings)

        lines = str(caught.value).splitlines()
        assert lines[0] == "public certificate material refused (1 certificate(s)):"
        assert lines[1] == (
            f"- served name 'alpha.{ZONE}' is covered by certificate 'alpha' but the leaf of "
            "certificate 'beta' also matches it; each served name must match exactly one "
            "certificate"
        )
        assert _startup_stubs == []
        assert not (settings.data_dir / "public-tls").exists()

    async def test_a_file_outside_the_confined_root_aborts_startup_naming_it(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        source_root: Path,
    ) -> None:
        for name in NAMES:
            _write(source_root, name)
        stray = tmp_path / "stray"
        stray.mkdir()
        _write(stray, "beta")
        entries = yaml.safe_load(_seed(source_root))
        beta = entries["public_tls"]["certificates"][1]
        beta["cert_file"] = str(stray / "beta" / "fullchain.pem")
        settings = _settings(tmp_path, fake_gateway(), yaml.safe_dump(entries, sort_keys=False))

        with pytest.raises(ValueError, match="resolves outside the allowed root") as caught:
            await bootstrap(settings)

        assert "public certificate 'beta'" in str(caught.value)
        assert "cert_file" in str(caught.value)

    async def test_the_error_never_carries_key_or_certificate_contents(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        source_root: Path,
    ) -> None:
        for name in NAMES:
            _write(source_root, name)
        bad_key = key_pem_of(ec_key())
        (source_root / "alpha" / "privkey.pem").write_bytes(bad_key)
        settings = _settings(tmp_path, fake_gateway(), _seed(source_root))

        with pytest.raises(ValueError) as caught:
            await bootstrap(settings)

        files = [
            (source_root / "alpha" / "fullchain.pem").read_bytes(),
            bad_key,
        ]
        for body in pem_bodies(*files):
            assert body not in str(caught.value)

    def test_a_refusal_is_a_startup_error_main_exits_on(self) -> None:
        assert issubclass(ValueError, main_module._STARTUP_ERRORS)


class TestPrivateModeUnaffected:
    async def test_private_mode_never_reads_public_material(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def _forbidden(*args: object, **kwargs: object) -> None:
            raise AssertionError("private mode must not read public certificate material")

        monkeypatch.setattr(main_module, "read_public_material", _forbidden)

        await bootstrap(_settings(tmp_path, fake_gateway(), _EMPTY_SEED))
