"""Fixtures for the ACME runner tests: an installed fake lego and the settings that point at it.

The fake lego (``tests/fakes/fake_lego.py``) is a POSIX script; every fixture that installs it
skips on win32, the same condition the repo's other POSIX-only tests use. Tests that only build
argv (``test_lego_argv.py``) use none of these fixtures and run everywhere.
"""

import os
import random
import sys
from collections.abc import AsyncIterator, Mapping
from pathlib import Path

import pytest

from gwops.acme import token as token_module
from gwops.acme.runner import AcmeConfig, AcmeRunner, InstallCallback
from gwops.certs.store import MaterialStore
from gwops.configmodel.schema import AcmePublicCertificate, AcmeSettings
from gwops.settings import GwopsSettings
from tests.acme.fake_lego_support import (
    FakeLego,
    TokenFile,
    install_fake_lego,
    write_token_file,
)
from tests.acme.runner_support import Clock, RunnerFactory
from tests.public_chain_support import NOW, ZONES, rsa_hierarchy
from tests.public_tls_support import ZONE


@pytest.fixture(autouse=True)
def acme_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the runtime ``/config/acme`` root at ``tmp_path/config/acme``.

    ``gwops.acme.token`` requires the token file to resolve under ``ACME_ROOT``; the sentinel
    token file lives under the tmp path, so every test in this package runs with the root
    swapped. The seed model's own confinement (a lexical rule on ``/config/acme/``) is a
    separate check and is not patched; the fixtures apply ``token_file`` with ``model_copy``.
    """
    root = tmp_path / "config" / "acme"
    monkeypatch.setattr(token_module, "ACME_ROOT", root)
    return root


@pytest.fixture
def fake_lego(tmp_path: Path) -> FakeLego:
    """An executable copy of the fake lego in ``tmp_path/bin``, with no behaviour configured.

    Configure it with ``fake_lego.succeed()``, ``.fail(kind)`` or ``.configure(*steps)``; read
    what the runner did with ``fake_lego.invocations()``. An unconfigured run exits 99.
    """
    if sys.platform == "win32":
        pytest.skip("requires a POSIX executable script (shebang)")
    return install_fake_lego(tmp_path / "bin")


@pytest.fixture
def lego_token(tmp_path: Path) -> TokenFile:
    """The sentinel token file (``TOKEN_SENTINEL``) under ``tmp_path/config/acme/``."""
    return write_token_file(tmp_path)


@pytest.fixture
def lego_settings(tmp_path: Path, fake_lego: FakeLego) -> GwopsSettings:
    """Settings with ``lego_binary`` the fake and ``data_dir`` a tmp path (``acme/`` made 0700).

    ``lego_path_dir`` is ``<tmp_path>/data/acme/lego``; lego's ``--path`` is a per-directory
    subdirectory of it (``lego_storage_dir(url)``); the runner creates it on the first attempt.
    """
    settings = GwopsSettings(data_dir=tmp_path / "data", lego_binary=fake_lego.binary)
    settings.acme_dir.mkdir(parents=True, mode=0o700)
    return settings


@pytest.fixture
def acme_settings(lego_token: TokenFile) -> AcmeSettings:
    """A valid staging ``public_tls.acme`` block whose ``token_file`` is the sentinel file.

    The seed model confines ``token_file`` to ``/config/acme/``, so the tmp path is applied with
    ``model_copy`` (no validation); a test of the confinement rule builds its own model.
    """
    block = AcmeSettings.model_validate(
        {"email": "ops@example.com", "accept_tos": True, "directory": "staging"}
    )
    return block.model_copy(update={"token_file": str(lego_token.path)})


@pytest.fixture
def acme_cert() -> AcmePublicCertificate:
    """The ``wildcard`` certificate (``*.example.com``), ``source: acme``."""
    return AcmePublicCertificate.model_validate(
        {"name": "wildcard", "names": [f"*.{ZONE}"], "source": "acme"}
    )


# --- AcmeRunner fixtures ---------------------------------------------------------------


@pytest.fixture
def clock() -> Clock:
    """The runner's injected clock, at ``NOW`` (inside every fake-issued leaf's validity)."""
    return Clock(NOW)


@pytest.fixture
def installed_calls() -> list[str]:
    """Certificate names passed to ``on_installed``, in call order."""
    return []


@pytest.fixture
def public_store(tmp_path: Path) -> MaterialStore:
    """The public ``MaterialStore`` under ``<data_dir>/public-tls`` (POSIX symlink layout)."""
    return MaterialStore(tmp_path / "data" / "public-tls")


@pytest.fixture
def production_settings(acme_settings: AcmeSettings) -> AcmeSettings:
    """``acme_settings`` with ``directory: production``."""
    return acme_settings.model_copy(update={"directory": "production"})


@pytest.fixture
def staging_config(acme_settings: AcmeSettings, acme_cert: AcmePublicCertificate) -> AcmeConfig:
    """Staging (dry run) configuration for ``wildcard``; needs no registered root."""
    return AcmeConfig(acme_settings, (acme_cert,), ZONES, None)


@pytest.fixture
def production_config(
    production_settings: AcmeSettings, acme_cert: AcmePublicCertificate
) -> AcmeConfig:
    """Production configuration for ``wildcard`` against the test hierarchy's root."""
    return AcmeConfig(production_settings, (acme_cert,), ZONES, rsa_hierarchy().root)


@pytest.fixture
async def new_runner(
    lego_settings: GwopsSettings,
    public_store: MaterialStore,
    clock: Clock,
    installed_calls: list[str],
) -> AsyncIterator[RunnerFactory]:
    """Build runners on the shared clock, store and callback list; closed at teardown.

    ``new_runner(settings=..., environ=..., on_installed=...)``. The child environment defaults
    to ``PATH`` only (the fake's shebang needs it); the rng is seeded.
    """
    created: list[AcmeRunner] = []

    def factory(
        *,
        settings: GwopsSettings | None = None,
        environ: Mapping[str, str] | None = None,
        on_installed: InstallCallback | None = None,
    ) -> AcmeRunner:
        runner = AcmeRunner(
            settings or lego_settings,
            store=public_store,
            on_installed=installed_calls.append if on_installed is None else on_installed,
            clock=clock,
            environ={"PATH": os.environ["PATH"]} if environ is None else environ,
            rng=random.Random(1234),
        )
        created.append(runner)
        return runner

    yield factory
    for runner in created:
        await runner.aclose()
