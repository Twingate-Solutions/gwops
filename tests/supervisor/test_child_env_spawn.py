"""Both gateway spawn sites hand the child an allowlisted environment.

A fake gateway that dumps the environment it inherited (``fake_gateway(env_dump=...)``) is
spawned through ``GatewayProcess.start`` and through ``validate_config_by_spawn`` with every
gwops secret set in the supervisor's own ``os.environ``. None may appear in the child; the proxy
and CA-bundle variables must. These tests use the real ``child_env`` end to end: the fake's own
``FAKE_GW_*`` knobs are exported by its launcher script after the spawn, so nothing here widens
the production allowlist.
"""

import asyncio
import json
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest

from gwops.supervisor.process import GatewayProcess
from gwops.supervisor.spawn import validate_config_by_spawn
from tests.supervisor.childenv_names import ALLOWLIST, SECRET_NAMES, WIN32_EXTRAS, sentinel

_Spawn = Callable[[Path, Path, Path], Awaitable[None]]

# The fake's launcher exports its own knobs inside the child; they are not inherited.
_LAUNCHER_PREFIX = "FAKE_GW_"
# cmd.exe-internal per-drive working-directory entries ("=C:"), never real variables.
_HIDDEN_PREFIX = "="
# Set by the launcher's own shell (cmd.exe for the Windows `.cmd`, sh for the POSIX script),
# not inherited from gwops.
_SHELL_ADDS = frozenset({"PROMPT"} if sys.platform == "win32" else {"PWD"})


async def _wait_for(predicate: Callable[[], bool], timeout: float = 10.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not met within timeout")


async def _spawn_via_gateway_process(binary: Path, config: Path, dump: Path) -> None:
    proc = GatewayProcess(binary, config, lambda _l: None, lambda _l: None)
    await proc.start()
    try:
        await _wait_for(dump.exists)
        await _wait_for(lambda: proc.returncode is not None)
    finally:
        await proc.stop(timeout=5.0)


async def _spawn_via_validate_config(binary: Path, config: Path, dump: Path) -> None:
    await validate_config_by_spawn(binary, config, timeout_seconds=10.0)
    await _wait_for(dump.exists)


_SPAWN_SITES = pytest.mark.parametrize(
    "spawn",
    [
        pytest.param(_spawn_via_gateway_process, id="GatewayProcess.start"),
        pytest.param(_spawn_via_validate_config, id="validate_config_by_spawn"),
    ],
)


@pytest.fixture
def secrets_in_environment(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Every gwops secret set in the supervisor's environment, each with a unique value."""
    values = {name: sentinel(name) for name in SECRET_NAMES}
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return values


@pytest.fixture
def passthrough_in_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> dict[str, str]:
    """Proxy and CA-bundle variables the gateway needs, set in the supervisor's environment."""
    values = {
        "HTTPS_PROXY": "http://proxy.invalid:3128",
        "HTTP_PROXY": "http://proxy.invalid:3128",
        "NO_PROXY": "localhost,127.0.0.1",
        "SSL_CERT_FILE": str(tmp_path / "ca-bundle.pem"),
        "SSL_CERT_DIR": str(tmp_path / "certs.d"),
        "GOMEMLIMIT": "512MiB",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return values


async def _child_environment(
    spawn: _Spawn, fake_gateway: Callable[..., Path], tmp_path: Path
) -> dict[str, str]:
    """Spawn the env-dumping fake through `spawn` and return what it inherited."""
    config = tmp_path / "config.yaml"
    config.write_text("twingate: {network: test}\n", encoding="utf-8")
    dump = tmp_path / "child-env.json"
    await spawn(fake_gateway(env_dump=dump), config, dump)
    raw: dict[str, str] = json.loads(dump.read_text(encoding="utf-8"))
    return {
        name: value
        for name, value in raw.items()
        if not name.startswith((_LAUNCHER_PREFIX, _HIDDEN_PREFIX))
    }


class TestChildEnvironmentScrub:
    @_SPAWN_SITES
    async def test_gwops_secrets_do_not_reach_the_gateway_child(
        self,
        spawn: _Spawn,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        secrets_in_environment: dict[str, str],
    ) -> None:
        child = await _child_environment(spawn, fake_gateway, tmp_path)
        leaked_names = sorted(set(secrets_in_environment) & set(child))
        assert leaked_names == []
        leaked_values = sorted(
            name for name, value in child.items() if value in secrets_in_environment.values()
        )
        assert leaked_values == []

    @_SPAWN_SITES
    async def test_proxy_and_ca_variables_still_reach_the_gateway_child(
        self,
        spawn: _Spawn,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        passthrough_in_environment: dict[str, str],
    ) -> None:
        child = await _child_environment(spawn, fake_gateway, tmp_path)
        for name, value in passthrough_in_environment.items():
            assert child.get(name) == value, f"{name} was not passed to the child"

    @_SPAWN_SITES
    async def test_secrets_are_stripped_while_passthrough_variables_are_kept(
        self,
        spawn: _Spawn,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        secrets_in_environment: dict[str, str],
        passthrough_in_environment: dict[str, str],
    ) -> None:
        child = await _child_environment(spawn, fake_gateway, tmp_path)
        assert not set(secrets_in_environment) & set(child)
        assert passthrough_in_environment.items() <= child.items()

    @_SPAWN_SITES
    async def test_child_holds_only_allowlisted_names(
        self,
        spawn: _Spawn,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # An arbitrary variable the allowlist has never heard of, alongside the secrets.
        monkeypatch.setenv("GWOPS_ADMIN_TOKEN", sentinel("GWOPS_ADMIN_TOKEN"))
        monkeypatch.setenv("SOME_UNRELATED_SETTING", "1")
        permitted = {
            *ALLOWLIST,
            *(WIN32_EXTRAS if sys.platform == "win32" else ()),
            *_SHELL_ADDS,
        }
        child = await _child_environment(spawn, fake_gateway, tmp_path)
        assert sorted(set(child) - permitted) == []

    @pytest.mark.skipif(
        sys.platform == "win32", reason="Windows environment names are case-insensitive"
    )
    @_SPAWN_SITES
    async def test_lowercase_proxy_variables_reach_the_gateway_child(
        self,
        spawn: _Spawn,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("https_proxy", "http://lower.invalid:3128")
        monkeypatch.setenv("no_proxy", "localhost")
        child = await _child_environment(spawn, fake_gateway, tmp_path)
        assert child.get("https_proxy") == "http://lower.invalid:3128"
        assert child.get("no_proxy") == "localhost"
