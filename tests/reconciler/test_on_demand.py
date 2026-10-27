"""On-demand issuance through the real reconciler: rendered config, SAN check, CA checks."""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from gwops.renderer.capabilities import Capabilities
from tests.on_demand_support import SSH_UPSTREAM_SEED, CAFiles, build_ca, ca_section
from tests.store_support import leaf_cert_path, leaf_key_path

from .test_core import Env, _leaf_sans


def _seed(on_demand: bool | None, byo: CAFiles | None = None) -> str:
    return SSH_UPSTREAM_SEED + ca_section(on_demand=on_demand, byo=byo)


def _env(tmp_path: Path, binary: Path, seed: str) -> Env:
    return Env(tmp_path, seed, binary, Capabilities(), None)


def _config(env: Env) -> dict[str, Any]:
    doc: dict[str, Any] = yaml.safe_load(env.config_path.read_text(encoding="utf-8"))
    return doc


def _all_keys(node: Any) -> set[str]:
    if isinstance(node, dict):
        return set(node) | {k for v in node.values() for k in _all_keys(v)}
    if isinstance(node, list):
        return {k for v in node for k in _all_keys(v)}
    return set()


class TestRenderedConfig:
    @pytest.mark.parametrize("on_demand", [None, False])
    async def test_mode_off_writes_no_tls_automation(
        self, tmp_path: Path, gateway_binary: Callable[..., Path], on_demand: bool | None
    ) -> None:
        """A pass with the mode absent or false writes a config with no automation key."""
        env = _env(tmp_path, gateway_binary(), _seed(on_demand))

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is True
        assert "automation" not in _all_keys(_config(env))

    async def test_a_generated_ca_is_rendered_at_the_certmanager_ca_files(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        """The issuer points at the CA files CertManager reports as active."""
        env = _env(tmp_path, gateway_binary(), _seed(True))

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is True
        active = env.certs.ensure_x509_ca(generate=True)
        tls = _config(env)["tls"]
        assert tls["automation"] == {
            "issuer": {
                "local": {
                    "certificateFile": active.cert_path.as_posix(),
                    "privateKeyFile": active.key_path.as_posix(),
                }
            }
        }
        assert active.cert_path.parent == env.paths.pki_dir
        assert active.cert_path.is_file() and active.key_path.is_file()

    async def test_the_static_leaf_stays_the_only_static_entry(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        """tls.certificates.files holds exactly the gwops leaf, beside the automation block."""
        env = _env(tmp_path, gateway_binary(), _seed(True))

        await env.reconciler.reconcile("startup")

        assert _config(env)["tls"]["certificates"] == {
            "files": [
                {
                    "certificateFile": leaf_cert_path(env.paths.pki_dir).as_posix(),
                    "privateKeyFile": leaf_key_path(env.paths.pki_dir).as_posix(),
                }
            ]
        }

    async def test_a_byo_ca_is_rendered_at_its_own_paths(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        """With a bring-your-own CA the issuer points at the operator's files, not pki_dir."""
        ca = build_ca(tmp_path / "byo")
        env = _env(tmp_path, gateway_binary(), _seed(True, ca))

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is True
        local = _config(env)["tls"]["automation"]["issuer"]["local"]
        assert local == {
            "certificateFile": ca.cert.as_posix(),
            "privateKeyFile": ca.key.as_posix(),
        }

    async def test_an_unchanged_second_pass_does_not_restart_the_gateway(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        """The render is stable, so a quiet pass in this mode is a no-op."""
        env = _env(tmp_path, gateway_binary(), _seed(True))
        await env.reconciler.reconcile("startup")

        result = await env.reconciler.reconcile("tick")

        assert result.local_ok is True
        assert env.process.calls == ["start"]  # type: ignore[attr-defined]

    async def test_switching_the_mode_on_in_the_seed_drain_restarts_the_gateway(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        """The config changes when the seed opts in, so the gateway is drain-restarted."""
        env = _env(tmp_path, gateway_binary(), _seed(False))
        await env.reconciler.reconcile("startup")
        assert "automation" not in _all_keys(_config(env))

        env.seed_path.write_text(_seed(True), encoding="utf-8")
        result = await env.reconciler.reconcile("seed-change")

        assert result.local_ok is True
        assert "automation" in _config(env)["tls"]
        assert env.process.calls == ["start", "drain_restart"]  # type: ignore[attr-defined]


class TestSanCoverageIsUnchanged:
    async def test_the_leaf_sans_are_the_same_with_the_mode_on_and_off(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        """On-demand issuance does not drop any SAN from the static leaf."""
        binary = gateway_binary()
        (tmp_path / "off").mkdir()
        (tmp_path / "on").mkdir()
        off = _env(tmp_path / "off", binary, _seed(False))
        on = _env(tmp_path / "on", binary, _seed(True))

        await off.reconciler.reconcile("startup")
        await on.reconciler.reconcile("startup")

        assert _leaf_sans(on.paths.pki_dir) == _leaf_sans(off.paths.pki_dir) == {"10.0.0.5"}

    async def test_a_new_upstream_name_is_added_to_the_static_leaf(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        """A name the on-demand issuer could cover is still minted into the static leaf."""
        env = _env(tmp_path, gateway_binary(), _seed(True))
        await env.reconciler.reconcile("startup")
        assert _leaf_sans(env.paths.pki_dir) == {"10.0.0.5"}

        env.store.add(
            {"ssh_upstreams": [{"name": "db-1", "address": "db.corp.internal"}]}, comment="add"
        )
        result = await env.reconciler.reconcile("api")

        assert result.local_ok is True
        assert _leaf_sans(env.paths.pki_dir) == {"10.0.0.5", "db.corp.internal"}

    @pytest.mark.parametrize("on_demand", [False, True])
    async def test_a_leaf_that_cannot_be_minted_aborts_the_pass_in_both_modes(
        self,
        tmp_path: Path,
        gateway_binary: Callable[..., Path],
        monkeypatch: pytest.MonkeyPatch,
        on_demand: bool,
    ) -> None:
        """A failing leaf mint is a local error, writes no config and starts nothing."""
        env = _env(tmp_path, gateway_binary(), _seed(on_demand))

        def _refuse(_sans: set[str]) -> object:
            raise ValueError("required SANs cannot be covered")

        monkeypatch.setattr(env.certs, "mint_leaf", _refuse)

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        assert any(error.startswith("leaf mint failed") for error in result.errors)
        assert not env.config_path.exists()
        assert env.process.calls == []  # type: ignore[attr-defined]


class TestCaSuitabilityOnEveryPass:
    async def test_a_ca_without_key_cert_sign_is_refused_with_the_mode_on(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        """The pass fails locally naming the cert and keyCertSign, and applies nothing."""
        ca = build_ca(tmp_path / "byo", key_usage="no_key_cert_sign")
        env = _env(tmp_path, gateway_binary(), _seed(True, ca))

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is False
        [error] = [e for e in result.errors if "keyCertSign" in e]
        assert ca.cert.as_posix() in error or str(ca.cert) in error
        assert not env.config_path.exists()
        assert env.process.calls == []  # type: ignore[attr-defined]

    async def test_the_same_ca_is_accepted_with_the_mode_off(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        """Existing behaviour: with the mode off the pass renders and starts the gateway."""
        ca = build_ca(tmp_path / "byo", key_usage="no_key_cert_sign")
        env = _env(tmp_path, gateway_binary(), _seed(False, ca))

        result = await env.reconciler.reconcile("startup")

        assert result.local_ok is True
        assert env.config_path.is_file()
        assert env.process.calls == ["start"]  # type: ignore[attr-defined]

    async def test_a_ca_swapped_for_an_unsuitable_one_keeps_the_previous_config(
        self, tmp_path: Path, gateway_binary: Callable[..., Path]
    ) -> None:
        """A later pass that finds an unusable CA keeps the live config and does not restart."""
        good = build_ca(tmp_path / "byo", name="good")
        env = _env(tmp_path, gateway_binary(), _seed(True, good))
        await env.reconciler.reconcile("startup")
        old_config = env.config_path.read_text(encoding="utf-8")

        bad = build_ca(tmp_path / "byo", name="bad", key_usage="no_key_cert_sign")
        env.seed_path.write_text(_seed(True, bad), encoding="utf-8")
        result = await env.reconciler.reconcile("seed-change")

        assert result.local_ok is False
        assert any("keyCertSign" in e for e in result.errors)
        assert env.config_path.read_text(encoding="utf-8") == old_config
        assert env.process.calls == ["start"]  # type: ignore[attr-defined]
