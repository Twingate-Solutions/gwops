"""Startup refusal of a CA the gateway's local issuer cannot use (`ca.x509.on_demand_issuance`).

Upstream would otherwise bind :8443 and then crash building the TLS certificate manager, so
gwops refuses at startup, naming the file and the missing property.
"""

from collections.abc import Callable
from pathlib import Path

import pytest

from gwops.supervisor.main import _STARTUP_ERRORS, bootstrap
from tests.on_demand_support import (
    BASE_SEED,
    BasicConstraintsMode,
    CAFiles,
    KeyUsageMode,
    build_ca,
    ca_section,
    make_settings,
)


def _seed(on_demand: bool, byo: CAFiles | None = None) -> str:
    return BASE_SEED + ca_section(on_demand=on_demand, byo=byo)


def _message(error: pytest.ExceptionInfo[BaseException]) -> str:
    return str(error.value)


class TestModeOnRefusals:
    async def test_a_keyusage_without_key_cert_sign_aborts_startup_naming_file_and_property(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        """A keyUsage extension lacking keyCertSign is refused, naming the cert and keyCertSign."""
        ca = build_ca(tmp_path / "byo", key_usage="no_key_cert_sign")
        settings = make_settings(tmp_path, fake_gateway(), _seed(True, ca))

        with pytest.raises(_STARTUP_ERRORS) as caught:
            await bootstrap(settings)

        message = _message(caught)
        assert "keyCertSign" in message
        assert str(ca.cert) in message or ca.cert.as_posix() in message
        assert "PRIVATE KEY" not in message

    @pytest.mark.parametrize("basic_constraints", ["not_ca", "absent"])
    async def test_a_ca_without_ca_true_aborts_startup_naming_file_and_property(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        basic_constraints: BasicConstraintsMode,
    ) -> None:
        """A cert lacking basicConstraints CA:TRUE is refused, naming the cert and CA:TRUE."""
        ca = build_ca(tmp_path / "byo", basic_constraints=basic_constraints)
        settings = make_settings(tmp_path, fake_gateway(), _seed(True, ca))

        with pytest.raises(_STARTUP_ERRORS) as caught:
            await bootstrap(settings)

        message = _message(caught)
        assert "CA:TRUE" in message
        assert str(ca.cert) in message or ca.cert.as_posix() in message

    async def test_a_missing_private_key_aborts_startup_naming_the_key_file(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        """A BYO CA whose key file is absent is refused, naming the key path."""
        ca = build_ca(tmp_path / "byo", write_key=False)
        settings = make_settings(tmp_path, fake_gateway(), _seed(True, ca))

        with pytest.raises(_STARTUP_ERRORS) as caught:
            await bootstrap(settings)

        assert str(ca.key) in _message(caught) or ca.key.as_posix() in _message(caught)

    async def test_an_unreadable_private_key_aborts_startup_naming_the_key_file(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        """A BYO CA whose key file holds no key is refused, naming the key path."""
        ca = build_ca(tmp_path / "byo")
        ca.key.write_text("not a key\n", encoding="utf-8")
        settings = make_settings(tmp_path, fake_gateway(), _seed(True, ca))

        with pytest.raises(_STARTUP_ERRORS) as caught:
            await bootstrap(settings)

        message = _message(caught)
        assert str(ca.key) in message or ca.key.as_posix() in message
        assert "not a key" not in message

    async def test_the_refusal_happens_before_anything_is_started(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        """No rendered config is written when the CA is refused."""
        ca = build_ca(tmp_path / "byo", key_usage="no_key_cert_sign")
        settings = make_settings(tmp_path, fake_gateway(), _seed(True, ca))

        with pytest.raises(_STARTUP_ERRORS):
            await bootstrap(settings)

        assert not (settings.runtime_dir / "config.yaml").exists()


class TestModeOnAccepts:
    @pytest.mark.parametrize("key_usage", ["key_cert_sign", "absent"])
    async def test_a_byo_ca_the_issuer_accepts_starts(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, key_usage: KeyUsageMode
    ) -> None:
        """keyCertSign present, or no keyUsage extension at all, both pass (as upstream)."""
        ca = build_ca(tmp_path / "byo", key_usage=key_usage)
        settings = make_settings(tmp_path, fake_gateway(), _seed(True, ca))

        result = await bootstrap(settings)

        assert result.certs.x509_ca_not_after() is not None

    async def test_a_gwops_generated_ca_starts(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        """The default generated CA passes the on-demand checks."""
        settings = make_settings(tmp_path, fake_gateway(), _seed(True))

        result = await bootstrap(settings)

        assert (settings.data_dir / "pki" / "x509-ca.crt").is_file()
        assert result.state.ca.x509.on_demand_issuance is True


class TestModeOffAddsNoChecks:
    @pytest.mark.parametrize("key_usage", ["no_key_cert_sign", "absent"])
    async def test_the_same_ca_starts_with_the_mode_off(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, key_usage: KeyUsageMode
    ) -> None:
        """A BYO CA without keyCertSign is not refused when the mode is off."""
        ca = build_ca(tmp_path / "byo", key_usage=key_usage)
        settings = make_settings(tmp_path, fake_gateway(), _seed(False, ca))

        result = await bootstrap(settings)

        assert result.state.ca.x509.on_demand_issuance is False

    async def test_the_same_ca_starts_when_the_key_is_absent_from_the_seed(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        """Omitting the key behaves like false for a keyCertSign-less BYO CA."""
        ca = build_ca(tmp_path / "byo", key_usage="no_key_cert_sign")
        settings = make_settings(tmp_path, fake_gateway(), BASE_SEED + ca_section(byo=ca))

        result = await bootstrap(settings)

        assert result.state.ca.x509.on_demand_issuance is False
