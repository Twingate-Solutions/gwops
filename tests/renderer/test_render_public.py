"""Tests for the public-mode ``tls`` render.

Public mode renders one ``tls.certificates.files`` entry per declared certificate at the
store's stable paths, sorted by certificate name, with no ``tls.automation`` and no gwops
leaf. Private output is unchanged.
"""

from pathlib import Path
from typing import Any

import pytest
import yaml

from gwops.configmodel.schema import EffectiveState
from gwops.renderer.capabilities import Capabilities
from gwops.renderer.render import (
    PUBLIC_TLS_ROOT,
    RenderError,
    RuntimePaths,
    render_gateway_config,
)
from gwops.settings import GwopsSettings
from tests.public_tls_support import ZONE, public_cert, public_seed, ssh, tls_block


@pytest.fixture
def paths() -> RuntimePaths:
    return RuntimePaths.from_settings(GwopsSettings())


def _render(state: EffectiveState, paths: RuntimePaths) -> dict[str, Any]:
    rendered = render_gateway_config(state, Capabilities(gateway_version="2.0.0"), paths)
    doc: dict[str, Any] = yaml.safe_load(rendered.config_yaml)
    return doc


def _state(certificates: list[dict[str, Any]], **top: Any) -> EffectiveState:
    return EffectiveState.model_validate(public_seed(tls_block(certificates=certificates), **top))


def _three_certs() -> list[dict[str, Any]]:
    """Declared out of name order on purpose."""
    return [
        public_cert("zeta", [f"zeta.{ZONE}"]),
        public_cert("alpha", [f"alpha.{ZONE}"]),
        public_cert("mid", [f"mid.{ZONE}"]),
    ]


class TestRuntimePaths:
    def test_the_public_roots_come_from_the_constant_and_the_data_dir(self) -> None:
        settings = GwopsSettings()

        paths = RuntimePaths.from_settings(settings)

        assert paths.public_tls_root == PUBLIC_TLS_ROOT == Path("/config/public-tls")
        assert paths.public_tls_dir == settings.data_dir / "public-tls"

    def test_public_cert_files_are_the_stores_stable_paths(self, paths: RuntimePaths) -> None:
        cert_file, key_file = paths.public_cert_files("wildcard")

        assert cert_file == paths.public_tls_dir / "wildcard" / "fullchain.pem"
        assert key_file == paths.public_tls_dir / "wildcard" / "privkey.pem"

    def test_public_cert_files_do_no_io(self, tmp_path: Path) -> None:
        missing = tmp_path / "never-created"
        paths = RuntimePaths.from_settings(GwopsSettings(data_dir=missing))

        paths.public_cert_files("any")

        assert not missing.exists()


class TestPublicRender:
    def test_one_entry_per_certificate_sorted_by_name(self, paths: RuntimePaths) -> None:
        doc = _render(_state(_three_certs()), paths)

        files = doc["tls"]["certificates"]["files"]
        expected = [
            {
                "certificateFile": paths.public_cert_files(name)[0].as_posix(),
                "privateKeyFile": paths.public_cert_files(name)[1].as_posix(),
            }
            for name in ("alpha", "mid", "zeta")
        ]
        assert files == expected

    def test_the_order_does_not_depend_on_the_seed_order(self, paths: RuntimePaths) -> None:
        forward = _render(_state(_three_certs()), paths)["tls"]
        backward = _render(_state(list(reversed(_three_certs()))), paths)["tls"]

        assert forward == backward

    def test_there_is_no_automation_and_nothing_but_certificates(
        self, paths: RuntimePaths
    ) -> None:
        doc = _render(_state(_three_certs()), paths)

        assert set(doc["tls"]) == {"certificates"}
        assert set(doc["tls"]["certificates"]) == {"files"}

    def test_the_gwops_leaf_is_not_rendered(self, paths: RuntimePaths) -> None:
        text = render_gateway_config(
            _state(_three_certs()), Capabilities(gateway_version="2.0.0"), paths
        ).config_yaml

        assert paths.leaf_cert_file.as_posix() not in text
        assert paths.leaf_key_file.as_posix() not in text
        assert paths.pki_dir.as_posix() + "/leaf" not in text

    def test_a_single_certificate_renders_one_entry(self, paths: RuntimePaths) -> None:
        state = EffectiveState.model_validate(public_seed())

        doc = _render(state, paths)

        [entry] = doc["tls"]["certificates"]["files"]
        assert entry["certificateFile"].endswith("/public-tls/wildcard/fullchain.pem")
        assert entry["privateKeyFile"].endswith("/public-tls/wildcard/privkey.pem")

    def test_the_rest_of_the_config_renders_as_in_private_mode(self, paths: RuntimePaths) -> None:
        state = _state(
            [public_cert("wild", [f"*.{ZONE}"])],
            ssh_upstreams=[ssh("web-1", f"web-1.{ZONE}:22")],
        )

        doc = _render(state, paths)

        assert doc["port"] == 8443
        assert doc["ssh"]["ca"]["local"]["privateKeyFile"] == paths.ssh_ca_key_file.as_posix()
        assert doc["log"]["sessionRecording"]["segment"]["maxSize"] == 256000


def _acme_cert(name: str) -> dict[str, Any]:
    return {"name": name, "names": [f"{name}.{ZONE}"], "source": "acme"}


def _mixed_state() -> EffectiveState:
    """``alpha`` is a file certificate; ``mid`` and ``zeta`` are ``source: acme``."""
    return EffectiveState.model_validate(
        public_seed(
            tls_block(
                certificates=[
                    _acme_cert("zeta"),
                    public_cert("alpha", [f"alpha.{ZONE}"]),
                    _acme_cert("mid"),
                ],
                acme={"email": "ops@example.com", "accept_tos": True},
            )
        )
    )


class TestPendingPublicCertificates:
    def test_paths_default_to_no_pending_certificates(self, paths: RuntimePaths) -> None:
        assert paths.pending_public_certs == frozenset()

    def test_with_pending_returns_a_copy_and_leaves_the_original_alone(
        self, paths: RuntimePaths
    ) -> None:
        pending = paths.with_pending_public_certs(["mid", "zeta"])

        assert pending.pending_public_certs == frozenset({"mid", "zeta"})
        assert paths.pending_public_certs == frozenset()
        assert pending.public_tls_dir == paths.public_tls_dir

    def test_a_pending_certificate_gets_no_entry(self, paths: RuntimePaths) -> None:
        doc = _render(_mixed_state(), paths.with_pending_public_certs({"zeta"}))

        files = doc["tls"]["certificates"]["files"]
        assert [f["certificateFile"] for f in files] == [
            paths.public_cert_files(name)[0].as_posix() for name in ("alpha", "mid")
        ]

    def test_the_remaining_entries_keep_name_order_and_the_stable_paths(
        self, paths: RuntimePaths
    ) -> None:
        doc = _render(_mixed_state(), paths.with_pending_public_certs({"alpha"}))

        assert doc["tls"]["certificates"]["files"] == [
            {
                "certificateFile": paths.public_cert_files(name)[0].as_posix(),
                "privateKeyFile": paths.public_cert_files(name)[1].as_posix(),
            }
            for name in ("mid", "zeta")
        ]

    def test_a_pending_name_that_is_not_declared_changes_nothing(
        self, paths: RuntimePaths
    ) -> None:
        plain = _render(_mixed_state(), paths)

        with_stray = _render(_mixed_state(), paths.with_pending_public_certs({"ghost"}))

        assert with_stray == plain

    def test_nothing_pending_renders_every_certificate(self, paths: RuntimePaths) -> None:
        doc = _render(_mixed_state(), paths.with_pending_public_certs(set()))

        assert len(doc["tls"]["certificates"]["files"]) == 3

    def test_every_certificate_pending_is_a_render_error(self, paths: RuntimePaths) -> None:
        pending = paths.with_pending_public_certs({"alpha", "mid", "zeta"})

        with pytest.raises(RenderError, match="no public certificate is installed to render"):
            render_gateway_config(_mixed_state(), Capabilities(gateway_version="2.0.0"), pending)

    def test_the_all_pending_error_names_acme_issuance(self, paths: RuntimePaths) -> None:
        pending = paths.with_pending_public_certs({"alpha", "mid", "zeta"})

        with pytest.raises(RenderError, match="pending ACME issuance"):
            render_gateway_config(_mixed_state(), Capabilities(gateway_version="2.0.0"), pending)

    def test_private_mode_ignores_the_pending_set(self, paths: RuntimePaths) -> None:
        state = EffectiveState.model_validate(
            {"twingate": {"network": "acme", "gateway_id": "g-1"}}
        )

        doc = _render(state, paths.with_pending_public_certs({"leaf", "alpha"}))

        assert doc["tls"] == {
            "certificates": {
                "files": [
                    {
                        "certificateFile": "/data/pki/leaf/fullchain.pem",
                        "privateKeyFile": "/data/pki/leaf/privkey.pem",
                    }
                ]
            }
        }


class TestPrivateRenderUnchanged:
    def test_private_mode_still_renders_the_leaf_at_the_stable_store_paths(
        self, paths: RuntimePaths
    ) -> None:
        state = EffectiveState.model_validate(
            {"twingate": {"network": "acme", "gateway_id": "g-1"}}
        )

        doc = _render(state, paths)

        assert doc["tls"] == {
            "certificates": {
                "files": [
                    {
                        "certificateFile": "/data/pki/leaf/fullchain.pem",
                        "privateKeyFile": "/data/pki/leaf/privkey.pem",
                    }
                ]
            }
        }

    def test_private_on_demand_still_renders_automation(self, paths: RuntimePaths) -> None:
        state = EffectiveState.model_validate(
            {
                "twingate": {"network": "acme", "gateway_id": "g-1"},
                "ca": {"x509": {"generate": True, "on_demand_issuance": True}},
            }
        )

        doc = _render(state, paths)

        assert "automation" in doc["tls"]
        assert len(doc["tls"]["certificates"]["files"]) == 1
