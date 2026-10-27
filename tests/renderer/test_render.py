"""Tests for gwops.renderer.render: render_gateway_config golden-file + error behavior."""

from pathlib import Path
from typing import Any

import pytest
import yaml

from gwops.configmodel.schema import EffectiveState
from gwops.renderer.capabilities import Capabilities
from gwops.renderer.render import (
    K8sCredentialFiles,
    RenderedConfig,
    RenderError,
    RuntimePaths,
    render_gateway_config,
)
from gwops.settings import GwopsSettings

FIXTURES = Path(__file__).parent.parent / "fixtures" / "rendered"


def make_state(**overrides: Any) -> EffectiveState:
    base: dict[str, Any] = {"twingate": {"network": "acme", "gateway_id": "g-1"}}
    base.update(overrides)
    return EffectiveState.model_validate(base)


_SOLO_CREDENTIALS = K8sCredentialFiles(
    token=Path("/data/k8s-creds/solo-token-0123456789ab"),
    ca=Path("/data/k8s-creds/solo-ca-fedcba987654.crt"),
)


@pytest.fixture
def paths() -> RuntimePaths:
    """Runtime paths with the `solo` cluster's credential copies already materialized."""
    return RuntimePaths.from_settings(GwopsSettings()).with_k8s_credentials(
        {"solo": _SOLO_CREDENTIALS}
    )


def _load_fixture(name: str) -> dict[str, Any]:
    result: dict[str, Any] = yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))
    return result


def _all_keys(node: Any) -> set[str]:
    """Every mapping key at any depth of a parsed YAML document."""
    if isinstance(node, dict):
        return set(node) | {k for v in node.values() for k in _all_keys(v)}
    if isinstance(node, list):
        return {k for v in node for k in _all_keys(v)}
    return set()


class TestGoldenFiles:
    def test_minimal_render_matches_golden_file(self, paths: RuntimePaths) -> None:
        state = make_state(
            twingate={"network": "acme2", "gateway_id": "g-2"},
            k8s_clusters=[
                {"name": "solo", "address": "solo.k8s.internal", "port": 443,
                 "bearer_token_file": "/config/k8s-creds/solo.token",
                 "ca_file": "/config/k8s-creds/solo-ca.crt"},
            ],
        )
        rendered = render_gateway_config(state, Capabilities(gateway_version="2.0.0"), paths)
        assert isinstance(rendered, RenderedConfig)
        assert yaml.safe_load(rendered.config_yaml) == _load_fixture("minimal.yaml")

    def test_webapp_render_matches_golden_file(self) -> None:
        state = make_state(
            web_apps=[{"name": "grafana", "address": "grafana.example:3000"}],
            web_app_proxy={
                "request_headers": {"X-Trusted-User": "{{username}}"},
                "upstream_ca_bundles": [
                    {"name": "example-root", "file": "/config/webapp-cas/example-root.pem"}
                ],
            },
        )
        paths = RuntimePaths.from_settings(GwopsSettings()).with_upstream_ca_files(
            {"example-root": Path("/data/upstream-ca/example-root-abcdef123456.pem")}
        )
        rendered = render_gateway_config(state, Capabilities(gateway_version="2.0.0"), paths)
        assert isinstance(rendered, RenderedConfig)
        assert yaml.safe_load(rendered.config_yaml) == _load_fixture("webapp.yaml")


    def test_kubernetes_credentials_render_the_content_addressed_copies(
        self, paths: RuntimePaths
    ) -> None:
        state = make_state(
            k8s_clusters=[
                {"name": "solo", "address": "solo.k8s.internal", "port": 443,
                 "bearer_token_file": "/config/k8s-creds/solo.token",
                 "ca_file": "/config/k8s-creds/solo-ca.crt"},
            ],
        )
        doc = yaml.safe_load(
            render_gateway_config(state, Capabilities(gateway_version="2.0.0"), paths).config_yaml
        )
        [upstream] = doc["kubernetes"]["upstreams"]
        assert upstream["bearerTokenFile"] == "/data/k8s-creds/solo-token-0123456789ab"
        assert upstream["caFile"] == "/data/k8s-creds/solo-ca-fedcba987654.crt"

    def test_a_cluster_without_materialized_credentials_is_a_render_error(self) -> None:
        state = make_state(
            k8s_clusters=[
                {"name": "solo", "address": "solo.k8s.internal", "port": 443,
                 "bearer_token_file": "/config/k8s-creds/solo.token",
                 "ca_file": "/config/k8s-creds/solo-ca.crt"},
            ],
        )
        bare = RuntimePaths.from_settings(GwopsSettings())
        with pytest.raises(RenderError, match="solo.*materialized"):
            render_gateway_config(state, Capabilities(gateway_version="2.0.0"), bare)


class TestSessionRecordingCap:
    def test_segment_max_size_is_rendered_at_the_gateway_ceiling(
        self, paths: RuntimePaths
    ) -> None:
        # segment.maxSize is validated against 256 KiB (262_144 bytes); 256_000 is under it and
        # bounds SSH and Kubernetes recording segments alike.
        rendered = render_gateway_config(make_state(), Capabilities(), paths)
        doc = yaml.safe_load(rendered.config_yaml)
        assert doc["log"]["sessionRecording"]["segment"]["maxSize"] == 256000

    def test_recording_cap_renders_even_with_zero_upstreams(self, paths: RuntimePaths) -> None:
        rendered = render_gateway_config(make_state(), Capabilities(), paths)
        doc = yaml.safe_load(rendered.config_yaml)
        assert doc["log"] == {"sessionRecording": {"segment": {"maxSize": 256000}}}


class TestZeroClustersOmitsKubernetesSection:
    def test_no_k8s_clusters_omits_kubernetes_key(self, paths: RuntimePaths) -> None:
        state = make_state()  # zero ssh_upstreams and k8s_clusters
        rendered = render_gateway_config(state, Capabilities(), paths)
        doc = yaml.safe_load(rendered.config_yaml)
        assert "kubernetes" not in doc
        # Base sections still render even with nothing to proxy.
        assert doc["ssh"]["gateway"]["username"] == "gateway"


class TestMultiClusterRaisesLoudly:
    def test_more_than_one_cluster_raises(self, paths: RuntimePaths) -> None:
        state = make_state(
            k8s_clusters=[
                {"name": "prod", "address": "prod.k8s.internal", "port": 6443,
                 "bearer_token_file": "/t1", "ca_file": "/c1"},
                {"name": "staging", "address": "staging.k8s.internal", "port": 443,
                 "bearer_token_file": "/t2", "ca_file": "/c2"},
            ]
        )
        with pytest.raises(RenderError, match="single entry"):
            render_gateway_config(state, Capabilities(), paths)


class TestRenderedSchemaShape:
    def test_tls_nested_under_certificates_files(self, paths: RuntimePaths) -> None:
        rendered = render_gateway_config(make_state(), Capabilities(), paths)
        doc = yaml.safe_load(rendered.config_yaml)
        assert doc["tls"] == {
            "certificates": {
                "files": [
                    {
                        "certificateFile": paths.leaf_cert_file.as_posix(),
                        "privateKeyFile": paths.leaf_key_file.as_posix(),
                    }
                ]
            }
        }

    def test_ssh_ca_renders_as_local(self, paths: RuntimePaths) -> None:
        rendered = render_gateway_config(make_state(), Capabilities(), paths)
        doc = yaml.safe_load(rendered.config_yaml)
        assert doc["ssh"]["ca"] == {"local": {"privateKeyFile": paths.ssh_ca_key_file.as_posix()}}

    def test_byo_ssh_ca_key_path_used_verbatim(self, paths: RuntimePaths) -> None:
        state = make_state(ca={"ssh": {"generate": False, "key_path": "/mnt/byo/ssh-ca"}})
        rendered = render_gateway_config(state, Capabilities(), paths)
        doc = yaml.safe_load(rendered.config_yaml)
        assert doc["ssh"]["ca"]["local"]["privateKeyFile"] == "/mnt/byo/ssh-ca"

    @pytest.mark.parametrize(
        "state",
        [
            pytest.param(make_state(), id="minimal"),
            pytest.param(
                make_state(ca={"ssh": {"generate": False, "key_path": "/mnt/byo/ssh-ca"}}),
                id="byo-ssh-ca",
            ),
            pytest.param(
                make_state(
                    k8s_clusters=[
                        {"name": "solo", "address": "solo.k8s.internal", "port": 443,
                         "bearer_token_file": "/t", "ca_file": "/c"},
                    ]
                ),
                id="one-cluster",
            ),
        ],
    )
    def test_no_output_contains_removed_or_unsupported_keys(
        self, paths: RuntimePaths, state: EffectiveState
    ) -> None:
        rendered = render_gateway_config(state, Capabilities(gateway_version="2.0.0"), paths)
        doc = yaml.safe_load(rendered.config_yaml)
        keys = _all_keys(doc)

        # 1.x shapes and the old web-app keys (`cas`, `upstreamCABundles`) never appear.
        assert not keys & {
            "auditLog",
            "flushSizeThreshold",
            "manual",
            "cas",
            "upstreamCABundles",
        }
        # The TLS leaf renders only under tls.certificates.files[*], never flat.
        assert set(doc["tls"]) == {"certificates"}
        assert "certificateFile" in keys
        assert set(doc["ssh"]["ca"]) == {"local"}


_CA_COPY = Path("/data/upstream-ca/corp-0123456789ab.pem")
_CA_COPY_2 = Path("/data/upstream-ca/lab-fedcba987654.pem")


def _web_app_state(**proxy: Any) -> EffectiveState:
    """A state with one web app and the given `web_app_proxy` settings."""
    return make_state(
        web_apps=[{"name": "grafana", "address": "grafana.corp.internal"}],
        web_app_proxy=proxy,
    )


def _web_paths(**copies: Path) -> RuntimePaths:
    return RuntimePaths.from_settings(GwopsSettings()).with_upstream_ca_files(copies)


def _render_doc(state: EffectiveState, paths: RuntimePaths | None = None) -> dict[str, Any]:
    rendered = render_gateway_config(
        state, Capabilities(gateway_version="2.0.0"), paths or _web_paths()
    )
    result: dict[str, Any] = yaml.safe_load(rendered.config_yaml)
    return result


class TestWebAppBlock:
    """`webApp` renders iff web apps are declared."""

    def test_no_web_apps_renders_neither_block(self) -> None:
        doc = _render_doc(make_state())
        assert "webApp" not in doc
        assert "upstreamTrustedCABundles" not in doc

    def test_gateway_wide_settings_without_web_apps_render_nothing(self) -> None:
        state = make_state(
            web_app_proxy={
                "request_headers": {"X-Twingate-User": "{{username}}"},
                "upstream_ca_bundles": [{"name": "corp", "file": "/config/webapp-cas/c.pem"}],
            }
        )
        doc = _render_doc(state, _web_paths(corp=_CA_COPY))
        assert "webApp" not in doc
        assert "upstreamTrustedCABundles" not in doc

    def test_web_apps_without_headers_render_an_empty_block(self) -> None:
        doc = _render_doc(_web_app_state())
        assert doc["webApp"] == {}
        assert "upstreamTrustedCABundles" not in doc

    def test_headers_render_under_request_headers(self) -> None:
        doc = _render_doc(_web_app_state(request_headers={"X-Geo-City": "{{clientGeoCity}}"}))
        assert doc["webApp"] == {"requestHeaders": {"X-Geo-City": "{{clientGeoCity}}"}}

    def test_headers_render_sorted_case_insensitively_whatever_the_seed_order(self) -> None:
        forward = _web_app_state(
            request_headers={"X-B": "b", "x-a": "a", "X-C": "{{clientGeoCity}}"}
        )
        backward = _web_app_state(
            request_headers={"X-C": "{{clientGeoCity}}", "x-a": "a", "X-B": "b"}
        )
        text_forward = render_gateway_config(forward, Capabilities(), _web_paths()).config_yaml
        text_backward = render_gateway_config(backward, Capabilities(), _web_paths()).config_yaml
        assert text_forward == text_backward
        assert list(_render_doc(forward)["webApp"]["requestHeaders"]) == ["x-a", "X-B", "X-C"]

    def test_header_names_keep_their_case_and_values_are_verbatim(self) -> None:
        value = "geo: {{clientGeoCity}} "
        doc = _render_doc(_web_app_state(request_headers={"X-Mixed-Case": value}))
        assert doc["webApp"]["requestHeaders"] == {"X-Mixed-Case": value}

    def test_per_resource_headers_never_reach_the_config(self) -> None:
        state = make_state(
            web_apps=[
                {
                    "name": "grafana",
                    "address": "grafana.corp.internal",
                    "request_headers": {"X-Per-App": "per-app-value"},
                }
            ]
        )
        text = render_gateway_config(state, Capabilities(), _web_paths()).config_yaml
        assert "X-Per-App" not in text
        assert "per-app-value" not in text

    def test_block_order_is_stable(self) -> None:
        state = _web_app_state(
            request_headers={"X-Geo": "{{clientGeoCity}}"},
            upstream_ca_bundles=[{"name": "corp", "file": "/config/webapp-cas/c.pem"}],
        )
        keys = list(_render_doc(state, _web_paths(corp=_CA_COPY)))
        assert keys == [
            "twingate", "port", "metricsPort", "tls", "log", "ssh",
            "webApp", "upstreamTrustedCABundles",
        ]

    def test_a_blank_header_value_is_a_render_error_naming_only_the_header(self) -> None:
        state = _web_app_state(request_headers={"X-Blank": "   "})
        with pytest.raises(RenderError, match="X-Blank") as caught:
            _render_doc(state)
        assert "empty" in str(caught.value)

    def test_an_empty_header_value_is_a_render_error(self) -> None:
        with pytest.raises(RenderError, match="X-Empty"):
            _render_doc(_web_app_state(request_headers={"X-Empty": ""}))

    def test_an_empty_header_value_is_not_checked_without_web_apps(self) -> None:
        state = make_state(web_app_proxy={"request_headers": {"X-Empty": ""}})
        assert "webApp" not in _render_doc(state)


class TestSeparatorVariants:
    """Trusted header names also render with every `-`/`_` spelling of their separators."""

    @staticmethod
    def _headers(name: str, value: str = "{{username}}", **more: str) -> dict[str, str]:
        doc = _render_doc(_web_app_state(request_headers={name: value, **more}))
        headers: dict[str, str] = doc["webApp"]["requestHeaders"]
        return headers

    def test_one_separator_gives_one_extra_spelling(self) -> None:
        assert self._headers("X-User") == {"X-User": "{{username}}", "X_User": "{{username}}"}

    def test_two_separators_give_three_extra_spellings_with_the_same_template(self) -> None:
        headers = self._headers("X-Twingate-User")
        assert headers == {
            "X-Twingate-User": "{{username}}",
            "X-Twingate_User": "{{username}}",
            "X_Twingate-User": "{{username}}",
            "X_Twingate_User": "{{username}}",
        }

    def test_four_separators_give_every_one_of_sixteen_spellings(self) -> None:
        headers = self._headers("X-A-B-C-D")
        expected = {
            "X" + a + "A" + b + "B" + c + "C" + d + "D"
            for a in "-_"
            for b in "-_"
            for c in "-_"
            for d in "-_"
        }
        assert set(headers) == expected and len(headers) == 16
        assert set(headers.values()) == {"{{username}}"}

    def test_a_mixed_spelling_as_written_expands_to_the_same_set(self) -> None:
        assert set(self._headers("X_Twingate-User")) == set(self._headers("X-Twingate-User"))

    def test_a_groups_header_gets_its_variants(self) -> None:
        headers = self._headers("X-Twingate-Groups", "{{groups}}")
        assert headers["X_Twingate_Groups"] == headers["X-Twingate_Groups"] == "{{groups}}"

    def test_the_template_prefix_and_suffix_are_kept_in_the_variants(self) -> None:
        headers = self._headers("X-Id", "user:{{ username }};")
        assert headers["X_Id"] == headers["X-Id"] == "user:{{ username }};"

    def test_a_jwt_header_is_trusted_too(self) -> None:
        # Policy refuses gateway-wide {{jwt}}; the renderer does not rely on that.
        assert self._headers("X-Token", "{{jwt}}")["X_Token"] == "{{jwt}}"

    def test_geo_and_static_headers_get_no_variant(self) -> None:
        doc = _render_doc(
            _web_app_state(
                request_headers={
                    "X-Geo-City": "{{clientGeoCity}}",
                    "X-Static-Flag": "on",
                }
            )
        )
        assert set(doc["webApp"]["requestHeaders"]) == {"X-Geo-City", "X-Static-Flag"}

    def test_a_trusted_name_without_separators_has_no_variant(self) -> None:
        assert self._headers("Username") == {"Username": "{{username}}"}

    def test_variant_case_follows_the_written_name(self) -> None:
        assert self._headers("x-auth-user") == {
            "x-auth-user": "{{username}}",
            "x-auth_user": "{{username}}",
            "x_auth-user": "{{username}}",
            "x_auth_user": "{{username}}",
        }

    def test_variants_sort_stably_beside_their_names(self) -> None:
        headers = self._headers("X-Twingate-User", **{"X-Aaa": "a"})
        assert list(headers) == [
            "X-Aaa",
            "X-Twingate-User",
            "X-Twingate_User",
            "X_Twingate-User",
            "X_Twingate_User",
        ]

    def test_the_render_is_byte_stable_whatever_the_seed_order(self) -> None:
        one = {"X-Twingate-User": "{{username}}", "X-Twingate-Groups": "{{groups}}"}
        two = dict(reversed(list(one.items())))
        text_one = render_gateway_config(
            _web_app_state(request_headers=one), Capabilities(), _web_paths()
        ).config_yaml
        text_two = render_gateway_config(
            _web_app_state(request_headers=two), Capabilities(), _web_paths()
        ).config_yaml
        assert text_one == text_two

    def test_identical_explicit_variants_are_not_duplicated(self) -> None:
        headers = self._headers("X-Twingate-User", x_twingate_user="{{username}}")
        assert len(headers) == 4
        assert "x_twingate_user" in headers and "X_Twingate_User" not in headers

    @pytest.mark.parametrize(
        "spoofed", ["X_Twingate_User", "X-Twingate_User", "X_Twingate-User", "x_TWINGATE-user"]
    )
    def test_an_explicit_variant_with_another_value_is_a_render_error(self, spoofed: str) -> None:
        state = _web_app_state(
            request_headers={"X-Twingate-User": "{{username}}", spoofed: "spoofed"}
        )
        with pytest.raises(RenderError, match=spoofed) as caught:
            _render_doc(state)
        assert "spoofed" not in str(caught.value).replace(spoofed, "")

    def test_two_trusted_names_colliding_on_one_variant_with_different_values_fail(self) -> None:
        state = _web_app_state(
            request_headers={"X-A_B": "{{username}}", "X_A-B": "{{groups}}"}
        )
        with pytest.raises(RenderError, match="X_A-B"):
            _render_doc(state)

    def test_more_than_four_separators_is_a_render_error(self) -> None:
        state = _web_app_state(request_headers={"X-A-B-C-D-E": "{{username}}"})
        with pytest.raises(RenderError, match="X-A-B-C-D-E") as caught:
            _render_doc(state)
        assert "4" in str(caught.value)


class TestUpstreamTrustedCABundles:
    def _state(self, *bundles: tuple[str, str], web_apps: bool = True) -> EffectiveState:
        return make_state(
            web_apps=[{"name": "grafana", "address": "grafana.corp.internal"}] if web_apps else [],
            web_app_proxy={
                "upstream_ca_bundles": [{"name": n, "file": f} for n, f in bundles]
            },
        )

    def test_bundles_render_as_file_only_entries_in_seed_order(self) -> None:
        state = self._state(
            ("lab", "/config/webapp-cas/lab.pem"), ("corp", "/config/webapp-cas/corp.pem")
        )
        doc = _render_doc(state, _web_paths(corp=_CA_COPY, lab=_CA_COPY_2))
        assert doc["upstreamTrustedCABundles"] == [
            {"file": _CA_COPY_2.as_posix()},
            {"file": _CA_COPY.as_posix()},
        ]

    def test_the_seed_name_and_source_path_never_reach_the_config(self) -> None:
        state = self._state(("corp", "/config/webapp-cas/source-name.pem"))
        text = render_gateway_config(state, Capabilities(), _web_paths(corp=_CA_COPY)).config_yaml
        assert "source-name" not in text
        assert "name" not in yaml.safe_load(text)["upstreamTrustedCABundles"][0]

    def test_no_bundles_omits_the_key_even_with_web_apps(self) -> None:
        assert "upstreamTrustedCABundles" not in _render_doc(self._state())

    def test_a_bundle_without_a_materialized_copy_is_a_render_error(self) -> None:
        state = self._state(("corp", "/config/webapp-cas/corp.pem"))
        with pytest.raises(RenderError, match="corp.*materialized"):
            _render_doc(state, _web_paths())

    def test_a_duplicate_rendered_file_is_a_render_error(self) -> None:
        state = self._state(
            ("corp", "/config/webapp-cas/corp.pem"), ("lab", "/config/webapp-cas/lab.pem")
        )
        with pytest.raises(RenderError, match="duplicate.*upstream-ca"):
            _render_doc(state, _web_paths(corp=_CA_COPY, lab=_CA_COPY))

    def test_a_changed_copy_changes_the_rendered_text(self) -> None:
        state = self._state(("corp", "/config/webapp-cas/corp.pem"))
        first = render_gateway_config(state, Capabilities(), _web_paths(corp=_CA_COPY))
        second = render_gateway_config(state, Capabilities(), _web_paths(corp=_CA_COPY_2))
        assert first.config_yaml != second.config_yaml


class TestWebAppRenderStability:
    def test_rendering_twice_is_byte_identical(self) -> None:
        state = _web_app_state(
            request_headers={"X-Twingate-User": "{{username}}", "X-Geo": "{{clientGeoCity}}"},
            upstream_ca_bundles=[{"name": "corp", "file": "/config/webapp-cas/c.pem"}],
        )
        paths = _web_paths(corp=_CA_COPY)
        first = render_gateway_config(state, Capabilities(), paths).config_yaml
        assert render_gateway_config(state, Capabilities(), paths).config_yaml == first

    def test_without_web_apps_web_app_settings_change_nothing(
        self, paths: RuntimePaths
    ) -> None:
        plain = render_gateway_config(make_state(), Capabilities(), paths).config_yaml
        with_settings = render_gateway_config(
            make_state(web_app_proxy={"request_headers": {"X-A": "a"}}), Capabilities(), paths
        ).config_yaml
        assert with_settings == plain


class TestRuntimePaths:
    def test_upstream_ca_files_are_the_materialized_copies(self) -> None:
        paths = RuntimePaths.from_settings(GwopsSettings()).with_upstream_ca_files(
            {"corp": _CA_COPY}
        )
        assert paths.upstream_ca_file("corp") == _CA_COPY

    def test_upstream_ca_file_for_an_unmaterialized_bundle_raises(self) -> None:
        paths = RuntimePaths.from_settings(GwopsSettings())
        with pytest.raises(RenderError, match="corp"):
            paths.upstream_ca_file("corp")

    def test_with_upstream_ca_files_returns_a_new_value(self) -> None:
        bare = RuntimePaths.from_settings(GwopsSettings())
        extended = bare.with_upstream_ca_files({"corp": _CA_COPY})
        assert extended is not bare
        with pytest.raises(RenderError):
            bare.upstream_ca_file("corp")

    def test_with_upstream_ca_files_keeps_the_k8s_credentials(self) -> None:
        paths = (
            RuntimePaths.from_settings(GwopsSettings())
            .with_k8s_credentials({"solo": _SOLO_CREDENTIALS})
            .with_upstream_ca_files({"corp": _CA_COPY})
        )
        assert paths.k8s_token_file("solo") == _SOLO_CREDENTIALS.token

    def test_with_k8s_credentials_keeps_the_upstream_ca_files(self) -> None:
        paths = (
            RuntimePaths.from_settings(GwopsSettings())
            .with_upstream_ca_files({"corp": _CA_COPY})
            .with_k8s_credentials({"solo": _SOLO_CREDENTIALS})
        )
        assert paths.upstream_ca_file("corp") == _CA_COPY

    def test_from_settings_derives_canonical_paths(self) -> None:
        settings = GwopsSettings()
        paths = RuntimePaths.from_settings(settings)
        assert paths.leaf_cert_file.as_posix() == "/data/pki/leaf/fullchain.pem"
        assert paths.leaf_key_file.as_posix() == "/data/pki/leaf/privkey.pem"
        assert paths.ssh_ca_key_file.as_posix() == "/data/pki/ssh-ca.key"
        assert paths.k8s_creds_dir.as_posix() == "/data/k8s-creds"
        assert paths.upstream_ca_dir.as_posix() == "/data/upstream-ca"

    def test_leaf_paths_are_the_material_stores_stable_paths(self) -> None:
        """The rendered leaf paths and CertManager's store agree on the stable location."""
        from gwops.certs.store import MaterialStore

        paths = RuntimePaths.from_settings(GwopsSettings())

        assert MaterialStore(paths.pki_dir).stable_paths("leaf") == (
            paths.leaf_cert_file,
            paths.leaf_key_file,
        )

    def test_confined_source_roots_are_under_config_not_data(self) -> None:
        paths = RuntimePaths.from_settings(GwopsSettings())
        assert paths.k8s_source_root.as_posix() == "/config/k8s-creds"
        assert paths.webapp_ca_root.as_posix() == "/config/webapp-cas"

    def test_k8s_credential_stems_and_suffix(self) -> None:
        paths = RuntimePaths.from_settings(GwopsSettings())
        assert paths.k8s_token_stem("prod") == "prod-token"
        assert paths.k8s_ca_stem("prod") == "prod-ca"
        assert RuntimePaths.K8S_CA_SUFFIX == ".crt"

    def test_k8s_files_are_the_materialized_copies(self) -> None:
        paths = RuntimePaths.from_settings(GwopsSettings()).with_k8s_credentials(
            {"solo": _SOLO_CREDENTIALS}
        )
        assert paths.k8s_token_file("solo") == _SOLO_CREDENTIALS.token
        assert paths.k8s_ca_file("solo") == _SOLO_CREDENTIALS.ca

    def test_k8s_files_for_an_unmaterialized_cluster_raise(self) -> None:
        paths = RuntimePaths.from_settings(GwopsSettings())
        with pytest.raises(RenderError, match="prod"):
            paths.k8s_token_file("prod")
        with pytest.raises(RenderError, match="prod"):
            paths.k8s_ca_file("prod")

    def test_with_k8s_credentials_returns_a_new_value(self) -> None:
        bare = RuntimePaths.from_settings(GwopsSettings())
        extended = bare.with_k8s_credentials({"solo": _SOLO_CREDENTIALS})
        assert extended is not bare
        with pytest.raises(RenderError):
            bare.k8s_token_file("solo")
