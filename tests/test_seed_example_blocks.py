"""The commented-out blocks of seed.example.yaml are valid when uncommented.

The example ships its optional blocks (web apps, gateway-wide web-app settings, public
certificate mode in both variants, admin-API automation) as comments, so loading the shipped
file never exercises them. These tests uncomment them from the real file text, then load,
policy-check and render the result.

The uncomment transform (``uncomment_block``) is deterministic. A commented-out block starts
at a line that is exactly ``<indent># <key>:`` and runs through the consecutive lines that
start with ``<indent>#`` followed by at least two spaces (the block's nested content). Each
of those lines loses its ``# `` prefix; the indent before the ``#`` is kept. A blank line, a
bare ``#`` line or any other line ends the block. If the start line is not found, or no
nested line follows it, the helper raises, so a reworded or reformatted example fails these
tests instead of silently dropping the coverage.

Public mode serves DNS names inside its zones only, which the private-mode example names
(an IP literal, ``example.com`` hosts, a single-label alias) are not, and it replaces the
``ca.x509`` block. The public cases therefore also drop ``ca.x509`` and move every served name
into the zone (``_prepare_public_mode``); everything else is the example's own text.
"""

from pathlib import Path
from typing import Any

import pytest
import yaml

from gwops.access import webapp_policy
from gwops.configmodel.loader import ConfigLoadError, load_effective_state
from gwops.configmodel.schema import EffectiveState
from gwops.configmodel.store import OverlayStore
from gwops.renderer.capabilities import Capabilities
from gwops.renderer.render import (
    K8sCredentialFiles,
    RenderError,
    RuntimePaths,
    render_gateway_config,
)

SEED_EXAMPLE = Path(__file__).parent.parent / "seed.example.yaml"
ZONE = "example.com"
CERT_NAME = "wildcard"


def uncomment_block(text: str, key: str, *, indent: str = "", occurrence: int = 0) -> str:
    """Uncomment the `occurrence`-th commented-out ``key:`` block at `indent`.

    Raises:
        AssertionError: the block is not found, or it has no nested content.
    """
    lines = text.splitlines(keepends=True)
    start_line = f"{indent}# {key}:"
    starts = [i for i, line in enumerate(lines) if line.rstrip("\r\n") == start_line]
    assert len(starts) > occurrence, (
        f"seed.example.yaml has no commented-out block #{occurrence} starting with "
        f"{start_line!r} ({len(starts)} found); the example's layout changed, so update "
        "uncomment_block's convention or the example"
    )
    first = starts[occurrence]
    nested_prefix = f"{indent}#  "
    end = first + 1
    while end < len(lines) and lines[end].startswith(nested_prefix):
        end += 1
    assert end > first + 1, f"commented-out block {start_line!r} has no nested lines"
    for i in range(first, end):
        lines[i] = indent + lines[i][len(indent) + 2 :]
    return "".join(lines)


def _prepare_public_mode(data: dict[str, Any]) -> None:
    """Drop `ca.x509` and move every served name into ``ZONE`` (see the module docstring)."""
    data["ca"].pop("x509")
    for upstream in data["ssh_upstreams"]:
        upstream["address"] = f"{upstream['name']}.{ZONE}"
    for cluster in data["k8s_clusters"]:
        cluster["address"] = f"{cluster['name']}.{ZONE}"
    for app in data["web_apps"]:
        _, _, port = app["address"].partition(":")
        app["address"] = f"{app['name']}-upstream.{ZONE}" + (f":{port}" if port else "")
        if app.get("alias"):
            app["alias"] = f"{app['name']}.{ZONE}"


def _optional_blocks(text: str) -> str:
    """Uncomment the blocks shared by every case."""
    text = uncomment_block(text, "web_apps")
    text = uncomment_block(text, "web_app_proxy")
    return uncomment_block(text, "automation", indent="  ")


def _seed_text(case: str) -> str:
    text = _optional_blocks(SEED_EXAMPLE.read_text(encoding="utf-8"))
    if case == "public_file":
        return uncomment_block(text, "public_tls", occurrence=0)
    if case == "public_acme":
        return uncomment_block(text, "public_tls", occurrence=1)
    return text


def _write_seed(case: str, tmp_path: Path) -> Path:
    text = _seed_text(case)
    if case.startswith("public"):
        data = yaml.safe_load(text)
        _prepare_public_mode(data)
        text = yaml.safe_dump(data, sort_keys=False)
    seed = tmp_path / "seed.yaml"
    seed.write_text(text, encoding="utf-8")
    return seed


def _runtime_paths(tmp_path: Path, state: EffectiveState) -> RuntimePaths:
    data = tmp_path / "data"
    return RuntimePaths(
        pki_dir=data / "pki",
        recording_spool_dir=data / "recording-spool",
        k8s_creds_dir=data / "k8s-creds",
        upstream_ca_dir=data / "upstream-ca",
        k8s_source_root=tmp_path / "k8s-source",
        webapp_ca_root=tmp_path / "webapp-cas",
        public_tls_root=tmp_path / "public-tls",
        public_tls_dir=data / "public-tls",
    ).with_k8s_credentials(
        {
            c.name: K8sCredentialFiles(
                token=data / "k8s-creds" / f"{c.name}-token-abc",
                ca=data / "k8s-creds" / f"{c.name}-ca-abc.crt",
            )
            for c in state.k8s_clusters
        }
    ).with_upstream_ca_files(
        {b.name: data / "upstream-ca" / f"{b.name}-abc.pem"
         for b in state.web_app_proxy.upstream_ca_bundles}
    )


def _load(case: str, tmp_path: Path) -> EffectiveState:
    seed = _write_seed(case, tmp_path)
    state, _ = load_effective_state(seed, OverlayStore(tmp_path / "overlays"))
    return state


def _render(state: EffectiveState, paths: RuntimePaths) -> dict[str, Any]:
    rendered = render_gateway_config(state, Capabilities(), paths)
    return yaml.safe_load(rendered.config_yaml)


@pytest.mark.parametrize("case", ["private", "public_file", "public_acme"])
def test_uncommented_blocks_pass_policy_and_render(case: str, tmp_path: Path) -> None:
    state = _load(case, tmp_path)

    # The blocks really loaded (not silently empty).
    assert [a.name for a in state.web_apps] == ["grafana"]
    assert state.web_apps[0].alias is not None
    assert state.web_app_proxy.request_headers["X-Twingate-User"] == "{{username}}"
    assert [b.name for b in state.web_app_proxy.upstream_ca_bundles] == ["corp-root"]
    assert state.web_app_proxy.plaintext_upstreams is not None
    assert state.admin_api.automation.name_prefix == "auto-"

    assert webapp_policy.violations(state, Capabilities()) == []

    rendered = _render(state, _runtime_paths(tmp_path, state))
    assert [u["name"] for u in rendered["kubernetes"]["upstreams"]] == ["prod"]
    assert "X-Twingate-User" in rendered["webApp"]["requestHeaders"]
    assert len(rendered["upstreamTrustedCABundles"]) == 1


def test_private_mode_example_keeps_the_generated_leaf(tmp_path: Path) -> None:
    state = _load("private", tmp_path)
    paths = _runtime_paths(tmp_path, state)

    assert state.public_tls is None
    files = _render(state, paths)["tls"]["certificates"]["files"]
    assert files == [
        {
            "certificateFile": paths.leaf_cert_file.as_posix(),
            "privateKeyFile": paths.leaf_key_file.as_posix(),
        }
    ]


@pytest.mark.parametrize(
    ("case", "source"), [("public_file", "file"), ("public_acme", "acme")]
)
def test_public_tls_variants_render_the_declared_certificate(
    case: str, source: str, tmp_path: Path
) -> None:
    state = _load(case, tmp_path)
    paths = _runtime_paths(tmp_path, state)

    assert state.public_tls is not None
    assert state.public_tls.zones == [ZONE]
    assert [(c.name, c.source) for c in state.public_tls.certificates] == [(CERT_NAME, source)]
    assert (state.public_tls.acme is not None) == (source == "acme")

    cert_file, key_file = paths.public_cert_files(CERT_NAME)
    assert _render(state, paths)["tls"] == {
        "certificates": {
            "files": [
                {
                    "certificateFile": cert_file.as_posix(),
                    "privateKeyFile": key_file.as_posix(),
                }
            ]
        }
    }


def test_acme_example_refuses_to_render_while_its_certificate_is_pending(tmp_path: Path) -> None:
    state = _load("public_acme", tmp_path)
    paths = _runtime_paths(tmp_path, state).with_pending_public_certs({CERT_NAME})

    with pytest.raises(RenderError, match="pending ACME issuance"):
        render_gateway_config(state, Capabilities(), paths)


def test_public_tls_blocks_are_mutually_exclusive_with_ca_x509(tmp_path: Path) -> None:
    """Uncommenting public_tls without removing ca.x509 is refused, as the example says."""
    seed = tmp_path / "seed.yaml"
    seed.write_text(
        uncomment_block(SEED_EXAMPLE.read_text(encoding="utf-8"), "public_tls"),
        encoding="utf-8",
    )

    with pytest.raises(ConfigLoadError, match="mutually exclusive"):
        load_effective_state(seed, OverlayStore(tmp_path / "overlays"))


def test_uncomment_block_fails_loudly_when_the_block_is_missing() -> None:
    text = SEED_EXAMPLE.read_text(encoding="utf-8")

    with pytest.raises(AssertionError, match="no commented-out block"):
        uncomment_block(text, "no_such_block")
    with pytest.raises(AssertionError, match="no commented-out block #2"):
        uncomment_block(text, "public_tls", occurrence=2)
    with pytest.raises(AssertionError, match="no nested lines"):
        uncomment_block("# key:\n\nother: 1\n", "key")


def test_uncomment_block_strips_only_the_comment_prefix() -> None:
    text = "top:\n  # nested:\n  #   leaf: 1   # note\n  #\n  other: 2\n"

    assert uncomment_block(text, "nested", indent="  ") == (
        "top:\n  nested:\n    leaf: 1   # note\n  #\n  other: 2\n"
    )
