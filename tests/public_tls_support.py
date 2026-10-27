"""Shared builders for the public-mode (`public_tls`) seed tests.

Builders return plain dicts so a test can break exactly one key. Nothing here touches the
filesystem except :func:`load`, which writes a seed under ``tmp_path``.
"""

from pathlib import Path
from typing import Any

import yaml

from gwops.configmodel.loader import ConfigLoadError, load_effective_state
from gwops.configmodel.schema import EffectiveState
from gwops.configmodel.store import OverlayStore

ZONE = "example.com"


def public_cert(
    name: str = "wildcard", names: list[str] | None = None, **fields: Any
) -> dict[str, Any]:
    """One ``public_tls.certificates`` entry; `fields` override or add keys."""
    entry: dict[str, Any] = {
        "name": name,
        "names": [f"*.{ZONE}"] if names is None else names,
        "source": "file",
        "cert_file": f"/config/public-tls/{name}/fullchain.pem",
        "key_file": f"/config/public-tls/{name}/privkey.pem",
    }
    entry.update(fields)
    return entry


def tls_block(
    zones: list[str] | None = None,
    certificates: list[dict[str, Any]] | None = None,
    **fields: Any,
) -> dict[str, Any]:
    """A valid ``public_tls`` block; `fields` override or add keys."""
    block: dict[str, Any] = {
        "zones": [ZONE] if zones is None else zones,
        "registered_root": "isrg_root_x1",
        "certificates": [public_cert()] if certificates is None else certificates,
    }
    block.update(fields)
    return block


def public_seed(tls: dict[str, Any] | None = None, **top: Any) -> dict[str, Any]:
    """A seed in public mode; `top` adds or overrides top-level keys."""
    seed: dict[str, Any] = {
        "twingate": {"network": "acme", "gateway_id": "g-1"},
        "public_tls": tls_block() if tls is None else tls,
    }
    seed.update(top)
    return seed


def ssh(name: str, address: str) -> dict[str, Any]:
    return {"name": name, "address": address}


def webapp(name: str, address: str, alias: str | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"name": name, "address": address}
    if alias is not None:
        entry["alias"] = alias
    return entry


def k8s(name: str, address: str) -> dict[str, Any]:
    return {
        "name": name,
        "address": address,
        "bearer_token_file": "/config/k8s-creds/token",
        "ca_file": "/config/k8s-creds/ca.crt",
    }


def load(tmp_path: Path, seed: dict[str, Any]) -> EffectiveState:
    """Load `seed` through the startup entry point (seed file -> overlays -> validation)."""
    seed_path = tmp_path / "seed.yaml"
    seed_path.write_text(yaml.safe_dump(seed, sort_keys=False), encoding="utf-8")
    state, _provenance = load_effective_state(seed_path, OverlayStore(tmp_path / "overlays"))
    return state


def load_error(tmp_path: Path, seed: dict[str, Any]) -> str:
    """The startup-abort message for `seed`; fails the test if the seed loads."""
    try:
        load(tmp_path, seed)
    except ConfigLoadError as exc:
        return str(exc)
    raise AssertionError("the seed loaded; expected a ConfigLoadError")
