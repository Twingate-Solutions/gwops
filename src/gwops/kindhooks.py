"""Default per-kind hooks for :class:`gwops.kinds.ResourceKind`.

A kind whose Twingate resource carries more than the shared address and upstream port
(web apps: downstream port, TLS modes, alias, header rewrites) overrides these hooks on
its descriptor; SSH and Kubernetes use the defaults.

This module imports nothing from :mod:`gwops.tgapi`: ``gwops.tgapi.ops`` imports
:mod:`gwops.kinds`, so a reverse import would be a cycle. It also imports nothing from
:mod:`gwops.configmodel` (whose ``UpstreamEntry`` uses :data:`EMPTY_EXTRAS`).
"""

from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Any

Extras = Mapping[str, Any]
"""Kind-specific resource settings beyond address and upstream port; immutable by convention."""

EMPTY_EXTRAS: Extras = MappingProxyType({})
"""The shared empty :data:`Extras`, used by every kind with nothing extra to sync."""


REWRITES_KEY = "request_header_rewrites"
"""The :data:`Extras` key holding a web app's per-resource header rewrites."""

Rewrites = tuple[tuple[str, str], ...]
"""Normalised header rewrites: ``(name.lower(), value)`` pairs, sorted."""


def normalise_rewrites(rewrites: Iterable[tuple[str, str]] | None) -> Rewrites | None:
    """Comparison form of header rewrites; ``None`` (unmanaged) stays distinct from ``()``.

    Both drift sides must use it: :func:`normalise_extras` (desired) and ``parse_remote``.
    """
    if rewrites is None:
        return None
    return tuple(sorted((name.lower(), value) for name, value in rewrites))


def normalise_extras(extras: Extras) -> Extras:
    """Return `extras` with :data:`REWRITES_KEY` normalised; unchanged if the key is absent."""
    if REWRITES_KEY not in extras:
        return extras
    return MappingProxyType({**extras, REWRITES_KEY: normalise_rewrites(extras[REWRITES_KEY])})


def no_extras(node: dict[str, Any]) -> Extras:
    """Default ``parse_remote``: a listed resource node carries no kind-specific settings."""
    return EMPTY_EXTRAS


def upstream_port_only(port: int, extras: Extras) -> dict[str, Any]:
    """Default ``create_variables``: the create mutation's ``upstream`` is ``{port}`` alone."""
    return {"upstream": {"port": port}}


def no_drift(
    want_port: int, want_extras: Extras, remote_port: int, remote_extras: Extras
) -> dict[str, Any]:
    """Default ``settings_drift``: nothing beyond address and port is synced, so no drift."""
    return {}


WEBAPP_UPSTREAM_TLS_MODES = frozenset({"VERIFY_FULL", "VERIFY_CA", "INSECURE", "NONE"})
WEBAPP_DOWNSTREAM_TLS_MODES = frozenset({"TLS13", "NONE"})

_RewriteInputs = list[dict[str, str]]


def _tls_mode(leg: Mapping[str, Any], name: str, allowed: frozenset[str]) -> str:
    """The leg's ``tlsMode``; raises ValueError naming the field, never the value."""
    mode = leg["tlsMode"]
    if not isinstance(mode, str) or mode not in allowed:
        raise ValueError(f"web app node has an unknown {name}.tlsMode")
    return mode


def webapp_parse_remote(node: dict[str, Any]) -> Extras:
    """``parse_remote`` for web apps; returns the keys of ``WebApp.tg_extras()``.

    Raises:
        ValueError: Unknown ``tlsMode`` for a leg, or a rewrite that is not a string pair.
        KeyError: A leg or the rewrites list is missing.
    """
    upstream, downstream = node["upstream"], node["downstream"]
    upstream_mode = _tls_mode(upstream, "upstream", WEBAPP_UPSTREAM_TLS_MODES)
    downstream_mode = _tls_mode(downstream, "downstream", WEBAPP_DOWNSTREAM_TLS_MODES)
    pairs: list[tuple[str, str]] = []
    for rewrite in node["requestHeaderRewrites"]:
        key, value = rewrite["key"], rewrite["value"]
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("web app node has a requestHeaderRewrites entry that is not strings")
        pairs.append((key, value))
    alias = node.get("alias")
    return MappingProxyType(
        {
            "downstream_port": int(downstream["port"]),
            "downstream_tls_mode": downstream_mode,
            "upstream_tls_mode": upstream_mode,
            "alias": alias.lower() if isinstance(alias, str) and alias else None,
            "request_header_rewrites": normalise_rewrites(pairs),
        }
    )


def _rewrite_inputs(rewrites: Iterable[tuple[str, str]]) -> _RewriteInputs:
    return [{"key": name, "value": value} for name, value in rewrites]


def webapp_create_variables(port: int, extras: Extras) -> dict[str, Any]:
    """``create_variables`` for web apps; both ``tlsMode``s explicit."""
    variables: dict[str, Any] = {
        "upstream": {"port": port, "tlsMode": extras["upstream_tls_mode"]},
        "downstream": {
            "port": extras["downstream_port"],
            "tlsMode": extras["downstream_tls_mode"],
        },
    }
    if extras["alias"] is not None:
        variables["alias"] = extras["alias"]
    rewrites = extras["request_header_rewrites"]
    if rewrites is not None:
        variables["requestHeaderRewrites"] = _rewrite_inputs(rewrites)
    return variables


def webapp_settings_drift(
    want_port: int, want_extras: Extras, remote_port: int, remote_extras: Extras
) -> dict[str, Any]:
    """``settings_drift`` for web apps; a drifted leg is sent whole, unmanaged rewrites skipped."""
    drift: dict[str, Any] = {}
    want_upstream = (want_port, want_extras["upstream_tls_mode"])
    if want_upstream != (remote_port, remote_extras["upstream_tls_mode"]):
        drift["upstream"] = {"port": want_upstream[0], "tlsMode": want_upstream[1]}
    want_downstream = (want_extras["downstream_port"], want_extras["downstream_tls_mode"])
    if want_downstream != (
        remote_extras["downstream_port"],
        remote_extras["downstream_tls_mode"],
    ):
        drift["downstream"] = {"port": want_downstream[0], "tlsMode": want_downstream[1]}
    if want_extras["alias"] != remote_extras["alias"]:
        drift["alias"] = want_extras["alias"]
    want_rewrites = want_extras["request_header_rewrites"]
    if want_rewrites is not None and tuple(want_rewrites) != tuple(
        remote_extras["request_header_rewrites"] or ()
    ):
        drift["requestHeaderRewrites"] = _rewrite_inputs(want_rewrites)
    return drift
