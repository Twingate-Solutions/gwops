"""Docker HEALTHCHECK client: probe the admin API's ``/healthz`` and exit 0/1.

``python:3.12-slim`` ships no ``curl``, so the image's ``HEALTHCHECK`` runs
``python -m gwops.healthcheck``. It issues one unauthenticated GET against the admin
API on loopback (``/healthz`` is the sole route exempt from bearer auth) and maps the
composite health signal to a process exit code: 0 iff the endpoint answers 200,
1 for anything else — 503 (gateway not RUNNING or last reconcile failed), a connection
error while uvicorn is still binding, or a timeout. It never raises.
"""

import sys

import httpx

from gwops.configmodel.loader import load_effective_state
from gwops.configmodel.store import OverlayStore
from gwops.settings import GwopsSettings

_TIMEOUT_SECONDS = 4.0  # under the HEALTHCHECK --timeout=5s so we own the failure, not Docker

# Bind values that mean "serving on all interfaces" — reachable on loopback from inside
# the container, which is where the healthcheck runs.
_WILDCARD_BINDS = frozenset({"0.0.0.0", "::", "localhost", "127.0.0.1"})


def check(url: str, *, timeout: float = _TIMEOUT_SECONDS) -> int:
    """Return 0 if ``url`` answers HTTP 200, else 1 — transport errors included."""
    try:
        response = httpx.get(url, timeout=timeout)
    except httpx.HTTPError:
        return 1
    return 0 if response.status_code == 200 else 1


def _resolve_admin_endpoint(settings: GwopsSettings) -> tuple[str, int]:
    """Resolve the (host, port) the admin API is actually served on.

    The server binds the *seed's* ``admin_api.bind``/``admin_api.port`` (not the
    ``GWOPS_HEALTHCHECK_ADMIN_FALLBACK`` env default), so the healthcheck must read the
    same effective state or it silently probes the wrong port whenever an operator
    overrides it. Falls back to the env-default port on loopback if the seed cannot be
    loaded.
    """
    try:
        store = OverlayStore(settings.data_dir / "overlays")
        state, _provenance = load_effective_state(settings.seed_path, store)
    except Exception:
        return "127.0.0.1", settings.healthcheck_admin_fallback
    bind = state.admin_api.bind
    host = "127.0.0.1" if bind in _WILDCARD_BINDS else bind
    return host, state.admin_api.port


def main() -> int:
    """Probe ``<admin bind>:<admin port>/healthz`` using the effective admin_api config."""
    settings = GwopsSettings()
    host, port = _resolve_admin_endpoint(settings)
    return check(f"http://{host}:{port}/healthz")


if __name__ == "__main__":
    sys.exit(main())
