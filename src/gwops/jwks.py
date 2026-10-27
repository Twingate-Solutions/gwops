"""Reachability probe for the Twingate tenant JWKS endpoint (``/api/v1/jwk/ec``).

The gateway fetches this key set to verify web-app tokens; gwops probes it so an egress,
proxy, DNS or TLS problem is visible before sessions fail. Observation only: a probe
result never gates startup, health or a reconcile pass. Nothing sensitive is sent or
logged: the request carries no credentials and response bodies are never logged.
"""

import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, cast, get_args

import httpx
import structlog

from gwops.tgapi.client import build_user_agent

logger = structlog.get_logger(__name__)

ErrorClass = Literal["unreachable", "degraded", "invalid", "internal_error"]

_PROBE_TIMEOUT_SECONDS = 5.0
_PROXY_AUTH_REQUIRED = 407


@dataclass(frozen=True, slots=True)
class JwksStatus:
    """Outcome of one probe; ``error_class`` is None when ``ok``, ``reason`` only on a mark."""

    ok: bool
    checked_at: datetime
    error_class: ErrorClass | None
    reason: str | None = None


def jwks_url(network: str, host: str) -> str:
    """Return the tenant's EC JWKS URL."""
    return f"https://{network}.{host}/api/v1/jwk/ec"


def make_client() -> httpx.AsyncClient:
    """Build the probe client: system trust roots, proxy env honoured, 5 s timeout."""
    return httpx.AsyncClient(
        verify=ssl.create_default_context(),
        trust_env=True,
        timeout=httpx.Timeout(_PROBE_TIMEOUT_SECONDS),
        headers={"User-Agent": build_user_agent()},
    )


def _failure(error_class: ErrorClass, reason: str | None = None) -> JwksStatus:
    return JwksStatus(
        ok=False, checked_at=datetime.now(UTC), error_class=error_class, reason=reason
    )


def _unreachable(url: str, hint: str, **fields: Any) -> JwksStatus:
    logger.error(
        "jwks.unreachable",
        url=url,
        reason=f"{hint} Check egress, proxy and DNS settings for this URL.",
        **fields,
    )
    return _failure("unreachable")


def _degraded(url: str, **fields: Any) -> JwksStatus:
    logger.warning("jwks.degraded", url=url, **fields)
    return _failure("degraded")


def _invalid(url: str, reason: str) -> JwksStatus:
    logger.warning("jwks.invalid", url=url, reason=reason)
    return _failure("invalid")


def _key_problem(key: object) -> str | None:
    """Return why `key` is not a usable EC P-256 JWK, or None if it is."""
    if not isinstance(key, dict):
        return "a key entry is not an object"
    if key.get("kty") != "EC":
        return "a key has kty other than EC"
    if key.get("crv") != "P-256":
        return "a key has crv other than P-256"
    kid = key.get("kid")
    if not isinstance(kid, str) or not kid:
        return "a key has no kid"
    return None


def _document_problem(document: object) -> str | None:
    """Return why `document` is not a usable JWKS, or None if it is."""
    if not isinstance(document, dict):
        return "body is not a JSON object"
    keys = document.get("keys")
    if not isinstance(keys, list) or not keys:
        return "keys is missing or empty"
    for key in keys:
        if (problem := _key_problem(key)) is not None:
            return problem
    return None


async def probe_jwks(client: httpx.AsyncClient, url: str) -> JwksStatus:
    """GET `url` and classify the result; transport and HTTP failures never raise."""
    try:
        response = await client.get(url)
    except httpx.TimeoutException as exc:
        return _degraded(url, error_type=type(exc).__name__)
    except httpx.ProxyError as exc:
        return _unreachable(url, "The proxy refused the request.", error_type=type(exc).__name__)
    except httpx.ConnectError as exc:
        cause = type(exc.__cause__).__name__ if exc.__cause__ else None
        return _unreachable(
            url,
            "Could not connect (DNS, refused connection or TLS verification).",
            error_type=type(exc).__name__,
            cause=cause,
        )
    except httpx.TransportError as exc:
        return _degraded(url, error_type=type(exc).__name__)

    code = response.status_code
    if code >= 500:
        return _degraded(url, status_code=code)
    if code != 200:
        hint = (
            "The proxy requires authentication."
            if code == _PROXY_AUTH_REQUIRED
            else f"The endpoint answered HTTP {code}."
        )
        return _unreachable(url, hint, status_code=code)

    try:
        document = response.json()
    except ValueError:
        return _invalid(url, "body is not JSON")
    if (problem := _document_problem(document)) is not None:
        return _invalid(url, problem)
    return JwksStatus(ok=True, checked_at=datetime.now(UTC), error_class=None)


class JwksMonitor:
    """Holds the latest probe status; ``check()`` refreshes it and never raises."""

    def __init__(self, client: httpx.AsyncClient, url: str) -> None:
        """Probe `url` with `client` (the caller owns and closes the client)."""
        self._client = client
        self._url = url
        self._status: JwksStatus | None = None

    @property
    def status(self) -> JwksStatus | None:
        """The latest status, or None before the first check."""
        return self._status

    async def check(self) -> JwksStatus:
        """Probe once, store and return the status; unexpected errors become internal_error."""
        try:
            status = await probe_jwks(self._client, self._url)
        except Exception as exc:
            logger.error("jwks.probe_failed", url=self._url, error_type=type(exc).__name__)
            status = _failure("internal_error")
        self._status = status
        return status

    def mark(self, error_class: str, reason: str) -> JwksStatus:
        """Store a failure the caller observed (e.g. a check timeout), replacing the last status."""
        if error_class not in get_args(ErrorClass):
            raise ValueError(f"unknown JWKS error_class {error_class!r}")
        status = _failure(cast(ErrorClass, error_class), reason)
        logger.warning("jwks.marked", url=self._url, error_class=error_class, reason=reason)
        self._status = status
        return status
