"""Rig web-app verifier: checks the Twingate Gateway Access Token (GAT) and echoes its claims."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import jwt
import uvicorn
from _version import __version__
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

log = logging.getLogger("webapp-verifier")

PRODUCT = "twingate-gwops-gateway-verifier"

ISSUERS = {
    "twingate.com": "twingate",
    "stg.opstg.com": "twingate-stg",
    "dev.opstg.com": "twingate-dev",
    "sec.opstg.com": "twingate-sec",
    "test": "twingate-local",
}
ALGORITHMS = ["ES256"]
LEEWAY_SECONDS = 30
JWKS_TIMEOUT_SECONDS = 5.0
JWKS_DEFAULT_TTL_SECONDS = 300.0
MAX_TOKEN_BYTES = 16384
METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.IGNORECASE)


def build_user_agent(*, version: str = __version__) -> str:
    """Return the attribution User-Agent sent on every request to Twingate."""
    return f"{PRODUCT}/{version} python-httpx/{httpx.__version__}"


class Unauthorized(Exception):
    """Raised for any failed check; ``reason`` is a fixed code, never request data."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, kw_only=True)
class VerifierSettings:
    """Expected tenant and resource; the issuer and JWKS URL derive from them."""

    network: str
    host: str
    expected_resource_id: str

    def __post_init__(self) -> None:
        """Reject blank fields and hosts with no issuer mapping."""
        for name in ("network", "host", "expected_resource_id"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must not be blank")
        if self.host not in ISSUERS:
            raise ValueError(f"host {self.host!r} has no issuer mapping; known: {sorted(ISSUERS)}")

    @property
    def issuer(self) -> str:
        """Return the ``iss`` value for the configured host."""
        return ISSUERS[self.host]

    @property
    def jwks_url(self) -> str:
        """Return the tenant's JWKS URL."""
        return f"https://{self.network}.{self.host}/api/v1/jwk/ec"

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> VerifierSettings:
        """Build settings from TWINGATE_NETWORK, TWINGATE_HOST and GAT_EXPECTED_RESOURCE_ID."""
        env = os.environ if environ is None else environ
        values: dict[str, str] = {}
        for field, var in (
            ("network", "TWINGATE_NETWORK"),
            ("host", "TWINGATE_HOST"),
            ("expected_resource_id", "GAT_EXPECTED_RESOURCE_ID"),
        ):
            value = env.get(var, "").strip()
            if not value:
                raise ValueError(f"{var} must be set and non-blank")
            values[field] = value
        return cls(**values)


class JwksCache:
    """Tenant signing keys cached per Cache-Control, with one refetch on an unknown kid."""

    def __init__(self, url: str, client: httpx.AsyncClient) -> None:
        self._url = url
        self._client = client
        self._keys: dict[str, jwt.PyJWK] = {}
        self._expires = 0.0
        self._lock = asyncio.Lock()

    async def key_for(self, kid: str) -> jwt.PyJWK:
        """Return the key for ``kid``, refetching once if it is unknown."""
        async with self._lock:
            fetched = False
            if time.monotonic() >= self._expires:
                await self._fetch()
                fetched = True
            if kid not in self._keys and not fetched:
                await self._fetch()
            key = self._keys.get(kid)
        if key is None:
            raise Unauthorized("unknown_kid")
        return key

    async def _fetch(self) -> None:
        """Replace the cache from the JWKS endpoint; any failure raises Unauthorized."""
        try:
            response = await self._client.get(
                self._url,
                headers={"User-Agent": build_user_agent()},
                timeout=httpx.Timeout(JWKS_TIMEOUT_SECONDS),
                follow_redirects=False,
            )
            response.raise_for_status()
            document = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            self._expires = 0.0
            raise Unauthorized(f"jwks_fetch_failed:{type(exc).__name__}") from None
        keys = _parse_keys(document)
        if not keys:
            self._expires = 0.0
            raise Unauthorized("jwks_unusable")
        self._keys = keys
        self._expires = time.monotonic() + _ttl(response.headers.get("cache-control"))


def _ttl(cache_control: str | None) -> float:
    """Return seconds to cache, from max-age; no-store and no-cache give 0."""
    if cache_control is None:
        return JWKS_DEFAULT_TTL_SECONDS
    lowered = cache_control.lower()
    if "no-store" in lowered or "no-cache" in lowered:
        return 0.0
    match = _MAX_AGE.search(cache_control)
    return float(match.group(1)) if match else JWKS_DEFAULT_TTL_SECONDS


def _parse_keys(document: Any) -> dict[str, jwt.PyJWK]:
    """Map kid to PyJWK for every usable key; malformed entries are skipped."""
    entries = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        return {}
    keys: dict[str, jwt.PyJWK] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("kid"), str):
            continue
        try:
            keys[entry["kid"]] = jwt.PyJWK(entry)
        except (jwt.PyJWTError, ValueError, KeyError, TypeError):
            log.warning("skipping unusable JWKS entry")
    return keys


def _bearer_token(authorization: str | None) -> str:
    """Return the token from ``Bearer <token>`` or raise Unauthorized."""
    parts = (authorization or "").split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise Unauthorized("missing_or_malformed_authorization")
    if len(parts[1]) > MAX_TOKEN_BYTES:
        raise Unauthorized("token_too_large")
    return parts[1]


def _precheck(token: str, settings: VerifierSettings) -> str:
    """Return the kid after unverified ES256, iss and aud checks, before any key fetch."""
    try:
        header = jwt.get_unverified_header(token)
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        raise Unauthorized("undecodable_token") from None
    kid = header.get("kid")
    if header.get("alg") not in ALGORITHMS:
        raise Unauthorized("alg_not_allowed")
    if not isinstance(kid, str) or not kid:
        raise Unauthorized("missing_kid")
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if claims.get("iss") != settings.issuer or settings.network not in audiences:
        raise Unauthorized("iss_or_aud_mismatch")
    return kid


def _check_payload(claims: dict[str, Any], settings: VerifierSettings) -> None:
    """Require typ, ver, and a WEB_APP resource whose id is this app's own."""
    resource = claims.get("resource")
    if claims.get("typ") != "GAT" or claims.get("ver") != "1":
        raise Unauthorized("typ_or_ver_mismatch")
    if not isinstance(resource, dict) or resource.get("type") != "WEB_APP":
        raise Unauthorized("resource_type_mismatch")
    if resource.get("id") != settings.expected_resource_id:
        raise Unauthorized("resource_id_mismatch")


async def _verify(request: Request, settings: VerifierSettings, cache: JwksCache) -> dict[str, Any]:
    """Return the verified GAT claims or raise Unauthorized."""
    token = _bearer_token(request.headers.get("authorization"))
    kid = _precheck(token, settings)
    key = await cache.key_for(kid)
    try:
        claims = jwt.decode(
            token,
            key.key,
            algorithms=ALGORITHMS,
            issuer=settings.issuer,
            audience=settings.network,
            leeway=LEEWAY_SECONDS,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except jwt.PyJWTError as exc:
        raise Unauthorized(f"token_invalid:{type(exc).__name__}") from None
    _check_payload(claims, settings)
    return claims


def create_app(settings: VerifierSettings, http_client: httpx.AsyncClient | None = None) -> FastAPI:
    """Build the verifier app; ``http_client`` serves the JWKS fetch (created lazily if None)."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    holder: dict[str, JwksCache] = {}

    def cache() -> JwksCache:
        if "cache" not in holder:
            client = http_client or httpx.AsyncClient(timeout=httpx.Timeout(JWKS_TIMEOUT_SECONDS))
            holder["cache"] = JwksCache(settings.jwks_url, client)
        return holder["cache"]

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        """Return liveness without touching the request or the JWKS."""
        return {"status": "ok"}

    @app.api_route("/{path:path}", methods=METHODS, include_in_schema=False)
    async def guard(request: Request) -> Response:
        """Verify the GAT on every path; 200 with claims and headers, otherwise a bare 401."""
        try:
            claims = await _verify(request, settings, cache())
        except Unauthorized as exc:
            log.info("rejected request: %s", exc.reason)
            return _unauthorized()
        except Exception as exc:
            log.error("verification error: %s", type(exc).__name__)
            return _unauthorized()
        headers = dict(request.headers)
        headers["authorization"] = "[redacted]"
        return JSONResponse({"claims": claims, "headers": headers})

    return app


def _unauthorized() -> JSONResponse:
    """Return the fixed 401 body; it carries no token, claim or failure detail."""
    return JSONResponse(
        {"detail": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer"}
    )


def _required_file(var: str) -> str:
    """Return the readable file path in env var ``var`` or exit naming the problem."""
    value = os.environ.get(var, "").strip()
    if not value:
        sys.exit(f"{var} must be set: the verifier serves HTTPS only")
    path = Path(value)
    if not path.is_file() or not os.access(path, os.R_OK):
        sys.exit(f"{var}={value} is not a readable file")
    return value


def main() -> None:
    """Serve the verifier over HTTPS; exits non-zero on bad settings or a missing certificate."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        settings = VerifierSettings.from_env()
    except ValueError as exc:
        sys.exit(str(exc))
    try:
        port = int(os.environ.get("VERIFIER_PORT", "8443"))
    except ValueError:
        sys.exit("VERIFIER_PORT must be an integer")
    uvicorn.run(
        create_app(settings),
        host=os.environ.get("VERIFIER_HOST", "0.0.0.0"),
        port=port,
        ssl_certfile=_required_file("VERIFIER_TLS_CERT"),
        ssl_keyfile=_required_file("VERIFIER_TLS_KEY"),
        server_header=False,
    )


if __name__ == "__main__":
    main()
