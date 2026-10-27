"""Client for the rig's gwops admin API (httpx); the bearer token never reaches a log."""

from collections.abc import Mapping
from typing import Any

import httpx

REQUEST_TIMEOUT = 180.0


class AdminError(Exception):
    """An admin API call failed; `status` is the HTTP status, None for a transport error."""

    def __init__(self, message: str, status: int | None = None) -> None:
        """Keep the message (status and path only) and the HTTP status."""
        super().__init__(message)
        self.status = status


class AdminClient:
    """Admin-token client for http://127.0.0.1:<port>."""

    def __init__(self, port: int, token: str, *, client: httpx.AsyncClient | None = None) -> None:
        """Bind the published admin port; `client` is a test seam."""
        self._base = f"http://127.0.0.1:{port}"
        self._http = client or httpx.AsyncClient(timeout=httpx.Timeout(REQUEST_TIMEOUT))
        self._headers = {"Authorization": f"Bearer {token}"}

    async def aclose(self) -> None:
        """Close the HTTP client."""
        await self._http.aclose()

    async def _request(
        self, method: str, path: str, body: Mapping[str, Any] | None = None, *, auth: bool = True
    ) -> httpx.Response:
        try:
            return await self._http.request(
                method,
                self._base + path,
                json=None if body is None else dict(body),
                headers=self._headers if auth else None,
            )
        except httpx.HTTPError as exc:
            raise AdminError(f"{method} {path}: {type(exc).__name__}") from None

    async def healthz(self) -> bool:
        """True when /healthz answers 200."""
        try:
            return (await self._request("GET", "/healthz", auth=False)).status_code == 200
        except AdminError:
            return False

    async def _json(self, response: httpx.Response, what: str) -> dict[str, Any]:
        if response.status_code != 200:
            raise AdminError(f"{what}: HTTP {response.status_code}", response.status_code)
        try:
            value = response.json()
        except ValueError:
            raise AdminError(f"{what}: non-JSON body") from None
        if not isinstance(value, dict):
            raise AdminError(f"{what}: unexpected body")
        return value

    async def status(self) -> dict[str, Any]:
        """GET /status."""
        return await self._json(await self._request("GET", "/status"), "GET /status")

    async def reconcile(self) -> dict[str, Any]:
        """POST /reconcile (admin route; a reconcile pass, not a signal)."""
        return await self._json(await self._request("POST", "/reconcile"), "POST /reconcile")

    async def get_webapp(self, name: str) -> dict[str, Any]:
        """GET /upstreams/webapp/<name>."""
        path = f"/upstreams/webapp/{name}"
        return await self._json(await self._request("GET", path), f"GET {path}")

    async def get_ssh(self, name: str) -> dict[str, Any]:
        """GET /upstreams/ssh/<name>."""
        path = f"/upstreams/ssh/{name}"
        return await self._json(await self._request("GET", path), f"GET {path}")

    async def put_webapp(self, name: str, body: Mapping[str, Any]) -> httpx.Response:
        """PUT /upstreams/webapp/<name>; the caller inspects the status."""
        return await self._request("PUT", f"/upstreams/webapp/{name}", body)


def response_text(response: httpx.Response, limit: int = 600) -> str:
    """A response body excerpt for logs (the API never echoes header values or secrets)."""
    return response.text[:limit]
