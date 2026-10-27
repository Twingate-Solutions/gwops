"""Exception hierarchy for failed Twingate GraphQL API calls.

Every exception here carries enough context to diagnose a failure (HTTP status,
the GraphQL operation name, a truncated response body) but never the API key —
callers must not put the key in ``body`` or ``query_name``.
"""

_MAX_BODY_CHARS = 500


def _truncate(body: str) -> str:
    """Truncate `body` to a safe length for logs and exception messages."""
    if len(body) <= _MAX_BODY_CHARS:
        return body
    return body[:_MAX_BODY_CHARS] + "...(truncated)"


class TGAPIError(Exception):
    """Base error for a failed Twingate GraphQL API call.

    :param status: HTTP status code, or ``None`` for transport-level failures
        (connection errors, timeouts) that never got a response.
    :param query_name: the GraphQL operation name (e.g. ``ListResources``).
    :param body: the raw response body (or diagnostic text), truncated for safety.
    """

    def __init__(self, message: str, *, status: int | None, query_name: str, body: str) -> None:
        super().__init__(message)
        self.status = status
        self.query_name = query_name
        self.body = _truncate(body)


class TGAuthError(TGAPIError):
    """The API key was rejected by the server (HTTP 401 or 403)."""


class TGRateLimited(TGAPIError):
    """The API rate limit was exceeded and all retries were exhausted (HTTP 429)."""


class TGGraphQLError(TGAPIError):
    """A 200 OK response whose payload carried a GraphQL ``errors[]`` array."""

    def __init__(
        self,
        message: str,
        *,
        status: int,
        query_name: str,
        body: str,
        errors: list[dict[str, object]],
    ) -> None:
        super().__init__(message, status=status, query_name=query_name, body=body)
        self.errors = errors
