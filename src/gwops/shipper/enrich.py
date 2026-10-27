"""Adds the ``gwops`` web-app TLS object to the gateway's ``Authenticated connection`` lines."""

import json
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import structlog

from gwops.kinds import WEBAPP
from gwops.shipper.counters import FailureLog

if TYPE_CHECKING:
    from gwops.reconciler.core import RemoteWebApp

logger = structlog.get_logger(__name__)

SCHEMA = 1
"""Version of the ``gwops`` object; bumped on any incompatible change."""

_SYSTEM_LOGGER = "system"
_AUTHENTICATED = "Authenticated connection"
_WEB_APP = "WEB_APP"


@dataclass(frozen=True, slots=True)
class _App:
    """The fields of one web app that reach the ``gwops`` object."""

    name: str
    managed: bool
    downstream_tls: str
    downstream_port: int
    upstream_tls: str
    upstream_port: int


class WebAppIndex:
    """Last successful web-app snapshot for this gateway, keyed by exact address."""

    def __init__(self, on_enrich_failed: Callable[[], None] | None = None) -> None:
        """Start empty; `on_enrich_failed` is called once per line that failed to enrich."""
        self._on_enrich_failed = on_enrich_failed
        self._failures = FailureLog("enrich.failed")
        self._gateway_id: str | None = None
        self._by_address: dict[str, tuple[_App, ...]] = {}
        self._last_update_at: datetime | None = None
        self._fresh: bool | None = None

    @property
    def gateway_id(self) -> str | None:
        """This gateway's id as of the latest update; None until known."""
        return self._gateway_id

    @property
    def active(self) -> bool:
        """Whether a tenant listing has ever been applied (else lines get ``match: none``)."""
        return self._last_update_at is not None

    @property
    def last_update_at(self) -> datetime | None:
        """When a listing was last applied (UTC), or None if never."""
        return self._last_update_at

    @property
    def apps(self) -> int:
        """Web apps held in the index (those bound to this gateway)."""
        return sum(len(found) for found in self._by_address.values())

    def mark_stale(self) -> None:
        """Record a pass that applied no listing (e.g. the update itself failed)."""
        self._set_fresh(False)

    def _set_fresh(self, fresh: bool) -> None:
        """Log once when the index moves between fresh and stale (a stale first pass too)."""
        previous, self._fresh = self._fresh, fresh
        if previous == fresh or (previous is None and fresh):
            return
        since = self._last_update_at.isoformat() if self._last_update_at is not None else None
        if fresh:
            logger.info("enrich.index_fresh")
        else:
            logger.warning("enrich.index_stale", last_update_at=since)

    def update(
        self,
        remote_web_apps: Sequence["RemoteWebApp"] | None,
        gateway_id: str | None,
        managed_ids: Mapping[str, str] | None = None,
    ) -> None:
        """Rebuild from one reconcile pass; a pass that did not list the tenant keeps the index.

        `gateway_id` is :func:`gwops.gateway_id.gateway_id_for`; `managed_ids` is the registry's
        ``<kind>/<name> -> id`` map, which names a managed app by its declared entry.
        """
        if gateway_id is not None:
            self._gateway_id = gateway_id
        if remote_web_apps is None:
            self._set_fresh(False)
            return
        declared = _declared_names(managed_ids or {})
        grouped: dict[str, list[_App]] = {}
        for app in remote_web_apps:
            if gateway_id is None or app.gateway_id != gateway_id:
                continue
            grouped.setdefault(app.address, []).append(
                _App(
                    name=declared.get(app.id, app.name) if app.managed else app.name,
                    managed=app.managed,
                    downstream_tls=app.downstream_tls,
                    downstream_port=app.downstream_port,
                    upstream_tls=app.upstream_tls,
                    upstream_port=app.upstream_port,
                )
            )
        self._by_address = {address: tuple(apps) for address, apps in grouped.items()}
        self._last_update_at = datetime.now(UTC)
        self._set_fresh(True)

    def enrich(self, line: bytes, obj: Mapping[str, Any]) -> bytes:
        """Return `line` with the ``gwops`` object spliced in, or unchanged; never raises.

        `obj` is `line` parsed. Only an ``Authenticated connection`` line of a ``WEB_APP``
        connection without a top-level ``gwops`` key is touched.
        """
        try:
            return self._splice(line, obj)
        except Exception as exc:  # a line is never lost to enrichment
            if self._on_enrich_failed is not None:
                self._on_enrich_failed()
            error_type = type(exc).__name__
            self._failures.emit(error_type, error_type=error_type, location=_location(exc))
            return line

    def _splice(self, line: bytes, obj: Mapping[str, Any]) -> bytes:
        if (
            obj.get("logger") != _SYSTEM_LOGGER
            or obj.get("message") != _AUTHENTICATED
            or obj.get("resource_type") != _WEB_APP
            or "gwops" in obj
        ):
            return line
        body = line.rstrip()
        if not body.endswith(b"}"):
            return line
        cut = len(body) - 1
        payload = json.dumps(self._gwops(obj.get("resource_address")), separators=(",", ":"))
        return b"".join((line[:cut], b',"gwops":', payload.encode("ascii"), line[cut:]))

    def _gwops(self, address: object) -> dict[str, Any]:
        found = self._by_address.get(address, ()) if isinstance(address, str) else ()
        head: dict[str, Any] = {"schema": SCHEMA, "gateway_id": self._gateway_id}
        if len(found) > 1:
            return {**head, "match": "ambiguous"}
        if not found:
            return {**head, "match": "none"}
        app = found[0]
        return {
            **head,
            "match": "exact",
            "app": app.name,
            "managed": app.managed,
            "downstream_tls": app.downstream_tls,
            "downstream_port": app.downstream_port,
            "upstream_tls": app.upstream_tls,
            "upstream_port": app.upstream_port,
        }


def _location(exc: BaseException) -> str | None:
    """``file:line`` of the innermost traceback frame, without any line content."""
    tb = exc.__traceback__
    while tb is not None and tb.tb_next is not None:
        tb = tb.tb_next
    if tb is None:
        return None
    return f"{os.path.basename(tb.tb_frame.f_code.co_filename)}:{tb.tb_lineno}"


def _declared_names(managed_ids: Mapping[str, str]) -> dict[str, str]:
    """Resource id -> declared web-app entry name, from the registry's ``webapp/<name>`` keys."""
    prefix = WEBAPP.resource_key("")
    return {rid: key[len(prefix) :] for key, rid in managed_ids.items() if key.startswith(prefix)}
