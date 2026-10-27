"""Counts of gateway lines not shipped, by reason; no line content is ever held."""

import time
from collections.abc import Callable
from typing import Any

import structlog

from gwops.shipper.filter import DropReason

logger = structlog.get_logger(__name__)


class DropCounters:
    """Per-reason drop counts since process start, with change tracking for the periodic log."""

    def __init__(self) -> None:
        """Start every reason, and the enrichment failure count, at zero."""
        self._counts: dict[DropReason, int] = dict.fromkeys(DropReason, 0)
        self._logged: dict[DropReason, int] = dict(self._counts)
        self._enrich_failed = 0
        self._enrich_failed_logged = 0

    def count(self, reason: DropReason, n: int = 1) -> None:
        """Record `n` dropped lines (one by default)."""
        self._counts[reason] += n

    def count_enrich_failed(self) -> None:
        """Record one line shipped unchanged because enrichment failed."""
        self._enrich_failed += 1

    @property
    def enrich_failed(self) -> int:
        """Lines shipped unchanged because enrichment failed, since process start."""
        return self._enrich_failed

    def snapshot(self) -> dict[str, int]:
        """Counts keyed by reason value, all reasons present."""
        return {reason.value: n for reason, n in self._counts.items()}

    def take_changed(self) -> dict[str, int] | None:
        """Counts plus `enrich_failed` if any changed since the last call that returned them."""
        if self._counts == self._logged and self._enrich_failed == self._enrich_failed_logged:
            return None
        self._logged = dict(self._counts)
        self._enrich_failed_logged = self._enrich_failed
        return {**self.snapshot(), "enrich_failed": self._enrich_failed}


class FailureLog:
    """Logs a failure at once per key, then at most once per interval with a suppressed count."""

    def __init__(
        self,
        event: str,
        *,
        interval: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Log under `event`; `clock` is injectable for tests."""
        self._event = event
        self._interval = interval
        self._clock = clock
        self._last: dict[str, float] = {}
        self._suppressed: dict[str, int] = {}

    def emit(self, key: str, **fields: Any) -> None:
        """Log an error for `key` unless one was logged within the interval."""
        now = self._clock()
        last = self._last.get(key)
        if last is not None and now - last < self._interval:
            self._suppressed[key] = self._suppressed.get(key, 0) + 1
            return
        self._last[key] = now
        suppressed = self._suppressed.pop(key, 0)
        if suppressed:
            fields["suppressed"] = suppressed
        logger.error(self._event, **fields)
