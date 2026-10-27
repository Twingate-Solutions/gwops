"""DropCounters and FailureLog: per-reason counts, change tracking, rate-limited failure logs."""

import structlog.testing

from gwops.shipper.counters import DropCounters, FailureLog
from gwops.shipper.filter import DropReason

_ZERO = {"not_json": 0, "not_allowlisted": 0, "too_long": 0, "spool_failed": 0}


def test_every_reason_starts_at_zero() -> None:
    assert DropCounters().snapshot() == _ZERO


def test_count_increments_only_its_reason() -> None:
    counters = DropCounters()
    counters.count(DropReason.NOT_ALLOWLISTED)
    counters.count(DropReason.NOT_ALLOWLISTED)
    assert counters.snapshot() == {**_ZERO, "not_allowlisted": 2}


def test_spool_failed_is_a_reason() -> None:
    counters = DropCounters()
    counters.count(DropReason.SPOOL_FAILED)
    assert counters.snapshot()["spool_failed"] == 1


def test_take_changed_returns_the_counts_once_per_change() -> None:
    counters = DropCounters()
    assert counters.take_changed() is None
    counters.count(DropReason.TOO_LONG)
    assert counters.take_changed() == {**_ZERO, "too_long": 1, "enrich_failed": 0}
    assert counters.take_changed() is None
    counters.count(DropReason.NOT_JSON)
    assert counters.take_changed() == {**_ZERO, "not_json": 1, "too_long": 1, "enrich_failed": 0}


def test_take_changed_does_not_reset_the_snapshot() -> None:
    counters = DropCounters()
    counters.count(DropReason.NOT_JSON)
    counters.take_changed()
    assert counters.snapshot()["not_json"] == 1


def test_enrich_failures_are_counted_apart_from_the_drop_reasons() -> None:
    counters = DropCounters()
    counters.count_enrich_failed()
    counters.count_enrich_failed()
    assert counters.enrich_failed == 2
    assert counters.snapshot() == _ZERO


def test_an_enrich_failure_alone_triggers_the_periodic_log() -> None:
    counters = DropCounters()
    counters.count_enrich_failed()
    assert counters.take_changed() == {**_ZERO, "enrich_failed": 1}
    assert counters.take_changed() is None


class TestFailureLog:
    def test_the_first_failure_per_key_logs_at_once_at_error_level(self) -> None:
        log = FailureLog("x.failed", clock=lambda: 0.0)
        with structlog.testing.capture_logs() as logs:
            log.emit("a", error_type="OSError")
            log.emit("b", error_type="ValueError")
        assert [(e["event"], e["log_level"], e["error_type"]) for e in logs] == [
            ("x.failed", "error", "OSError"),
            ("x.failed", "error", "ValueError"),
        ]

    def test_later_failures_are_suppressed_within_the_interval_then_reported_with_a_count(
        self,
    ) -> None:
        now = [0.0]
        log = FailureLog("x.failed", interval=60.0, clock=lambda: now[0])
        with structlog.testing.capture_logs() as logs:
            log.emit("a", error_type="OSError")
            now[0] = 10.0
            log.emit("a", error_type="OSError")
            now[0] = 59.0
            log.emit("a", error_type="OSError")
            assert len(logs) == 1
            now[0] = 61.0
            log.emit("a", error_type="OSError")
            now[0] = 125.0
            log.emit("a", error_type="OSError")
        assert [e.get("suppressed") for e in logs] == [None, 2, None]


def test_count_accepts_a_batch_size() -> None:
    counters = DropCounters()
    counters.count(DropReason.SPOOL_FAILED, 5)
    counters.count(DropReason.SPOOL_FAILED)
    assert counters.snapshot()["spool_failed"] == 6
