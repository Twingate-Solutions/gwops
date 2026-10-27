"""Spool tests: cursor semantics across restart, rotation, and bounded loud eviction.

A kill -9 mid-stream (simulated by dropping the Spool object without commit and reopening
the directory) re-reads every uncommitted line and never re-reads a committed one: no loss,
no duplication beyond what the cursor semantics promise.
"""

import stat
import sys
from pathlib import Path
from typing import BinaryIO

import pytest
import structlog.testing

import gwops.shipper.spool as spool_module
from gwops.shipper.limits import LINE_MAX_BYTES
from gwops.shipper.spool import Spool
from tests.spool_support import make_flaky

_posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX permission bits are not enforced on Windows"
)

KIB = 1024


def make_spool(
    tmp_path: Path, *, max_bytes: int = 64 * KIB, rotate_bytes: int = 4 * KIB
) -> Spool:
    return Spool(tmp_path / "spool", max_bytes, rotate_bytes=rotate_bytes)


class Clock:
    """A settable monotonic clock."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def lines(n: int, prefix: str = "line", pad: int = 0) -> list[str]:
    return [f'{{"event":"{prefix}-{i:04d}","pad":"{"x" * pad}"}}' for i in range(n)]


class TestRoundTrip:
    def test_append_read_commit(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path)
        for line in lines(3):
            spool.append(line.encode())
        batch, cursor = spool.read_batch()
        assert batch == lines(3)
        assert cursor.lines_read == 3
        spool.commit(cursor)
        batch2, cursor2 = spool.read_batch()
        assert batch2 == []
        assert cursor2.lines_read == 0

    def test_empty_spool_reads_nothing(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path)
        batch, cursor = spool.read_batch()
        assert batch == []
        assert cursor.lines_read == 0

    def test_max_lines_bounds_batch(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path)
        for line in lines(10):
            spool.append(line.encode())
        batch, cursor = spool.read_batch(max_lines=4)
        assert batch == lines(10)[:4]
        spool.commit(cursor)
        batch2, _ = spool.read_batch(max_lines=100)
        assert batch2 == lines(10)[4:]

    def test_lines_are_verbatim(self, tmp_path: Path) -> None:
        """Byte-identical round-trip — Gatorcast's classifier depends on exact shapes."""
        fixture = (
            Path(__file__).parent.parent / "fixtures" / "sample_log_lines.ndjson"
        ).read_text(encoding="utf-8")
        originals = [line for line in fixture.splitlines() if line]
        spool = make_spool(tmp_path)
        for line in originals:
            spool.append(line.encode())
        batch, _ = spool.read_batch()
        assert batch == originals


class TestRestart:
    def test_uncommitted_lines_survive_restart(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path)
        for line in lines(5):
            spool.append(line.encode())
        spool.read_batch()  # read but never committed — the "kill -9 mid-POST" case
        spool.close()

        reopened = make_spool(tmp_path)
        batch, _ = reopened.read_batch()
        assert batch == lines(5)

    def test_committed_lines_never_resent(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path)
        for line in lines(5):
            spool.append(line.encode())
        batch, cursor = spool.read_batch(max_lines=3)
        spool.commit(cursor)
        spool.close()

        reopened = make_spool(tmp_path)
        batch2, _ = reopened.read_batch()
        assert batch2 == lines(5)[3:]

    def test_restart_then_append_keeps_order(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path)
        spool.append(b"a")
        spool.append(b"b")
        _, cursor = spool.read_batch()
        spool.commit(cursor)
        spool.append(b"c")
        spool.close()

        reopened = make_spool(tmp_path)
        reopened.append(b"d")
        batch, _ = reopened.read_batch()
        assert batch == ["c", "d"]


class TestRotation:
    def test_rotation_creates_segments_and_reads_across(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path, rotate_bytes=1 * KIB)
        payload = lines(30, pad=100)  # ~130 B each -> several 1 KiB segments
        for line in payload:
            spool.append(line.encode())
        segments = sorted((tmp_path / "spool").glob("*.ndjson"))
        assert len(segments) > 1
        batch, cursor = spool.read_batch(max_lines=1000)
        assert batch == payload
        spool.commit(cursor)

    def test_commit_deletes_fully_consumed_segments(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path, rotate_bytes=1 * KIB)
        for line in lines(30, pad=100):
            spool.append(line.encode())
        before = len(list((tmp_path / "spool").glob("*.ndjson")))
        batch, cursor = spool.read_batch(max_lines=1000)
        assert len(batch) == 30
        spool.commit(cursor)
        after = len(list((tmp_path / "spool").glob("*.ndjson")))
        assert after < before


class TestLargeLines:
    def test_a_line_larger_than_rotate_bytes_sits_alone_in_its_own_segment(
        self, tmp_path: Path
    ) -> None:
        spool = make_spool(tmp_path, rotate_bytes=1 * KIB)
        big = "b" * (10 * KIB)
        spool.append(b"before")
        spool.append(big.encode())
        spool.append(b"after")
        spool.flush()
        segments = sorted((tmp_path / "spool").glob("*.ndjson"))
        assert [p.read_bytes() for p in segments] == [
            b"before\n",
            big.encode() + b"\n",
            b"after\n",
        ]
        batch, _ = spool.read_batch()
        assert batch == ["before", big, "after"]

    def test_max_bytes_caps_a_batch_and_nothing_is_lost(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path)
        payload = ["x" * 99 for _ in range(5)]  # 100 B each with its newline
        for line in payload:
            spool.append(line.encode())
        batch, cursor = spool.read_batch(max_bytes=250)
        assert batch == payload[:2]
        spool.commit(cursor)
        batch, cursor = spool.read_batch(max_bytes=250)
        assert batch == payload[2:4]
        spool.commit(cursor)
        batch, cursor = spool.read_batch(max_bytes=250)
        assert batch == payload[4:]

    def test_max_bytes_exactly_filled_by_whole_lines(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path)
        payload = ["x" * 99 for _ in range(3)]
        for line in payload:
            spool.append(line.encode())
        batch, _ = spool.read_batch(max_bytes=200)
        assert batch == payload[:2]

    def test_max_bytes_spans_segments(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path, rotate_bytes=150)
        payload = ["y" * 99 for _ in range(4)]
        for line in payload:
            spool.append(line.encode())
        assert len(list((tmp_path / "spool").glob("*.ndjson"))) > 1
        batch, cursor = spool.read_batch(max_bytes=250)
        assert batch == payload[:2]
        spool.commit(cursor)
        batch, _ = spool.read_batch(max_bytes=250)
        assert batch == payload[2:]

    def test_line_over_the_byte_cap_is_returned_alone(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path)
        big = "z" * 1000
        for line in ("small", big, "tail"):
            spool.append(line.encode())
        batch, cursor = spool.read_batch(max_bytes=100)
        assert batch == ["small"]
        spool.commit(cursor)
        batch, cursor = spool.read_batch(max_bytes=100)
        assert batch == [big]
        spool.commit(cursor)
        batch, _ = spool.read_batch(max_bytes=100)
        assert batch == ["tail"]

    def test_line_at_line_max_bytes_ships_alone(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path, max_bytes=64 * 1024 * KIB, rotate_bytes=4 * 1024 * KIB)
        big = "q" * LINE_MAX_BYTES
        spool.append(b"lead")
        spool.append(big.encode())
        spool.append(b"trail")
        batch, cursor = spool.read_batch()
        assert batch == ["lead"]
        spool.commit(cursor)
        batch, cursor = spool.read_batch()
        assert batch == [big]
        spool.commit(cursor)
        batch, _ = spool.read_batch()
        assert batch == ["trail"]

    def test_huge_sealed_segment_evicts_loudly_and_reads_resume(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path, max_bytes=64 * KIB, rotate_bytes=4 * KIB)
        first, second = "f" * (40 * KIB), "g" * (40 * KIB)
        with structlog.testing.capture_logs() as logs:
            spool.append(first.encode())
            spool.append(second.encode())
        evictions = [e for e in logs if e["event"] == "spool.evicted"]
        assert len(evictions) == 1
        assert evictions[0]["lines_lost"] == 1
        assert spool.pending_lines == 1
        batch, cursor = spool.read_batch()
        assert batch == [second]
        spool.commit(cursor)
        assert spool.pending_lines == 0


class TestNewestLineIsNeverEvicted:
    """A budget of exactly one cap-size line must still hold that line."""

    @staticmethod
    def _spool(tmp_path: Path) -> Spool:
        return make_spool(tmp_path, max_bytes=LINE_MAX_BYTES, rotate_bytes=4 * 1024 * KIB)

    def test_a_cap_size_line_after_committed_small_lines_is_in_the_next_batch(
        self, tmp_path: Path
    ) -> None:
        spool = self._spool(tmp_path)
        for line in lines(3):
            spool.append(line.encode())
        _, cursor = spool.read_batch()
        spool.commit(cursor)
        big = "c" * LINE_MAX_BYTES
        spool.append(big.encode())
        batch, cursor = spool.read_batch()
        assert batch == [big]
        spool.commit(cursor)
        assert spool.pending_lines == 0

    def test_pending_small_lines_make_way_loudly_for_a_cap_size_line(self, tmp_path: Path) -> None:
        spool = self._spool(tmp_path)
        for _ in range(3):  # 3 MiB pending in the active segment
            spool.append(b"s" * (1024 * KIB - 1))
        big = "c" * LINE_MAX_BYTES
        with structlog.testing.capture_logs() as logs:
            spool.append(big.encode())
        evictions = [e for e in logs if e["event"] == "spool.evicted"]
        assert [e["lines_lost"] for e in evictions] == [3]
        batch, _ = spool.read_batch()
        assert batch == [big]
        assert spool.pending_lines == 1

    def test_the_segment_with_the_newest_line_survives_even_when_over_budget(
        self, tmp_path: Path
    ) -> None:
        spool = make_spool(tmp_path, max_bytes=1 * KIB, rotate_bytes=512)
        spool.append(b"a" * 100)
        spool.append(b"z" * (4 * KIB))
        assert spool.read_batch()[0][-1] == "z" * (4 * KIB)


class TestEviction:
    def test_eviction_honors_bound_and_logs_error(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path, max_bytes=4 * KIB, rotate_bytes=1 * KIB)
        with structlog.testing.capture_logs() as logs:
            for line in lines(100, pad=100):
                spool.append(line.encode())
        spool.flush()
        total = sum(p.stat().st_size for p in (tmp_path / "spool").glob("*.ndjson"))
        assert total <= 4 * KIB
        evictions = [e for e in logs if e["event"] == "spool.evicted"]
        assert evictions, "eviction must be loud (ERROR)"
        assert all(e["log_level"] == "error" for e in evictions)
        assert all(e["lines_lost"] > 0 and e["bytes_lost"] > 0 for e in evictions)

    def test_reads_resume_after_eviction(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path, max_bytes=4 * KIB, rotate_bytes=1 * KIB)
        payload = lines(100, pad=100)
        for line in payload:
            spool.append(line.encode())
        batch, cursor = spool.read_batch(max_lines=1000)
        # Oldest lines were evicted; whatever remains is a contiguous tail, in order.
        assert batch == payload[len(payload) - len(batch):]
        assert 0 < len(batch) < 100
        spool.commit(cursor)
        assert spool.pending_lines == 0


class TestCommitAfterEviction:
    def test_lines_evicted_mid_batch_are_not_debited_again_by_the_commit(
        self, tmp_path: Path
    ) -> None:
        spool = make_spool(tmp_path, max_bytes=1000, rotate_bytes=400)
        for _ in range(8):  # 100 B each: segment 1 and segment 2 hold four lines apiece
            spool.append(b"o" * 99)
        batch, cursor = spool.read_batch()
        assert len(batch) == 8 and cursor.segment == 2

        for tag in (b"1", b"2", b"3"):  # the third pushes the spool over budget: segment 1 goes
            spool.append(tag * 99)
        assert spool.pending_lines == 7

        spool.commit(cursor)

        assert spool.pending_lines == 3
        assert spool.read_batch()[0] == ["1" * 99, "2" * 99, "3" * 99]

    def test_a_commit_with_nothing_evicted_debits_the_whole_batch(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path, rotate_bytes=400)
        for _ in range(9):
            spool.append(b"o" * 99)
        _, cursor = spool.read_batch()
        spool.commit(cursor)
        assert spool.pending_lines == 0


class TestWriteFailures:
    def test_a_failed_write_leaves_no_partial_line_and_the_next_append_is_clean(
        self, tmp_path: Path
    ) -> None:
        spool = make_spool(tmp_path)
        for line in lines(3):
            spool.append(line.encode())
        spool.flush()
        handle = make_flaky(spool)
        handle.fail_write = True
        with pytest.raises(OSError, match="disk full"):
            spool.append(b"torn-line-torn-line")
        handle.fail_write = False
        spool.append(b"next")
        batch, _ = spool.read_batch()
        assert batch == [*lines(3), "next"]
        assert spool.pending_lines == 4
        on_disk = sum(p.stat().st_size for p in (tmp_path / "spool").glob("*.ndjson"))
        assert spool.pending_bytes == on_disk

    def test_lines_buffered_before_a_failed_write_are_dropped_loudly_and_counted_out(
        self, tmp_path: Path
    ) -> None:
        spool = make_spool(tmp_path)
        for line in lines(3):
            spool.append(line.encode())  # buffered, not flushed
        lost_counts: list[int] = []
        spool.on_lost = lost_counts.append
        handle = make_flaky(spool)
        handle.fail_write = True
        with structlog.testing.capture_logs() as logs, pytest.raises(OSError):
            spool.append(b"x" * 50)
        handle.fail_write = False
        [lost] = [e for e in logs if e["event"] == "spool.buffered_lines_lost"]
        assert lost["lines_lost"] == 3 and lost["log_level"] == "error"
        assert lost_counts == [3]  # the failing line is the raised error, not in this count
        assert spool.pending_lines == 0
        spool.append(b"next")
        assert spool.read_batch()[0] == ["next"]
        assert spool.pending_lines == 1

    def test_a_failed_periodic_flush_raises_and_keeps_the_counters_consistent(
        self, tmp_path: Path
    ) -> None:
        spool = Spool(tmp_path / "spool", 64 * KIB, rotate_bytes=4 * KIB, flush_every=2)
        spool.append(b"kept-by-flush")
        spool.append(b"kept-by-flush-too")  # flushed here
        spool.append(b"buffered")
        lost_counts: list[int] = []
        spool.on_lost = lost_counts.append
        handle = make_flaky(spool)
        handle.fail_flush = True
        with pytest.raises(OSError, match="disk full"):
            spool.append(b"fails-on-flush")
        handle.fail_flush = False
        assert lost_counts == [1]  # "buffered"; the line whose flush failed is the raised error
        assert spool.pending_lines == 2
        spool.append(b"next")
        assert spool.read_batch()[0] == ["kept-by-flush", "kept-by-flush-too", "next"]

    def test_a_failed_public_flush_reports_every_lost_line_and_does_not_raise(
        self, tmp_path: Path
    ) -> None:
        spool = make_spool(tmp_path)
        for line in lines(4):
            spool.append(line.encode())
        lost_counts: list[int] = []
        spool.on_lost = lost_counts.append
        handle = make_flaky(spool)
        handle.fail_flush = True
        spool.flush()
        handle.fail_flush = False
        assert lost_counts == [4]
        assert spool.pending_lines == 0

    def test_a_flush_then_truncate_failure_never_lets_a_read_pass_the_flushed_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spool = make_spool(tmp_path)
        spool.append(b"committed")
        _, cursor = spool.read_batch()
        spool.commit(cursor)
        for line in (b"lost-1" + b"x" * 20, b"lost-2" + b"y" * 20):
            spool.append(line)  # buffered
        lost: list[int] = []
        spool.on_lost = lost.append
        make_flaky(spool).fail_flush = True
        real_open = Path.open

        def failing_open(self: Path, mode: str = "r", *args: object, **kw: object) -> object:
            if mode == "r+b":
                raise OSError("cannot truncate")
            return real_open(self, mode, *args, **kw)  # type: ignore[arg-type]

        monkeypatch.setattr(Path, "open", failing_open)
        spool.flush()  # fails; closing the handle pushes the bytes to disk; the reset fails
        assert lost == [2]

        batch, cursor = spool.read_batch()  # must not see, or commit past, the unflushed bytes
        assert batch == []
        spool.commit(cursor)

        monkeypatch.setattr(Path, "open", real_open)
        spool.append(b"next")  # the reset now succeeds and truncates
        batch, cursor = spool.read_batch()
        assert batch == ["next"]
        spool.commit(cursor)
        assert spool.pending_lines == 0

    def test_a_failed_reopen_is_retried_by_the_next_append(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spool = make_spool(tmp_path)
        spool.append(b"first")
        spool.flush()
        handle = make_flaky(spool)
        handle.fail_write = True
        real_open = spool_module._open_segment_append

        def broken(_path: Path) -> BinaryIO:
            raise OSError("cannot reopen")

        monkeypatch.setattr(spool_module, "_open_segment_append", broken)
        with pytest.raises(OSError, match="disk full"):
            spool.append(b"torn-line")
        with pytest.raises(OSError, match="cannot reopen"):
            spool.append(b"still-failing")
        monkeypatch.setattr(spool_module, "_open_segment_append", real_open)
        spool.append(b"recovered")
        assert spool.read_batch()[0] == ["first", "recovered"]
        assert spool.pending_lines == 2

    def test_a_failed_rotate_keeps_writing_to_the_old_segment_and_logs_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock()
        spool = Spool(tmp_path / "spool", 64 * KIB, rotate_bytes=100, clock=clock)
        real_open = spool_module._open_segment_append

        def broken(_path: Path) -> BinaryIO:
            raise OSError("no inodes")

        spool.append(b"a" * 80)
        monkeypatch.setattr(spool_module, "_open_segment_append", broken)
        with structlog.testing.capture_logs() as logs:
            spool.append(b"b" * 40)  # needs a rotate, which fails
            clock.now += 10
            spool.append(b"c" * 40)  # retried after the back-off, fails again, no new log
        assert [e["event"] for e in logs] == ["spool.rotate_failed"]
        assert logs[0]["error_type"] == "OSError"
        monkeypatch.setattr(spool_module, "_open_segment_append", real_open)
        clock.now += 10
        spool.append(b"d" * 40)  # rotates now
        spool.flush()
        assert len(list((tmp_path / "spool").glob("*.ndjson"))) == 2
        assert spool.read_batch()[0] == ["a" * 80, "b" * 40, "c" * 40, "d" * 40]
        assert spool.pending_lines == 4


class TestRotateBackoff:
    def test_a_failing_rotation_is_retried_at_most_once_per_interval(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock()
        spool = Spool(
            tmp_path / "spool", 64 * KIB, rotate_bytes=100, rotate_retry_seconds=5.0, clock=clock
        )
        attempts: list[int] = []

        def broken(_path: Path) -> BinaryIO:
            attempts.append(1)
            raise OSError("no inodes")

        spool.append(b"a" * 80)
        monkeypatch.setattr(spool_module, "_open_segment_append", broken)
        for _ in range(6):  # every append is above rotate_bytes
            spool.append(b"b" * 40)
        assert len(attempts) == 1
        clock.now += 4.9
        spool.append(b"b" * 40)
        assert len(attempts) == 1
        clock.now += 0.2
        spool.append(b"b" * 40)
        assert len(attempts) == 2

    def test_appends_are_refused_once_the_unrotatable_segment_exceeds_the_budget(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock()
        spool = Spool(tmp_path / "spool", 1 * KIB, rotate_bytes=100, clock=clock)
        real_open = spool_module._open_segment_append

        def broken(_path: Path) -> BinaryIO:
            raise OSError("no inodes")

        spool.append(b"first")
        monkeypatch.setattr(spool_module, "_open_segment_append", broken)
        accepted = 0
        with pytest.raises(OSError, match="over the size budget"):
            for _ in range(100):
                spool.append(b"x" * 99)
                accepted += 1
        assert 1 * KIB // 100 <= accepted <= 1 * KIB // 100 + 2  # stopped just past the budget
        assert spool.pending_lines == accepted + 1
        with pytest.raises(OSError, match="over the size budget"):
            spool.append(b"again")
        assert spool.pending_lines == accepted + 1

        monkeypatch.setattr(spool_module, "_open_segment_append", real_open)
        clock.now += 10
        spool.append(b"recovered")  # rotates, then the old segment is evicted loudly
        assert spool.read_batch()[0] == ["recovered"]


class TestLagCounters:
    def test_pending_counts_track_append_and_commit(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path)
        assert spool.pending_lines == 0
        assert spool.pending_bytes == 0
        for line in lines(4):
            spool.append(line.encode())
        assert spool.pending_lines == 4
        assert spool.pending_bytes > 0
        batch, cursor = spool.read_batch(max_lines=2)
        assert len(batch) == 2
        spool.commit(cursor)
        assert spool.pending_lines == 2

    def test_pending_counts_survive_restart(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path)
        for line in lines(6):
            spool.append(line.encode())
        _, cursor = spool.read_batch(max_lines=4)
        spool.commit(cursor)
        spool.close()

        reopened = make_spool(tmp_path)
        assert reopened.pending_lines == 2
        assert reopened.pending_bytes > 0

    def test_on_append_hook_fires(self, tmp_path: Path) -> None:
        spool = make_spool(tmp_path)
        calls: list[int] = []
        spool.on_append = lambda: calls.append(1)
        spool.append(b"x")
        spool.append(b"y")
        assert len(calls) == 2


class TestPermissions:
    @_posix_only
    def test_spool_dir_and_segments_are_owner_only(self, tmp_path: Path) -> None:
        # Session recordings are the most sensitive data at rest here, so the
        # spool dir is 0700 and segment files 0600 — matching the PKI keys,
        # not the umask default open("ab") would give.
        spool = make_spool(tmp_path)
        spool.append(b"x")
        spool.append(b"y")
        spool.flush()
        dir_mode = stat.S_IMODE((tmp_path / "spool").stat().st_mode)
        assert dir_mode == 0o700
        segments = list((tmp_path / "spool").glob("*.ndjson"))
        assert segments
        for seg in segments:
            assert stat.S_IMODE(seg.stat().st_mode) == 0o600
