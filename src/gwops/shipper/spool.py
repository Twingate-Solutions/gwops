"""`Spool`: a bounded, cursor-tracked NDJSON spool on disk.

Lines kept by gwops' stderr filter are appended to numbered segment files
(``0000001.ndjson``). A segment is sealed before a line that would push it past 4 MiB, so
a larger line sits alone in its own segment. The shipper reads batches from the last
committed position and commits a new cursor only after the sink acknowledged the batch, so
delivery is at-least-once: a crash between read and commit re-sends the same batch, and a
committed line is never read again.

Durability: appends are buffered with a periodic flush (and every ``read_batch`` flushes
first); a segment is fsync'd once, when it rotates; the cursor file is written atomically
(tmp + fsync + rename) on every commit. A torn tail left by a hard kill is quarantined at
open time: an active segment not ending in a newline is sealed and a fresh segment
started, and readers skip any trailing partial line.

The spool is size-bounded: when the total exceeds ``max_bytes``, whole oldest segments are
evicted and each eviction logs an error with the exact line and byte counts lost. The
segment holding the newest line is never evicted, so the spool may exceed the budget by
that one segment. Committed segments are deleted at commit time, so eviction only destroys
undelivered data.

A failed write drops everything past the last flush and reopens the segment, so a partial
line never merges with the next one; the failing append raises to its caller.
"""

import contextlib
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

import structlog

from gwops.shipper.limits import BATCH_MAX_BYTES

logger = structlog.get_logger(__name__)

_SEGMENT_SUFFIX = ".ndjson"
_CURSOR_NAME = "cursor.json"
_DEFAULT_ROTATE_BYTES = 4 * 2**20
_DEFAULT_FLUSH_EVERY = 64
_DEFAULT_ROTATE_RETRY_SECONDS = 5.0
# Recordings contain privileged SSH/kubectl I/O, so segments are owner-only rather than
# the umask default.
_DIR_MODE = 0o700
_SEGMENT_MODE = 0o600


def _open_segment_append(path: Path) -> BinaryIO:
    """Open (creating if needed) a spool segment for appending, owner-only on POSIX.

    ``os.open`` applies the mode only when it creates the file; existing segments keep
    their permissions.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, _SEGMENT_MODE)
    return os.fdopen(fd, "ab")


@dataclass(frozen=True)
class Cursor:
    """A read position: the next unread line lives at `offset` in segment `segment`.

    `lines_read` is how many lines the batch that produced this cursor consumed, read from
    (`start_segment`, `start_offset`); :meth:`Spool.commit` uses them to keep the
    pending-lines counter exact.
    """

    segment: int
    offset: int
    lines_read: int = 0
    start_segment: int = 0
    start_offset: int = 0


class Spool:
    """Bounded on-disk NDJSON spool with an fsync'd commit cursor.

    Single-writer, single-reader, one event loop: ``append`` is called from the
    supervisor's stderr callback and ``read_batch``/``commit`` from the shipper task.
    ``on_append``, if set, is invoked after every append (the shipper points it at
    its wake-up event). ``on_lost``, if set, is called with the number of earlier lines
    dropped from the write buffer when a write or flush fails (the failing line itself is
    reported by the exception its append raises).
    """

    on_append: Callable[[], None] | None
    on_lost: Callable[[int], None] | None

    def __init__(
        self,
        directory: Path,
        max_bytes: int,
        *,
        rotate_bytes: int = _DEFAULT_ROTATE_BYTES,
        flush_every: int = _DEFAULT_FLUSH_EVERY,
        rotate_retry_seconds: float = _DEFAULT_ROTATE_RETRY_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Open (or create) the spool under `directory`, bounded at `max_bytes` total.

        `rotate_bytes` caps one segment file; `flush_every` is the append-buffer
        flush interval in lines; a failed rotation is retried after `rotate_retry_seconds`
        (`clock` is injectable).
        """
        self._dir = directory
        self._max_bytes = max_bytes
        self._rotate_bytes = rotate_bytes
        self._flush_every = flush_every
        self.on_append = None
        self.on_lost = None
        self._unflushed = 0

        self._dir.mkdir(parents=True, exist_ok=True)
        # mkdir's mode is umask-masked, so set owner-only explicitly (best-effort).
        try:
            os.chmod(self._dir, _DIR_MODE)
        except OSError:
            logger.debug("spool.chmod_dir_unsupported", directory=os.fspath(self._dir))
        ids = sorted(
            int(p.stem) for p in self._dir.glob(f"*{_SEGMENT_SUFFIX}") if p.stem.isdigit()
        )
        # Sizes of *closed* segments; the active segment is tracked via _active_size.
        self._sizes: dict[int, int] = {
            sid: self._segment_path(sid).stat().st_size for sid in ids[:-1]
        }
        active_id = ids[-1] if ids else 1
        active_path = self._segment_path(active_id)
        if ids and _has_torn_tail(active_path):
            # Torn last line: seal this segment instead of appending onto the partial line.
            self._sizes[active_id] = active_path.stat().st_size
            active_id += 1
        self._active_id = active_id
        self._handle: BinaryIO = _open_segment_append(self._segment_path(active_id))
        self._active_size = self._segment_path(active_id).stat().st_size
        self._flushed_size = self._active_size
        self._rotate_failing = False
        self._rotate_retry_seconds = rotate_retry_seconds
        self._clock = clock
        self._rotate_retry_at = 0.0

        self._read_segment, self._read_offset = self._load_cursor()
        self._pending_lines = self._count_pending_lines()

    # --- write side ----------------------------------------------------------------

    def append(self, line: bytes) -> None:
        """Append one line (no newline) whole; raises `OSError` or `ValueError` on a write failure.

        A line that would push the active segment past `rotate_bytes` starts a new segment.
        While rotation keeps failing the segment keeps growing, and the append is refused with
        `OSError` once it exceeds the spool budget.
        """
        if self._handle.closed:
            self._reset_active()
        size = len(line) + 1
        if (
            self._active_size > 0
            and self._active_size + size > self._rotate_bytes
            and self._clock() >= self._rotate_retry_at
        ):
            self._rotate()
        if self._active_size > self._max_bytes:
            raise OSError("spool segment is over the size budget and cannot be rotated")
        try:
            self._handle.write(line)
            self._handle.write(b"\n")
        except (OSError, ValueError):
            self._discard_unflushed(current_counted=False)
            raise
        self._active_size += size
        self._pending_lines += 1
        self._unflushed += 1
        if self._unflushed >= self._flush_every:
            try:
                self._flush()
            except (OSError, ValueError):
                self._discard_unflushed(current_counted=True)
                raise
        try:
            self._evict_over_budget()
        except OSError as exc:  # the line is already spooled; eviction retries on the next append
            logger.error("spool.evict_failed", error_type=type(exc).__name__)
        if self.on_append is not None:
            self.on_append()

    def flush(self) -> None:
        """Push buffered appends to the OS (no fsync — that happens on rotate); never raises."""
        try:
            self._flush()
        except (OSError, ValueError):
            self._discard_unflushed(current_counted=False)

    def close(self) -> None:
        """Flush + fsync the active segment and release the handle (shutdown path)."""
        self.flush()
        if self._handle.closed:
            return
        os.fsync(self._handle.fileno())
        self._handle.close()

    # --- read side -----------------------------------------------------------------

    def read_batch(
        self, max_lines: int = 500, max_bytes: int = BATCH_MAX_BYTES
    ) -> tuple[list[str], Cursor]:
        """Read up to `max_lines` lines or `max_bytes` bytes from the last committed position.

        The byte count includes each line's newline. The first line is always returned,
        so a line at the cap ships alone; the cap never drops or splits a line.
        Does not advance the position: the same batch is returned again until
        :meth:`commit` is called with the returned cursor. Partial trailing lines (torn by
        a crash) are skipped.
        """
        self.flush()
        batch: list[str] = []
        total = 0
        full = False
        start_seg, start_off = cur_seg, cur_off = self._read_segment, self._read_offset
        for sid in self._existing_ids():
            if sid < self._read_segment:
                continue
            if full or len(batch) >= max_lines:
                break
            start = self._read_offset if sid == self._read_segment else 0
            with self._segment_path(sid).open("rb") as fh:
                fh.seek(start)
                while len(batch) < max_lines:
                    room = max_bytes - total
                    if batch and room <= 0:
                        full = True
                        break
                    # After the first line, read one byte past the room left to detect overflow.
                    want = room + 1 if batch else -1
                    if sid == self._active_id:  # never past the flushed size
                        left = max(0, self._flushed_size - fh.tell())
                        want = left if want < 0 else min(want, left)
                    raw = fh.readline(want)
                    if batch and len(raw) > room:
                        full = True
                        break
                    if not raw or not raw.endswith(b"\n"):
                        break  # segment exhausted (or torn tail — skip it)
                    batch.append(raw[:-1].decode("utf-8", errors="replace"))
                    total += len(raw)
                    cur_seg, cur_off = sid, fh.tell()
        return batch, Cursor(cur_seg, cur_off, len(batch), start_seg, start_off)

    def commit(self, cursor: Cursor) -> None:
        """Persist `cursor` atomically and drop segments it has fully consumed.

        Must be called with the cursor from the most recent :meth:`read_batch`.
        """
        # Eviction racing this commit may already have advanced the read position and
        # decremented pending_lines for lines this batch read. Debit only the lines still
        # pending between the read position and the cursor, to avoid subtracting twice.
        here = (self._read_segment, self._read_offset)
        if (cursor.segment, cursor.offset) > here:
            if here == (cursor.start_segment, cursor.start_offset):
                debit = cursor.lines_read
            else:
                debit = self._count_lines_between(here, (cursor.segment, cursor.offset))
            self._read_segment, self._read_offset = cursor.segment, cursor.offset
            self._pending_lines = max(0, self._pending_lines - debit)
        self._write_cursor_file(self._read_segment, self._read_offset)
        for sid in [s for s in self._sizes if s < self._read_segment]:
            self._segment_path(sid).unlink(missing_ok=True)
            del self._sizes[sid]

    # --- lag inputs ----------------------------------------------------------------

    @property
    def pending_lines(self) -> int:
        """Lines appended but not yet committed (exact, survives restart)."""
        return self._pending_lines

    @property
    def pending_bytes(self) -> int:
        """Bytes on disk (plus append buffer) beyond the committed cursor."""
        total = 0
        for sid in self._existing_ids():
            if sid < self._read_segment:
                continue
            size = self._active_size if sid == self._active_id else self._sizes[sid]
            total += size - self._read_offset if sid == self._read_segment else size
        return max(0, total)

    # --- internals -------------------------------------------------------------------

    def _segment_path(self, sid: int) -> Path:
        return self._dir / f"{sid:07d}{_SEGMENT_SUFFIX}"

    def _existing_ids(self) -> list[int]:
        return sorted([*self._sizes, self._active_id])

    def _flush(self) -> None:
        self._handle.flush()
        self._unflushed = 0
        self._flushed_size = self._active_size

    def _rotate(self) -> None:
        """Seal the active segment (flush + fsync) and start the next; on failure keep this one."""
        try:
            self._flush()
            os.fsync(self._handle.fileno())
            new_id = self._active_id + 1
            new_handle = _open_segment_append(self._segment_path(new_id))
        except (OSError, ValueError) as exc:
            if not self._rotate_failing:
                logger.error("spool.rotate_failed", error_type=type(exc).__name__)
            self._rotate_failing = True
            self._rotate_retry_at = self._clock() + self._rotate_retry_seconds
            return
        self._rotate_failing = False
        old = self._handle
        self._sizes[self._active_id] = self._active_size
        self._active_id = new_id
        self._handle = new_handle
        self._active_size = 0
        self._flushed_size = 0
        try:
            old.close()
        except OSError as exc:
            logger.warning("spool.close_sealed_failed", error_type=type(exc).__name__)

    def _discard_unflushed(self, *, current_counted: bool) -> None:
        """After a failed write or flush: drop everything past the last flush and reopen.

        The lines buffered before the failure are lost; they are logged with their count
        (the failing line is not included, its caller sees the error).
        """
        buffered = self._unflushed
        self._unflushed = 0
        self._pending_lines = max(0, self._pending_lines - buffered)
        earlier = buffered - 1 if current_counted else buffered
        if earlier > 0:
            logger.error(
                "spool.buffered_lines_lost",
                lines_lost=earlier,
                reason="write to the spool failed; lines buffered since the last flush dropped",
            )
            if self.on_lost is not None:
                self.on_lost(earlier)
        try:
            self._reset_active()
        except OSError as exc:
            logger.error("spool.reopen_failed", error_type=type(exc).__name__)

    def _reset_active(self) -> None:
        """Truncate the active segment to its last flushed size and reopen it for appending."""
        with contextlib.suppress(OSError, ValueError):  # buffered bytes are discarded anyway
            self._handle.close()
        path = self._segment_path(self._active_id)
        with path.open("r+b") as fh:
            fh.truncate(self._flushed_size)
        self._handle = _open_segment_append(path)
        self._active_size = self._flushed_size
        self._unflushed = 0

    def _evict_over_budget(self) -> None:
        """Drop whole oldest sealed segments until back under `max_bytes`, logging each."""
        while self._sizes and sum(self._sizes.values()) + self._active_size > self._max_bytes:
            oldest = min(self._sizes)
            path = self._segment_path(oldest)
            start = self._read_offset if oldest == self._read_segment else 0
            data = path.read_bytes()
            lines_lost = data.count(b"\n", start)
            bytes_lost = len(data) - start
            path.unlink()
            del self._sizes[oldest]
            self._pending_lines = max(0, self._pending_lines - lines_lost)
            if self._read_segment <= oldest:
                self._read_segment = min(self._sizes, default=self._active_id)
                self._read_offset = 0
            logger.error(
                "spool.evicted",
                segment=os.fspath(path),
                lines_lost=lines_lost,
                bytes_lost=bytes_lost,
                max_bytes=self._max_bytes,
                reason="spool over size budget; oldest undelivered recordings dropped",
            )

    def _load_cursor(self) -> tuple[int, int]:
        """The committed position, clamped onto segments that still exist."""
        existing = self._existing_ids()
        seg, off = existing[0], 0
        cursor_path = self._dir / _CURSOR_NAME
        try:
            raw = json.loads(cursor_path.read_text(encoding="utf-8"))
            seg, off = int(raw["segment"]), int(raw["offset"])
        except FileNotFoundError:
            return existing[0], 0
        except (OSError, ValueError, KeyError, TypeError):
            logger.warning("spool.cursor_unreadable", path=os.fspath(cursor_path))
            return existing[0], 0
        if seg not in existing:
            later = [s for s in existing if s > seg]
            return (later[0], 0) if later else (existing[-1], 0)
        size = self._active_size if seg == self._active_id else self._sizes[seg]
        return seg, min(off, size)

    def _write_cursor_file(self, segment: int, offset: int) -> None:
        """Atomic cursor write: tmp file + fsync + rename (+ best-effort dir fsync)."""
        cursor_path = self._dir / _CURSOR_NAME
        tmp_path = self._dir / (_CURSOR_NAME + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as fh:
            json.dump({"segment": segment, "offset": offset}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, cursor_path)
        try:
            dir_fd = os.open(self._dir, os.O_RDONLY)
        except OSError:
            return  # directory fds are unavailable on Windows; rename is still atomic
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _count_lines_between(self, start: tuple[int, int], end: tuple[int, int]) -> int:
        """Newlines from position `start` up to position `end` (segment, offset)."""
        count = 0
        for sid in self._existing_ids():
            if not start[0] <= sid <= end[0]:
                continue
            first = start[1] if sid == start[0] else 0
            with self._segment_path(sid).open("rb") as fh:
                data = fh.read() if sid != end[0] else fh.read(max(0, end[1]))
            count += data.count(b"\n", first)
        return count

    def _count_pending_lines(self) -> int:
        """Startup scan: newline count from the committed cursor to the end."""
        count = 0
        for sid in self._existing_ids():
            if sid < self._read_segment:
                continue
            start = self._read_offset if sid == self._read_segment else 0
            count += self._segment_path(sid).read_bytes().count(b"\n", start)
        return count


def _has_torn_tail(path: Path) -> bool:
    """True if `path` is non-empty and does not end with a newline."""
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            if fh.tell() == 0:
                return False
            fh.seek(-1, os.SEEK_END)
            return fh.read(1) != b"\n"
    except OSError:
        return False
