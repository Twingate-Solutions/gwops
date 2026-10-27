"""A file-handle wrapper that makes a Spool's writes or flushes fail on demand."""

from typing import Any, BinaryIO

from gwops.shipper.spool import Spool


class FlakyHandle:
    """Wraps the spool's file handle; an armed write puts half the data down, then raises."""

    def __init__(self, real: BinaryIO) -> None:
        self._real = real
        self.fail_write = False
        self.fail_flush = False

    def write(self, data: bytes) -> int:
        if self.fail_write:
            self._real.write(data[: len(data) // 2])
            raise OSError("disk full")
        return self._real.write(data)

    def flush(self) -> None:
        if self.fail_flush:
            raise OSError("disk full")
        self._real.flush()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


def make_flaky(spool: Spool) -> FlakyHandle:
    """Swap the spool's handle for a flaky wrapper and return it."""
    handle = FlakyHandle(spool._handle)
    spool._handle = handle  # type: ignore[assignment]
    return handle
