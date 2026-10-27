"""`GatewayProcess`: spawn the gateway child, own its pipes, and manage its lifecycle.

The supervisor spawns one child, ``<binary> start --config <path>``, with stdout and stderr
piped. Two reader tasks stream each line to a caller callback and re-emit it to gwops'
stdout tagged with its origin stream, so ``docker logs`` stays complete. :class:`LineReader`
frames lines from fixed-size chunks: a line up to `LINE_MAX_BYTES` is delivered whole, a
longer one is discarded whole; only stderr ones are counted.

Lifecycle: ``STOPPED -> STARTING -> RUNNING``; a clean ``stop()``/``drain_restart()``
goes through ``DRAINING``. An unexpected exit while ``RUNNING`` is one of two things:

- **Early-exit rollback**: an exit within `early_exit_window` seconds of the start is a
  failed start. It is the backstop for a bad config that passed the reconciler's pre-flight
  (`gwops.supervisor.spawn`). The on-disk config is restored from the last-good sidecar
  (promoted once the previous start survived the same window) and an error is logged. State
  returns to `STOPPED`, not `BACKOFF`, so the next reconcile retries with the restored config.
- **Routine crash-backoff**: an exit after `early_exit_window` goes to `BACKOFF` and
  schedules a restart with exponential backoff (``backoff_start`` doubling to
  ``backoff_cap``), resetting to ``backoff_start`` once the child has stayed up for
  ``running_reset_after`` seconds.

Graceful shutdown is SIGTERM (via ``Process.terminate``) with a SIGKILL
(``Process.kill``) escalation after the timeout.
"""

import asyncio
import os
import time
from collections import deque
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path

import structlog

from gwops.shipper.limits import LINE_MAX_BYTES
from gwops.supervisor.childenv import child_env
from gwops.supervisor.spawn import _VALIDATE_TIMEOUT_SECONDS

logger = structlog.get_logger(__name__)

_CHUNK_BYTES = 64 * 1024

_DEFAULT_BACKOFF_START = 1.0
_DEFAULT_BACKOFF_CAP = 60.0
_DEFAULT_RUNNING_RESET_AFTER = 300.0

# How long a just-started child must survive before it is trusted; shared with the
# pre-flight spawn in `gwops.supervisor.spawn`.
_DEFAULT_EARLY_EXIT_WINDOW = _VALIDATE_TIMEOUT_SECONDS

_LAST_GOOD_SUFFIX = ".last-good"


def last_good_path(config_path: Path) -> Path:
    """The last-good sidecar of `config_path`; files it references must survive GC."""
    return config_path.with_name(config_path.name + _LAST_GOOD_SUFFIX)


class LineReader:
    """Frames newline-terminated lines from fixed-size reads of a stream.

    Memory is bounded to one in-flight line (at most `max_line_bytes`) plus one chunk.
    """

    def __init__(
        self,
        stream: asyncio.StreamReader,
        *,
        max_line_bytes: int = LINE_MAX_BYTES,
        chunk_bytes: int = _CHUNK_BYTES,
        on_too_long: Callable[[int], None] | None = None,
    ) -> None:
        """Read `stream`; `on_too_long(byte_count)` fires once per discarded line."""
        self._stream = stream
        self._max = max_line_bytes
        self._chunk_bytes = chunk_bytes
        self._on_too_long = on_too_long
        self._buf = bytearray()
        self._ready: deque[bytes] = deque()
        self._discarding = False
        self._discarded = 0
        self._eof = False
        self.too_long_count = 0

    async def read_line(self) -> bytes | None:
        """The next line without its newline, or None at EOF.

        A final unterminated line is returned if within the cap. A line over the cap is
        discarded through its newline (or EOF) and never delivered, whole or in part.
        """
        while not self._ready:
            if self._eof:
                return None
            chunk = await self._stream.read(self._chunk_bytes)
            if chunk:
                self._feed(chunk)
            else:
                self._eof = True
                self._finish()
        return self._ready.popleft()

    def _feed(self, chunk: bytes) -> None:
        """Split `chunk` on newlines, extending or completing the in-flight line."""
        pos = 0
        end = len(chunk)
        while pos < end:
            nl = chunk.find(b"\n", pos)
            stop = end if nl < 0 else nl
            self._extend(chunk[pos:stop])
            if nl < 0:
                return
            self._complete()
            pos = nl + 1

    def _extend(self, piece: bytes) -> None:
        if self._discarding:
            self._discarded += len(piece)
        elif len(self._buf) + len(piece) > self._max:
            self._discarding = True
            self._discarded = len(self._buf) + len(piece)
            self._buf = bytearray()
        else:
            self._buf += piece

    def _complete(self) -> None:
        """A newline ended the in-flight line: queue it, or count it as too long."""
        if self._discarding:
            self._report_too_long()
        else:
            self._ready.append(bytes(self._buf))
            self._buf.clear()

    def _finish(self) -> None:
        """EOF: queue a final unterminated line, or count an unfinished over-long one."""
        if self._discarding:
            self._report_too_long()
        elif self._buf:
            self._ready.append(bytes(self._buf))
            self._buf.clear()

    def _report_too_long(self) -> None:
        count = self._discarded
        self._discarding = False
        self._discarded = 0
        self.too_long_count += 1
        if self._on_too_long is not None:
            self._on_too_long(count)


def _text(raw: bytes) -> str:
    """Lossy text for stdout callbacks and log echo."""
    return raw.decode("utf-8", errors="replace").rstrip("\r")


class ProcState(StrEnum):
    """The gateway child's lifecycle state, as tracked by :class:`GatewayProcess`."""

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    DRAINING = "draining"
    BACKOFF = "backoff"


class GatewayProcess:
    """Owns one gateway child process: spawn, stream pipes, drain, restart."""

    def __init__(
        self,
        binary: Path,
        config_path: Path,
        on_stdout_line: Callable[[str], None],
        on_stderr_line: Callable[[bytes], None],
        *,
        echo_stderr_content: bool = True,
        on_stderr_too_long: Callable[[], None] | None = None,
        backoff_start: float = _DEFAULT_BACKOFF_START,
        backoff_cap: float = _DEFAULT_BACKOFF_CAP,
        running_reset_after: float = _DEFAULT_RUNNING_RESET_AFTER,
        early_exit_window: float = _DEFAULT_EARLY_EXIT_WINDOW,
        on_backoff: Callable[[float], None] | None = None,
    ) -> None:
        """Bind to a gateway `binary` and `config_path`; nothing is spawned until `start()`.

        `on_stdout_line` receives each child stdout line as text; `on_stderr_line` receives
        each stderr line as raw bytes. Neither includes the newline, and a line over
        `LINE_MAX_BYTES` is never delivered: it is logged (`gateway.line_too_long`) and, for
        stderr only, counted in `stderr_too_long_count` and passed to `on_stderr_too_long`.
        `echo_stderr_content` controls whether the raw text of each child stderr line is
        mirrored to gwops' stdout log. It must be False whenever recording is enabled: the
        gateway emits session-recording payloads (asciicast JSON containing recorded
        terminal content) on the same stderr stream as operational logs, so any stderr line
        may carry session content that must not reach the container's stdout log. The line
        still reaches `on_stderr_line`; only the echo of its content is suppressed and a
        metadata-only event is logged instead.
        The `backoff_*` and `running_reset_after` arguments tune crash-restart timing.
        `early_exit_window` is the early-exit-rollback threshold (see module docstring).
        `on_backoff`, if given, is called with each computed backoff delay.
        """
        self._binary = binary
        self._config_path = config_path
        self._on_stdout_line = on_stdout_line
        self._on_stderr_line = on_stderr_line
        self._echo_stderr_content = echo_stderr_content
        self._on_stderr_too_long = on_stderr_too_long
        self._stderr_too_long_count = 0
        self._backoff_start = backoff_start
        self._backoff_cap = backoff_cap
        self._running_reset_after = running_reset_after
        self._early_exit_window = early_exit_window
        self._last_good_path = last_good_path(config_path)
        self._on_backoff = on_backoff

        self._state = ProcState.STOPPED
        self._proc: asyncio.subprocess.Process | None = None
        self._reader_tasks: list[asyncio.Task[None]] = []
        self._watch_task: asyncio.Task[None] | None = None
        self._restart_task: asyncio.Task[None] | None = None
        self._promote_task: asyncio.Task[None] | None = None
        self._backoff_delay = backoff_start
        self._running_since: float | None = None
        self._lock = asyncio.Lock()
        # Config text most recently rolled back; the reconciler refuses to re-apply it.
        # `_recovering_via_rollback` stops the post-rollback restart from looping if the
        # restored last-good config also exits early.
        self._rolled_back_config: str | None = None
        self._recovering_via_rollback = False

    @property
    def state(self) -> ProcState:
        """The current lifecycle state."""
        return self._state

    @property
    def last_rolled_back_config(self) -> str | None:
        """The config text most recently rolled back after a failed start, or None.

        The reconciler refuses to re-apply a rendered config equal to this one.
        """
        return self._rolled_back_config

    @property
    def stderr_too_long_count(self) -> int:
        """Stderr lines over `LINE_MAX_BYTES` discarded since this object was created."""
        return self._stderr_too_long_count

    @property
    def returncode(self) -> int | None:
        """The last child's exit code, or None if it has not exited (or never started).

        A negative value is ``-signum`` for a child killed by a signal (POSIX).
        """
        return self._proc.returncode if self._proc is not None else None

    async def start(self) -> None:
        """Spawn the gateway child and begin streaming its pipes; state becomes RUNNING.

        Raises `RuntimeError` if a child is already running.
        """
        if self._proc is not None and self._proc.returncode is None:
            raise RuntimeError("gateway process is already running")

        self._state = ProcState.STARTING
        argv = [
            str(self._binary),
            "start",
            "--config",
            str(self._config_path),
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=child_env(),
            )
        except BaseException:
            # Spawn failed or was cancelled: reset so state is not stuck at STARTING and
            # the reconciler's next pass retries start().
            self._state = ProcState.STOPPED
            raise
        self._proc = proc
        assert proc.stdout is not None and proc.stderr is not None
        self._reader_tasks = [
            asyncio.create_task(
                self._pump(
                    proc.stdout, self._deliver_stdout, "gateway-stdout", echo_content=True
                )
            ),
            asyncio.create_task(
                self._pump(
                    proc.stderr,
                    self._on_stderr_line,
                    "gateway-stderr",
                    echo_content=self._echo_stderr_content,
                    on_too_long=self._count_stderr_too_long,
                )
            ),
        ]
        self._running_since = time.monotonic()
        self._state = ProcState.RUNNING
        self._watch_task = asyncio.create_task(self._watch(proc))
        self._promote_task = asyncio.create_task(
            self._promote_last_good_after(self._early_exit_window)
        )
        logger.info("gateway.spawned", pid=proc.pid, argv=argv)

    async def drain_restart(self, timeout: float = 30.0) -> None:
        """Gracefully drain the current child, then start a fresh one; ends RUNNING."""
        await self._drain(timeout)
        await self.start()

    async def stop(self, timeout: float = 30.0) -> None:
        """Gracefully drain the current child and do not restart; ends STOPPED."""
        await self._drain(timeout)
        self._state = ProcState.STOPPED
        logger.info("gateway.stopped", returncode=self.returncode)

    # --- internals ---------------------------------------------------------------------

    async def _drain(self, timeout: float) -> None:
        """Mark DRAINING (so the crash watch treats the exit as intentional), cancel pending
        restarts, then SIGTERM the child and SIGKILL it after `timeout`."""
        async with self._lock:
            self._state = ProcState.DRAINING
            if self._restart_task is not None and not self._restart_task.done():
                self._restart_task.cancel()
            if self._promote_task is not None and not self._promote_task.done():
                self._promote_task.cancel()
        await self._terminate_and_wait(timeout)
        if self._watch_task is not None:
            await asyncio.gather(self._watch_task, return_exceptions=True)
        if self._restart_task is not None:
            await asyncio.gather(self._restart_task, return_exceptions=True)
        if self._promote_task is not None:
            await asyncio.gather(self._promote_task, return_exceptions=True)

    async def _terminate_and_wait(self, timeout: float) -> None:
        proc = self._proc
        if proc is None or proc.returncode is not None:
            await self._join_readers()
            return
        proc.terminate()  # SIGTERM on POSIX; TerminateProcess on Windows
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except TimeoutError:
            logger.warning("gateway.drain_timeout", timeout=timeout)
            proc.kill()  # SIGKILL on POSIX
            await proc.wait()
        await self._join_readers()

    async def _join_readers(self) -> None:
        if self._reader_tasks:
            await asyncio.gather(*self._reader_tasks, return_exceptions=True)
            self._reader_tasks = []

    async def _watch(self, proc: asyncio.subprocess.Process) -> None:
        """Await the child's exit; if it was unexpected, roll back or back off.

        An exit within `early_exit_window` of the start is a failed start: the config is
        restored from the last-good sidecar and the state returns to `STOPPED`. An exit
        after the window is a routine crash: back off and schedule a restart.
        """
        returncode = await proc.wait()
        async with self._lock:
            if self._state is not ProcState.RUNNING:
                # Intentional termination — stop()/drain_restart() drives the transition.
                return
            if self._promote_task is not None and not self._promote_task.done():
                self._promote_task.cancel()
            ran_for = time.monotonic() - (self._running_since or time.monotonic())
            if ran_for < self._early_exit_window:
                # Failed start: remember the failed config, roll back to last-good and,
                # unless this was already a rollback attempt, restart on it.
                already_recovering = self._recovering_via_rollback
                try:
                    self._rolled_back_config = self._config_path.read_text(encoding="utf-8")
                except OSError:
                    self._rolled_back_config = None
                try:
                    restored = self._restore_last_good()
                except OSError:
                    restored = False
                logger.error(
                    "gateway.early_exit_rollback",
                    returncode=returncode,
                    ran_for=round(ran_for, 3),
                    early_exit_window=self._early_exit_window,
                    restored_last_good=restored,
                    reason=(
                        "gateway exited within the early-exit window; treating this as "
                        "a failed start rather than a routine crash. "
                        + (
                            "restored the last-good config"
                            if restored
                            else "no last-good config to restore — the newly applied "
                            "config is the likely cause"
                        )
                    ),
                )
                if restored and not already_recovering:
                    # If last-good also dies in the window, the next _watch takes the
                    # STOPPED branch below instead of looping.
                    self._recovering_via_rollback = True
                    self._state = ProcState.STARTING
                    self._restart_task = asyncio.create_task(self._rollback_restart())
                    return
                # No last-good to restore, or last-good itself exited early: stay stopped.
                self._recovering_via_rollback = False
                self._state = ProcState.STOPPED
                return
            if ran_for >= self._running_reset_after:
                self._backoff_delay = self._backoff_start
            delay = self._backoff_delay
            self._backoff_delay = min(self._backoff_delay * 2, self._backoff_cap)
            self._state = ProcState.BACKOFF
            logger.warning(
                "gateway.crashed", returncode=returncode, backoff_seconds=delay
            )
            if self._on_backoff is not None:
                self._on_backoff(delay)
            self._restart_task = asyncio.create_task(self._backoff_restart(delay))

    async def _promote_last_good_after(self, delay: float) -> None:
        """Copy the on-disk config to the last-good sidecar once it has survived `delay` seconds."""
        try:
            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            return
        async with self._lock:
            if self._state is not ProcState.RUNNING:
                return
            # Stable again: a future early exit may attempt its own rollback-restart.
            self._recovering_via_rollback = False
        try:
            data = self._config_path.read_bytes()
            tmp = self._last_good_path.with_name(self._last_good_path.name + ".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, self._last_good_path)
        except OSError:
            logger.warning(
                "gateway.last_good_promote_failed", path=str(self._last_good_path)
            )

    def _restore_last_good(self) -> bool:
        """Restore `config_path` from the last-good sidecar; True if one existed."""
        if not self._last_good_path.is_file():
            return False
        data = self._last_good_path.read_bytes()
        tmp = self._config_path.with_name(self._config_path.name + ".rollback-tmp")
        tmp.write_bytes(data)
        os.replace(tmp, self._config_path)
        return True

    async def _backoff_restart(self, delay: float) -> None:
        try:
            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            return
        async with self._lock:
            if self._state is not ProcState.BACKOFF:
                return  # a stop()/drain came in while we were sleeping
        await self.start()

    async def _rollback_restart(self) -> None:
        """Restart on the restored last-good config after an early-exit rollback.

        Does nothing if a stop()/drain moved the state off STARTING in the meantime.
        """
        async with self._lock:
            if self._state is not ProcState.STARTING:
                return
        await self.start()

    def _deliver_stdout(self, raw: bytes) -> None:
        self._on_stdout_line(_text(raw))

    def _count_stderr_too_long(self) -> None:
        self._stderr_too_long_count += 1
        if self._on_stderr_too_long is not None:
            self._on_stderr_too_long()

    async def _pump(
        self,
        stream: asyncio.StreamReader,
        on_line: Callable[[bytes], None],
        tag: str,
        *,
        echo_content: bool = True,
        on_too_long: Callable[[], None] | None = None,
    ) -> None:
        """Stream `stream` line by line to `on_line` and re-emit each tagged to our stdout.

        When `echo_content` is False the line's text is not copied into our stdout log (a
        metadata-only event is emitted instead); `on_line` still receives the full line. See
        :meth:`__init__`'s `echo_stderr_content`. A line over `LINE_MAX_BYTES` is logged by
        size only, passed to `on_too_long` and not delivered.
        """

        def too_long(byte_count: int) -> None:
            logger.warning("gateway.line_too_long", stream=tag, bytes=byte_count)
            if on_too_long is not None:
                try:
                    on_too_long()
                except Exception:
                    logger.exception("gateway.line_callback_error", stream=tag)

        reader = LineReader(stream, on_too_long=too_long)
        try:
            while (raw := await reader.read_line()) is not None:
                try:
                    on_line(raw)
                except Exception:
                    logger.exception("gateway.line_callback_error", stream=tag)
                if echo_content:
                    logger.info("gateway.line", stream=tag, line=_text(raw))
                else:
                    # Recording mode: the line may be a session-recording payload, so log
                    # only the stream and byte length.
                    logger.info(
                        "gateway.line", stream=tag, bytes=len(raw), content="[suppressed]"
                    )
        except Exception:
            logger.exception("gateway.reader_died", stream=tag)
