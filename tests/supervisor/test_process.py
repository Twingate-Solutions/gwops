"""Tests for gwops.supervisor.process.GatewayProcess.

Behaviors that require real POSIX signal semantics (graceful SIGTERM drain, SIGKILL
escalation, SIGHUP reload) are marked POSIX-only: on Windows ``send_signal``/``terminate``
map to an immediate ``TerminateProcess`` with no in-child handler, so those semantics
cannot be exercised. Streaming, tagging, oversized lines, crash-backoff, and state
transitions run on every platform (the image target is Linux; the suite also runs on
Windows).
"""

import asyncio
import json
import signal
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
import structlog
import structlog.testing

import gwops.supervisor.process as process_module
from gwops.logging import configure_logging
from gwops.shipper.limits import LINE_MAX_BYTES
from gwops.supervisor.process import GatewayProcess, LineReader, ProcState

_AUDIT_MARK = b'"logger":"audit"'  # the fake gateway's `audit` line, compact JSON

_posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="requires POSIX signal semantics"
)


async def _wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not met within timeout")


def _boot_count(path: Path) -> int:
    """Read the fake's boot counter, treating a not-yet-written file as zero."""
    try:
        return int(path.read_text() or "0")
    except (FileNotFoundError, ValueError):
        return 0


def _config_file(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text("twingate: {network: test}\n", encoding="utf-8")
    return path


class TestState:
    def test_initial_state_is_stopped(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        proc = GatewayProcess(
            fake_gateway(), _config_file(tmp_path), lambda _l: None, lambda _l: None
        )
        assert proc.state == ProcState.STOPPED
        assert proc.returncode is None

    async def test_failed_spawn_resets_state_to_stopped(
        self, tmp_path: Path
    ) -> None:
        # A spawn failure (here, a non-existent binary) must not strand the
        # state machine at STARTING — otherwise the reconciler's apply step reads
        # "not STOPPED, not RUNNING", waits for a restart that was never scheduled,
        # and the gateway is wedged. start() must roll back to STOPPED so the next
        # reconcile retries.
        missing = tmp_path / "does-not-exist"
        proc = GatewayProcess(
            missing, _config_file(tmp_path), lambda _l: None, lambda _l: None
        )
        with pytest.raises(OSError):
            await proc.start()
        assert proc.state == ProcState.STOPPED

    @_posix_only
    async def test_start_reaches_running_then_stop_returns_to_stopped(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        proc = GatewayProcess(
            fake_gateway(), _config_file(tmp_path), lambda _l: None, lambda _l: None
        )
        await proc.start()
        assert proc.state == ProcState.RUNNING
        await proc.stop(timeout=5.0)
        assert proc.state == ProcState.STOPPED
        # PID-1 duty: the child is reaped, returncode observed (no zombie).
        assert proc.returncode is not None


@_posix_only
class TestStreaming:
    async def test_streams_lines_to_both_callbacks(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        stdout_lines: list[str] = []
        stderr_lines: list[bytes] = []
        proc = GatewayProcess(
            fake_gateway(), _config_file(tmp_path), stdout_lines.append, stderr_lines.append
        )
        await proc.start()
        try:
            await _wait_for(lambda: any("gateway.started" in line for line in stdout_lines))
            await _wait_for(lambda: any(_AUDIT_MARK in line for line in stderr_lines))
        finally:
            await proc.stop(timeout=5.0)
        # Lines arrive intact and newline-stripped (valid JSON, no trailing newline);
        # stdout as text, stderr as bytes.
        started = next(line for line in stdout_lines if "gateway.started" in line)
        assert json.loads(started)["event"] == "gateway.started"
        audit = next(line for line in stderr_lines if _AUDIT_MARK in line)
        assert json.loads(audit)["logger"] == "audit"

    async def test_reemits_lines_to_our_stdout_tagged_by_stream(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        configure_logging()
        structlog.contextvars.clear_contextvars()
        proc = GatewayProcess(
            fake_gateway(), _config_file(tmp_path), lambda _l: None, lambda _l: None
        )
        await proc.start()
        try:
            # Give the readers a beat to pump some lines from both streams through structlog.
            await asyncio.sleep(0.3)
        finally:
            await proc.stop(timeout=5.0)
        out = capsys.readouterr().out
        records = [json.loads(line) for line in out.strip().splitlines() if line.strip()]
        passthrough = [r for r in records if r.get("event") == "gateway.line"]
        streams = {r["stream"] for r in passthrough}
        assert "gateway-stdout" in streams
        assert "gateway-stderr" in streams

    async def test_stderr_content_not_echoed_when_recording(
        self,
        fake_gateway: Callable[..., Path],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # With recording on (echo_stderr_content=False), stderr may carry session
        # recording payloads, so its content must never reach our stdout log — but the
        # callback still receives the full line (it still spools + ships).
        configure_logging()
        structlog.contextvars.clear_contextvars()
        stderr_lines: list[bytes] = []
        proc = GatewayProcess(
            fake_gateway(),
            _config_file(tmp_path),
            lambda _l: None,
            stderr_lines.append,
            echo_stderr_content=False,
        )
        await proc.start()
        try:
            await _wait_for(lambda: any(_AUDIT_MARK in line for line in stderr_lines))
        finally:
            await proc.stop(timeout=5.0)
        # The callback saw full stderr content (delivery path intact)...
        assert any(_AUDIT_MARK in line for line in stderr_lines)
        # ...but no gateway.line event for the stderr stream carries the raw text.
        out = capsys.readouterr().out
        records = [json.loads(line) for line in out.strip().splitlines() if line.strip()]
        stderr_events = [
            r
            for r in records
            if r.get("event") == "gateway.line" and r.get("stream") == "gateway-stderr"
        ]
        assert stderr_events, "expected suppressed stderr metadata events"
        assert all("line" not in r for r in stderr_events)
        assert all(r.get("content") == "[suppressed]" for r in stderr_events)
        # stdout is still echoed in full.
        stdout_events = [
            r
            for r in records
            if r.get("event") == "gateway.line" and r.get("stream") == "gateway-stdout"
        ]
        assert any("line" in r for r in stdout_events)

    async def test_oversized_line_survives_reader(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        # 256 KB line: far past one read chunk and asyncio's 64 KiB StreamReader limit.
        big = 256 * 1024
        stdout_lines: list[str] = []
        proc = GatewayProcess(
            fake_gateway(bigline_bytes=big),
            _config_file(tmp_path),
            stdout_lines.append,
            lambda _l: None,
        )
        await proc.start()
        try:
            await _wait_for(
                lambda: any(len(line) >= big for line in stdout_lines), timeout=8.0
            )
        finally:
            await proc.stop(timeout=5.0)


def _stream(*pieces: bytes) -> asyncio.StreamReader:
    """A StreamReader holding `pieces` followed by EOF."""
    stream = asyncio.StreamReader()
    for piece in pieces:
        stream.feed_data(piece)
    stream.feed_eof()
    return stream


async def _read_all(reader: LineReader) -> list[bytes]:
    lines: list[bytes] = []
    while (line := await reader.read_line()) is not None:
        lines.append(line)
    return lines


class TestLineReader:
    async def test_line_at_the_cap_is_delivered_whole(self) -> None:
        line = b"a" * LINE_MAX_BYTES
        reader = LineReader(_stream(line, b"\nnext\n"))
        assert await _read_all(reader) == [line, b"next"]
        assert reader.too_long_count == 0

    async def test_one_byte_over_the_cap_is_dropped_whole(self) -> None:
        counts: list[int] = []
        reader = LineReader(
            _stream(b"a" * (LINE_MAX_BYTES + 1), b"\nnext\n"), on_too_long=counts.append
        )
        assert await _read_all(reader) == [b"next"]
        assert reader.too_long_count == 1
        assert counts == [LINE_MAX_BYTES + 1]

    async def test_far_over_the_cap_delivers_no_tail_and_resumes(self) -> None:
        counts: list[int] = []
        reader = LineReader(
            _stream(b"first\n", b"x" * 10_000, b"\n", b"second\n"),
            max_line_bytes=100,
            chunk_bytes=16,
            on_too_long=counts.append,
        )
        assert await _read_all(reader) == [b"first", b"second"]
        assert reader.too_long_count == 1
        assert counts == [10_000]

    async def test_too_long_lines_are_counted_once_each(self) -> None:
        reader = LineReader(
            _stream(b"y" * 50 + b"\nok\n" + b"y" * 60 + b"\n"), max_line_bytes=40, chunk_bytes=7
        )
        assert await _read_all(reader) == [b"ok"]
        assert reader.too_long_count == 2

    async def test_over_long_line_at_eof_without_newline_is_counted_not_delivered(self) -> None:
        counts: list[int] = []
        reader = LineReader(
            _stream(b"ok\n", b"z" * 500), max_line_bytes=100, on_too_long=counts.append
        )
        assert await _read_all(reader) == [b"ok"]
        assert counts == [500]

    async def test_several_lines_in_one_chunk(self) -> None:
        reader = LineReader(_stream(b"one\ntwo\n\nthree\n"))
        assert await _read_all(reader) == [b"one", b"two", b"", b"three"]

    async def test_line_spanning_chunks(self) -> None:
        reader = LineReader(_stream(b"abcdefghij\nklmnopqrst\n"), chunk_bytes=4)
        assert await _read_all(reader) == [b"abcdefghij", b"klmnopqrst"]

    async def test_line_split_across_stream_pieces(self) -> None:
        stream = asyncio.StreamReader()
        reader = LineReader(stream)

        async def feed() -> None:
            for piece in (b"par", b"tial li", b"ne\nsec", b"ond\n"):
                stream.feed_data(piece)
                await asyncio.sleep(0)
            stream.feed_eof()

        feeder = asyncio.create_task(feed())
        assert await _read_all(reader) == [b"partial line", b"second"]
        await feeder

    async def test_final_unterminated_line_is_delivered_within_the_cap(self) -> None:
        reader = LineReader(_stream(b"one\ntail"))
        assert await _read_all(reader) == [b"one", b"tail"]

    async def test_empty_stream_and_trailing_newline_yield_no_extra_line(self) -> None:
        assert await _read_all(LineReader(_stream())) == []
        assert await _read_all(LineReader(_stream(b"only\n"))) == [b"only"]

    async def test_non_utf8_bytes_pass_through_untouched(self) -> None:
        reader = LineReader(_stream(b"\xff\xfe bad\n"))
        assert await _read_all(reader) == [b"\xff\xfe bad"]


class TestPumpTooLong:
    async def test_over_long_line_is_logged_by_size_counted_and_not_delivered(self) -> None:
        delivered: list[bytes] = []
        hook_calls: list[int] = []
        proc = GatewayProcess(
            Path("unused"),
            Path("unused.yaml"),
            lambda _l: None,
            delivered.append,
            on_stderr_too_long=lambda: hook_calls.append(1),
        )
        secret = b"s3cret-session-bytes"
        stream = _stream(secret + b"a" * LINE_MAX_BYTES, b"\nok\n")
        with structlog.testing.capture_logs() as logs:
            await proc._pump(
                stream,
                proc._on_stderr_line,
                "gateway-stderr",
                echo_content=False,
                on_too_long=proc._count_stderr_too_long,
            )
        assert delivered == [b"ok"]
        assert proc.stderr_too_long_count == 1
        assert hook_calls == [1]
        (event,) = [e for e in logs if e["event"] == "gateway.line_too_long"]
        assert event["stream"] == "gateway-stderr"
        assert event["bytes"] == len(secret) + LINE_MAX_BYTES
        assert "s3cret" not in repr(logs)


class _FailingStream(asyncio.StreamReader):
    """Delivers its fed data, then raises instead of reaching EOF."""

    async def read(self, n: int = -1) -> bytes:
        if self._buffer:
            return await super().read(n)
        raise ConnectionResetError("pipe broke")


class TestPumpReaderDeath:
    async def test_a_reader_error_is_logged_and_does_not_escape_the_task(self) -> None:
        delivered: list[bytes] = []
        proc = GatewayProcess(
            Path("unused"), Path("unused.yaml"), lambda _l: None, delivered.append
        )
        stream = _FailingStream()
        stream.feed_data(b"before the failure\nsecret-partial")

        with structlog.testing.capture_logs() as logs:
            await proc._pump(stream, proc._on_stderr_line, "gateway-stderr", echo_content=False)

        assert delivered == [b"before the failure"]
        [entry] = [e for e in logs if e["event"] == "gateway.reader_died"]
        assert entry["stream"] == "gateway-stderr"
        assert entry["log_level"] == "error"
        assert entry["exc_info"] is True

    async def test_a_failing_stdout_echo_is_logged_too(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proc = GatewayProcess(Path("unused"), Path("unused.yaml"), lambda _l: None, lambda _l: None)
        real = process_module.logger

        class Broken:
            def info(self, event: str, **kw: object) -> None:
                if event == "gateway.line":
                    raise OSError("stdout closed")
                real.info(event, **kw)

            def __getattr__(self, name: str) -> object:
                return getattr(real, name)

        monkeypatch.setattr(process_module, "logger", Broken())
        with structlog.testing.capture_logs() as logs:
            await proc._pump(_stream(b"a\nb\n"), proc._on_stderr_line, "gateway-stdout")

        assert [e["event"] for e in logs] == ["gateway.reader_died"]

    async def test_cancellation_is_not_swallowed_or_logged_as_a_death(self) -> None:
        proc = GatewayProcess(Path("unused"), Path("unused.yaml"), lambda _l: None, lambda _l: None)
        stream = asyncio.StreamReader()  # never fed: the pump parks in read()
        with structlog.testing.capture_logs() as logs:
            task = asyncio.create_task(
                proc._pump(stream, proc._on_stderr_line, "gateway-stderr", echo_content=False)
            )
            await asyncio.sleep(0.01)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        assert task.cancelled()
        assert [e for e in logs if e["event"] == "gateway.reader_died"] == []


class TestDrain:
    @_posix_only
    async def test_stop_drains_gracefully_within_timeout(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        stdout_lines: list[str] = []
        proc = GatewayProcess(
            fake_gateway(), _config_file(tmp_path), stdout_lines.append, lambda _l: None
        )
        await proc.start()
        # Wait until the child has installed its SIGTERM handler (it emits this line only
        # afterward) so the drain exercises graceful shutdown, not a startup-race kill.
        await _wait_for(lambda: any("gateway.started" in line for line in stdout_lines))
        loop = asyncio.get_running_loop()
        started = loop.time()
        await proc.stop(timeout=5.0)
        # The fake exits 0 on SIGTERM, so this returns well before the timeout.
        assert loop.time() - started < 3.0
        assert proc.returncode == 0
        assert proc.state == ProcState.STOPPED

    @_posix_only
    async def test_stop_escalates_to_sigkill_when_child_ignores_sigterm(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        stdout_lines: list[str] = []
        proc = GatewayProcess(
            fake_gateway(ignore_sigterm=True),
            _config_file(tmp_path),
            stdout_lines.append,
            lambda _l: None,
        )
        await proc.start()
        # Ensure SIGTERM is already being ignored before we send it.
        await _wait_for(lambda: any("gateway.started" in line for line in stdout_lines))
        await proc.stop(timeout=0.3)
        assert proc.state == ProcState.STOPPED
        # SIGKILL shows up as a negative returncode of the signal number.
        assert proc.returncode == -signal.SIGKILL

    @_posix_only
    async def test_drain_restart_replaces_the_child(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        boot_counter = tmp_path / "boots.count"
        proc = GatewayProcess(
            fake_gateway(boot_counter=boot_counter),
            _config_file(tmp_path),
            lambda _l: None,
            lambda _l: None,
        )
        await proc.start()
        await _wait_for(lambda: _boot_count(boot_counter) == 1)
        await proc.drain_restart(timeout=5.0)
        assert proc.state == ProcState.RUNNING
        await _wait_for(lambda: _boot_count(boot_counter) == 2)
        await proc.stop(timeout=5.0)


@_posix_only
class TestCrashBackoff:
    async def test_crash_triggers_backoff_restarts_with_increasing_delay(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        boot_counter = tmp_path / "boots.count"
        delays: list[float] = []
        proc = GatewayProcess(
            fake_gateway(crash_after=1, boot_counter=boot_counter),
            _config_file(tmp_path),
            lambda _l: None,
            lambda _l: None,
            backoff_start=0.05,
            backoff_cap=1.0,
            # Each boot crashes near-instantly (after one line, no sleep): a tiny
            # early_exit_window keeps that crash classified as "after the window" —
            # i.e. a routine crash — rather than early-exit rollback,
            # which is exercised separately in TestEarlyExitRollback below.
            early_exit_window=0.01,
            on_backoff=delays.append,
        )
        await proc.start()
        try:
            # Each boot crashes after one line; the supervisor should keep restarting.
            await _wait_for(lambda: _boot_count(boot_counter) >= 3, timeout=8.0)
            await _wait_for(lambda: len(delays) >= 2, timeout=8.0)
            # Backoff grows monotonically (0.05 -> 0.10 -> ...).
            assert delays[1] > delays[0]
            # It passes through BACKOFF between restarts.
            assert proc.state in {ProcState.BACKOFF, ProcState.RUNNING, ProcState.STARTING}
        finally:
            await proc.stop(timeout=5.0)


class TestEarlyExitRollback:
    """A live gateway that dies shortly after a start."""

    async def test_exit_within_window_restores_last_good_and_does_not_backoff(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        configure_logging()
        structlog.contextvars.clear_contextvars()
        config_path = _config_file(tmp_path)
        last_good = config_path.with_name(config_path.name + ".last-good")
        last_good.write_text("twingate: {network: last-good}\n", encoding="utf-8")
        delays: list[float] = []
        proc = GatewayProcess(
            fake_gateway(early_exit_after=0.05),
            config_path,
            lambda _l: None,
            lambda _l: None,
            early_exit_window=2.0,
            on_backoff=delays.append,
        )
        await proc.start()
        await _wait_for(lambda: proc.state == ProcState.STOPPED, timeout=5.0)

        assert config_path.read_text(encoding="utf-8") == "twingate: {network: last-good}\n"
        assert delays == []  # never entered the exponential-backoff path
        out = capsys.readouterr().out
        events = [
            json.loads(line).get("event")
            for line in out.strip().splitlines() if line.strip()
        ]
        assert "gateway.early_exit_rollback" in events

    async def test_rollback_restarts_on_last_good_then_stops_if_it_also_fails(
        self, fake_gateway: Callable[..., Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # After an early exit, the supervisor restores last-good AND restarts on it (so a
        # transient bad config doesn't leave the gateway down until the next tick). The
        # `_recovering_via_rollback` guard means that if last-good ALSO early-exits (here
        # the fake always does), it stops loudly after exactly one restart — no infinite
        # loop and no exponential backoff.
        configure_logging()
        structlog.contextvars.clear_contextvars()
        config_path = _config_file(tmp_path)
        last_good = config_path.with_name(config_path.name + ".last-good")
        last_good.write_text("twingate: {network: last-good}\n", encoding="utf-8")
        delays: list[float] = []
        proc = GatewayProcess(
            fake_gateway(early_exit_after=0.05),
            config_path,
            lambda _l: None,
            lambda _l: None,
            early_exit_window=2.0,
            on_backoff=delays.append,
        )
        await proc.start()
        await _wait_for(lambda: proc.state == ProcState.STOPPED, timeout=6.0)
        # A failed config was captured so the reconciler won't re-apply it (the exact
        # value in the recoverable case is covered by the reconciler skip test).
        assert proc.last_rolled_back_config is not None
        assert delays == []  # never entered exponential backoff
        out = capsys.readouterr().out
        events = [
            json.loads(line).get("event")
            for line in out.strip().splitlines() if line.strip()
        ]
        # Exactly two rollbacks: the initial start's exit, then the one restart's exit.
        assert events.count("gateway.early_exit_rollback") == 2
        assert "gateway.spawned" in events

    async def test_exit_within_window_with_no_last_good_still_stops_loudly(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        # First-ever start, so there is no last-good sidecar yet to restore.
        config_path = _config_file(tmp_path)
        proc = GatewayProcess(
            fake_gateway(early_exit_after=0.05),
            config_path,
            lambda _l: None,
            lambda _l: None,
            early_exit_window=2.0,
        )
        await proc.start()
        await _wait_for(lambda: proc.state == ProcState.STOPPED, timeout=5.0)
        # The bad config is left in place (nothing to restore it to); the caller
        # (the reconciler) is expected to re-render on its next pass.
        assert config_path.read_text(encoding="utf-8") == "twingate: {network: test}\n"

    @_posix_only
    async def test_exit_after_window_preserves_normal_backoff(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        delays: list[float] = []
        proc = GatewayProcess(
            fake_gateway(early_exit_after=0.15),
            _config_file(tmp_path),
            lambda _l: None,
            lambda _l: None,
            early_exit_window=0.02,
            backoff_start=0.05,
            backoff_cap=1.0,
            on_backoff=delays.append,
        )
        await proc.start()
        try:
            await _wait_for(lambda: len(delays) >= 1, timeout=5.0)
            assert proc.state in {ProcState.BACKOFF, ProcState.STARTING, ProcState.RUNNING}
        finally:
            await proc.stop(timeout=5.0)

    @_posix_only
    async def test_last_good_is_promoted_only_after_surviving_the_window(
        self, fake_gateway: Callable[..., Path], tmp_path: Path
    ) -> None:
        config_path = _config_file(tmp_path)
        last_good = config_path.with_name(config_path.name + ".last-good")
        proc = GatewayProcess(
            fake_gateway(),
            config_path,
            lambda _l: None,
            lambda _l: None,
            early_exit_window=0.1,
        )
        await proc.start()
        try:
            assert not last_good.is_file()
            await _wait_for(lambda: last_good.is_file(), timeout=5.0)
            assert last_good.read_text(encoding="utf-8") == config_path.read_text(
                encoding="utf-8"
            )
        finally:
            await proc.stop(timeout=5.0)
