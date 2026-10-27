"""A fake Twingate Gateway binary for supervisor/reconciler tests.

Stands in for the real gateway child that :class:`gwops.supervisor.process.GatewayProcess`
spawns (and that :func:`gwops.supervisor.spawn.validate_config_by_spawn` pre-flights). It accepts
(and ignores) the real invocation shape — ``start --config <path>`` — and drives its own behavior
from environment variables so the supervisor/reconciler, which control the argv, do not need to
know about the fake at all.

Real-binary shape: there is no ``config validate`` subcommand. A good config never exits (the real
binary binds :8443 and runs until killed); a bad config makes ``start`` itself exit non-zero with
a ``failed to validate config`` stderr line, fast, before doing anything else.

- ``FAKE_GW_INTERVAL``        seconds between emitted line pairs (default 0.05)
- ``FAKE_GW_REJECT_CONFIG``   if "1", exit 1 immediately with a `failed to validate config`
  stderr line instead of starting — simulates a config the binary refuses to run
- ``FAKE_GW_EARLY_EXIT_AFTER`` if > 0, sleep this many seconds after boot then exit — simulates
  a live child that dies shortly after a start (drives the early-exit-rollback tests)
- ``FAKE_GW_EARLY_EXIT_CODE`` the exit code used by ``FAKE_GW_EARLY_EXIT_AFTER`` (default 1;
  set to 0 to simulate the "exited zero early" spawn-primitive outcome)
- ``FAKE_GW_CRASH_AFTER``     exit nonzero after emitting this many stdout lines (0 = never)
- ``FAKE_GW_IGNORE_SIGTERM``  if "1", ignore SIGTERM so the supervisor must escalate to KILL
- ``FAKE_GW_BIGLINE_BYTES``   pad each stdout line to at least this many bytes (0 = normal)
- ``FAKE_GW_STDERR_FILE``     replay this file's lines verbatim on stderr before the tick
  loop (recording lines land on stderr in the real gateway; shipper e2e tests use this)
- ``FAKE_GW_STDERR_TICKS``    if "0", the tick loop writes nothing to stderr (default "1": each
  tick writes :func:`stderr_cycle`, real-shaped lines of every kind the filter must tell apart)

- ``FAKE_GW_ENV_DUMP``        if set (a file path), write this process's complete environment there
  as a JSON object (atomically: temp file, then rename) and exit 0 immediately, before any other
  behaviour. The env-scrub tests read it to see exactly what the supervisor's child inherited.

Every ``FAKE_GW_*`` knob is baked into the launcher script by ``tests/supervisor/conftest.py``,
so it is set *inside* the already-spawned child and never crosses the supervisor's ``env=``
allowlist. The allowlist therefore needs no test-only widening, and the dump shows the real
``child_env()`` result plus the ``FAKE_GW_*`` names the launcher itself exports.

On every boot it increments ``FAKE_GW_BOOT_COUNTER`` (a file path) if set, so a test can count
how many times the supervisor (re)started it across a crash loop. Both streams are flushed
after every write so the supervisor's readers observe lines promptly.
"""

import json
import os
import signal
import sys
import time

_VERSION = "2.0.0"
_CAST = '{"version":2,"width":80,"height":24}\n[0.1,"o","hi"]\n'
_USER = {"id": "placeholder-user", "username": "placeholder-user", "groups": ["example-group"]}


def stderr_cycle(n: int) -> list[str]:
    """One tick's stderr lines in the gateway's shapes: 3 kept, 1 service line, 1 plain text."""
    conn = f"00000000-0000-4000-8000-{n:012d}"
    base = {"levelname": "info", "ts": "2026-10-08T18:28:41.757Z", "version": _VERSION}
    lines: list[str] = [
        json.dumps(
            {**base, "logger": "system", "caller": "proxy/proxy.go:169",
             "message": "Starting connect proxy", "port": 8443},
            separators=(",", ":"),
        ),
        json.dumps(
            {**base, "logger": "system", "caller": "frontend/conn.go:226",
             "message": "Authenticated connection", "user": _USER, "conn_id": conn,
             "resource_type": "WEB_APP", "resource_address": "echo-plain.run0001.rig.test"},
            separators=(",", ":"),
        ),
        json.dumps(
            {**base, "logger": "audit",
             "message": "API request completed", "method": "GET", "url": "/", "user": _USER,
             "conn_id": conn, "request": {"headers": {"Accept": ["*/*"]}},
             "response": {"headers": {}, "status_code": 200}},
            separators=(",", ":"),
        ),
        json.dumps(
            {**base, "logger": "session_recording", "caller": "sessionrecorder/recorder.go:262",
             "message": "session recording", "user": _USER, "conn_id": conn,
             "asciicast": _CAST, "asciicast_sequence_num": n},
            separators=(",", ":"),
        ),
        f"2026/10/08 18:28:42 http: proxy error: tls: failed to verify certificate (tick {n})",
    ]
    return lines


def _emit(stream: object, event: str, **fields: object) -> None:
    payload = {"event": event, **fields}
    line = json.dumps(payload)
    stream.write(line + "\n")  # type: ignore[attr-defined]
    stream.flush()  # type: ignore[attr-defined]


def _dump_environment(path: str) -> None:
    """Write `os.environ` to `path` as JSON, atomically, so a reader never sees a partial file."""
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(dict(os.environ), handle)
    os.replace(tmp, path)


def main() -> int:
    env_dump = os.environ.get("FAKE_GW_ENV_DUMP")
    if env_dump:
        _dump_environment(env_dump)
        return 0

    reject_config = os.environ.get("FAKE_GW_REJECT_CONFIG") == "1"
    if reject_config:
        # Real-binary shape: `start` itself refuses to run a bad config, fast, before
        # emitting anything else — no separate `config validate` subcommand exists.
        sys.stderr.write("failed to validate config: invalid seed field bogus\n")
        sys.stderr.flush()
        return 1

    interval = float(os.environ.get("FAKE_GW_INTERVAL", "0.05"))
    early_exit_after = float(os.environ.get("FAKE_GW_EARLY_EXIT_AFTER", "0"))
    early_exit_code = int(os.environ.get("FAKE_GW_EARLY_EXIT_CODE", "1"))
    crash_after = int(os.environ.get("FAKE_GW_CRASH_AFTER", "0"))
    ignore_sigterm = os.environ.get("FAKE_GW_IGNORE_SIGTERM") == "1"
    bigline_bytes = int(os.environ.get("FAKE_GW_BIGLINE_BYTES", "0"))
    boot_counter = os.environ.get("FAKE_GW_BOOT_COUNTER")
    stderr_ticks = os.environ.get("FAKE_GW_STDERR_TICKS", "1") != "0"

    if boot_counter:
        # Best-effort boot count so a crash-loop test can assert repeated restarts.
        try:
            prior = int(open(boot_counter).read())  # noqa: SIM115
        except (OSError, ValueError):
            prior = 0
        with open(boot_counter, "w") as handle:
            handle.write(str(prior + 1))

    if ignore_sigterm:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    else:
        # Graceful shutdown: the real gateway drains on SIGTERM (2.0.0 GA then exits 1 after
        # printing `Error: use of closed network connection` and cobra usage to stderr; this
        # fake exits 0). Without a handler the default disposition would exit -SIGTERM, which
        # is a crash, not a clean drain. (On Windows SIGTERM is registrable but never delivered by
        # TerminateProcess — harmless, and the drain tests are POSIX-only.)
        signal.signal(signal.SIGTERM, lambda _s, _f: sys.exit(0))

    _emit(sys.stdout, "gateway.started", pid=os.getpid())

    stderr_file = os.environ.get("FAKE_GW_STDERR_FILE")
    if stderr_file:
        # Byte-fidelity matters here: the shipper e2e test asserts these exact lines
        # arrive at the sink unmodified, so replay without any re-encoding tricks.
        with open(stderr_file, encoding="utf-8") as handle:
            for raw in handle:
                stripped = raw.rstrip("\n")
                if stripped:
                    sys.stderr.write(stripped + "\n")
        sys.stderr.flush()

    if early_exit_after:
        # Simulates a live child that dies shortly after a real start (as opposed to
        # FAKE_GW_REJECT_CONFIG's instant refusal): boots normally, then crashes.
        time.sleep(early_exit_after)
        _emit(sys.stderr, "gateway.crashing", after=early_exit_after)
        return early_exit_code

    count = 0
    while True:
        padding = "x" * bigline_bytes if bigline_bytes else ""
        _emit(sys.stdout, "gateway.tick", n=count, pad=padding)
        # Recording/audit and service lines land on stderr in the real gateway.
        if stderr_ticks:
            for text in stderr_cycle(count):
                sys.stderr.write(text + "\n")
            sys.stderr.flush()
        count += 1
        if crash_after and count >= crash_after:
            _emit(sys.stderr, "gateway.crashing", after=count)
            return 3
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
