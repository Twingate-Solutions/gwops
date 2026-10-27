"""Gatorcast evidence for the live rig (--gatorcast): ingest tap log, Gatorcast store, /status."""

import asyncio
import json
import secrets
import shlex
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import seedgen
from .checks import RigContext, _expect
from .results import CheckFailed, CheckFinding

MIB = 1024 * 1024
SSH_MIN_TOTAL = 2 * MIB  # the payload prints about 3.3 MiB; the recording lines sum above this
SSH_MIN_SEGMENTS = 2  # `session recording` lines before the final line: the cap segmented it
# gwops renders a 256,000-byte cap on the summed event text. A shipped line is that plus JSON
# escaping (about 5% on the rig's CRLF-wrapped base64 output) and whatever events land between
# the size trigger and the flush (SSH data events are at most tens of KiB), so about 270 KB.
# 1 MiB is four times the cap: slack for flush lag, yet far below the 3.3 MiB one line a
# gateway that ignored the cap would ship.
SSH_MAX_SEGMENT = 1 * MIB
SSH_OUTPUT_BYTES = 2_400_000
SSH_CLIENT_IMAGE = "gwops-rig-ssh-client:local"
MARKER_PREFIX = "RIG-SSH-DONE-"
SSH_SESSION_TIMEOUT = 240.0
SSH_ATTEMPTS = 4
SSH_RETRY_SECONDS = 5.0
SSH_READY_TIMEOUT = 420.0
SSH_READY_POLL = 5.0
_BANNER_PROBE = (
    "import socket,sys;"
    "s=socket.create_connection((sys.argv[1],22),timeout=15);"
    "sys.exit(0 if s.recv(4)==b'SSH-' else 1)"
)
DRAIN_TIMEOUT = 90.0
STORE_TIMEOUT = 90.0
ALIAS_TIMEOUT = 60.0
GATORCAST_ASSERTIONS: list[tuple[str, str]] = [
    ("12", "web-app Authenticated connection reached Gatorcast with an exact gwops object"),
    ("13", "no non-allowlisted or non-JSON line reached Gatorcast"),
    ("14", "/status shipper counters: lines dropped, no enrichment or spool failure"),
    ("15", "alias connection: what the gateway logged and what gwops matched (recorded only)"),
]
SSH_ASSERTION = (
    "16",
    "SSH recording arrived at Gatorcast as capped segment lines plus a final line, in sequence",
)

_STORE_SCRIPT = """
import json, os, sqlite3, sys
c = sqlite3.connect('file:/data/gatorcast.db?mode=ro', uri=True)
c.row_factory = sqlite3.Row
cols = [r['name'] for r in c.execute('PRAGMA table_info(connections)')]
out = {'connection_columns': cols}
if sys.argv[1] == 'connections':
    if 'gwops_match' in cols:
        q = ('SELECT conn_id, resource_address, resource_type, gwops_match, gwops_gateway_id, '
             'gwops_app, gwops_managed, downstream_tls, downstream_port, upstream_tls, '
             'upstream_port FROM connections WHERE resource_type = ?')
        out['rows'] = [dict(r) for r in c.execute(q, (sys.argv[2],))]
else:
    q = ('SELECT conn_id, status, size_bytes, chunk_count, cast_path, resource_address, '
         'resource_type FROM sessions WHERE conn_id = ?')
    row = c.execute(q, (sys.argv[2],)).fetchone()
    out['row'] = dict(row) if row else None
    p = (out['row'] or {}).get('cast_path') or ''
    for cand in (p, os.path.join('/data', p), os.path.join('/data/casts', os.path.basename(p))):
        if p and os.path.isfile(cand):
            data = open(cand, 'rb').read()
            out['cast_bytes'] = len(data)
            out['marker_in_cast'] = sys.argv[3].encode() in data
            break
print(json.dumps(out))
"""


def read_tap(path: Path) -> list[dict[str, Any]]:
    """Every record of the tap log; a torn last line is ignored."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def shipped_lines(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The `line` records, in arrival order."""
    return [r for r in records if r.get("rec") == "line"]


def web_starts(lines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Shipped `Authenticated connection` lines (logger `system`) for WEB_APP resources."""
    return [
        r
        for r in lines
        if r.get("logger") == "system"
        and r.get("message") == "Authenticated connection"
        and r.get("resource_type") == "WEB_APP"
    ]


def host_of(address: object) -> str:
    """The host part of a resource address (the port, if any, is dropped)."""
    return str(address or "").partition(":")[0]


def gwops_problems(line: dict[str, Any], expected: seedgen.ExpectedWebApp) -> list[str]:
    """Differences between a shipped line's gwops object and the rig's configured app."""
    gwops = line.get("gwops")
    if not isinstance(gwops, dict):
        return ["no gwops object"]
    want: dict[str, Any] = {
        "schema": 1,
        "match": "exact",
        "app": expected.name,
        "managed": True,
        "downstream_tls": expected.downstream_tls,
        "downstream_port": expected.downstream_port,
        "upstream_tls": expected.upstream_tls,
        "upstream_port": expected.upstream_port,
    }
    return [f"{k}={gwops.get(k)!r} (want {v!r})" for k, v in want.items() if gwops.get(k) != v]


def check_web_gwops(
    lines: list[dict[str, Any]],
    expected: dict[str, seedgen.ExpectedWebApp],
    must_see: tuple[str, ...],
) -> tuple[str, list[dict[str, Any]]]:
    """Verify every rig-app start line; returns (detail, verified lines). Raises CheckFailed.

    A `none` object is counted, not failed: a connection can precede the first tenant listing.
    """
    problems: list[str] = []
    verified: list[dict[str, Any]] = []
    none_hosts: list[str] = []
    for line in web_starts(lines):
        host = host_of(line.get("resource_address"))
        app = expected.get(host)
        if app is None:
            continue
        gwops = line.get("gwops")
        if isinstance(gwops, dict) and gwops.get("match") == "none":
            none_hosts.append(host)
            continue
        found = gwops_problems(line, app)
        if found:
            problems.append(f"{line.get('resource_address')}: {'; '.join(found)}")
        else:
            verified.append(line)
    seen = {host_of(line.get("resource_address")) for line in verified}
    missing = [h for h in must_see if h not in seen]
    if problems or missing:
        parts = problems[:6]
        if missing:
            parts.append(f"no exact start line for {', '.join(missing)} ({len(none_hosts)} none)")
        raise CheckFailed("; ".join(parts))
    detail = f"{len(verified)} start lines exact across {len(seen)} apps"
    return f"{detail}; {len(none_hosts)} with match none", verified


def check_allowlist(lines: list[dict[str, Any]]) -> str:
    """Fail if any shipped line is outside the allowlist; returns the detail otherwise."""
    _expect(bool(lines), "the ingest tap saw no shipped line at all")
    bad = [r for r in lines if not r.get("allowed")]
    if bad:
        kinds: dict[str, int] = {}
        for r in bad:
            key = f"{r.get('kind')}:{r.get('excerpt', '')[:60]}"
            kinds[key] = kinds.get(key, 0) + 1
        shown = "; ".join(f"{n}x {k}" for k, n in list(kinds.items())[:6])
        raise CheckFailed(f"{len(bad)} of {len(lines)} shipped lines are not allowlisted: {shown}")
    proxy = [r for r in lines if "proxy error" in str(r.get("message") or "")]
    _expect(not proxy, f"{len(proxy)} shipped lines mention a proxy error")
    return (
        f"{len(lines)} shipped lines, all allowlisted; none is a service or http: proxy error line"
    )


def check_counters(shipper: dict[str, Any]) -> tuple[str, dict[str, str]]:
    """Judge /status `shipper`; returns (detail, metrics). Raises CheckFailed."""
    dropped = shipper.get("dropped_lines") or {}
    enrichment = shipper.get("enrichment") or {}
    metrics = {
        "shipper.dropped_lines": json.dumps(dropped, sort_keys=True),
        "shipper.enrich_failed": str(shipper.get("enrich_failed")),
        "shipper.enrichment": json.dumps(enrichment, sort_keys=True),
        "shipper.pending_lines": str(shipper.get("pending_lines")),
    }
    _expect(shipper.get("mode") == "spool", f"shipper mode is {shipper.get('mode')!r}")
    _expect(
        shipper.get("shipping") is True,
        "shipper is not shipping (GWOPS_RECORDING_TOKEN missing?)",
    )
    _expect(not shipper.get("enrich_failed"), f"enrich_failed={shipper.get('enrich_failed')}")
    for reason in ("spool_failed", "too_long"):
        _expect(not dropped.get(reason), f"dropped_lines.{reason}={dropped.get(reason)}")
    _expect(enrichment.get("active") is True, f"enrichment not active: {enrichment}")
    service = int(dropped.get("not_allowlisted") or 0) + int(dropped.get("not_json") or 0)
    _expect(service > 0, "no service line was dropped: the filter never saw one")
    return (
        f"dropped {metrics['shipper.dropped_lines']}; enrichment {metrics['shipper.enrichment']}",
        metrics,
    )


def ssh_script(host: str, marker: str) -> str:
    """Shell for the ssh client container: an interactive PTY shell (the gateway records only
    `shell` requests) fed a payload on stdin that prints about 3 MiB, then the marker.

    The marker is built by printf so the tty echo of the typed line never contains it whole.
    """
    token = marker.removeprefix(MARKER_PREFIX)
    remote = (
        f"head -c {SSH_OUTPUT_BYTES} /dev/urandom | base64 -w 76; "
        f'printf "RIG-SSH-%s-%s\\n" DONE {token}; exit'
    )
    opts = (
        "-tt -F /dev/null -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=20"
    )
    return (
        f"{{ printf '%s\\n' '{remote}'; sleep 2; }} | "
        f"ssh {opts} {seedgen.SSH_GATEWAY_USER}@{host} > /tmp/out 2>&1; rc=$?; "
        "tail -c 300 /tmp/out; exit $rc"
    )


def ssh_retryable(returncode: int, text: str) -> bool:
    """Whether an ssh exit is a pre-session connection reset (gateway skew), safe to retry."""
    if returncode != 255:
        return False
    if "kex_exchange_identification" in text:
        return True
    return "Connection reset" in text and "client_loop" not in text


async def wait_ssh_ready(ctx: RigContext, timeout: float = SSH_READY_TIMEOUT) -> float | None:
    """Poll an SSH banner read through the gateway; seconds taken, None on timeout."""
    started = time.monotonic()
    script = f"python -c {shlex.quote(_BANNER_PROBE)} {shlex.quote(ctx.names.ssh_host)}"
    while True:
        result = await ctx.docker.run_in_client_netns(SSH_CLIENT_IMAGE, script, timeout=60)
        elapsed = time.monotonic() - started
        if result.returncode == 0:
            ctx.book.metrics["ready_ssh_s"] = f"{elapsed:.0f}"
            ctx.log.event("host-ready", host="ssh", seconds=f"{elapsed:.0f}")
            return elapsed
        if elapsed >= timeout:
            ctx.book.metrics["ready_ssh_s"] = f"not ready in {timeout:.0f}s"
            ctx.log.event("host-not-ready", host="ssh", exit=result.returncode)
            return None
        await asyncio.sleep(SSH_READY_POLL)


def _is_recording(record: dict[str, Any]) -> bool:
    return record.get("asciicast_len") is not None


def _has_marker(record: dict[str, Any], marker: str) -> bool:
    return marker in (record.get("markers") or [])


def check_ssh_recording(lines: list[dict[str, Any]], marker: str) -> dict[str, Any]:
    """Judge the shipped recording of the SSH session that printed `marker`.

    The gateway segments an SSH recording like a Kubernetes one: `session recording` lines of
    about the rendered 256,000-byte cap (or every five minutes), then one `session finished`
    line, each carrying `asciicast_sequence_num` (1, 2, ...; the final line has the highest).
    A redelivered line (at-least-once) has the same sequence number and the same sha256 and
    counts once; the same number with a different sha256 fails (a second shell channel on the
    connection numbers its own flushes from 1). Returns the session's summary; raises
    CheckFailed naming the first problem.
    """
    recordings = [r for r in lines if _is_recording(r)]
    _expect(bool(recordings), "no recording line reached the tap after the SSH session")
    holders = [r for r in recordings if _has_marker(r, marker)]
    _expect(
        bool(holders), f"the session-end marker is in none of {len(recordings)} recording lines"
    )
    conn_id = str(holders[0].get("conn_id") or "")
    _expect(bool(conn_id), "the recording line holding the marker has no conn_id")
    session = [r for r in recordings if str(r.get("conn_id") or "") == conn_id]
    for record in session:
        number = record.get("asciicast_sequence_num")
        _expect(bool(record.get("allowed")), f"recording line {number} is not allowlisted")
        status = int(record.get("status") or 0)
        _expect(status in range(200, 300), f"Gatorcast answered {record.get('status')} to {number}")
    unique: dict[int, dict[str, Any]] = {}
    for record in session:
        number = record.get("asciicast_sequence_num")
        if not isinstance(number, int):
            raise CheckFailed("a recording line has no integer sequence number")
        first = unique.setdefault(number, record)
        _expect(
            first.get("sha256") == record.get("sha256"),
            f"sequence {number} arrived twice with different content: a redelivery is "
            "byte-identical, so this is a second recorder on the connection (another shell "
            "channel)",
        )
    numbers = sorted(unique)
    _expect(
        numbers == list(range(1, len(numbers) + 1)),
        f"recording sequence numbers {numbers[:20]} are not 1..{len(numbers)} without a gap",
    )
    _expect(
        unique[numbers[-1]].get("message") == "session finished",
        f"no final `session finished` line at the highest sequence number {numbers[-1]}",
    )
    _expect(
        all(unique[n].get("message") == "session recording" for n in numbers[:-1]),
        "a line before the final one is not a `session recording` segment",
    )
    segments = len(numbers) - 1
    _expect(
        segments >= SSH_MIN_SEGMENTS,
        f"only {segments} segment lines before the final one; the recording was not segmented",
    )
    largest = max(int(r.get("bytes") or 0) for r in unique.values())
    _expect(
        largest < SSH_MAX_SEGMENT,
        f"a recording line is {largest} bytes: the segment cap did not apply to SSH",
    )
    total = sum(int(r.get("bytes") or 0) for r in unique.values())
    _expect(total > SSH_MIN_TOTAL, f"the recording lines total {total} bytes, under 2 MiB")
    return {
        "conn_id": conn_id,
        "segments": segments,
        "lines": len(numbers),
        "largest": largest,
        "total_bytes": total,
        "asciicast_chars": sum(int(r.get("asciicast_len") or 0) for r in unique.values()),
    }


class GatorcastEvidence:
    """The --gatorcast assertions; each returns a one-line detail or raises CheckFailed."""

    def __init__(
        self, ctx: RigContext, tap_path: Path, *, ssh_ready: Callable[[], str | None]
    ) -> None:
        """Bind the run context, the tap log and a probe: why SSH is unavailable, or None."""
        self.c = ctx
        self.n = ctx.names
        self._tap = tap_path
        self._ssh_ready = ssh_ready
        self.expected = seedgen.expected_webapps(ctx.names)

    def _lines(self) -> list[dict[str, Any]]:
        return shipped_lines(read_tap(self._tap))

    async def drain(self) -> None:
        """Wait until the spool is empty (or the timeout), then let the tap flush."""
        deadline = time.monotonic() + DRAIN_TIMEOUT
        while time.monotonic() < deadline:
            shipper = (await self.c.admin.status()).get("shipper") or {}
            if shipper.get("pending_lines") == 0:
                break
            await asyncio.sleep(3)
        await asyncio.sleep(2)

    async def _store(self, *args: str) -> dict[str, Any]:
        container = self.c.docker.container(seedgen.GATORCAST_SERVICE)
        out = await self.c.docker.exec_python(container, _STORE_SCRIPT, *args)
        document = json.loads(out)
        _expect(isinstance(document, dict), "Gatorcast store read returned no object")
        return document  # type: ignore[no-any-return]

    async def recording_web_gwops(self) -> str:
        """Assertion 12: rig web-app start lines carry the right gwops object."""
        must = (self.n.plain_host, self.n.tls_host)
        detail, verified = check_web_gwops(self._lines(), self.expected, must)
        for line in verified:
            self.c.log.event(
                "evidence-gwops",
                address=line.get("resource_address"),
                conn=line.get("conn_id"),
                gwops=json.dumps(line.get("gwops"), sort_keys=True),
            )
        wanted = {str(line["conn_id"]): line for line in verified if line.get("conn_id")}
        deadline = time.monotonic() + STORE_TIMEOUT
        while True:
            store = await self._store("connections", "WEB_APP")
            _expect(
                "gwops_match" in store["connection_columns"],
                "the Gatorcast image has no gwops columns (older than web-app support)",
            )
            rows = {r["conn_id"]: r for r in store.get("rows", [])}
            if wanted.keys() <= rows.keys() or time.monotonic() >= deadline:
                break
            await asyncio.sleep(5)
        missing = sorted(wanted.keys() - rows.keys())
        _expect(
            not missing,
            f"Gatorcast has no connection row for {len(missing)} of {len(wanted)} start lines",
        )
        problems = [
            f"{r['resource_address']}: {p}"
            for cid, line in wanted.items()
            for r in [rows[cid]]
            for p in _row_problems(r, self.expected[host_of(line["resource_address"])])
        ]
        _expect(not problems, "; ".join(problems[:6]))
        return f"{detail}; {len(wanted)} matching Gatorcast connection rows"

    async def recording_no_service_lines(self) -> str:
        """Assertion 13: every line the tap saw is allowlisted."""
        detail = check_allowlist(self._lines())
        posts = [r for r in read_tap(self._tap) if r.get("rec") == "post"]
        failed = [r for r in posts if not 200 <= int(r.get("status") or 0) < 300]
        return f"{detail}; {len(posts)} POSTs, {len(failed)} not accepted by Gatorcast"

    async def recording_counters(self) -> str:
        """Assertion 14: /status shipper counters."""
        shipper = (await self.c.admin.status()).get("shipper") or {}
        detail, metrics = check_counters(shipper)
        self.c.book.metrics.update(metrics)
        return detail

    async def recording_alias_host(self) -> str:
        """Assertion 15: connect by alias and record the logged address and the gwops match."""
        alias = self.n.alias_host
        before = len(self._lines())
        try:
            result = await self.c.http.get(f"https://{alias}/", cacert=True)
            status = result.line()
        except Exception as exc:
            return f"alias request failed ({type(exc).__name__}); nothing recorded"
        await self.drain()
        deadline = time.monotonic() + ALIAS_TIMEOUT
        new: list[dict[str, Any]] = []
        while not new and time.monotonic() < deadline:
            new = web_starts(self._lines()[before:])
            if not new:
                await asyncio.sleep(3)
        if not new:
            return f"curl {status}; no start line reached the tap in {ALIAS_TIMEOUT:.0f}s"
        seen = []
        for line in new:
            address = str(line.get("resource_address"))
            raw = line.get("gwops")
            gwops: dict[str, Any] = raw if isinstance(raw, dict) else {}
            kind = (
                "alias"
                if host_of(address) == alias
                else "address"
                if host_of(address) in self.expected
                else "other"
            )
            seen.append(
                f"resource_address={address} ({kind}) gwops.match={gwops.get('match', 'absent')}"
            )
            self.c.log.event("evidence-alias", curl=status, line=seen[-1])
        return f"curl {status}; " + "; ".join(sorted(set(seen)))

    async def recording_ssh(self) -> str:
        """Assertion 16: one SSH session ships as capped segment lines plus a final line."""
        unavailable = self._ssh_ready()
        if unavailable:
            raise CheckFinding(f"SSH infrastructure unavailable: {unavailable}")
        host = self.n.ssh_host
        marker = f"{MARKER_PREFIX}{secrets.token_hex(6)}"
        before = len(self._lines())
        for attempt in range(1, SSH_ATTEMPTS + 1):
            result = await self.c.docker.run_in_client_netns(
                SSH_CLIENT_IMAGE, ssh_script(host, marker), timeout=SSH_SESSION_TIMEOUT
            )
            text = result.stdout + result.stderr
            if attempt == SSH_ATTEMPTS or not ssh_retryable(result.returncode, text):
                break
            self.c.log.event("ssh-retry", attempt=attempt, exit=result.returncode)
            await asyncio.sleep(SSH_RETRY_SECONDS)
        self.c.book.metrics["ssh_attempts"] = str(attempt)
        _expect(
            result.returncode == 0 and marker in result.stdout,
            f"ssh session did not complete after {attempt} attempt(s) "
            f"(exit {result.returncode}): {text.strip()[-300:]}",
        )
        deadline = time.monotonic() + DRAIN_TIMEOUT
        while True:
            await self.drain()
            fresh = self._lines()[before:]
            finished = any(
                _is_recording(r) and r.get("message") == "session finished" for r in fresh
            )
            if finished or time.monotonic() >= deadline:
                break
        summary = check_ssh_recording(fresh, marker)
        conn_id = str(summary["conn_id"])
        starts = [
            r
            for r in fresh
            if r.get("message") == "Authenticated connection" and r.get("conn_id") == conn_id
        ]
        kind = starts[0].get("resource_type") if starts else "not seen"
        row, store = await self._wait_session(conn_id, marker)
        size, sent = int(row.get("size_bytes") or 0), int(summary["asciicast_chars"])
        _expect(row.get("status") == "complete", f"Gatorcast session status {row.get('status')!r}")
        _expect(size >= 0.9 * sent, f"Gatorcast stored {size} bytes of {sent} recorded chars")
        if "marker_in_cast" in store:
            _expect(
                store["marker_in_cast"] is True, "the marker is missing from the stored cast file"
            )
        return (
            f"{summary['segments']} segment lines + 1 final, {summary['total_bytes']} bytes in "
            f"all (largest {summary['largest']}, asciicast {sent} chars), all POSTs 2xx, "
            f"start line resource_type {kind}; Gatorcast session complete "
            f"({row.get('chunk_count')} chunks), {size} bytes stored, "
            f"cast file {'checked' if 'marker_in_cast' in store else 'not readable'}"
        )

    async def _wait_session(
        self, conn_id: str, marker: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        deadline = time.monotonic() + STORE_TIMEOUT
        while True:
            store = await self._store("session", conn_id, marker)
            row = store.get("row")
            if isinstance(row, dict) and row.get("status") == "complete":
                return row, store
            if time.monotonic() >= deadline:
                raise CheckFailed(
                    f"Gatorcast has no complete session for conn_id {conn_id} (row: {row})"
                )
            await asyncio.sleep(5)


def _row_problems(row: dict[str, Any], expected: seedgen.ExpectedWebApp) -> list[str]:
    """Differences between a Gatorcast `connections` row and the configured app."""
    want: dict[str, Any] = {
        "gwops_match": "exact",
        "gwops_app": expected.name,
        "gwops_managed": 1,
        "downstream_tls": expected.downstream_tls,
        "downstream_port": expected.downstream_port,
        "upstream_tls": expected.upstream_tls,
        "upstream_port": expected.upstream_port,
    }
    return [f"{k}={row.get(k)!r} (want {v!r})" for k, v in want.items() if row.get(k) != v]
