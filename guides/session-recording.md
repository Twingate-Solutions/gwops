# Session recording

Deliver the gateway's session recordings and HTTP audit lines to a recording receiver you
run: a SIEM pipeline, a log collector with an HTTP input, a custom service, or a ready-made
recording browser. gwops spools the lines on disk and POSTs them in batches until the receiver
acknowledges them.

> **Security:** shipped lines are not redacted. They carry terminal output, full URLs with
> query strings, request and response header values (`Authorization`, `Cookie`, `X-Api-Key`,
> `Set-Cookie`), and user ids and groups. Treat the spool on `/data` and everything the receiver
> stores as holding those credentials. Use `https://` for the receiver.

## When to use

You want SSH and `kubectl exec` session recordings, and the gateway's HTTP audit lines, in your
SIEM, log platform or a recording browser.

### What ships and what does not

The gateway binary writes three kinds of JSON lines, interleaved, to its stderr: operational
(`system` logger), audit (`audit`) and recording (`session_recording`). With recording on, gwops
keeps three shapes and drops everything else:

| Ships | Logger | How it is recognised |
| --- | --- | --- |
| Session recordings | `session_recording` | An `asciicast` field holding a string |
| HTTP audit lines (web apps and Kubernetes API calls) | `audit` | Message `API request completed` or `API request failed`, no `asciicast` |
| Connection starts | `system` | Message `Authenticated connection` |

Not shipped, and counted as `not_allowlisted` in `/status` `shipper.dropped_lines`:

- SSH audit events such as `SSH connection established` and `SSH connection closed`.
- Every other `system` line: the gateway's operational log, including reverse-proxy errors.

Lines that are not JSON objects are dropped as `not_json`; lines over 16 MiB are dropped whole
as `too_long`.

Kept lines ship byte for byte as the gateway wrote them. The one addition: a web app's
`Authenticated connection` line gains a `gwops` object naming the app and its TLS modes and
ports.

> **Note:** whether recording is on or off, gwops relays the gateway's operational (`system`)
> lines to `docker logs` as `gateway.system` events, including each `Authenticated connection`
> line with the user's id, username and groups. Audit lines (HTTP and SSH) and session
> recordings never appear in `docker logs`: gwops logs only their metadata (`gateway.line` with a
> byte count and `content: "[suppressed]"`). The recording pipeline is the only way gateway audit
> and recording data leaves the container. See
> [Log events: gateway output](../reference/log-events.md).

What the gateway records at all: interactive SSH sessions and interactive `kubectl exec` or
`attach` TTY sessions. Web-app traffic is never session-recorded; it appears only as HTTP audit
lines. Non-interactive `kubectl` calls (`get`, `logs`, `apply`) appear only as HTTP audit lines.

## Prerequisites

- A receiver that implements the [recording wire format](../reference/recording-wire-format.md).
  In short:
  - It accepts `POST <base URL>/ingest`.
  - It checks `Authorization: Bearer <token>`.
  - It reads a body of newline-delimited JSON (`application/x-ndjson`), one JSON object per
    line, every line ending in `\n`, up to 500 lines and 16 MiB per request. A single line
    larger than the remaining room ships alone, and one line can be up to 16 MiB.
  - It answers any `2xx` only after it has stored the whole batch. Any other answer, a
    connection error or a 30 s timeout makes gwops resend the same batch, with backoff from
    1 s doubling to 30 s, forever. There is no partial acknowledgement.
  - It removes duplicates. Delivery is at least once: a batch can arrive twice after a crash or
    a lost response.
- A token for the receiver, which gwops sends as the bearer. Generate one with
  `openssl rand -hex 32`.
- Egress from the container to the receiver. The shipper honours `HTTPS_PROXY`, `HTTP_PROXY`
  and `NO_PROXY` from the container environment.
- A receiver certificate gwops trusts. gwops verifies it against the public root bundle that
  ships with its HTTP client. For a receiver behind a private CA, set `SSL_CERT_FILE` to a
  mounted bundle that holds the public roots as well as your CA, and test delivery before
  relying on it. The variable replaces the trust store for every gwops HTTPS call, including
  the Twingate API, and is also passed to the gateway binary, so a bundle without the public
  roots breaks those connections.
- Room on the `/data` volume for the spool (default 256 MiB).

## Steps

### 1. Build or choose a receiver

Pick one of the patterns below, or anything else that meets the contract.

> **Note:** Untested example. The receiver sketch and the Caddy configuration below have not been run by this project. Adapt them to your environment and test them before you rely on them.

### Example: a minimal receiver

This sketch uses only the Python standard library. It checks the bearer, appends each new line
to a file, drops duplicates and answers `204`. It is a sketch, not production code: it serves
plain HTTP, keeps its duplicate set in memory, and has no rotation.

```python
"""Minimal recording receiver. A sketch, not production code."""
import hashlib
import hmac
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = os.environ["RECEIVER_TOKEN"]
OUT = open("recordings.ndjson", "ab")
SEEN: set[bytes] = set()  # in memory only; use a durable store in production


class Ingest(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/ingest":
            return self.reply(404)
        if not hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {TOKEN}"):
            return self.reply(401)
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        for line in body.splitlines():
            key = hashlib.sha256(line).digest()  # a resent line is byte-identical
            if line and key not in SEEN:
                SEEN.add(key)
                OUT.write(line + b"\n")
        OUT.flush()
        os.fsync(OUT.fileno())  # store before acknowledging
        self.reply(204)

    def reply(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()


HTTPServer(("0.0.0.0", 8000), Ingest).serve_forever()
```

A resent line is byte-identical to the first copy, so a hash of the line is a safe duplicate
key. Receivers that index fields can dedupe on them instead: recording lines carry `conn_id`
and `asciicast_sequence_num` (plus `ssh.channel.id` for SSH, `request_id` for Kubernetes), and
HTTP audit lines carry `conn_id` and `request_id`. The wire format reference lists the fields.

Put a TLS-terminating proxy in front of it before you ship real recordings.

### Example: forwarding into a log pipeline

A log collector or SIEM ingest service can receive the lines directly if its HTTP input meets
every requirement:

- It serves `POST` at a path ending in `/ingest`. gwops appends `/ingest` to the base URL you
  configure, and the base URL may carry a path prefix: `https://logs.example.com/gw` becomes
  `https://logs.example.com/gw/ingest`.
- It accepts `Authorization: Bearer <token>`. Inputs that expect another scheme, or a fixed
  path, cannot receive directly.
- It splits the body on newlines into events and accepts bodies up to 16 MiB.
- It answers `2xx` only after the batch is durably queued, and never `2xx` for a batch it
  dropped.

When the input cannot do this, put a small adapter in front: a reverse proxy that checks the
bearer and rewrites the path, or a service like the sketch above that forwards to the
collector. A Caddy front end, for example:

```text
receiver.example.com {
    @ingest {
        method POST
        path /ingest
        header Authorization "Bearer {$RECEIVER_TOKEN}"
    }
    handle @ingest {
        rewrite * /<collector-input-path>
        reverse_proxy <collector-host>:<collector-port>
    }
    handle {
        respond 401
    }
}
```

Confirm that the collector acknowledges only what it has queued: a collector that answers `200`
and then drops events loses recordings with no trace on the gateway side. No specific log
product has been tested against the shipper.

### Example: Gatorcast

Gatorcast is a separate recording-ingest and playback service that implements this contract.
To use it, set `recording.receiver_url` to its base URL and `GWOPS_RECORDING_TOKEN` to its
ingest token.

### 2. Turn recording on in the seed

```yaml
recording:
  enabled: true
  receiver_url: https://receiver.example.com   # base URL; gwops POSTs to <url>/ingest
  spool_max_bytes: 268435456                     # 256 MiB, the default; at least 16 MiB
# ...rest of your seed
```

`recording.receiver_url` accepts the base URL of any receiver, `http://` or `https://`. A trailing `/` is removed before `/ingest` is appended. A
`http://` URL logs `shipper.insecure_transport` at startup: the token and the recordings then
cross the network in cleartext.

`recording.enabled: true` without `receiver_url` is refused when the seed loads.

### 3. Set the token

Add the token to `.env`:

```sh
GWOPS_RECORDING_TOKEN=<receiver-token>
```

Then uncomment the matching line in `compose.yaml`, under `environment:`:

```yaml
      GWOPS_RECORDING_TOKEN: ${GWOPS_RECORDING_TOKEN:-}
```

Uncomment it only once `.env` holds the value. Without the variable, gwops spools lines and ships
nothing (`supervisor.shipper_token_missing`). A variable that is present but empty is sent as an
empty bearer, which a receiver should reject.

### 4. Restart

Recording settings and the token are read once, at startup. A seed or overlay change to
`recording.*` takes effect only after a restart.

After changing `.env` or `compose.yaml`, recreate the container so it gets the new environment:

```sh
docker compose up -d
```

After a seed-only change, a restart is enough:

```sh
docker compose restart gateway
```

### 5. Size the spool

The spool at `/data/spool` holds every kept line until the receiver acknowledges it. It is
bounded by `recording.spool_max_bytes` (default 256 MiB, minimum 16 MiB, the longest line it
accepts). When the receiver is down long enough to fill it, gwops deletes the oldest undelivered
segment and logs `spool.evicted` with the exact lines and bytes lost. Those recordings are gone.
The segment holding the newest line is never evicted, so the spool can exceed the bound by up to
one segment.

Size it for the longest receiver outage you want to survive at your recording rate. An SSH
session can be a single line, because the gateway's SSH backend ignores the recording segment
cap; a session longer than 16 MiB is dropped as `too_long`.

## Verify

```sh
curl -s -H "Authorization: Bearer $TOKEN" $BASE/status | jq .shipper
```

```json
{
  "mode": "spool",
  "shipping": true,
  "pending_lines": 0,
  "pending_bytes": 0,
  "dropped_lines": {"not_json": 7, "not_allowlisted": 212, "too_long": 0, "spool_failed": 0},
  "enrich_failed": 0,
  "enrichment": {"active": true, "last_update_at": "2026-10-08T18:56:40+00:00", "apps": 2},
  "last_success_at": "2026-10-08T18:56:49+00:00"
}
```

- `mode` is `spool`. `disabled` means recording is off in the effective state at startup.
- `shipping` is `true`. `false` means `GWOPS_RECORDING_TOKEN` was not set at startup.
- Open an SSH session through the gateway, run a few commands and exit. `pending_lines` rises
  and drains back to 0, and `last_success_at` advances.
- On the receiver, the session's `session_recording` lines appear, together with its
  `Authenticated connection` line.

Delivery failures are logged as `shipper.post_rejected` (with the receiver's status code) or
`shipper.post_failed` (connection error or timeout). Every 300 s, when a count changed, gwops
logs `shipper.lines_dropped` with the drop counts.

## Roll back

Set `recording.enabled: false` (or remove the block) and restart. Lines still in the spool are
not shipped while recording is off; they stay in `/data/spool` until recording is turned on
again. Remove the `GWOPS_RECORDING_TOKEN` line from `compose.yaml` and `.env` if you no longer need it.

## Related

- [Recording wire format](../reference/recording-wire-format.md): the exact receiver contract.
- [Recording pipeline](../architecture/recording-pipeline.md): filter, enrichment, spool and
  shipper.
- [Seed reference: `recording`](../reference/seed.md#recording)
- [Environment variables](../reference/environment.md)
- [Admin API: `shipper` block](../reference/admin-api.md#shipper)
