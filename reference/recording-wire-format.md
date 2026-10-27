# Recording wire format

This page is the contract between gwops and a recording receiver: the HTTP service that accepts
the gateway's session recordings and audit lines. Any service that implements it works, for
example a recording browser, a SIEM bridge or a log pipeline's HTTP input. How the lines are
produced and filtered is in [Recording pipeline](../architecture/recording-pipeline.md); how to
turn delivery on is in [Session recording](../guides/session-recording.md).

gwops is the client. It sends one request at a time, from one sender per container.

## Endpoint

```text
POST <recording.receiver_url, trailing slashes removed>/ingest
```

- The base URL is the seed key `recording.receiver_url`.
- The base URL may carry a path prefix: `https://logs.example.com/gw` gives
  `https://logs.example.com/gw/ingest`, and `https://logs.example.com/gw/` gives the same.
- `/ingest` is appended to the string as given, so do not put a query string or fragment in the
  base URL.
- The scheme must be `http` or `https`; anything else is refused when the seed loads. An `http://`
  URL logs `shipper.insecure_transport` at startup: the bearer token and every recording then
  travel in cleartext.
- The URL is read once at startup. Changing it needs a restart.

## Request

| Part | Value |
| --- | --- |
| Method | `POST` |
| `Authorization` | `Bearer <GWOPS_RECORDING_TOKEN>` |
| `Content-Type` | `application/x-ndjson` |
| Other headers | The httpx client defaults only (`Host`, `Content-Length`, `Accept`, `Accept-Encoding`, `Connection`, and `User-Agent: python-httpx/<version>`). gwops adds no custom header. |
| Body encoding | UTF-8, uncompressed. No `Content-Encoding`. |
| Protocol | HTTP/1.1. Connections are kept alive and reused between requests. |
| Client certificate | None. |
| Timeout | 30 s for each of connect, read, write and pool acquisition. |
| Proxy | `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` from gwops' environment are honoured. |
| TLS | The receiver certificate is verified. See [Environment](environment.md#variables-that-gwops-own-http-clients-read) for which trust store applies and how to trust a private CA. |
| Redirects | Not followed. A `3xx` is a failure. |

### Body

The body is a batch of one or more lines:

- Each line is exactly one JSON object, as the gateway wrote it (plus the optional `gwops` member
  described [below](#the-gwops-enrichment-object)).
- Each line ends with `\n`, including the last one. gwops joins lines with `\n` only; it adds no
  `\r`, no array wrapper and no blank line.
- Every line is valid UTF-8 and begins with `{`. Lines that are not a JSON object, or not valid
  UTF-8, never reach the spool.
- A line is at most 16 MiB (16,777,216 bytes), not counting its newline. Longer gateway lines are
  dropped whole before the spool and never sent in part.
- A batch holds at most 500 lines.
- A batch holds at most 16 MiB including newlines, except that the first line of a batch is
  always included: a line larger than 16 MiB minus one byte is sent alone. The largest possible
  body is therefore 16,777,217 bytes.

Split the body on `\n` (byte 0x0A) only. Do not split on other line separators: JSON values in
the lines may contain the Unicode characters U+0085, U+2028 or U+2029 literally, and splitting on
them breaks a line into fragments.

Example body with two lines (trimmed):

```text
{"levelname":"info","ts":"2026-10-15T08:59:59.000Z","logger":"system","message":"Authenticated connection",...}\n
{"levelname":"info","ts":"2026-10-15T09:00:00.000Z","logger":"session_recording","message":"session recording",...}\n
```

## Response

- **Any `2xx`** acknowledges the whole batch. The response body is ignored.
- **Anything else** is a failure: any other status, a connection error, a TLS error or a timeout.
  gwops logs `shipper.post_rejected` (with the status and the first 200 characters of the
  response body) or `shipper.post_failed` (with the error), and sends again after a backoff.

There is no partial acknowledgement. A receiver that answers non-`2xx` gets the same lines again.
Reject a batch only if you want all of it resent; to discard a line you cannot use, accept the
batch and drop the line yourself.

Do not put secrets in error response bodies: the first 200 characters are written to gwops' log.

### Retry and backoff

After a failure gwops waits a random delay drawn uniformly from `[b/2, b]`, where `b` starts at
1 s and doubles after each consecutive failure up to a cap of 30 s. A success resets `b` to 1 s.
Retries continue for as long as gwops runs; there is no retry limit and no dead-letter queue.

Each retry starts again at the first unacknowledged line. Its batch can differ from the failed
one: it can hold more lines if more arrived in the meantime (up to the limits above), and it can
start later if the spool evicted the oldest lines while the receiver was down.

## Delivery semantics

- **At least once.** gwops advances its committed position only after a `2xx`. A crash or kill
  between the receiver's acknowledgement and that commit, or a response lost on the network,
  causes the same lines to be sent again.
- **Ordered.** Lines are sent in the order the gateway wrote them to stderr. Batches are sent one
  at a time, and a batch is never sent until the previous one was acknowledged.
- **Byte-identical redelivery.** A resent line is byte-for-byte the line sent before, including
  any `gwops` member, because gwops stores lines in the spool exactly as it will send them.

### Deduplication

Either approach works:

1. **Hash the line bytes** (for example SHA-256 of the line without its newline) and drop lines
   you have already stored. This is exact, because redelivered lines are byte-identical.
2. **Use the gateway's own identifiers**:

   | Line | Key |
   | --- | --- |
   | Recording line (`logger: session_recording`) of an SSH session | `conn_id`, `ssh.channel.id`, `asciicast_sequence_num` |
   | Recording line of a Kubernetes `exec` or `attach` session | `conn_id`, `request_id`, `asciicast_sequence_num` |
   | HTTP audit line (`logger: audit`) | `request_id` |
   | Connection start (`message: Authenticated connection`) | `conn_id` |

   The field names are from gateway `2.0.0` output. Including the channel or request id in the
   recording key is a safe choice for sessions with several channels or requests on one
   connection; this page does not establish whether `asciicast_sequence_num` restarts per channel.

## Line types you will receive

gwops forwards three kinds of gateway line and drops every other line before the spool. The
filter keys on the gateway's `logger` and `message` fields:

| Kind | `logger` | Selector |
| --- | --- | --- |
| Recording line | `session_recording` | Has a string `asciicast` field. The message is not consulted (`session recording`, `session finished`). |
| HTTP audit line | `audit` | `message` is `API request completed` or `API request failed`, and there is no `asciicast` field. |
| Connection start | `system` | `message` is `Authenticated connection`. |

Lines you will **not** receive include SSH audit events (`SSH connection established`,
`SSH connection closed` and other `audit` messages), reverse-proxy errors, authentication failures
and every other operational `system` line.

Every line carries the gateway's common fields: `levelname`, `ts` (RFC 3339 UTC with
milliseconds), `logger`, `message` and `version` (the gateway version); most also carry `caller`.
Treat any field not listed here as optional and expect new fields over time.

The examples below are from gateway `2.0.0`, pretty-printed and with long values trimmed. On the
wire each is one line.

### Connection start

One per authenticated connection. `resource_type` is `SSH`, `KUBERNETES` or `WEB_APP`.

```json
{
  "levelname": "info",
  "ts": "2026-10-15T08:59:59.000Z",
  "logger": "system",
  "caller": "frontend/conn.go:226",
  "message": "Authenticated connection",
  "version": "2.0.0",
  "user": {
    "id": "VXNlcjpwbGFjZWhvbGRlci11c2VyLWlk",
    "username": "placeholder-user",
    "groups": ["example-client-group", "twingate:authenticated"]
  },
  "conn_id": "5d7c1f0e-8a3b-4c2d-9e41-000000000001",
  "resource_type": "SSH",
  "resource_address": "ssh-target.example.com:22"
}
```

### Recording line: SSH

An interactive SSH session ships as one or more recording lines. `asciicast` is a string holding
asciicast v2 text: in the observed output each value starts with the asciicast header line
(`{"version":2,...}`) followed by event lines, separated by `\n` inside the string.
`asciicast_sequence_num` numbers the segments, starting at 1. The final segment has the message
`session finished`.

```json
{
  "levelname": "info",
  "ts": "2026-10-15T09:00:00.000Z",
  "logger": "session_recording",
  "caller": "sessionrecorder/recorder.go:262",
  "message": "session recording",
  "version": "2.0.0",
  "user": {"id": "VXNlcjpwbGFjZWhvbGRlci11c2VyLWlk", "username": "placeholder-user", "groups": ["example-client-group"]},
  "conn_id": "5d7c1f0e-8a3b-4c2d-9e41-000000000001",
  "ssh": {
    "id": "a1b2c3d4",
    "username": "placeholder",
    "client_version": "SSH-2.0-OpenSSH_9.6",
    "server_version": "SSH-2.0-OpenSSH_9.6",
    "channel": {"id": "00000000-0000-4000-8000-000000000001", "type": "session", "source": "client", "target": "upstream"}
  },
  "asciicast": "{\"version\":2,\"width\":120,\"height\":40,\"timestamp\":1792000000,\"command\":\"shell\",\"user\":\"placeholder\"}\n[0.01,\"o\",\"Welcome\\r\\n\"]",
  "asciicast_sequence_num": 1
}
```

The gateway config gwops renders caps a recording segment at 256,000 bytes, but the SSH
recorder does not honour that cap, so a whole SSH session can arrive as a single line, up to the
16 MiB line limit.

### Recording line: Kubernetes

An interactive `kubectl exec` or `attach` session with a TTY ships the same way. Instead of
`ssh`, the line carries the API request: `request_id`, `requested_at`, `method`, `url` and
`remote_addr`.

```json
{
  "levelname": "info",
  "ts": "2026-10-15T09:10:05.000Z",
  "logger": "session_recording",
  "message": "session recording",
  "version": "2.0.0",
  "user": {"id": "VXNlcjpwbGFjZWhvbGRlci11c2VyLWlk", "username": "placeholder-user", "groups": ["example-client-group"]},
  "conn_id": "5d7c1f0e-8a3b-4c2d-9e41-000000000002",
  "request_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "requested_at": "2026-10-15T09:10:00.000Z",
  "method": "POST",
  "url": "/api/v1/namespaces/default/pods/example/exec?command=sh&stdin=true&tty=true",
  "remote_addr": "192.0.2.10:51022",
  "asciicast": "{\"version\":2,\"width\":80,\"height\":24,\"timestamp\":1792000600,\"command\":\"sh\",\"user\":\"placeholder\"}\n[0.1,\"o\",\"# \"]",
  "asciicast_sequence_num": 1
}
```

### HTTP audit line

One per HTTP request through a web app, and one per Kubernetes API request. Header values are
lists of strings.

```json
{
  "levelname": "info",
  "ts": "2026-10-08T18:28:41.760Z",
  "logger": "audit",
  "message": "API request completed",
  "version": "2.0.0",
  "request_id": "ab2db8a1-0f3f-4458-9613-e66547890dad",
  "requested_at": "2026-10-08T18:28:41.758Z",
  "method": "GET",
  "url": "/",
  "remote_addr": "192.0.2.10:51008",
  "user": {"id": "VXNlcjpwbGFjZWhvbGRlci11c2VyLWlk", "username": "placeholder-user", "groups": ["example-client-group"]},
  "conn_id": "686adfd9-5e8e-4d45-b732-a056a29a2692",
  "request": {"headers": {"Accept": ["*/*"], "User-Agent": ["curl/8.22.0"]}},
  "response": {"headers": {"Content-Type": ["application/json"], "Content-Length": ["884"]}, "status_code": 200}
}
```

`API request failed` lines come from the same logger. No sample of their full field set is
reproduced here; parse them defensively.

## The gwops enrichment object

gwops adds one member, `gwops`, to connection-start lines whose `resource_type` is `WEB_APP`, so a
receiver can tell which web app and TLS settings the connection used. It is appended as the last
member of the object, in compact JSON. No other line is changed, and a line that already has a
top-level `gwops` member is left alone.

```json
{"gwops": {"schema": 1, "gateway_id": "R2F0ZXdheTox", "match": "exact", "app": "grafana", "managed": true, "downstream_tls": "tls13", "downstream_port": 443, "upstream_tls": "verify_full", "upstream_port": 3000}}
```

| Field | Type | Present | Meaning |
| --- | --- | --- | --- |
| `schema` | integer | always | `1`. Incremented on any incompatible change. |
| `gateway_id` | string or null | always | The Gateway object id of this container, `null` until known. |
| `match` | string | always | `exact`: one web app on this gateway has this address. `none`: no web app matched (including before gwops has listed the tenant). `ambiguous`: several did. |
| `app` | string | `match: exact` | The web app's entry name in the seed or overlay when gwops manages it, otherwise its Twingate resource name. |
| `managed` | boolean | `match: exact` | Whether gwops created and manages the resource. |
| `downstream_tls` | string | `match: exact` | `tls13` or `none`. |
| `downstream_port` | integer | `match: exact` | The client-facing port. |
| `upstream_tls` | string | `match: exact` | `verify_full`, `verify_ca`, `insecure` or `none`. |
| `upstream_port` | integer | `match: exact` | The upstream port the gateway dials. |

The match compares the line's `resource_address` with each web app's address as the tenant lists
it, by exact string equality, among web apps attached to this gateway. The index is rebuilt from
the tenant listing on every reconcile pass that lists the tenant; a pass that does not keeps the
previous index. If adding the object fails, the line is sent without it and counted in
`/status` `shipper.enrich_failed`.

## Content is not redacted

gwops sends lines as the gateway wrote them. Treat the receiver, its storage and the spool at
`/data/spool` as stores of credentials and personal data. The lines can contain:

- terminal output of SSH and Kubernetes sessions (`asciicast`), which can include anything shown
  on screen, such as secrets printed by a command;
- request header values (`request.headers`): `Authorization`, `Cookie`, API keys and any other
  header the client sent;
- response header values (`response.headers`), including `Set-Cookie`;
- the full request `url`, including its query string (for example OAuth `code` parameters);
- the user's Twingate id, username and group names (`user`), and the client address
  (`remote_addr`);
- the SSH login username (`ssh.username`).

Use `https://` for the receiver.

## Limits and backpressure

| Limit | Value |
| --- | --- |
| Line size | 16 MiB, excluding the newline. Longer lines are dropped (`/status` `shipper.dropped_lines.too_long`). |
| Batch | 500 lines and 16 MiB, or one larger line alone. |
| Spool bound | `recording.spool_max_bytes`, default 256 MiB, minimum 16 MiB. |
| Spool segment | 4 MiB. |

While the receiver is down or rejecting, lines accumulate in the spool. When the spool exceeds
its bound, gwops deletes the oldest whole segments of undelivered lines and logs
`spool.evicted` with the exact line and byte counts lost. The segment holding the newest line is
never evicted, so the spool can exceed the bound by up to one segment.

Lines can also be lost before the receiver sees them:

- a write to the spool fails (counted as `shipper.dropped_lines.spool_failed`, logged as
  `spool.buffered_lines_lost` for lines buffered since the last flush);
- gwops is killed without a graceful shutdown: up to 64 lines that were appended but not yet
  flushed to disk are lost. A host crash can also lose data that was flushed but not yet synced to
  disk; segments are synced when they rotate and on shutdown.

With recording on and `GWOPS_RECORDING_TOKEN` unset, nothing is sent; lines spool until a restart
supplies the token, subject to the same bound. `/status` `shipper` reports `pending_lines`,
`pending_bytes` and `last_success_at`; see [`shipper`](admin-api.md#shipper).

## Minimal conformance checklist

1. Accept `POST` at `<base path>/ingest` over HTTPS.
2. Require `Authorization: Bearer <token>` and compare it in constant time against the token you
   gave the operator for `GWOPS_RECORDING_TOKEN`. Answer `401` otherwise.
3. Accept `Content-Type: application/x-ndjson` and bodies up to 16,777,217 bytes. Configure any
   proxy or framework body limit in front of the receiver to match.
4. Split the body on `\n` only. Ignore an empty final element after the last newline.
5. Parse each line as one JSON object. Do not reject the batch because one line is unusable;
   accept the batch and handle that line yourself.
6. Persist the batch durably before you answer.
7. Answer any `2xx` only after step 6. Do not redirect.
8. Deduplicate: by a hash of the line bytes, or by the keys in [Deduplication](#deduplication).
9. Expect lines to arrive in gateway order, one batch at a time, with redelivery after any
   failure.
10. Tolerate unknown fields, new line shapes from the three kinds above, and the optional `gwops`
    member on web-app connection starts.
11. Protect the stored data as credentials (see [Content is not redacted](#content-is-not-redacted)).
