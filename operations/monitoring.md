# Monitoring

Four signals tell you how the container is doing: the Docker health status, the admin API's
`GET /status`, gwops' JSON log on stdout, and the gateway binary's metrics server.

## When to use

You run the gateway in production and want to be alerted before users notice a problem.

## Prerequisites

- The admin token, and a monitoring host that can reach the admin API. See
  [Admin API behind a TLS proxy](admin-api-behind-tls-proxy.md); the examples below run on the
  Docker host.
- `jq` for the shell examples.
- A log pipeline that reads container stdout, if you alert on log events.

## Steps

### 1. Watch container health

The image's healthcheck runs `python -m gwops.healthcheck` every 30 s (5 s timeout, 30 s start
period) against the unauthenticated `GET /healthz`.

```sh
docker compose ps
docker inspect --format '{{json .State.Health}}' gwops-gateway | jq
docker events --filter container=gwops-gateway --filter event=health_status
```

The container is healthy when both hold:

- the gateway process is `running` or `starting`, and
- the last reconcile pass had no local failure (or no pass has finished yet).

Tenant problems never make it unhealthy: the gateway keeps serving its last good config while
the tenant is unreachable or the API key is wrong. Watch `/status` for those.

Unhealthy means the gateway is not serving, or the last pass failed locally (a refused config,
a certificate, credential or CA-bundle problem, a web-app policy violation). The gateway is also
`stopped`, and the container unhealthy, while it is held down on purpose: no upstreams are
declared yet, or every public certificate is still waiting for ACME issuance.

### 2. Poll `/status`

```sh
curl -s -H "Authorization: Bearer $TOKEN" $BASE/status
```

Suggested alerts:

| Condition | What it means |
| --- | --- |
| `last_reconcile.ok == false` | The last pass recorded errors. `last_reconcile.errors` says which. |
| `last_reconcile.local_ok == false` | A local step failed; the gateway runs its last good config. |
| `last_reconcile.started_at` older than twice `GWOPS_RECONCILE_TICK_SECONDS` (default 600 s) | Passes have stopped running. |
| `tg.ok == false` | Tenant sync is failing: an outage, a bad API key, or permissions. `tg.errors` lists them. |
| `tg.gateway_mismatches` not empty with `corrected: false` | A managed SSH or Kubernetes resource is attached to another gateway. |
| `certs.leaf_state` neither `ok` nor `null` | The private-mode leaf is missing, expiring, has wrong SANs or is invalid. |
| any `certs.public[].state` in `invalid`, `expiring` | A public certificate was refused, or has under a third of its lifetime left. |
| any `certs.public[].acme.error_code` not `null` | The last ACME attempt failed. |
| `certs.registered_root.bound == false` | Public mode: the gateway is not bound to the registered root. |
| `jwks.ok == false` | The tenant's token-signing keys are unreachable or invalid; web apps will fail. |
| `shipper.shipping == false` with `shipper.mode == "spool"` | Recording is on but no token was set; nothing ships. |
| `shipper.pending_lines` growing across polls, or `shipper.last_success_at` not advancing while it is non-zero | The receiver is not acknowledging. The spool will eventually evict. |
| any `web_apps.readiness[].state == "action_required"` | Something stands between a web app and a working session; `reasons` says what. |
| `housekeeping.errors` not empty | A cleanup step failed. Not urgent; disk use can grow. |
| `state_error` not `null` | The effective state does not load. |

A poller that prints one line per problem:

```sh
curl -fsS -H "Authorization: Bearer $TOKEN" $BASE/status | jq -r '
  (if .last_reconcile.ok == false then "reconcile: \(.last_reconcile.errors | join("; "))" else empty end),
  (if .tg.ok == false then "tenant: \(.tg.errors | join("; "))" else empty end),
  (if (.certs.leaf_state // "ok") != "ok" then "leaf: \(.certs.leaf_state)" else empty end),
  (.certs.public[]? | select(.state == "invalid" or .state == "expiring") | "public cert \(.name): \(.state)"),
  (.certs.public[]? | select(.acme.error_code? != null) | "acme \(.name): \(.acme.error_code)"),
  (if .jwks != null and .jwks.ok == false then "jwks: \(.jwks.error_class)" else empty end),
  (if .shipper.mode == "spool" and .shipper.shipping == false then "shipper: not shipping" else empty end),
  (.web_apps.readiness[]? | select(.state == "action_required") | "web app \(.name): \(.reasons | join(", "))"),
  (.housekeeping.errors[]? | "housekeeping: \(.)"),
  (if .state_error != null then "state: \(.state_error)" else empty end)'
```

Empty output means nothing to report. A `/status` block that cannot be built is replaced by an
object with `computation_failed: true` and an `error_type`; the call still answers `200`, so
alert on `computation_failed` too.

### 3. Collect gwops logs

gwops writes one JSON object per line to stdout, with ISO 8601 UTC timestamps. Values under
keys that look like secrets (token, key, secret, password, auth, cookie and similar) are
redacted. Read them with:

```sh
docker compose logs --no-log-prefix -f gateway
```

Events worth alerting on:

| Event | Meaning |
| --- | --- |
| `supervisor.startup_failed` | Startup aborted; the container exits with status 1. The `error` field says why. |
| `gateway.crashed` | The gateway exited; gwops restarts it with backoff (1 s doubling to 60 s). |
| `gateway.early_exit_rollback` | The gateway exited within 5 s of starting; gwops restored the last good config. |
| `spool.evicted` | Undelivered recordings were deleted because the spool was full. `lines_lost` and `bytes_lost` say how many. |
| `shipper.post_rejected` | The receiver answered with a non-2xx status (in `status_code`). |
| `shipper.post_failed` | The receiver could not be reached or timed out. |
| `enrich.index_stale` | The web-app enrichment index is no longer refreshed from the tenant. |

`docker logs` carries gwops' own log, the gateway's stdout, and the gateway's operational
(`system`) lines as `gateway.system` events. Alert on `gateway.system` with `level: error` to catch
gateway-side failures such as reverse-proxy errors. `Authenticated connection` lines carry the
user's id, username and groups, so treat the container log as holding user identity. The gateway's
audit lines (HTTP and SSH) and session recordings never reach `docker logs`: each appears only as a
`gateway.line` event with a byte count and `content: "[suppressed]"`. To collect gateway audit and
recording data, use [session recording](../guides/session-recording.md).

The [log events reference](../reference/log-events.md) lists every event.

### 4. Scrape gateway metrics

The gateway binary runs its own metrics server on port 9090 (`metricsPort: 9090` in the
rendered config), serving `/metrics`. `compose.yaml` publishes it on host loopback only
(`127.0.0.1:9090:9090`). A Prometheus scrape job on the Docker host:

```yaml
scrape_configs:
  - job_name: twingate-gateway
    static_configs:
      - targets: ["127.0.0.1:9090"]
```

Which metrics the binary exports is defined by the Twingate Gateway, not by gwops. Port 9090
is not a health endpoint; use `/healthz` for health.

## Verify

- In a test deployment, set `TWINGATE_API_KEY` to a wrong value, recreate the container, and
  confirm the poller reports `tenant:` while the container stays healthy.
- `curl -s http://127.0.0.1:9090/metrics | head` on the Docker host returns metrics.
- Your log pipeline shows `reconcile.completed` events every `GWOPS_RECONCILE_TICK_SECONDS`.

## Related

- [Health and observability](../architecture/health-and-observability.md)
- [Admin API: `GET /status`](../reference/admin-api.md#get-status)
- [Admin API: `GET /healthz`](../reference/admin-api.md#get-healthz)
- [Log events reference](../reference/log-events.md)
- [Troubleshooting](troubleshooting.md)
