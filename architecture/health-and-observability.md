# Health and observability

gwops exposes three signals: a composite health endpoint for Docker, a detailed authenticated
status document, and a structured JSON log. The gateway binary adds its own metrics server. This
page explains what each signal means and how they are built.

Code: [`src/gwops/healthcheck.py`](../src/gwops/healthcheck.py), the `healthz` and `status`
handlers in [`src/gwops/api/routes_state.py`](../src/gwops/api/routes_state.py),
[`src/gwops/api/status_webapps.py`](../src/gwops/api/status_webapps.py),
[`src/gwops/logging.py`](../src/gwops/logging.py), and the `HEALTHCHECK` in the `Dockerfile`.

## /healthz

`GET /healthz` is the only unauthenticated admin API route. It answers 200 when healthy and 503
otherwise:

```json
{
  "status": "ok",
  "checks": {
    "gateway": {"ok": true, "state": "running"},
    "reconcile": {"ok": true, "last_at": "2026-10-20T09:14:03.120518+00:00"}
  }
}
```

**Healthy** means both:

- the gateway process is `running` or `starting`; and
- the last reconcile pass had no **local** failure (`local_ok`), or no pass has finished yet.

Tenant-side problems never make the container unhealthy: an unreachable tenant, a missing API
key, a throttled or rejected write all leave `local_ok` true. A degraded start that holds the
gateway down (no upstreams yet, every public certificate still pending ACME) is unhealthy,
because the gateway is not running. So is a gateway in crash backoff, or stopped after a failed
start.

The body carries only booleans, the process state and a timestamp: reconcile actions and errors can
name addresses, tenant ids and file paths, and this route has no authentication.

**Docker healthcheck.** The image's `HEALTHCHECK` runs `python -m gwops.healthcheck` every 30 s with
a 5 s timeout and a 30 s start period (the slim base image has no `curl`). The client:

1. loads the effective state to find `admin_api.bind` and `admin_api.port`, so it probes the same
   address the server bound when you override them; `0.0.0.0`, `::`, `localhost` and `127.0.0.1`
   are probed on `127.0.0.1`, any other bind address directly;
2. falls back to `127.0.0.1` and `GWOPS_HEALTHCHECK_ADMIN_FALLBACK` (default 8081) if the state cannot be loaded;
3. sends one GET with a 4 s timeout, under Docker's 5 s, and exits 0 only on HTTP 200.

The server binds once at startup, but the healthcheck reads the seed every time, so changing
`admin_api.port` or `bind` without restarting makes the healthcheck probe an address nothing listens
on. Restart after changing them.

## /status

`GET /status` needs the admin token (the automation token gets 403) and returns the operational
snapshot. Each block answers one question:

| Block | Tells you |
| --- | --- |
| `process` | The gateway's state (`stopped`, `starting`, `running`, `draining`, `backoff`) and last exit code |
| `capabilities` | `gateway_version`: the pinned binary version baked into the image (reported, never enforced) |
| `last_reconcile` | The last pass: `ok`, `local_ok`, `trigger`, `started_at`, `actions`, `errors` |
| `certs` | Private mode: `x509_ca_not_after`, `leaf_not_after`, `leaf_state`. Public mode: `public[]` per certificate (state, expiry, generation, last error, ACME state), `public_acme_errors`, `registered_root` (tenant CA id, `bound`) |
| `tg` | `configured` (API key set), `attempted` (the last pass reached tenant sync), `ok`, the tenant-side `errors` of the last pass (`TG sync...`, `CA registration...`), and `gateway_mismatches` |
| `web_apps` | Counts, policy `warnings`, `browser_trust`, unmanaged and unserved apps, `automation_off_policy`, and `readiness[]` with probe results |
| `tls` | `mode` (`static`, `static+on_demand`, `public`) and the on-demand `warning` |
| `jwks` | Reachability of the tenant key set: `ok`, `checked_at`, `error_class`, `reason`; `null` before the first check |
| `housekeeping` | `errors` from the last garbage collection and whether the last pass ran it |
| `shipper` | `{"mode": "disabled"}` with recording off; otherwise `shipping`, `pending_lines`, `pending_bytes`, `dropped_lines` by reason, `enrich_failed`, `enrichment`, `last_success_at` |
| `state_error` | The load error when the effective state does not currently load, else `null` |

`/status` is built to keep answering while something is broken. The effective state is loaded
fresh for each request; if it fails, `state_error` carries the message and the blocks that need it
degrade. The computed blocks (`certs`, `web_apps`, `tls` and the readiness inside `web_apps`)
catch their own failures and degrade to `{"computation_failed": true, "error_type": "..."}`
instead of failing the request, logging `status.block_failed` with the error type only.

What to watch:

| Signal | Means |
| --- | --- |
| `last_reconcile.ok == false` | Something failed on the last pass; read `errors` |
| `last_reconcile.local_ok == false` | The gateway is running on an older config |
| `tg.ok == false` | Tenant sync is failing; resources may be out of date |
| `certs.leaf_state != "ok"` | The leaf could not be kept current (re-minting normally fixes it within a pass) |
| `certs.public[].state` `invalid` or `expiring` | A public certificate needs attention |
| `jwks.ok == false` | Web-app sessions will fail to authenticate |
| `shipper.pending_lines` growing, `last_success_at` stale | The recording receiver is not acknowledging; the spool is filling |
| `web_apps.readiness[].state == "action_required"` | A web app is not usable as declared |
| `housekeeping.errors` non-empty | Stale copies are accumulating on `/data` |

The response schema is in [`reference/admin-api.md`](../reference/admin-api.md#get-status).

## gwops logs

gwops logs with structlog: one JSON object per line on stdout, which is what `docker logs` shows.

```json
{"trigger": "tick", "ok": true, "actions": ["minted TLS leaf (expiring: ...) covering 3 SAN(s)"],
 "errors": [], "duration": 0.412, "event": "reconcile.completed", "level": "info",
 "timestamp": "2026-10-20T09:24:03.532871Z"}
```

| Field | Content |
| --- | --- |
| `event` | The event name, `<area>.<what>`: `supervisor.*`, `reconcile.*`, `gateway.*`, `api.*`, `tgapi.*`, `acme.*`, `shipper.*`, `spool.*`, `jwks.*`, `tls.*` |
| `level` | `info`, `warning` or `error` |
| `timestamp` | ISO 8601 in UTC |
| other keys | The event's structured fields |

**Redaction.** Before rendering, every field whose **key** matches `token`, `key`, `secret`,
`password`, `passphrase`, `auth`, `credential`, `bearer`, `cookie` or `signature`
(case-insensitive) has its entire value replaced with `[REDACTED]`, recursively: a dict or list
under a secret-named key is redacted whole, so a secret cannot hide one level down. The
structlog-owned keys `event`, `level`, `timestamp` and `logger` are exempt. Redaction is by key, a
safety net behind the main rule that secrets are never put into log fields; values under
innocent keys are not scanned.

`GET /state` applies the same key rule to the effective state it returns, except keys ending in
`_file`, `_path` or `_dir`, which name locations you need to see, not secrets.

The gateway's operational (`system`) lines are relayed into the gwops log as `gateway.system`
events, with every field of the gateway's line, including user identity on `Authenticated
connection` lines; the redaction rule above still applies to them. What is not in the gwops log:
gateway audit lines and session recordings (see
[Recording pipeline](recording-pipeline.md#what-reaches-docker-logs)), request bodies, header
values, PEM text and key material. uvicorn's own logging and access log are disabled.

The events worth alerting on, with their meaning and the action to take, are listed in
[`reference/log-events.md`](../reference/log-events.md).

## Gateway metrics

The gateway binary runs its own metrics server on port 9090 (rendered as `metricsPort: 9090`) and
serves `/metrics` there. gwops does not read, proxy or change it. The shipped `compose.yaml`
publishes it on host loopback only (`127.0.0.1:9090:9090`). Treat it as the binary's interface; it
is not a health endpoint, and gwops' health is `/healthz` on the admin port.

## See also

- [`reference/admin-api.md`](../reference/admin-api.md#get-status): the `/status` schema.
- [`reference/admin-api.md`](../reference/admin-api.md#get-healthz): `/healthz`.
- [`reference/log-events.md`](../reference/log-events.md): log events and actions.
- [`operations/monitoring.md`](../operations/monitoring.md): what to poll and alert on.
- [`reference/image.md`](../reference/image.md#healthcheck): the image healthcheck parameters.
