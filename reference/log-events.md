# Log events

gwops writes one JSON object per line to stdout, which `docker logs` shows. This page lists the
events worth watching or alerting on. How logging works is in
[Health and observability](../architecture/health-and-observability.md).

## Line format

```json
{"trigger": "startup", "ok": true, "actions": ["minted TLS leaf ..."], "errors": [], "duration": 1.234, "event": "reconcile.completed", "level": "info", "timestamp": "2026-10-15T09:00:01.234567Z"}
```

| Field | Meaning |
| --- | --- |
| `event` | The event name, `<area>.<what>`. Match on this. |
| `level` | `info`, `warning` or `error`. Unexpected exceptions are logged at `error` with an `exception` field holding the traceback. |
| `timestamp` | ISO 8601, UTC. |
| other fields | Event-specific. Field names and order are not a stable interface beyond those named on this page. |

Values under any key whose name contains `token`, `key`, `secret`, `password`, `passphrase`,
`auth`, `credential`, `bearer`, `cookie` or `signature` (case-insensitive) are replaced with
`[REDACTED]`, including everything nested under such a key. Debug events are not emitted.

### Gateway output in `docker logs`

The gateway writes its operational (`system`), audit and session-recording lines to stderr. What
gwops puts in its own log, whether recording is on or off:

- **Every stderr line** produces a metadata-only `gateway.line` event: `stream: gateway-stderr`,
  the byte count and `content: "[suppressed]"`.
- **Operational lines** (logger `system`) are also relayed in full as `gateway.system` events.
  See [Gateway `system` lines](#gateway-system-lines).
- **Audit lines** (HTTP and SSH), **session recordings**, lines that are not JSON objects, and any
  line carrying an `asciicast` key are never relayed. Their content leaves the container only
  through the [recording pipeline](recording-wire-format.md), when recording is on.
- **Gateway stdout** is copied: `gateway.line` with `stream: gateway-stdout` and the `line` text.
- **Pre-flight output.** When a candidate config fails pre-flight, `spawn.validate_rejected`
  (and `spawn.validate_exited_zero_early`) includes the candidate process's stderr text, so you
  can see why the gateway refused it.

### Gateway `system` lines

Each `gateway.system` event carries every field of the gateway's JSON line as a top-level key:
`ts`, `levelname`, `logger` (always `system`), `caller`, `message`, `version`, and any others the
line has. An `Authenticated connection` line includes a `user` object (`id`, `username`,
`groups`), `conn_id`, `resource_type` and `resource_address`, so user identity appears in
`docker logs`.

- A gateway field named `event`, `level`, `timestamp`, `exc_info`, `stack_info` or `exception` is
  renamed with a `gateway_` prefix (`gateway_level`), so it cannot replace gwops' own fields.
- `level` derives from the gateway's `levelname`: `warn` and `warning` give `warning`; `error`,
  `dpanic`, `panic` and `fatal` give `error`; anything else gives `info`.
- The redaction rule above applies: a gateway field whose name matches it is logged as
  `[REDACTED]`.

```json
{"levelname": "info", "ts": "2026-10-15T09:00:05.120Z", "logger": "system", "caller": "frontend/conn.go:226", "message": "Authenticated connection", "version": "2.0.0", "user": {"id": "VXNlcjox", "username": "alice@example.com", "groups": ["Platform Engineers", "twingate:authenticated"]}, "conn_id": "5d7c1f0e-8a3b-4c2d-9e41-000000000001", "resource_type": "SSH", "resource_address": "web-1.internal.example.com:22", "event": "gateway.system", "level": "info", "timestamp": "2026-10-15T09:00:05.121004Z"}
```

## Startup and lifecycle

| Event | Level | Meaning | Action |
| --- | --- | --- | --- |
| `supervisor.startup_failed` | error | Startup aborted; the container exits with status 1. `error` names the problem: an invalid seed (dotted path and layer), unusable CA material, a web-app policy violation, an unsafe automation token, refused public certificate material, a registered public root missing from the image's trust store, a populated seed that could not start the gateway, or an admin socket that could not bind. | Fix what `error` names, then restart. |
| `supervisor.running` | info | Startup finished. Fields: `gateway_started`, `tick_seconds`, `admin_port`, `shipping`. | None. |
| `supervisor.waiting_for_upstreams` | warning | The seed declares no upstreams, so there is no TLS leaf to mint; the gateway is held down until the first upstream arrives. | Add an upstream, in the seed or through the admin API. |
| `supervisor.waiting_for_acme` | warning | Every public certificate is a `source: acme` certificate with nothing installed; the gateway starts after the first install. `certificates` lists them. | Watch `/status` `certs.public[].acme`. With `directory: staging` the wait never ends. |
| `supervisor.tg_sync_disabled` | warning | `TWINGATE_API_KEY` is not set; nothing is synced to the tenant. | Set the key, or accept local-only operation. |
| `supervisor.shipper_token_missing` | warning | `recording.enabled` is true but `GWOPS_RECORDING_TOKEN` is not set; lines spool and are not sent. | Set the token and restart. |
| `supervisor.acme_staging_dry_run` | warning | `public_tls.acme.directory` is staging: certificates are issued and validated but never installed. | Set `directory: production` once the dry run reports `dry_run_ok`. |
| `supervisor.acme_cloudflare_environment_ignored` | warning | `CF_*` or `CLOUDFLARE_*` variables are in gwops' environment. They are never given to lego. `variables` lists the names. | Remove them; the DNS token comes from `public_tls.acme.token_file`. |
| `supervisor.acme_token_file_unusable` | error | The ACME DNS token file is missing, empty, not a regular file or outside `/config/acme/`. Startup continues; lego does not run. | Mount the token file. |
| `supervisor.acme_certificate_pending` | warning | A `source: acme` certificate has nothing valid installed (or its names changed). | None if issuance is in progress. |
| `supervisor.acme_installed_material_refused` | error | Installed ACME material failed validation at startup; the certificate is treated as pending and reissued. | Watch the next issuance. |
| `supervisor.signal` | info | A signal arrived (`SIGTERM`, `SIGINT` start shutdown; `SIGHUP` runs a reconcile pass). | None. |
| `supervisor.exited` | info | Shutdown finished. | None. |
| `acme.runner_unavailable` | error | The ACME runner could not be built. Startup continues; no certificate is issued or renewed. | Read `error`; restart after fixing. |
| `api.serving` | info | The admin API is listening. Fields: `bind`, `port`. | None. |
| `api.admin_token_unset` | warning | `GWOPS_ADMIN_TOKEN` is not set; every route except `GET /healthz` answers `401`. | Set the token and restart. |
| `tls.on_demand_issuance_active` | warning | `ca.x509.on_demand_issuance` is on. `reason` states the exposure. Logged at startup and when the mode turns on. | Confirm this is intended. |
| `jwks.client_unavailable` | error | The JWKS check could not be set up; `/status` `jwks` stays `null`. | Read `error_type`. |

## Reconcile passes

| Event | Level | Meaning | Action |
| --- | --- | --- | --- |
| `reconcile.started` | info | A pass began. `trigger` is `startup`, `seed-change`, `tick`, `api`, `api-rollback` or `sighup`. | None. |
| `reconcile.completed` | info or warning | A pass ended. Fields: `trigger`, `ok`, `actions`, `errors`, `duration` (seconds). Logged at `warning` when `ok` is false. | Alert on repeated `ok: false`; `errors` names each problem. |
| `reconcile.tg_write_deferred` | warning | The tenant throttled a write earlier in the pass, so this resource's write was skipped (`resource`); the next pass retries it. | None unless it persists. |
| `reconcile.webapp_policy_warnings` | warning | The effective state uses allowed but weaker web-app settings (`verify_ca`, `insecure`, `none`). Logged once per distinct set. | Review `warnings`. |
| `reconcile.gateway_mismatches` | warning | Managed resources are attached to another gateway on the tenant. | Move SSH and Kubernetes resources back on the tenant; web apps are moved back by gwops. |
| `reconcile.probe_skipped` | warning | The upstream TLS probe was skipped because the CA bundle step failed. | Fix the CA bundle error in `errors`. |
| `reconcile.acme_token_file_unusable` | error | The ACME DNS token file became unusable. lego does not run. | Fix the token file mount. |
| `public_cert_unused` | warning | A `public_tls` certificate matches no served name. Logged once when the set changes. | Remove the certificate or add the upstream it is for. |
| `watch.seed_changed` | info | The seed file changed; a pass follows. | None. |
| `leaf.minted` | info | A new TLS leaf was minted. | None. |
| `x509_ca.rotation_completed` | info | An X.509 CA rotation was promoted. | None. |
| `registry.recorded`, `registry.forgotten` | info | gwops recorded or forgot a tenant object id in its ownership registry. | None. |

## Gateway process

| Event | Level | Meaning | Action |
| --- | --- | --- | --- |
| `gateway.spawned` | info | The gateway process started. Fields: `pid`, `argv`. | None. |
| `gateway.stopped` | info | The gateway process was stopped deliberately. | None. |
| `gateway.line` | info | One line of gateway output. From stdout it carries `line`; from stderr it carries only `bytes` and `content: "[suppressed]"` (a `system` line is relayed separately as `gateway.system`). | None. |
| `gateway.line_too_long` | warning | A gateway output line over 16 MiB was discarded whole. `bytes` gives its size. | If recording is on, a recording was lost. |
| `gateway.crashed` | warning | The gateway exited unexpectedly after running at least 5 s; it restarts after `backoff_seconds` (1 s doubling to 60 s, reset after 300 s up). | Alert on repeats. |
| `gateway.early_exit_rollback` | error | The gateway exited within 5 s of starting; gwops restored the last-good config (`restored_last_good`). The failed config is never re-applied. | Find the cause in `reconcile.completed` errors and the seed change that preceded it. |
| `gateway.drain_timeout` | warning | The gateway did not exit within 30 s of SIGTERM and was killed. | Investigate if frequent. |
| `gateway.system` | info, warning or error | One gateway operational (`system`) line, relayed with all its fields. See [Gateway `system` lines](#gateway-system-lines). | Alert on `level: error`. |
| `gateway.system_relay_failed` | warning | A `system` line could not be relayed. The line is not lost from the recording pipeline. | Investigate if frequent. |
| `gateway.reader_died` | error | A reader of the gateway's output failed; that pipe is no longer read and the gateway blocks once it fills. | Restart the container. |
| `spawn.validate_rejected` | warning | A candidate config failed pre-flight; the running config is kept. `stderr` holds the candidate's output. | Read `stderr`; fix the seed or overlay. |
| `spawn.validate_exited_zero_early` | warning | The candidate exited with status 0 before the pre-flight window ended. `stderr` holds its output. | Read `stderr`. |

## Recording delivery

| Event | Level | Meaning | Action |
| --- | --- | --- | --- |
| `shipper.insecure_transport` | warning | The receiver URL is `http://`: the token and recordings travel in cleartext. The message names `recording.receiver_url`. | Use `https://`. |
| `shipper.post_failed` | error | A batch could not be sent (connection error, TLS error or timeout). `error` gives the reason. Retried with backoff. | Check receiver reachability. |
| `shipper.post_rejected` | error | The receiver answered non-`2xx`. Fields: `status_code`, `body` (first 200 characters). Retried with backoff. | Check the receiver and the token. |
| `shipper.lines_dropped` | info | Counts of gateway lines not shipped, by reason (`not_json`, `not_allowlisted`, `too_long`, `spool_failed`) and `enrich_failed`. Logged every 300 s when a count changed, and at shutdown. | Alert on `too_long` or `spool_failed` increasing. |
| `shipper.spool_append_failed` | error | A kept line could not be written to the spool. | Check `/data` space and permissions. |
| `spool.evicted` | error | The spool exceeded `recording.spool_max_bytes`; the oldest undelivered segment was deleted. Fields: `lines_lost`, `bytes_lost`. | Restore the receiver; raise the bound if needed. |
| `spool.buffered_lines_lost` | error | A spool write failed and lines buffered since the last flush were dropped (`lines_lost`). | Check `/data` space and permissions. |
| `spool.rotate_failed` | error | A spool segment could not be sealed; retried. | Check `/data`. |
| `enrich.index_stale` | warning | The web-app index used for the `gwops` enrichment object was not refreshed by the last pass; lines are enriched from the last successful listing. | Check tenant sync. |
| `enrich.index_fresh` | info | The index was refreshed again. | None. |

## Admin API

| Event | Level | Meaning | Action |
| --- | --- | --- | --- |
| `api.audit` | info | One line per `POST`, `PUT` and `DELETE` request. Fields: `principal` (`admin`, `automation` or `null` for an unauthenticated request), `method`, `route`, `status`, `overlay_id`. Never request bodies or credentials. | Ship to your audit store. |
| `api.change_rolled_back` | warning | A write was rolled back because the reconcile did not confirm it. | Read the response body or the pass errors. |
| `api.acme_issue` | info | `POST /certs/public/{name}/issue` queued an attempt. | None. |
| `api.acme_issue_refused` | warning | An issuance request was refused before it reached the runner. | Read the response. |
| `api.rotate_ca_completed` | info or warning | `POST /certs/rotate-ca` `complete` finished; `warning` when it has `errors`. | Read `errors`. |

## ACME

| Event | Level | Meaning | Action |
| --- | --- | --- | --- |
| `acme.runner.attempt_started` | info | lego started for a certificate. | None. |
| `acme.runner.installed` | info | A certificate was issued, validated and installed. | None. |
| `acme.runner.dry_run_ok` | info | A staging dry run issued and validated a certificate (not installed). | Switch to production. |
| `acme.runner.attempt_failed` | warning | An attempt failed; it is held for a backoff. | Read `/status` `certs.public[].acme.error_code`. |
| `acme.runner.lego_timeout` | warning | lego exceeded `GWOPS_LEGO_TIMEOUT_SECONDS` and was killed. | Check egress to the ACME directory and Cloudflare. |
| `acme.runner.task_died` | error | The ACME runner's loop ended; nothing is scheduled. | Restart the container. |
| `acme.runner.state_unusable` | error | `/data/acme/state.json` cannot be used; issuance is refused. | Repair or remove the file. |

## Twingate API and JWKS

| Event | Level | Meaning | Action |
| --- | --- | --- | --- |
| `tgapi.throttled` | warning | The tenant answered HTTP 429; gwops waits (at most 60 s per wait). | None unless frequent. |
| `tgapi.throttle_budget_exhausted` | warning | This pass has spent its 90 s throttle budget; further throttled calls fail at once. | None unless frequent. |
| `tgapi.transport_error` | warning | A Twingate API request failed in transport; retried. | Check egress. |
| `jwks.unreachable` | error | The tenant's token-signing key set could not be fetched. Web-app sessions are likely to fail. | Check egress to `https://<network>.<host>/api/v1/jwk/ec`. |
| `jwks.degraded` | warning | The key-set fetch timed out or returned `5xx`. | Watch for repeats. |
| `jwks.invalid` | warning | The key set was fetched but is not usable. | Check the tenant URL. |
| `jwks.check_timeout` | warning | A check outlasted its 30 s bound; marked `degraded`. | Check egress. |

## Web apps

| Event | Level | Meaning | Action |
| --- | --- | --- | --- |
| `webapp_probe.result` | info or warning | The upstream TLS probe outcome for an app changed (`outcome`). | Act on non-`ok` outcomes. |
| `webapp_probe.address_refused` | warning | The probe refused to dial an address (loopback, link-local, metadata and similar). | None, or fix the app address. |
| `reconcile.webapp_snapshot_failed` | warning | The web-app part of `/status` could not be built from the tenant listing this pass. | Check logs; a later pass recovers. |
