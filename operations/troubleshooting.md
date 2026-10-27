# Troubleshooting

Symptom-to-cause tables for the gateway container, by area. Each row names what you see, where
you see it (a log event or a `/status` field), the cause, and the fix.

## When to use

Something does not work and you want to find out why before changing anything.

## Prerequisites

- Shell access to the Docker host.
- The admin token, for `/status`. If the admin API does not answer, start with the logs.

## Steps

### Gather the facts

```sh
docker compose ps
docker compose logs --no-log-prefix --tail 200 gateway
curl -s http://127.0.0.1:8081/healthz
curl -s -H "Authorization: Bearer $TOKEN" $BASE/status | jq '{process, last_reconcile, tg, tls, state_error}'
```

- The log is one JSON object per line. `event` is the event name; `error`, `errors` and
  `reason` carry the explanation.
- `last_reconcile.errors` lists what went wrong in the last pass; `last_reconcile.actions` lists
  what it did.
- `curl` on the host reaches the admin API only when the seed sets `admin_api.bind: 0.0.0.0`;
  see [Admin API behind a TLS proxy](admin-api-behind-tls-proxy.md).

The gateway's own operational log reaches `docker logs` as `gateway.system` events. Filter on
them to see what the gateway itself reports: listeners, certificate reloads, proxy errors and
`Authenticated connection` lines.

```sh
docker compose logs gateway | grep '"event": "gateway.system"'
```

Gateway audit lines (HTTP and SSH) and session recordings never reach `docker logs`. HTTP audit
lines and recordings leave the container only through
[session recording](../guides/session-recording.md); SSH audit events are not carried anywhere.

### Name resolution

The gateway dials every upstream itself (SSH hosts, the Kubernetes API server, web apps) through
the container's resolver, not the Docker host's. gwops does not manage `/etc/hosts`. A name that
resolves on the host or on your LAN can still fail inside the container, and this is the most
common cause of upstreams that do not connect. Check any host-name address first:

```sh
docker compose exec gateway getent hosts <address>
```

No output means the container cannot resolve the name. Serve it from DNS the container uses, or pin
it with `extra_hosts` on the `gateway` service in `compose.yaml` (the shipped file has a commented
example), then `docker compose up -d`. A name added later through the admin API needs the same
edit. IP-literal addresses are not affected.

| Symptom | Where | Cause | Fix |
| --- | --- | --- | --- |
| Connections to a resource addressed by host name fail, while resources addressed by IP work | Twingate client | The name does not resolve inside the container. | `getent hosts <address>` as above; add DNS or an `extra_hosts` entry. |
| `kubectl` through the gateway fails while the cluster is reachable from the host | Twingate client | The cluster's `server` host name does not resolve inside the container. | As above, for the API server's host name. |
| `502` from a web app | Browser or client | The app's `address` does not resolve inside the container (other causes are under [Web apps](#web-apps)). | As above. |
| `probe:unreachable` | `web_apps.readiness[].reasons` | The upstream TLS probe could not resolve or connect to the address from inside the container. | Check resolution as above, then that the upstream port is reachable from the container. |
| An upstream added through `PUT /upstreams/...` does not connect, though the seed's upstreams do | Twingate client | Its name is new and has no `extra_hosts` entry. | Add the entry and `docker compose up -d`. |

### Startup

| Symptom | Where | Cause | Fix |
| --- | --- | --- | --- |
| Container exits with status 1 and restarts | `supervisor.startup_failed`, `error` holds `<dotted.path>: <message> (set by layer: seed)` | The seed fails validation. Unknown keys are refused. | Fix the named key in `seed.yaml`. |
| As above, with `(set by layer: 0003-...)` | `supervisor.startup_failed` | An overlay makes the effective state invalid. | While the container is down, remove that overlay's file, `/data/overlays/<id>.json` (for example with `docker compose run --rm --no-deps --entrypoint rm gateway /data/overlays/<id>.json`). When it is running, use `DELETE /overlays/<id>`. |
| `cannot read seed file /config/seed.yaml` (`Is a directory`) | `supervisor.startup_failed` | `seed.yaml` did not exist when the container was created, so Docker created a directory in its place. | Stop the container, remove the `seed.yaml` directory, `cp seed.example.yaml seed.yaml`, edit it, and `docker compose up -d`. |
| `docker compose up` refuses to start: `set TWINGATE_API_KEY in .env` | Compose output | `TWINGATE_API_KEY` or `GWOPS_ADMIN_TOKEN` is missing from `.env`. | Set both in `.env`. |
| `GWOPS_AUTOMATION_TOKEN is set but twingate.access_allowlist ... not configured` | `supervisor.startup_failed` | The automation token needs both allowlists. An empty but present variable counts as set. | Add both allowlists, or remove the variable from `compose.yaml`. See [Automation and CI](../guides/automation-and-ci.md). |
| `GWOPS_AUTOMATION_TOKEN must differ from GWOPS_ADMIN_TOKEN` | `supervisor.startup_failed` | The two tokens are equal. | Generate a separate automation token. |
| `startup reconcile could not bring the gateway up: ...` | `supervisor.startup_failed` | The first pass could not start the gateway; the rest of the message is the pass's errors. | Fix the first error listed. |
| Startup fails on a certificate file | `supervisor.startup_failed` | A bring-your-own CA, an on-demand CA or a `source: file` public certificate was refused. The message names the file and property. | Fix that file. |
| Container runs but is unhealthy; log shows `supervisor.waiting_for_upstreams` | `/status` `process.state: stopped` | No upstreams are declared, so there is nothing for a leaf to cover. The gateway is held down. | Add an upstream to the seed or with `PUT /upstreams/...`. |
| Container runs but is unhealthy; log shows `supervisor.waiting_for_acme` | `last_reconcile.actions` contains `gateway held down until a public certificate can be rendered` | Every public certificate is a `source: acme` certificate with nothing installed yet. With `directory: staging` this never ends. | Wait for the first issuance, or set `public_tls.acme.directory: production` after a successful dry run. |

### Tenant sync

| Symptom | Where | Cause | Fix |
| --- | --- | --- | --- |
| `TG sync skipped: TWINGATE_API_KEY is not set` | `last_reconcile.errors`, `supervisor.tg_sync_disabled` | No API key. Local config still applies; nothing is synced to the tenant. | Set `TWINGATE_API_KEY` and recreate the container. |
| `tg.ok: false`, errors about permissions or authorization | `tg.errors` | The API key cannot read or write what gwops needs. | Use an API key with read and write access, including resources, certificate authorities and gateways. |
| `cannot auto-create the gateway: no registered X.509 CA` | `last_reconcile.errors` | Remote-network mode found no Gateway object at `gateway_address`, and gwops has no registered X.509 CA to create one with (the X.509 CA is bring-your-own). | Use `ca.x509.generate: true`, or create the Gateway object yourself and set `twingate.gateway_id`. See [Gateway modes](../guides/gateway-modes.md). |
| `TG sync skipped: the gateway could not be resolved this pass` | `last_reconcile.errors` | The Gateway object could not be found or created; an earlier error says why. | Fix the earlier error. |
| `access: no group named '...'` on a resource | `GET /upstreams/<segment>/<name>` `errors` | A group or policy name does not match exactly one object. A new resource is not created until it resolves. | Fix the name (exact, case-sensitive), or use `{id: ...}`. See [Access control](../guides/access-control.md). |
| `deferred: rate-limited` on a resource | `errors` on the resource | The tenant throttled a write; later writes in that pass were skipped. | None. The next pass retries. |
| A managed resource is attached to another gateway | `tg.gateway_mismatches`, `corrected: false` | Someone moved an SSH or Kubernetes resource on the tenant. gwops moves web apps back, not those. | Move it back in the Admin Console. |

### Gateway config and process

| Symptom | Where | Cause | Fix |
| --- | --- | --- | --- |
| `rendered config failed validation, keeping previous config: ...` | `last_reconcile.errors`, `spawn.validate_rejected` | The gateway binary refused the candidate config in pre-flight. The last good config keeps running. | Read the reason (the binary's own error) and fix the seed or credential that produced it. |
| `rendered config matches one that was rolled back after a failed start` | `last_reconcile.errors` | This exact config already crashed the gateway on start; gwops will not apply it again. | Fix the seed or credentials that produce it. Any change to the rendered config lifts the block. |
| `render failed: 2 Kubernetes clusters configured ...` | `last_reconcile.errors` | The gateway fronts one Kubernetes cluster only. | Keep one `k8s_clusters` entry; run a second container for another cluster. See [Kubernetes](../guides/kubernetes.md). |
| `cluster '<name>': credential file (bearer_token_file) ... resolves outside the allowed root` | `last_reconcile.errors` | Kubernetes credential files must sit under `/config/k8s-creds/`, as regular files of at most 1 MiB. | Mount them there read-only and point the seed at them. |
| Repeated `gateway.crashed` | gwops log | The gateway keeps exiting; gwops restarts it with backoff up to 60 s. | Check the `gateway.system` events just before the exit (the gateway's own error), `gateway.line` events from stdout and the last pass's errors. |
| `gateway.early_exit_rollback` | gwops log | The gateway exited within 5 s of starting on a new config; gwops restored the last good one. | Fix what the new config changed. |

### Certificates and ACME

| Symptom | Where | Cause | Fix |
| --- | --- | --- | --- |
| Clients reject the gateway certificate for a new upstream | `certs.leaf_state: sans_incomplete` | No pass has re-minted the leaf since the upstream was added, or the last pass failed before minting. | `POST /reconcile` and read `last_reconcile.errors`; `POST /certs/rotate-leaf` forces a new leaf. |
| `public certificate '<name>': <file>: <property>: <reason>` | `last_reconcile.errors`, `certs.public[].state: invalid` | A `source: file` pair was refused. The last good copy keeps serving. | Fix the named property. Write both files before gwops reads them. See [Public certificates from files](../guides/public-certs-files.md). |
| `certs.public[].acme.error_code: dns_propagation` | `/status` | The `_acme-challenge` TXT record was not seen in time. Often a LAN DNS server that serves its own copy of the zone answers NXDOMAIN for the challenge. | Use public resolvers for the container (`dns:` in `compose.yaml`) and pin your internal names with `extra_hosts`, or forward `_acme-challenge.<zone>` to a public resolver. See [Public certificates with ACME](../guides/public-certs-acme.md). |
| `error_code: dns_auth` | `/status` | Cloudflare refused the token. | Check the token file and that the token has `Zone:Read` and `DNS:Edit` on the zone (the alias zone with `challenge_alias`). The hold lifts when the token file changes. |
| `error_code: dns_zone` | `/status` | The zone cannot be found by the token or the resolver. | Check the token's zone scope and DNS resolution. |
| `error_code: rate_limited` | `/status` `certs.public[].acme.retry_after` | Let's Encrypt rate-limited the account. | Wait until `retry_after`. Test with `directory: staging`. |
| `POST /certs/public/<name>/issue` answers `429` | Response `reason` | A backoff, the 24 h force window, or the 60 s request floor holds the certificate. | Wait for the `Retry-After` header. `force` never ends a backoff. |
| `supervisor.acme_cloudflare_environment_ignored` | gwops log | `CF_*` or `CLOUDFLARE_*` variables are in the container environment. lego never receives them. | Remove them. Put the token in the file named by `public_tls.acme.token_file`. |
| `gateway_ca_unbound` on every web app | `web_apps.readiness[].reasons`, `certs.registered_root.bound: false` | Public mode: the gateway is not yet bound to the registered root. The rebind happens only after a pass applies its config successfully. | Fix the pass's local errors; the next pass rebinds. |

### Web apps

| Symptom | Where | Cause | Fix |
| --- | --- | --- | --- |
| `401` on the first request after a change, then works on retry | Browser or client | The gateway applies no leeway to a token's issue time, and its clock is behind the tenant's. | Keep the host clock synced with NTP. |
| `502` from a web app | Browser or client | The gateway cannot reach or verify the upstream: the address does not resolve inside the container, the upstream speaks only TLS 1.2, or verification fails. | Check [name resolution](#name-resolution) first; turn on `web_app_proxy.upstream_tls_probe` and read `web_apps.readiness[].probe`. See [Web-app upstream TLS](../guides/web-apps-upstream-tls.md). |
| `probe:tls12_only` | `web_apps.readiness[].reasons` | The upstream does not offer TLS 1.3, which the gateway requires. | Enable TLS 1.3 on the upstream. |
| `probe:untrusted_issuer` or `probe:hostname` | `web_apps.readiness[].reasons` | The upstream's certificate is from a CA the gateway does not trust, or does not match the address. | Add the CA under `web_app_proxy.upstream_ca_bundles`, or fix the address. |
| `san_missing:<name>` | `web_apps.readiness[].reasons` | The served certificate does not cover the app's address or alias. | `POST /reconcile` (private CA mode), or declare the name in a `public_tls` certificate. |
| `operator_action` | `web_apps.readiness[].reasons`, `web_apps.browser_trust` | Downstream `tls13` with a generated CA: browsers need the CA installed. | Install `/data/pki/x509-ca.crt` in the browsers' trust stores. See [Generated private CAs](../guides/private-ca-generated.md). |
| `422` with `violations` on a web-app write | Admin API response | The web-app policy refused the change; nothing was persisted. | Fix each listed violation. See [Web-app identity](../guides/web-apps-identity.md). |
| `jwks.ok: false` | `/status` `jwks` | The tenant's token-signing key set is unreachable from the container. The gateway needs it to accept tokens. | Allow egress to `https://<network>.<host>/api/v1/jwk/ec`. |

### Recording

| Symptom | Where | Cause | Fix |
| --- | --- | --- | --- |
| No recordings arrive; `shipper.shipping: false` | `/status`, `supervisor.shipper_token_missing` | `GWOPS_RECORDING_TOKEN` was not set when the container started. Lines spool locally. | Set it in `.env`, uncomment it in `compose.yaml`, and `docker compose up -d`. |
| `shipper.mode: disabled` after turning recording on | `/status` | Recording settings are read only at startup. | Restart the container. |
| `shipper.post_rejected` with `status_code: 401` or `403` | gwops log | The receiver refused the token, or the token is empty. | Match the token on both sides. |
| `shipper.post_rejected` with another status | gwops log | The receiver refused the batch. gwops resends the same batch forever. | Fix the receiver; check its body size limit (batches reach 16 MiB). |
| `shipper.post_failed` | gwops log | Connection error or 30 s timeout. | Check egress, DNS, TLS trust and proxy settings for the receiver. |
| `shipper.insecure_transport` at startup | gwops log | `recording.receiver_url` is `http://`. The token and recordings cross the network in cleartext. | Use `https://`. |
| `spool.evicted` | gwops log | The receiver was down long enough to fill the spool; the oldest undelivered recordings were deleted. | Restore the receiver; raise `recording.spool_max_bytes` if outages are expected. |
| SSH audit events missing at the receiver | Receiver | The shipper sends recordings, HTTP audit lines and connection starts only. SSH audit events are dropped. | None; this is the filter's design. Connection starts carry the user and resource. |
| A long SSH session is missing; `too_long` counter rises | `shipper.dropped_lines.too_long` | A whole SSH session can be one line, and lines over 16 MiB are dropped. | None. Keep sessions shorter where recordings must be complete. |

### Admin API

| Symptom | Where | Cause | Fix |
| --- | --- | --- | --- |
| `curl` on the host gets "connection reset" or "empty reply" | Shell | `admin_api.bind` is `127.0.0.1`, which Docker's port publish cannot reach. | Set `admin_api.bind: 0.0.0.0` and restart. |
| `401` with an empty body | Response | Missing, malformed or wrong token. The response never says which. | Check the `Authorization: Bearer` header. |
| `401` on every route, with the right token | `api.admin_token_unset` at startup | `GWOPS_ADMIN_TOKEN` was not set when the container started; the API fails closed. | Set it and recreate the container. |
| `403` `the automation token may only use /upstreams/{kind}/{name}` | Response | The automation token called another route. | Use the admin token for that route. |
| `403` `the automation token may not manage k8s_clusters entries` (or `web_apps`) | Response | Kubernetes is never allowed to the automation token; web apps need the seed opt-in. | See [Automation and CI](../guides/automation-and-ci.md). |
| `409` from upstream and certificate routes | Response, `/status` `state_error` | The effective state does not load. | Fix the seed or remove the bad overlay; the error names the path and layer. |
| `503` on a write | Response | The tenant was unreachable, or `TWINGATE_API_KEY` is unset. Nothing was kept. | Retry once the tenant is reachable. |
| Container turns unhealthy after changing `admin_api.port` or `bind` | `docker compose ps` | The healthcheck reads the new value at once; gwops reads it only at startup. | Restart the container. |
| Container unhealthy behind an outbound proxy, while `/status` shows the gateway `running` | `docker compose ps`, `docker inspect --format '{{json .State.Health}}' <container>` | `HTTP_PROXY` or `HTTPS_PROXY` is set and `NO_PROXY` lacks `127.0.0.1,localhost` (the shipped `compose.yaml` default has them; an override in `.env` can drop them), so the healthcheck's loopback call goes to the proxy. | Add `127.0.0.1,localhost` to `NO_PROXY` and recreate the container. List other hosts by exact name or IP: httpx ignores CIDR entries. See [Restricted egress and outbound proxies](../recipes/restricted-egress.md). |

## Verify

After a fix, run `POST /reconcile` and check that `last_reconcile.ok` is `true` and the error is
gone from `last_reconcile.errors`:

```sh
curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/reconcile | jq '{ok, errors}'
```

## Related

- [Log events reference](../reference/log-events.md)
- [Admin API: `GET /status`](../reference/admin-api.md#get-status)
- [Health and observability](../architecture/health-and-observability.md)
- [Startup and shutdown](../architecture/startup-and-shutdown.md)
- [Monitoring](monitoring.md)
- [Known limitations](../reference/limitations.md)
