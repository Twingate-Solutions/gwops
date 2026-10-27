# Automation and CI

Let software add, change and remove upstreams through the admin API. Two patterns:

- **An unattended caller**, such as a deploy tool's webhook relay creating and removing
  resources as apps come and go, uses the limited **automation token**
  (`GWOPS_AUTOMATION_TOKEN`). It reaches only the upstream routes, only inside the seed's
  allowlists, and only entries it created.
- **A trusted pipeline**, such as CI applying reviewed changes, uses the **admin token**
  (`GWOPS_ADMIN_TOKEN`) to write overlays or upstream entries.

Every write is transactional: gwops validates it, persists it as an overlay, runs a reconcile
pass before it answers, and keeps the change only if every tenant object it touches is
confirmed. Otherwise it rolls the change back and answers with the errors.

## When to use

- Resources should follow application lifecycle events without a person editing the seed.
- A pipeline should apply upstream changes and be able to revert them.

To manage the seed itself from Git, deploy the seed file and let gwops pick it up: it watches
the file and also polls its content every 5 s. Seed changes are not transactional; their
outcome shows in `GET /status` `last_reconcile`.

## Prerequisites

- A working deployment with `GWOPS_ADMIN_TOKEN` set.
- A network path from the caller to the admin API. gwops serves plain HTTP on loopback by
  default; see [Admin API behind a TLS proxy](../operations/admin-api-behind-tls-proxy.md) before you expose
  it to another machine.
- For the automation token: the groups, policies and address ranges the caller may use.

## Steps

### Pattern A: the automation token

**1. Add both allowlists and the automation settings to the seed**

The automation token is refused at startup unless the seed has both
`twingate.access_allowlist` and `twingate.address_allowlist`.

```yaml
twingate:
  network: acme
  host: twingate.com
  remote_network: Production DC
  gateway_address: 10.0.0.20:8443
  access_allowlist:
    groups: ["App Users"]
    security_policies: []            # the caller may not set a policy
  address_allowlist:
    cidrs: ["10.20.0.0/16"]
    dns_suffixes: ["apps.example.com"]
admin_api:
  automation:
    name_prefix: auto-               # every name the token uses must start with this
    web_apps:
      enabled: true                  # default false: every web-app route is 403
      request_header_names: [X-Env]  # header rewrites it may set; empty = none
# ...rest of your seed
```

- `name_prefix` is optional. When set, a name without it is `403`
  (`automation upstream names must start with 'auto-'`).
- `web_apps.enabled` is the opt-in for web apps. Without it, `PUT`, `GET` and `DELETE` on
  `/upstreams/webapp/...` are `403` for the automation token, including `DELETE` of a name that
  does not exist. With it, the token's web-app writes are limited further:
  `upstream_tls: verify_full` only, header rewrites only with names in `request_header_names`
  and never a `{{jwt}}` value, and an address and alias that no seed entry, other entry or
  tenant resource already uses (exact spelling).
- Kubernetes (`k8s`) entries are always `403` for the automation token: they name credential
  files inside the container.
- All of `admin_api` and `twingate` is seed-only. Neither token can change these rules.

[Access control](access-control.md) explains the allowlist rules.

**2. Create the token**

```sh
openssl rand -hex 32
```

Put it in `.env`:

```sh
GWOPS_AUTOMATION_TOKEN=<automation-token>
```

Then uncomment the matching line under `environment:` in `compose.yaml`:

```yaml
      GWOPS_AUTOMATION_TOKEN: ${GWOPS_AUTOMATION_TOKEN:-}
```

Uncomment it only once `.env` holds the value. A variable that is present, even empty, enables
the startup check, so a missing allowlist then aborts startup.

The automation token must differ from the admin token. Startup aborts with
`supervisor.startup_failed` if the two are equal or an allowlist is missing.

**3. Restart**

```sh
docker compose up -d
```

**4. Call the upstream routes**

The automation token can use only `PUT`, `GET` and `DELETE` on `/upstreams/{segment}/{name}`.
Any other route is `403`.

```sh
export AUTOMATION_TOKEN=<automation-token>
```

Create or update an SSH upstream (`PUT` merges by name: fields the body omits keep their stored
value):

```sh
curl -s -X PUT -H "Authorization: Bearer $AUTOMATION_TOKEN" -H "Content-Type: application/json" \
  -d '{"address": "10.20.3.4:22", "access": {"groups": ["App Users"]}}' \
  $BASE/upstreams/ssh/auto-app-42
# 200 {"id": "0005-api-put-ssh-upstreams-auto-app-42", "origin": "automation", "patch": {...}, "reconcile": {...}}
```

Create a web app (needs the web-app opt-in):

```sh
curl -s -X PUT -H "Authorization: Bearer $AUTOMATION_TOKEN" -H "Content-Type: application/json" \
  -d '{"address": "app-42.apps.example.com", "upstream_tls": "verify_full", "request_headers": {"X-Env": "prod"}}' \
  $BASE/upstreams/webapp/auto-app-42
```

Read it back, including its Twingate resource id and last errors:

```sh
curl -s -H "Authorization: Bearer $AUTOMATION_TOKEN" $BASE/upstreams/ssh/auto-app-42
```

Delete it. Deleting a name that does not exist answers `200 {"deleted": false}` and writes
nothing, so a retried webhook is harmless:

```sh
curl -s -X DELETE -H "Authorization: Bearer $AUTOMATION_TOKEN" $BASE/upstreams/ssh/auto-app-99
# 200 {"deleted": false}
```

The token's namespace is the entries it created. A seed entry, or an entry the admin token
created or last edited, is `409`
(`... is owned by admin; the automation token may only change entries it created`). The token
sees only its own entries on `GET`; anything else is `404`.

### Pattern B: a trusted pipeline with the admin token

The admin token can write any upstream kind and whole overlays.

Apply a change as one overlay, and keep its id:

```sh
curl -s --fail-with-body -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"patch": {"ssh_upstreams": [{"name": "ci-runner-1", "address": "10.0.30.11:22"}]}, "comment": "ci runner 1"}' \
  $BASE/overlays
# 201 {"id": "0007-ci-runner-1", "origin": "admin", "comment": "ci runner 1", "patch": {...}, "reconcile": {...}}
```

Remove an entry with a `_delete` patch:

```sh
curl -s --fail-with-body -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"patch": {"ssh_upstreams": [{"name": "ci-runner-1", "_delete": true}]}, "comment": "remove ci runner 1"}' \
  $BASE/overlays
```

Revert an overlay by deleting it. Its effect disappears from the effective state and the next
reconcile, run before the response, applies that:

```sh
curl -s --fail-with-body -X DELETE -H "Authorization: Bearer $TOKEN" $BASE/overlays/0007-ci-runner-1
# 204, no body
```

List overlays in application order:

```sh
curl -s -H "Authorization: Bearer $TOKEN" $BASE/overlays
```

Overlays may set only `ssh_upstreams`, `k8s_clusters`, `web_apps` and `recording`
(`recording.receiver_url` excluded). Everything else is seed-only. The allowlists apply to the
admin token too.

### Handling responses and retries

| Status | Meaning | What to do |
| --- | --- | --- |
| `200`, `201`, `204` | Applied and confirmed on the tenant. | Nothing. |
| `401` | Missing or wrong token. The body is empty. | Fix the token. Do not retry. |
| `403` | Out of scope: route, kind, name prefix, allowlist or web-app field rule. | Fix the request. Do not retry. |
| `404` | Unknown segment or entry. | Check the name. |
| `409` | The entry belongs to someone else, or the effective state does not load. | Do not retry; investigate. |
| `422` | Invalid body, policy refusal, or the change was rolled back. | Read `detail`. Retry only if `errors` shows `deferred: rate-limited`, after a delay. |
| `503` | The tenant was unreachable, or `TWINGATE_API_KEY` is unset. Nothing was kept. | Retry with backoff. |

Writes are serialized: concurrent calls wait for one another. Expect a few seconds per call,
and longer when a change drain-restarts the gateway (a Kubernetes change, for example). Use a
generous client timeout. If a call times out on the client side, the write may still have
completed: `GET` the entry before retrying. A repeated `PUT` with the same body is harmless.

## Verify

- `GET /upstreams/{segment}/{name}` returns `origin: "automation"` for entries the automation
  token created, a `tg_resource_id`, and empty `errors`.
- `GET /state` shows the merged effective state, with `provenance` naming the overlay id that
  set each field.
- Each mutating call writes one `api.audit` log line with `principal`, `method`, `route`,
  `status` and `overlay_id`. Bodies and credentials are never logged.

```sh
docker compose logs --no-log-prefix gateway | grep '"api.audit"'
```

- `GET /status` `web_apps.automation_off_policy` lists automation-owned web apps that no longer
  meet the field rules after a seed change.

## Roll back

- To revoke the automation token, remove it from `.env` and `compose.yaml` and run
  `docker compose up -d`. Entries it created stay; the admin token can change or delete them.
- Narrowing `request_header_names` or turning the web-app opt-in off does not change or delete
  existing automation-owned entries. A `PUT` to one that no longer complies is `403` until it is
  fixed.
- To undo a pipeline change, `DELETE /overlays/{id}` the overlay it created.

## Related

- [Admin API architecture](../architecture/admin-api.md): principals, guardrails and
  transactional writes.
- [Admin API: automation and web apps](../reference/admin-api.md#automation-and-web-apps)
- [Admin API: write semantics](../reference/admin-api.md#write-semantics)
- [Seed reference: `admin_api`](../reference/seed.md#admin_api)
- [Seed reference: `twingate`](../reference/seed.md#twingate)
- [Access control](access-control.md)
