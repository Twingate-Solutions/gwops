# gwops Admin API Reference

This page is the route-by-route reference. For the authentication model, principals,
transactional writes and the audit trail, see [Admin API architecture](../architecture/admin-api.md).

Base URL `http://127.0.0.1:8081` (seed `admin_api.bind` / `admin_api.port`). From the Docker
host this works only with `admin_api.bind: 0.0.0.0`: the default `127.0.0.1` is the container's
own loopback, which `compose.yaml`'s `127.0.0.1:8081:8081` publish cannot reach. Plain HTTP, JSON
request and response bodies, `Authorization: Bearer <token>` on every route except
`GET /healthz`. There is no OpenAPI or docs endpoint. Error `detail` text is not stable: match
on status code and JSON field names.

Examples use:

```sh
export BASE=http://127.0.0.1:8081
export TOKEN=<admin-token>
```

## Authentication

| Token (env var) | Allowed routes |
| --- | --- |
| Admin (`GWOPS_ADMIN_TOKEN`) | All routes |
| Automation (`GWOPS_AUTOMATION_TOKEN`) | `PUT`, `DELETE`, `GET` on `/upstreams/{segment}/{name}`: `ssh`, and `webapp` when the seed opts in ([Automation and web apps](#automation-and-web-apps)). Never `k8s`. |

- Missing, malformed or wrong token: `401`, empty body, `WWW-Authenticate: Bearer`.
- Automation token on any other route or method: `403`.

## Data model

### Overlay

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | `<4-digit counter>-<slug>`, e.g. `0001-add-web-2`. Order of application. |
| `created_at` | string | ISO 8601, UTC. |
| `comment` | string | Free text. |
| `origin` | `"admin"` \| `"automation"` | Credential that wrote it. |
| `patch` | object | The patch applied on top of the seed. |

### Patch rules

- Allowed top-level keys: `ssh_upstreams`, `k8s_clusters`, `web_apps`, `recording`. Anything
  else is `422`; `web_app_proxy` and `public_tls` are seed-only.
- In public mode (the seed has `public_tls`), a patch whose merged state would serve a name that
  is not a DNS name inside a `public_tls` zone, or that no single declared certificate covers, is
  `422` (the error names the entry and field). Declare the name in the seed's `public_tls` first.
- `recording.receiver_url` is not allowed (`422`). `recording.enabled` and
  `recording.spool_max_bytes` are; `spool_max_bytes` below 16777216 (16 MiB) is `422`.
- `ssh_upstreams`, `k8s_clusters` and `web_apps` merge by `name`: a patch entry updates the entry
  with the same name (only the fields given) or adds a new one.
- `{"name": "web-2", "_delete": true}` removes the entry.
- Nested lists, including `access.groups`, are replaced, not merged. So is a web app's
  `request_headers`: a patch's map replaces the stored one (`{}` clears it, `null` makes it
  unmanaged).
- Maximum patch size 256 KiB, maximum nesting depth 32 (`422`).

### Upstream entry fields

`ssh` = `ssh_upstreams` / `/upstreams/ssh/...`; `k8s` = `k8s_clusters` / `/upstreams/k8s/...`;
`webapp` = `web_apps` / `/upstreams/webapp/...`.

| Field | Kind | Type | Required | Description |
| --- | --- | --- | --- | --- |
| `name` | all | string | yes | `[a-z0-9-]{1,63}`. Implied by the path on `PUT`. |
| `address` | all | string | yes | `host` or `host:port`, lowercased. `ssh` default port 22; `webapp` default upstream port 443 (80 when `upstream_tls` is `none`). |
| `port` | `k8s` | integer | no | 1-65535. Default 443. |
| `bearer_token_file` | `k8s` | string | yes | Token file path under `/config/k8s-creds/`. |
| `ca_file` | `k8s` | string | yes | CA file path under `/config/k8s-creds/`. |
| `alias` | `webapp` | string \| null | no | Second client-facing host: concrete host name or IP literal, no `*`, no port, different from the address. On `PUT`, omitted keeps the stored value; `null` clears it. Judged by `twingate.address_allowlist` like `address` (`403`). |
| `upstream_tls` | `webapp` | string | no | `verify_full` (default), `verify_ca`, `insecure`, `none`. |
| `downstream` | `webapp` | object | no | `{"tls": "tls13" \| "none", "port": 1-65535}`. `tls` defaults to `tls13`; `port` to 443 (`tls13`) or 80 (`none`). |
| `request_headers` | `webapp` | object \| null | no | `{name: value}` header rewrites. On `PUT`, omitted keeps the stored value (a new entry starts unmanaged); a given map replaces the stored one; `null` makes the rewrites unmanaged; `{}` is managed, none set. |
| `access` | all | object | no | See [Access](#access). |

The web-app policy also constrains every web-app write, for both tokens: no hop-by-hop, framing,
forwarding or routing-override header names, `Cookie` or `Host`; values are static text or one
`{{key}}` template the gateway supports, never empty and never a static secret; a per-resource
header may not reuse a gateway-wide identity header (`username`, `groups` or `jwt` template);
`upstream_tls` `none` or `insecure` needs the address host in `web_app_proxy.plaintext_upstreams`;
a `{{jwt}}` template in any effective header, gateway-wide or per-resource, is refused for a web
app whose `upstream_tls` is `verify_ca`, `insecure` or `none` unless its upstream host is
`localhost` or a loopback IP. A gateway-wide identity header name (`username`, `groups` or `jwt`
template) with more than 4 `-` or `_` separators is refused when the seed loads, because every
spelling of it is rendered. A write that adds a violation is refused before anything is persisted,
with `422` ([web-app policy refusal body](#422-web-app-policy-refusal-body)).

### Access

`access` is `{"groups": [ref, ...], "security_policy": ref}`. Both keys are optional.

| Ref form | Meaning |
| --- | --- |
| `"Platform Engineers"` | Name. Must match exactly one object. |
| `{"id": "R3JvdXA6MTIz"}` | Explicit id. |
| `{"id": "R3JvdXA6MTIz", "name": "Platform Engineers"}` | Pinned form. Overlay writes store refs in this form. |

- An omitted key falls back to the seed's `twingate.resource_defaults`.
- `groups: []` means no groups.

## Write semantics

`POST /overlays` and `PUT`/`DELETE /upstreams/...` run these steps in order. A failing step
returns its status and nothing is persisted. Steps 3 to 12 and the reconcile run under one
mutation lock, so overlay mutations are serialized.

1. `PUT` body: `422` if it carries `_delete` (`use DELETE to remove an entry`, both tokens) or a
   `name` that differs from the path name.
2. Automation token on `/upstreams/...`, reach: `403` if the kind is not allowed, the kind's
   seed opt-in is off, or the name lacks `admin_api.automation.name_prefix`.
3. Automation token, `PUT` only: the request body is validated by itself, without any stored
   state, and a failure is `422`. An omitted `address` is stood in for, so a partial update is
   judged on the fields it carries. The error text names only fields of the body.
4. Namespace, automation token (`PUT` and `DELETE`): `409` (entry exists and is owned by the seed
   or the admin token). It runs before the body is merged with stored state, so a caller that
   fails it learns nothing about a stored entry from a validation error.
5. Validation of the patch against the full merged state (schema): `422`.
6. Web-app policy, both tokens, when the patch sets a web app (not a `_delete`): `422`
   ([web-app policy refusal body](#422-web-app-policy-refusal-body)). The body lists every
   violation of each web-app entry the write sets, including one the entry already had, and any
   gateway-wide or other-entry violation the candidate state has that the current state does not.
   When the current state does not load, nothing can be compared: the body lists only violations
   on the entries the write sets and gateway-wide ones.
7. Automation field policy, automation token, `PUT` on `webapp` only: `403`
   ([policy refusal body](#403-policy-refusal-body)).
8. Address allowlist (`twingate.address_allowlist`; covers `address` and a web app's `alias`):
   `403`.
9. Access reference pinning: `422` (no match, several matches, unknown id); `503` (no
   `TWINGATE_API_KEY`, or Twingate unreachable).
10. Access allowlist (`twingate.access_allowlist`): `403`; `503` if the allowlist cannot be
    resolved.
11. Address exclusivity, automation token, `PUT` on `webapp` only: `403`
    ([policy refusal body](#403-policy-refusal-body)); `503` if it cannot be decided. The whole
    tenant is listed (paginated) only after step 10 passes, while the mutation lock is held.
12. Persist: `422` (size or depth limit).
13. Reconcile synchronously.

`DELETE /overlays/{id}` (admin token) runs its own check under the same lock. When the overlay's
patch sets `web_apps` entries, the removal is refused with `422` if the resulting state has web-app
policy violations the current state does not
([web-app policy refusal body](#422-web-app-policy-refusal-body)); nothing is removed. Then `404`
(unknown id) or `422` (malformed id), then the reconcile.

If the reconcile does not confirm the change, the overlay is rolled back and the response is
`422`, or `503` if Twingate was unreachable. The body is the
[transactional failure object](#common-error-bodies). A write that passes step 6 can still fail
here under the web-app policy: the pass refuses a state that carries any violation (for example
one a seed edit introduced), records `web-app policy: ...` errors and syncs and renders nothing.
The change is rolled back with `422`, never `503`; `detail.message` reads
`change rolled back: web-app policy refused the change`, and the body also carries a top-level
`violations` list ([web-app policy refusal body](#422-web-app-policy-refusal-body)).

A Twingate write the tenant throttles (HTTP 429) is retried after the server's hint (capped at
60 s, plus jitter). Once one write in a pass has been throttled, the pass skips its remaining
Twingate writes and records `deferred: rate-limited` against each affected resource. A mutation
whose Twingate write is deferred is not confirmed, so its overlay is rolled back and the
response is `422` with that error in `errors` (see the transactional failure object). Deferred
work outside a mutation is retried on the next pass.

Throttle waits within one pass add up to at most 90 s. Once that budget is spent, a throttled
Twingate call fails immediately instead of waiting: a throttled read makes the sync report
Twingate as unreachable (`503` for a mutation), and a throttled write is recorded as that
resource's error (`422`, with `rate-limited` in the message).

## Automation and web apps

The automation token reaches `ssh` entries it owns (see [Write semantics](#write-semantics)). It
reaches `webapp` entries only when the seed opts in and only within the field rules below.

Seed opt-in (read-only seed; not settable through the API):

```yaml
admin_api:
  automation:
    name_prefix: auto-
    web_apps:
      enabled: false              # default; true opts in
      request_header_names: []    # rewrite names the token may set, case-insensitive; empty = none
```

- Opt-in absent or `enabled: false`: `PUT`, `GET` and `DELETE /upstreams/webapp/{name}` return
  `403` `{"detail": "the automation token may not manage web_apps entries"}`, including `DELETE`
  of a name that does not exist. The admin token is unaffected.
- `request_header_names` may not contain a denied or identity header name: startup aborts, and a
  later pass records a local error.
- `web_app_proxy` (gateway-wide headers, CA bundles, plaintext upstreams) is seed-only and cannot
  be written by either token.

**Field rules.** They apply to the effective entry (the stored automation-owned entry merged with
the request body), so omitting a field does not bypass them.

| Field | Automation token | Refused with `403` when |
| --- | --- | --- |
| `name` | allowed | name lacks `name_prefix` |
| `address` | allowed | outside `twingate.address_allowlist`; not exclusive |
| `alias` | allowed, including `null` | outside `twingate.address_allowlist`; not exclusive |
| `upstream_tls` | `verify_full` only | any other value |
| `downstream` | `tls` `tls13` or `none`, any `port` | never |
| `request_headers` | omitted, `null` or `{}` always; otherwise each name must be in `request_header_names` | a name not in the list (or a denied or identity name even if listed); any value using the `jwt` template key |
| `access` | allowed | `twingate.access_allowlist` rules |

**Exclusivity.** The entry's portless, lowercased `address` and `alias` may not equal the address
or alias of any seed entry (of any kind), any other effective entry (any kind and owner), or any
Twingate resource of any type in the tenant other than the one backing this entry. The tenant is
listed at write time. Comparison is exact string equality: a tenant resource with a wildcard or
CIDR address that covers the name, and a different spelling of the same host (a name and its IP),
are not conflicts. A `403` also tells the caller that a tenant resource holds that name, for names
inside `twingate.address_allowlist`.

- `403`: a field-rule or exclusivity violation. The two checks report separately, each listing
  only its own violations.
- `503`: exclusivity cannot be decided (no `TWINGATE_API_KEY`, Twingate unreachable, or an
  incomplete listing). Nothing is persisted.

**Seed narrowing.** Shrinking `request_header_names` or turning the opt-in off does not change,
exclude or delete existing automation-owned entries. A `PUT` to an entry that no longer complies
is `403` until it is fixed. With the opt-in off the token can no longer reach those entries; the
admin token can still change or delete them.

## Endpoints

| Method | Path | Auth | Success |
| --- | --- | --- | --- |
| `GET` | `/healthz` | none | `200` |
| `GET` | `/status` | admin | `200` |
| `GET` | `/state` | admin | `200` |
| `GET` | `/overlays` | admin | `200` |
| `POST` | `/overlays` | admin | `201` |
| `DELETE` | `/overlays/{id}` | admin | `204` |
| `PUT` | `/upstreams/{segment}/{name}` | admin, automation | `200` |
| `DELETE` | `/upstreams/{segment}/{name}` | admin, automation | `200` |
| `GET` | `/upstreams/{segment}/{name}` | admin, automation | `200` |
| `POST` | `/reconcile` | admin | `200` |
| `POST` | `/certs/rotate-leaf` | admin | `200` |
| `POST` | `/certs/rotate-ca` | admin | `200` |
| `POST` | `/certs/public/{name}/issue` | admin | `202` |

`segment` is `ssh`, `k8s` or `webapp`. Timestamps are ISO 8601, UTC.

### ReconcileResult

Returned by `POST /reconcile`, and as `reconcile` in overlay write responses and
`last_reconcile` in `/status`.

| Field | Type | Description |
| --- | --- | --- |
| `ok` | boolean | No errors in the pass. |
| `local_ok` | boolean | No local failure (web-app policy, credentials, CA bundles, certs, render, gateway apply). |
| `trigger` | string | `"api"`, `"api-rollback"`, `"startup"`, `"tick"`, ... |
| `started_at` | string | Pass start time. |
| `actions` | string[] | What the pass did. |
| `errors` | string[] | What went wrong. Web-app policy failures read `web-app policy: <entry and field>`. |

In public mode, a refused certificate reads `public certificate '<name>': <file>: <property>: <reason>`
(never PEM text or key bytes) and an unresolvable root reads `registered root: <reason>`; Twingate-side
failures registering or binding the root read `CA registration: <reason>`. A served name that the
actual leaf SANs of two certificates both match is refused with `served name '<name>' is covered by
certificate '<a>' but the leaf of certificate '<b>' also matches it; ...` and nothing is installed.
The gateway reloads a certificate only when the previous generation's files are deleted. When that
delete fails the pass records a local error (`public certificate '<name>': installed but previous
generation not removed; gateway has not reloaded`, and `leaf certificate: ...` in private CA mode), the
action line reads `... (previous generation not removed; gateway has not reloaded)` instead of
`(gateway hot-reloads)`, and the next pass retries the delete. `actions` include
`installed public certificate '<name>' generation <id> (gateway hot-reloads)`,
`gateway held down until every public certificate is installed`, and
`rebound gateway <id> X.509 CA to registered public root <root> (<ca id>; was <ca id>); the binding is
read back on the next pass`. The rebind is sent only after the pass rendered and applied its config
successfully; otherwise the pass records `deferred rebinding gateway <id> X.509 CA to registered
public root <root> (<ca id>): <reason>`. A recorded root CA id that is no longer on the tenant is
dropped (`forgot recorded X.509 CA <id>: ...`) before a create-bind or rebind and the root is adopted
or registered again.

ACME problems are never part of `errors` and never set `local_ok` to `false`; they are reported
under [`certs.public[].acme`](#certspublicacme) and `certs.public_acme_errors` in `/status`.

`actions` names fields and header names, never header values. A web-app update reads
`updated webapp resource '<name>': <changed fields> (the change re-issues access tokens)`.

### GET /healthz

Response `200` (healthy) or `503` (unhealthy), same body:

```json
{
  "status": "ok",
  "checks": {
    "gateway": {"ok": true, "state": "running"},
    "reconcile": {"ok": true, "last_at": "2026-10-06T14:32:01+00:00"}
  }
}
```

`status` is `"ok"` or `"unhealthy"`. `gateway.state` is one of `stopped`, `starting`,
`running`, `draining`, `backoff`. `reconcile.last_at` is `null` before the first pass.

```sh
curl -s $BASE/healthz
```

### GET /status

| Field | Type | Description |
| --- | --- | --- |
| `process.state` | string | Gateway state, as in `/healthz`. |
| `process.returncode` | integer \| null | Last exit code. |
| `capabilities.gateway_version` | string | The wrapped gateway version baked into the image (`GWOPS_GATEWAY_VERSION`). Reported, never enforced; empty outside the built image. `capabilities` is `{"gateway_version": "<string>"}`. |
| `last_reconcile` | ReconcileResult \| null | Last pass. |
| `certs.x509_ca_not_after` | string \| null | CA expiry. `null` in public mode. |
| `certs.leaf_not_after` | string \| null | Leaf expiry; `null` if none minted and in public mode. |
| `certs.leaf_state` | string \| null | `null` in public mode (the leaf is never read). Otherwise `ok`, `missing`, `expiring`, `sans_incomplete`, `sans_extra`, `invalid`. `sans_extra`: the leaf carries SANs beyond the required set. `invalid` includes a leaf whose bundled CA is not the active X.509 CA. |
| `certs.public` | object[] | Public mode only; absent in private CA mode. One entry per declared `public_tls` certificate, in seed order: `{"name", "names": string[], "not_after": string \| null, "state": "ok" \| "expiring" \| "invalid" \| "pending", "last_error": string \| null, "generation": string \| null}`, plus `"acme": object` on `source: acme` entries (see [`certs.public[].acme`](#certspublicacme)). `not_after` and `generation` describe the material currently served (the last good install). Both are `null` until the first install; `generation` is also `null` after a restart whose first pass fails, because the store exposes no read of the current generation (serving is unaffected). `expiring`: less than a third of the lifetime remains. `invalid`: the last pass refused the certificate's files, or installed it without being able to delete the previous generation (the gateway has not reloaded); `last_error` names the certificate and file (never contents) and the last good copy keeps serving. `pending`: the certificate validated but was not installed this pass because another certificate failed (installs are all-or-nothing); `last_error` is `not installed: another certificate failed validation`, and `generation` and `not_after` are those of the copy still served, or `null` when nothing was ever installed. A `source: acme` certificate with nothing valid installed has `generation` and `not_after` `null` and is not rendered. It is `pending` with `last_error` `null` when nothing has been issued yet (and always with `directory: staging`, which never installs), or with `last_error` `awaiting reissue for changed names` when the installed leaf's SANs differ from the declared `names`. It is `invalid`, with the validator's refusal as `last_error`, when the pair the store holds was refused or could not be read. `[]` before the first pass. |
| `certs.public_acme_errors` | object[] | Public mode only; absent in private CA mode. ACME problems that name no certificate and are not `config` problems: `{"code": string, "detail": string}`, where `code` is an [error code](#certspublicacme) (in practice `internal`) and `detail` says what: the runner is unavailable (with why it could not be built), its `state.json` is unusable, or its task is not running. `config` problems (an unusable DNS token file or ACME configuration) are in `config_error` on each certificate's `acme` entry. `[]` when none. |
| `certs.registered_root` | object | Public mode only; absent in private CA mode. `{"name": string, "sha256": string, "tg_ca_id": string \| null, "bound": bool \| null}`: the configured public root, its SHA-256 fingerprint (lowercase hex), the tenant CA object for it, and whether the gateway's X.509 CA is that root. `tg_ca_id` and `bound` are `null` while unknown (before the first pass, no API key, or a Twingate-side failure). `bound` is also `null` in the pass that sent a rebind: it is read back, never assumed, on the next pass. |
| `certs` (degraded) | object | If the block cannot be built it is `{"computation_failed": true, "error_type": string}` (the exception class name) and `/status` still answers `200`. |
| `tg.configured` | boolean | `TWINGATE_API_KEY` is set. |
| `tg.attempted` | boolean | The last pass reached the Twingate sync step. `false` when `TWINGATE_API_KEY` is unset, before the first pass, or when the pass stopped earlier (the effective state failed to load, or the web-app policy refused it). A sync that was reached but skipped itself (no gateway resolved yet) still counts as attempted. |
| `tg.ok` | boolean \| null | `null` when Twingate is configured and the last pass stopped before the sync step (`tg.attempted` is `false`). Otherwise `true` when Twingate is configured, a pass has run and it had no Twingate sync errors; `false` if not. |
| `tg.errors` | string[] | Twingate sync errors from the last pass. |
| `tg.gateway_mismatches` | object | Managed resources of every kind that the tenant attaches to a gateway other than gwops' own, keyed `<kind>/<name>`: `{"remote_gateway_id": string, "corrected": bool}`. `corrected` is `true` only when the pass moved the resource back (web apps); SSH and Kubernetes resources are never reassigned, so a mismatch stays reported until fixed on the tenant. Report-only: never an error. `{}` when none, or when the last pass did not list the tenant. |
| `web_apps` | object | See [`web_apps`](#web_apps). |
| `tls` | object | `{"mode": "static" \| "static+on_demand" \| "public", "warning": string \| null}`. `mode` is `public` when the seed has a `public_tls` block. `warning` is `null` unless the seed sets `ca.x509.on_demand_issuance` (and always `null` in public mode); then it states that a client presenting any SNI to `:8443` receives a certificate for that name signed by the gwops X.509 CA (the client never receives the CA key), and that the exposure is the gateway loading the CA private key and using it before the access token is authenticated, on a path anyone who can reach `:8443` can trigger. It adds that such a certificate would be browser-trusted for any name when the CA is gwops-generated and a web app uses downstream `tls13`, and that a bring-your-own CA is typically already trusted by devices. The startup and mode-change log lines carry the same text. If the block cannot be built it is `{"mode": null, "warning": null, "computation_failed": true, "error_type": string}`; `error_type` is `StateUnavailable` when the effective state fails to load (see `state_error`), otherwise the exception class name. |
| `jwks` | object \| null | Reachability of the tenant's token-signing key set (`https://<network>.<host>/api/v1/jwk/ec`): `{"ok": bool, "checked_at": string, "error_class": "unreachable" \| "degraded" \| "invalid" \| "internal_error" \| null, "reason": string \| null}`. `null` before the first check, and when no monitor is wired (its HTTP client could not be built at startup). Checked at startup and then every `GWOPS_RECONCILE_TICK_SECONDS`, one check at a time. `unreachable`: DNS, refused connection, TLS verification, a proxy refusal or `407`, or any non-`200` below `500`. `degraded`: timeout, other transport error or `5xx`. `invalid`: `200` but not a usable key set (not JSON, no `keys`, or a key that is not EC P-256 with a `kid`). `internal_error`: the check itself raised unexpectedly. `reason` is `null` except when a caller recorded the failure: `check_timeout` (with `degraded`) when a check outlasted its 30 s bound. Never affects `/healthz` or a reconcile pass. |
| `housekeeping.errors` | string[] | Failed cleanup steps of the last pass (garbage collection of credential and CA-bundle copies, legacy credential directory removal, removal of the pre-store `leaf.crt` / `leaf.key`). Exception text is never included; never part of `last_reconcile.errors`. A pass that did not run housekeeping carries the previous pass's errors. |
| `housekeeping.ran` | boolean | The last pass ran garbage collection and legacy cleanup. That happens only after a pass whose local steps all succeeded and that had upstreams to apply. `false` before the first pass. |
| `shipper` | object | `{"mode": "disabled"}` when `recording.enabled` is false; otherwise the spool block described under [`shipper`](#shipper). |
| `state_error` | string \| null | Set when the effective state fails to load. |

```sh
curl -s -H "Authorization: Bearer $TOKEN" $BASE/status
```

#### `shipper`

With recording on (`mode: "spool"`), gwops keeps only the gateway's audit and session lines and
delivers them to the recording receiver ([recording wire format](recording-wire-format.md)); every other stderr line is dropped and counted. Counts are since
process start and never include line content. Never affects `/healthz` or a reconcile pass.

| Field | Type | Description |
| --- | --- | --- |
| `mode` | string | `spool`. |
| `shipping` | boolean | `false` when `GWOPS_RECORDING_TOKEN` is not set: lines spool locally until a restart supplies it. |
| `pending_lines` | integer | Lines spooled and not yet acknowledged by the recording receiver. |
| `pending_bytes` | integer | Bytes on disk beyond the committed cursor. |
| `dropped_lines` | object | Lines not shipped, by reason: `not_json` (not a JSON object; includes Go standard-library lines and lines that are not valid UTF-8), `not_allowlisted` (JSON, but not a recording, HTTP audit or `Authenticated connection` line), `too_long` (over 16 MiB; dropped whole, never in part) and `spool_failed` (a kept line lost to a failed spool write or flush). All four keys are always present. |
| `enrich_failed` | integer | Kept web-app `Authenticated connection` lines shipped without the `gwops` object because adding it raised. |
| `enrichment` | object | State of the web-app index that feeds the `gwops` object: `active` (boolean, `true` once a tenant listing has been applied; before that the lines get `"match": "none"`), `last_update_at` (string \| null, when the index was last rebuilt from a listing) and `apps` (integer, web apps bound to this gateway that the index holds). A pass that does not list the tenant keeps the previous index, so `last_update_at` stops advancing. |
| `last_success_at` | string \| null | Time of the last acknowledged POST; `null` when none yet or when `shipping` is `false`. |

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

Every 300 s, if a count changed, gwops also logs `shipper.lines_dropped` with the counts and
`enrich_failed`, and logs it once more at shutdown.

#### `certs.public[].acme`

Present on every `certs.public` entry whose seed `source` is `acme`; absent on `source: file`
entries. Built on every request from the ACME runner's snapshot and the last pass. Read-only: it
never affects `/healthz` or a reconcile pass. The entry's own `state` is `pending` (or `invalid`
for refused or unreadable installed material), with `generation` and `not_after` `null`, while
nothing valid is installed.

| Field | Type | Description |
| --- | --- | --- |
| `state` | string \| null | `idle`: nothing to do until the next check. `scheduled`: an admin request is queued, or the certificate is due and waiting its turn. `issuing`: lego is running for it. `backoff`: held until `next_attempt_at` (a failure, a rate limit, the failed-validation limiter, or an interrupted run). `failed`: the last attempt failed and its backoff has elapsed, so the next attempt is due. `dry_run_ok`: staging only, the last dry run issued and validated; the material is never installed. `null` when the runner holds no entry for the certificate and no `config_error` is set. |
| `directory` | string \| null | The ACME directory URL in use (`staging` and `production` appear as the Let's Encrypt URLs). |
| `staging` | boolean \| null | `true` when the seed's `directory` is `staging` or the explicit URL of Let's Encrypt's staging directory: a dry run that installs nothing. Any other explicit `https://` URL is not `staging`. |
| `installed` | boolean | The public store holds a pair for this certificate. Staging never installs, so this is `false` with `staging` unless production material installed earlier is still serving. |
| `installed_at` | string \| null | When the pair now installed was installed. |
| `installed_serial` | string \| null | Serial of the installed leaf, lowercase hex. |
| `last_attempt_at` | string \| null | When lego last started for this certificate. |
| `last_success_at` | string \| null | The last clean lego exit: an install, a run that was not yet due, or a staging dry run. |
| `next_attempt_at` | string \| null | Earliest time lego may start next (the present when it is due now). After a clean run, the next check, 12 h later with up to 1 h of jitter either way. |
| `error_code` | string \| null | Class of the last failure, until a run succeeds. See below. |
| `error_excerpt` | string \| null | A bounded (at most 512 characters), redacted excerpt of lego's output for that failure. Never the DNS token. |
| `renewal_reason` | string \| null | Why the last attempt started: `forced` or `requested` (this route), `missing` (including installed material the reconciler found refused, unreadable or not matching the declared names), `names_changed`, `directory_changed`, `check_interval` (the 12 h check) or `retry` (the backoff ended). |
| `consecutive_failures` | integer | Failures in a row; resets on a clean run. The backoff after the nth is 15 min × 2^(n−1), at most 24 h. |
| `in_backoff` | boolean | A hold is in force: `POST /certs/public/{name}/issue` would answer `429`. |
| `retry_after` | string \| null | While a `rate_limited` hold runs, when it ends. |
| `last_crash` | string \| null | A bounded, redacted excerpt of the last unexpected exception in the runner's own attempt code for this certificate. Kept in memory (lost on restart) and cleared by a clean attempt. While it is the only error, `error_code` is `internal`. Repeated crashes hold the certificate for 15 min, doubling up to 24 h. |
| `permissions_problem` | string \| null | Runner-wide, repeated on each entry: path-only text when a lego storage directory or file could not be restricted to its owner (`0700` directories, `0600` files). `null` when none. |
| `task_dead` | boolean | Runner-wide, repeated on each entry: the runner's loop ended other than by shutdown, so nothing is scheduled. The same condition is in `certs.public_acme_errors`. |
| `state_error` | string \| null | Runner-wide, repeated on each entry: why `state.json` is unusable. Issuance is refused (this route answers `409`) until it is repaired. |
| `config_error` | string \| null | Runner-wide, repeated on each entry: the DNS token file is missing, empty, not a regular file or resolves outside `/config/acme`, or the ACME configuration is unusable. lego does not run while it is set. |

`error_code` is one of:

| Code | Meaning |
| --- | --- |
| `rate_limited` | The CA rate-limited the request. The next attempt waits at least 1 h, and until the time in the CA's `retry after` clause when there is one. |
| `dns_auth` | Cloudflare refused the request or the DNS token (400, 401 or 403). Check the token file and that the token has `Zone:Read` and `DNS:Edit` (on the alias zone when the certificate uses `challenge_alias`). |
| `dns_zone` | The Cloudflare zone cannot be found: the token cannot see it, or the resolver cannot look up its SOA record. |
| `dns_propagation` | The `_acme-challenge` TXT record was not seen in time. |
| `unauthorized` | The CA's validation failed (also its `dns`, `caa` and `connection` problems). Counts toward the CA's failed-validation limit. |
| `acme_unreachable` | The ACME directory or API cannot be reached, answered 5xx or failed TLS; the CA answered `badNonce` or `serverInternal`; or Cloudflare answered 429 or 5xx or could not be reached. Transient: retried with backoff. |
| `timeout` | lego did not finish within `GWOPS_LEGO_TIMEOUT_SECONDS` and was killed. |
| `invalid_output` | lego exited 0, but its certificate or key failed validation (or could not be read) and nothing was installed. |
| `config` | A lego usage, credentials, terms-of-service or read-only-filesystem error; an ACME problem only a configuration change fixes (`invalidContact`, `rejectedIdentifier`, `malformed`, `accountDoesNotExist`, `userActionRequired`); lego could not be started; or the DNS token file is unusable. |
| `internal` | Anything else, including a failed install into the store, an unusable `state.json`, an unexpected exception in the runner (`last_crash`), and a clean lego run after which the certificate was still due (`lego exited 0 but the certificate is still due`). |

Failures of class `config`, `dns_auth` and `dns_zone` can be fixed by the operator: when the
certificate's ACME configuration or the token file changes, the backoff is cleared and the next
attempt starts without waiting.

Staging entry after a successful dry run, with nothing installed:

```json
{
  "name": "wildcard",
  "names": ["*.example.com"],
  "not_after": null,
  "state": "pending",
  "last_error": null,
  "generation": null,
  "acme": {
    "state": "dry_run_ok",
    "directory": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "staging": true,
    "installed": false,
    "installed_at": null,
    "installed_serial": null,
    "last_attempt_at": "2026-10-20T12:34:56+00:00",
    "last_success_at": "2026-10-20T12:36:41+00:00",
    "next_attempt_at": "2026-10-21T00:12:09+00:00",
    "error_code": null,
    "error_excerpt": null,
    "renewal_reason": "missing",
    "consecutive_failures": 0,
    "in_backoff": false,
    "retry_after": null,
    "last_crash": null,
    "permissions_problem": null,
    "task_dead": false,
    "state_error": null,
    "config_error": null
  }
}
```

Production entry whose first attempt failed and is in backoff:

```json
{
  "name": "wildcard",
  "names": ["*.example.com"],
  "not_after": null,
  "state": "pending",
  "last_error": null,
  "generation": null,
  "acme": {
    "state": "backoff",
    "directory": "https://acme-v02.api.letsencrypt.org/directory",
    "staging": false,
    "installed": false,
    "installed_at": null,
    "installed_serial": null,
    "last_attempt_at": "2026-10-20T12:34:56+00:00",
    "last_success_at": null,
    "next_attempt_at": "2026-10-20T12:49:56+00:00",
    "error_code": "dns_propagation",
    "error_excerpt": "dns01: time limit exceeded: last error: recursive nameservers: NS 127.0.0.11:53 did not return the expected TXT record",
    "renewal_reason": "missing",
    "consecutive_failures": 1,
    "in_backoff": true,
    "retry_after": null,
    "last_crash": null,
    "permissions_problem": null,
    "task_dead": false,
    "state_error": null,
    "config_error": null
  }
}
```

When the runner holds no entry for the certificate (no runner, an unusable DNS token file, or the
runner has not been configured yet), `acme` carries the same keys, with the seed's `directory` and
`staging`, `installed` from the entry's own `generation`, and `null` history fields. Its `state` is
`failed` with `error_code` `internal` when the runner is unavailable (`error_excerpt` says why it
could not be built), `failed` with `error_code` `config` while `config_error` is set, and `null`
otherwise. If the runner's snapshot cannot be taken, `acme` carries the same keys with `state`
`failed`, `error_code` `internal`, an `error_excerpt` naming the exception type, and
`"computation_failed": true` with `"error_type": string`.

#### `web_apps`

Built on every request from the last pass's tenant listing and the effective state. Read-only: no
part of it can fail a pass or `/healthz`, and a part that cannot be built degrades instead of
failing `/status`: the readiness entries become `computation_failed`, or, if the whole block
fails, `counts`, `unmanaged` and `unserved` are `null`, `readiness_status` is `computation_failed`
and the block carries `computation_failed: true` and an `error_type` (the exception class name).
Fields that come from the tenant listing are `null` when the last pass did not list the
tenant (no Twingate API key, an unresolved gateway, a failed listing, a listing whose web-app
snapshot failed, or a pass that stopped before the sync).

| Field | Type | Description |
| --- | --- | --- |
| `counts` | object | `declared` (entries in the effective state), `managed_on_tenant` (web apps gwops owns, on any gateway) and `unmanaged_on_this_gateway`. The last two are `null` when the tenant was not listed. |
| `warnings` | string[] | Allowed settings that weaken security, from the last pass: upstream `verify_ca`, `insecure` or `none`, and downstream `none`. Each of those names the entry, never a value. One further warning names no entry: when the tenant listing was read but its web-app snapshot failed, the pass adds `web-app snapshot of the tenant listing failed (<error_type>); web-app status is unavailable until a later pass succeeds`, where `<error_type>` is the exception class name. When updating the recording enrichment index from the listing fails, the pass adds `web-app enrichment index update failed (<error_type>); gateway lines are enriched from the last successful listing`. |
| `browser_trust` | string \| null | A note when the X.509 CA is gwops-generated and a declared web app uses downstream `tls13`: browsers trust the app only after the operator installs that CA. Otherwise `null`, always in public mode. |
| `unmanaged` | object[] \| null | Web apps attached to this gateway that gwops does not own: `{"name", "id", "flags"}`. `flags` may hold `trusted_name_rewrite` (a rewrite sets a gateway-wide identity header name), `invalid_rewrite` (a rewrite sets a denied header name) and `plaintext_mode` (upstream or downstream `none`). `null` when the tenant was not listed. |
| `unserved` | object[] \| null | `{"name", "id"}` of every web app attached to this gateway while the effective state declares none; `[]` otherwise. The gateway serves them with 2.0 TLS enforcement, so each needs a readiness check. `null` when the tenant was not listed. |
| `automation_off_policy` | object | `{"entries": [...], "computation_failed": bool, "error_type"?: string}`. `entries` holds the automation-owned entries whose effective state fails the current automation field policy: `{"name", "violations": [{"field", "reason"}]}`. Report-only; a seed change can cause it ([Seed narrowing](#automation-and-web-apps)). `computation_failed` is `true` (with `error_type`) when the check could not run; `entries` is then empty. `error_type` is `StateUnavailable` when the effective state fails to load (see `state_error`), otherwise the exception class name. |
| `readiness_status` | string | `ok`: `readiness` was computed. `tenant_unlisted`: the last pass did not list the tenant, so `readiness` is `[]`. `computation_failed`: the computation failed, the effective state does not load, or the pass listed the tenant but could not build its web-app snapshot (the pass itself still succeeds); `error_type` is then present beside it. `readiness` holds `computation_failed` entries for the declared apps when the computation failed, and is `[]` when the effective state does not load or the snapshot failed. |
| `readiness` | object[] | One entry per web app on this gateway, managed or not, plus managed apps with a gateway mismatch and declared apps the tenant listing does not hold. See below. |

**`readiness` entry:** `name`, `id`, `managed`, `upstream_tls`, `downstream_tls`, `state`,
`reasons` and `probe`. `id` is `null` for a declared app the tenant does not hold.

- `state`: `action_required` (something stands between the app and a working session) if any
  reason needs action; else `unverifiable` (gwops cannot decide) if any reason is unverifiable;
  else `ready`. Informational reasons never leave `ready`.
- `reasons`: strings of the form `<code>` or `<code>:<detail>`.

| Code | Meaning | State |
| --- | --- | --- |
| `san_missing:<name>` | The leaf lacks the address or alias `<name>`, and on-demand issuance does not cover it (it is off, or `<name>` is an IP). In public mode: no declared `public_tls` certificate covers `<name>`. | `action_required` |
| `covered_on_demand:<name>` | The leaf lacks `<name>`, but on-demand issuance covers it. | informational |
| `on_demand_unavailable:<name>` | On-demand issuance would cover `<name>`, but the last pass's local steps failed. | `action_required` |
| `leaf_unreadable` | The current leaf cannot be read, so names cannot be checked. | `unverifiable` |
| `operator_action` | Downstream `tls13` with a gwops-generated CA: the CA must be installed in browser trust stores. Never reported in public mode. | informational |
| `byo_ca` | Downstream `tls13` with a bring-your-own CA: browser trust is the operator's. Never reported in public mode. | informational |
| `public_cert_invalid:<cert>` | Public mode: certificate `<cert>`, which covers the app's address or alias, was refused by the last pass (the last good copy, if any, keeps serving), or validated but was never installed because another certificate failed (state `pending` with no generation). For a `source: acme` certificate it means the material installed in the store was refused by the validator or could not be read; it is not rendered, and the runner reissues it. | `action_required` |
| `public_cert_expiring:<cert>` | Public mode: certificate `<cert>`, which covers the app's address or alias, has less than a third of its lifetime left. | informational |
| `public_cert_pending:<cert>` | Public mode: the `source: acme` certificate `<cert>`, which covers the app's address or alias, has nothing valid installed (not issued yet, `directory: staging`, which never installs, or awaiting reissue because its `names` changed). The names it covers are served by no certificate meanwhile. | `action_required` |
| `acme_staging_dry_run:<cert>` | Public mode: the `source: acme` certificate `<cert>`, which covers the app's address or alias, uses a staging ACME directory. Staging is a dry run that never installs or serves a certificate; set `public_tls.acme.directory: production` to serve. | `action_required` |
| `acme_failed:<code>` | Public mode: the last ACME attempt for the `source: acme` certificate `<cert>` covering the app's address or alias failed with the [error code](#certspublicacme) `<code>`. `acme_failed:config` is also reported while the DNS token file or the ACME configuration is unusable. `acme_failed:internal` is also reported when the ACME runner is unavailable, its task died, its `state.json` is unusable or its snapshot could not be taken. | `action_required` |
| `acme_backoff` | Public mode: such a certificate is held back until its `next_attempt_at` (a failure, a rate limit or an interrupted run). | informational |
| `gateway_ca_unbound` | Public mode: the gateway is not bound to the registered public root. Reported on every app. | `action_required` |
| `plaintext_upstreams` | Upstream `none` or `insecure` for a host outside `web_app_proxy.plaintext_upstreams`. | `action_required` |
| `unmanaged` | On this gateway, not declared in the effective state. | `action_required` |
| `unserved` | On this gateway while the effective state declares no web apps. | `action_required` |
| `gateway_mismatch` | A managed app still attached to another gateway after the pass. | `action_required` |
| `not_on_tenant` | Declared in the effective state, absent from the tenant listing. | `action_required` |
| `wildcard_address` | A wildcard address cannot be matched against the leaf. | `unverifiable` |
| `computation_failed` | The readiness computation or the probe merge failed; check the logs. | `unverifiable` |
| `probe:<outcome>` | The upstream TLS probe ended with an outcome other than `ok`. | `action_required` |
| `probe_ca_unusable` | An `upstream_ca_bundles` copy could not be loaded, so the probe cannot judge a certificate failure. | `action_required` |
| `probe_unverifiable` | The probe is on and may not dial this app's address. | `unverifiable` |
| `probe_refused_address` | The probe is on and the app's name resolves to an address it never dials. | `unverifiable` |
| `probe_error:<type>` | The probe, or its whole batch, raised `<type>` (an exception class name). | `unverifiable` |
| `probe_pending` | The probe is on and has no result for this app yet. | informational |

`probe` is `null` unless the upstream TLS probe has a result for the app. It is the opt-in
handshake probe (`web_app_proxy.upstream_tls_probe: true` in the seed): after each pass, in the
background, a TLS 1.3-minimum handshake from gwops to the upstream of every web app whose
`upstream_tls` is `verify_full` or `verify_ca`, then close; no request is sent. A batch started
while the previous one is still running is dropped. A pass whose CA bundle step failed starts no
batch and the previous results stay (the bundles are missing, so private-CA upstreams would read as
untrusted); gwops logs `reconcile.probe_skipped` once per run of such passes.

- **Targets.** The declared entries, dialled on their own upstream port, and unmanaged apps on this
  gateway whose address is inside `twingate.address_allowlist`, dialled on the upstream port the
  tenant reports for the app. Any other unmanaged address (outside the allowlist, no allowlist, or
  a wildcard) is `probe_unverifiable` and never resolved or dialled. Each distinct upstream (host,
  port, mode and trust) is dialled once per batch, and its result is recorded for every app that
  shares it. Results are keyed by the app's tenant resource id (its name until the app exists on
  the tenant).
- **Addresses.** A name is resolved first, on a small dedicated thread pool. If any result is a
  loopback, link-local (including `169.254.169.254`), unspecified, multicast or `0.0.0.0/8`
  address, or `fd00:ec2::254` or `100.100.100.200`, the app is `probe_refused_address` and nothing
  is dialled. An IPv6 address that embeds an IPv4 address (IPv4-mapped, `::/96`,
  `::ffff:0:0:0/96`, `64:ff9b::/96`, `2002::/16`) is judged by the embedded IPv4 address. Private
  and unique-local addresses are dialled. Otherwise the probe dials the first resolved IP with the name as the TLS
  server name.
- **Trust.** The system roots plus the validated `upstream_ca_bundles`; the hostname is checked for
  `verify_full` only.
- **Limits.** At most 4 handshakes run at once, each with a 5 s timeout. The probe dials directly
  and ignores `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`, so its result is advisory where the
  gateway reaches the upstream another way.
- **The flag** is read from the effective state on every pass: a change takes effect on the next
  pass with no restart, and turning it off discards all results.

```json
{"outcome": "untrusted_issuer", "checked_at": "2026-10-07T09:14:02+00:00", "target": "grafana.apps.example.com:3000", "error_type": "SSLCertVerificationError", "verify_code": 20}
```

`probe` fields: `outcome`, `checked_at`, `target` (`host:port`), `error_type` (the exception class
name behind a non-`ok` outcome, else `null`) and `verify_code` (the OpenSSL verification error
number of a certificate failure, else `null`). `outcome` is `ok`, `untrusted_issuer`, `hostname`
(`verify_full` only), `tls12_only`, `unreachable` (refused, no route, timeout or any other
failure) or `ca_unusable` (an untrusted-issuer failure while a CA bundle copy could not be loaded).

### GET /state

```json
{
  "state": {"ssh_upstreams": [{"name": "web-1", "address": "10.0.10.5:22"}]},
  "provenance": {"ssh_upstreams.web-1.address": "seed"}
}
```

`state` is the merged seed and overlays, secret values redacted. `provenance` maps dotted paths
(list entries addressed by `name`) to `"seed"` or the overlay id that last set the path.
Errors: `500` if the state fails to load.

```sh
curl -s -H "Authorization: Bearer $TOKEN" $BASE/state
```

### GET /overlays

Response: array of [Overlay](#overlay), in application order.

```sh
curl -s -H "Authorization: Bearer $TOKEN" $BASE/overlays
```

### POST /overlays

Request:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `patch` | object | yes | See [Patch rules](#patch-rules). |
| `comment` | string | no | Default `""`. Slugged into the overlay id. |

Response `201`: the Overlay plus `reconcile` (ReconcileResult).
Errors: `403`, `422`, `503` per [Write semantics](#write-semantics).

```sh
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"patch": {"ssh_upstreams": [{"name": "web-2", "address": "10.0.10.6:22"}]}, "comment": "add web-2"}' \
  $BASE/overlays
```

### DELETE /overlays/{id}

`id` matches `^\d{4}-[a-z0-9-]+$`. Response `204`, no body.
Errors: `404` (unknown id), `422` (malformed id; the removal would add web-app policy violations,
see [Write semantics](#write-semantics); or rolled back), `503` (rolled back).

```sh
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" $BASE/overlays/0001-add-web-2
```

### PUT /upstreams/{segment}/{name}

Request: the [upstream entry fields](#upstream-entry-fields) for the segment, without `name`. If
`name` is sent it must equal the path name. `PUT` merges by name: a field the body omits keeps the
stored value, except that a `request_headers` map replaces the stored map wholesale (a header the
body omits is removed). A body may not carry `_delete`; use `DELETE`.

Response `200`: the Overlay plus `reconcile`.
Errors: `403`, `404` (unknown segment), `409`, `422`, `503` per
[Write semantics](#write-semantics). Automation token: `403` for `k8s`, and for `webapp` unless
the seed opts in ([Automation and web apps](#automation-and-web-apps)).

```sh
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"address": "10.0.10.5:22"}' $BASE/upstreams/ssh/web-1
```

### DELETE /upstreams/{segment}/{name}

Response `200`: the Overlay plus `reconcile` and `"deleted": true`. Automation token and entry
does not exist: `{"deleted": false}`, nothing written.
Errors: `403`, `404` (unknown segment; admin token and entry does not exist), `409`, `422`,
`503`.

```sh
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" $BASE/upstreams/ssh/web-1
```

### GET /upstreams/{segment}/{name}

| Field | Type | Description |
| --- | --- | --- |
| `kind` | string | `"ssh"`, `"kubernetes"` or `"webapp"`. |
| `name` | string | Entry name. |
| `origin` | string | `"seed"`, `"admin"` or `"automation"`. |
| `address` | string | Declared address. |
| `declared_access` | object \| null | The entry's own `access`, as stored. |
| `effective_access.groups` | array \| null | Group refs after seed defaults; `null` if not managed. |
| `effective_access.security_policy` | object \| null | Policy ref after seed defaults. |
| `tg_resource_id` | string \| null | Twingate resource id; `null` if not synced. |
| `applied_access.groups` | string[] | Group ids last applied. |
| `applied_access.security_policy` | string \| null | Policy id last applied. |
| `last_reconcile_at` | string \| null | Last pass time. |
| `errors` | string[] | This resource's errors from the last pass. Can contain `deferred: rate-limited`: a Twingate write for this resource was skipped because an earlier write in that pass was throttled; the next pass retries it. |
| `gateway_mismatch` | object \| null | Every kind. `{"remote_gateway_id": string, "corrected": bool}` when the last pass found the resource attached to another gateway; `null` otherwise. Report-only: an uncorrected SSH or Kubernetes mismatch is not a resource error. |

`webapp` entries add:

| Field | Type | Description |
| --- | --- | --- |
| `alias` | string \| null | Second client-facing host. |
| `upstream_tls` | string | `verify_full`, `verify_ca`, `insecure` or `none`. |
| `downstream` | object | `{"tls": "tls13" \| "none", "port": integer}`; `port` is the effective port. |
| `request_headers` | object \| null | Per-resource header rewrites, `{name: value}`; `null` when unmanaged. Templates and static text are returned as stored. The value under a secret-looking name (for example `Authorization`) is `"[REDACTED]"`. |
| `warnings` | string[] | Allowed settings of this entry that weaken security (upstream `verify_ca`, `insecure` or `none`; downstream `none`). |
| `automation_policy_violations` | object[] | Automation-owned entries only: `{"field", "reason"}` for each field the current automation field policy would refuse for the stored entry. Report-only; `[]` when compliant. |

Errors: `404` (unknown segment, or no such entry; automation token sees only entries it
created), `409` (state fails to load), `403` (automation token: `k8s`, or `webapp` without the
seed opt-in).

```sh
curl -s -H "Authorization: Bearer $TOKEN" $BASE/upstreams/ssh/web-1
curl -s -H "Authorization: Bearer $TOKEN" $BASE/upstreams/webapp/grafana
```

### POST /reconcile

No request body. Response `200`: ReconcileResult.

```sh
curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/reconcile
```

### POST /certs/rotate-leaf

No request body. Response `200`:

```json
{"minted": true, "sans": ["10.0.10.5"], "not_after": "2026-11-05T00:00:00+00:00"}
```

Errors: `409` (no upstreams configured; or public mode: `public certificate mode (public_tls): gwops does not mint or rotate the leaf`, checked first), `500` (mint failed).

```sh
curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/certs/rotate-leaf
```

### POST /certs/rotate-ca

Request: `{"phase": "stage"}` or `{"phase": "complete"}`.

Response `200`, `stage`: `phase` (`"stage"`), `ca_pem` (string, staged CA PEM),
`staged_cert_path` (string), `manual_steps` (string[], steps gwops cannot do).

Response `200`, `complete`: `phase` (`"complete"`), `actions` (string[]), `errors` (string[];
non-empty on a partial failure such as no API key, status stays `200`), `manual_steps`
(string[]). `complete` promotes the staged CA files first, then registers the new CA with the
tenant and rebinds the gateway, then re-mints the leaf. If registration fails or is skipped, the
promotion and the re-minted leaf stay in place. A second `complete` is `409` (nothing staged) and
a reconcile pass does not register a CA while one is already recorded, so register the new CA and
rebind the gateway on the tenant yourself, or run `stage` and `complete` again.

With `ca.x509.on_demand_issuance` set in the seed, `complete` finishes by getting the gateway's
on-demand issuer onto the promoted CA. It takes the mutation lock, then the reconciler's pass lock,
and acts on the gateway state:

| Gateway state | Result |
| --- | --- |
| shutting down | no restart; `actions` gains `gateway loads the new CA on next start` |
| `running` | drain-restart; `actions` gains `drain-restarted gateway so the on-demand issuer loads the new CA`; a failed restart is an entry in `errors` |
| `starting` | `errors` gains `gateway was starting; restart it to load the new CA` (it may have read the old CA) |
| any other state | `actions` gains `gateway loads the new CA on next start` |

The call waits for an in-flight mutation or reconcile pass before it restarts the gateway. The
restart runs shielded from request cancellation: a client that disconnects does not interrupt it.

Errors: `409` (public mode: `public certificate mode (public_tls): gwops does not mint or rotate the CA`, checked first; CA is bring-your-own; `complete` with nothing staged), `422` (bad `phase`),
`500` (local cert error).

```sh
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"phase": "stage"}' $BASE/certs/rotate-ca
```

`manual_steps` is the same list in both phases:

```json
{
  "manual_steps": [
    "Before 'complete': distribute the staged X.509 CA (ca_pem) to any client that pins or otherwise trusts the gateway's TLS CA. SSH upstream targets need no change: this rotation does not touch the SSH CA.",
    "After 'complete': the previous CA object remains registered on the Twingate tenant; delete it there once nothing trusts it anymore."
  ]
}
```

### POST /certs/public/{name}/issue

Queues an immediate ACME issuance or renewal of the `source: acme` public certificate `{name}`.
The lego run happens in the background, outside any reconcile pass; the response only says the
request was queued. Read the outcome from [`certs.public[].acme`](#certspublicacme) in
`GET /status`. With `directory: staging` the run is a dry run: it issues and validates, reports
`dry_run_ok` and installs nothing.

Admin token only. The automation token gets `403`.

Request body (optional; `{}` and no body both mean `force: false`). Unknown fields are `422`.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `force` | boolean | `false` | Add `--renew-force`, so lego renews even when the certificate is not yet in its renewal window. It never skips a backoff: a hold in force still answers `429`. In production, a forced request is also refused with `429` (`reason` `force_window`) while the installed certificate is under 24 h old; a request without `force` is accepted. |

Response `202`:

```json
{"certificate": "wildcard", "status": "scheduled", "force": false, "detail": "issuance for 'wildcard' scheduled"}
```

Errors:

| Status | When | Body |
| --- | --- | --- |
| `401` | Missing, malformed or wrong token. | Empty. |
| `403` | The automation token. | `{"detail": "the automation token may only use /upstreams/{kind}/{name}"}` |
| `404` | `{name}` is not a declared public certificate (also when the seed has no `public_tls`). | `{"detail": "'nope' is not a declared public certificate"}` |
| `409` | The certificate has `source: file`. | `{"detail": "public certificate 'files-cert' has source: file; gwops does not issue it (replace the mounted files instead)"}` |
| `409` | Issuance for it is running now. | `{"detail": "issuance for 'wildcard' is in progress"}` |
| `409` | The runner cannot take work. Every such case is `409`; `detail` says which. | `{"detail": "ACME DNS token file /config/acme/cloudflare-token does not exist; mount it read-only under /config/acme/ (issuance cannot succeed until it is present)"}` |
| `409` | The effective state fails to load (as on the other routes). | `{"detail": "..."}` |
| `422` | The body is not `{"force": <boolean>}`. | `{"detail": [...]}` (the validation error list) |
| `429` | The request is held back. The `Retry-After` header is the whole seconds until a request may be accepted (rounded up, at least 1). The body is `{detail, reason, error_code}`: `reason` is `backoff`, `force_window` or `request_floor` (below), and `error_code` is the certificate's current [error code](#certspublicacme) or `null`. When more than one hold applies, the latest end time is reported. | `{"detail": "'wildcard' is in backoff until 2026-10-20T14:05:00+00:00", "reason": "backoff", "error_code": "dns_propagation"}` |

The runner-cannot-take-work `409` details are: `the ACME runner is not running` followed, when the
runner could not be built, by the cause in parentheses (the exception type and text) and then
`; check the gwops startup log`; the DNS token file problem (`... does not exist ...`, `... is not
a regular file`, `... is empty`, `... resolves to <path>, outside /config/acme ...` or `... cannot
be examined (<ErrorType>)`); `ACME state file is unusable; issuance is refused until it is fixed`
(also `ACME state file cannot be written; ...`); `the ACME runner is shut down`; and `the ACME
runner has not picked up 'wildcard' yet; run POST /reconcile and retry` (the entry is in the
seed but the runner has not been configured with it).

The three `429` reasons:

| `reason` | Meaning |
| --- | --- |
| `backoff` | A recorded failure holds the certificate (including a rate limit), a run was interrupted by a restart, the production failed-validation limit applies, or the runner is cooling down after an unexpected exception in its own attempt code. |
| `force_window` | Production only: `force` was requested and the installed certificate is under 24 h old. A request without `force` is accepted. |
| `request_floor` | A request for this certificate was accepted less than 60 s ago (staging included). |

A failure of the kind an operator can fix (`config`, `dns_auth`, `dns_zone`) stops holding the
certificate as soon as its ACME configuration or the token file changes (the file's inode, mtime
or size); the change is noticed only while gwops is running, so one made while it was down leaves
the hold in force. `force` never ends a hold.

Every call is audited (`api.audit`, with the status). The outcome is also logged as
`api.acme_issue`; a refusal that never reached the runner is logged as `api.acme_issue_refused`.

```sh
curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/certs/public/wildcard/issue
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"force": true}' $BASE/certs/public/wildcard/issue
```

## Common error bodies

Plain error (`403`, `404`, `409`, `422`, `503`):

```json
{"detail": "address allowlist: [\"'web-9': address '192.168.1.50' is not allowlisted\"]"}
```

Transactional failure (`422` or `503`; the change was rolled back):

```json
{
  "detail": {
    "message": "change rolled back: Twingate sync did not complete for ['ssh/web-2']",
    "rolled_back": true,
    "unsynced": ["ssh/web-2"],
    "errors": ["TG sync: ssh/web-2: rejected"],
    "rollback": {"ok": true, "local_ok": true, "trigger": "api-rollback", "started_at": "...", "actions": [], "errors": []}
  }
}
```

`rolled_back` is always `true`; `unsynced` lists `kind/name` keys not confirmed on Twingate;
`errors` are from the failed pass; `rollback` is the cleanup pass's ReconcileResult. A deferred
write appears as `"TG sync: ssh/web-2: deferred: rate-limited"`.

### 422 web-app policy refusal body

A write that sets a web app is checked against the web-app policy before anything is persisted,
for both tokens, and so is the removal of an overlay that set web apps. The body lists:

- every violation of each web-app entry the write sets, including one the entry already had (the
  write would carry it forward), and
- any violation elsewhere (gateway-wide, or on an entry the write does not set) that the resulting
  state has and the current state does not. A violation already present elsewhere is not blamed on
  the write.

For `DELETE /overlays/{id}` it lists the violations the removal adds. Each violation is a string
that names the entry and field. Header names can appear; header values and certificate content
never do. Nothing is persisted.

```json
{
  "detail": "web-app policy refused the change",
  "violations": [
    "web_apps entry 'grafana', request_headers: header 'Connection' is denied (hop-by-hop or framing header)",
    "web_apps entry 'grafana': upstream_tls 'none' requires the address host to be allowed by web_app_proxy.plaintext_upstreams"
  ]
}
```

Both `422` paths carry a top-level `violations` list. They differ in `detail`. When the check above
refuses the write, `detail` is the string `web-app policy refused the change`. When the write
passes it and the reconcile pass then refuses the state, the change is rolled back and `detail` is
the [transactional failure object](#common-error-bodies) (`message` reads `change rolled back:
web-app policy refused the change`), with `violations` listing the pass's violations:

```json
{
  "detail": {
    "message": "change rolled back: web-app policy refused the change",
    "rolled_back": true,
    "unsynced": ["webapp/grafana"],
    "errors": ["web-app policy: web_apps entry 'grafana': ..."],
    "rollback": {"ok": false, "local_ok": false, "trigger": "api-rollback", "started_at": "...", "actions": [], "errors": ["..."]}
  },
  "violations": ["web_apps entry 'grafana': ..."]
}
```

### 403 policy refusal body

An automation field-rule or exclusivity refusal (`403`) lists every violation of the check that
failed. No header value is echoed. Nothing is persisted, and one `api.audit` line records the
`403`.

```json
{
  "detail": "automation policy refused web_apps entry 'auto-grafana'",
  "violations": [
    {"field": "upstream_tls", "reason": "only verify_full is allowed for the automation token"},
    {"field": "request_headers.X-Debug", "reason": "header name not in admin_api.automation.web_apps.request_header_names"}
  ]
}
```

An exclusivity refusal has the same shape, with violations such as
`{"field": "alias", "reason": "conflicts with an existing resource address or alias"}` (`field` is
`address` or `alias`). Other `403`s, such as the opt-in refusal, use the plain error body.

## Examples

### Create an SSH upstream

```sh
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"address": "10.0.10.5:22"}' $BASE/upstreams/ssh/web-1
```

```json
{"id": "0001-api-put-ssh-upstreams-web-1", "origin": "admin",
 "patch": {"ssh_upstreams": [{"name": "web-1", "address": "10.0.10.5:22"}]},
 "reconcile": {"ok": true, "...": "..."}}
```

### Update it with access (refs are pinned in the response)

```sh
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"address": "10.0.10.9:22", "access": {"groups": ["Platform Engineers"], "security_policy": "Privileged Access MFA"}}' \
  $BASE/upstreams/ssh/web-1
```

```json
{"id": "0002-api-put-ssh-upstreams-web-1", "origin": "admin",
 "patch": {"ssh_upstreams": [{"name": "web-1", "address": "10.0.10.9:22", "access": {
   "groups": [{"id": "R3JvdXA6MTIz", "name": "Platform Engineers"}],
   "security_policy": {"id": "U2VjUG9saWN5OjQ1Ng==", "name": "Privileged Access MFA"}}}]},
 "reconcile": {"ok": true, "...": "..."}}
```

### Add an entry with an overlay

```sh
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"patch": {"ssh_upstreams": [{"name": "build-box", "address": "build.internal.example.com"}]}, "comment": "add build-box"}' \
  $BASE/overlays
# 201 {"id": "0003-add-build-box", "origin": "admin", "comment": "add build-box", "patch": {...}, "reconcile": {...}}
```

### Remove an entry with a `_delete` overlay

```sh
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"patch": {"ssh_upstreams": [{"name": "build-box", "_delete": true}]}, "comment": "remove build-box"}' \
  $BASE/overlays
# 201 {"id": "0004-remove-build-box", "origin": "admin", "patch": {...}, "reconcile": {...}}
```

### Revert by deleting an overlay

```sh
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" $BASE/overlays/0004-remove-build-box
# 204, no body
```

### Create a web app

```sh
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"address": "grafana.apps.example.com:3000", "alias": "grafana", "upstream_tls": "verify_full", "request_headers": {"X-Env": "prod"}}' \
  $BASE/upstreams/webapp/grafana
# 200 {"id": "0006-api-put-web-apps-grafana", "origin": "admin", "patch": {"web_apps": [{...}]}, "reconcile": {...}}
```

### Read a web app back

```sh
curl -s -H "Authorization: Bearer $TOKEN" $BASE/upstreams/webapp/grafana
```

```json
{"kind": "webapp", "name": "grafana", "origin": "admin", "address": "grafana.apps.example.com:3000",
 "tg_resource_id": "UmVzb3VyY2U6NzE=", "alias": "grafana", "upstream_tls": "verify_full",
 "downstream": {"tls": "tls13", "port": 443}, "request_headers": {"X-Env": "prod"},
 "warnings": [], "gateway_mismatch": null, "errors": [], "...": "..."}
```

### A write the web-app policy refuses

```sh
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"address": "grafana.apps.example.com:3000", "request_headers": {"Connection": "close"}}' \
  $BASE/upstreams/webapp/grafana
# 422 {"detail": "web-app policy refused the change", "violations": ["web_apps entry 'grafana', request_headers: header 'Connection' is denied (hop-by-hop or framing header)"]}
```

### Automation: PUT and idempotent DELETE

```sh
export AUTOMATION_TOKEN=<automation-token>

curl -s -X PUT -H "Authorization: Bearer $AUTOMATION_TOKEN" -H "Content-Type: application/json" \
  -d '{"address": "10.20.3.4:22"}' $BASE/upstreams/ssh/auto-app-42
# 200 {"id": "0005-api-put-ssh-upstreams-auto-app-42", "origin": "automation", "patch": {...}, "reconcile": {...}}

curl -s -X DELETE -H "Authorization: Bearer $AUTOMATION_TOKEN" $BASE/upstreams/ssh/auto-app-99
# 200 {"deleted": false}
```
