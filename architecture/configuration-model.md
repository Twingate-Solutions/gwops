# Configuration model

gwops runs from one declarative configuration, the **effective state**: the read-only seed with
zero or more overlays merged on top, validated as a whole. Every reconcile pass rebuilds it from
disk, so there is no in-memory configuration that can drift from what is on disk.

Code: [`src/gwops/configmodel/`](../src/gwops/configmodel) (`schema.py`, `merge.py`,
`store.py`, `loader.py`) and [`src/gwops/reconciler/watch.py`](../src/gwops/reconciler/watch.py).

## Seed

The seed is `/config/seed.yaml`, mounted read-only (`GWOPS_SEED_PATH` overrides the path). gwops
never writes it back.

- **Strict schema.** Every model forbids unknown keys, so a typo is a load error, not a silently
  ignored setting. The top-level keys are `twingate`, `ca`, `ssh_upstreams`, `k8s_clusters`,
  `web_apps`, `web_app_proxy`, `recording`, `admin_api` and `public_tls`; only `twingate` is
  required.
- **Names** of upstreams, CA bundles and public certificates match `[a-z0-9-]{1,63}` and are unique
  within their list.
- **Addresses** are `host` or `host:port` with a host of letters, digits, `.`, `_` and `-`, and are
  lowercased, because the Twingate API lowercases addresses and a mixed-case seed would differ
  from the tenant on every pass. A colon is only accepted as the port separator, so IPv6 literals
  cannot be written as addresses.
- **Cross-key rules** run on the whole document: exactly one gateway mode, `public_tls` and an
  explicit `ca.x509` block are mutually exclusive, every served name must be covered in public
  mode, `recording.enabled: true` requires `recording.receiver_url`, and so on. They are listed in
  [`reference/seed.md`](../reference/seed.md).

The effective state has the same shape as the seed (`EffectiveState` subclasses `SeedConfig`), so
everything that validates a seed validates the merged result.

## Overlays

An overlay is one persisted admin-API change. Each one is a JSON file under `/data/overlays/`:

```json
{
  "id": "0003-api-put-ssh-upstreams-web-2",
  "created_at": "2026-10-20T09:14:03.120518+00:00",
  "comment": "api put ssh_upstreams web-2",
  "patch": {"ssh_upstreams": [{"name": "web-2", "address": "10.0.10.6:22"}]},
  "origin": "admin"
}
```

- **Id.** `<4-digit counter>-<slug>`. The counter is one past the highest on disk; the slug is the
  lowercased comment, at most 40 characters. Ids are validated against `^\d{4}-[a-z0-9-]+$`
  before any filesystem access, so an id from the API can never name a path outside the store.
- **Order.** Overlays apply in lexical filename order, which is counter order.
- **Origin.** `admin` or `automation`: which bearer token wrote it. The automation token may only
  change entries it created and no admin write has touched since (see
  [Admin API](admin-api.md#principals)).
- **Atomic writes.** Each file is written to a `.tmp` sibling and renamed into place. A leftover
  `.tmp` from a crash is ignored.
- **Bounds.** A patch larger than 256 KiB serialised, or nested deeper than 32 levels, is refused
  before anything is written. The merge itself stops at 64 levels, so an over-deep file already on
  disk is a clear load error instead of a recursion crash.

Overlays are created by `POST /overlays` and by `PUT`/`DELETE /upstreams/{segment}/{name}`, which
build the equivalent patch. `DELETE /overlays/{id}` removes one. Every route goes through the same
validate, persist, reconcile and keep-or-roll-back path described in
[Admin API](admin-api.md#transactional-writes).

## Merge rules

`merge_layers` applies each overlay's `patch` to the seed in order:

| Value | Rule |
| --- | --- |
| Maps | Recurse key by key. |
| Top-level named lists (`ssh_upstreams`, `k8s_clusters`, `web_apps`) | Merge **by `name`**. A patch item with a new name is appended; one with an existing name is merged into that entry; `{"name": "x", "_delete": true}` removes the entry. |
| A web app's `request_headers` inside a named-list item | Replaced wholesale, so an overlay can remove a header. |
| Nested lists, even of named dicts (for example `access.groups`) | Replaced wholesale. Merging them by name would union a group list across overlays, so a later declaration could never drop a group. |
| Scalars and plain lists | Replaced; the last layer wins. |

Because named-list items merge, `PUT /upstreams/ssh/web-1` with only `{"address": ...}` changes the
address and keeps every other field the entry already had.

### Worked example

Seed:

```yaml
twingate:
  network: acme
  remote_network: Production DC
  gateway_address: 10.0.0.20:8443
ssh_upstreams:
  - name: web-1
    address: 10.0.10.5:22
    access:
      groups: ["Platform Engineers", "App Users"]
web_apps:
  - name: grafana
    address: grafana.apps.example.com:3000
    request_headers: {X-Env: prod, X-Team: obs}
```

Overlay `0001-ci-update` (from `POST /overlays` with comment `ci update`):

```json
{"ssh_upstreams": [{"name": "web-1", "access": {"groups": [{"id": "R3JvdXA6MTA=", "name": "Platform Engineers"}]}},
                   {"name": "web-2", "address": "10.0.10.6:22"}],
 "web_apps": [{"name": "grafana", "request_headers": {"X-Env": "staging"}}]}
```

Overlay `0002-drop-web-2`:

```json
{"ssh_upstreams": [{"name": "web-2", "_delete": true}]}
```

Effective state:

```yaml
twingate:
  network: acme
  remote_network: Production DC
  gateway_address: 10.0.0.20:8443
ssh_upstreams:
  - name: web-1
    address: 10.0.10.5:22            # from the seed
    access:
      groups:                        # replaced wholesale by 0001-ci-update: "App Users" is gone
        - {id: R3JvdXA6MTA=, name: Platform Engineers}
web_apps:
  - name: grafana
    address: grafana.apps.example.com:3000
    request_headers: {X-Env: staging} # replaced wholesale by 0001-ci-update: X-Team is gone
```

`web-2` was added by `0001` and removed by `0002`. The group reference in the overlay is in the
pinned `{id, name}` form, which the admin API writes for every reference it persists (see
[Twingate integration](twingate-integration.md#access-assignment)).

## Provenance

While merging, gwops records which layer last set every leaf, keyed by dotted path. Named-list
items are addressed by name, never by index, so paths stay stable as lists change:

```json
{
  "twingate.network": "seed",
  "ssh_upstreams.web-1.address": "seed",
  "ssh_upstreams.web-1.access.groups": "0001-ci-update",
  "web_apps.grafana.request_headers.X-Env": "0001-ci-update"
}
```

Provenance is returned by `GET /state` next to the redacted effective state. It is also what makes
load errors actionable: a validation error is reported as the dotted path plus the layer that set
the value, for example
`k8s_clusters.prod.port: Input should be less than or equal to 65535 (set by layer: 0004-api-put-k8s-clusters-prod)`.
A bad overlay can then be removed with `DELETE /overlays/{id}`, or by deleting its file while the
container is stopped.

## What overlays may and may not set

An overlay, whichever token writes it, may set only these top-level keys:

| Overlay-writable | Seed-only |
| --- | --- |
| `ssh_upstreams`, `k8s_clusters`, `web_apps` | `twingate` (tenant, gateway mode, `resource_defaults`, `access_allowlist`, `address_allowlist`) |
| `recording`, except `recording.receiver_url` | `ca`, `web_app_proxy`, `public_tls`, `admin_api` |

Anything else is refused with 422 before validation (`_reject_forbidden_overlay_keys` in
[`api/routes_state.py`](../src/gwops/api/routes_state.py)).

The reason is that the seed is the guardrail an API caller cannot widen. Letting an overlay change
the tenant, a CA path, the recording destination or the allowlists would let anyone holding the
admin token redirect the API key, the CA private key or the recordings somewhere else. The
upstream lists are operational data; the trust configuration around them is not.

## When changes take effect

| Source | Trigger | Delay |
| --- | --- | --- |
| Seed edit, seen by the file watch | `seed-change` | The parent directory of the seed is watched with `watchfiles`, debounced 2 s. Watching the directory keeps working across editor rename-over saves. Only events that name the seed file itself fire, so a directory-mounted Kubernetes ConfigMap update (a `..data` symlink swap) is not seen here. |
| Seed edit, seen by the content-hash poll | `seed-change` | The seed's SHA-256 is compared every 5 s; on a change it is re-read every 0.5 s until two reads agree, so a half-written file is not reconciled. |
| Periodic tick | `tick` | Every `GWOPS_RECONCILE_TICK_SECONDS` (default 600 s), measured between passes. |
| Admin API | `api` | Writes reconcile synchronously before the response. `POST /reconcile` runs a pass. A completed CA rotation and an installed ACME certificate set an event that runs a pass. |
| `SIGHUP` | `sighup` | Immediate. |

The poll exists because a single-file bind mount (`./seed.yaml:/config/seed.yaml:ro`, as in the
shipped `compose.yaml`) delivers no inotify events inside the container when the host file is
edited in place. It is also the only thing that notices a directory-mounted Kubernetes ConfigMap
update: the kubelet swaps the mount's `..data` symlink, which produces no event for the seed file
itself. Two related limits:

- An editor that saves by writing a new file and renaming it over the old one replaces the host
  inode. A single-file bind mount keeps pointing at the old inode, so the container never sees the
  change. Restart the container, or mount the directory that holds the seed instead of the file.
- The watch and the poll share one fingerprint, so one edit runs one pass, not two.

Some settings are read once and need a restart:

| Setting | Read |
| --- | --- |
| `recording.enabled`, `recording.receiver_url`, `recording.spool_max_bytes`, and `GWOPS_RECORDING_TOKEN` | Once at startup, when the spool and shipper are built. An overlay that changes `recording.*` validates and persists, but has no effect until the next start. |
| `admin_api.bind`, `admin_api.port` | Once, when the admin socket is bound. The Docker healthcheck reads the current values each time it runs, so changing the port without a restart makes the healthcheck probe a port nothing listens on. |
| Every environment variable | Once at startup. |

Everything else, including `web_app_proxy.upstream_tls_probe`, the allowlists and
`resource_defaults`, is read on every pass.

## Validation is layered

| Layer | When | What a failure does |
| --- | --- | --- |
| Schema and cross-key rules | Every load: startup, every pass, every API write (on the candidate state before anything is written), `/status`, `/state` | Startup: abort. A pass: `effective state failed to load`, local failure, last good config keeps running. API write: 422 naming the path and the layer `candidate`. |
| Web-app policy | Startup, every pass, every write that touches a web app, and an overlay delete | Startup: abort. A pass: local failure. Write: 422 listing the violations. See [Web apps](web-apps.md#the-web-app-policy). |
| Public certificate coverage | Part of the schema: every served name must be a DNS name in a zone and match exactly one certificate | As for the schema. |
| Allowlists | Every API write, on the patch only | 403. See [Admin API](admin-api.md#guardrails). |
| Access references | API writes: resolved and pinned before the overlay is stored (422 on no match or several, 503 when the tenant is unreachable). Seed references: resolved on each pass | A pass records a per-resource error and does not create a resource whose access cannot be resolved. |
| The binary itself | Pre-flight on every changed render | The candidate is discarded and the last good config stays. See [Gateway process](gateway-process.md#pre-flight-by-spawn). |

## See also

- [`reference/seed.md`](../reference/seed.md): every key, type, default and whether overlays may
  set it.
- [`reference/admin-api.md`](../reference/admin-api.md#write-semantics): write semantics of the
  overlay routes.
- [Reconciler](reconciler.md): what a pass does with the effective state.
- [`guides/automation-and-ci.md`](../guides/automation-and-ci.md): managing overlays from CI.
- [`operations/backup-and-restore.md`](../operations/backup-and-restore.md): overlays live on `/data`.
