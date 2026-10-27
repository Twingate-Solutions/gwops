# Seed reference

The seed is the declarative configuration file mounted read-only at `/config/seed.yaml`
(override the path with `GWOPS_SEED_PATH`). gwops never writes it back. Admin API changes are
stored as overlays under `/data/overlays/` and merged on top of the seed; see
[Configuration model](../architecture/configuration-model.md) for the merge rules.

Every model is strict: an unknown key anywhere in the seed is a load error, and startup aborts
with the dotted path of the problem and the layer (seed or overlay id) that set it.

Columns used in the tables below:

- **Default**: the value when the key is omitted. "required" means there is no default.
- **Overlay-writable**: whether an overlay (`POST /overlays`, `PUT /upstreams/...`) may set the
  key. Everything marked "no" is seed-only. An overlay that sets a seed-only key is refused with
  `422`.

Top-level keys:

| Key | Type | Default | Overlay-writable |
| --- | --- | --- | --- |
| [`twingate`](#twingate) | object | required | no |
| [`ca`](#ca) | object | generated X.509 and SSH CAs | no |
| [`ssh_upstreams`](#ssh_upstreams) | list | `[]` | yes |
| [`k8s_clusters`](#k8s_clusters) | list | `[]` | yes |
| [`web_apps`](#web_apps) | list | `[]` | yes |
| [`web_app_proxy`](#web_app_proxy) | object | see section | no |
| [`recording`](#recording) | object | recording off | `enabled` and `spool_max_bytes` only |
| [`admin_api`](#admin_api) | object | `127.0.0.1:8081` | no |
| [`public_tls`](#public_tls) | object | absent (private CA mode) | no |

## twingate

Which Twingate tenant and Gateway object this container serves, plus the seed-only access
defaults and allowlists.

| Key | Type | Default | Constraints | Overlay-writable |
| --- | --- | --- | --- | --- |
| `network` | string | required | The tenant slug: the label before `.<host>` in the Admin Console URL (`acme` for `acme.twingate.com`). | no |
| `host` | string | `twingate.com` | Everything after the slug in the Admin Console URL, for example `twingate.com` or `us1.twingate.com`. | no |
| `gateway_id` | string | `null` | GraphQL id of an existing Gateway object. Selects pinned-gateway mode. | no |
| `remote_network` | string | `null` | Remote Network name (exact). Remote-network mode only. | no |
| `remote_network_id` | string | `null` | Remote Network GraphQL id. Remote-network mode only. | no |
| `gateway_address` | string | `null` | `host:port` the Connector uses to reach this container. The port is mandatory (1-65535). Lowercased. Remote-network mode only. | no |
| `resource_defaults` | [access block](#access-blocks) | `null` | Applied to every resource whose own `access` omits a key. | no |
| `access_allowlist` | object | `null` | See below. | no |
| `access_allowlist.groups` | list of refs | `[]` | Groups that API and overlay writes may reference. | no |
| `access_allowlist.security_policies` | list of refs | `[]` | Security policies that API and overlay writes may reference. | no |
| `address_allowlist` | object | `null` | See below. | no |
| `address_allowlist.cidrs` | list of strings | `[]` | Each must parse as a CIDR (IPv4 or IPv6; host bits allowed). | no |
| `address_allowlist.dns_suffixes` | list of strings | `[]` | Non-empty. Stored trimmed, lowercased, without leading or trailing dots. | no |

Notes:

- **Exactly one gateway mode.** Set `gateway_id` (pinned-gateway mode), or set exactly one of
  `remote_network` / `remote_network_id` together with `gateway_address` (remote-network mode).
  The load errors are:
  - `gateway_id` with any remote-network key: `set either gateway_id (to pin an existing gateway) or remote_network + gateway_address (to auto-create), not both`
  - neither: `provide gateway_id, or remote_network(_id) + gateway_address`
  - no `gateway_address`: `remote-network mode requires gateway_address (...)`
  - neither network key: `remote-network mode requires exactly one of remote_network (console name) or remote_network_id (GraphQL id)`
  - both network keys: `set exactly one of remote_network (console name) or remote_network_id (GraphQL id), not both`
- **Allowlists bound API and overlay writes**, for the admin token as well as the automation
  token. Absent means unrestricted; an empty list allows nothing for that key. Seed entries and
  `resource_defaults` are implicitly allowed. `access_allowlist` is checked on resolved ids, so an
  `{id: ...}` reference cannot bypass a name entry. In `address_allowlist`, an IP literal must fall
  inside one of `cidrs`, and a DNS name must equal one of `dns_suffixes` or end with it at a label
  boundary (`apps.example.com` allows `x.apps.example.com`, not `xapps.example.com`). No DNS
  resolution is done.
- **`GWOPS_AUTOMATION_TOKEN` requires both allowlists.** If the token is set and either
  allowlist is absent, startup aborts.

Guides: [Gateway modes](../guides/gateway-modes.md), [Access control](../guides/access-control.md),
[Automation and CI](../guides/automation-and-ci.md).

## ca

Certificate authorities for private CA mode. Each CA is generated on first run or supplied by
you (bring-your-own).

| Key | Type | Default | Constraints | Overlay-writable |
| --- | --- | --- | --- | --- |
| `x509.generate` | boolean | `true` | `false` requires `cert_path` and `key_path`. | no |
| `x509.cert_path` | string | `null` | Bring-your-own X.509 CA certificate (PEM). Required when `generate: false`. | no |
| `x509.key_path` | string | `null` | Bring-your-own X.509 CA private key (unencrypted PEM, EC). Required when `generate: false`. | no |
| `x509.on_demand_issuance` | boolean | `false` | Opt-in. The gateway also issues certificates for names the leaf does not cover. Not available in public certificate mode. | no |
| `ssh.generate` | boolean | `true` | `false` requires `key_path`. | no |
| `ssh.key_path` | string | `null` | Bring-your-own SSH CA private key. The public key must sit beside it as `<key_path>.pub`. Required when `generate: false`. | no |

Notes:

- Generated CAs live under `/data/pki/`: `x509-ca.crt`, `x509-ca.key` (EC P-256, 10 years) and
  `ssh-ca.key`, `ssh-ca.key.pub` (ed25519). See [Data volume layout](image.md#data-volume-layout).
- Bring-your-own paths are used as given; they are not confined to a mount root. Put the files on
  a read-only mount such as `/config/ca/`, readable by uid 10001.
- Startup aborts on unusable CA material: an X.509 CA that is not `CA:TRUE`, is out of date, has a
  non-EC key, or whose key does not match the certificate; or only one half of a pair present.
- `on_demand_issuance: true` additionally requires `CA:TRUE`, `keyCertSign` when the CA has a
  `keyUsage` extension, and an unencrypted PEM key, or startup aborts.

> **Security:** with `ca.x509.on_demand_issuance: true`, a client that presents any SNI to
> port 8443 receives a certificate for that name signed by the X.509 CA, before its access token
> is authenticated. The client never receives the CA key, but anyone who can reach 8443 can
> trigger signing with it. See [On-demand issuance](../guides/on-demand-issuance.md).

- `ca.x509` and `public_tls` are mutually exclusive: with `public_tls` present, omit the `x509`
  block entirely (`ca` may then hold only `ssh`).

See: [Generated private CAs](../guides/private-ca-generated.md),
[Bring your own CA](../guides/private-ca-byo.md),
[CA and leaf rotation](../operations/ca-and-leaf-rotation.md),
[On-demand issuance](../guides/on-demand-issuance.md).

## ssh_upstreams

One entry per SSH target. gwops keeps one Twingate SSH resource per entry.

| Key | Type | Default | Constraints | Overlay-writable |
| --- | --- | --- | --- | --- |
| `name` | string | required | `[a-z0-9-]{1,63}`, unique within `ssh_upstreams`. | yes |
| `address` | string | required | `host` or `host:port`. Host characters `[a-zA-Z0-9._-]`; port 1-65535; default port 22. Lowercased. | yes |
| `access` | [access block](#access-blocks) | `null` |  | yes |

Notes:

- The Twingate resource address is the portless host. The port is the one the gateway dials.
- The host is a DNS name or an IPv4 literal. IPv6 literals are not accepted.
- In public certificate mode the host must be a DNS name covered by a `public_tls` certificate
  (see [Validation rules that span keys](#validation-rules-that-span-keys)).

Guide: [SSH resources](../guides/ssh-resources.md).

## k8s_clusters

The Kubernetes API server the gateway fronts. The gateway supports exactly one cluster: a second
entry loads, but rendering refuses it. At startup that aborts; on a later pass it is a local
error and the previous config keeps running.

| Key | Type | Default | Constraints | Overlay-writable |
| --- | --- | --- | --- | --- |
| `name` | string | required | `[a-z0-9-]{1,63}`, unique within `k8s_clusters`. | yes |
| `address` | string | required | API server host, no scheme. Same format as `ssh_upstreams[].address`; lowercased. A `:port` here is not used as the API server port; set `port`. | yes |
| `port` | integer | `443` | 1-65535. The API server port. | yes |
| `bearer_token_file` | string | required | Path of the service-account bearer token. Must resolve under `/config/k8s-creds/`. | yes |
| `ca_file` | string | required | Path of the API server CA certificate. Must resolve under `/config/k8s-creds/`. | yes |
| `access` | [access block](#access-blocks) | `null` |  | yes |

Notes:

- The credential files are read at reconcile time, not at load: the resolved path must stay
  under `/config/k8s-creds/` (symlinks and `..` that escape are refused), be a regular file, and
  be at most 1 MiB. gwops copies them to content-addressed files under `/data/k8s-creds/`, and the
  rendered gateway config points at the copies, so a changed credential restarts the gateway.
- The automation token cannot manage `k8s_clusters` entries.

Guide: [Kubernetes](../guides/kubernetes.md).

## web_apps

One entry per internal HTTP(S) app the gateway fronts as an L7 proxy. gwops keeps one Twingate
web-app resource per entry.

| Key | Type | Default | Constraints | Overlay-writable |
| --- | --- | --- | --- | --- |
| `name` | string | required | `[a-z0-9-]{1,63}`, unique within `web_apps`. | yes |
| `address` | string | required | `host` or `host:port`, the upstream the gateway dials. Default port 443, or 80 when `upstream_tls: none`. Lowercased. | yes |
| `alias` | string | `null` | Second client-facing host: a host name or IP literal (`[a-zA-Z0-9._-]`), no `*`, no port, different from the address host. Lowercased. `null` clears it on the tenant. | yes |
| `upstream_tls` | string | `verify_full` | `verify_full`, `verify_ca`, `insecure` or `none`. | yes |
| `downstream.tls` | string | `tls13` | `tls13` or `none`: whether the client-facing hop is TLS. | yes |
| `downstream.port` | integer | `443` (`tls13`) or `80` (`none`) | 1-65535. The client-facing port. | yes |
| `request_headers` | map of string to string | `null` | Per-app header rewrites. `null`: unmanaged (never sent). `{}`: managed and empty. See notes. | yes |
| `access` | [access block](#access-blocks) | `null` |  | yes |

Notes:

- **Header names** are 1-64 RFC 9110 token characters (letters, digits and
  ``!#$%&'*+-.^_`|~``), unique ignoring case. **Header values** are at most 1024 characters and
  contain no control characters.
- **The web-app policy** applies to every load, every pass and every write. It refuses:
  hop-by-hop and framing names (`Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`,
  `Upgrade`, `Content-Length`, `Expect`, `Proxy-*`), forwarding names (`Forwarded`,
  `X-Forwarded-*`, `X-Real-IP`, `Via`), routing overrides (`X-Original-URL`, `X-Rewrite-URL`,
  `X-HTTP-Method-Override`), `Cookie` and `Host` (names compare case-insensitively with `_` treated
  as `-`); malformed templates and template keys the gateway does not support; empty values;
  values that look like a static secret; a per-app header that reuses a gateway-wide identity
  header name; `upstream_tls` `none` or `insecure` for a host outside
  `web_app_proxy.plaintext_upstreams`; and a `{{jwt}}` template, gateway-wide or per-app, for an
  app whose `upstream_tls` is `verify_ca`, `insecure` or `none` unless its upstream host is
  `localhost` or a loopback IP.
- **Values** are static text or one `{{key}}` template with optional static text around it. Keys:
  `jwt`, `username`, `groups`, `clientGeoLatLong`, `clientGeoCity`, `clientGeoRegion`,
  `clientGeoCountry`.
- `upstream_tls` `verify_ca`, `insecure` or `none`, and `downstream.tls: none`, are allowed but
  reported as warnings in `/status`.
- The address host and the alias are served names: the TLS leaf covers both.

Guides: [Web apps](../guides/web-apps.md), [Web-app identity](../guides/web-apps-identity.md),
[Upstream TLS for web apps](../guides/web-apps-upstream-tls.md).

## web_app_proxy

Gateway-wide web-app settings. Seed-only.

| Key | Type | Default | Constraints | Overlay-writable |
| --- | --- | --- | --- | --- |
| `request_headers` | map of string to string | `{}` | Applied to every web app on this gateway. Same name and value rules as `web_apps[].request_headers`. `{{jwt}}` is refused here. | no |
| `upstream_ca_bundles` | list | `[]` | Private CAs trusted for upstream TLS, in addition to the system roots. | no |
| `upstream_ca_bundles[].name` | string | required | `[a-z0-9-]{1,63}`, unique. | no |
| `upstream_ca_bundles[].file` | string | required | Non-empty. Must resolve under `/config/webapp-cas/`. Two bundles may not name the same file. | no |
| `plaintext_upstreams` | object | `null` | The only hosts allowed `upstream_tls` `none` or `insecure`. Absent allows none. | no |
| `plaintext_upstreams.cidrs` | list of strings | `[]` | Same rules as `twingate.address_allowlist.cidrs`. | no |
| `plaintext_upstreams.dns_suffixes` | list of strings | `[]` | Same rules as `twingate.address_allowlist.dns_suffixes`. | no |
| `upstream_tls_probe` | boolean | `false` | Opt-in TLS 1.3 handshake probe of web-app upstreams, reported in `/status`. Read on every pass. | no |

Notes:

- A gateway-wide header whose value uses the `username`, `groups` or `jwt` template is a trusted
  identity header: per-app rewrites may not set it, and the gateway config renders it under
  every `-`/`_` spelling of its name. Such a name may have at most 4 `-` or `_` separators.
- A CA bundle file must hold `CERTIFICATE` PEM blocks only, each `CA:TRUE` and in date. It is read
  at reconcile time (regular file, at most 1 MiB), copied to `/data/upstream-ca/`, and rendered
  only while at least one web app exists. A changed file restarts the gateway.

Guides: [Web-app identity](../guides/web-apps-identity.md),
[Upstream TLS for web apps](../guides/web-apps-upstream-tls.md).

## recording

Delivery of session recordings and audit lines to a recording receiver. Off by default.

| Key | Type | Default | Constraints | Overlay-writable |
| --- | --- | --- | --- | --- |
| `enabled` | boolean | `false` | `true` requires `receiver_url`. | yes (takes effect at restart) |
| `receiver_url` | string | `null` | Base URL of the recording receiver; gwops POSTs to `<url>/ingest`. Scheme `http` or `https`. | no |
| `spool_max_bytes` | integer | `268435456` (256 MiB) | At least `16777216` (16 MiB). | yes (takes effect at restart) |

Notes:

- `receiver_url` accepts the base URL of any receiver that implements the [recording wire format](recording-wire-format.md).
- The bearer token comes from `GWOPS_RECORDING_TOKEN`, never from the seed. With recording on and the
  token unset, lines spool locally and ship after a restart supplies it.
- An `http://` URL is accepted and logs `shipper.insecure_transport` at startup: the token and the
  recordings travel in cleartext. Prefer `https://`.
- Recording settings are read once at startup. A change through the seed or an overlay is stored
  immediately but takes effect only after a restart.

Guide: [Session recording](../guides/session-recording.md).

## admin_api

The gwops admin API listener and the automation token's namespace rules. Seed-only.

| Key | Type | Default | Constraints | Overlay-writable |
| --- | --- | --- | --- | --- |
| `bind` | string | `127.0.0.1` | Address the admin API binds inside the container. | no |
| `port` | integer | `8081` | 1-65535. | no |
| `automation.name_prefix` | string | `null` | If set, every upstream the automation token creates must be named with this prefix. | no |
| `automation.web_apps.enabled` | boolean | `false` | Opt-in for the automation token to manage `web_apps` entries. | no |
| `automation.web_apps.request_header_names` | list of strings | `[]` | Header names the automation token may set in `request_headers`, matched case-insensitively. Same name rules as other header names; may not contain a denied or identity header name. | no |

Notes:

- `bind` and `port` are read once at startup; change them and restart. A failure to bind aborts
  startup.
- The default `127.0.0.1` is the container's own loopback. Docker forwards a published port to
  the container's network interface, so with the default the host cannot reach the API through
  `compose.yaml`'s `127.0.0.1:8081:8081` publish. Set `bind: 0.0.0.0` to reach it from the host;
  the publish still keeps it on host loopback.
- The admin API is plain HTTP. Do not bind it to a routable interface without a TLS proxy in
  front; see [Admin API behind a TLS proxy](../operations/admin-api-behind-tls-proxy.md).
- The Docker healthcheck probes the effective `bind` and `port` (`0.0.0.0`, `::`, `localhost` and
  `127.0.0.1` are probed on `127.0.0.1`).
- What the automation token may do with web apps is in
  [Automation and web apps](admin-api.md#automation-and-web-apps).

See: [Automation and CI](../guides/automation-and-ci.md),
[Admin API behind a TLS proxy](../operations/admin-api-behind-tls-proxy.md).

## public_tls

Public certificate mode. Its presence turns the mode on: the gateway serves publicly trusted
certificates (from files you supply, or issued by ACME) instead of a leaf minted by gwops, and
gwops registers a public root as the gateway's X.509 CA. Seed-only.

> **Security:** registering ISRG Root X1 as the gateway's X.509 CA means a Client accepts any
> certificate that chains to that root for the names it dials through this gateway, not only the
> certificates gwops serves. See [Known limitations](limitations.md#certificates-and-public-mode).

| Key | Type | Default | Constraints | Overlay-writable |
| --- | --- | --- | --- | --- |
| `zones` | list of strings | required | At least one. Each a lowercase ASCII DNS name of at least two labels, A-label form, no wildcard, no trailing dot. Unique. | no |
| `registered_root` | string | required | `isrg_root_x1` is the only accepted value. | no |
| `certificates` | list | required | At least one entry. | no |
| `certificates[].name` | string | required | `[a-z0-9-]{1,63}`, unique. | no |
| `certificates[].names` | list of strings | required | At least one. Concrete DNS names, or a leftmost `*.` wildcard label, each inside a zone. Lowercased. A name may belong to only one certificate. | no |
| `certificates[].source` | string | `file` | `file` or `acme`. | no |
| `certificates[].cert_file` | string | required for `source: file` | Leaf first, then intermediates (PEM). Must resolve under `/config/public-tls/`. Not allowed with `source: acme`. | no |
| `certificates[].key_file` | string | required for `source: file` | Unencrypted EC P-256, EC P-384 or RSA (at least 2048-bit) key matching the leaf (PEM). Must resolve under `/config/public-tls/`. Not allowed with `source: acme`. | no |
| `certificates[].challenge_alias` | string | `null` | `source: acme` only. Concrete lowercase DNS name of the zone that `_acme-challenge.<name>` is CNAME-delegated to. | no |
| `acme` | object | `null` | Required when any certificate has `source: acme`. | no |
| `acme.email` | string | required | ACME account contact address. A changed value registers a new account. | no |
| `acme.accept_tos` | boolean | `false` | Must be `true`. | no |
| `acme.directory` | string | `staging` | `staging`, `production`, or an `https://` ACME directory URL without credentials or fragment. | no |
| `acme.provider` | string | `cloudflare` | `cloudflare` is the only value. | no |
| `acme.propagation` | string | `resolver` | `resolver` (check through the container's resolver) or `authoritative` (also query the zone's authoritative nameservers; needs outbound UDP and TCP 53). | no |
| `acme.token_file` | string | `/config/acme/cloudflare-token` | Absolute path under `/config/acme/`, no `..` components. The file must exist, be a regular non-empty file, and resolve under `/config/acme/`. gwops checks it and never reads it. | no |

Notes:

- `staging` and `production` are Let's Encrypt's directories. `staging` (the default) is a dry
  run: certificates are issued and validated but never installed or served. An explicit URL equal
  to the Let's Encrypt staging URL is also staging; any other explicit URL is treated as
  production.
- `source: file` material is validated at startup and on every pass; a refused certificate aborts
  startup. `source: acme` certificates with nothing installed are pending and do not abort.
- Not available in this mode: IP-addressed upstreams or aliases, single-label names, the
  in-cluster name `kubernetes.default.svc`, and on-demand issuance.
- The token file mount and Cloudflare token scope are described in
  [Public certificates with ACME](../guides/public-certs-acme.md).

Guides: [Public certificates from files](../guides/public-certs-files.md),
[Public certificates with ACME](../guides/public-certs-acme.md),
[Mixed public mode](../guides/public-mode-mixed.md).

## access blocks

`twingate.resource_defaults` and the `access` key of every upstream entry share one shape.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `groups` | list of refs | `null` (omitted) | Groups the resource is assigned. `[]` means no groups, even when defaults exist. |
| `security_policy` | ref | `null` (omitted) | Security policy the resource is assigned. |

A ref is one of:

| Form | Meaning |
| --- | --- |
| `"Platform Engineers"` | Name. Must match exactly one existing object, exactly. |
| `{id: R3JvdXA6MTIz}` | Explicit GraphQL id. |
| `{id: R3JvdXA6MTIz, name: Platform Engineers}` | Pinned form. API writes store references this way; the id is authoritative. |

A ref needs a non-empty `name` or `id`. A key set on an entry replaces the default for that key
(it is not merged with it). A key omitted on both the entry and `resource_defaults` is left
alone: no groups and the tenant's default policy at creation, never changed afterwards. gwops
never creates groups or policies. See [Access control](../guides/access-control.md).

## Validation rules that span keys

| Rule | Error when |
| --- | --- |
| Unique names per list | Two entries in one of `ssh_upstreams`, `k8s_clusters`, `web_apps` share a `name` (`duplicate <list> name '<name>'`). |
| Gateway mode exclusivity | See [twingate](#twingate). |
| `public_tls` replaces `ca.x509` | Both `public_tls` and an explicit `ca.x509` block are present. |
| `public_tls.acme` presence | A certificate has `source: acme` and `public_tls.acme` is missing. |
| Served names in public mode | Any upstream address host or web-app alias is an IP literal, the in-cluster API name, a single-label name, not a valid DNS name, or outside every zone; or is covered by no certificate's `names`, or by more than one. |
| Recording URL | `recording.enabled: true` without `receiver_url`, or a URL whose scheme is not `http` or `https`. |
| Spool bound | `recording.spool_max_bytes` below 16 MiB. |
| One Kubernetes cluster | More than one `k8s_clusters` entry (refused at render, not at load). |
| Automation token | `GWOPS_AUTOMATION_TOKEN` set without both allowlists, or equal to `GWOPS_ADMIN_TOKEN` (startup aborts). |

Errors that come from an overlay name the overlay id, so you can delete it with
`DELETE /overlays/{id}`.

## Complete example

Every key below is shown with an example value. Delete what you do not use: in particular,
`k8s_clusters` needs mounted credential files and `recording` needs a reachable receiver.

```yaml
twingate:
  network: acme                     # tenant slug from https://acme.twingate.com
  host: twingate.com                # or a shard host such as us1.twingate.com

  # Pinned-gateway mode: an existing Gateway object.
  gateway_id: R2F0ZXdheTox
  # Remote-network mode instead (remove gateway_id):
  # remote_network: Production DC   # or remote_network_id: UmVtb3RlTmV0d29yazox
  # gateway_address: 10.0.0.20:8443 # how the Connector reaches this container

  resource_defaults:
    groups: ["Platform Engineers"]
    security_policy: "Standard Resource Policy"

  access_allowlist:                 # bounds API and overlay writes
    groups: ["Platform Engineers", "App Users"]
    security_policies: []
  address_allowlist:
    cidrs: ["10.20.0.0/16"]
    dns_suffixes: ["apps.example.com"]

ca:
  x509:
    generate: true                  # false: set cert_path and key_path
    on_demand_issuance: false
  ssh:
    generate: true                  # false: set key_path (with <key_path>.pub beside it)

ssh_upstreams:
  - name: web-1
    address: 10.0.10.5:22
  - name: build-box
    address: build.internal.example.com
    access:
      groups: ["Platform Engineers", {id: R3JvdXA6MTIz}]
      security_policy: "Privileged Access MFA"

k8s_clusters:                       # at most one entry
  - name: prod
    address: prod.k8s.internal.example.com
    port: 6443
    bearer_token_file: /config/k8s-creds/prod.token
    ca_file: /config/k8s-creds/prod-ca.crt

web_apps:
  - name: grafana
    address: grafana.apps.example.com:3000
    alias: grafana
    upstream_tls: verify_full
    downstream:
      tls: tls13
      port: 443
    request_headers:
      X-Env: prod
      Authorization: "Bearer {{jwt}}"
    access:
      groups: ["App Users"]

web_app_proxy:
  request_headers:
    X-Twingate-User: "{{username}}"
  upstream_ca_bundles:
    - name: corp-root
      file: /config/webapp-cas/corp-root.pem
  plaintext_upstreams:
    cidrs: ["10.20.0.0/16"]
    dns_suffixes: ["internal.example.com"]
  upstream_tls_probe: false

recording:
  enabled: true
  receiver_url: https://recordings.example.com   # gwops POSTs to /ingest
  spool_max_bytes: 268435456

admin_api:
  bind: 127.0.0.1
  port: 8081
  automation:
    name_prefix: auto-
    web_apps:
      enabled: false
      request_header_names: []
```

Public certificate mode replaces the `ca.x509` block. A seed using it keeps `ca.ssh` only. The
fragment below shows the keys that change; the `twingate` block is the same as above:

```yaml
# ...twingate block as above
ca:
  ssh:
    generate: true

public_tls:
  zones: ["example.com"]
  registered_root: isrg_root_x1
  acme:                              # required because one certificate uses source: acme
    email: ops@example.com
    accept_tos: true
    directory: staging               # dry run; set production to serve
    provider: cloudflare
    propagation: resolver
    token_file: /config/acme/cloudflare-token
  certificates:
    - name: wildcard
      names: ["*.apps.example.com"]
      source: acme
      # challenge_alias: acme-challenges.example.net
    - name: files-cert
      names: ["ssh.example.com"]
      source: file
      cert_file: /config/public-tls/files-cert/fullchain.pem
      key_file: /config/public-tls/files-cert/privkey.pem

ssh_upstreams:
  - name: bastion
    address: ssh.example.com        # a DNS name covered by exactly one certificate
```
