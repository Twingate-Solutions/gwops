# Web-app upstream TLS

`upstream_tls` on each web app sets how the gateway checks the app it forwards to. The default,
`verify_full`, verifies the app's certificate chain and host name against the system roots. This
guide covers apps whose certificates come from a private CA, apps that speak plain HTTP, and the
opt-in probe that tests each upstream's TLS handshake.

| `upstream_tls` | Gateway to app | Allowed for |
| --- | --- | --- |
| `verify_full` | TLS; chain and host name verified | Any app. Required for `{{jwt}}` to a non-loopback app. |
| `verify_ca` | TLS; chain verified, host name not checked | Any app. Reported as a warning. |
| `insecure` | TLS; certificate not verified | Hosts in `web_app_proxy.plaintext_upstreams` only. Reported as a warning. |
| `none` | Plain HTTP | Hosts in `web_app_proxy.plaintext_upstreams` only. Reported as a warning. Default port 80. |

Every mode that uses TLS requires TLS 1.3. An app that only speaks TLS 1.2 fails with `502`.

## When to use

- The app's certificate is issued by an internal CA that the image's system roots do not include.
- The app speaks plain HTTP on a trusted network segment, or uses a certificate you cannot fix yet.
- You want gwops to tell you, before users do, that an upstream's TLS will fail.

## Prerequisites

- A declared web app (see [Web apps](web-apps.md)).
- For a private CA: the CA certificates as PEM.
- Seed edit access: `web_app_proxy` is seed-only; no overlay or API call can set it.

## Steps

### Trust a private upstream CA

1. Put the CA certificates in a PEM file on the Docker host, for example `webapp-cas/corp-root.pem`.
   The file may hold only `CERTIFICATE` blocks: no private key, no other PEM block, and no text
   outside the blocks. Each certificate must be a CA (`basicConstraints` `CA:TRUE`) and in date.
   Make it readable by uid 10001.
2. Mount the directory read-only. In `compose.yaml`, under `volumes:` of the `gateway` service:

   ```yaml
   - ./webapp-cas:/config/webapp-cas:ro
   ```

3. Reference it in the seed:

   ```yaml
   web_app_proxy:
     upstream_ca_bundles:
       - name: corp-root
         file: /config/webapp-cas/corp-root.pem
   web_apps:
     - name: wiki
       address: wiki.internal.example.com
       upstream_tls: verify_full
   # ...rest of your seed
   ```

   Bundle names are `[a-z0-9-]{1,63}` and unique, and two bundles may not name the same file. The
   file must resolve to a regular file of at most 1 MiB under `/config/webapp-cas/`.

4. Save the seed. gwops validates every bundle, copies each one to
   `/data/upstream-ca/<name>-<sha12>.pem` and renders the copies as the gateway's trusted upstream
   CA bundles, added to the system roots. The rendered config changes, so the gateway
   drain-restarts.

The bundles are rendered only while at least one web app is declared. A refused bundle is a local
error, for example
`CA bundle refused: web_app_proxy.upstream_ca_bundles: bundle 'corp-root' contains a private key block; only CERTIFICATE blocks are accepted`;
the pass applies nothing and the gateway keeps its last good config.

To update a bundle, rewrite the file. The next pass copies it to a new content-addressed path and
drain-restarts the gateway; the old copy is removed after a fully successful pass.

### Allow a plaintext or unverified upstream

`upstream_tls: none` and `upstream_tls: insecure` are refused unless the app's host is listed in
`web_app_proxy.plaintext_upstreams`:

```yaml
web_app_proxy:
  plaintext_upstreams:
    cidrs: ["10.20.0.0/16"]
    dns_suffixes: ["lab.internal.example.com"]
web_apps:
  - name: legacy-dash
    address: dash.lab.internal.example.com:8080
    upstream_tls: none
    downstream:
      tls: tls13
# ...rest of your seed
```

- An IP address host must fall inside one of `cidrs`.
- A DNS name must equal one of `dns_suffixes` or end with it at a label boundary:
  `lab.internal.example.com` allows `dash.lab.internal.example.com` but not
  `xlab.internal.example.com`. Names are judged by spelling; gwops resolves nothing.
- Absent `plaintext_upstreams` allows no host.

Without the entry, the error is:

```text
web_apps entry 'legacy-dash': upstream_tls 'none' requires the address host to be allowed by web_app_proxy.plaintext_upstreams
```

`{{jwt}}` is never sent to a `none`, `insecure` or `verify_ca` upstream unless it is on `localhost`
or a loopback IP; see [Pass identity to a web app](web-apps-identity.md). `verify_ca` needs no
allowlist entry but is reported in `/status` `web_apps.warnings`.

### Probe upstream TLS

The probe is off by default. When on, after each reconcile pass gwops completes a TLS 1.3
handshake with the upstream of every web app whose `upstream_tls` is `verify_full` or `verify_ca`,
then closes the connection. It sends no request.

```yaml
web_app_proxy:
  upstream_tls_probe: true
# ...rest of your seed
```

The flag is read on every pass: a change takes effect on the next pass, with no restart. Turning it
off discards the results.

- **Targets:** the declared web apps, on their own upstream port, and unmanaged web apps on this
  gateway whose address is inside `twingate.address_allowlist`. Any other unmanaged app is reported
  `probe_unverifiable` and is never resolved or dialled.
- **Trust:** the system roots plus the validated `upstream_ca_bundles`. The host name is checked
  for `verify_full` only.
- **Refused addresses:** a name that resolves to a loopback, link-local, unspecified, multicast or
  `0.0.0.0/8` address, or to `fd00:ec2::254` or `100.100.100.200`, is reported
  `probe_refused_address` and nothing is dialled. Private addresses are dialled.
- **Limits:** at most 4 handshakes at a time, 5 seconds each. The probe dials directly and ignores
  `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`, so where the gateway reaches an upstream another way
  the result is advisory.
- A pass whose CA bundle step failed starts no probe batch, and the previous results stay.

| Probe `outcome` | Meaning |
| --- | --- |
| `ok` | The handshake succeeded. |
| `untrusted_issuer` | The certificate does not chain to a trusted root. Add the CA as a bundle. |
| `hostname` | `verify_full` only: the certificate does not cover the app's host name. |
| `tls12_only` | The upstream does not offer TLS 1.3. The gateway will fail with `502`. |
| `unreachable` | Connection refused, no route, timeout or another failure. |
| `ca_unusable` | An untrusted-issuer failure while a CA bundle copy could not be loaded. |

Any outcome other than `ok` adds the readiness reason `probe:<outcome>` (action required). An app
with no result yet has `probe_pending`.

## Verify

```sh
export BASE=http://127.0.0.1:8081
export TOKEN=<admin-token>   # the GWOPS_ADMIN_TOKEN value from .env

curl -s -H "Authorization: Bearer $TOKEN" $BASE/status | jq '{warnings: .web_apps.warnings, readiness: [.web_apps.readiness[] | {name, state, reasons, probe}]}'
```

- With the probe on, each app's `probe.outcome` is `ok`; `probe.target` is the `host:port` it
  dialled, and `verify_code` carries the OpenSSL error number of a certificate failure.
- `web_apps.warnings` lists each `verify_ca`, `insecure` and `none` upstream by name.
- `last_reconcile.actions` lists `materialized CA bundle /data/upstream-ca/corp-root-<sha12>.pem for 'corp-root'`
  when a bundle is first copied.

## Roll back

- Remove a bundle from `upstream_ca_bundles`; apps that need it then fail verification.
- Set `upstream_tls` back to `verify_full` and remove the host from `plaintext_upstreams`.
- Set `upstream_tls_probe: false` or remove it.

## Related

- [Web apps architecture](../architecture/web-apps.md): the web-app policy and the upstream probe.
- [Reconciler](../architecture/reconciler.md): content-addressed copies.
- [Seed reference: `web_app_proxy`](../reference/seed.md#web_app_proxy),
  [`web_apps`](../reference/seed.md#web_apps)
- [Admin API: `web_apps` in `/status`](../reference/admin-api.md#web_apps)
- [Web apps](web-apps.md), [Pass identity to a web app](web-apps-identity.md)
