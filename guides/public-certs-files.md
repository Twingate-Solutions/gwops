# Serve public certificates from files

> **Security:** In public certificate mode gwops registers a public root, ISRG Root X1, as the
> Gateway object's X.509 CA on your tenant. A Client that fetches the gateway's trust anchor then
> accepts any certificate that chains to that root for the names it dials through the gateway, not
> only the certificates gwops serves. That is the cost of serving publicly trusted certificates
> without a private CA. Use the mode only when that is acceptable.

In public certificate mode the gateway serves certificates you obtain from a public CA, such as
Let's Encrypt, instead of a leaf gwops mints. This guide covers certificates you supply as files
(`source: file`) and renew with any tool you like. To have gwops issue and renew them itself, see
[Issue public certificates with ACME](public-certs-acme.md).

## When to use

- Browsers open your web apps and you do not want to install a private CA on every device.
- You already have publicly trusted certificates for the names you serve, for example a wildcard
  from your platform's certificate manager, or you run certbot or another ACME client elsewhere.
- Your DNS provider or CA is not one that the built-in ACME support covers.

Every served name must then be a DNS name. IP-addressed upstreams, single-label names and on-demand
issuance are not available in this mode.

## Prerequisites

- One or more DNS zones you control, for example `example.com`.
- For each certificate: the full chain as PEM, leaf first, then its intermediates, chaining to
  ISRG Root X1, and its private key as unencrypted PEM.
- Every served name, meaning every SSH address, Kubernetes address, web-app address and web-app
  alias, is a DNS name of at least two labels inside one of your zones.
- The files readable by uid 10001 on the Docker host.

## Steps

1. Lay out one directory per certificate on the Docker host:

   ```text
   public-tls/
     wildcard/
       fullchain.pem   # leaf first, then intermediates; CERTIFICATE blocks only
       privkey.pem     # one unencrypted key
   ```

   ```sh
   sudo chown -R 10001:10001 public-tls
   chmod 0600 public-tls/*/privkey.pem
   ```

2. Mount the directory read-only. In `compose.yaml`, under `volumes:` of the `gateway` service:

   ```yaml
   - ./public-tls:/config/public-tls:ro
   ```

   gwops reads certificate files only from under `/config/public-tls/`. A path that resolves outside
   it, through a symlink or `..`, is refused.

3. Remove the `ca.x509` block from the seed, if you have one. `public_tls` and an explicit
   `ca.x509` are mutually exclusive (`public_tls and ca.x509 are mutually exclusive: public mode
   registers a public root as the X.509 CA; remove the ca.x509 block`). `ca.ssh` stays.
4. Add the `public_tls` block:

   ```yaml
   ca:
     ssh:
       generate: true
   public_tls:
     zones: ["example.com"]
     registered_root: isrg_root_x1
     certificates:
       - name: wildcard
         names: ["*.apps.example.com"]
         source: file
         cert_file: /config/public-tls/wildcard/fullchain.pem
         key_file: /config/public-tls/wildcard/privkey.pem
   ssh_upstreams:
     - name: build-box
       address: build.apps.example.com
   web_apps:
     - name: grafana
       address: grafana.apps.example.com:3000
   # ...rest of your seed
   ```

   | Key | Rule |
   | --- | --- |
   | `zones` | Lowercase DNS names of two or more labels, no wildcard, no trailing dot. A zone's apex is inside it. |
   | `registered_root` | `isrg_root_x1`, the only accepted value. |
   | `certificates[].name` | `[a-z0-9-]{1,63}`, unique. |
   | `certificates[].names` | The coverage you declare: concrete DNS names, or a leftmost `*.` wildcard that matches exactly one label. Each inside a zone. Each name belongs to one certificate. |
   | `certificates[].source` | `file`, the default when omitted. |
   | `cert_file`, `key_file` | Paths under `/config/public-tls/`. |

5. Restart the container: `docker compose up -d`. gwops looks up ISRG Root X1 in the image's trust
   store by SHA-256 fingerprint; if it is missing, startup aborts.

### The coverage rule

Every served name must be a DNS name inside a zone and match exactly one certificate's `names`.
gwops checks this when it loads the seed, and the API refuses an overlay that would break it with
`422`. Refused at load:

- an IP address as an upstream address or alias (`... is an IP literal; public mode serves DNS names only`),
- a single-label name (`... is a single-label name; a served name needs at least two labels`),
- a name outside every zone,
- a name no certificate covers, or one that several certificates cover,
- the Kubernetes in-cluster name `kubernetes.default.svc`.

A `*.apps.example.com` wildcard covers `grafana.apps.example.com` but neither `apps.example.com`
nor `a.b.apps.example.com`. To serve a name the seed does not yet cover, declare it in `public_tls`
first. A certificate whose `names` match no served name is logged once as `public_cert_unused`.

### What gwops checks in each pair

Before installing a pair, gwops checks that:

- `cert_file` holds only `CERTIFICATE` blocks, leaf first;
- `key_file` holds one unencrypted key, EC P-256, EC P-384 or RSA of 2048 bits or more, that
  matches the leaf;
- the leaf is `CA:FALSE`, carries `serverAuth`, is in date and carries no IP SANs;
- every DNS SAN is inside a zone and the SANs cover every declared name;
- the chain through the supplied intermediates reaches ISRG Root X1.

A refusal names the certificate, the file and the property, never file contents. At startup, any
refused `source: file` certificate aborts startup. After startup, a refused certificate shows as
state `invalid` with `last_error` in `/status`, and the last good pair keeps serving. Installs are
all-or-nothing per pass: if one certificate fails, none is installed that pass, and the others
report `pending`.

> **Note:** Let's Encrypt's ECDSA certificates chain to ISRG Root X2. For the chain to reach ISRG
> Root X1, `fullchain.pem` must include the cross-signed intermediate that links them.

### Renew

gwops does not contact a CA for `source: file` certificates. Renew with your own tool:

1. Write the new `fullchain.pem` and `privkey.pem` to the same paths. Write each pair so it is
   consistent when read, for example by writing to temporary names and renaming. A pair read
   mid-write is refused, and the next pass picks up the finished files.
2. Wait for the next pass, or apply at once (`BASE` and `TOKEN` as set in [Verify](#verify)):

   ```sh
   curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/reconcile
   ```

gwops validates the new pair, installs it under `/data/public-tls/<name>/` and the gateway
hot-reloads it, with no restart. Adding or removing a certificate entry in the seed drain-restarts
the gateway.

A certificate with less than a third of its lifetime left is `expiring`, and web apps it covers get
the readiness reason `public_cert_expiring:<name>`. An expired certificate is refused.

### Registering the root

On the first pass with an API key, gwops registers ISRG Root X1 as an X.509 CA on the tenant, or
reuses a CA object that already has its fingerprint, and binds the Gateway object to it. It sends
the binding only after the pass has rendered and applied the gateway config; until then the action
line says the rebind is deferred and why. gwops reads the binding on every pass and rebinds whenever
it differs. In remote-network mode, a newly created Gateway object is bound to the root from the
start.

## Verify

```sh
export BASE=http://127.0.0.1:8081
export TOKEN=<admin-token>   # the GWOPS_ADMIN_TOKEN value from .env

curl -s -H "Authorization: Bearer $TOKEN" $BASE/status | jq '{tls: .tls, public: .certs.public, root: .certs.registered_root}'
```

- `tls.mode` is `public`.
- Each `certs.public[]` entry has `state: "ok"`, a `not_after` and a `generation`.
- `certs.registered_root.bound` is `true`. It is `null` in the pass that sent the rebind, and
  becomes `true` when the next pass reads the binding back.
- `certs.leaf_state` and `certs.x509_ca_not_after` are `null`: there is no gwops leaf or CA in
  this mode. `POST /certs/rotate-leaf` and `POST /certs/rotate-ca` answer `409`.

From a device with the Twingate Client, `openssl s_client -connect grafana.apps.example.com:443
-servername grafana.apps.example.com` shows your certificate.

## Roll back

To return to private CA mode:

1. Remove the `public_tls` block. Add a `ca.x509` block back only if you need non-default settings.
2. Make sure every served name still works in private CA mode (IP addresses are allowed again).
3. Restart the container. gwops mints a leaf under its X.509 CA.
4. Rebind the Gateway object yourself, if needed. gwops does not move the binding away from the
   public root. If this install ran in private CA mode before, the gwops X.509 CA is still registered:
   bind the Gateway object to the CA id recorded as `ca/x509` in `/data/state.json`. If it never
   did, gwops registers a new X.509 CA and binds the Gateway object to it in its first private-mode
   pass.

Until the Gateway object is bound to the gwops CA, Clients refuse the gateway's leaf. Browsers then
also need the gwops CA installed; see [Use gwops-generated CAs](private-ca-generated.md).

## Related

- [Certificates](../architecture/certificates.md): public certificate mode and its validation.
- [Seed reference: `public_tls`](../reference/seed.md#public_tls)
- [Issue public certificates with ACME](public-certs-acme.md)
- [Mix certificate sources; SSH and Kubernetes in public mode](public-mode-mixed.md)
- [Web apps](web-apps.md)
