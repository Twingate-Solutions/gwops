# Mix certificate sources; SSH and Kubernetes in public mode

One `public_tls` block can hold certificates you supply as files and certificates gwops issues with
ACME. In public certificate mode the SSH and Kubernetes addresses are served names too, so they
follow the same DNS and coverage rules as web apps.

## When to use

- Some names are covered by a certificate you already have, for example from a corporate CA
  program, and others should be issued by gwops with ACME.
- You front SSH hosts or a Kubernetes API server on a gateway that runs in public certificate mode.
- You are deciding whether one gateway can serve both private-CA and public certificates. It
  cannot; see [No split mode](#no-split-mode).

## Prerequisites

- Public certificate mode set up as in [Serve public certificates from files](public-certs-files.md).
  For `source: acme` certificates, also the token file and egress from
  [Issue public certificates with ACME](public-certs-acme.md).
- Every SSH and Kubernetes address is a DNS name inside a `public_tls` zone, and that name resolves
  inside the container to the target. The gateway dials the address itself.

## Steps

1. Declare every certificate in one list, each with its own `source`. The `acme` block is required
   as soon as one certificate has `source: acme`. Each served name must match exactly one
   certificate's `names`.

   ```yaml
   public_tls:
     zones: ["example.com"]
     registered_root: isrg_root_x1
     acme:
       email: ops@example.com
       accept_tos: true
       directory: production
       token_file: /config/acme/cloudflare-token
     certificates:
       - name: apps-wildcard
         names: ["*.apps.example.com"]
         source: acme
       - name: infra
         names: ["build.infra.example.com", "k8s.infra.example.com"]
         source: file
         cert_file: /config/public-tls/infra/fullchain.pem
         key_file: /config/public-tls/infra/privkey.pem
   ssh_upstreams:
     - name: build-box
       address: build.infra.example.com
   k8s_clusters:
     - name: prod
       address: k8s.infra.example.com
       port: 6443
       bearer_token_file: /config/k8s-creds/prod.token
       ca_file: /config/k8s-creds/prod-ca.crt
   web_apps:
     - name: grafana
       address: grafana.apps.example.com:3000
   # ...rest of your seed
   ```

2. Mount both `./public-tls:/config/public-tls:ro` and `./acme:/config/acme:ro`, plus
   `./k8s-creds:/config/k8s-creds:ro` for the cluster credentials.
3. Keep the `ca.ssh` settings you use. The SSH CA works the same in public mode: generated or
   bring-your-own, and SSH targets trust its public key as in
   [SSH resources](ssh-resources.md#trust-the-ssh-ca-on-each-target). Only `ca.x509` is replaced.
4. Restart the container: `docker compose up -d`.

### How mixed sources start and renew

- At startup, a refused `source: file` certificate aborts startup. A `source: acme` certificate
  never does: with nothing installed yet it is `pending`.
- The gateway starts as soon as at least one certificate can be served. In the example, `infra` is
  served at once. Until `apps-wildcard` is issued, `grafana.apps.example.com` is served by no
  certificate and the web app reports `public_cert_pending:apps-wildcard`.
- Each source renews on its own: rewrite the files for `source: file`; gwops renews
  `source: acme`. Both hot-reload.

### SSH and Kubernetes rules in public mode

The seed is refused at load when an SSH or Kubernetes address:

- is an IP address. An SSH target addressed as `10.0.10.5:22` must be given a DNS name in a zone;
- is a single-label name or outside every zone;
- is covered by no certificate, or by more than one;
- is the in-cluster name `kubernetes.default.svc`, which no public certificate covers.

The error names the entry, for example:

```text
ssh_upstreams entry 'web-1': address '10.0.10.5' is an IP literal; public mode serves DNS names only
```

Kubernetes keeps its other rules: one cluster per gateway, credentials under `/config/k8s-creds/`.
See [Front a Kubernetes API server](kubernetes.md).

### Which certificate a handshake gets

gwops renders one `tls.certificates.files` entry per installed certificate, sorted by certificate
`name`. A `source: acme` certificate with nothing installed is left out. The gateway serves the
first certificate that matches the handshake. Because each served name matches exactly one
certificate, a client that sends SNI always gets the certificate covering that name. Order matters
only for a client that sends no SNI: it gets the first certificate by name.

### No split mode

One gateway cannot serve a gwops-minted leaf for some names and public certificates for others.
`public_tls` and an explicit `ca.x509` block are mutually exclusive, and public mode registers the
public root as the Gateway object's only X.509 CA.

To serve both, run two containers. Each needs its own seed, its own `/data` volume, its own Gateway
object (its own `gateway_id`, or its own `gateway_address` in remote-network mode) and its own host
port. For the second container, publish for example `8444:8443` and set
`gateway_address: 10.0.0.20:8444`. Give each container distinct upstream names and addresses.

## Verify

```sh
export BASE=http://127.0.0.1:8081
export TOKEN=<admin-token>   # the GWOPS_ADMIN_TOKEN value from .env

curl -s -H "Authorization: Bearer $TOKEN" $BASE/status | jq '.certs.public[] | {name, state, source_acme: (.acme != null)}'
curl -s -H "Authorization: Bearer $TOKEN" $BASE/upstreams/ssh/build-box | jq '{tg_resource_id, errors}'
```

- Every `certs.public[]` entry is `ok`. A `source: acme` entry carries an `acme` object; a
  `source: file` entry does not.
- The SSH and Kubernetes upstreams have a `tg_resource_id` and no `errors`.

## Roll back

Remove a certificate entry, and every served name it covered, from the seed. Removing an entry
drain-restarts the gateway. To leave public mode, follow the rollback in
[Serve public certificates from files](public-certs-files.md#roll-back).

## Related

- [Certificates](../architecture/certificates.md): public certificate mode.
- [Seed reference: `public_tls`](../reference/seed.md#public_tls),
  [`ssh_upstreams`](../reference/seed.md#ssh_upstreams),
  [`k8s_clusters`](../reference/seed.md#k8s_clusters)
- [Serve public certificates from files](public-certs-files.md),
  [Issue public certificates with ACME](public-certs-acme.md)
