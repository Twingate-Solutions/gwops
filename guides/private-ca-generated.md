# Use gwops-generated CAs

By default gwops generates two certificate authorities on first start and keeps them on the `/data`
volume:

| CA | Used for | Files under `/data/pki/` |
| --- | --- | --- |
| X.509 CA (EC P-256, 10-year validity) | Signs the gateway's TLS leaf, which the Twingate Client verifies | `x509-ca.crt` (mode 0644), `x509-ca.key` (mode 0600) |
| SSH CA (ed25519) | The gateway signs short-lived SSH certificates with it | `ssh-ca.key` (mode 0600), `ssh-ca.key.pub` (mode 0644) |

gwops never overwrites existing CA files. A restart loads the same CAs.

## When to use

You want private CA mode with no PKI of your own. This is the default and the path the
[quickstart](../quickstart/README.md) uses. Use [Bring your own CA](private-ca-byo.md) instead when
your organisation already runs a CA that SSH targets or browsers trust.

## Prerequisites

- A persistent `/data` volume (`gwdata:/data` in `compose.yaml`), writable by uid 10001.
- `TWINGATE_API_KEY` set, so gwops can register the CAs on the tenant.
- No `public_tls` block in the seed. Public certificate mode replaces the X.509 CA.

## Steps

1. Leave `ca` out of the seed, or set the defaults explicitly:

   ```yaml
   ca:
     x509:
       generate: true
     ssh:
       generate: true
   # ...rest of your seed
   ```

2. Start the container: `docker compose up -d`. gwops generates the CAs before its first pass.
3. On the first pass with an API key, gwops registers each generated CA on the tenant, once, as
   `gwops-x509-<label>` and `gwops-ssh-<label>`, and binds the Gateway object to them. The label is
   the `twingate.gateway_id` in pinned-gateway mode and the `twingate.gateway_address` in
   remote-network mode (see [Choose how gwops finds the Gateway object](gateway-modes.md)). The CA
   ids are recorded as `ca/x509` and `ca/ssh` in `/data/state.json`; gwops does not register them
   again while they are recorded.
4. Once at least one upstream is declared, gwops mints the TLS leaf under the X.509 CA. The Twingate
   Client trusts it through the CA registered on the tenant, so Client devices need no extra step.

### Trust the SSH CA on SSH targets

Each SSH target must trust the SSH CA public key.

1. Copy the public key out of the container:

   ```sh
   docker compose exec gateway cat /data/pki/ssh-ca.key.pub > twingate-gateway-ssh-ca.pub
   ```

2. On each SSH target, install it and point `sshd` at it, for example in `/etc/ssh/sshd_config`:

   ```text
   TrustedUserCAKeys /etc/ssh/twingate-gateway-ssh-ca.pub
   ```

3. Reload `sshd`.

The gateway signs a user certificate valid for 5 minutes with this CA for each session. See
[SSH resources](ssh-resources.md) and the [Twingate documentation](https://www.twingate.com/docs)
for the rest of the target configuration.

### Trust the X.509 CA in browsers (web apps only)

A web app with `downstream.tls: tls13` (the default) is served to the browser with the gwops leaf.
No browser trusts a gwops-generated CA. Installing it is an operator step.

1. Copy the CA certificate out of the container:

   ```sh
   docker compose exec gateway cat /data/pki/x509-ca.crt > gwops-x509-ca.crt
   ```

2. Install `gwops-x509-ca.crt` as a trusted root in the operating system or browser trust store of
   every device that opens the web apps, for example through your device management tool.

Until you do, browsers show a certificate warning. `/status` reminds you: `web_apps.browser_trust`
carries a note, and every such app has the readiness reason `operator_action`. Both stay present
after you install the CA, because gwops cannot see device trust stores.

> **Security:** A CA in browser trust stores is trusted for every name, not only the gateway's.
> Protect `/data/pki/x509-ca.key`, and read the caveat in
> [On-demand issuance](on-demand-issuance.md) before you turn that on.

### Keep `/data`

The CA keys exist only on the `/data` volume. If you lose it:

- gwops generates new CAs and registers them as new CA objects on the tenant.
- Every SSH target must trust the new SSH CA public key.
- Every browser must trust the new X.509 CA.
- The old CA objects stay on the tenant. Delete them in the Admin Console.

Back up `/data`; see [Back up and restore `/data`](../operations/backup-and-restore.md).

## Verify

```sh
export BASE=http://127.0.0.1:8081
export TOKEN=<admin-token>   # the GWOPS_ADMIN_TOKEN value from .env

curl -s -H "Authorization: Bearer $TOKEN" $BASE/status | jq '{certs: .certs, tls: .tls}'
```

- `certs.x509_ca_not_after` is about 10 years after first start.
- `certs.leaf_state` is `ok` and `certs.leaf_not_after` is about 90 days out. `leaf_state` is
  `missing` until the first upstream is declared.
- `tls.mode` is `static`.
- On the first pass, `last_reconcile.actions` lists `registered X.509 CA (<id>) and bound it to
  gateway` and `registered SSH CA (<id>) and bound it to gateway`.

On each SSH target, the installed public key line must match the output of
`docker compose exec gateway cat /data/pki/ssh-ca.key.pub`.

## Roll back

There is nothing to switch off: generated CAs are the default. To move to your own CA, follow
[Bring your own CA](private-ca-byo.md). To replace the generated X.509 CA, follow
[Rotate the leaf and the CA](../operations/ca-and-leaf-rotation.md).

## Related

- [Certificates](../architecture/certificates.md): the private PKI, the leaf and hot reload.
- [Seed reference: `ca`](../reference/seed.md#ca)
- [Rotate the leaf and the CA](../operations/ca-and-leaf-rotation.md)
- [SSH resources](ssh-resources.md), [Web apps](web-apps.md)
