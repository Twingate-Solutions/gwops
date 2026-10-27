# Bring your own X.509 or SSH CA

gwops can use certificate authorities you already run instead of generating its own. Each CA is
independent: you can bring your own X.509 CA and let gwops generate the SSH CA, or the reverse.

With a bring-your-own (BYO) X.509 CA, gwops still mints the gateway's TLS leaf, signed by your CA.
With a BYO SSH CA, the gateway signs its short-lived SSH certificates with your key.

## When to use

- Your SSH targets already trust an SSH CA and you do not want to roll out another one.
- Devices already trust your X.509 CA, so browsers accept web apps served with
  `downstream.tls: tls13` with no extra step.

Use [generated CAs](private-ca-generated.md) when neither applies. To serve publicly trusted
certificates, use [public certificate mode](public-certs-files.md) instead.

## Prerequisites

For an X.509 CA:

- The CA certificate as PEM. gwops uses the first certificate in the file.
- `basicConstraints` `CA:TRUE`, and the current time inside its validity period.
- The private key as an **unencrypted** PEM file. It must be an **EC** key (P-256 recommended):
  gwops signs the leaf with ECDSA and refuses RSA and other key types.
- The key matches the certificate.

For an SSH CA:

- The private key file and its public key in OpenSSH format beside it, named `<key_path>.pub`.
  Both halves must be present. The private key must be unencrypted, because the gateway reads it
  directly.

For both:

- The files are readable by uid 10001, the container's user, and stay in place across restarts.
- A gateway mode that fits the CA you bring. gwops never registers a BYO CA on the tenant, and
  remote-network mode can create a Gateway object only with an X.509 CA gwops generated and
  registered. So:
  - **BYO X.509 CA** (with either SSH CA): pinned-gateway mode (`twingate.gateway_id`).
  - **BYO SSH CA with a generated X.509 CA**: either mode. In remote-network mode gwops creates
    the Gateway object with no SSH CA bound; bind yours to it on the tenant. This has not been
    run against a tenant: test it before you rely on it, or use pinned-gateway mode.

  See [Choose how gwops finds the Gateway object](gateway-modes.md).
- Access to the Admin Console or the Twingate API, to register the CA and bind it to the Gateway
  object.

## Steps

1. Put the CA files in a directory on the Docker host, for example `./ca/`, and make them readable
   by uid 10001:

   ```sh
   mkdir -p ca
   cp /path/to/x509-ca.crt /path/to/x509-ca.key /path/to/ssh-ca.key /path/to/ssh-ca.key.pub ca/
   sudo chown 10001:10001 ca/*
   chmod 0600 ca/x509-ca.key ca/ssh-ca.key
   chmod 0644 ca/x509-ca.crt ca/ssh-ca.key.pub
   ```

2. Mount the directory read-only. gwops uses the paths exactly as given and does not confine them
   to a root, so any readable path works; a read-only mount under `/config/` keeps the keys out of
   the writable `/data` volume. In `compose.yaml`, under `volumes:` of the `gateway` service:

   ```yaml
   - ./ca:/config/ca:ro
   ```

3. Point the seed at the files:

   ```yaml
   ca:
     x509:
       generate: false
       cert_path: /config/ca/x509-ca.crt
       key_path: /config/ca/x509-ca.key
     ssh:
       generate: false
       key_path: /config/ca/ssh-ca.key   # gwops reads /config/ca/ssh-ca.key.pub beside it
   # ...rest of your seed
   ```

   `generate: false` without the paths is a seed error:
   `x509 CA with generate=false requires cert_path and key_path`, or
   `ssh CA with generate=false requires key_path`. Leave out the `x509` or `ssh` block you do not
   bring; that CA is generated.

4. On the tenant, register your X.509 CA certificate (the certificate in `cert_path`) and your SSH
   CA public key as certificate authorities, and bind both to the Gateway object. gwops does not do
   this for a BYO CA. See the [Twingate documentation](https://www.twingate.com/docs).
5. Start or restart the container: `docker compose up -d`.

gwops validates the X.509 CA at startup. Unusable material aborts startup with
`supervisor.startup_failed`, naming the file and the problem, for example:

```text
X.509 CA material at /config/ca/x509-ca.crt / /config/ca/x509-ca.key is unusable: the CA private key at /config/ca/x509-ca.key is RSA but only EC keys are supported for signing leaves; supply an EC (P-256) CA key.
```

Other refusals: a certificate that is not a CA, an expired or not-yet-valid certificate, a key that
cannot be loaded (encrypted, or not PEM), a key that does not match the certificate, and only one
of the two files present. For the SSH CA, gwops checks that both halves exist; the gateway itself
reads the private key.

### What gwops does with your CA

- Mints a leaf covering every served name, valid 90 days, signed by your X.509 CA. The leaf file
  carries the leaf and your CA certificate. gwops re-mints it 14 days before expiry and whenever the
  set of served names changes.
- Renders your SSH CA key path into the gateway config. The gateway signs 5-minute user
  certificates with it.
- Never writes to your CA files and never rotates them. `POST /certs/rotate-ca` answers `409`
  with `the X.509 CA is bring-your-own (ca.x509.generate=false); gwops does not rotate operator-owned CA material`.
- Reports web apps with `downstream.tls: tls13` with the readiness reason `byo_ca`: browser trust is
  whatever your CA already has.

### Replace a BYO CA

gwops reads the CA files on every reconcile pass, so new files take effect without a restart.

1. Register the new CA on the tenant.
2. Replace the certificate and key together. A mismatched pair is a local error
   (`CA material is unusable: ...`) and the gateway keeps running on its last good config.
3. Run a pass at once so gwops re-mints the leaf under the new CA (`BASE` and `TOKEN` as set in
   [Verify](#verify)):

   ```sh
   curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/reconcile
   ```

4. Bind the Gateway object to the new CA on the tenant.

Between steps 3 and 4 the leaf is signed by a CA the tenant does not yet bind to the gateway, so
Clients may refuse new connections. Keep the gap short. With
[on-demand issuance](on-demand-issuance.md) on, also restart the container
(`docker compose restart gateway`): the gateway's issuer loads the CA when it starts, and gwops does
not restart the gateway for a BYO CA change.

For a BYO SSH CA, replace `ssh-ca.key` and `ssh-ca.key.pub` together, update the CA on the tenant,
and roll the new public key out to SSH targets.

## Verify

```sh
export BASE=http://127.0.0.1:8081
export TOKEN=<admin-token>   # the GWOPS_ADMIN_TOKEN value from .env

curl -s -H "Authorization: Bearer $TOKEN" $BASE/status | jq '.certs'
```

- `certs.x509_ca_not_after` is your CA certificate's expiry.
- `certs.leaf_state` is `ok` once an upstream is declared.
- `last_reconcile.actions` contains no `registered X.509 CA` or `registered SSH CA` line: gwops
  registers nothing for a BYO CA.

To confirm the leaf chains to your CA, copy it out and check it with OpenSSL on the host:

```sh
docker compose exec gateway cat /data/pki/leaf/fullchain.pem > leaf.pem
openssl verify -CAfile ca/x509-ca.crt leaf.pem
```

## Roll back

To return to generated CAs, remove `generate: false` and the paths (or the whole `ca` block) and
restart. gwops then generates a CA, if none exists at `/data/pki/`, registers it on the tenant and
binds the Gateway object to it, and re-mints the leaf. SSH targets and browsers must then trust the
generated CAs; see [Use gwops-generated CAs](private-ca-generated.md).

## Related

- [Certificates](../architecture/certificates.md): bring-your-own validation and leaf minting.
- [Seed reference: `ca`](../reference/seed.md#ca)
- [Choose how gwops finds the Gateway object](gateway-modes.md)
- [On-demand issuance](on-demand-issuance.md)
