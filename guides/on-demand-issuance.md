# Turn on on-demand issuance

> **Security:** With `ca.x509.on_demand_issuance: true`, a client that presents **any SNI to port
> 8443 receives a certificate for that name, signed by the gwops X.509 CA, before its access token
> is authenticated**. The client never receives the CA key. The exposure is that the gateway loads
> the CA private key and uses it on a path anyone who can reach port 8443 can trigger. If the CA is
> in browser trust stores, which is expected for a gwops-generated CA serving web apps with
> `downstream.tls: tls13`, or is a bring-your-own CA that devices already trust, such a certificate
> is accepted for any name. Turn it on only when that exposure is acceptable.

On-demand issuance lets the gateway serve a certificate for a name the gwops leaf does not cover.
The leaf stays the gateway's static certificate. A TLS handshake for a name the leaf covers gets the
leaf; a handshake for any other DNS name gets a certificate the gateway issues for that name on the
spot.

## When to use

Clients reach the gateway by DNS names that are not declared as upstream addresses or web-app
aliases, so the leaf cannot list them, and you accept the exposure above. In most deployments the
leaf already covers every served name and you do not need this mode.

On-demand issuance is not available in [public certificate mode](public-certs-files.md): a seed
with `public_tls` cannot carry a `ca.x509` block.

## Prerequisites

- Private CA mode: a [generated](private-ca-generated.md) or [bring-your-own](private-ca-byo.md)
  X.509 CA.
- The X.509 CA certificate has `basicConstraints` `CA:TRUE` and, if it has a `keyUsage` extension,
  `keyCertSign`. Its private key is an unencrypted PEM. A gwops-generated CA meets all three.
- Access to edit the seed. The key is seed-only.

## Steps

1. Set the key in the seed:

   ```yaml
   ca:
     x509:
       generate: true
       on_demand_issuance: true
   # ...rest of your seed
   ```

   With a bring-your-own CA, keep your `generate: false`, `cert_path` and `key_path` and add
   `on_demand_issuance: true`.

2. Save the seed. gwops picks up the change on its next pass, within a few seconds. The rendered
   gateway config gains `tls.automation.issuer.local`, pointing at the active X.509 CA files beside
   the leaf, so the gateway drain-restarts once to load it.

When the CA is not suitable, startup aborts (`supervisor.startup_failed`); after startup, the pass
records an error and the gateway keeps its previous config. Both name the file and the property,
for example:

```text
ca.x509.on_demand_issuance is true but the X.509 CA is unusable for the gateway's local issuer: the CA certificate /config/ca/x509-ca.crt has a keyUsage extension without keyCertSign (the gateway refuses an issuer certificate that cannot sign certificates). Supply a suitable CA or set ca.x509.on_demand_issuance to false.
```

### How issued certificates behave

- The gateway issues each certificate for the SNI name it was asked for, valid 24 hours.
- Issued certificates live in the gateway's memory only. A restart clears them.
- IP addresses are not covered: a client that dials an IP the leaf lacks gets no certificate for
  it. Keep IP-addressed upstreams in the leaf, which gwops does automatically.
- gwops still mints and checks the leaf exactly as without this mode.

### What gwops reports

- Every startup in this mode logs `tls.on_demand_issuance_active` at warning level, with the warning
  text. Turning the mode on with a seed edit logs it on the next pass; turning it off logs
  `tls.on_demand_issuance_disabled`.
- `/status` `tls.mode` is `static+on_demand` and `tls.warning` carries the exposure text. The text
  is stronger for a bring-your-own CA, and for a generated CA while any web app uses
  `downstream.tls: tls13`.
- In `web_apps.readiness[]`, a web-app name the leaf lacks but on-demand issuance covers is
  reported as `covered_on_demand:<name>` (informational) instead of `san_missing:<name>`. When the
  last pass's local steps failed, it is `on_demand_unavailable:<name>` (action required).

### CA rotation in this mode

`POST /certs/rotate-ca` with `{"phase": "complete"}` drain-restarts a running gateway so the issuer
loads the promoted CA. See [Rotate the leaf and the CA](../operations/ca-and-leaf-rotation.md#with-on-demand-issuance-on).
A bring-your-own CA you replace yourself needs a container restart for the issuer to load it.

## Verify

```sh
export BASE=http://127.0.0.1:8081
export TOKEN=<admin-token>   # the GWOPS_ADMIN_TOKEN value from .env

curl -s -H "Authorization: Bearer $TOKEN" $BASE/status | jq '.tls'
```

`tls.mode` is `static+on_demand` and `tls.warning` is set. In the logs:

```sh
docker compose logs gateway | grep tls.on_demand_issuance_active
```

## Roll back

Set `on_demand_issuance: false`, or remove the key, and save the seed. The next pass renders the
config without `tls.automation`, logs `tls.on_demand_issuance_disabled` and drain-restarts the
gateway. Names the leaf does not cover stop working. `/status` `tls.mode` returns to `static` and
`tls.warning` to `null`.

## Related

- [Certificates](../architecture/certificates.md): on-demand issuance and its exposure.
- [Security model](../architecture/security-model.md): accepted risks.
- [Seed reference: `ca`](../reference/seed.md#ca)
- [Admin API: `GET /status`](../reference/admin-api.md#get-status)
