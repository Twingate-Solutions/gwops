# Issue public certificates with ACME

> **Security:** Public certificate mode registers ISRG Root X1 as the Gateway object's X.509 CA, so
> a Client accepts any certificate that chains to that root for the names it dials through the
> gateway. Read the caveat in [Serve public certificates from files](public-certs-files.md) first.

With `source: acme`, gwops issues and renews a public certificate itself. It runs
[lego](https://go-acme.github.io/lego/), which the image carries, against Let's Encrypt (or another
ACME directory) and answers the DNS-01 challenge through the Cloudflare API. Everything else about
public certificate mode, including the coverage rule, validation and the registered root, is as in
[Serve public certificates from files](public-certs-files.md).

## When to use

Your served names are in a DNS zone hosted on Cloudflare, and you want gwops to keep the
certificates renewed. For any other DNS provider or CA, supply the certificates as files instead.

## Prerequisites

- Public certificate mode prerequisites: every served name is a DNS name inside a zone, and the seed
  has no `ca.x509` block.
- A Cloudflare zone for the names, for example `example.com`.
- A Cloudflare API token with `Zone:Read` and `DNS:Edit`, scoped to one zone only. For production,
  scope it to a dedicated challenge zone; see [Production hardening](#production-hardening).
- Outbound HTTPS from the container to the ACME directory (for Let's Encrypt,
  `acme-v02.api.letsencrypt.org` and `acme-staging-v02.api.letsencrypt.org`) and to
  `api.cloudflare.com`. With `propagation: authoritative`, also outbound UDP and TCP 53.
- A persistent `/data` volume. The ACME account and the renewal schedule live under `/data/acme/`;
  losing them means a new account and fresh orders, which count against the CA's rate limits.

## Steps

1. Write the token to a file on the Docker host, without putting it in your shell history, and
   make it readable by uid 10001:

   ```sh
   mkdir -p acme
   read -rs token && printf '%s' "$token" > acme/cloudflare-token && unset token
   sudo chown 10001:10001 acme/cloudflare-token
   chmod 0400 acme/cloudflare-token
   ```

2. Mount the directory read-only. In `compose.yaml`, under `volumes:` of the `gateway` service:

   ```yaml
   - ./acme:/config/acme:ro
   ```

   The token file must be a non-empty regular file under `/config/acme/`; a symlink must resolve
   inside it. gwops only checks that the file is usable and never reads it. lego reads it.

   > **Security:** The gateway process runs as the same uid as gwops and can read the token file.
   > Scope the token as narrowly as you can.

3. Add `public_tls` with an `acme` block and a `source: acme` certificate. Start on `staging`:

   ```yaml
   public_tls:
     zones: ["example.com"]
     registered_root: isrg_root_x1
     acme:
       email: ops@example.com
       accept_tos: true
       directory: staging
       token_file: /config/acme/cloudflare-token
     certificates:
       - name: wildcard
         names: ["*.apps.example.com"]
         source: acme
   # ...rest of your seed
   ```

   | Key | Default | Meaning |
   | --- | --- | --- |
   | `acme.email` | (required) | ACME account contact. Changing it registers a new account. |
   | `acme.accept_tos` | `false` | Must be `true`: you accept the CA's terms of service. |
   | `acme.directory` | `staging` | `staging`, `production`, or an `https://` ACME directory URL. |
   | `acme.provider` | `cloudflare` | The only provider. |
   | `acme.propagation` | `resolver` | `resolver` checks the TXT record through the container's resolver; `authoritative` also queries the zone's authoritative nameservers. |
   | `acme.token_file` | `/config/acme/cloudflare-token` | Must be under `/config/acme/`. |
   | `certificates[].challenge_alias` | none | Optional; see [Production hardening](#production-hardening). |

   A `source: acme` certificate takes no `cert_file` or `key_file`.

4. Start or restart the container: `docker compose up -d`. Startup logs
   `supervisor.acme_staging_dry_run`, and `supervisor.waiting_for_acme` if every public certificate
   is a pending `source: acme` one.
5. Wait for the dry run. Staging issues from Let's Encrypt's staging CA and validates the result
   (everything except the chain to ISRG Root X1), then reports `dry_run_ok` and installs nothing,
   because Clients do not trust staging roots. Check:

   ```sh
   curl -s -H "Authorization: Bearer $TOKEN" $BASE/status | jq '.certs.public[] | {name, state, acme: .acme.state, error: .acme.error_code}'
   ```

   (`BASE` and `TOKEN` as set in [Verify](#verify).) Wait for `"acme": "dry_run_ok"`.
6. Switch to production in the seed and save it. Only `directory` changes:

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
       - name: wildcard
         names: ["*.apps.example.com"]
         source: acme
   # ...rest of your seed
   ```

   gwops picks up the change on its next pass; no restart is needed. lego issues the production
   certificate, gwops validates it, installs it under `/data/public-tls/<name>/` and runs a pass.
7. The gateway starts, or hot-reloads, once the first certificate is installed. While every public
   certificate is pending, the gateway is held down. With `directory: staging` that hold never ends.

### Renewal

lego decides when to renew: when the CA's renewal information (ARI) says so, or when a third of the
lifetime remains. gwops checks each certificate every 12 hours, with up to 1 hour of jitter either
way, and when its names or directory change. A renewed certificate is validated, installed and
hot-reloaded. A failed attempt never stops gwops and never affects `/healthz`; the installed
certificate keeps serving.

Failures back off: 15 minutes after the first, doubling to at most 24 hours. The backoff survives a
restart. After a `rate_limited` failure the next attempt waits at least 1 hour. When the failure is
one you fix (`config`, `dns_auth`, `dns_zone`), changing the ACME settings or the token file
releases the hold at once.

### Force an attempt

```sh
curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/certs/public/wildcard/issue
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"force": true}' $BASE/certs/public/wildcard/issue
```

`202` means the attempt is queued; read the outcome from `/status`. `force` renews even outside the
renewal window. `429` carries a `reason`:

| `reason` | Meaning |
| --- | --- |
| `backoff` | A recorded failure, a rate limit or an interrupted run holds the certificate. `force` does not skip it. |
| `force_window` | Production only: `force` was asked for and the installed certificate is under 24 hours old. A request without `force` is accepted. |
| `request_floor` | A request for this certificate was accepted less than 60 seconds ago. |

`409` means the certificate is `source: file`, an attempt is already running, or the ACME runner
cannot take work (for example the token file is missing); `detail` says which.

### Production hardening

Use `challenge_alias` so the Cloudflare token cannot edit your main zone.

1. Create a dedicated zone on Cloudflare that holds nothing else, for example
   `acme-challenges.example.net`.
2. For each challenge name, create a CNAME in your main zone from `_acme-challenge.<name>` to a
   name inside the dedicated zone. A wildcard `*.apps.example.com` and `apps.example.com` share
   `_acme-challenge.apps.example.com`.
3. Scope the token to the dedicated zone only (`Zone:Read`, `DNS:Edit`).
4. Set `challenge_alias` on the certificate:

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
       - name: wildcard
         names: ["*.apps.example.com"]
         source: acme
         challenge_alias: acme-challenges.example.net
   # ...rest of your seed
   ```

lego follows the CNAME and writes the TXT record in the dedicated zone. You create the CNAME; gwops
passes nothing extra to lego. A leaked token can then edit only the dedicated zone.

### Split-horizon DNS

If a LAN DNS server serves its own copy of your zone, it has no `_acme-challenge` record. lego's
check through it gets NXDOMAIN and the attempt fails with `dns_propagation`.
`propagation: authoritative` does not help: lego finds the authoritative nameservers through the
same resolver. Two setups work.

**Public resolvers plus `extra_hosts`.** Give the service public resolvers and pin each web-app name
to its upstream address:

```yaml
services:
  gateway:
    dns: [1.1.1.1, 1.0.0.1]
    extra_hosts:
      - "grafana.apps.example.com:10.0.0.11"
```

Every new web app, including one added through the admin API, then needs a compose edit and
`docker compose up -d` before it resolves.

**A LAN DNS server that forwards the challenge name.** Forward `_acme-challenge.<zone>` to a
public resolver and answer the served names locally. In dnsmasq or Pi-hole:

```text
server=/_acme-challenge.apps.example.com/1.1.1.1
address=/apps.example.com/10.0.0.11
```

The more specific `server=` line wins for the challenge name. Set `dns: [<LAN DNS IP>]` on the
service so the container does not depend on the host's resolver, and keep
`propagation: resolver`. New web apps then resolve with no compose change. Each distinct challenge
name needs its own forwarder line: `x.sub.apps.example.com` needs
`_acme-challenge.sub.apps.example.com`.

Check what the container resolves with `docker compose exec gateway getent hosts <name>`.

### Cloudflare variables are ignored

The token comes only from `token_file`. gwops never passes `CF_*` or `CLOUDFLARE_*` variables from
its own environment to lego, and logs `supervisor.acme_cloudflare_environment_ignored` with their
names at startup. Remove them from `.env` and `compose.yaml`.

## Verify

```sh
export BASE=http://127.0.0.1:8081
export TOKEN=<admin-token>   # the GWOPS_ADMIN_TOKEN value from .env

curl -s -H "Authorization: Bearer $TOKEN" $BASE/status | jq '.certs.public[] | {name, state, not_after, acme: (.acme | {state, staging, installed, error_code, next_attempt_at})}'
```

After the production certificate lands:

- the entry's `state` is `ok`, with a `not_after`;
- `acme.installed` is `true`, `acme.staging` is `false`, `acme.error_code` is `null`;
- `tls.mode` is `public` and `certs.registered_root.bound` is `true`.

While a certificate is not installed, web apps it covers report the readiness reason
`public_cert_pending:<cert>`, plus `acme_staging_dry_run:<cert>` on staging or
`acme_failed:<code>` after a failure.

### Common failures

| `acme.error_code` | Cause | Fix |
| --- | --- | --- |
| `dns_auth` | Cloudflare refused the token (400, 401 or 403). | Check the token file and that the token has `Zone:Read` and `DNS:Edit` on the zone, or on the alias zone with `challenge_alias`. |
| `dns_zone` | The token cannot see the zone, or the resolver cannot find its SOA record. | Check the token's zone scope and the container's DNS. |
| `dns_propagation` | The `_acme-challenge` TXT record was not seen in time. | Usually split-horizon DNS; see [Split-horizon DNS](#split-horizon-dns). |
| `rate_limited` | The CA rate-limited the request. | Wait; the next attempt waits at least 1 hour. Test on staging first. |
| `unauthorized` | The CA's validation failed, including CAA problems. | Check CAA records and that the challenge record is publicly visible. |
| `acme_unreachable` | The ACME directory or Cloudflare could not be reached, or answered with a server error. | Check egress; gwops retries with backoff. |
| `timeout` | lego ran longer than `GWOPS_LEGO_TIMEOUT_SECONDS` (default 600 s) and was stopped. | Check DNS propagation and egress. |
| `config` | A configuration problem, an unusable token file, or a problem only a configuration change fixes. | Read `acme.error_excerpt` and `acme.config_error`. |

`acme.error_excerpt` holds a short, redacted excerpt of lego's output; it never contains the
token.

## Roll back

- To stop serving the ACME certificate but stay in public mode, change it to `source: file` with
  your own files, as in [Serve public certificates from files](public-certs-files.md).
- To leave public mode, follow the rollback in
  [Serve public certificates from files](public-certs-files.md#roll-back).

gwops keeps the ACME account and state under `/data/acme/`. A certificate removed from the seed has
its state kept for 7 days and restored if you declare it again.

## Related

- [ACME](../architecture/acme.md): the runner, lego invocation, backoff and secrets.
- [Admin API: `POST /certs/public/{name}/issue`](../reference/admin-api.md#post-certspublicnameissue)
- [Admin API: `certs.public[].acme`](../reference/admin-api.md#certspublicacme)
- [Seed reference: `public_tls`](../reference/seed.md#public_tls)
- [Mix certificate sources](public-mode-mixed.md), [Web apps](web-apps.md)
- [Let's Encrypt documentation](https://letsencrypt.org/docs/),
  [Cloudflare documentation](https://developers.cloudflare.com/)
