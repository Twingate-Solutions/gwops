# Environment reference

gwops reads secrets and a few runtime settings from environment variables. Secrets never go in
the seed, in overlays or in any file under version control. With the shipped `compose.yaml`,
variables come from `.env` in the same directory.

## Secrets

| Variable | Required when | Effect when unset |
| --- | --- | --- |
| `TWINGATE_API_KEY` | You want resources, CAs and the Gateway object synced to the tenant. | gwops logs `supervisor.tg_sync_disabled` at startup. Local steps (certificates, rendered config, the gateway process) still run; every pass records an error starting `TG sync skipped: TWINGATE_API_KEY is not set`. Admin API writes that change upstreams cannot be confirmed on the tenant, so they are rolled back with `503`. `/healthz` is unaffected. |
| `GWOPS_ADMIN_TOKEN` | You use the admin API. | gwops logs `api.admin_token_unset`; every route except `GET /healthz` answers `401`. |
| `GWOPS_AUTOMATION_TOKEN` | An unattended caller manages upstreams through the admin API. | The automation principal does not exist. When set, it must differ from `GWOPS_ADMIN_TOKEN` and the seed must define both `twingate.access_allowlist` and `twingate.address_allowlist`, or startup aborts. |
| `GWOPS_RECORDING_TOKEN` | `recording.enabled: true`. | gwops logs `supervisor.shipper_token_missing`; kept lines spool to `/data/spool` (bounded) and ship only after a restart supplies the token. |

`GWOPS_RECORDING_TOKEN` is sent as `Authorization: Bearer <token>` to the recording receiver: any
service that implements the [recording wire format](recording-wire-format.md).

The shipped `compose.yaml` refuses to start (`docker compose up` fails) when `TWINGATE_API_KEY` or
`GWOPS_ADMIN_TOKEN` is unset. `GWOPS_RECORDING_TOKEN` and `GWOPS_AUTOMATION_TOKEN` are commented out in
both `compose.yaml` and `.env.example`; uncomment them in both files to use them.

Generate tokens with a strong random value, for example `openssl rand -hex 32`.

## Settings

Settings use the `GWOPS_` prefix. The defaults are the container's canonical paths and rarely need
changing.

| Variable | Default | Constraints | Purpose |
| --- | --- | --- | --- |
| `GWOPS_SEED_PATH` | `/config/seed.yaml` |  | Path of the seed. |
| `GWOPS_DATA_DIR` | `/data` |  | Persistent state root. |
| `GWOPS_RUNTIME_DIR` | `/run/gateway` |  | Where the rendered gateway config is written. |
| `GWOPS_GATEWAY_BINARY` | `/usr/local/bin/gateway` |  | Path of the gateway binary. |
| `GWOPS_LEGO_BINARY` | `/usr/local/bin/lego` | Absolute path, or settings validation fails. | Path of the lego ACME client. |
| `GWOPS_LEGO_TIMEOUT_SECONDS` | `600` | Greater than 0 and at most 3600. | Wall-clock limit for one lego run; gwops then kills it and records a `timeout` failure. |
| `GWOPS_RECONCILE_TICK_SECONDS` | `600` |  | Interval of the periodic reconcile pass, in addition to event-driven triggers. Also the interval of the JWKS reachability check. |
| `GWOPS_GATEWAY_VERSION` | empty; the image sets it to the `GATEWAY_TAG` build argument |  | The wrapped gateway version, reported in `/status` `capabilities.gateway_version`. Never enforced. |
| `GWOPS_HEALTHCHECK_ADMIN_FALLBACK` | `8081` | A port number. | Used only by the healthcheck as its fallback port when the seed cannot be loaded. The admin API itself listens on the seed's `admin_api.port`. |

A settings validation failure stops gwops before it reads the seed.

gwops reads only the variables listed on this page. Any other `GWOPS_*` variable is ignored,
including the service-link variables Kubernetes injects for a Service whose name starts with
`gwops` (such as `GWOPS_ADMIN_SERVICE_HOST` or `GWOPS_ADMIN_PORT`). No setting ends in `_PORT`, so
those variables cannot collide with one.

## Variables passed to the gateway

The gateway process receives a new environment built from an exact allowlist. Names match exactly
and case-sensitively; nothing else is passed, including every `TWINGATE_*`, `GWOPS_*` and
`CF_*` variable.

| Variable | Why it passes |
| --- | --- |
| `PATH`, `HOME`, `LANG`, `LC_ALL`, `TZ` | Process, locale and time zone. |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | Outbound certificate verification. |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `http_proxy`, `https_proxy`, `no_proxy` | Proxy settings. |
| `GOMEMLIMIT`, `GOMAXPROCS`, `GOGC`, `GODEBUG` | Go runtime tuning. |

> **Security:** `GODEBUG` is passed through to the gateway and can re-enable legacy TLS and X.509
> behaviour. Do not set it in production unless directed.

The same allowlist applies to the pre-flight spawn of a candidate config. See
[Gateway child environment](image.md#gateway-child-environment).

## Variables passed to lego

lego receives the gateway allowlist above, minus any variable whose name starts with `CF_`,
`CLOUDFLARE_` or `LEGO_` (case-insensitive) and minus `GODEBUG`, plus:

| Variable | Value |
| --- | --- |
| `CF_DNS_API_TOKEN_FILE` | The resolved path of `public_tls.acme.token_file`. |
| `CF_ZONE_API_TOKEN_FILE` | The same path. |

gwops never reads the token file and never places the token in an environment or command line.

> **Security:** `SSL_CERT_FILE`, `SSL_CERT_DIR` and the proxy variables also reach lego. A CA
> supplied that way, or a proxy that terminates TLS with such a CA, can read the Cloudflare API
> connection and the DNS token on it. Add a CA there only if you trust it with that token.

## Variables that gwops' own HTTP clients read

gwops' Twingate API client, recording shipper, JWKS check and healthcheck honour `HTTP_PROXY`,
`HTTPS_PROXY` and `NO_PROXY`. The upstream TLS probe does not: it dials directly.

The shipped `compose.yaml` sets `NO_PROXY: ${NO_PROXY:-127.0.0.1,localhost}` and carries
`HTTPS_PROXY` and `HTTP_PROXY` lines commented out. When you set `HTTP_PROXY` or `HTTPS_PROXY`:

- **`NO_PROXY` must include `127.0.0.1,localhost`.** The healthcheck (`python -m gwops.healthcheck`)
  calls `http://127.0.0.1:<admin port>/healthz` with httpx and the container's environment.
  Without those entries that request goes to the proxy, fails, and the container turns
  unhealthy. The shipped default has them; if you set your own `NO_PROXY` in `.env`, keep them.
- **List exact hosts in `NO_PROXY`.** httpx matches host names, domain suffixes
  (`.internal.example.com`) and exact IP addresses, but not CIDR ranges: `10.0.0.0/8` does not
  exempt `10.1.2.3`. Name every internal host gwops calls, such as a recording receiver.

See [Restricted egress and outbound proxies](../recipes/restricted-egress.md) for a complete
deployment.

For certificate verification, the JWKS check and the upstream TLS probe use the image's system
trust store (`/etc/ssl/certs/ca-certificates.crt`), which `SSL_CERT_FILE` and `SSL_CERT_DIR`
override. The Twingate API client and the recording shipper use the httpx defaults: with
httpx 0.28, a bundled CA list unless `SSL_CERT_FILE` or `SSL_CERT_DIR` is set, in which case
that file or directory replaces it. To trust a private CA for a recording receiver, point
`SSL_CERT_FILE` at a bundle that contains the public roots and your CA, then test delivery.
`SSL_CERT_FILE` also reaches the gateway and lego, so the bundle must still verify the Twingate
tenant, web-app upstreams and the ACME and Cloudflare endpoints.

## Variables ignored on purpose

| Variable | What happens |
| --- | --- |
| `CF_*`, `CLOUDFLARE_*` | Never passed to lego. When the seed has `source: acme` certificates and any such variable is in gwops' environment, startup logs `supervisor.acme_cloudflare_environment_ignored` with the variable names (never values). The DNS token comes only from `public_tls.acme.token_file`. |
| `LEGO_*` | Never passed to lego. |
| `TWINGATE_CONFIG` | Not passed to the gateway, and inert anyway: gwops always starts the binary with `--config /run/gateway/config.yaml`. |

## Build arguments

Build-time arguments are not runtime environment variables, except `GATEWAY_TAG`, which the image
bakes into `GWOPS_GATEWAY_VERSION`. See [Build arguments](image.md#build-arguments) for
`GATEWAY_TAG`, `GATEWAY_DIGEST`, `LEGO_TAG`, `LEGO_DIGEST` and `GWOPS_VERSION`.
