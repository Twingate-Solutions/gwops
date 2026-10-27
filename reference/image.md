# Image reference

The image runs the official Twingate Gateway binary under gwops. It is built from one multi-stage
`Dockerfile` that copies the `gateway` binary out of the official `twingate/gateway` image and the
`lego` ACME client out of the official `goacme/lego` image onto `python:3.12-slim`. All three
images are pinned by tag and digest, and gwops's Python dependencies are installed from a
hash-locked file.

## Published image

| Property | Value |
| --- | --- |
| Registry path in `compose.yaml` | `ghcr.io/twingate-solutions/gwops` |
| Platform | `linux/amd64` only |
| Tags from a `vX.Y.Z` git tag push | `:<commit-sha>` and `:X.Y.Z` |
| Tags from a manual workflow run | `:<commit-sha>`, plus `:latest` only when the run sets `tag_latest: true` |
| Base image | `python:3.12-slim`, pinned by digest (`PYTHON_TAG`, `PYTHON_DIGEST`) |
| Entrypoint | `python -m gwops` (gwops is PID 1) |

`:latest` moves only when a maintainer opts in, so pin a version tag (`:X.Y.Z`) or a commit tag
for a reproducible deployment. The shipped `compose.yaml` uses `pull_policy: missing`: run
`docker compose pull` to fetch a newer image. If the GHCR package is private, run
`docker login ghcr.io` first.

The gwops version is set at build time (`GWOPS_VERSION`): the git tag without its leading `v` for
a tag build, `0.0.0-dev.<7-char sha>` for other workflow builds, and `0.0.0-dev` for a local build.

## Ports

| Port | Owner | Purpose | `compose.yaml` publishes |
| --- | --- | --- | --- |
| 8443 | gateway | Gateway listener. Clients reach it through a Connector, so the Connector must reach this port. | `8443:8443` |
| 9090 | gateway | The gateway binary's metrics server (`metricsPort: 9090` in the rendered config; it serves `/metrics`). | `127.0.0.1:9090:9090` |
| 8081 | gwops | Admin API, plain HTTP. Binds `admin_api.bind` (default `127.0.0.1`) inside the container; the published port reaches it only with `admin_api.bind: 0.0.0.0`. | `127.0.0.1:8081:8081` |

All three are declared with `EXPOSE`. The gateway ports are fixed by the rendered config; the
admin API port is `admin_api.port` in the seed.

> **Security:** the admin API is plain HTTP. Do not publish it on a routable interface without a
> TLS proxy in front.

## Mounts

| Path | Kind | Purpose |
| --- | --- | --- |
| `/config/seed.yaml` | read-only bind mount, required | The [seed](seed.md). Never written. |
| `/config/k8s-creds/` | read-only mount, optional | Kubernetes bearer token and CA files (`k8s_clusters[].bearer_token_file`, `ca_file`). |
| `/config/webapp-cas/` | read-only mount, optional | Web-app upstream CA bundles (`web_app_proxy.upstream_ca_bundles[].file`). |
| `/config/public-tls/` | read-only mount, optional | Public certificate and key files (`public_tls.certificates[]` with `source: file`). |
| `/config/acme/` | read-only mount, optional | The Cloudflare API token file for ACME (`public_tls.acme.token_file`, default `/config/acme/cloudflare-token`). |
| `/data` | named volume or host directory, required for persistence | All state; see [Data volume layout](#data-volume-layout). Declared with `VOLUME`. |
| `/run/gateway` | tmpfs (in `compose.yaml`) | The rendered gateway config. |
| `/tmp` | tmpfs (in `compose.yaml`) | Scratch space. |

The four `/config/` directories are confined roots. gwops reads a file from one only if its
resolved path (after symlinks and `..`) stays under that root and it is a regular file of at most
1 MiB. The token file under `/config/acme/` is the exception to the size read: gwops only checks
that it exists, is a regular non-empty file and resolves under the root; lego reads it.

Files must be readable by uid 10001. A bind-mounted `/data` must be writable by uid 10001.

If `./seed.yaml` does not exist when you run `docker compose up`, Docker creates a directory at
that path and startup fails. Copy `seed.example.yaml` to `seed.yaml` first.

Bring-your-own CA paths (`ca.x509.cert_path`, `key_path`, `ca.ssh.key_path`) are not confined:
they are used as given. Put them on a read-only mount such as `/config/ca/`.

## Data volume layout

```text
/data/
├── state.json                   ownership registry: tenant objects gwops created (atomic writes)
├── overlays/
│   └── <NNNN>-<slug>.json       one file per admin-API change, applied in name order
├── pki/
│   ├── x509-ca.crt              generated X.509 CA certificate (0644)
│   ├── x509-ca.key              generated X.509 CA key, EC P-256 (0600)
│   ├── ssh-ca.key               generated SSH CA key, ed25519 (0600)
│   ├── ssh-ca.key.pub           SSH CA public key, OpenSSH format (0644)
│   ├── leaf/                    atomic store for the gwops-minted TLS leaf
│   │   ├── fullchain.pem        -> ..data/fullchain.pem (leaf then CA, 0644)
│   │   ├── privkey.pem          -> ..data/privkey.pem (0600)
│   │   ├── ..data               -> ..<sha12>
│   │   └── ..<sha12>/           the current generation
│   ├── staged/                  a new X.509 CA awaiting promotion (CA rotation)
│   └── archive/                 X.509 CAs displaced by a completed rotation
├── k8s-creds/                   content-addressed copies: <name>-token-<sha12> (0600),
│                                <name>-ca-<sha12>.crt (0644)
├── upstream-ca/                 content-addressed CA bundle copies: <name>-<sha12>.pem
├── spool/                       recording spool (0700), only with recording on
│   ├── 0000001.ndjson           segments of at most 4 MiB (0600)
│   └── cursor.json              committed delivery position
├── public-tls/                  public certificate mode only
│   └── <name>/                  atomic store, same layout as pki/leaf/
└── acme/                        ACME state (0700), public certificate mode with source: acme
    ├── state.json               per-certificate attempts, backoff and next attempt time
    └── lego/<host[_port]>/      lego's storage for one ACME directory host
        ├── accounts/            ACME account key and registration
        └── certificates/        what lego issued (never served from here)
```

Notes:

- The CA files above are the generated ones. Bring-your-own CA files stay where the seed points.
- Leaf and public certificates are installed by writing a whole new generation directory and
  swapping the `..data` symlink, then deleting the previous generation. The gateway reloads on
  that deletion, so a re-minted leaf or a renewed public certificate needs no restart.
- Credential and CA-bundle copies are named by a digest of their content, so a changed source file
  changes the path in the rendered config and restarts the gateway. Copies that neither the
  current config nor its last-good copy reference are removed after a successful pass.
- `upstream-ca/` copies are written only while at least one web app is declared.
- gwops validates what lego writes and installs it into `public-tls/<name>/`; staging and
  production use different `lego/` subdirectories and never share files.
- A `pki/leaf.crt` and `pki/leaf.key` from an older layout are not read and are removed after the
  first successful leaf install.

What each part means for backups is in [Backup and restore](../operations/backup-and-restore.md).

## Runtime user and filesystem

| Property | Value |
| --- | --- |
| User | `gwops`, uid 10001, gid 10001, home `/home/gwops`, shell `/usr/sbin/nologin` |
| Gateway binary | `/usr/local/bin/gateway`, started as `gateway start --config /run/gateway/config.yaml` |
| lego binary | `/usr/local/bin/lego`, always run with an explicit `--path` under `/data/acme/lego/` |
| Writable paths | `/data` and `/run/gateway` (owned by uid 10001 in the image), `/tmp` |
| Files in `/run/gateway` | `config.yaml` (live), `config.yaml.next` (pre-flight candidate), `config.yaml.last-good` (rollback copy) |

gwops, the gateway and lego all run as uid 10001. The shipped `compose.yaml` also sets
`stop_grace_period: 40s`, so Docker waits for gwops' 30 s gateway drain before it kills the
container, and adds:

```yaml
security_opt:
  - "no-new-privileges:true"
cap_drop:
  - ALL
read_only: true
tmpfs:
  - /run/gateway:mode=1777
  - /tmp:mode=1777
```

No capability is needed: the gateway listens on unprivileged ports.

## Healthcheck

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
    CMD ["python", "-m", "gwops.healthcheck"]
```

`gwops.healthcheck` sends one unauthenticated `GET /healthz` to the admin API and exits `0` only on
HTTP 200, `1` otherwise (including connection errors and its own 4 s timeout). It reads the
effective `admin_api.bind` and `admin_api.port` from the seed and overlays. A bind of `0.0.0.0`,
`::`, `localhost` or `127.0.0.1` is probed on `127.0.0.1`; any other bind address is probed
directly. If the seed cannot be loaded, it probes `127.0.0.1:$GWOPS_HEALTHCHECK_ADMIN_FALLBACK` (default 8081).

`/healthz` is 200 when the gateway process is `running` or `starting` and the last reconcile pass
had no local failure (or none has finished). Tenant-side problems never make the container
unhealthy. Because the admin API reads `admin_api.port` only at startup, changing the port in the
seed makes the healthcheck probe the new port before the server listens on it; restart after
changing it. See [Health and observability](../architecture/health-and-observability.md).

## Build arguments

| Argument | Default | Constraint (the build fails otherwise) | Meaning |
| --- | --- | --- | --- |
| `GATEWAY_TAG` | `2.0.0` | `^2\.[0-9]+\.[0-9]+(-dev-[0-9a-f]{7,40})?$` (so `latest`, `dev`, `2`, `2.0` and 1.x are refused) | Tag of `twingate/gateway` used as the binary source. Baked into the image as `GWOPS_GATEWAY_VERSION`. |
| `GATEWAY_DIGEST` | the pinned image-index digest | Non-empty, `sha256:<64 hex>` | The binary is copied from `twingate/gateway:$GATEWAY_TAG@$GATEWAY_DIGEST`. |
| `LEGO_TAG` | `v5.5.2` | `^v5\.[0-9]+\.[0-9]+$` | Tag of `goacme/lego` used as the binary source. |
| `LEGO_DIGEST` | the pinned image-index digest | Non-empty, `sha256:<64 hex>` | The binary is copied from `goacme/lego:$LEGO_TAG@$LEGO_DIGEST`. |
| `PYTHON_TAG` | `3.12-slim` |  | Tag of the `python` base image. |
| `PYTHON_DIGEST` | the pinned image-index digest | Non-empty | The runtime stage is built `FROM python:$PYTHON_TAG@$PYTHON_DIGEST`. |
| `GWOPS_VERSION` | `0.0.0-dev` | `^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$` | gwops release version, written into the package at build time and reported in the Twingate API `User-Agent`. Not an `ENV`. |

Docker pulls by digest and ignores the tag, so a tag and digest that do not match would bake the
wrong `GWOPS_GATEWAY_VERSION` over the binary. `make verify-pin` (run by `make image`) and the
`build-images` workflow check that the tag still resolves to the digest.

```sh
docker build \
  --build-arg GATEWAY_TAG=2.0.0 \
  --build-arg GATEWAY_DIGEST=sha256:4993a7db015f7c2091d55f1c7a36c3e0c277137cb9937a46e9ced2c17456a6d1 \
  -t gwops-gateway:dev .
```

See [Build and publish](../operations/build-and-publish.md).

## Pinned binaries

| Binary | Source image | Tag | Image-index digest |
| --- | --- | --- | --- |
| Twingate Gateway | `twingate/gateway` | `2.0.0` | `sha256:4993a7db015f7c2091d55f1c7a36c3e0c277137cb9937a46e9ced2c17456a6d1` |
| lego | `goacme/lego` | `v5.5.2` | `sha256:1944e8c36055beec47c7de6f15202b41128be75eea0ffa257f0c14d93c5155fd` |
| Python base image | `python` | `3.12-slim` | `sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f` |

gwops renders only the gateway 2.0 configuration schema. The gateway binary has no
config-validate subcommand, no SIGHUP reload and no recording sink; gwops pre-flights candidate
configs by spawning the binary, drain-restarts it on config changes and reads recordings from its
stderr. The pin lives in several files that must change together; `tests/test_pin.py` checks that
they agree. See [Upgrades and pins](../operations/upgrades-and-pins.md).

## Python dependencies

gwops's runtime dependencies are pinned to exact versions (`==`) in `pyproject.toml`. The image
installs them from `requirements.lock` at the repository root, which pins every package,
transitive ones included, with sha256 hashes. The Dockerfile runs
`pip install --require-hashes --only-binary=:all: -r requirements.lock`, so the build installs
nothing unpinned or unhashed and compiles nothing from source. The lock's header holds the
command that regenerates it. See [Upgrades and pins](../operations/upgrades-and-pins.md).

Source of the gateway binary: [github.com/Twingate/gateway](https://github.com/Twingate/gateway).
lego documentation: [go-acme.github.io/lego](https://go-acme.github.io/lego/).

## Network egress

| From | To | When | Notes |
| --- | --- | --- | --- |
| gwops | `https://<network>.<host>/api/graphql/` | `TWINGATE_API_KEY` set | Resource, CA and Gateway object sync. `X-API-KEY` header, 30 s timeout. |
| gwops | `https://<network>.<host>/api/v1/jwk/ec` | always | Reachability check of the tenant's token-signing keys, at startup and every `GWOPS_RECONCILE_TICK_SECONDS`. 5 s timeout, no credentials. |
| gwops | `<recording.receiver_url>/ingest` | `recording.enabled: true` and `GWOPS_RECORDING_TOKEN` set | Recording delivery; see [Recording wire format](recording-wire-format.md). |
| gwops | each web-app upstream `host:port` | `web_app_proxy.upstream_tls_probe: true` | One TLS 1.3 handshake, then close. Dialled directly, ignoring proxy variables. At most 4 at once, 5 s each. |
| gateway | `https://<network>.<host>/api/v1/jwk/ec` | always | The tenant's token-signing keys, fetched by the binary itself. |
| gateway | SSH, Kubernetes and web-app upstreams | when declared | Dialled from the container's network namespace, using the container's resolver. |
| lego | the ACME directory | `public_tls.acme` configured | `https://acme-staging-v02.api.letsencrypt.org/directory` (`staging`), `https://acme-v02.api.letsencrypt.org/directory` (`production`) or your `https://` URL. Proxy variables honoured. |
| lego | `https://api.cloudflare.com` | `public_tls.acme` configured | Creates and removes the `_acme-challenge` TXT records and looks up the zone. Proxy variables honoured. |
| lego | the container's DNS resolver | `public_tls.acme` configured | CNAME following, zone discovery and the propagation check. Never proxied. |
| lego | the zone's authoritative nameservers, UDP and TCP 53 | `public_tls.acme.propagation: authoritative` | Never proxied. |

Inbound, only the Connector needs to reach 8443. Nothing in the container needs to be reachable
from the internet: ACME uses DNS-01.

Behind an outbound proxy, `NO_PROXY` must include `127.0.0.1,localhost`: the healthcheck calls
the admin API on loopback with httpx, which honours the proxy variables, and without those entries
the container turns unhealthy. The shipped `compose.yaml` defaults `NO_PROXY` to exactly that;
keep both entries if you override it. httpx does not match CIDR entries in `NO_PROXY`, so list the exact
hosts gwops calls directly. See [Environment: variables that gwops' own HTTP clients
read](environment.md#variables-that-gwops-own-http-clients-read) and
[Restricted egress and outbound proxies](../recipes/restricted-egress.md).

## Gateway child environment

The gateway process gets a new environment built from an exact allowlist, never the inherited
one. The same applies to the pre-flight spawn of a candidate config.

| Variable | Why it passes |
| --- | --- |
| `PATH`, `HOME`, `LANG`, `LC_ALL`, `TZ` | Process, locale and time zone. |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | Outbound certificate verification. |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and their lowercase forms | Proxy settings. |
| `GOMEMLIMIT`, `GOMAXPROCS`, `GOGC`, `GODEBUG` | Go runtime tuning. |

Names match exactly and case-sensitively. No secret reaches the gateway: `TWINGATE_API_KEY`,
`GWOPS_ADMIN_TOKEN`, `GWOPS_AUTOMATION_TOKEN`, `GWOPS_RECORDING_TOKEN`, every other `TWINGATE_*`,
`GWOPS_*` and `CF_*` variable are dropped. The binary reads no variable of its own except
`TWINGATE_CONFIG`, which the `--config` flag makes inert. Passing another variable requires a code
change to `src/gwops/supervisor/childenv.py`.

> **Security:** `GODEBUG` can re-enable legacy TLS and X.509 behaviour in the gateway. Do not set
> it in production unless directed.

The gateway runs as the same uid as gwops, so it can read every file gwops can, including the CA
and leaf keys under `/data/pki/`, lego's keys under `/data/acme/` and the mounted DNS token file.

lego receives the same allowlist minus `CF_*`, `CLOUDFLARE_*`, `LEGO_*` and `GODEBUG`, plus the
two token-file variables; see [Environment](environment.md#variables-passed-to-lego).

## System CA roots

The image's trust store is the Debian `ca-certificates` bundle from `python:3.12-slim`, at
`/etc/ssl/certs/ca-certificates.crt` with hashed links in `/etc/ssl/certs/`.

- gwops' JWKS check and upstream TLS probe trust that store; `SSL_CERT_FILE` and `SSL_CERT_DIR`
  override it.
- The gateway verifies web-app upstreams against the system roots plus
  `web_app_proxy.upstream_ca_bundles`. That the Go binary reads `/etc/ssl/certs` follows from the
  Go standard library on Linux.
- In public certificate mode, gwops finds ISRG Root X1 in that bundle by its SHA-256 fingerprint
  (`96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6`). If a base-image update
  drops or changes the root, startup aborts rather than registering a different certificate.

The Twingate API client and the recording shipper use httpx's default trust; see
[Environment](environment.md#variables-that-gwops-own-http-clients-read).

## Clock

The container uses the host clock; gwops neither sets nor checks it. Keep the host on NTP.

- The gateway applies no leeway to the issue time (`iat`) of a web-app access token. A gateway
  clock behind the tenant's rejects a fresh token with `401` (`token used before issued`) until
  the clock catches up.
- Certificate validity checks (the leaf, CAs, public certificates) and ACME scheduling use the
  container clock.
