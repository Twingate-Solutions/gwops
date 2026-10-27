# Known limitations

What the image and the wrapped gateway binary do not do, and the risks accepted by design. Each
group links the page that explains the mechanism.

## Platform

- The published image is `linux/amd64` only. ARM hosts, including Apple Silicon without
  emulation, cannot run it. See [Image reference](image.md#published-image).
- Upstream addresses and aliases are host names or IPv4 literals. IPv6 literals are not accepted.
- The base image (`python:3.12-slim`) is not pinned by digest, so a rebuild can pick up a newer
  base and trust store.

## Gateway binary

Mechanism: [Gateway process](../architecture/gateway-process.md).

- The binary has no config-validate subcommand. gwops infers whether a candidate config is
  accepted by spawning the binary on it for 5 s (pre-flight). While the gateway is running, only a
  schema error is detected this way, because the candidate cannot bind the busy ports.
- The binary has no SIGHUP reload. Any change to the rendered config is applied by a
  drain-restart, which drops the gateway's open connections. Certificate renewals hot-reload
  without a restart.
- The binary has no recording sink. gwops reads recordings from its stderr.
- gwops renders only the gateway 2.0 configuration schema; 1.x binaries are refused at build.
- If gwops' reader of a gateway output pipe fails (`gateway.reader_died`), nothing reads that pipe
  afterwards and the gateway blocks once it fills. Restart the container.

## Logs and recording

Mechanism: [Recording pipeline](../architecture/recording-pipeline.md).

- **`docker logs` does not carry gateway audit or recording lines.** The gateway writes its
  operational, audit and recording lines to stderr. gwops relays only the operational (`system`)
  lines into its own log, as `gateway.system` events, whether recording is on or off. A collector
  that reads `docker logs` sees gwops' events, the gateway's stdout and its operational lines
  (including user identity on `Authenticated connection` lines), never its HTTP or SSH audit lines
  or session recordings. Gateway audit and recording data leaves the container only through the
  recording pipeline.
- **The recording pipeline forwards three kinds of line only**: recording lines, HTTP audit lines
  (`API request completed`, `API request failed`) and `Authenticated connection` lines. SSH audit
  events (`SSH connection established`, `SSH connection closed`) and all other operational lines
  are dropped and counted.
- **The filter keys on the gateway's logger names** (`system`, `audit`, `session_recording`). A
  gateway release that renames a logger makes its lines drop as `not_allowlisted`, with no error
  beyond the drop counters. Check the names on every gateway pin change.
- **Shipped lines are not redacted.** They carry terminal output, request and response header
  values (`Authorization`, `Cookie`, `Set-Cookie`), full URLs with query strings, and user ids,
  usernames and groups. The spool and the receiver hold this data at rest. See
  [Recording wire format](recording-wire-format.md#content-is-not-redacted).
- **SSH recording covers interactive shells only.** An SSH `exec` or `subsystem` request produces
  no recording, and a recording holds the target's output and window resizes, not what the user
  typed.
- **Kubernetes recording covers interactive `exec` and `attach` sessions with a TTY.** Other API
  requests appear only as HTTP audit lines. Web-app traffic appears only as HTTP audit lines.
- **A gateway line over 16 MiB is dropped whole.** The SSH recorder does not apply the rendered
  256,000-byte segment cap, so one long session can be one very large line.
- **Peak memory per maximum-size line is about 200 MiB**: a 16 MiB line of non-ASCII text is
  parsed into memory at up to 4 bytes per character. `compose.yaml` sets no memory limit.
- **Delivery is at least once.** Receivers must deduplicate. The spool is bounded; when the
  receiver is unavailable long enough, the oldest undelivered lines are evicted (`spool.evicted`).
- **gwops cannot tell a forged line from a gateway line.** The gateway JSON-escapes the messages
  it logs, but text that reaches stderr unescaped from another path (Go runtime crash output, for
  example) and happens to match the filter is forwarded, and one that parses as a `system` line
  is relayed to `docker logs` as `gateway.system`.
- Recording settings are read only at startup. Changing `recording.*`, in the seed or an overlay,
  takes effect after a restart.

## Kubernetes

Mechanism: [Gateway process](../architecture/gateway-process.md).

- **One Kubernetes cluster per gateway.** The binary consumes a single `kubernetes.upstreams`
  entry; a second `k8s_clusters` entry is refused when the config is rendered. Run another
  container for another cluster.
- The automation token cannot manage Kubernetes clusters.
- In public certificate mode the in-cluster name `kubernetes.default.svc` cannot be served.

## SSH

Mechanism: [Certificates](../architecture/certificates.md).

- **SSH port forwarding is neither gated nor audited by the gateway.** Command controls are
  guardrails, not a jail.
- gwops generates or loads the SSH CA and renders it into the gateway config; it does not
  configure SSH targets. Each target must trust the SSH CA public key itself.
- There is no rotation route for the SSH CA.

## Web apps

Mechanism: [Web apps](../architecture/web-apps.md).

- Every upstream TLS mode requires TLS 1.3. An upstream that only speaks TLS 1.2 fails.
- The client-to-gateway side is HTTP/1.1 only.
- The `Host` header cannot be rewritten: the web-app policy refuses it.
- Wildcard web-app addresses and aliases are not supported.
- The gateway closes a client connection at the access token's expiry, so a long-lived WebSocket,
  server-sent event stream or transfer is cut then.
- The gateway applies no clock leeway to a token's issue time. If the gateway host's clock is
  behind the tenant's, the first request after a resource change (which re-issues tokens) can get
  `401` until the clock catches up. Keep the host on NTP.
- gwops does not verify access tokens; the app must, if it relies on them.
- gwops does not manage name resolution. The gateway resolves each web-app `address` through the
  container's resolver.
- The opt-in upstream TLS probe dials directly from gwops and ignores proxy variables, so its
  result can differ from what the gateway sees. It is advisory.
- With a generated CA and downstream `tls13`, browsers trust the app only after you install the
  CA in their trust stores.

## Certificates and public mode

Mechanism: [Certificates](../architecture/certificates.md), [ACME](../architecture/acme.md).

- **On-demand issuance is an exposure when enabled.** With `ca.x509.on_demand_issuance`, any
  client that can reach port 8443 can make the gateway sign a certificate for any SNI name with the
  X.509 CA, before the access token is authenticated. The client never receives the CA key. If the
  CA is trusted by browsers or devices, such a certificate is accepted for any name. The generated
  CA carries no name constraints. Off by default.
- **The registered public root widens what the Client accepts.** In public certificate mode the
  gateway's X.509 CA on the tenant is ISRG Root X1, so a Client accepts any certificate that chains
  to that root for the names it dials through the gateway, not only the ones gwops serves.
- **Public mode serves DNS names only.** No IP-addressed upstreams or aliases, no IP SANs, no
  single-label names and no on-demand issuance. ISRG Root X1 is the only accepted root, so every
  certificate must chain to it (an ECDSA chain needs its cross-signed intermediate served).
- **Private CA and public certificates cannot be mixed on one gateway** (`public_tls` and
  `ca.x509` are mutually exclusive). Run two containers.
- **Path validation applies the CA/Browser Forum profile.** A certificate from another public CA
  can be refused for a profile reason. gwops does not relax the profile.
- **Switching from public mode back to private CA mode does not rebind the gateway.** Bind the
  gateway on the tenant to the gwops X.509 CA (the `ca/x509` id in `/data/state.json`) yourself.
- **A store failure partway through a multi-certificate install is not rolled back.** Validation
  is all-or-nothing, but installation is one certificate at a time; a served set can briefly mix
  new and previous generations, each internally consistent.
- `/status` `certs.public[].generation` is `null` after a restart whose first pass fails; serving
  is unaffected.
- **ACME is DNS-01 against Cloudflare only.** No other DNS provider, no HTTP-01 or TLS-ALPN-01,
  and no ACME in private CA mode. Only Let's Encrypt's staging directory is treated as a dry run;
  another CA's staging directory given as a URL is treated as production.
- **ACME issuance is subject to the CA's rate limits.** gwops backs off and honours the CA's retry
  hints, but cannot see a limit before the CA answers.
- **Every issued name is published in Certificate Transparency logs.** Use a wildcard
  certificate where host names must not be public.
- **The Cloudflare token can edit its zone.** Scope it to one zone, and use `challenge_alias` with
  a dedicated delegation zone for production.
- **Resolver-only propagation can report success early.** With the default
  `propagation: resolver` the CA can still fail validation when an authoritative nameserver lacks
  the record. `authoritative` needs outbound UDP and TCP 53.
- **An unusable DNS token file stops issuance and renewal.** The installed certificate keeps
  serving until it expires.
- **A CA or proxy supplied to lego can see the DNS token.** `SSL_CERT_FILE`, `SSL_CERT_DIR` and
  the proxy variables pass to lego, and a TLS-intercepting proxy for lego is not supported.
- ACME failures are classified by matching lego's output. A lego version change can alter that
  output; unmatched errors are reported as `internal`.

## Tenant management

Mechanism: [Twingate integration](../architecture/twingate-integration.md).

- gwops never creates groups, security policies, Remote Networks or Connectors, and never changes
  group membership. Beyond resources and CA registrations, the only object it creates is the
  Gateway object, in remote-network mode.
- gwops changes only tenant objects recorded in its ownership registry (`/data/state.json`). If
  that file is lost, gwops forgets which resources it created: it is expected to create new ones
  and leave the old ones in place. Back up `/data`.
- A managed SSH or Kubernetes resource attached to another gateway on the tenant is reported, not
  moved back.
- Access references by name must match exactly one object.
- Overlays accumulate; there is no compaction.

## Key storage and trust boundaries

Mechanism: [Security model](../architecture/security-model.md).

- CA and leaf private keys are files on `/data` (mode 0600). There is no HSM, KMS or Vault
  integration.
- gwops, lego and the gateway run as the same uid (10001). The gateway process can read the CA
  keys, lego's account and certificate keys under `/data/acme/`, and the mounted DNS token file.
- The admin API is plain HTTP. Exposing it beyond loopback needs a TLS proxy or a private path.
- `GODEBUG` passes through to the gateway and can re-enable legacy TLS and X.509 behaviour.
