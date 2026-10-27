# Glossary

The terms used throughout this documentation, alphabetically.

| Term | Definition | Explained in |
| --- | --- | --- |
| admin token | The bearer token in `GWOPS_ADMIN_TOKEN`. Its principal, `admin`, may use every admin API route. | [Admin API architecture](../architecture/admin-api.md) |
| allowlists | `twingate.access_allowlist` (groups and security policies) and `twingate.address_allowlist` (CIDRs and DNS suffixes). Seed-only bounds on what admin API and overlay writes may reference or target, for both tokens. | [Access control](../guides/access-control.md) |
| automation token | The bearer token in `GWOPS_AUTOMATION_TOKEN`. Its principal, `automation`, may only `PUT`, `DELETE` and `GET` `/upstreams/{segment}/{name}`, within the allowlists and its own namespace. | [Automation and CI](../guides/automation-and-ci.md) |
| bring-your-own (BYO) CA | An X.509 or SSH CA you supply, selected with `generate: false` and file paths in the seed's `ca` block. | [Bring your own CA](../guides/private-ca-byo.md) |
| confined root | One of the four read-only mount roots gwops reads files from: `/config/k8s-creds/`, `/config/webapp-cas/`, `/config/public-tls/`, `/config/acme/`. A path that resolves outside its root is refused. | [Security model](../architecture/security-model.md) |
| drain-restart | Stopping the gateway with SIGTERM, waiting for it to exit (SIGKILL after 30 s), then starting a new one. How every rendered config change is applied. | [Gateway process](../architecture/gateway-process.md) |
| effective state | The seed with every overlay merged on top and the result validated. What a reconcile pass acts on. | [Configuration model](../architecture/configuration-model.md) |
| gateway, gateway binary | The official Twingate Gateway program inside the container. "The gateway" alone means the binary. | [Architecture](../architecture/README.md) |
| Gateway object | The Twingate tenant object that represents this gateway. Capitalized when the tenant object is meant. | [Twingate integration](../architecture/twingate-integration.md) |
| gwops | The Python control plane in the image. It runs as PID 1 and supervises the gateway. | [Architecture](../architecture/README.md) |
| hot reload | The gateway reloading changed certificate files without a restart. | [Certificates](../architecture/certificates.md) |
| leaf | The gateway's TLS server certificate, minted by gwops in private CA mode. It covers every served name. | [Certificates](../architecture/certificates.md) |
| on-demand issuance | Opt-in mode in which the gateway signs a certificate for any SNI name the leaf does not cover, with the X.509 CA, before the client is authenticated. A security exposure; off by default. | [On-demand issuance](../guides/on-demand-issuance.md) |
| overlay | One persisted admin API change, stored as a JSON file under `/data/overlays/` and applied on top of the seed. | [Configuration model](../architecture/configuration-model.md) |
| ownership registry | `/data/state.json`: the ids of the tenant objects gwops created. gwops updates or deletes only those. | [Twingate integration](../architecture/twingate-integration.md) |
| pinned-gateway mode | The gateway mode selected by `twingate.gateway_id`: gwops uses an existing Gateway object. | [Gateway modes](../guides/gateway-modes.md) |
| pre-flight | Spawning the gateway binary on a candidate config for 5 s before swapping it in, to catch configs the binary rejects. | [Gateway process](../architecture/gateway-process.md) |
| private CA mode | The default certificate mode: gwops mints the leaf from a generated or bring-your-own X.509 CA. `/status` `tls.mode` is `static` or `static+on_demand`. | [Certificates](../architecture/certificates.md) |
| public certificate mode | The certificate mode turned on by a `public_tls` block: the gateway serves certificates that chain to ISRG Root X1, supplied as files or issued by ACME. `/status` `tls.mode` is `public`. | [Certificates](../architecture/certificates.md) |
| readiness reason | A code in `/status` `web_apps.readiness[].reasons` that says what stands between a web app and a working session, or what gwops cannot verify. | [Admin API: `web_apps`](admin-api.md#web_apps) |
| reconcile pass | One run of gwops' level-triggered loop: load the effective state, sync the tenant, materialize files and certificates, render and apply the gateway config. | [Reconciler](../architecture/reconciler.md) |
| recording receiver | Any HTTP service that implements the recording wire format and accepts the gateway's recordings and audit lines from gwops. Its base URL is `recording.receiver_url`; gwops authenticates with `GWOPS_RECORDING_TOKEN`. | [Recording wire format](recording-wire-format.md) |
| remote-network mode | The gateway mode selected by `twingate.remote_network` or `remote_network_id` plus `gateway_address`: gwops adopts the Gateway object at that address, or creates one. | [Gateway modes](../guides/gateway-modes.md) |
| seed | `/config/seed.yaml`, the read-only declarative configuration. gwops never writes it. | [Seed reference](seed.md) |
| seed-only | A key that overlays and the admin API cannot set. | [Configuration model](../architecture/configuration-model.md) |
| served name | Every upstream address host and web-app alias: the names the TLS certificate must cover. | [Certificates](../architecture/certificates.md) |
| spool | `/data/spool`, the bounded on-disk queue of recording lines waiting for delivery. | [Recording pipeline](../architecture/recording-pipeline.md) |
| tenant | The Twingate account, addressed as `<network>.<host>` (for example `acme.twingate.com`). | [Twingate integration](../architecture/twingate-integration.md) |
| upstream | A target the gateway fronts: an SSH host, a Kubernetes API server or a web app. The resource kinds are `ssh`, `kubernetes` (admin API segment `k8s`) and `webapp`. | [Seed reference](seed.md) |
