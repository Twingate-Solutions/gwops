# Operations

Day-2 tasks for a gateway container that is already running: watching it, reaching its admin API
safely, rotating certificates, backing up state, upgrading, building your own image and finding
out why something is broken. To set up a capability, see the [guides](../guides/README.md); for a
complete deployment, see the [recipes](../recipes/README.md).

## Pick a task

| I want to... | Page |
| --- | --- |
| Alert on problems | [Monitoring](monitoring.md) |
| Find out why something is broken | [Troubleshooting](troubleshooting.md) |
| Reach the admin API from another machine | [Admin API behind a TLS proxy](admin-api-behind-tls-proxy.md) |
| Rotate the TLS leaf or the generated X.509 CA | [CA and leaf rotation](ca-and-leaf-rotation.md) |
| Back up the state volume | [Backup and restore](backup-and-restore.md) |
| Upgrade the image, or move the gateway or lego pin in a fork | [Upgrades and pins](upgrades-and-pins.md) |
| Build the image myself or publish it from a fork | [Build and publish](build-and-publish.md) |

## Index

### Run

- [Monitoring](monitoring.md): health, `/status`, logs, gateway metrics.
- [Troubleshooting](troubleshooting.md): symptom-to-cause tables.
- [Admin API behind a TLS proxy](admin-api-behind-tls-proxy.md): expose the admin API safely.

### Maintain

- [CA and leaf rotation](ca-and-leaf-rotation.md): rotate the leaf and the generated X.509 CA.
- [Backup and restore](backup-and-restore.md): what `/data` holds and what losing it costs.
- [Upgrades and pins](upgrades-and-pins.md): upgrade, roll back, move pins.
- [Build and publish](build-and-publish.md): local builds and GHCR publishing from a fork.

## Page format

Each page uses the same sections as the guides: **When to use**, **Prerequisites**, **Steps**,
**Verify**, **Roll back** where there is something to undo, and **Related**.

Shell examples assume you are in the directory that holds `compose.yaml` and that these are
set:

```sh
export BASE=http://127.0.0.1:8081
export TOKEN=<admin-token>
```

> **Note:** For `curl` on the Docker host to reach the admin API through the `127.0.0.1:8081`
> publish in `compose.yaml`, gwops must listen on all container interfaces
> (`admin_api.bind: 0.0.0.0`). [Admin API behind a TLS proxy](admin-api-behind-tls-proxy.md)
> explains the options.
