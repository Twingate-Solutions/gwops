# Upgrades and pins

Upgrade the image you run, roll back to an earlier one, and, if you maintain a fork, move one of
the image's pins: the gateway binary, the lego ACME client, the Python base image or the Python
dependencies.

Every input to the image is pinned:

| Input | Pinned to | Where the pin lives |
| --- | --- | --- |
| Twingate Gateway (`twingate/gateway`) | `2.0.0` and its image-index digest; accepted tags are `2.X.Y` or a preview `2.X.Y-dev-<git sha>` | `Dockerfile`, `Makefile`, `.github/workflows/build-images.yml`, `tests/test_image_smoke.py` |
| lego (`goacme/lego`) | `v5.5.2` and its digest; accepted tags are `v5.X.Y` | `Dockerfile`, `tests/test_image_smoke.py` |
| Python base image (`python`) | `3.12-slim` and its image-index digest | `Dockerfile`, `tests/test_image_smoke.py`, and the regeneration command in the `requirements.lock` header |
| Python dependencies | Exact versions | `pyproject.toml` and the hashed `requirements.lock` |
| GitHub Actions | Full commit SHA on every `uses:` | `.github/workflows/` |

The build refuses a floating gateway or lego tag such as `latest`, `dev`, `2` or `2.0`, an empty
digest for any of the three images, and a gateway or lego digest that is not `sha256:<64 hex>`.
gwops renders only the gateway's 2.0 configuration schema, so 1.x binaries cannot be built in.
`tests/test_pin.py` checks that the copies of every pin agree and that every `FROM` is pinned by
digest.

## When to use

- A new image release is available and you want it.
- An upgrade went wrong and you want the previous image back.
- You maintain a fork and want to move it to a newer gateway, lego or Python base image, or
  bump a Python dependency.

## Prerequisites

- A backup of the `/data` volume taken just before the change. See
  [Backup and restore](backup-and-restore.md).
- For moving pins: a fork with GitHub Actions enabled (see [Build and publish](build-and-publish.md)),
  Docker with Buildx, and the project's development environment (see the
  [development reference](../reference/development.md)).

## Steps

### Upgrade the image

1. Pick a version. Images are tagged `:<X.Y.Z>` (published when a `vX.Y.Z` tag is pushed) and
   `:<commit-sha>`. `:latest` moves only when a maintainer publishes it on purpose, so do not
   rely on it to track releases. Pin a version tag in `compose.yaml`:

   ```yaml
   services:
     gateway:
       image: ghcr.io/twingate-solutions/gwops:<X.Y.Z>
   ```

2. Pull it. `compose.yaml` uses `pull_policy: missing`, so `docker compose up` never fetches a
   newer image on its own:

   ```sh
   docker compose pull gateway
   ```

3. Recreate the container:

   ```sh
   docker compose up -d
   ```

Recreating the container stops gwops, which shuts down in order and drains the gateway, so
active sessions through the gateway end. gwops allows the gateway up to 30 s to drain; Docker
kills the container once its own stop timeout passes. The shipped `compose.yaml` sets
`stop_grace_period: 40s`, which covers the drain; keep it in your own compose file. The `/data`
volume carries over: CAs, overlays, the ownership
registry, the spool and ACME state are reused, and nothing is re-created on the tenant.

### Roll back the image

1. Set `image:` back to the previous tag.
2. Run `docker compose pull gateway` if that image is no longer on the host, then
   `docker compose up -d`.

gwops reads older on-disk formats and rewrites them in the current one: an ownership registry
in the original flat format is read and rewritten in the current versioned format on its next
write, and a leaf in the older layout (`/data/pki/leaf.crt`, `/data/pki/leaf.key`) is never read and
is removed by housekeeping once no gateway config on disk names it. It does not convert formats backwards. A gwops image refuses a
registry file whose version it does not know and aborts rather than guess which tenant objects
it owns. If an older image refuses state that a newer one wrote, stop it and restore the `/data`
backup taken before the upgrade.

### Move the gateway pin (forks)

Do this only for a newer 2.x release, or for a preview only when it carries a fix gwops needs.

1. **Resolve the digest** of the tag you want. Pin the image-index digest, not a
   platform-specific one:

   ```sh
   docker buildx imagetools inspect twingate/gateway:<2.X.Y> --format '{{json .Manifest}}'
   ```

   The `digest` field of the output is the value to pin.

2. **Change the tag and digest together** everywhere the pin lives:
   - `Dockerfile`: both `ARG GATEWAY_TAG` and `ARG GATEWAY_DIGEST` pairs (one before the first
     `FROM`, one in the runtime stage).
   - `Makefile`: `GATEWAY_TAG` and `GATEWAY_DIGEST`.
   - `.github/workflows/build-images.yml`: the `gateway_tag` and `gateway_digest` dispatch input
     defaults, and every `inputs.gateway_tag || '...'` and `inputs.gateway_digest || '...'`
     fallback.
   - `tests/test_image_smoke.py`: the `GATEWAY_TAG` default and `_DEFAULT_GATEWAY_DIGEST`.

3. **Check the pin agrees and resolves**:

   ```sh
   make verify-pin
   pytest tests/test_pin.py
   ```

   `make verify-pin` resolves the tag in the registry and fails if it does not match the
   digest. `tests/test_pin.py` fails if any location disagrees with the `Dockerfile`.

4. **Run the `preflight` workflow** (Actions tab, or open a pull request that touches the
   `Dockerfile`). It renders the project's golden configs and validates them against two
   gateway binaries: the new pin and the floating `twingate/gateway:dev`. Both legs must run, not
   be skipped, and pass.

5. **Build and boot the image** on the new pin, and watch it settle:

   ```sh
   make image
   ```

   Point a test deployment at the image, start it, and check that the log shows
   `supervisor.running` and no `gateway.crashed` or `gateway.early_exit_rollback` loop.
   `GET /status` `capabilities.gateway_version` reports the new tag.

6. **Re-check the gateway's logger names.** The recording filter keeps lines only from the
   loggers `system`, `audit` and `session_recording`, and matches the messages
   `API request completed`, `API request failed` and `Authenticated connection`. With recording
   on, open an SSH session through the test deployment and confirm its lines reach the
   receiver and `shipper.dropped_lines.not_allowlisted` does not swallow them. A renamed logger
   or message silently stops recordings from shipping.

7. Publish the image (see [Build and publish](build-and-publish.md)) and upgrade as above.

### Move the lego pin (forks)

1. Resolve the digest:

   ```sh
   docker buildx imagetools inspect goacme/lego:<v5.X.Y> --format '{{json .Manifest}}'
   ```

2. Change both `ARG LEGO_TAG` and `ARG LEGO_DIGEST` pairs in the `Dockerfile`, and `_LEGO_TAG`
   and `_LEGO_DIGEST` in `tests/test_image_smoke.py`. No other file carries the lego pin.
3. Run `pytest tests/test_pin.py`.
4. Build the image and run an ACME dry run against Let's Encrypt staging (see
   [Public certificates with ACME](../guides/public-certs-acme.md)): `certs.public[].acme.state` should
   reach `dry_run_ok`.

### Move the Python base image pin (forks)

The `3.12-slim` tag moves with every Python 3.12 patch release upstream; the digest fixes the
bytes. Refresh it to pick up base-image security fixes.

1. Resolve the image-index digest:

   ```sh
   docker buildx imagetools inspect python:3.12-slim --format '{{json .Manifest}}'
   ```

2. Change `ARG PYTHON_DIGEST` in the `Dockerfile` (and `ARG PYTHON_TAG` if you change the tag),
   `_PYTHON_TAG` and `_PYTHON_DIGEST` in `tests/test_image_smoke.py`, and the image reference in
   the regeneration command in the `requirements.lock` header.
3. Regenerate `requirements.lock` with that command, so the hashes are resolved on the new base
   image, and re-add the header the regeneration overwrites. See
   [Change a dependency](../reference/development.md#change-a-dependency).
4. Run `pytest tests/test_pin.py`, then build and boot the image as for a gateway pin move.

### Bump a Python dependency (forks)

1. Change the package's `==` version in `pyproject.toml`.
2. Regenerate `requirements.lock` with the command in its header and re-add the header.
3. Run `pytest tests/test_pin.py`, then build and boot the image.

The image installs only what `requirements.lock` lists, with `pip install --require-hashes`, so a
`pyproject.toml` change without a regenerated lock does not reach the image, and
`tests/test_pin.py` fails.

## Verify

```sh
docker compose images gateway
curl -s -H "Authorization: Bearer $TOKEN" $BASE/status | jq '{gateway: .capabilities.gateway_version, process: .process.state, reconcile_ok: .last_reconcile.ok}'
```

- `docker compose images` shows the tag you pinned.
- `capabilities.gateway_version` is the gateway tag baked into the image.
- `process.state` is `running` and `last_reconcile.ok` is `true`.

## Roll back

See [Roll back the image](#roll-back-the-image) above. For a fork, revert the pin commit; the
same files change back together, and `tests/test_pin.py` must pass.

## Related

- [Image reference: pinned binaries](../reference/image.md#pinned-binaries)
- [Image reference: Python dependencies](../reference/image.md#python-dependencies)
- [Image reference: build arguments](../reference/image.md#build-arguments)
- [Development reference](../reference/development.md)
- [Gateway process](../architecture/gateway-process.md): rendering, pre-flight and drain-restart.
- [Build and publish](build-and-publish.md)
