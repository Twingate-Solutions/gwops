# Build and publish

Build the image on your own machine, or publish your own copy to the GitHub Container Registry
(GHCR) from a fork with GitHub Actions.

## When to use

- You changed the code and want to run it.
- Your organisation runs images only from its own registry.
- You maintain a fork with a different gateway, lego or Python base image pin.

## Prerequisites

- Docker with BuildKit (the default builder in current Docker releases) and Buildx.
- A linux/amd64 build host, or emulation for it. The published image is linux/amd64 only.
- Network access to Docker Hub for the `twingate/gateway`, `goacme/lego` and `python:3.12-slim`
  images the build copies from, all pulled by digest, and to PyPI for the packages in
  `requirements.lock`.
- For publishing: a GitHub fork of the repository with Actions enabled.

## Steps

### Build locally

From the repository root:

```sh
make image
```

`make image` first runs `make verify-pin`, which checks that the pinned gateway tag still
resolves to the pinned digest, then builds `gwops-gateway:dev` with the pinned tag and digest.

`make` is not always available (for example on Windows). The equivalent commands:

```sh
docker buildx imagetools inspect twingate/gateway:2.0.0 --format '{{json .Manifest}}'
# the "digest" field must equal the pinned GATEWAY_DIGEST

docker build \
  --build-arg GATEWAY_TAG=2.0.0 \
  --build-arg GATEWAY_DIGEST=sha256:4993a7db015f7c2091d55f1c7a36c3e0c277137cb9937a46e9ced2c17456a6d1 \
  --build-arg GWOPS_VERSION=0.0.0-local \
  -t gwops-gateway:dev .
```

The build arguments:

| Argument | Default | Notes |
| --- | --- | --- |
| `GATEWAY_TAG` | `2.0.0` | Must be `2.X.Y` or `2.X.Y-dev-<git sha>`. Also baked in as `GWOPS_GATEWAY_VERSION`, which `/status` reports. |
| `GATEWAY_DIGEST` | the pinned digest | Must be `sha256:<64 hex>`. Docker pulls by digest, so a tag that does not match its digest bakes the wrong version label over the binary; `verify-pin` catches that. |
| `LEGO_TAG` | `v5.5.2` | Must be `v5.X.Y`. |
| `LEGO_DIGEST` | the pinned digest | Must be `sha256:<64 hex>`. |
| `PYTHON_TAG` | `3.12-slim` | Tag of the base image. |
| `PYTHON_DIGEST` | the pinned digest | The base image's index digest. Must be set. |
| `GWOPS_VERSION` | `0.0.0-dev` | gwops' own release version, written into the package. Letters, digits, `.`, `_` and `-`, up to 64 characters. |

The `Dockerfile` defaults already carry the pins, so `docker build -t gwops-gateway:dev .` also
works.

The build installs gwops's Python dependencies from `requirements.lock` with
`pip install --require-hashes --only-binary=:all:`: every package is pinned with its sha256
hashes, nothing is resolved at build time, and nothing is compiled from source. A change to the
dependencies in `pyproject.toml` reaches the image only after the lock is regenerated; see
[Change a dependency](../reference/development.md#change-a-dependency).

The workflows pin every GitHub Action to a full commit SHA. Keep that when you add a step to a
fork's workflow: `tests/test_pin.py` fails on a tag or branch reference.

### Run a local build

`compose.yaml` never builds. Point it at your local tag:

```yaml
services:
  gateway:
    image: gwops-gateway:dev
```

With `pull_policy: missing`, Compose uses the local image and does not try to pull it. Then:

```sh
docker compose up -d
```

After a rebuild under the same tag, run `docker compose up -d --force-recreate` so the
container uses the new image.

### Publish from a fork with GitHub Actions

The `build-images` workflow builds the image and pushes it to GHCR as
`ghcr.io/<owner>/<repo>`, lowercased (GHCR requires lowercase names).

1. **Allow the workflow to push packages.** The workflow declares `packages: write`. If your
   organisation restricts workflow permissions, allow read and write permissions under
   Settings > Actions > General > Workflow permissions.
2. **Docker Hub credentials, if needed.** The build pulls `twingate/gateway` from Docker Hub. If
   your runners need to authenticate there, add `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`
   repository secrets and uncomment the "Log in to Docker Hub" step in
   `.github/workflows/build-images.yml`.
3. **Trigger a build**, in one of two ways:
   - **Push a release tag** `vX.Y.Z`:

     ```sh
     git tag v1.2.3
     git push origin v1.2.3
     ```

     This builds with the pinned gateway and publishes `:<commit-sha>` (the full 40-character
     SHA) and `:1.2.3`. `GWOPS_VERSION` is the tag without the leading `v`.
   - **Run it manually** from the Actions tab (`build-images`, "Run workflow"), with these
     inputs:

     | Input | Default | Meaning |
     | --- | --- | --- |
     | `gateway_tag` | `2.0.0` | The gateway tag to wrap. Same rules as the build argument. |
     | `gateway_digest` | the pinned digest | Its image-index digest. The workflow checks that the tag resolves to it. |
     | `tag_latest` | `false` | Also publish `:latest`. |

     A manual run publishes `:<commit-sha>`, plus `:latest` when `tag_latest` is set.
     `GWOPS_VERSION` is `0.0.0-dev.<7-character SHA>`.
4. **Read the exact tags** in the run's job summary, which lists the `docker pull` commands.

Publishing `:latest` moves what any deployment pulling `:latest` gets on its next pull, which is
why it is opt-in. Prefer version tags in deployments.

The workflow builds `linux/amd64` only. Adding `linux/arm64` needs a QEMU setup step and the
platform added to the build step; it has not been tested.

### Make the package pullable

A new GHCR package is private by default. Either:

- make it public in the package's settings on GitHub, or
- log in on every host that pulls it, with a token that has the `read:packages` scope:

  ```sh
  echo "<token>" | docker login ghcr.io -u <github-user> --password-stdin
  ```

Then point `compose.yaml` at your package:

```yaml
services:
  gateway:
    image: ghcr.io/<owner>/<repo>:<X.Y.Z>
```

## Verify

```sh
docker image inspect gwops-gateway:dev --format '{{.Config.Env}}'
docker compose up -d
curl -s -H "Authorization: Bearer $TOKEN" $BASE/status | jq .capabilities
```

- The image environment includes `GWOPS_GATEWAY_VERSION=2.0.0` (or the tag you built).
- `capabilities.gateway_version` in `/status` matches it.
- `docker compose ps` shows the container `(healthy)`.

## Roll back

Point `image:` back at the published image you ran before, then `docker compose pull gateway`
and `docker compose up -d`.

## Related

- [Image reference: build arguments](../reference/image.md#build-arguments)
- [Image reference: pinned binaries](../reference/image.md#pinned-binaries)
- [Image reference: Python dependencies](../reference/image.md#python-dependencies)
- [Image reference: published image](../reference/image.md#published-image)
- [Development reference](../reference/development.md)
- [Upgrades and pins](upgrades-and-pins.md)
