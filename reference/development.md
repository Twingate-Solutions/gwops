# Development

How to work on gwops itself: set up an environment, lint, test, and check the gateway pin and
rendered configs. Architecture is in [Architecture](../architecture/README.md); building and
publishing images is in [Build and publish](../operations/build-and-publish.md).

## Requirements

- Python 3.12 or later (`requires-python = ">=3.12"`).
- Docker, for building the image and for the tests that need Linux symlinks or a real image.
- Linux for the full test suite. On Windows, tests that need symlinks skip; run them in a
  `python:3.12-slim` container (see [Tests](#tests)).

## Set up

```sh
git clone <your fork URL>
cd gwops
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

On Windows, run tools through the venv interpreter, for example
`.venv\Scripts\python -m pytest ...`.

The `dev` extra installs `pytest`, `pytest-asyncio`, `respx`, `ruff`, `mypy` and `types-pyyaml`,
each pinned to an exact version in `pyproject.toml`.

## Lint and type-check

```sh
ruff check src tests
mypy src
```

`make lint` runs the same two commands.

`ruff` targets Python 3.12 with a line length of 100 and the `E`, `W`, `F`, `I`, `UP`, `B` and `SIM`
rule sets. `mypy` runs in strict mode over the `gwops` package. Both are configured in
`pyproject.toml`.

## Tests

```sh
pytest tests/certs/test_store.py         # one file
pytest tests/shipper/                    # one directory
pytest                                   # everything under tests/
```

- The full suite takes several minutes. While iterating, run the files you changed.
- `asyncio_mode = "auto"`: async test functions need no decorator.
- The certificate store and other symlink tests skip on Windows. Run them by path in a Linux
  container, for example:

  ```sh
  docker run --rm -v "$PWD:/src" -w /src python:3.12-slim \
    sh -c 'pip install -q -e ".[dev]" && pytest tests/certs/test_store.py'
  ```

- Tests marked `integration` need external services and skip unless their environment variables
  are set. Select them with `-m integration`.
- The image smoke tests in `tests/test_image_smoke.py` build the real image and run containers.
  They need Docker and are opt-in:

  ```sh
  GWOPS_SMOKE_IMAGE=1 pytest -m integration tests/test_image_smoke.py
  # reuse an image you already built instead of building one:
  GWOPS_SMOKE_IMAGE=1 GWOPS_SMOKE_BASE_IMAGE=gwops-gateway:dev \
    pytest -m integration tests/test_image_smoke.py
  ```

  The build uses `GATEWAY_TAG` and `GATEWAY_DIGEST` from the environment when set, else the pin.

- The live web-app rig (`make integration-webapp`) runs against a real tenant and is never part of
  `pytest` runs. It refuses to start unless every `IT_*` variable it needs is set, including
  `IT_APPROVED_NETWORK` and `IT_APPROVED_REMOTE_NETWORK_ID`, which must equal
  `IT_TWINGATE_NETWORK` and `IT_TWINGATE_REMOTE_NETWORK_ID` exactly. Its verifier service lives in
  `tests/integration/webapp/verifier/`, and `tests/integration/webapp/README.md` describes the
  tenant rules and every variable. Read it before a run: the rig creates and deletes objects on
  the tenant.

## Pin checks

Every input to the image is pinned, and `tests/test_pin.py` checks that the copies of each pin
agree:

| Pin | Where it lives |
| --- | --- |
| Gateway binary (tag and image-index digest) | `Dockerfile`, `Makefile`, `.github/workflows/build-images.yml`, `tests/test_image_smoke.py` |
| lego (tag and digest) | `Dockerfile`, `tests/test_image_smoke.py` |
| Python base image (`PYTHON_TAG`, `PYTHON_DIGEST`) | `Dockerfile`, `tests/test_image_smoke.py`, and the regeneration command in the `requirements.lock` header |
| Python dependencies (exact versions) | `pyproject.toml` (`==` for every runtime, dev and build dependency) and `requirements.lock` (every package, transitive ones included, with sha256 hashes) |
| GitHub Actions | Every `uses:` in `.github/workflows/` is pinned to a full commit SHA |

```sh
pytest tests/test_pin.py
```

`tests/test_pin.py` fails when the copies disagree. It also checks the Dockerfile's tag guard,
that every `FROM` is pinned by digest, that the lock carries hashes for every package and no dev
dependencies, and that the CI preflight's `dev` leg cannot be skipped.

`make verify-pin` checks that `twingate/gateway:<GATEWAY_TAG>` still resolves to
`GATEWAY_DIGEST` in the registry (it needs `docker buildx`). `make image` runs it before building.
Moving the pin is described in [Upgrades and pins](../operations/upgrades-and-pins.md); the pinned
values are in [Pinned binaries](image.md#pinned-binaries).

## Rendered-config preflight

The gateway has no config-validate subcommand, so rendered configs are checked by spawning a real
binary on them:

```sh
python -m gwops.ci.preflight <gateway binary> <config> [<config> ...]
```

`make preflight-ci GATEWAY_BIN=<path> CONFIGS="<files>"` runs the same command (default config
`tests/fixtures/rendered/minimal.yaml`). The golden configs live in `tests/fixtures/rendered/`.

The outcome is classified strictly:

| Outcome | Result |
| --- | --- |
| The gateway came up on the config. | Pass |
| The gateway got past config load and validation and failed at proxy creation on runtime files absent outside the container (for example `/data/pki/leaf/fullchain.pem`). | Pass (expected startup failure) |
| The binary rejected the config at load (`failed to load config`) or validation (`failed to validate config`). | Fail (schema break) |
| Anything else: an early exit 0, a usage error, a panic, a binary that will not run. | Fail (stderr is logged) |

The `preflight` GitHub Actions workflow runs this on pull requests that touch the renderer, the
preflight code, `Dockerfile`, `Makefile` or the golden configs, and on manual dispatch. It runs two
legs: the pinned binary, and the floating `twingate/gateway:dev` tag to catch schema breaks before
a release. Both must run and pass before the pin moves.

## Extension point: resource kinds

Everything that would otherwise hardcode a resource type (the effective-state lists, the Twingate
GraphQL fragments and mutations, SAN computation, the overlay allowlist and the
`/upstreams/{segment}/{name}` routes) iterates the resource-kind registry in
`src/gwops/kinds.py`. Adding a kind takes:

1. a config model subclassing `UpstreamEntry` in `src/gwops/configmodel/schema.py`;
2. a `list[...]` field for it on `SeedConfig`;
3. one `ResourceKind` appended to `KINDS` in `src/gwops/kinds.py`.

Hook fields default to the SSH shape. The registered kinds are `ssh` (`ssh_upstreams`),
`kubernetes` (`k8s_clusters`, API segment `k8s`) and `webapp` (`web_apps`).

## Code style

- Python 3.12 type hints (`str | None`) on every signature; `mypy --strict` clean.
- async-first; Pydantic v2 and pydantic-settings for configuration; httpx is the only HTTP client;
  structlog for logging (JSON to stdout).
- Docstrings on public classes and methods.
- Secrets only from environment variables or mounted files; never logged. The log processor
  redacts secret-looking keys, but do not rely on it: never put a secret in an event field.
- Fail loud: configuration and certificate problems abort startup or are refused with an
  actionable message.

Runtime dependencies are deliberately few. The current set, pinned in `pyproject.toml`:

| Package | Version |
| --- | --- |
| `httpx` | 0.28.1 |
| `pydantic` | 2.13.4 |
| `pydantic-settings` | 2.14.2 |
| `structlog` | 26.1.0 |
| `fastapi` | 0.139.2 |
| `uvicorn` | 0.51.0 |
| `cryptography` | 49.0.0 |
| `pyyaml` | 6.0.3 |
| `watchfiles` | 1.2.0 |

Discuss any new runtime dependency before adding it.

### Change a dependency

The image never resolves dependencies: it installs `requirements.lock` with
`pip install --require-hashes`. To add, remove or bump a package:

1. Edit its `==` pin in `pyproject.toml`.
2. Regenerate `requirements.lock` with the command in its header. The command runs `pip-compile`
   inside the pinned `python:3.12-slim@sha256:...` image, so the hashes cover the Linux wheels the
   image installs. Regeneration overwrites the header; put it back.
3. Run `pytest tests/test_pin.py`, then build the image (`make image`).

Your local `pip install -e ".[dev]"` reads `pyproject.toml`, not the lock; reinstall after a
change.

## Documentation

When a change affects behaviour, update the matching page in the same change:
[Seed reference](seed.md) for seed keys, [Admin API](admin-api.md) for routes,
[Environment](environment.md) for variables, [Log events](log-events.md) for event names, and the
[recording wire format](recording-wire-format.md) for anything a receiver sees.
