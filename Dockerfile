# syntax=docker/dockerfile:1
#
# gwops gateway image: multi-stage, non-root. Wraps the Twingate gateway binary, copied
# from the official image and pinned by tag and index digest:
#     docker build --build-arg GATEWAY_TAG=2.0.0 --build-arg GATEWAY_DIGEST=sha256:<64 hex> .

# Official gateway image tag and index digest, used only as a binary source. Pin both,
# never `latest` or a floating tag: preview tags can be re-pushed, so the digest is what
# fixes the bytes.
ARG GATEWAY_TAG=2.0.0
ARG GATEWAY_DIGEST=sha256:4993a7db015f7c2091d55f1c7a36c3e0c277137cb9937a46e9ced2c17456a6d1

# lego (ACME client), copied from the official goacme/lego image and pinned by tag and
# digest. The binary is /lego in that image.
ARG LEGO_TAG=v5.5.2
ARG LEGO_DIGEST=sha256:1944e8c36055beec47c7de6f15202b41128be75eea0ffa257f0c14d93c5155fd

# Python base image, pinned by tag and index digest like the binaries above. The tag is a
# floating one upstream (it moves with every 3.12 patch release); the digest fixes the bytes.
# Bump both together. To refresh: `docker buildx imagetools inspect python:3.12-slim`, take
# the top-level index digest, and update PYTHON_DIGEST here and in the pip-compile command
# in requirements.lock.
ARG PYTHON_TAG=3.12-slim
ARG PYTHON_DIGEST=sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f

# --- Stage: gateway binary -----------------------------------------------------------
# The official image, used ONLY as a source to copy /gateway out of — never run here.
# `:?` makes an empty GATEWAY_DIGEST fail the build with a message naming it; a malformed
# one fails BuildKit's reference parse here, and the runtime-stage guard below rejects any
# well-formed reference that is not `sha256:<64 hex>`.
FROM twingate/gateway:${GATEWAY_TAG}@${GATEWAY_DIGEST:?GATEWAY_DIGEST_must_be_set_to_sha256:64hex} AS gateway-binary

# --- Stage: lego binary --------------------------------------------------------------
# Source only, never run. BuildKit rejects variable expansion in `COPY --from`, so the
# pinned reference is a named stage, as for the gateway. `:?` fails an empty LEGO_DIGEST.
FROM goacme/lego:${LEGO_TAG}@${LEGO_DIGEST:?LEGO_DIGEST_must_be_set_to_sha256:64hex} AS lego-binary

# --- Stage: runtime ------------------------------------------------------------------
FROM python:${PYTHON_TAG}@${PYTHON_DIGEST:?PYTHON_DIGEST_must_be_set_to_sha256:64hex} AS runtime

# ARGs do not survive across FROM boundaries — re-declare to pull them into this stage.
# Upstream has no `--version` flag, so the build arg is the source of truth for
# GWOPS_GATEWAY_VERSION, baked as ENV (not left as ARG) so it is present in the running
# container. gwops reports it in /status and never enforces it.
ARG GATEWAY_TAG=2.0.0
ARG GATEWAY_DIGEST=sha256:4993a7db015f7c2091d55f1c7a36c3e0c277137cb9937a46e9ced2c17456a6d1
# Refuse any tag that is not a v2 release or a pinned v2 preview: `latest`, `dev`, `2`,
# `2.0` or a tag with embedded newlines would resolve to whatever the registry currently
# points at, defeating the pin. The digest must be a full sha256 so the pin cannot fall
# back to the mutable tag. gwops renders only the 2.0 config schema. The build fails
# otherwise.
RUN printf %s "${GATEWAY_TAG}" | grep -Ezq '^2\.[0-9]+\.[0-9]+(-dev-[0-9a-f]{7,40})?$' \
    || { echo "ERROR: GATEWAY_TAG must be 2.X.Y or 2.X.Y-dev-<git sha>, got '${GATEWAY_TAG}'" >&2; exit 1; }
RUN printf %s "${GATEWAY_DIGEST}" | grep -Ezq '^sha256:[0-9a-f]{64}$' \
    || { echo "ERROR: GATEWAY_DIGEST must be sha256:<64 hex>, got '${GATEWAY_DIGEST}'" >&2; exit 1; }
ENV GWOPS_GATEWAY_VERSION=${GATEWAY_TAG}

# lego pin guard. Only v5.X.Y release tags are accepted (no `latest`, `v5`, `v5.5`), and
# the digest must be a full sha256. `:?` makes an empty LEGO_DIGEST fail the build with a
# message naming it.
ARG LEGO_TAG=v5.5.2
ARG LEGO_DIGEST=sha256:1944e8c36055beec47c7de6f15202b41128be75eea0ffa257f0c14d93c5155fd
RUN printf %s "${LEGO_TAG}" | grep -Ezq '^v5\.[0-9]+\.[0-9]+$' \
    || { echo "ERROR: LEGO_TAG must be v5.X.Y, got '${LEGO_TAG}'" >&2; exit 1; }
RUN printf %s "${LEGO_DIGEST:?LEGO_DIGEST_must_be_set_to_sha256:64hex}" | grep -Ezq '^sha256:[0-9a-f]{64}$' \
    || { echo "ERROR: LEGO_DIGEST must be sha256:<64 hex>, got '${LEGO_DIGEST}'" >&2; exit 1; }

# Non-root runtime user with a fixed uid so mounted-volume ownership is predictable.
RUN groupadd --gid 10001 gwops \
    && useradd --uid 10001 --gid 10001 --home-dir /home/gwops \
        --create-home --shell /usr/sbin/nologin gwops

# Install the control plane. Dependencies come from requirements.lock: every package,
# transitive ones included, pinned to an exact version with sha256 hashes, so the build
# installs nothing unpinned (--require-hashes refuses any requirement without a hash).
# Every runtime dependency ships as a wheel (pydantic-core, cryptography, watchfiles all
# have cp312 manylinux wheels), so slim needs no compiler; --only-binary makes a missing
# wheel fail the build instead of compiling an sdist. The lock holds setuptools, the
# build backend, which gwops is built with offline (--no-build-isolation) and which is
# removed afterwards. The lock is copied first so a source edit does not re-run the install.
COPY requirements.lock /tmp/build/requirements.lock
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/build/requirements.lock
# Build in /tmp and delete it: `pip install .` copies gwops into site-packages, so the
# source tree is not needed at runtime.
COPY pyproject.toml README.md /tmp/build/
COPY src /tmp/build/src
# Release version, baked into the package source before it is installed. No ENV: the
# value lives only in gwops/_version.py.
ARG GWOPS_VERSION=0.0.0-dev
RUN printf %s "${GWOPS_VERSION}" | grep -Ezq '^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$' \
    || { echo "ERROR: GWOPS_VERSION must match ^[0-9A-Za-z][0-9A-Za-z._-]{0,63}\$, got '${GWOPS_VERSION}'" >&2; exit 1; }
RUN printf '"""Release version of gwops, written at image build time."""\n\n__version__ = "%s"\n' "${GWOPS_VERSION}" \
    > /tmp/build/src/gwops/_version.py
RUN pip install --no-cache-dir --no-deps --no-build-isolation /tmp/build \
    && pip uninstall --yes setuptools \
    && rm -rf /tmp/build /root/.cache

# The gateway binary from the official image (exposed there at /gateway).
COPY --from=gateway-binary /gateway /usr/local/bin/gateway

# The lego binary from the official image (exposed there at /lego). Runs as uid 10001 on a
# read-only rootfs; always invoked with an explicit --path under /data/acme.
COPY --from=lego-binary /lego /usr/local/bin/lego

# Runtime dirs, owned by the non-root user:
#   /data        persistent state, overlays, PKI, recording spool  (declared a volume)
#   /run/gateway rendered config + runtime scratch
#   /config      read-only mount point for the seed (seed.yaml lands here)
RUN mkdir -p /data /run/gateway /config \
    && chown gwops:gwops /data /run/gateway /config

USER gwops

# Gateway listener, gateway metrics/health, gwops admin API.
EXPOSE 8443 9090 8081
VOLUME /data

# curl is absent from slim; the healthcheck is a tiny httpx probe of the admin API's
# unauthenticated /healthz. Exit 0 = healthy, 1 = anything else.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
    CMD ["python", "-m", "gwops.healthcheck"]

ENTRYPOINT ["python", "-m", "gwops"]
