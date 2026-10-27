# Rig web-app GAT verifier. Built locally by the live rig (compose.rig.yaml); never published.
# Pip-installs requirements.txt only; pyjwt stays out of the gwops image.
FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin verifier

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app.py _version.py ./
# Release version, baked into _version.py at build time. No ENV.
ARG VERIFIER_VERSION=0.0.0-dev
RUN printf %s "${VERIFIER_VERSION}" | grep -Ezq '^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$' \
    || { echo "ERROR: VERIFIER_VERSION must match ^[0-9A-Za-z][0-9A-Za-z._-]{0,63}\$, got '${VERIFIER_VERSION}'" >&2; exit 1; }
RUN printf '"""Verifier version, written at image build time."""\n\n__version__ = "%s"\n' "${VERIFIER_VERSION}" \
    > /app/_version.py

USER 10001:10001
EXPOSE 8443

# Required at run time: TWINGATE_NETWORK, TWINGATE_HOST, GAT_EXPECTED_RESOURCE_ID,
# VERIFIER_TLS_CERT, VERIFIER_TLS_KEY (files readable by uid 10001). Optional: VERIFIER_PORT.
ENTRYPOINT ["python", "app.py"]
