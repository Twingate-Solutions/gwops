# Rig-only: an OpenSSH client run in the headless Client's network namespace (`docker run
# --network container:<client>`). Built per run; never pushed.
FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*
