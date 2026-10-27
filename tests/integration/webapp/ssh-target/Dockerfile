# Rig-only: a non-root sshd that trusts the run's gwops SSH CA and logs in the gateway's fixed
# principal (`gateway`). It runs as that user, so it needs no capabilities. Built per run.
FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && useradd --uid 10001 --create-home --shell /bin/bash gateway \
    && usermod -p '*' gateway
COPY sshd_config /etc/rig-ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh /etc/rig-ssh/sshd_config \
    && chmod 0755 /usr/local/bin/entrypoint.sh
USER gateway
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
