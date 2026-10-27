# Rig-only: the gwops image plus gateway shims. gateway-stdio merges the binary's stderr into
# stdout; gateway-tee (--gatorcast runs) keeps stderr and copies it to stdout.
# Built per run from the local `make image` result; never pushed. The shims are baked in (not
# bind-mounted) so their LF endings and exec bit do not depend on the host file system.
ARG BASE_IMAGE=gwops-gateway:dev
FROM ${BASE_IMAGE}
USER root
COPY gateway-stdio.sh /usr/local/bin/gateway-stdio
COPY gateway-tee.sh /usr/local/bin/gateway-tee
RUN sed -i 's/\r$//' /usr/local/bin/gateway-stdio /usr/local/bin/gateway-tee \
    && chmod 0755 /usr/local/bin/gateway-stdio /usr/local/bin/gateway-tee
USER gwops
