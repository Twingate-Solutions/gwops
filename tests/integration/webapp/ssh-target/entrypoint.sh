#!/bin/sh
# Wait for the run's SSH CA public key (bind-mounted at /ca by the rig), then run sshd.
set -eu
i=0
while [ ! -s /ca/ssh-ca.key.pub ]; do
    i=$((i + 1))
    [ "$i" -lt 120 ] || { echo "ssh-target: SSH CA public key never appeared" >&2; exit 1; }
    sleep 1
done
cp /ca/ssh-ca.key.pub /tmp/ssh-ca.pub
ssh-keygen -q -t ed25519 -N '' -f /tmp/ssh_host_ed25519_key
exec /usr/sbin/sshd -D -e -f /etc/rig-ssh/sshd_config
