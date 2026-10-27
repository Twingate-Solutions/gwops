# SSH resources

Each `ssh_upstreams` entry is one SSH target the gateway fronts. gwops keeps one Twingate SSH
resource per entry in sync: named after the entry, with the entry's address, attached to this
gateway, and assigned the groups and security policy you declare. The gateway authenticates the
user through Twingate and opens the SSH session to the target with a short-lived certificate signed
by the SSH CA.

## When to use

You want privileged SSH access to hosts through the gateway, with Twingate identity and,
optionally, session recording.

## Prerequisites

- A running gwops container (see the [quickstart](../quickstart/README.md)).
- The SSH target is reachable from the container on its SSH port.
- You can edit `sshd_config` on the target and reload `sshd`.
- The groups and security policy you assign already exist on the tenant. gwops assigns them; it
  never creates them.

## Steps

### Declare the target

In the seed:

```yaml
ssh_upstreams:
  - name: web-1
    address: 10.0.10.5:22
    access:
      groups: ["Platform Engineers"]
      security_policy: "Privileged Access MFA"
  - name: build-box
    address: build.internal.example.com
# ...rest of your seed
```

| Key | Rule |
| --- | --- |
| `name` | `[a-z0-9-]{1,63}`, unique among `ssh_upstreams`. It is also the Twingate resource's name. |
| `address` | `host` or `host:port`. The port defaults to 22. gwops lowercases it. The Twingate resource address is the host without the port. IPv6 literals are not accepted; use a DNS name. |
| `access` | Optional. `groups` (a list) and `security_policy`, each an exact name or `{id: <GraphQL id>}`. A key you set replaces `twingate.resource_defaults` for this resource; a key you omit falls back to it. `groups: []` means no groups. |

Save the seed. gwops picks up the change within a few seconds, creates the SSH resource and
re-mints the gateway's TLS leaf so it covers the new address. The leaf change hot-reloads; the
gateway does not restart. See [Access control](access-control.md) for how references resolve and
how later changes are applied.

In [public certificate mode](public-certs-files.md), `address` must be a DNS name inside a
`public_tls` zone and covered by a certificate; IP addresses are refused at load. See
[Mix certificate sources; SSH and Kubernetes in public mode](public-mode-mixed.md).

### Trust the SSH CA on each target

The target must trust the SSH CA that signs the gateway's user certificates.

1. Copy the public key. For a generated SSH CA:

   ```sh
   docker compose exec gateway cat /data/pki/ssh-ca.key.pub > twingate-gateway-ssh-ca.pub
   ```

   For a [bring-your-own SSH CA](private-ca-byo.md), use your `<key_path>.pub`.

2. Install it on the target and reference it from `/etc/ssh/sshd_config`:

   ```text
   TrustedUserCAKeys /etc/ssh/twingate-gateway-ssh-ca.pub
   ```

3. Reload `sshd`, for example `sudo systemctl reload sshd` (the unit is `ssh` on some
   distributions).

The gateway's user certificates are valid for 5 minutes. For login names, principals and other
target-side settings, see the [Twingate documentation](https://www.twingate.com/docs).

### Connect

A user who is a member of an assigned group, signed in to the Twingate Client, connects to the
resource address with their usual SSH client, for example `ssh <user>@10.0.10.5`. See the
[Twingate documentation](https://www.twingate.com/docs) for Client-side setup.

### Add, change and remove targets at runtime

The admin API adds, changes and removes targets without a seed edit. Each change persists as an
overlay under `/data/overlays/` and is reconciled before the response returns: it is kept only if
the tenant confirms it.

```sh
export BASE=http://127.0.0.1:8081
export TOKEN=<admin-token>   # the GWOPS_ADMIN_TOKEN value from .env

# Add or update
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"address": "10.0.10.6:22", "access": {"groups": ["Platform Engineers"]}}' \
  $BASE/upstreams/ssh/web-2

# Remove
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" $BASE/upstreams/ssh/web-2
```

- `PUT` merges by name: fields the body omits keep their stored value. It also works on a target
  declared in the seed; the change is stored as an overlay and the seed is never written.
- Group and policy names are resolved to ids before anything is stored, so an unknown name is a
  `422`.
- Writes must stay inside `twingate.address_allowlist` and `twingate.access_allowlist` when the
  seed sets them (`403` otherwise).
- `DELETE` removes the target and its Twingate resource. A failed write rolls back and answers
  `422`, or `503` when the tenant is unreachable.

An unattended caller can do the same with the automation token, inside its namespace; see
[Automation and CI](automation-and-ci.md).

### Recording

With [session recording](session-recording.md) on, the gateway records interactive SSH sessions.
The gateway's SSH backend writes a whole session as one recording line; a line larger than 16 MiB
is dropped and that recording is lost. With recording off, nothing is recorded or shipped.

### Limits

- SSH port forwarding through the gateway is neither gated nor audited by the gateway.
- Command controls are guardrails, not a jail.
- gwops only manages the SSH resources it created. A resource you create in the Admin Console is
  never changed or deleted by gwops.

## Verify

```sh
curl -s -H "Authorization: Bearer $TOKEN" $BASE/upstreams/ssh/web-1 | jq
```

- `tg_resource_id` is set: the Twingate resource exists.
- `effective_access` shows the groups and policy after defaults; `applied_access` shows the ids
  gwops last applied.
- `errors` is empty and `gateway_mismatch` is `null`.
- `origin` is `seed`, `admin` or `automation`.

In `/status`, `last_reconcile.actions` lists `created ssh resource 'web-1' (<id>)` on the pass that
created it, and `certs.leaf_state` is `ok`.

## Roll back

Remove the entry from the seed, or `DELETE /upstreams/ssh/{name}`. gwops deletes the Twingate
resource it created and re-mints the leaf without the address. To revert an API change instead,
delete its overlay with `DELETE /overlays/{id}` (see `GET /overlays` for ids).

## Related

- [Twingate integration](../architecture/twingate-integration.md): resource sync and ownership.
- [Seed reference: `ssh_upstreams`](../reference/seed.md#ssh_upstreams),
  [`twingate`](../reference/seed.md#twingate)
- [Admin API: `PUT /upstreams/{segment}/{name}`](../reference/admin-api.md#put-upstreamssegmentname),
  [`GET /upstreams/{segment}/{name}`](../reference/admin-api.md#get-upstreamssegmentname),
  [`DELETE /upstreams/{segment}/{name}`](../reference/admin-api.md#delete-upstreamssegmentname)
- [Access control](access-control.md), [Session recording](session-recording.md)
