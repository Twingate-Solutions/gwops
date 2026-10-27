# Choose how gwops finds the Gateway object

gwops serves one Gateway object on your tenant. The seed names it in one of two ways:

| Mode | Seed keys | What gwops does on the tenant |
| --- | --- | --- |
| Pinned-gateway mode | `twingate.gateway_id` | Uses the Gateway object you created, as-is. Binds it to the CAs gwops generates. |
| Remote-network mode | `twingate.remote_network` or `twingate.remote_network_id`, plus `twingate.gateway_address` | Adopts the Gateway object already at that address in that Remote Network, or creates one. |

Set exactly one mode. Both or neither is a seed error and startup aborts.

## When to use

- **Remote-network mode** when you want no Admin Console step for the Gateway object. This is the
  common path with gwops-generated CAs.
- **Pinned-gateway mode** when the Gateway object already exists, when someone else manages it, or
  when you bring your own X.509 CA (remote-network mode cannot create a Gateway object without a
  generated X.509 CA).

## Prerequisites

- A Twingate tenant with a Remote Network and a healthy Connector in it.
- The Connector can reach this container on TCP 8443 (published as `8443:8443` by `compose.yaml`).
- `TWINGATE_API_KEY` set in `.env`, with read and write access, including resources, certificate
  authorities and gateways. Without a key gwops resolves nothing on the tenant.
- For pinned-gateway mode: the GraphQL id of the Gateway object. You can read it from the Twingate
  GraphQL API.

## Steps

### Remote-network mode

1. Pick the address the Connector uses to reach the container's port 8443, for example the Docker
   host's LAN address. The port is required.
2. Set the `twingate` block. Give the Remote Network by its exact name (`remote_network`) or by its
   GraphQL id (`remote_network_id`), not both:

   ```yaml
   twingate:
     network: acme
     host: twingate.com
     remote_network: Production DC
     gateway_address: 10.0.0.20:8443
   # ...rest of your seed
   ```

3. Keep `ca.x509.generate: true` (the default). gwops registers the X.509 CA it generates and
   creates the Gateway object bound to it.
4. Start or restart the container: `docker compose up -d`.

On its first pass with an API key, gwops:

1. Resolves the Remote Network. A name must match exactly one Remote Network.
2. Looks for a Gateway object in that Remote Network whose address equals `gateway_address`.
3. If it finds one, it adopts it and binds it to the CAs it registered in the same pass. An adopted
   Gateway object is rebound to the gwops CAs.
4. If it finds none, it creates one bound to the registered X.509 CA and, when gwops generated it,
   the SSH CA.
5. Records the Gateway object's id as `gateway/self` in the ownership registry,
   `/data/state.json`, and reuses it on every later pass.

In [public certificate mode](public-certs-files.md) the same flow applies, except that the Gateway
object is created bound to the registered public root instead of a gwops X.509 CA.

> **Note:** With a bring-your-own SSH CA, gwops creates the Gateway object without an SSH CA
> binding. Bind your SSH CA to the Gateway object on the tenant yourself. Untested behaviour:
> this project has not created a Gateway object with no SSH CA against a tenant. Test it before
> you rely on it, or use pinned-gateway mode.

### Pinned-gateway mode

1. Create the Gateway object on your tenant, or find the existing one, and note its GraphQL id.
2. Set `gateway_id` and leave out `remote_network`, `remote_network_id` and `gateway_address`:

   ```yaml
   twingate:
     network: acme
     host: twingate.com
     gateway_id: R2F0ZXdheTox
   # ...rest of your seed
   ```

3. Start or restart the container: `docker compose up -d`.

On its first pass, gwops records the id as `gateway/self`, registers each CA it generated, and
binds the Gateway object to them. With a [bring-your-own CA](private-ca-byo.md) gwops registers and
binds nothing: register the CA on the tenant and bind it to the Gateway object yourself.

### Seed errors

The seed is refused at load, with startup exiting and logging `supervisor.startup_failed`, when the
mode keys do not add up:

| You set | Error text |
| --- | --- |
| `gateway_id` and any of `remote_network`, `remote_network_id`, `gateway_address` | `set either gateway_id (to pin an existing gateway) or remote_network + gateway_address (to auto-create), not both` |
| None of the mode keys | `provide gateway_id, or remote_network(_id) + gateway_address` |
| `remote_network` or `remote_network_id` without `gateway_address` | `remote-network mode requires gateway_address (a connector-reachable host:port for the gateway, e.g. 10.0.0.1:8443)` |
| `gateway_address` without a Remote Network | `remote-network mode requires exactly one of remote_network (console name) or remote_network_id (GraphQL id)` |
| Both `remote_network` and `remote_network_id` | `set exactly one of remote_network (console name) or remote_network_id (GraphQL id), not both` |
| `gateway_address` without a port | `gateway_address '10.0.0.20' must be host:port with an explicit port (e.g. 10.0.0.1:8443)` |

Tenant-side failures do not abort startup. They appear in `/status` `tg.errors` and
`last_reconcile.errors` and are retried on the next pass:

- `gateway resolve/create: no remote network named 'Production DC'`: the name does not match a
  Remote Network exactly.
- `cannot auto-create the gateway: no registered X.509 CA. ...`: remote-network mode found no
  Gateway object at the address, and there is no generated X.509 CA to create one with. Use
  pinned-gateway mode, or set `ca.x509.generate: true`.

### Changing the mode or the Gateway object later

The recorded `gateway/self` id takes precedence over the seed. Once gwops has recorded a Gateway
object, changing `gateway_id`, `remote_network` or `gateway_address` in the seed does not move it to
a different Gateway object. To serve a different Gateway object:

1. Stop the container: `docker compose stop gateway`.
2. Remove the `gateway/self` entry from the `ids` map in `/data/state.json`, or start from an empty
   `/data` volume. Back up `/data` first (see [Back up and restore `/data`](../operations/backup-and-restore.md)).
3. Change the seed and start the container.

gwops binds a Gateway object to its CAs only in the pass that registers them, and the CAs recorded
as `ca/x509` and `ca/ssh` are already registered. Bind the new Gateway object to those existing
`gwops-x509-*` and `gwops-ssh-*` CA objects on the tenant yourself. Remote-network mode is the
exception: a Gateway object it creates is created bound to the recorded CAs.

### If `/data/state.json` is lost

- In remote-network mode, gwops finds the Gateway object again by its address and adopts it.
- In pinned-gateway mode, it uses `gateway_id` from the seed again.
- The registry no longer lists the resources gwops created, so gwops creates them again and the
  previous resource objects are left on the tenant, unmanaged. Delete them in the Admin Console.
- With generated CAs, gwops registers its CA again as a new CA object and rebinds the Gateway
  object to it.

This is the expected behaviour from how the registry works; it has not been exercised against a
tenant. Keep `/data` on a persistent volume and back it up.

## Verify

```sh
export BASE=http://127.0.0.1:8081
export TOKEN=<admin-token>   # the GWOPS_ADMIN_TOKEN value from .env

curl -s -H "Authorization: Bearer $TOKEN" $BASE/status | jq '{tg: .tg, actions: .last_reconcile.actions}'
```

- `tg.ok` is `true` and `tg.errors` is empty.
- On the first pass, `last_reconcile.actions` contains one of `adopted existing gateway (<id>) at
  10.0.0.20:8443` or `created gateway (<id>) at 10.0.0.20:8443 in remote network <id>` (remote-network
  mode), and `registered X.509 CA (<id>) and bound it to gateway` when gwops generated the CA. Later
  passes do not repeat these lines.
- In the Admin Console, the Gateway object shows the gwops CAs, named `gwops-x509-<label>` and
  `gwops-ssh-<label>`. The label is the `gateway_id` in pinned-gateway mode and the
  `gateway_address` in remote-network mode.

`jq` is optional; it only trims the output.

## Roll back

gwops never deletes the Gateway object or the CA objects it registered. To stop using a Gateway
object that gwops created, stop the container and delete the Gateway object and the `gwops-*` CA
objects in the Admin Console. To keep the container but serve a different Gateway object, follow
[Changing the mode or the Gateway object later](#changing-the-mode-or-the-gateway-object-later).

## Related

- [Twingate integration](../architecture/twingate-integration.md): what gwops reads and writes on
  the tenant, and the ownership registry.
- [Seed reference: `twingate`](../reference/seed.md#twingate)
- [Generated private CAs](private-ca-generated.md), [Bring your own CA](private-ca-byo.md)
- [Back up and restore `/data`](../operations/backup-and-restore.md)
- [Twingate documentation](https://www.twingate.com/docs)
