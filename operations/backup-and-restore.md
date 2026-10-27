# Backup and restore

Everything gwops must remember lives on the `/data` volume: the CA keys, the record of which
tenant objects it created, the changes made through the admin API, undelivered recordings and
ACME state. The seed and the files under `/config` are yours and live outside the container.
Back up `/data` as a whole and restore it as a whole.

> **Security:** a `/data` backup holds the X.509 and SSH CA private keys, the leaf key,
> Kubernetes bearer-token copies, and undelivered recordings, which are not redacted. Anyone
> with the backup can sign certificates your SSH targets and browsers trust. Encrypt it and
> restrict access to it as you would the CA itself.

> **Note:** Untested example. The backup and restore commands on this page have not been run by this project. Adapt them to your environment and test them before you rely on them.

## When to use

- Before every upgrade, seed restructure or host move.
- On a schedule, so a lost volume does not mean re-trusting CAs on every target.
- When moving the container to a new host.

## Prerequisites

- The deployment directory with `compose.yaml`, `.env` and `seed.yaml`. Back those up
  separately; `.env` holds secrets.
- Space for the archive. The spool can be up to `recording.spool_max_bytes` (default 256 MiB).

## Steps

### Know what `/data` holds

| Path | What it is | If it is lost |
| --- | --- | --- |
| `pki/` | The X.509 and SSH CAs (generated ones, and any staged or archived during rotation) and the leaf. | gwops generates new CAs. SSH targets must trust the new SSH CA and browsers the new X.509 CA. See the note below the table. |
| `state.json` | The ownership registry: the tenant ids of the CAs, Gateway object and resources gwops created, and the access it last applied. | gwops no longer knows which tenant objects it made. It creates new resources and leaves the old ones on the tenant, orphaned. It registers its CAs again as new tenant objects. In remote-network mode it re-adopts the Gateway object by address. |
| `overlays/` | Every change made through the admin API. | Those changes are gone from the effective state. If `state.json` survives, gwops deletes the tenant resources that only those overlays declared. |
| `spool/` | Recording lines not yet acknowledged by the receiver. | Those recordings are lost. |
| `k8s-creds/`, `upstream-ca/` | Copies of the Kubernetes credentials and web-app CA bundles from `/config`. | Recreated from `/config` on the next pass. |
| `public-tls/` | Installed public certificates. | `source: file` certificates are reinstalled from `/config/public-tls`. `source: acme` certificates are issued again. |
| `acme/` | The ACME account, lego's storage, and the issuance schedule and backoff state. | A new ACME account is registered and every `source: acme` certificate is issued again, which can run into the CA's rate limits. |

The orphaning and deletion behaviour in this table follows from how the reconciler uses the
ownership registry: it creates a resource when it has no recorded id for it, and deletes a
recorded resource that the effective state no longer declares.

Keep `pki/` and `state.json` from the same backup. If `pki/` is lost while `state.json`
survives, gwops generates a new X.509 CA but does not register it, because the registry still
records the old one; the tenant keeps the gateway bound to the old CA and the new leaf does not
match it. A CA rotation (`POST /certs/rotate-ca`, `stage` then `complete`) registers a new
X.509 CA and rebinds the gateway. There is no route for the SSH CA.

Bring-your-own CA files live wherever your seed points. Back them up with your PKI, not only
with `/data`.

### Back up

Stop the container for a consistent copy. A copy taken while it runs is crash-consistent at
best: gwops writes its files atomically, but an archive taken mid-pass can mix states.

```sh
docker compose stop gateway
docker compose run --rm -T --no-deps --entrypoint tar gateway -C /data -czf - . > gwdata-$(date +%Y%m%d).tgz
docker compose start gateway
```

`docker compose run` mounts the same `gwdata` volume and runs as the image's user (uid 10001),
so it can read every file. `-T` keeps the output binary-safe. The archive preserves the symlinks
the certificate store uses.

### Restore

Restore into an empty volume before the container's first start, or stop it first.

```sh
docker compose stop gateway
docker compose run --rm -T --no-deps --entrypoint sh gateway -c 'find /data -mindepth 1 -delete'
docker compose run --rm -T --no-deps --entrypoint tar gateway -C /data -xzf - < gwdata-20261027.tgz
docker compose start gateway
```

The second command empties the volume, so files from the failed state do not mix with the
backup. It deletes everything under `/data`; check you are pointing at the right deployment
before running it.

Extracting as uid 10001 leaves every file owned by the user gwops runs as. If you restore with
another tool, make sure everything under `/data` is owned by uid and gid 10001, with keys
readable only by that user.

On a new host, copy the deployment directory first, then run the restore commands; Compose
creates the volume on first use.

### Restore from an older backup

A restored `state.json` describes the tenant as it was when the backup was taken:

- Resources gwops created after the backup are not in the registry. gwops does not touch them;
  delete them in the Admin Console if the restored state no longer declares them.
- Resources deleted since the backup are recreated if the restored state declares them
  (`recreated ... resource` in `last_reconcile.actions`).
- Overlays made after the backup are gone. Re-apply them through the admin API.
- The restored spool can hold lines the receiver already acknowledged. They are sent again;
  the receiver must remove duplicates, as it must for any redelivery.

## Verify

After a restore:

```sh
curl -s -H "Authorization: Bearer $TOKEN" $BASE/status | jq '{reconcile: .last_reconcile.ok, actions: .last_reconcile.actions, tg: .tg.ok, leaf: .certs.leaf_state}'
```

- `last_reconcile.ok` and `tg.ok` are `true`.
- `last_reconcile.actions` shows no `created ... resource` for entries that already existed,
  and no `created gateway`.
- `certs.leaf_state` is `ok` (private CA mode).
- `GET /overlays` lists the overlays you expect.

## Roll back

A restore replaces the volume's contents. To undo one, restore the archive you took before it.
Take a fresh backup of the current state before any restore.

## Related

- [Image reference: data volume layout](../reference/image.md#data-volume-layout)
- [Twingate integration](../architecture/twingate-integration.md): the ownership registry.
- [Certificates](../architecture/certificates.md): the PKI and the certificate store.
- [Upgrades and pins](upgrades-and-pins.md)
