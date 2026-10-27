# Front a Kubernetes API server

A `k8s_clusters` entry makes the gateway a proxy for one Kubernetes API server. gwops keeps a
Twingate Kubernetes resource for it in sync, renders the cluster into the gateway config, and copies
the credential files the gateway uses to reach the API server.

## When to use

You want `kubectl` access to a cluster to go through Twingate identity, with interactive sessions
optionally recorded.

## Prerequisites

- A running gwops container (see the [quickstart](../quickstart/README.md)).
- The API server is reachable from the container at a host name or IP and port.
- A bearer token file and the API server's CA certificate file. The gateway authenticates to the
  API server with that token, so the token's permissions bound what the gateway can do. See the
  [Twingate documentation](https://www.twingate.com/docs) for the permissions the gateway needs.
- One cluster per gateway. The gateway binary reads a single Kubernetes upstream. For a second
  cluster, run a second container.

## Steps

1. Put the credential files on the Docker host and make them readable by uid 10001:

   ```text
   k8s-creds/
     prod.token     # the bearer token
     prod-ca.crt    # the API server's CA certificate, PEM
   ```

   ```sh
   sudo chown -R 10001:10001 k8s-creds
   chmod 0600 k8s-creds/prod.token
   ```

2. Mount the directory read-only. In `compose.yaml`, under `volumes:` of the `gateway` service:

   ```yaml
   - ./k8s-creds:/config/k8s-creds:ro
   ```

3. Declare the cluster in the seed:

   ```yaml
   k8s_clusters:
     - name: prod
       address: prod.k8s.internal.example.com
       port: 6443
       bearer_token_file: /config/k8s-creds/prod.token
       ca_file: /config/k8s-creds/prod-ca.crt
       access:
         groups: ["Platform Engineers"]
   # ...rest of your seed
   ```

   | Key | Rule |
   | --- | --- |
   | `name` | `[a-z0-9-]{1,63}`. Also the Twingate resource's name. |
   | `address` | The API server host, without a scheme or port. gwops lowercases it. It is the Twingate resource address and is added to the gateway's TLS leaf. |
   | `port` | The API server port, 1 to 65535. Default 443. |
   | `bearer_token_file`, `ca_file` | Paths that resolve to regular files of at most 1 MiB under `/config/k8s-creds/`. A path that resolves outside it, through a symlink or `..`, is refused. |
   | `access` | Optional groups and security policy, as for [SSH resources](ssh-resources.md#declare-the-target). |

4. Save the seed. On the next pass gwops reads both files, writes content-addressed copies to
   `/data/k8s-creds/` (`prod-token-<sha12>` and `prod-ca-<sha12>.crt`), renders the cluster
   pointing at those copies, creates the Kubernetes resource and drain-restarts the gateway.

A credential file that cannot be read is a local error naming the path and the allowed root. The
pass then applies nothing and the gateway keeps its last good config.

### Rotate the credentials

Rewrite `prod.token` or `prod-ca.crt` in place on the host. On the next pass gwops copies the new
content to new content-addressed paths, renders them, and drain-restarts the gateway so it reads
them. Copies that no config references any more are removed after a fully successful pass. To apply
at once:

```sh
export BASE=http://127.0.0.1:8081
export TOKEN=<admin-token>   # the GWOPS_ADMIN_TOKEN value from .env

curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/reconcile
```

### Change the cluster through the admin API

`PUT /upstreams/k8s/{name}` and `DELETE /upstreams/k8s/{name}` work with the admin token only. The
automation token gets `403` for `k8s`: a cluster entry names credential files inside the container,
which an unattended caller must not choose. A Kubernetes change waits for the gateway's
drain-restart before it returns.

```sh
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"address": "prod.k8s.internal.example.com", "port": 6443, "bearer_token_file": "/config/k8s-creds/prod.token", "ca_file": "/config/k8s-creds/prod-ca.crt"}' \
  $BASE/upstreams/k8s/prod
```

### Only one cluster

A second `k8s_clusters` entry loads, but the gateway config cannot be rendered:

```text
2 Kubernetes clusters configured, but the gateway's 'kubernetes.upstreams' schema only consumes a single entry. Reduce to one cluster.
```

At startup this aborts startup. After startup the pass records it as a local error and the gateway
keeps running on its last good config. To move to a different cluster, replace the entry rather
than adding one.

### Connect

Users connect with the Twingate Client and a kubeconfig that points at the resource address. See
the [Twingate documentation](https://www.twingate.com/docs) for the Client and kubeconfig setup.

### Recording

With [session recording](session-recording.md) on, the gateway records interactive `kubectl exec`
and `kubectl attach` sessions with a TTY. Other API calls, such as `get` and `logs`, produce audit
lines but no recording.

### Public certificate mode

In [public certificate mode](public-mode-mixed.md), `address` must be a DNS name inside a
`public_tls` zone and covered by exactly one certificate. The in-cluster name
`kubernetes.default.svc` cannot be served.

## Verify

```sh
curl -s -H "Authorization: Bearer $TOKEN" $BASE/upstreams/k8s/prod | jq '{kind, tg_resource_id, effective_access, errors}'
curl -s -H "Authorization: Bearer $TOKEN" $BASE/status | jq '{process: .process.state, ok: .last_reconcile.ok, errors: .last_reconcile.errors}'
```

- `kind` is `kubernetes`, `tg_resource_id` is set and `errors` is empty.
- `process.state` is `running` and `last_reconcile.ok` is `true`.
- `docker compose exec gateway ls /data/k8s-creds/` lists the two content-addressed copies.

## Roll back

Remove the entry from the seed, or `DELETE /upstreams/k8s/prod`. gwops deletes the Kubernetes
resource it created, renders the config without the cluster, and drain-restarts the gateway. The
credential copies are removed after the next fully successful pass.

## Related

- [Reconciler](../architecture/reconciler.md): credential copies and garbage collection.
- [Gateway process](../architecture/gateway-process.md): rendering and drain-restart.
- [Seed reference: `k8s_clusters`](../reference/seed.md#k8s_clusters)
- [Admin API: `PUT /upstreams/{segment}/{name}`](../reference/admin-api.md#put-upstreamssegmentname)
- [Session recording](session-recording.md), [Access control](access-control.md)
