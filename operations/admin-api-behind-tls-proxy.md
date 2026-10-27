# Admin API behind a TLS proxy

The admin API is plain HTTP. Every route except `GET /healthz` needs a bearer token, and the
token crosses the wire in clear text, so the API must never listen on a routable network
without TLS in front of it. This page covers the default, reaching it from the Docker host,
and two safe ways to reach it from elsewhere.

> **Security:** anyone who can send the admin token to the admin API can change which
> resources exist on your tenant and who can reach them (within the seed's allowlists), rotate
> certificates and read the effective state. Treat port 8081 as an administrative interface.

> **Note:** Untested example. The Caddy and nginx configurations on this page have not been run by this project. Adapt them to your environment and test them before you rely on them.

## When to use

- You want `curl` on the Docker host to reach the admin API.
- A CI system, a webhook relay or an operator on another machine needs the admin API.

## Prerequisites

- A working deployment.
- For option A: permission to create a Resource in the Twingate Admin Console, and a Connector
  that can reach the Docker host.
- For option B: a reverse proxy you run (the examples use Caddy and nginx) and a certificate for
  its name.

## Steps

### Know the defaults

- gwops listens on `admin_api.bind` and `admin_api.port`, default `127.0.0.1:8081`. These are
  addresses inside the container.
- `compose.yaml` publishes `127.0.0.1:8081:8081`: only the host's loopback interface.
- Both keys are seed-only and read once, at startup. Restart after changing them.

```yaml
admin_api:
  bind: 127.0.0.1
  port: 8081
# ...rest of your seed
```

Docker forwards a published port to the container's network interface, not to the container's
loopback. With the default `bind: 127.0.0.1`, the API answers only inside the container: the
image's healthcheck works, but `curl http://127.0.0.1:8081` on the host does not reach it.

### Reach it from the Docker host

Set gwops to listen on every container interface, and keep the loopback-only publish:

```yaml
admin_api:
  bind: 0.0.0.0
  port: 8081
# ...rest of your seed
```

```yaml
    ports:
      - "8443:8443"
      - "127.0.0.1:9090:9090"
      - "127.0.0.1:8081:8081"   # host loopback only
```

```sh
docker compose restart gateway
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8081/status
```

With `bind: 0.0.0.0`, other containers on the same Docker network can also reach port 8081. The
token still guards every route except `/healthz`. If that is not acceptable, run the container on
a network of its own.

### Option A: a Twingate resource for the admin port

Reach the admin API through Twingate itself, so only members of an admin group can connect,
with your security policy applied.

1. Set `admin_api.bind: 0.0.0.0` as above.
2. Publish the port on the host address the Connector reaches. Keep the loopback publish beside
   it if operators also call the API from the host:

   ```yaml
       ports:
         - "8443:8443"
         - "127.0.0.1:9090:9090"
         - "127.0.0.1:8081:8081"   # optional: host loopback, for operators on the host
         - "10.0.0.20:8081:8081"   # the host address your Connector reaches
   ```

3. In the Admin Console, create a Resource for that address, restricted to TCP port 8081, and
   grant it only to the group that administers the gateway. gwops does not create this
   resource: it is an ordinary Twingate network resource, not one of the gateway's upstreams.
4. Block port 8081 on that host interface for everything except the Connector, with the host
   firewall.
5. Restart: `docker compose up -d`.

Callers then use `http://10.0.0.20:8081` with the Twingate Client connected. The hop from the
Client to the Connector is encrypted by Twingate; the hop from the Connector to the Docker host
is plain HTTP on your network, so keep the Connector on the same host or a trusted segment, or
combine this option with option B.

### Option B: a TLS reverse proxy

Terminate TLS in a reverse proxy that runs beside the gateway on a Docker network. Remote
callers reach the API only through the proxy; 8081 is never published on a routable interface.

1. Set `admin_api.bind: 0.0.0.0` as above.
2. Decide whether to keep the `127.0.0.1:8081:8081` publish:
   - **Keep it** when operators run `curl` on the Docker host, as the recipes do. It binds the
     host's loopback only, so it adds no remote exposure.
   - **Remove it** when nothing on the host needs the API, or when other users on the host must
     not reach port 8081. The API is then reachable only from containers on the compose network.
3. Add the proxy service to the same compose project. With Caddy:

   ```yaml
   services:
     gateway:
       # ...the gateway service, unchanged
     admin-proxy:
       image: caddy:2
       restart: unless-stopped
       ports:
         - "443:443"
       volumes:
         - ./Caddyfile:/etc/caddy/Caddyfile:ro
         - caddy-data:/data

   volumes:
     gwdata:
     caddy-data:
   ```

   ```text
   gwops-admin.example.com {
       reverse_proxy gateway:8081
   }
   ```

   Caddy obtains a certificate for `gwops-admin.example.com` itself when that name is publicly
   resolvable and reachable. For an internal name, give it a certificate with the `tls`
   directive.

   With nginx, the equivalent server block:

   ```text
   server {
       listen 443 ssl;
       server_name gwops-admin.example.com;
       ssl_certificate     /etc/nginx/certs/fullchain.pem;
       ssl_certificate_key /etc/nginx/certs/privkey.pem;
       ssl_protocols       TLSv1.2 TLSv1.3;

       location / {
           proxy_pass http://gateway:8081;
           proxy_read_timeout 120s;
       }
   }
   ```

4. Restart: `docker compose up -d`.

The proxy forwards the `Authorization` header unchanged; gwops still checks it. Do not add a
proxy rule that answers for gwops or skips the token. Only `GET /healthz` is unauthenticated,
and it reports health booleans, not state.

Writes run a reconcile pass before they answer and can take several seconds, longer when the
gateway drain-restarts. Give the proxy a read timeout well above that, as in the nginx example.

### The healthcheck after a bind change

The image's healthcheck (`python -m gwops.healthcheck`) runs inside the container and reads
the effective `admin_api` settings each time. It probes `127.0.0.1` when `bind` is `0.0.0.0`,
`::`, `localhost` or `127.0.0.1`, and probes the bind address directly otherwise. Because gwops
reads `bind` and `port` only at startup, the healthcheck fails after you change either in the
seed until you restart the container.

## Verify

From the caller's machine:

```sh
curl -s https://gwops-admin.example.com/healthz
curl -s -o /dev/null -w '%{http_code}\n' https://gwops-admin.example.com/status   # 401 without a token
curl -s -H "Authorization: Bearer $TOKEN" https://gwops-admin.example.com/status
```

On the host, confirm 8081 is not published on a routable interface (`docker port` lists every
publish of the port; the service's container name is in `docker compose ps`):

```sh
docker port <container> 8081
```

For option B it prints `127.0.0.1:8081` if you kept the loopback publish, and nothing otherwise.
For option A it prints the address you chose, plus `127.0.0.1:8081` if you kept the loopback
publish.

The startup log line `api.serving` shows the bind address and port gwops is using.

## Roll back

Set `admin_api.bind` back to `127.0.0.1`, restore the `127.0.0.1:8081:8081` publish if you removed
it, remove the proxy service, and run `docker compose up -d`.

## Related

- [Admin API architecture](../architecture/admin-api.md): authentication, principals and
  exposure.
- [Seed reference: `admin_api`](../reference/seed.md#admin_api)
- [Admin API reference](../reference/admin-api.md)
- [Automation and CI](../guides/automation-and-ci.md)
