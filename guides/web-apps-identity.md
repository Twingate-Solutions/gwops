# Pass identity to a web app

The gateway can add headers to every request it forwards to a web app. A header value is static
text or text around one `{{key}}` template that the gateway fills per request. The `{{jwt}}` key
carries the user's signed Twingate access token, which the app can verify; other keys carry the
user name, groups or the client's location.

There are two places to set headers:

| Where | Applies to | Who can set it |
| --- | --- | --- |
| `web_apps[].request_headers` | One web app | Seed, or the admin API |
| `web_app_proxy.request_headers` | Every web app on this gateway | Seed only |

gwops does not verify tokens. The app does.

## When to use

- **Inject the token** when the app can verify a JWT and you want it to trust nothing else.
- **Inject identity headers** when the app supports trusted-header authentication, such as an
  `X-Remote-User` style header, and the upstream is reachable only through the gateway.

## Prerequisites

- A declared web app (see [Web apps](web-apps.md)).
- To inject `{{jwt}}`: the app's `upstream_tls` is `verify_full`, or the app is on `localhost` or a
  loopback IP.
- For the app owner: access to the tenant's key set at `https://<network>.<host>/api/v1/jwk/ec`
  from where the app runs.

## Steps

### Inject the access token into one app

```yaml
web_apps:
  - name: grafana
    address: grafana.apps.example.com:3000
    upstream_tls: verify_full
    request_headers:
      Authorization: "Bearer {{jwt}}"
# ...rest of your seed
```

Or a header of your own, such as `X-Twingate-Token: "{{jwt}}"`. Through the admin API:

```sh
export BASE=http://127.0.0.1:8081
export TOKEN=<admin-token>   # the GWOPS_ADMIN_TOKEN value from .env

curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"address": "grafana.apps.example.com:3000", "upstream_tls": "verify_full", "request_headers": {"Authorization": "Bearer {{jwt}}"}}' \
  $BASE/upstreams/webapp/grafana
```

A `request_headers` map replaces the stored map as a whole: a header the request omits is removed.
`{}` removes every header; `null` stops gwops managing the app's headers.

`{{jwt}}` toward an upstream with `upstream_tls` `verify_ca`, `insecure` or `none` is refused,
unless the upstream host is `localhost` or a loopback IP, because the token would reach a party the
gateway has not authenticated or would cross the network in plaintext:

```text
web_apps entry 'grafana': upstream_tls 'verify_ca' must not carry a {{jwt}} header (header 'Authorization') unless the upstream host is loopback: the upstream hostname is not checked, so any holder of a trusted certificate could receive the token
```

### Inject identity headers on every app

```yaml
web_app_proxy:
  request_headers:
    X-Twingate-User: "{{username}}"
    X-Twingate-Groups: "{{groups}}"
# ...rest of your seed
```

A gateway-wide header whose template uses `username`, `groups` or `jwt` is a **trusted name**:

- No web app's own `request_headers` may set it, so a per-app rewrite cannot override identity.
- gwops also renders it under every `-` and `_` spelling (`X_Twingate_User`, ...), so a client
  cannot slip a differently spelled copy past frameworks that treat both spellings as one. A
  trusted name may have at most 4 separators.

`{{jwt}}` is refused gateway-wide: it would replace every app's `Authorization` header and send
the token to every upstream. Set it per app instead.

Gateway-wide headers are rendered only while at least one web app is declared.

### Header rules

These apply to both places, for every write, and at startup.

| Rule | Detail |
| --- | --- |
| Template keys | `jwt`, `username`, `groups`, `clientGeoLatLong`, `clientGeoCity`, `clientGeoRegion`, `clientGeoCountry`. Case-sensitive. One `{{key}}` per value, with optional static text around it and no other braces. |
| Denied names | Hop-by-hop and framing: `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, `Content-Length`, `Expect`, any `Proxy-*`. Forwarding: `Forwarded`, `X-Real-IP`, `Via`, any `X-Forwarded-*`. Routing overrides: `X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`. Also `Cookie` and `Host`. Matched ignoring case, with `_` treated as `-`. |
| No static secrets | A static value under a secret-like name (for example `Authorization: Basic ...`), or static text that looks like a long high-entropy token, is refused. Use a template key. |
| Names and values | Names are 1 to 64 RFC 9110 token characters, unique ignoring case. Values are at most 1024 characters, not empty, with no control characters. |

A refused write answers `422` with every violation; error messages name headers but never print
values. `GET /upstreams/webapp/{name}` shows the value of a secret-like header name, such as
`Authorization`, as `[REDACTED]`.

### What the app owner verifies

When the app receives `{{jwt}}`, it can check the same access token the gateway checked:

- **Algorithm:** ES256 only.
- **Keys:** the tenant's key set at `https://<network>.<host>/api/v1/jwk/ec`. The keys are EC
  P-256 with a `kid` and no `alg` or `use` member.
- **`aud`:** the tenant's network name (`acme` for `acme.twingate.com`).
- **`iss`:** `twingate` for tenants on `twingate.com`. For other hosts, read `iss` from a real token
  before you pin it.
- **`exp`:** required.
- **Type:** the JOSE header `typ` is `GAT`, not `JWT`. Do not require `JWT`. The payload also
  carries `typ: "GAT"`.
- **`resource.id`:** must equal this app's Twingate resource id, the `tg_resource_id` from
  `GET /upstreams/webapp/{name}`. A token minted for another web app on the tenant passes the
  signature, `iss`, `aud` and `exp` checks; only this check rejects it.

The payload has this shape (other claims omitted; placeholders in angle brackets):

```json
{
  "iss": "twingate",
  "aud": "acme",
  "exp": 1791307957,
  "iat": 1791304386,
  "typ": "GAT",
  "resource": {
    "id": "UmVzb3VyY2U6NzE=",
    "type": "WEB_APP",
    "address": "grafana.apps.example.com"
  },
  "user": {
    "id": "<user id>",
    "username": "<username>",
    "groups": ["<group>"]
  },
  "sub": "<user id>"
}
```

A sketch of the check in Python with PyJWT, to adapt and test against a real token, not production
code:

```python
import jwt  # PyJWT, with the cryptography extra

JWKS = jwt.PyJWKClient("https://acme.twingate.com/api/v1/jwk/ec")
RESOURCE_ID = "UmVzb3VyY2U6NzE="  # tg_resource_id of this web app

def verify(token: str) -> dict:
    key = JWKS.get_signing_key_from_jwt(token).key
    claims = jwt.decode(
        token, key, algorithms=["ES256"], audience="acme", issuer="twingate",
        options={"require": ["exp", "aud", "iss"]},
    )
    if jwt.get_unverified_header(token).get("typ") != "GAT":
        raise jwt.InvalidTokenError("typ is not GAT")
    if claims.get("resource", {}).get("id") != RESOURCE_ID:
        raise jwt.InvalidTokenError("token was minted for another resource")
    return claims
```

### Apps that trust headers only

An app that authenticates by a trusted header, without verifying a token, trusts anyone who can
send it that header. Make the gateway the only way to reach it: bind the app to an interface only
the gateway can reach, or restrict it with a firewall to the gateway host. Otherwise a client that
reaches the app directly can claim any identity.

## Verify

```sh
curl -s -H "Authorization: Bearer $TOKEN" $BASE/upstreams/webapp/grafana | jq '{tg_resource_id, upstream_tls, request_headers, warnings, errors}'
curl -s -H "Authorization: Bearer $TOKEN" $BASE/state | jq '.state.web_app_proxy'
```

- `request_headers` lists the header names, with secret-like values shown as `[REDACTED]`.
- `errors` is empty.
- On the app side, log the received header names (not the token) for one request, and check that
  a token minted for another web app is rejected by the `resource.id` check.

## Roll back

Remove the header from `request_headers` (per app) or `web_app_proxy.request_headers` (gateway
wide). Through the API, send the app's full `request_headers` map without it, or `{}`.

## Related

- [Web apps architecture](../architecture/web-apps.md): header injection and the web-app policy.
- [Seed reference: `web_apps`](../reference/seed.md#web_apps),
  [`web_app_proxy`](../reference/seed.md#web_app_proxy)
- [Admin API: `web_apps` in `/status`](../reference/admin-api.md#web_apps)
- [Web apps](web-apps.md), [Web-app upstream TLS](web-apps-upstream-tls.md),
  [Automation and CI](automation-and-ci.md) (the automation token never sets `{{jwt}}`)
