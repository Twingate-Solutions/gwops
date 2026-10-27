# Access control

gwops assigns existing Twingate groups and security policies to the resources it creates. It
never creates, renames or deletes groups or policies, and never changes group membership. Two
seed-only allowlists bound what any admin-API write may grant or target.

## When to use

- You want every resource gwops creates to be granted to a group, with a security policy.
- Some upstreams need different access from the rest.
- You let API callers (people, CI or a webhook) add upstreams and want to limit which groups,
  policies and addresses they can use.

## Prerequisites

- The groups and security policies already exist on the tenant. Create them in the Admin
  Console or your identity provider; see the [Twingate documentation](https://www.twingate.com/docs).
- Each name you reference is unique on the tenant, or you reference it by id.
- `TWINGATE_API_KEY` is set: names are resolved against the tenant.

## Steps

### 1. Set defaults for every resource

`twingate.resource_defaults` applies to every resource whose own `access` block omits a key.

```yaml
twingate:
  network: acme
  host: twingate.com
  remote_network: Production DC
  gateway_address: 10.0.0.20:8443
  resource_defaults:
    groups: ["Platform Engineers"]
    security_policy: "Privileged Access MFA"
# ...rest of your seed
```

### 2. Override access on individual resources

Any upstream entry (`ssh_upstreams`, `k8s_clusters`, `web_apps`) can carry its own `access`
block with `groups`, `security_policy`, or both.

```yaml
ssh_upstreams:
  - name: web-1
    address: 10.0.10.5:22              # uses resource_defaults for both keys
  - name: db-1
    address: 10.0.20.7
    access:
      groups: ["Database Admins"]      # replaces the default groups
                                       # security_policy omitted: uses the default
  - name: build-box
    address: build.internal.example.com
    access:
      groups: []                       # no groups, even though a default exists
# ...rest of your seed
```

gwops works out effective access separately for `groups` and for `security_policy`:

| The resource's own value | Effective access |
| --- | --- |
| Present and non-empty | Used as is. It replaces the default; it is never merged with it. |
| `groups: []` | No groups, even when a default exists. |
| Omitted, or `null` | The `twingate.resource_defaults` value. |
| Omitted, and no default | Not managed: gwops sends nothing and never changes it on the tenant. |

### 3. Choose a reference form

| Form | Example | Meaning |
| --- | --- | --- |
| Name | `"Platform Engineers"` | Exact, case-sensitive match. It must match exactly one object. |
| Id | `{id: R3JvdXA6MTIz}` | The object's GraphQL id. |
| Pinned | `{id: R3JvdXA6MTIz, name: Platform Engineers}` | The id is authoritative; the name is for display. |

A name that matches nothing, or more than one object, is an error. Use the id form when two
groups share a name.

When names are resolved depends on where they come from:

- **Seed names** are resolved on each reconcile pass. A successful lookup is cached for the
  life of the process; a failed one is retried on the next pass, so a fix in the Admin Console
  is picked up without a restart. If you rename or recreate a group that the seed names,
  restart the container (or use the id form) so the cache does not hold the old id.
- **Admin-API names** are resolved when the write arrives and stored in the pinned form. A typo
  is a synchronous `422`, and a group created later under the same name cannot capture the
  access.

An unresolvable reference is a per-resource error in the pass. A resource that does not exist
yet is not created, so it never comes up with the wrong access. An existing resource keeps its
address and port in sync but skips the access change.

### 4. Understand how changes are applied

gwops records, per resource, the access it last applied (in `/data/state.json`) and applies
changes as a delta against that record:

- It adds the groups that are desired and not yet applied, and removes only groups it applied
  earlier. A group someone added in the Admin Console is never removed.
- It sets the security policy only when the policy is managed and differs from the last one it
  applied. It never resets a policy to the tenant default.
- A key that is not managed is left exactly as it is on the tenant. Removing `groups` from an
  entry and from the defaults stops gwops managing groups for that resource; it does not
  remove them.

### 5. Restrict admin-API writes with allowlists

Two seed-only keys bound every overlay and admin-API write, for the admin token as well as the
automation token:

```yaml
twingate:
  network: acme
  host: twingate.com
  remote_network: Production DC
  gateway_address: 10.0.0.20:8443
  access_allowlist:
    groups: ["Platform Engineers", "App Users"]
    security_policies: ["Privileged Access MFA"]
  address_allowlist:
    cidrs: ["10.0.10.0/24", "10.20.0.0/16"]
    dns_suffixes: ["apps.example.com"]
# ...rest of your seed
```

The rules:

- **Absent** allowlist: that dimension is unrestricted. **Empty list**: nothing is allowed for
  that key. `security_policies: []` refuses any write that sets a policy.
- Only what a write supplies is checked. Seed entries and `resource_defaults` are written by the
  seed's author and are implicitly allowed.
- `access_allowlist` is compared on resolved ids, so an `{id: ...}` reference cannot get past a
  name entry.
- `address_allowlist` covers `address` and a web app's `alias`. An IP literal must fall inside
  one of `cidrs`. A DNS name must equal one of `dns_suffixes` or end with it at a label
  boundary: `apps.example.com` allows `grafana.apps.example.com`, not `xapps.example.com`. No
  DNS resolution is done, so a name never matches a CIDR. With `cidrs` only, every DNS name is
  refused.
- A violation is `403` and nothing is persisted:

  ```json
  {"detail": "address allowlist: [\"'web-9': address '192.168.1.50' is not allowlisted\"]"}
  ```

  ```json
  {"detail": "access allowlist: [\"'web-9': group R3JvdXA6OTk5 is not on the access allowlist\"]"}
  ```

- If the access allowlist cannot be resolved (no API key, or the tenant is unreachable), the
  write is `503`.

Allowlists are required when you set `GWOPS_AUTOMATION_TOKEN`; see
[Automation and CI](automation-and-ci.md).

### 6. Apply the change

Seed edits are picked up automatically within a few seconds. To apply at once:

```sh
curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/reconcile
```

## Verify

Read one resource back:

```sh
curl -s -H "Authorization: Bearer $TOKEN" $BASE/upstreams/ssh/db-1
```

Check:

- `effective_access` holds the groups and policy after defaults. `null` means not managed.
- `applied_access` holds the ids gwops last applied on the tenant.
- `errors` is empty. An `access: no group named '...'` entry means the reference did not
  resolve.

`last_reconcile.actions` in `GET /status` lists each change, for example
`updated ssh resource 'db-1' access: ...`.

## Roll back

- To stop managing a key, remove it from the entry and from `resource_defaults`. gwops leaves
  the tenant value as it is; change it in the Admin Console if you need to.
- To lift an allowlist restriction, remove the allowlist key from the seed. Writes already
  refused were never persisted, so there is nothing to clean up.

## Related

- [Twingate integration](../architecture/twingate-integration.md): access assignment and the
  ownership registry.
- [Admin API architecture](../architecture/admin-api.md): guardrails and transactional writes.
- [Seed reference: `twingate`](../reference/seed.md#twingate)
- [Seed reference: `ssh_upstreams`](../reference/seed.md#ssh_upstreams),
  [`k8s_clusters`](../reference/seed.md#k8s_clusters), [`web_apps`](../reference/seed.md#web_apps)
- [Admin API: write semantics](../reference/admin-api.md#write-semantics)
