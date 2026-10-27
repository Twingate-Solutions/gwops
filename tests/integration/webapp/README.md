# Live web-app integration rig

Runs the whole web-app path against a real Twingate tenant: gwops (built from this repo) creates
web apps through its own render, a connector and a headless Twingate Client reach them, and curl in
the Client's network namespace drives the assertions below. It is local-only. No GitHub Actions
workflow runs it, and `make test` neither collects nor runs it.

## Tenant rules

The rig writes to a live tenant. These rules are enforced in code (`rig/guards.py`,
`rig/tenant.py`) and covered by offline tests (`tests/test_rig_guards.py`, `tests/test_rig_run.py`).

- **Approved pair only.** The operator names the tenant and remote network twice: in
  `IT_TWINGATE_NETWORK` / `IT_TWINGATE_REMOTE_NETWORK_ID` and again in `IT_APPROVED_NETWORK` /
  `IT_APPROVED_REMOTE_NETWORK_ID`. The rig starts only when each approval equals its counterpart
  exactly; any difference, or an unset or empty variable, is refused before any docker or tenant
  call.
- **Net-new objects only.** The rig creates a connector, a service account and its key, a Gateway,
  an X.509 CA, an SSH CA and web apps, and deletes them again. Every name carries the run prefix
  `gwops-it-<run id>-` or the run's unique gateway address. It records every id it creates in
  `state.json`, and the sweep deletes only recorded ids.
- **Existing assets are untouchable.** The rig never modifies, reassigns, references or attaches to an
  existing gateway, resource, CA, group or security policy. It passes no `securityPolicyId` and no
  existing group id. Access is granted to the run's own service account only.
- **Mode B adoption guard.** gwops runs in Mode B with a per-run `gateway_address`. Setup aborts if
  any gateway with that address already exists in the remote network, because Mode B would adopt it.
- **Cleanup always runs.** The sweep runs in a `finally` block, after gwops is stopped, and the run
  ends by comparing the tenant inventory with the inventory taken before the run.
- **Resources fall under the tenant's default security policy.** The rig does not set one.
- **No other connector online in the remote network.** Operational rule; the rig does not check it.
  A connector from another stack in the same remote network takes the rig Client's traffic, so no
  host becomes ready and no connection reaches the rig's gateway. A run with a foreign connector
  online is invalid, not a gwops failure. Stop every other connector in the remote network before
  the run.
- **No console activity during a run.** The final inventory comparison is tenant-wide for
  gateways, resources, CAs, connectors and service accounts, so any change anyone makes in
  the tenant while the rig runs can fail it. Avoid console activity in the tenant until the run
  ends.

## Prerequisites

- Docker with Compose v2. The Client container needs `/dev/net/tun` and the `NET_ADMIN`
  capability.
- The project `.venv` with the dev dependencies (`pip install -e ".[dev]"`). The Make target uses
  `.venv/bin/python` (`.venv/Scripts/python.exe` on Windows).
- A tenant API key for the approved tenant with write access, supplied by the tenant owner. Use a dedicated key with a
  short expiry, created for the run.
- A local Docker engine. The rig and the sweep refuse a remote one (`DOCKER_HOST` set, or an active
  context that is not a local socket).
- Egress to the tenant's GraphQL API, `https://<tenant>.twingate.com/api/v1/jwk/ec` and Docker
  Hub (third-party images). Third-party images are pinned by tag and digest in `compose.rig.yaml`:
  `twingate/connector:1.93.0`, `twingate/client:2026.239`, `curlimages/curl:8.22.0` and
  `python:3.12-slim`.

## Environment variables

Read by the rig only, never by gwops' runtime. Child processes started by the rig do not inherit
any `IT_*` variable.

| Variable | Secret | Value |
|---|---|---|
| `IT_TWINGATE_API_KEY` | Yes | Tenant API key with write access. Passed to the rig's gwops container as `TWINGATE_API_KEY` and used by the setup and sweep code. |
| `IT_TWINGATE_NETWORK` | No | The tenant's network name (`<name>` in `<name>.twingate.com`). |
| `IT_TWINGATE_REMOTE_NETWORK_ID` | No | The id of the remote network the rig may write to. |
| `IT_APPROVED_NETWORK` | No | The operator's approval: must equal `IT_TWINGATE_NETWORK` exactly. |
| `IT_APPROVED_REMOTE_NETWORK_ID` | No | The operator's approval: must equal `IT_TWINGATE_REMOTE_NETWORK_ID` exactly. |

## Run

```sh
read -rs IT_TWINGATE_API_KEY; export IT_TWINGATE_API_KEY    # paste the key; it is not echoed
export IT_TWINGATE_NETWORK=<tenant-name>
export IT_TWINGATE_REMOTE_NETWORK_ID=<remote-network-id>
export IT_APPROVED_NETWORK=<tenant-name>                    # repeat the values to approve them
export IT_APPROVED_REMOTE_NETWORK_ID=<remote-network-id>

make image                 # builds gwops-gateway:dev on the pinned gateway binary
make integration-webapp
```

The Make target refuses to start when any `IT_*` variable is unset. The rig builds the
verifier image (`gwops-rig-verifier:local`) from `verifier/` in this folder; nothing is pushed.
Its Python dependencies are pinned to exact versions in `verifier/requirements.txt`.

`HOLD=1 make integration-webapp` keeps the rig up after the assertions; see
[Hold the rig for manual probes](#hold-the-rig-for-manual-probes).

Two options need the module invoked directly. On Windows use `.venv\Scripts\python.exe` in place of
`.venv/bin/python`:

```sh
.venv/bin/python -m tests.integration.webapp.run --image <local image tag>   # default gwops-gateway:dev
.venv/bin/python -m tests.integration.webapp.run --apply-timeout <seconds>   # bound for assertion 8
```

A run creates real objects and is throttled by the tenant API (about 12 rapid mutations per 30
seconds; the rig waits out the throttle hint). Assertion 8 waits for a new access token, so a run
can take as long as one token lifetime (about an hour) on top of setup.

## Gatorcast evidence (`--gatorcast`)

Opt-in; a default run is unchanged. gwops ships its recording lines to a real Gatorcast sink and the
run asserts what arrived. Needs egress to GHCR for `ghcr.io/twingate-solutions/gatorcast:latest`
(the Gatorcast image is pulled by tag, not digest; `--gatorcast-image <ref>` overrides it, and a
private image needs a prior `docker login ghcr.io`). The published image can predate the `gwops_*`
columns on `connections`; then assertion 12 fails. `--gatorcast-build <path>` builds
`gwops-it-gatorcast:local` from a Gatorcast source tree and uses it (implies `--gatorcast`). The
rig copies the tree (minus `.git`, `.venv`, caches) to a temp dir and builds from the copy, so the
source tree is only read.

```powershell
.venv\Scripts\python.exe -m tests.integration.webapp.run --gatorcast         # web-app evidence
.venv\Scripts\python.exe -m tests.integration.webapp.run --gatorcast-ssh     # plus the SSH leg
.venv\Scripts\python.exe -m tests.integration.webapp.run --gatorcast-ssh --gatorcast-build <path-to-twingate-asciicast-sink>
```

```sh
.venv/bin/python -m tests.integration.webapp.run --gatorcast
.venv/bin/python -m tests.integration.webapp.run --gatorcast-ssh
.venv/bin/python -m tests.integration.webapp.run --gatorcast-ssh --gatorcast-build ../twingate-asciicast-sink
GATORCAST=1 make integration-webapp          # GATORCAST_SSH=1 for the SSH leg
```

`--gatorcast-ssh` implies `--gatorcast`. The options combine with `--hold`.

**What changes.** The seed sets `recording: {enabled: true, receiver_url: http://ingest-tap:8080,
spool_max_bytes: 64 MiB}`. The rig adds a `gatorcast` service and an `ingest-tap` service (profile
`gatorcast`). gwops ships to the tap; the tap forwards to Gatorcast and writes one metadata record
per shipped line to `<run dir>\tap\ingest.jsonl` (size, sha256, logger, message, `gwops` object,
tail, sequence number and session-end markers of a recording; never a header or body). The tap re-implements the allowlist independently, so
a line gwops should have dropped shows up as `allowed: false`. Gatorcast drops lines it does not
classify, so its own store cannot prove their absence; the tap can. gwops runs with
`gateway-tee` instead of `gateway-stdio`: stderr stays on stderr (the recording path) and a copy,
minus asciicast lines, goes to stdout so `docker logs` and the skew check keep working.

**Secrets.** The ingest token and the Gatorcast UI password are generated per run, written to
`<run dir>\gatorcast.env` (mode 0600; the token also goes into `gwops.env` as `GWOPS_RECORDING_TOKEN`),
registered with the redactor, never printed, and emptied and deleted at teardown like the other env
files. Gatorcast publishes no host port; the rig reads it with `docker exec` (read-only SQLite).

| # | What it asserts |
|---|---|
| 12 | Each rig web app's `Authenticated connection` line (logger `system`) reached the tap with a `gwops` object (`match: exact`, `managed: true`, the app's name, downstream and upstream TLS mode and port as seeded), and Gatorcast's `connections` rows carry the same values. `match: none` lines (a connection before the first tenant listing) are counted, not failed; the plain and `verify_full` apps each need at least one exact line. |
| 13 | Every shipped line is allowlisted: no `http: proxy error` text, no gateway service line, no non-JSON line. |
| 14 | `/status` `shipper`: no `enrich_failed`, `spool_failed` or `too_long`; enrichment active; and some service line was dropped (the filter saw one). `dropped_lines`, `enrich_failed` and `enrichment` go to the summary metrics. |
| 15 | Alias: a request to the alias host. The summary records the `resource_address` the gateway logged and `gwops.match` (`exact` if the gateway logged the address, `none` if it logged the alias). Recorded only; never fails. |
| 16 | (`--gatorcast-ssh`) One interactive PTY shell session through the gateway (payload on stdin, `exit` at the end) prints about 3 MiB. The gateway records only `shell` requests, never `exec`. The recording arrives as capped `session recording` segment lines plus a final `session finished` line. For the session whose recording holds the session-end marker: every line is allowlisted and accepted by Gatorcast (2xx); the `asciicast_sequence_num` values are contiguous from 1 (a redelivered line counts once); the highest-numbered line is the `session finished` line and every earlier one is a `session recording` line; there are at least 2 segment lines before the final one; no line is 2 MiB or larger; the lines total more than 2 MiB. Gatorcast has the session `complete` with at least 90% of the recorded characters stored and the marker in the cast file. |

Assertions 12 to 16 run after the phase 2 assertions. Header values never reach this evidence: the
tap records none, and everything the rig logs goes through the redactor.

**SSH leg.** The rig adds an SSH resource (`gwops-it-<run id>-ssh`, seeded under `ssh_upstreams`,
swept as kind `ssh`), an sshd target on the backend network that trusts the run's SSH CA and
logs in as `gateway` (the gateway's fixed upstream principal), and an OpenSSH client run with
`docker run --network container:<client>` so it takes the Twingate path. The gateway accepts any
downstream SSH auth, so the service account needs no key. If the SSH infrastructure cannot be built
or started, assertion 16 is a finding (exit 3), not a failure of the run.

## Hold the rig for manual probes

`--hold` keeps the whole rig up after the assertions so you can probe it by hand. `make` takes the
same switch as `HOLD=1`; `HOLD_MAX=<seconds>` sets the limit:

```powershell
$env:HOLD = "1"; make integration-webapp
.venv\Scripts\python.exe -m tests.integration.webapp.run --hold --hold-max 3600
```

```sh
HOLD=1 make integration-webapp
.venv/bin/python -m tests.integration.webapp.run --hold --hold-max 3600
```

`--hold-max` is the longest hold in seconds. The default is 7200 s and the cap is 14400 s.
The hold is skipped when an infrastructure error occurred before it.

**Release.** The hold ends when any of these happens; the rig then tears down as for a normal run:

- You delete the marker file `<run dir>\HOLD`: `Remove-Item <run dir>\HOLD`.
- You press Ctrl+C. This ends the hold only; it is not treated as an interrupted run.
- `--hold-max` seconds pass.

`<run dir>` is `tests\integration\webapp\.run\<run id>`. The rig prints its path, the admin API
port and ready-to-run probe commands when the hold starts, and writes a heartbeat to `run.log`
every 300 s.

**What stays live while held.**

- The tenant objects the run created: the Gateway, the X.509 and SSH CAs, the web-app resources and
  the service account, all under the tenant's default security policy.
- The connector, with its connector tokens in `<run dir>\connector.env`.
- The headless Client, with the service-account key in `<run dir>\client.env`.
- The gwops admin API on `127.0.0.1:<admin port>` of the host. The admin token is in
  `<run dir>\admin-token` (mode 0600; see [File modes](#file-modes)).

Everything is removed at release. If the run is killed during the hold, use
[Recovery after an interrupted run](#recovery-after-an-interrupted-run).

**Probe the apps.** The containers are named `gwops-it-<run id>-<service>`; the banner prints the
exact commands. curl runs in the Client's network namespace, so requests take the Twingate path:

```powershell
docker exec gwops-it-<run id>-curl curl -sS --max-time 25 -i http://<plain host>/
docker exec gwops-it-<run id>-curl curl -sS --max-time 25 -i --cacert /trust/gwops-ca.pem https://<tls host>/
docker logs gwops-it-<run id>-verifier-b
```

**Call the admin API.**

```powershell
$token = (Get-Content <run dir>\admin-token -Raw).Trim()
Invoke-RestMethod -Headers @{ Authorization = "Bearer $token" } http://127.0.0.1:<admin port>/status
```

**Credentials in manual probes.** The gateway's web-app audit line records request headers
(including `Authorization` and `Cookie`) and query strings verbatim, and `docker logs` shows it
as written. `run.log` captures a manual probe only after redaction: it redacts audit-line header
values outside an allowlist, and query strings. A probe with real credentials is therefore
visible in the gateway container's own log for the life of the hold, and in `run.log` only in
redacted form.

## Exit codes

These are the exit codes of `python -m tests.integration.webapp.run`. `make` reports any non-zero
exit as its own failure.

| Code | Meaning |
|---|---|
| 0 | Every assertion passed, none was skipped, and there was no infrastructure error. |
| 1 | An assertion failed or was skipped (not reached), or an infrastructure error occurred (setup, gwops stop, sweep, compose down). |
| 2 | Refused before running: an `IT_*` variable is unset, the pair is not the approved one, the gateway-address guard tripped, docker or the local image is missing, the Docker engine is not local, or a tenant API call failed during start. |
| 3 | Findings only: no failure, but an assertion could not be confirmed (assertion 8 when the rewrite is not applied within its bound). |
| 130 | Interrupted (Ctrl+C or SIGTERM) before setup began, while the rig was still checking the Docker engine and the tenant (`Interrupted before the run was set up.`). An interrupt after that point runs the full teardown and exits 1 with the infrastructure error `interrupted by a signal; cleaned up`. Ctrl+C during a hold only ends the hold. |

## Run directory

Each run writes `tests/integration/webapp/.run/<run id>/` (gitignored, created mode 0700):

| Path | Contents |
|---|---|
| `state.json` | Run id, network, remote-network id, gateway address, the pre-run inventory and every id the run created or deleted. No secrets. |
| `run.log` | Redacted event log, container log tails and the assertion summary. |
| `gwops.env` | **Secret.** The tenant API key and the generated admin token, as the gwops container's env file. |
| `admin-token` | **Secret.** The generated admin API token alone (mode 0600), for manual admin API calls during a hold. |
| `HOLD` | Present only during a hold. Deleting it releases the hold. |
| `connector.env` | **Secret.** Connector tokens. |
| `gatorcast.env` | **Secret** (`--gatorcast`). The Gatorcast ingest token and UI password. |
| `tap/ingest.jsonl` | (`--gatorcast`) One metadata record per line gwops shipped. No content. Kept after the run. |
| `ssh-ca/` | (`--gatorcast-ssh`) The run's SSH CA public key, mounted into the sshd target. |
| `client.env` | **Secret.** The service-account key for the headless Client. |
| `pki/` | Throwaway leaf certificates and **private keys** for the echo upstreams and verifiers, readable by uid 10001. |
| `seed/seed.yaml` | The run's gwops seed. Holds no secret. |
| `webapp-cas/upstream-ca.pem` | The throwaway upstream CA gwops trusts in phase 2. |
| `trust/gwops-ca.pem` | The gwops X.509 CA exported from the container, for curl `--cacert`. |

On a normal run the env files (including `gatorcast.env`) are emptied and deleted after the stack is removed, and the sweep
deletes the service account. The run directory itself stays; delete it when
you no longer need `run.log`.

### File modes

The rig creates the run directory with mode 0700 and the secret files (`gwops.env`,
`connector.env`, `client.env`, `admin-token`) with mode 0600. Windows does not enforce POSIX
modes, so on Windows these modes have no effect: the files carry the access rights inherited from
`tests\integration\webapp\.run`. Keep the repository on a profile only you can read.

## Recovery after an interrupted run

Press Ctrl+C once and let teardown finish. Once teardown starts, further Ctrl+C presses are
ignored (`TeardownShield`) and counted in `run.log` (`ignored_signals`), so an impatient second
press is harmless. Only a hard kill (`Stop-Process -Force`, closing the terminal window, power
loss) skips teardown and can leave objects on the tenant, containers on the host and secret files
in the run directory. In that case re-run the sweep from the run's state file. Use the run id
printed at the start of the run, or the directory name under `.run/`. Set the `IT_*` variables as
for a run.

Windows (PowerShell):

```powershell
.venv\Scripts\python.exe -m tests.integration.webapp.rig.tenant sweep --state tests\integration\webapp\.run\<run id>\state.json
```

Linux and macOS:

```sh
.venv/bin/python -m tests.integration.webapp.rig.tenant sweep --state tests/integration/webapp/.run/<run id>/state.json
```

The sweep:

1. Refuses unless the Docker engine is local.
2. Stops gwops (`compose stop`, then `docker rm -f`) and confirms it is gone. A running gwops would
   recreate what the sweep deletes.
3. Discovers the run's objects by exact name or prefix and records them.
4. Verifies each object by id (name or address, and remote network) before deleting it, then
   deletes it.
5. Re-checks the tenant for new run objects.
6. Runs `compose down -v --remove-orphans`, then empties and deletes `gwops.env`,
   `connector.env` and `client.env`.

It deletes only objects the run recorded and verified, and is safe to repeat. Exit codes:

| Code | Meaning |
|---|---|
| 0 | Recorded objects are deleted and the inventory matches the pre-run state. |
| 1 | A problem; each `ERROR` line names it. If gwops cannot be confirmed stopped, the sweep deletes only the service account, exits 1 and prints the recovery command. Fix the cause and run the sweep again. |
| 2 | Refused, for example because the Docker engine is not local or the state file was written for a different network. |

Only if Docker itself is broken and the sweep cannot stop gwops, remove the stack by hand, gwops
first, then run the sweep:

```sh
docker rm -f gwops-it-<run id>-gwops
docker ps -aq --filter "name=gwops-it-<run id>-" | xargs -r docker rm -f
```

Do not delete tenant objects by hand in the console.

## Assertions

Phase 1 runs with no upstream CA bundle listed and the insecure host not allowlisted. The rig then
rewrites the seed (bundle listed, insecure host allowlisted), signals gwops (PID 1) to reload it,
waits for a settled reconcile, and runs phase 2. It signals gwops only, never the gateway binary.

**Readiness gate.** A new resource can take about five minutes to route; until then curl exits 35 or
56 even though the Client authorised the attempt. Before the first assertion the rig polls each
asserted host (plain, TLS, alias, `verify_ca`, wrong-host `verify_full`, both verifiers, and the SSH
host with `--gatorcast-ssh`, which is probed by reading the SSH banner) for up to 420 s until it
answers with any HTTP status or curl exit 60. Each host's time to ready is in the summary metrics
(`ready_<host>_s`). A host that never routes is recorded as `not ready` and its assertion fails on
its own terms. The SSH session retries up to 4 times, 5 s apart, on a reset before the session
starts (`kex_exchange_identification`); the count is metric `ssh_attempts`.

Every request goes through the Twingate Client path: curl runs in the Client container's network
namespace. A `401` is retried once only when the gateway log shows a `token used before issued`
rejection since the previous request; the retry is listed under `clock-skew retries` in the
summary. Any other `401` fails the assertion.

| # | Phase | What it checks |
|---|---|---|
| 1 | 1 | Upstream `none`, downstream `none`: 200 from the plain echo. |
| 7 | 1 | The gateway-wide `X-Twingate-User` header (`{{username}}`) overwrites a client-sent `X-Twingate-User` and `X_Twingate_User`. The underscore spelling is added by gwops, and gwops provides it only for gateway-wide trusted headers. No `X-Forwarded-For` or `X-Forwarded-Host` reaches the upstream, and an unknown header passes through. |
| 2a | 1 | `verify_full` with the upstream CA bundle not listed: 502. |
| 6a | 1 | Downstream `tls13` without the gwops CA: curl exit 60 and no HTTP status. |
| 10a | 1 | With `upstream_tls_probe: true`, the probe reports `untrusted_issuer` for the private-CA upstream. |
| 5a | 1 | `insecure` for a host that is not in `plaintext_upstreams`: the admin API answers 422 citing `plaintext_upstreams`. |
| 2b | 2 | `verify_full` with the bundle listed: 200, upstream TLS 1.3. |
| 3 | 2 | The alias over TLS: 200. The upstream certificate is verified against the resource address, not the alias, so the upstream leaf carries the address SAN only; the gwops leaf covers the alias. |
| 4a | 2 | `verify_ca` against a leaf for another host name: 200 (hostname not checked). |
| 4b | 2 | `verify_full` against the same leaf: 502. |
| 5b | 2 | `insecure` once the host is allowlisted: the app is created through the admin API, recorded and granted to the service account. The Client does not pick up a resource created mid-run, so the rig then restarts the Client and curl containers (curl shares the Client's network namespace) and checks that the namespace is shared again. The app returns 200 after the restart. |
| 6b | 2 | Downstream `tls13` with the gwops CA: 200 and `X-Forwarded-Proto: https`. |
| 10b | 2 | The probe reports `ok` for the bundled upstream and `hostname` for the wrong-host leaf, `readiness_status` is `ok`, and every rig app is `ready` except the wrong-host `verify_full` app (`action_required`). |
| 9a | 2 | The verifier behind its own app returns 200, and the claims have `typ` `GAT`, `ver` `1`, `resource.type` `WEB_APP` and `resource.id` equal to the app's `tg_resource_id`. |
| 9b | 2 | A second verifier expects the first app's resource id. A token issued for the second app is sent to it, and the verifier answers 401 and logs `resource_id_mismatch`. |
| 8 | 2 | A static header added to one app through the admin API reaches the upstream. The gateway never mints tokens, so a rewrite applies only on a new token and a new connection. The rig polls on fresh connections until the header arrives on a token with a new `jti`, up to the token's expiry (capped at 3900 s, or `--apply-timeout`). If it does not arrive in time the result is a finding (exit 3), because the Client may keep the old token until it expires. |
| 11 | end | After the sweep, the tenant inventory (gateways, resources, CAs, connectors and service accounts) equals the pre-run inventory. |

The summary also records metrics such as the time the rewrite took to apply. Human-user claims and
WebSocket behaviour at token expiry are not covered: the rig's only identity is a service account.
