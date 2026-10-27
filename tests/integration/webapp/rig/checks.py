"""The rig's assertions, driven through curl in the client's network namespace."""

import asyncio
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from . import logfilter, seedgen
from .admin import AdminClient, AdminError, response_text
from .curlparse import CurlResult
from .dockerops import Docker, DockerError
from .redact import RunLog
from .results import CheckFailed, CheckFinding, ResultBook
from .tenant import RigTenant

TRANSIENT_STATUSES = frozenset({502, 503, 504})
TRANSIENT_CURL_EXITS = frozenset({6, 7, 28, 35, 52, 55, 56})
SPOOF = "spoofed-by-client"
THROTTLE_PAUSE_SECONDS = 35.0
PUT_ATTEMPTS = 3
DEFAULT_APPLY_CAP_SECONDS = 3900.0
SKEW_POLL_SECONDS = 3.0
SKEW_POLL_INTERVAL = 0.25
READY_TIMEOUT_SECONDS = 420.0
READY_POLL_SECONDS = 5.0
READY_CURL_EXIT = 60

EXPECTED_ASSERTIONS: list[tuple[str, str]] = [
    ("1", "upstream none / downstream none returns 200"),
    ("2a", "verify_full without a bundle returns 502"),
    ("2b", "verify_full with the bundle returns 200 over TLS 1.3"),
    ("3", "alias over TLS returns 200 (upstream SAN is the address only)"),
    ("4a", "verify_ca with a wrong-host leaf returns 200"),
    ("4b", "verify_full with the same wrong-host leaf returns 502"),
    ("5a", "insecure is refused (422) while the host is not allowlisted"),
    ("5b", "insecure returns 200 once the host is allowlisted"),
    ("6a", "downstream tls13 without the gwops CA fails TLS verification (curl 60)"),
    ("6b", "downstream tls13 with the gwops CA returns 200 and X-Forwarded-Proto https"),
    ("7", "identity headers overwrite client spoofs; no X-Forwarded-For/Host; unknown passes"),
    ("8", "a rewrite change through the admin API reaches the upstream"),
    ("9a", "verifier accepts its own app's GAT and its claims match"),
    ("9b", "verifier rejects another app's GAT on resource.id (401)"),
    ("10a", "upstream_tls_probe reports untrusted_issuer without the bundle"),
    ("10b", "upstream_tls_probe reports ok with the bundle; readiness as expected"),
    ("11", "post-sweep tenant inventory equals the pre-run inventory"),
]


@dataclass(frozen=True)
class RequestRecord:
    """The last curl the rig sent: enough to repeat it, and when (monotonic) it was sent."""

    url: str
    cacert: bool
    headers: tuple[str, ...]
    max_time: int
    at: float


class RigHttp:
    """Fresh curl requests with the clock-skew policy: a 401 is never retried unless proven skew."""

    def __init__(self, docker: Docker, log: RunLog, book: ResultBook) -> None:
        """Bind the docker wrapper, log and result book."""
        self._docker = docker
        self._log = log
        self._book = book
        self.last: RequestRecord | None = None

    async def get(
        self,
        url: str,
        *,
        cacert: bool = False,
        headers: Sequence[str] = (),
        max_time: int = 25,
    ) -> CurlResult:
        """One request; retried once if the gateway logged a skew rejection during it."""
        started = datetime.now(UTC)
        result = await self._docker.curl(url, cacert=cacert, headers=headers, max_time=max_time)
        self._log.event("curl", url=url, result=result.line())
        evidence = await self._skew_evidence_for(result, started)
        if evidence:
            self._book.skew_retries.append(url)
            matched = logfilter.scrub_gwops_line(evidence[0])
            self._log.event("skew-retry", url=url, first=result.line(), evidence=matched)
            result = await self._docker.curl(url, cacert=cacert, headers=headers, max_time=max_time)
            self._log.event("curl", url=url, result=result.line())
        self.last = RequestRecord(url, cacert, tuple(headers), max_time, time.monotonic())
        return result

    async def _skew_evidence_for(self, result: CurlResult, started: datetime) -> list[str]:
        """Skew evidence for a request; a connection-level failure waits briefly for a late line."""
        evidence = await self._skew_evidence(started)
        if evidence or result.status is not None or result.exit_code not in TRANSIENT_CURL_EXITS:
            return evidence
        deadline = time.monotonic() + SKEW_POLL_SECONDS
        while not evidence and time.monotonic() < deadline:
            await asyncio.sleep(SKEW_POLL_INTERVAL)
            evidence = await self._skew_evidence(started)
        return evidence

    async def _skew_evidence(self, started: datetime) -> list[str]:
        try:
            return await self._docker.skew_evidence(started)
        except DockerError as exc:
            self._log.event("skew-check-failed", error=str(exc)[:200])
            return []

    async def wait_for(
        self,
        url: str,
        want: int,
        *,
        cacert: bool = False,
        headers: Sequence[str] = (),
        timeout: float = 180.0,
        interval: float = 5.0,
        max_time: int = 20,
    ) -> CurlResult:
        """Poll until `want`; only gateway 5xx and connection-level curl errors are retried."""
        deadline = time.monotonic() + timeout
        while True:
            result = await self.get(url, cacert=cacert, headers=headers, max_time=max_time)
            if result.status == want:
                return result
            transient = result.status in TRANSIENT_STATUSES or (
                result.status is None and result.exit_code in TRANSIENT_CURL_EXITS
            )
            if not transient or time.monotonic() >= deadline:
                note = " (401 is never retried)" if result.status == 401 else ""
                raise CheckFailed(f"{url}: expected {want}, got {result.line()}{note}")
            await asyncio.sleep(interval)


@dataclass
class RigContext:
    """Everything the assertions use."""

    names: seedgen.RigNames
    docker: Docker
    admin: AdminClient
    tenant: RigTenant
    http: RigHttp
    book: ResultBook
    log: RunLog
    apply_bundle_phase: Callable[[], Awaitable[None]]
    apply_timeout: float | None = None


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailed(message)


def _echo_json(result: CurlResult) -> dict[str, Any]:
    document = result.json()
    if document is None:
        raise CheckFailed(f"response was not the echo/verifier JSON ({result.line()})")
    return document


class Checks:
    """The assertion bodies; each returns a one-line detail or raises CheckFailed/CheckFinding."""

    def __init__(self, ctx: RigContext) -> None:
        """Bind the run context."""
        self.c = ctx
        self.n = ctx.names

    def _name(self, suffix: str) -> str:
        return self.n.app_name(suffix)

    async def _tg_id(self, suffix: str) -> str:
        entry = await self.c.admin.get_webapp(self._name(suffix))
        value = entry.get("tg_resource_id")
        _expect(isinstance(value, str) and bool(value), f"{suffix} has no tg_resource_id")
        return str(value)

    async def _put(self, suffix: str, body: dict[str, Any]) -> Any:
        """PUT a web app, waiting out a throttled (rate-limited, rolled back) attempt."""
        response = None
        for attempt in range(1, PUT_ATTEMPTS + 1):
            response = await self.c.admin.put_webapp(self._name(suffix), body)
            self.c.log.event("put", app=suffix, status=response.status_code, attempt=attempt)
            if response.status_code != 422 or "rate-limited" not in response.text:
                return response
            await asyncio.sleep(THROTTLE_PAUSE_SECONDS)
        return response

    # --- readiness gate ------------------------------------------------------------------

    def ready_targets(self) -> list[tuple[str, str, bool]]:
        """(label, url, needs the gwops CA) for every host the assertions rely on."""
        n = self.n
        return [
            ("plain", f"http://{n.plain_host}/", False),
            ("tls", f"https://{n.tls_host}/", True),
            ("alias", f"https://{n.alias_host}/", True),
            ("vca", f"http://{n.vca_host}/", False),
            ("wrongfull", f"http://{n.wrongfull_host}/", False),
            ("verifier-a", f"http://{n.verifier_a_host}/", False),
            ("verifier-b", f"http://{n.verifier_b_host}/", False),
        ]

    async def wait_host_ready(
        self, label: str, url: str, cacert: bool, timeout: float = READY_TIMEOUT_SECONDS
    ) -> float | None:
        """Poll until `url` gives an HTTP status or curl exit 60; seconds taken, None on timeout."""
        started = time.monotonic()
        while True:
            result = await self.c.http.get(url, cacert=cacert, max_time=20)
            elapsed = time.monotonic() - started
            if result.status is not None or result.exit_code == READY_CURL_EXIT:
                self.c.book.metrics[f"ready_{label}_s"] = f"{elapsed:.0f}"
                self.c.log.event("host-ready", host=label, seconds=f"{elapsed:.0f}")
                return elapsed
            if elapsed >= timeout:
                self.c.book.metrics[f"ready_{label}_s"] = f"not ready in {timeout:.0f}s"
                self.c.log.event("host-not-ready", host=label, last=result.line())
                return None
            await asyncio.sleep(READY_POLL_SECONDS)

    async def wait_hosts_ready(self) -> None:
        """Gate: wait for every asserted host to route before any single-shot assertion."""
        waits = [self.wait_host_ready(*target) for target in self.ready_targets()]
        for outcome in await asyncio.gather(*waits, return_exceptions=True):
            if isinstance(outcome, Exception):
                self.c.log.event("host-gate-error", error=repr(outcome)[:200])

    # --- phase 1 (no upstream CA bundle) ---------------------------------------------

    async def plain_http(self) -> str:
        """Assertion 1: none/none returns 200."""
        result = await self.c.http.wait_for(f"http://{self.n.plain_host}/", 200, timeout=420)
        _expect(_echo_json(result).get("method") == "GET", "echo did not report GET")
        return "200 from the plain echo"

    async def identity_headers(self) -> str:
        """Assertion 7: gateway-wide identity header beats spoofs in both spellings."""
        headers = [
            f"X-Twingate-User: {SPOOF}",
            f"X_Twingate_User: {SPOOF}",
            "X-Rig-Passthrough: keep-me",
        ]
        result = await self.c.http.get(f"http://{self.n.plain_host}/", headers=headers)
        _expect(result.status == 200, f"expected 200, got {result.line()}")
        seen = result.seen_headers()
        hyphen, underscore = seen.get("x-twingate-user", []), seen.get("x_twingate_user", [])
        _expect(bool(hyphen), "X-Twingate-User did not reach the upstream")
        _expect(bool(underscore), "X_Twingate_User (gwops-added spelling) did not reach upstream")
        _expect(
            SPOOF not in hyphen + underscore, "a client-spoofed identity value reached upstream"
        )
        _expect(set(hyphen) == set(underscore), "the two spellings carry different values")
        for name in ("x-forwarded-for", "x-forwarded-host"):
            _expect(name not in seen, f"upstream saw {name}")
        _expect(seen.get("x-rig-passthrough") == ["keep-me"], "an unknown header was not passed")
        return "both spellings overwritten; no X-Forwarded-For/Host; unknown header passed"

    async def verify_full_no_bundle(self) -> str:
        """Assertion 2 (no bundle): 502."""
        result = await self.c.http.get(f"https://{self.n.tls_host}/", cacert=True)
        _expect(result.status == 502, f"expected 502, got {result.line()}")
        return "502 without a listed bundle"

    async def tls13_untrusted(self) -> str:
        """Assertion 6 (no CA): curl exit 60 and no HTTP status."""
        result = await self.c.http.get(f"https://{self.n.tls_host}/", cacert=False)
        _expect(result.exit_code == 60, f"expected curl exit 60, got {result.line()}")
        _expect(
            result.status is None, f"got an HTTP status {result.status} despite the TLS failure"
        )
        return "curl exit 60 (certificate not trusted), no HTTP status"

    async def insecure_refused(self) -> str:
        """Assertion 5 (not allowlisted): the admin API answers 422."""
        response = await self._put(seedgen.INSECURE_SUFFIX, seedgen.insecure_app_body(self.n))
        _expect(response.status_code == 422, f"expected 422, got {response.status_code}")
        _expect(
            "plaintext_upstreams" in response.text,
            f"422 did not cite plaintext_upstreams: {response_text(response, 200)}",
        )
        return "422 citing web_app_proxy.plaintext_upstreams"

    async def _wait_probe(
        self, suffix: str, outcome: str, timeout: float = 180.0
    ) -> dict[str, Any]:
        name = self._name(suffix)
        try:
            await self.c.admin.reconcile()
        except AdminError as exc:
            self.c.log.event("reconcile-failed", error=str(exc))
        deadline = time.monotonic() + timeout
        last = "no probe result"
        while True:
            status = await self.c.admin.status()
            entries = status.get("web_apps", {}).get("readiness") or []
            entry = next((e for e in entries if e.get("name") == name), None)
            probe = (entry or {}).get("probe")
            if probe:
                last = f"outcome={probe.get('outcome')}"
                if probe.get("outcome") == outcome:
                    return entry or {}
            if time.monotonic() >= deadline:
                raise CheckFailed(f"{suffix}: expected probe {outcome}, last {last}")
            await asyncio.sleep(10)

    async def probe_untrusted(self) -> str:
        """Assertion 10 (no bundle): untrusted_issuer."""
        entry = await self._wait_probe("vfull", "untrusted_issuer")
        return f"probe untrusted_issuer; state {entry.get('state')}"

    # --- phase 2 (bundle listed, insecure host allowlisted) ---------------------------

    async def verify_full_bundle(self) -> str:
        """Assertion 2 (bundle): 200 over TLS 1.3."""
        result = await self.c.http.wait_for(f"https://{self.n.tls_host}/", 200, cacert=True)
        document = _echo_json(result)
        _expect(
            document.get("tls_version") == "TLSv1.3", f"upstream TLS {document.get('tls_version')}"
        )
        return "200, upstream TLSv1.3"

    async def alias_host(self) -> str:
        """Assertion 3: alias over TLS is 200."""
        result = await self.c.http.wait_for(f"https://{self.n.alias_host}/", 200, cacert=True)
        _expect(_echo_json(result).get("scheme") == "https", "upstream hop was not TLS")
        return "200 via the alias; gwops leaf covers it, echo leaf has the address only"

    async def verify_ca_wrong_host(self) -> str:
        """Assertion 4 (verify_ca): 200."""
        await self.c.http.wait_for(f"http://{self.n.vca_host}/", 200)
        return "200: hostname not checked"

    async def verify_full_wrong_host(self) -> str:
        """Assertion 4 (verify_full): 502."""
        result = await self.c.http.get(f"http://{self.n.wrongfull_host}/")
        _expect(result.status == 502, f"expected 502, got {result.line()}")
        return "502: hostname mismatch rejected"

    async def insecure_allowlisted(self) -> str:
        """Assertion 5 (allowlisted): create through the admin API, record, grant, 200."""
        name = self._name(seedgen.INSECURE_SUFFIX)
        response = await self._put(seedgen.INSECURE_SUFFIX, seedgen.insecure_app_body(self.n))
        _expect(response.status_code == 200, f"expected 200, got {response.status_code}")
        found = await self.c.tenant.discover_new("web_app", name=name)
        _expect(len(found) == 1, f"expected one new tenant resource named {name}, got {len(found)}")
        tenant_id = found[0][0]
        _expect(
            tenant_id == await self._tg_id(seedgen.INSECURE_SUFFIX),
            "admin API and tenant ids differ",
        )
        self.c.tenant.record("web_app", tenant_id, name)
        await self.c.tenant.grant_access([tenant_id])
        await self._restart_client_for_new_resource()
        await self.c.http.wait_for(f"http://{self.n.insecure_host}/", 200, timeout=300)
        return "422 before the allowlist, 200 after (client restarted to learn the new resource)"

    async def _restart_client_for_new_resource(self) -> None:
        """Restart the client then curl (it joins the client's netns); re-verify with plain."""
        docker = self.c.docker
        self.c.log.event(
            "client-restart",
            reason="resource created mid-run",
            containers=f"{docker.container('client')}, {docker.container('curl')}",
        )
        await docker.restart(docker.container("client"))
        await docker.restart(docker.container("curl"))
        if not await docker.curl_shares_client_netns():
            raise CheckFailed("curl no longer shares the client's network namespace after restart")
        await self.c.http.wait_for(f"http://{self.n.plain_host}/", 200, timeout=300)
        self.c.log.event("client-restart", result="client up; curl shares its namespace")

    async def tls13_trusted(self) -> str:
        """Assertion 6 (gwops CA): 200 and X-Forwarded-Proto https."""
        result = await self.c.http.wait_for(f"https://{self.n.tls_host}/", 200, cacert=True)
        proto = result.seen_headers().get("x-forwarded-proto")
        _expect(proto == ["https"], f"X-Forwarded-Proto was {proto}")
        return "200 with --cacert; X-Forwarded-Proto https"

    async def probe_ok(self) -> str:
        """Assertion 10 (bundle): probe ok and the rig's apps ready."""
        await self._wait_probe("vfull", "ok")
        await self._wait_probe("vfullwrong", "hostname")
        status = await self.c.admin.status()
        web = status.get("web_apps", {})
        _expect(
            web.get("readiness_status") == "ok", f"readiness_status {web.get('readiness_status')}"
        )
        by_name = {e.get("name"): e for e in web.get("readiness") or []}
        problems: list[str] = []
        for suffix in (*seedgen.APP_SUFFIXES, seedgen.INSECURE_SUFFIX):
            entry = by_name.get(self._name(suffix))
            want = "action_required" if suffix == "vfullwrong" else "ready"
            if entry is None or entry.get("state") != want:
                state = None if entry is None else (entry.get("state"), entry.get("reasons"))
                problems.append(f"{suffix}: want {want}, got {state}")
        _expect(not problems, "; ".join(problems))
        return "vfull probe ok; vfullwrong probe hostname; the other apps ready"

    async def verifier_accepts_own(self) -> str:
        """Assertion 9: the verifier accepts its own app's GAT."""
        result = await self.c.http.wait_for(f"http://{self.n.verifier_a_host}/", 200)
        claims = _echo_json(result).get("claims")
        _expect(isinstance(claims, dict), "verifier returned no claims")
        assert isinstance(claims, dict)
        raw_resource = claims.get("resource")
        resource: dict[str, Any] = raw_resource if isinstance(raw_resource, dict) else {}
        tenant_id = await self._tg_id("verifier-a")
        _expect(claims.get("typ") == "GAT", f"typ {claims.get('typ')}")
        _expect(claims.get("ver") == "1", f"ver {claims.get('ver')}")
        _expect(resource.get("type") == "WEB_APP", f"resource.type {resource.get('type')}")
        _expect(resource.get("id") == tenant_id, "resource.id is not the app's tg_resource_id")
        return "200; typ GAT, ver 1, resource WEB_APP with the app's own id"

    async def verifier_rejects_other(self) -> str:
        """Assertion 9: a GAT minted for verifier-b is rejected by a verifier expecting a's id."""
        result = await self.c.http.wait_for(f"http://{self.n.verifier_b_host}/", 401)
        verifier_log = await self.c.docker.logs(self.c.docker.container("verifier-b"))
        _expect(
            "resource_id_mismatch" in verifier_log,
            "401 was not the verifier's resource.id rejection",
        )
        _expect("unauthorized" in result.body, "401 body was not the verifier's")
        return "401 from the verifier (resource_id_mismatch)"

    async def rewrite_applies(self) -> str:
        """Assertion 8: a rewrite change is applied after a new token and a new connection."""
        url = f"http://{self.n.verifier_a_host}/"
        base = await self.c.http.wait_for(url, 200)
        claims = _echo_json(base).get("claims") or {}
        base_jti = claims.get("jti")
        bound = self._apply_bound(claims.get("rnw") or claims.get("exp"))
        response = await self._put("verifier-a", seedgen.rewrite_body(self.n))
        _expect(response.status_code == 200, f"PUT returned {response.status_code}")
        started = time.monotonic()
        seen_new_jti = False
        seen_ok = False
        result = base
        while time.monotonic() - started < bound:
            await asyncio.sleep(5)
            result = await self.c.http.get(url)
            if result.status == 401:
                raise CheckFailed("401 while polling; not retried (no skew in the gateway log)")
            if result.status != 200:
                continue
            seen_ok = True
            document = _echo_json(result)
            claims_now = document.get("claims")
            jti = claims_now.get("jti") if isinstance(claims_now, dict) else None
            seen_new_jti = seen_new_jti or (jti is not None and jti != base_jti)
            marker = result.seen_headers().get(seedgen.REWRITE_HEADER.lower())
            if marker == [seedgen.REWRITE_VALUE]:
                elapsed = time.monotonic() - started
                self.c.book.metrics["rewrite_time_to_apply_s"] = f"{elapsed:.0f}"
                _expect(jti != base_jti, "the rewrite arrived on the old token (same jti)")
                return f"applied after {elapsed:.0f}s on a new token"
        self.c.book.metrics["rewrite_time_to_apply_s"] = f"not applied within {bound:.0f}s"
        if not seen_ok:
            raise CheckFailed(f"no 200 from {url} in {bound:.0f}s; last result {result.line()}")
        raise CheckFinding(
            f"rewrite not applied within {bound:.0f}s (new jti seen: {seen_new_jti}); the "
            "client may lack allow_gat_invalidation, so the old token stays in use until it expires"
        )

    def _apply_bound(self, expiry: object) -> float:
        if self.c.apply_timeout is not None:
            return self.c.apply_timeout
        if isinstance(expiry, int | float):
            return max(60.0, min(float(expiry) - time.time(), DEFAULT_APPLY_CAP_SECONDS))
        return DEFAULT_APPLY_CAP_SECONDS
