"""Opt-in active TLS probe of web-app upstreams: handshake only, bounded, direct.

Off unless ``web_app_proxy.upstream_tls_probe`` is set in the seed (read on every schedule).
Each batch dials, at most once per distinct upstream and four at a time, the upstream of every
web app whose ``upstream_tls`` verifies: declared entries, plus unmanaged apps on this gateway
whose address passes ``twingate.address_allowlist``. Any other address is reported
unverifiable and never resolved or dialled. A name is resolved first on a small dedicated
thread pool; a loopback, link-local, unspecified (including 0.0.0.0/8), multicast or cloud
metadata result, also inside an IPv6 form embedding an IPv4 address, is refused and never
dialled. The probe dials the checked IP with the name as the TLS server name, does a TLS
1.3-minimum handshake with stdlib ``ssl`` and closes; it sends no application data, never
uses ``HTTP(S)_PROXY`` and logs no certificate content.
"""

import asyncio
import contextlib
import ipaddress
import socket
import ssl
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal

import structlog

from gwops.access.allowlist import address_allowed
from gwops.configmodel.schema import EffectiveState
from gwops.renderer.render import RuntimePaths
from gwops.renderer.sans import strip_port

if TYPE_CHECKING:
    from gwops.reconciler.core import RemoteWebApp

logger = structlog.get_logger(__name__)

ProbeOutcome = Literal[
    "ok", "untrusted_issuer", "hostname", "tls12_only", "unreachable", "ca_unusable"
]
ProbeMode = Literal["verify_full", "verify_ca"]
_IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_THIS_NETWORK = ipaddress.IPv4Network("0.0.0.0/8")
_METADATA_ADDRESSES = frozenset(
    ipaddress.ip_address(a) for a in ("fd00:ec2::254", "100.100.100.200")
)
# IPv4-compatible ::/96, IPv4-translated ::ffff:0:0:0/96 and NAT64 64:ff9b::/96.
_IPV4_EMBEDDING_NETWORKS = tuple(
    ipaddress.IPv6Network(n) for n in ("::/96", "::ffff:0:0:0/96", "64:ff9b::/96")
)
_MAX_CONCURRENT = 4
_RESOLVER_WORKERS = 4
_CLOSE_WAIT_SECONDS = 1.0
_HOSTNAME_VERIFY_CODES = frozenset({62, 64})  # X509_V_ERR_HOSTNAME_MISMATCH, _IP_ADDRESS_MISMATCH
_TLS12_ONLY_REASONS = frozenset(
    {"TLSV1_ALERT_PROTOCOL_VERSION", "UNSUPPORTED_PROTOCOL", "NO_PROTOCOLS_AVAILABLE"}
)


@dataclass(frozen=True)
class ProbeResult:
    """One probe's outcome; ``target`` is ``host:port``."""

    outcome: ProbeOutcome
    checked_at: datetime
    target: str
    error_type: str | None = None
    """Exception class name behind a non-ok outcome."""
    verify_code: int | None = None
    """OpenSSL verify code of a certificate-verification failure."""


@dataclass(frozen=True)
class ProbeTarget:
    """One upstream to handshake with; ``ca_files`` extend the system roots."""

    name: str
    host: str
    port: int
    mode: ProbeMode
    ca_files: tuple[Path, ...]
    key: str | None = None
    """The result key: the tenant resource id, or the name before the app is on the tenant."""
    managed: bool = True

    @property
    def result_key(self) -> str:
        """The key this target's result is stored under."""
        return self.key or self.name


@dataclass(frozen=True)
class ProbeSnapshot:
    """A read-only copy of the runner's state; keys are :attr:`ProbeTarget.result_key`."""

    results: Mapping[str, ProbeResult]
    failed: Mapping[str, str]
    """Key -> exception class name of a probe that raised."""
    unverifiable: frozenset[str]
    """Keys the selection could not verify (address outside the allowlist, wildcard)."""
    refused: frozenset[str]
    """Keys whose name resolved to an address the probe refuses to dial."""
    last_batch_error: str | None
    """Exception class name of the last batch if it failed."""


class _AddressRefused(Exception):
    """A resolved address the probe must not dial."""


def _probe_mode(upstream_tls: str) -> ProbeMode | None:
    match upstream_tls:
        case "verify_full" | "verify_ca":
            return upstream_tls
        case _:
            return None


def select_targets(
    state: EffectiveState,
    remote_web_apps: "list[RemoteWebApp] | None",
    gateway_id: str | None,
    paths: RuntimePaths,
) -> tuple[list[ProbeTarget], list[str]]:
    """The bounded probe set and the result keys that cannot be verified.

    Declared entries are always targets (upstream ``verify_full``/``verify_ca``), keyed by the
    tenant id of their managed app when it exists. Unmanaged apps on ``gateway_id`` are targets
    on the port the tenant reports when ``twingate.address_allowlist`` covers them, and
    unverifiable (by tenant id) when it does not, is absent, or the address is a wildcard.
    """
    ca_files = tuple(paths.upstream_ca_files.values())
    remote = list(remote_web_apps or ())
    managed_ids = {app.name: app.id for app in remote if app.managed}
    targets: list[ProbeTarget] = []
    unverifiable: list[str] = []
    for entry in state.web_apps:
        mode = _probe_mode(entry.upstream_tls)
        if mode is not None:
            key = managed_ids.get(entry.name, entry.name)
            targets.append(
                ProbeTarget(
                    entry.name,
                    strip_port(entry.address),
                    entry.upstream_port(),
                    mode,
                    ca_files,
                    key,
                )
            )
    allowlist = state.twingate.address_allowlist
    seen: set[str] = set()
    for app in remote:
        mode = _probe_mode(app.upstream_tls)
        if app.managed or app.gateway_id != gateway_id or mode is None or app.id in seen:
            continue
        seen.add(app.id)
        host = strip_port(app.address)
        if "*" in host or allowlist is None or not address_allowed(host.lower(), allowlist):
            unverifiable.append(app.id)
            continue
        targets.append(
            ProbeTarget(app.name, host, app.upstream_port, mode, ca_files, app.id, managed=False)
        )
    return targets, unverifiable


def _embedded_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv6 form carries (mapped, translated, compatible, NAT64, 6to4)."""
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address.sixtofour is not None:
        return address.sixtofour
    if any(address in network for network in _IPV4_EMBEDDING_NETWORKS):
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return None


def _address_refused(address: _IpAddress) -> bool:
    """Whether the probe must never dial `address`.

    Loopback, link-local, unspecified, multicast, 0.0.0.0/8 and the cloud metadata addresses,
    including when carried inside an IPv6 form that embeds an IPv4 address.
    """
    if isinstance(address, ipaddress.IPv6Address):
        address = _embedded_ipv4(address) or address
    if address in _METADATA_ADDRESSES:
        return True
    if isinstance(address, ipaddress.IPv4Address) and address in _THIS_NETWORK:
        return True
    return (
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
    )


def _lookup(host: str, port: int) -> list[_IpAddress]:
    """Every address `host` resolves to, in resolver order, without duplicates."""
    found: list[_IpAddress] = []
    for *_head, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        address = ipaddress.ip_address(str(sockaddr[0]).partition("%")[0])
        if address not in found:
            found.append(address)
    return found


def _build_context(
    target: ProbeTarget, warned: set[Path] | None
) -> tuple[ssl.SSLContext, tuple[Path, ...]]:
    """The TLS context and the CA files that could not be loaded (warned once per file)."""
    context = ssl.create_default_context()
    unusable: list[Path] = []
    for ca_file in target.ca_files:
        try:
            context.load_verify_locations(cafile=str(ca_file))
        except (OSError, ssl.SSLError) as exc:
            unusable.append(ca_file)
            if warned is None or ca_file not in warned:
                if warned is not None:
                    warned.add(ca_file)
                logger.warning(
                    "webapp_probe.ca_file_unusable",
                    file=ca_file.name,
                    error_type=type(exc).__name__,
                )
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = target.mode == "verify_full"
    return context, tuple(unusable)


def _classify(exc: BaseException) -> tuple[ProbeOutcome, int | None]:
    if isinstance(exc, ssl.SSLCertVerificationError):
        code = exc.verify_code
        return ("hostname" if code in _HOSTNAME_VERIFY_CODES else "untrusted_issuer"), code
    if isinstance(exc, ssl.SSLError) and exc.reason in _TLS12_ONLY_REASONS:
        return "tls12_only", None
    return "unreachable", None


async def _close(writer: asyncio.StreamWriter) -> None:
    """Close after a completed handshake; slowness here never changes the outcome."""
    writer.close()
    with contextlib.suppress(Exception):
        async with asyncio.timeout(_CLOSE_WAIT_SECONDS):
            await writer.wait_closed()


async def _handshake(
    target: ProbeTarget, timeout: float, address: str | None, warned: set[Path] | None
) -> tuple[ProbeOutcome, str | None, int | None]:
    context, unusable = await asyncio.to_thread(_build_context, target, warned)
    try:
        async with asyncio.timeout(timeout):
            _reader, writer = await asyncio.open_connection(
                address or target.host, target.port, ssl=context, server_hostname=target.host
            )
    except TimeoutError:
        return "unreachable", "TimeoutError", None
    except (OSError, ValueError) as exc:
        outcome, verify_code = _classify(exc)
        if outcome == "untrusted_issuer" and unusable:
            outcome = "ca_unusable"
        return outcome, type(exc).__name__, verify_code
    await _close(writer)
    return "ok", None, None


async def probe_one(
    target: ProbeTarget,
    *,
    timeout: float = 5.0,
    address: str | None = None,
    warned: set[Path] | None = None,
) -> ProbeResult:
    """Handshake with one target (TLS 1.3 minimum) and close; never raises for network failures.

    `address` is the already-checked IP to dial (the target's host stays the TLS server name);
    `warned` collects CA files already reported unusable.
    """
    outcome, error_type, verify_code = await _handshake(target, timeout, address, warned)
    return ProbeResult(
        outcome, datetime.now(UTC), f"{target.host}:{target.port}", error_type, verify_code
    )


class ProbeRunner:
    """Runs probe batches in the background; ``snapshot()`` is the read-only view of its state."""

    def __init__(self, paths: RuntimePaths, *, enabled: bool, timeout: float = 5.0) -> None:
        """`enabled` is the initial seed flag; every ``schedule`` re-reads it from the state."""
        self._paths = paths
        self.enabled = enabled
        self._timeout = timeout
        self.results: dict[str, ProbeResult] = {}
        self.failed: dict[str, str] = {}
        self.unverifiable: frozenset[str] = frozenset()
        self.refused: set[str] = set()
        self.last_batch_error: str | None = None
        self._managed_keys: set[str] = set()
        self._key_by_name: dict[str, str] = {}
        self._warned_ca: set[Path] = set()
        self._generation = 0
        self._executor = ThreadPoolExecutor(
            max_workers=_RESOLVER_WORKERS, thread_name_prefix="gwops-probe-dns"
        )
        self._task: asyncio.Task[None] | None = None
        self._closed = False

    def snapshot(self) -> ProbeSnapshot:
        """A read-only copy of the current results and per-key failures."""
        return ProbeSnapshot(
            results=MappingProxyType(dict(self.results)),
            failed=MappingProxyType(dict(self.failed)),
            unverifiable=frozenset(self.unverifiable),
            refused=frozenset(self.refused),
            last_batch_error=self.last_batch_error,
        )

    def schedule(
        self,
        state: EffectiveState,
        remote_web_apps: "list[RemoteWebApp] | None",
        gateway_id: str | None,
        *,
        paths: RuntimePaths | None = None,
    ) -> None:
        """Start a batch without waiting; dropped while one runs. Never raises."""
        if self._closed:
            return
        try:
            flag = state.web_app_proxy.upstream_tls_probe
            if flag != self.enabled:
                self.enabled = flag
                if not flag:
                    self._clear()
            if not self.enabled:
                return
            if self._task is not None and not self._task.done():
                return
            self._task = asyncio.get_running_loop().create_task(
                self._run_batch(
                    state, remote_web_apps, gateway_id, paths or self._paths, self._generation
                )
            )
        except Exception as exc:  # observation only: never fails the caller
            logger.warning("webapp_probe.schedule_failed", error_type=type(exc).__name__)

    async def aclose(self) -> None:
        """Cancel any running batch and stop the resolver pool; safe to call repeatedly."""
        self._closed = True
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _clear(self) -> None:
        """Drop everything the last batches learned; an in-flight batch's results are discarded."""
        self._generation += 1
        self.results.clear()
        self.failed.clear()
        self.refused.clear()
        self.unverifiable = frozenset()
        self.last_batch_error = None
        self._managed_keys = set()
        self._key_by_name = {}

    def _current(self, generation: int) -> bool:
        return self.enabled and generation == self._generation

    async def _run_batch(
        self,
        state: EffectiveState,
        remote_web_apps: "list[RemoteWebApp] | None",
        gateway_id: str | None,
        paths: RuntimePaths,
        generation: int,
    ) -> None:
        try:
            targets, unverifiable = select_targets(state, remote_web_apps, gateway_id, paths)
            if not self._current(generation):
                return
            if remote_web_apps is None:  # no listing: declared apps keep the keys they had
                targets = [
                    replace(t, key=self._key_by_name.get(t.name, t.result_key))
                    if t.managed
                    else t
                    for t in targets
                ]
            self._apply_selection(targets, unverifiable, listed=remote_web_apps is not None)
            self._warned_ca &= set(paths.upstream_ca_files.values())
            groups: dict[tuple[str, int, str, tuple[Path, ...]], list[ProbeTarget]] = {}
            for target in targets:
                groups.setdefault(
                    (target.host, target.port, target.mode, target.ca_files), []
                ).append(target)
            limit = asyncio.Semaphore(_MAX_CONCURRENT)
            async with asyncio.TaskGroup() as group:
                for members in groups.values():
                    group.create_task(self._probe(members, limit, generation))
        except Exception as exc:  # observation only: a failed batch changes nothing else
            logger.warning("webapp_probe.batch_failed", error_type=type(exc).__name__)
            if self._current(generation):
                self.results.clear()
                self.failed.clear()
                self.refused.clear()
                self.unverifiable = frozenset()
                self._managed_keys = set()
                self.last_batch_error = type(exc).__name__

    def _apply_selection(
        self, targets: list[ProbeTarget], unverifiable: list[str], *, listed: bool
    ) -> None:
        """Adopt a new selection; a batch without a tenant listing keeps unmanaged state."""
        self.last_batch_error = None
        wanted = {target.result_key for target in targets}
        managed = {target.result_key for target in targets if target.managed}
        if listed:
            stale = (
                self.results.keys() | self.failed.keys() | self.refused
            ) - wanted
            self.unverifiable = frozenset(unverifiable)
        else:
            stale = (
                (self.results.keys() | self.failed.keys() | self.refused) & self._managed_keys
            ) - wanted
        for key in stale:
            self.results.pop(key, None)
            self.failed.pop(key, None)
            self.refused.discard(key)
        self._managed_keys = managed
        if listed:
            self._key_by_name = {t.name: t.result_key for t in targets if t.managed}

    async def _dial_address(self, target: ProbeTarget) -> str:
        """The checked IP to dial for `target`.

        Raises:
            _AddressRefused: any resolved address is one the probe never dials.
            OSError, TimeoutError: the name did not resolve in time.
        """
        try:
            addresses: list[_IpAddress] = [ipaddress.ip_address(target.host)]
        except ValueError:
            loop = asyncio.get_running_loop()
            addresses = await asyncio.wait_for(
                loop.run_in_executor(self._executor, _lookup, target.host, target.port),
                self._timeout,
            )
        if not addresses:
            raise OSError("name resolved to no address")
        if any(_address_refused(address) for address in addresses):
            raise _AddressRefused
        return str(addresses[0])

    async def _probe(
        self, members: list[ProbeTarget], limit: asyncio.Semaphore, generation: int
    ) -> None:
        """Probe one upstream once and record the outcome for every target that shares it."""
        target = members[0]
        async with limit:
            try:
                address = await self._dial_address(target)
                result = await probe_one(
                    target, timeout=self._timeout, address=address, warned=self._warned_ca
                )
            except _AddressRefused:
                self._record_refused(members, generation)
                return
            except OSError as exc:
                result = ProbeResult(
                    "unreachable",
                    datetime.now(UTC),
                    f"{target.host}:{target.port}",
                    type(exc).__name__,
                )
            except Exception as exc:
                self._record_failed(members, type(exc).__name__, generation)
                return
        self._record(members, result, generation)

    def _record_refused(self, members: list[ProbeTarget], generation: int) -> None:
        if not self._current(generation):
            return
        for member in members:
            key = member.result_key
            self.results.pop(key, None)
            self.failed.pop(key, None)
            if key not in self.refused:
                logger.warning("webapp_probe.address_refused", app=member.name)
            self.refused.add(key)

    def _record_failed(self, members: list[ProbeTarget], error_type: str, generation: int) -> None:
        if not self._current(generation):
            return
        for member in members:
            key = member.result_key
            self.results.pop(key, None)
            self.refused.discard(key)
            self.failed[key] = error_type
            logger.warning("webapp_probe.failed", app=member.name, error_type=error_type)

    def _record(self, members: list[ProbeTarget], result: ProbeResult, generation: int) -> None:
        if not self._current(generation):
            return
        for member in members:
            key = member.result_key
            previous = self.results.get(key)
            self.results[key] = result
            self.failed.pop(key, None)
            self.refused.discard(key)
            if previous is None or previous.outcome != result.outcome:
                log = logger.info if result.outcome == "ok" else logger.warning
                log(
                    "webapp_probe.result",
                    app=member.name,
                    target=result.target,
                    outcome=result.outcome,
                    error_type=result.error_type,
                    verify_code=result.verify_code,
                )
