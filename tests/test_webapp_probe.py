"""Tests for gwops.webapp_probe: the opt-in active upstream TLS probe.

Interface under test:

* Seed key ``web_app_proxy.upstream_tls_probe: bool = False``.
* ``ProbeResult(outcome, checked_at, target, error_type=None, verify_code=None)`` and
  ``ProbeTarget(name, host, port, mode, ca_files, key=None)``: frozen. Outcomes: ``ok``,
  ``untrusted_issuer``, ``hostname``, ``tls12_only``, ``unreachable``, ``ca_unusable``. Modes:
  ``verify_full`` (hostname checked), ``verify_ca`` (chain only).
* ``select_targets(state, remote_web_apps, gateway_id, paths) -> (targets, unverifiable)``.
  Every target's ``ca_files`` is the full set of ``paths.upstream_ca_files`` values. An unmanaged
  remote app is dialled on the ``upstream_port`` the tenant listing reports. Result keys (and
  the unverifiable list) are tenant resource ids where the app is on the tenant, else the name.
* ``async probe_one(target, *, timeout=5.0, address=None) -> ProbeResult``: TLS 1.3 minimum
  handshake, then close; ``address`` is the checked IP to dial.
* ``ProbeRunner(paths, *, enabled, timeout=5.0)``: ``enabled`` is the initial value of the seed
  flag, which every ``schedule(state, remote_web_apps, gateway_id)`` re-reads from the state;
  ``snapshot()`` is the read-only view of ``results`` (keyed by result key); ``aclose()``
  cancels. A schedule while a batch is running is dropped (no trailing re-run).
* The runner resolves each name itself and refuses loopback, link-local, unspecified and
  multicast results. Tests that serve on loopback allow it with ``loopback_allowed``.

The tests assume the runner calls ``select_targets`` and ``probe_one`` through the module's
globals, so ``monkeypatch.setattr(webapp_probe, ...)`` reaches them.
"""

import asyncio
import contextlib
import gc
import ipaddress
import socket
import ssl
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from gwops import webapp_probe
from gwops.configmodel.schema import EffectiveState
from gwops.renderer.render import RuntimePaths
from gwops.webapp_probe import (
    ProbeResult,
    ProbeRunner,
    ProbeTarget,
    probe_one,
    select_targets,
)

GW = "g-1"
LOOPBACK = "127.0.0.1"
ALLOWLIST = {"dns_suffixes": ["corp.internal"], "cidrs": ["10.0.0.0/24"]}
_OUTCOMES = {"ok", "untrusted_issuer", "hostname", "tls12_only", "unreachable"}


# --- PKI and local servers ---------------------------------------------------------------


@dataclass(frozen=True)
class _Pki:
    ca_file: Path
    cert_file: Path
    key_file: Path


def _pem_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _make_pki(
    directory: Path, *, dns: tuple[str, ...] = (), ips: tuple[str, ...] = (), tag: str = "pki"
) -> _Pki:
    """A private CA and a serverAuth leaf signed by it, with the given SANs, as PEM files."""
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{tag} test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = [x509.DNSName(d) for d in dns]
    sans += [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{tag} leaf")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    files = _Pki(directory / f"{tag}-ca.pem", directory / f"{tag}.crt", directory / f"{tag}.key")
    files.ca_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    files.cert_file.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    files.key_file.write_bytes(_pem_key(leaf_key))
    return files


@dataclass
class _Gauge:
    """Simultaneous open connections across every server sharing it."""

    active: int = 0
    peak: int = 0

    def enter(self) -> None:
        self.active += 1
        self.peak = max(self.peak, self.active)

    def leave(self) -> None:
        self.active -= 1


@dataclass
class _Server:
    port: int
    connections: int = 0
    """TCP connections accepted (handshake complete or not)."""
    handshakes: int = 0
    """Connections whose TLS handshake completed (TLS servers only)."""
    sni: list[str | None] = field(default_factory=list)
    received: bytearray = field(default_factory=bytearray)
    """Application bytes read after the handshake."""
    finished: asyncio.Event = field(default_factory=asyncio.Event)
    """Set once a handshaken connection has read to EOF."""


@contextlib.contextmanager
def _tls12_only_server(pki: _Pki) -> Iterator[_Server]:
    """A loopback TLS 1.2-only server on a thread.

    Not an asyncio server: on Windows its asyncio transport resets the connection on a failed
    handshake, so the client sees ConnectionResetError instead of the protocol_version alert.
    """
    server = _Server(port=0)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki.cert_file, pki.key_file)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    listener = socket.socket()
    listener.bind((LOOPBACK, 0))
    listener.listen(8)
    server.port = listener.getsockname()[1]

    def serve() -> None:
        while True:
            try:
                conn, _addr = listener.accept()
            except OSError:
                return
            server.connections += 1
            try:
                ctx.wrap_socket(conn, server_side=True).close()
            except (OSError, ssl.SSLError):
                conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        listener.close()
        thread.join(2)


@contextlib.asynccontextmanager
async def _tls_server(pki: _Pki) -> AsyncIterator[_Server]:
    """A loopback asyncio TLS 1.3-minimum server that records SNI and post-handshake bytes."""
    server = _Server(port=0)

    def on_sni(_sock: Any, name: str | None, _ctx: ssl.SSLContext) -> None:
        server.sni.append(name)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki.cert_file, pki.key_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.sni_callback = on_sni

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        server.connections += 1
        server.handshakes += 1
        try:
            server.received += await asyncio.wait_for(reader.read(), 5)
        except (TimeoutError, ConnectionError, ssl.SSLError):
            pass
        finally:
            server.finished.set()
            writer.close()

    srv = await asyncio.start_server(handle, LOOPBACK, 0, ssl=ctx)
    server.port = srv.sockets[0].getsockname()[1]
    try:
        yield server
    finally:
        srv.close()
        await srv.wait_closed()


@contextlib.asynccontextmanager
async def _hanging_server(gauge: _Gauge | None = None) -> AsyncIterator[_Server]:
    """A loopback server that accepts TCP and never answers the TLS handshake."""
    server = _Server(port=0)
    gauge = gauge or _Gauge()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        server.connections += 1
        gauge.enter()
        try:
            await asyncio.wait_for(reader.read(), 10)
        except (TimeoutError, ConnectionError):
            pass
        finally:
            gauge.leave()
            writer.close()

    srv = await asyncio.start_server(handle, LOOPBACK, 0)
    server.port = srv.sockets[0].getsockname()[1]
    try:
        yield server
    finally:
        srv.close()
        await srv.wait_closed()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind((LOOPBACK, 0))
        return int(sock.getsockname()[1])


async def _wait_until(predicate: Callable[[], bool], timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached before the deadline")
        await asyncio.sleep(0.01)


# --- dial recorder -----------------------------------------------------------------------


class _Dials:
    def __init__(self) -> None:
        self.connects: list[str] = []
        self.lookups: list[str] = []

    @property
    def hosts(self) -> set[str]:
        return {*self.connects, *self.lookups}


def _record_dials(monkeypatch: pytest.MonkeyPatch) -> _Dials:
    """Record every outbound connect and name lookup from here on, passing each through."""
    dials = _Dials()
    base = asyncio.base_events.BaseEventLoop
    loop_type = type(asyncio.get_running_loop())

    orig_create = base.create_connection

    async def create_connection(self: Any, protocol_factory: Any, host: Any = None, *a: Any,
                                **kw: Any) -> Any:
        if host is not None:
            dials.connects.append(str(host))
        return await orig_create(self, protocol_factory, host, *a, **kw)

    orig_sock_connect = loop_type.sock_connect

    async def sock_connect(self: Any, sock: Any, address: Any) -> Any:
        dials.connects.append(str(address[0]))
        return await orig_sock_connect(self, sock, address)

    orig_socket_create = socket.create_connection

    def socket_create(address: Any, *a: Any, **kw: Any) -> Any:
        dials.connects.append(str(address[0]))
        return orig_socket_create(address, *a, **kw)

    orig_getaddrinfo = socket.getaddrinfo

    def getaddrinfo(host: Any, *a: Any, **kw: Any) -> Any:
        dials.lookups.append(str(host))
        return orig_getaddrinfo(host, *a, **kw)

    monkeypatch.setattr(base, "create_connection", create_connection)
    monkeypatch.setattr(loop_type, "sock_connect", sock_connect)
    monkeypatch.setattr(socket, "create_connection", socket_create)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return dials


# --- state and remote builders -----------------------------------------------------------


def _paths(root: Path, bundles: Mapping[str, Path] | None = None) -> RuntimePaths:
    paths = RuntimePaths(
        pki_dir=root / "pki",
        recording_spool_dir=root / "spool",
        k8s_creds_dir=root / "k8s-creds",
        upstream_ca_dir=root / "upstream-ca",
        k8s_source_root=root / "k8s-src",
        webapp_ca_root=root / "webapp-cas",
        public_tls_root=root / "public-tls-src",
        public_tls_dir=root / "public-tls",
    )
    return paths.with_upstream_ca_files(bundles or {})


def _state(
    web_apps: list[dict[str, Any]] | None = None,
    *,
    allowlist: dict[str, Any] | None = None,
    probe: bool = True,
) -> EffectiveState:
    twingate: dict[str, Any] = {"network": "acme", "gateway_id": GW}
    if allowlist is not None:
        twingate["address_allowlist"] = allowlist
    return EffectiveState.model_validate(
        {
            "twingate": twingate,
            "web_apps": web_apps or [],
            "web_app_proxy": {
                "plaintext_upstreams": {"dns_suffixes": ["corp.internal"]},
                "upstream_tls_probe": probe,
            },
        }
    )


@pytest.fixture
def loopback_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let the runner dial the loopback servers these tests start; every other refusal stays."""
    real = webapp_probe._address_refused
    monkeypatch.setattr(
        webapp_probe, "_address_refused", lambda a: False if a.is_loopback else real(a)
    )


def _managed(name: str, address: str, **fields: Any) -> dict[str, Any]:
    return {"name": name, "address": address, **fields}


def _remote(name: str, address: str, **fields: Any) -> Any:
    from gwops.reconciler.core import RemoteWebApp

    values: dict[str, Any] = {
        "id": f"r-{name}",
        "name": name,
        "gateway_id": GW,
        "address": address,
        "upstream_port": 443,
        "alias": None,
        "upstream_tls": "verify_full",
        "downstream_tls": "tls13",
        "downstream_port": 443,
        "header_rewrite_names": (),
        "managed": False,
    }
    values.update(fields)
    return RemoteWebApp(**values)


def _by_name(targets: list[ProbeTarget]) -> dict[str, ProbeTarget]:
    return {t.name: t for t in targets}


def _target(
    port: int, *, host: str = LOOPBACK, mode: str = "verify_full", ca: tuple[Path, ...] = ()
) -> ProbeTarget:
    return ProbeTarget(name="app", host=host, port=port, mode=mode, ca_files=ca)  # type: ignore[arg-type]


async def _run_batch(
    runner: ProbeRunner,
    state: EffectiveState,
    remote: list[Any] | None,
    expect: set[str],
    *,
    grace: float = 0.2,
) -> None:
    """Schedule one batch, wait for `expect` results, then give stray dials time to appear."""
    runner.schedule(state, remote, GW)
    await _wait_until(lambda: expect <= set(runner.results))
    await asyncio.sleep(grace)


def _make_self_signed(directory: Path) -> _Pki:
    """A single self-signed server certificate (no separate CA) for 127.0.0.1."""
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "self-signed")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(LOOPBACK))]), False
        )
        .sign(key, hashes.SHA256())
    )
    pem = directory / "ss.crt"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile = directory / "ss.key"
    keyfile.write_bytes(_pem_key(key))
    return _Pki(pem, pem, keyfile)


# --- probe_one ---------------------------------------------------------------------------


class TestProbeOneOutcomes:
    @pytest.mark.parametrize("mode", ["verify_full", "verify_ca"])
    async def test_a_private_ca_leaf_is_ok_when_the_ca_file_is_trusted(
        self, tmp_path: Path, mode: str
    ) -> None:
        """A TLS 1.3 server whose leaf chains to a CA in ca_files is ok in both modes."""
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as server:
            result = await probe_one(_target(server.port, mode=mode, ca=(pki.ca_file,)))

        assert result.outcome == "ok"

    @pytest.mark.parametrize("mode", ["verify_full", "verify_ca"])
    async def test_a_private_ca_leaf_is_untrusted_when_the_ca_file_is_absent(
        self, tmp_path: Path, mode: str
    ) -> None:
        """Without the issuing CA in ca_files the system roots reject the chain."""
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as server:
            result = await probe_one(_target(server.port, mode=mode))

        assert result.outcome == "untrusted_issuer"

    async def test_a_self_signed_leaf_is_untrusted(self, tmp_path: Path) -> None:
        """A server certificate with no separate CA, absent from ca_files, is untrusted."""
        async with _tls_server(_make_self_signed(tmp_path / "ss")) as server:
            result = await probe_one(_target(server.port))

        assert result.outcome == "untrusted_issuer"

    async def test_a_tls12_only_server_is_reported_as_tls12_only(self, tmp_path: Path) -> None:
        """The TLS 1.3 minimum fails against a TLS 1.2-only server, even with the CA trusted."""
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        with _tls12_only_server(pki) as server:
            result = await probe_one(_target(server.port, ca=(pki.ca_file,)))

        assert result.outcome == "tls12_only"

    async def test_verify_full_reports_a_hostname_mismatch(self, tmp_path: Path) -> None:
        """A trusted leaf with no SAN for the dialled host is `hostname` under verify_full."""
        pki = _make_pki(tmp_path, dns=("other.corp.internal",))
        async with _tls_server(pki) as server:
            result = await probe_one(_target(server.port, mode="verify_full", ca=(pki.ca_file,)))

        assert result.outcome == "hostname"

    async def test_verify_ca_ignores_the_hostname(self, tmp_path: Path) -> None:
        """The same wrong-name leaf is ok under verify_ca, which checks the chain only."""
        pki = _make_pki(tmp_path, dns=("other.corp.internal",))
        async with _tls_server(pki) as server:
            result = await probe_one(_target(server.port, mode="verify_ca", ca=(pki.ca_file,)))

        assert result.outcome == "ok"

    async def test_a_refused_port_is_unreachable(self) -> None:
        """Nothing listening on the port yields `unreachable`."""
        result = await probe_one(_target(_free_port()), timeout=2.0)

        assert result.outcome == "unreachable"

    async def test_an_unresolvable_host_is_unreachable(self) -> None:
        """A name that does not resolve yields `unreachable`, not an exception."""
        result = await probe_one(_target(443, host="no-such-host.invalid"), timeout=3.0)

        assert result.outcome == "unreachable"

    async def test_a_handshake_that_never_completes_is_unreachable_within_the_timeout(
        self,
    ) -> None:
        """A server that accepts TCP and goes silent ends in `unreachable` at the timeout."""
        async with _hanging_server() as server:
            started = time.monotonic()
            result = await probe_one(_target(server.port), timeout=0.3)
            elapsed = time.monotonic() - started

        assert result.outcome == "unreachable"
        assert 0.25 <= elapsed < 2.0
        assert server.connections == 1


class TestProbeOneResultShape:
    async def test_the_result_carries_target_and_a_utc_timestamp(self, tmp_path: Path) -> None:
        """`target` is host:port and `checked_at` is a timezone-aware UTC time of the check."""
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        before = datetime.now(UTC)
        async with _tls_server(pki) as server:
            result = await probe_one(_target(server.port, ca=(pki.ca_file,)))
        after = datetime.now(UTC)

        assert isinstance(result, ProbeResult)
        assert result.outcome in _OUTCOMES
        assert result.target == f"{LOOPBACK}:{server.port}"
        assert result.checked_at.utcoffset() == timedelta(0)
        assert before <= result.checked_at <= after

    async def test_results_and_targets_are_frozen(self) -> None:
        """ProbeResult and ProbeTarget reject attribute assignment."""
        result = await probe_one(_target(_free_port()), timeout=2.0)
        target = _target(443)

        with pytest.raises((AttributeError, ValueError)):
            result.outcome = "ok"  # type: ignore[misc]
        with pytest.raises((AttributeError, ValueError)):
            target.port = 80  # type: ignore[misc]


class TestProbeOneWireBehaviour:
    async def test_the_probe_sends_no_application_data(self, tmp_path: Path) -> None:
        """After the handshake the server reads zero bytes before EOF."""
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as server:
            result = await probe_one(_target(server.port, ca=(pki.ca_file,)))
            await asyncio.wait_for(server.finished.wait(), 3)

        assert result.outcome == "ok"
        assert server.handshakes == 1
        assert bytes(server.received) == b""

    async def test_sni_is_the_host_for_a_dns_name(self, tmp_path: Path) -> None:
        """A DNS-name target presents its host as the SNI."""
        pki = _make_pki(tmp_path, dns=("localhost",), ips=(LOOPBACK,))
        async with _tls_server(pki) as server:
            result = await probe_one(
                _target(server.port, host="localhost", ca=(pki.ca_file,)), timeout=3.0
            )

        assert result.outcome == "ok"
        assert [s for s in server.sni if s] == ["localhost"]

    async def test_no_sni_is_sent_for_an_ip_literal(self, tmp_path: Path) -> None:
        """An IP-literal target sends no SNI."""
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as server:
            await probe_one(_target(server.port, ca=(pki.ca_file,)))

        assert [s for s in server.sni if s] == []

    @pytest.mark.parametrize("var", ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"])
    async def test_proxy_environment_is_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, var: str
    ) -> None:
        """A bogus proxy in the environment does not affect the direct dial."""
        for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY"):
            monkeypatch.delenv(name, raising=False)
            monkeypatch.delenv(name.lower(), raising=False)
        monkeypatch.setenv(var, f"http://{LOOPBACK}:{_free_port()}")
        monkeypatch.setenv(var.lower(), f"http://{LOOPBACK}:{_free_port()}")
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as server:
            result = await probe_one(_target(server.port, ca=(pki.ca_file,)))

        assert result.outcome == "ok"
        assert server.handshakes == 1


# --- select_targets ----------------------------------------------------------------------


class TestSeedFlag:
    def test_the_probe_flag_defaults_off(self) -> None:
        """`web_app_proxy.upstream_tls_probe` is False unless the seed sets it."""
        state = EffectiveState.model_validate({"twingate": {"network": "acme", "gateway_id": GW}})
        assert state.web_app_proxy.upstream_tls_probe is False

    def test_the_probe_flag_can_be_enabled_in_the_seed(self) -> None:
        """The seed accepts `web_app_proxy.upstream_tls_probe: true`."""
        state = EffectiveState.model_validate(
            {
                "twingate": {"network": "acme", "gateway_id": GW},
                "web_app_proxy": {"upstream_tls_probe": True},
            }
        )

        assert state.web_app_proxy.upstream_tls_probe is True


class TestSelectManaged:
    @pytest.mark.parametrize("mode", ["verify_full", "verify_ca"])
    def test_managed_verifying_entries_are_targets(self, tmp_path: Path, mode: str) -> None:
        """A declared web app with verify_full or verify_ca is probed at host and port."""
        ca = tmp_path / "corp-aaaa.pem"
        state = _state([_managed("grafana", "grafana.corp.internal:8443", upstream_tls=mode)])

        targets, unverifiable = select_targets(
            state, [], GW, _paths(tmp_path, {"corp": ca})
        )

        assert unverifiable == []
        [target] = targets
        assert (target.name, target.host, target.port, target.mode) == (
            "grafana", "grafana.corp.internal", 8443, mode,
        )
        assert set(target.ca_files) == {ca}

    def test_a_managed_address_without_a_port_uses_443(self, tmp_path: Path) -> None:
        """The upstream port defaults to 443 for a portless managed address."""
        state = _state([_managed("grafana", "grafana.corp.internal")])

        targets, _ = select_targets(state, [], GW, _paths(tmp_path))

        assert [(t.host, t.port) for t in targets] == [("grafana.corp.internal", 443)]

    def test_every_validated_bundle_copy_is_a_trust_file(self, tmp_path: Path) -> None:
        """ca_files holds each upstream CA bundle copy, not just one."""
        bundles = {"a": tmp_path / "a-1.pem", "b": tmp_path / "b-2.pem"}
        state = _state([_managed("grafana", "grafana.corp.internal")])

        [target], _ = select_targets(state, [], GW, _paths(tmp_path, bundles))

        assert set(target.ca_files) == set(bundles.values())

    @pytest.mark.parametrize("mode", ["insecure", "none"])
    def test_insecure_and_plaintext_entries_are_not_probed(
        self, tmp_path: Path, mode: str
    ) -> None:
        """Upstream modes insecure and none are neither targets nor unverifiable."""
        state = _state([_managed("grafana", "grafana.corp.internal", upstream_tls=mode)])

        targets, unverifiable = select_targets(state, [], GW, _paths(tmp_path))

        assert (targets, unverifiable) == ([], [])

    def test_managed_entries_do_not_need_the_allowlist(self, tmp_path: Path) -> None:
        """Seed-authored entries are probed with no allowlist and outside one."""
        apps = [_managed("one", "one.example.net"), _managed("two", "two.example.net")]

        no_list, _ = select_targets(_state(apps), [], GW, _paths(tmp_path))
        outside, _ = select_targets(_state(apps, allowlist=ALLOWLIST), [], GW, _paths(tmp_path))

        assert set(_by_name(no_list)) == set(_by_name(outside)) == {"one", "two"}

    def test_a_managed_app_present_in_the_tenant_listing_is_one_target(
        self, tmp_path: Path
    ) -> None:
        """A managed remote row for a declared entry is not a second target."""
        state = _state([_managed("grafana", "grafana.corp.internal")])
        remote = [_remote("grafana", "grafana.corp.internal", managed=True)]

        targets, unverifiable = select_targets(state, remote, GW, _paths(tmp_path))

        assert [t.name for t in targets] == ["grafana"]
        assert unverifiable == []

    def test_the_alias_is_never_a_target(self, tmp_path: Path) -> None:
        """Only the address host is dialled; the alias is a client-facing name."""
        state = _state(
            [_managed("grafana", "grafana.corp.internal", alias="graf.example.net")]
        )

        targets, _ = select_targets(state, [], GW, _paths(tmp_path))

        assert {t.host for t in targets} == {"grafana.corp.internal"}


class TestSelectUnmanaged:
    @pytest.mark.parametrize("mode", ["verify_full", "verify_ca"])
    @pytest.mark.parametrize("address", ["stranger.corp.internal", "10.0.0.7"])
    def test_an_unmanaged_app_inside_the_allowlist_is_a_target(
        self, tmp_path: Path, mode: str, address: str
    ) -> None:
        """An unmanaged app on this gateway inside the allowlist is probed on the tenant's port."""
        ca = tmp_path / "corp-aaaa.pem"
        remote = [_remote("stranger", address, upstream_tls=mode, upstream_port=8443)]

        targets, unverifiable = select_targets(
            _state(allowlist=ALLOWLIST), remote, GW, _paths(tmp_path, {"corp": ca})
        )

        assert unverifiable == []
        [target] = targets
        assert (target.name, target.host, target.port, target.mode) == (
            "stranger", address, 8443, mode,
        )
        assert target.result_key == "r-stranger"
        assert set(target.ca_files) == {ca}

    @pytest.mark.parametrize(
        "address",
        [
            "stranger.example.net",
            "xcorp.internal",
            "corp.internal.evil.net",
            "10.0.1.7",
            "169.254.169.254",
        ],
    )
    def test_an_unmanaged_app_outside_the_allowlist_is_unverifiable(
        self, tmp_path: Path, address: str
    ) -> None:
        """An address the allowlist does not cover is listed unverifiable and not a target."""
        remote = [_remote("stranger", address)]

        targets, unverifiable = select_targets(
            _state(allowlist=ALLOWLIST), remote, GW, _paths(tmp_path)
        )

        assert targets == []
        assert unverifiable == ["r-stranger"]

    @pytest.mark.parametrize("address", ["stranger.corp.internal", "10.0.0.7", "169.254.169.254"])
    def test_with_no_allowlist_an_unmanaged_app_is_unverifiable(
        self, tmp_path: Path, address: str
    ) -> None:
        """With no twingate.address_allowlist no unmanaged address is ever a target."""
        remote = [_remote("stranger", address)]

        targets, unverifiable = select_targets(_state(), remote, GW, _paths(tmp_path))

        assert targets == []
        assert unverifiable == ["r-stranger"]

    @pytest.mark.parametrize("address", ["*.corp.internal", "*"])
    def test_a_wildcard_address_is_unverifiable_even_inside_the_allowlist(
        self, tmp_path: Path, address: str
    ) -> None:
        """Wildcard addresses are never dialled."""
        remote = [_remote("wild", address)]

        targets, unverifiable = select_targets(
            _state(allowlist=ALLOWLIST), remote, GW, _paths(tmp_path)
        )

        assert targets == []
        assert unverifiable == ["r-wild"]

    def test_another_gateways_apps_are_excluded_from_both_lists(self, tmp_path: Path) -> None:
        """Apps attached to a different gateway are neither probed nor reported."""
        remote = [
            _remote("elsewhere", "elsewhere.corp.internal", gateway_id="g-2"),
            _remote("elsewhere-out", "elsewhere.example.net", gateway_id="g-2"),
        ]

        targets, unverifiable = select_targets(
            _state(allowlist=ALLOWLIST), remote, GW, _paths(tmp_path)
        )

        assert (targets, unverifiable) == ([], [])

    @pytest.mark.parametrize("mode", ["insecure", "none"])
    def test_unmanaged_insecure_and_plaintext_apps_are_not_probed(
        self, tmp_path: Path, mode: str
    ) -> None:
        """Upstream modes insecure and none are neither targets nor unverifiable."""
        remote = [
            _remote("in", "in.corp.internal", upstream_tls=mode),
            _remote("out", "out.example.net", upstream_tls=mode),
        ]

        targets, unverifiable = select_targets(
            _state(allowlist=ALLOWLIST), remote, GW, _paths(tmp_path)
        )

        assert (targets, unverifiable) == ([], [])

    def test_no_tenant_listing_leaves_only_the_managed_targets(self, tmp_path: Path) -> None:
        """A None remote listing (tenant not listed) selects the declared entries only."""
        state = _state([_managed("grafana", "grafana.corp.internal")], allowlist=ALLOWLIST)

        targets, unverifiable = select_targets(state, None, GW, _paths(tmp_path))

        assert [t.name for t in targets] == ["grafana"]
        assert unverifiable == []


class TestSelectBoundedSet:
    def test_a_mixed_estate_yields_exactly_the_in_scope_names_once_each(
        self, tmp_path: Path
    ) -> None:
        """Targets and unverifiable names are the in-scope apps, each once, with no extras."""
        state = _state(
            [
                _managed("m-full", "m-full.example.net"),
                _managed("m-ca", "m-ca.example.net:8443", upstream_tls="verify_ca"),
                _managed("m-insecure", "m-insecure.corp.internal", upstream_tls="insecure"),
            ],
            allowlist=ALLOWLIST,
        )
        remote = [
            _remote("m-full", "m-full.example.net", managed=True),
            _remote("u-in", "u-in.corp.internal"),
            _remote("u-ip", "10.0.0.9", upstream_tls="verify_ca"),
            _remote("u-out", "u-out.example.net"),
            _remote("u-wild", "*.corp.internal"),
            _remote("u-plain", "u-plain.corp.internal", upstream_tls="none"),
            _remote("other-gw", "other.corp.internal", gateway_id="g-9"),
        ]

        targets, unverifiable = select_targets(state, remote, GW, _paths(tmp_path))

        names = [t.name for t in targets]
        assert sorted(names) == ["m-ca", "m-full", "u-in", "u-ip"]
        assert len(set(names)) == len(names)
        assert sorted(unverifiable) == ["r-u-out", "r-u-wild"]
        assert {t.host for t in targets} == {
            "m-full.example.net", "m-ca.example.net", "u-in.corp.internal", "10.0.0.9",
        }


# --- ProbeRunner -------------------------------------------------------------------------


def _loopback_apps(servers: list[_Server], **fields: Any) -> list[dict[str, Any]]:
    return [
        _managed(f"app{i}", f"{LOOPBACK}:{server.port}", **fields)
        for i, server in enumerate(servers)
    ]


@pytest.mark.usefixtures("loopback_allowed")
class TestRunnerDisabled:
    def test_enabled_reflects_the_constructor_flag(self, tmp_path: Path) -> None:
        """`enabled` is the seed flag the runner was built with."""
        assert ProbeRunner(_paths(tmp_path), enabled=True).enabled is True
        assert ProbeRunner(_paths(tmp_path), enabled=False).enabled is False

    async def test_a_disabled_runner_makes_no_dial_or_lookup(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With the flag off, schedule attempts no connection and no name resolution."""
        dials = _record_dials(monkeypatch)
        state = _state(
            [_managed("grafana", "grafana.corp.internal"), _managed("ip", f"{LOOPBACK}:9")],
            allowlist=ALLOWLIST,
            probe=False,
        )
        remote = [_remote("stranger", "stranger.corp.internal"), _remote("ip2", "10.0.0.7")]
        runner = ProbeRunner(_paths(tmp_path), enabled=False)

        runner.schedule(state, remote, GW)
        await asyncio.sleep(0.3)
        await runner.aclose()

        assert dials.connects == []
        assert dials.lookups == []
        assert runner.results == {}

    async def test_a_disabled_runner_never_reaches_a_listening_server(
        self, tmp_path: Path
    ) -> None:
        """A live server sees zero connections when the flag is off."""
        async with _hanging_server() as server:
            runner = ProbeRunner(_paths(tmp_path), enabled=False)

            runner.schedule(_state(_loopback_apps([server]), probe=False), [], GW)
            await asyncio.sleep(0.3)
            await runner.aclose()

        assert server.connections == 0


@pytest.mark.usefixtures("loopback_allowed")
class TestRunnerScope:
    async def test_the_runner_dials_only_in_scope_addresses(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Out-of-allowlist, wildcard and other-gateway addresses are never dialled or resolved."""
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as server:
            dials = _record_dials(monkeypatch)
            paths = _paths(tmp_path, {"corp": pki.ca_file})
            state = _state(_loopback_apps([server]), allowlist=ALLOWLIST)
            remote = [
                _remote("out-dns", "out.example.net"),
                _remote("out-ip", "10.9.9.9"),
                _remote("metadata", "169.254.169.254"),
                _remote("wild", "*.corp.internal"),
                _remote("other-gw", "other.corp.internal", gateway_id="g-9"),
                _remote("other-gw-ip", "10.0.0.8", gateway_id="g-9"),
            ]
            runner = ProbeRunner(paths, enabled=True, timeout=1.0)

            await _run_batch(runner, state, remote, {"app0"})
            await runner.aclose()

        assert dials.connects, "the recorder saw no dial at all"
        assert dials.hosts <= {LOOPBACK}
        assert set(runner.results) == {"app0"}

    async def test_no_allowlist_means_no_unmanaged_dial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With no allowlist, unmanaged apps (even on loopback) are never dialled."""
        async with _hanging_server() as unmanaged:
            dials = _record_dials(monkeypatch)
            remote = [_remote("loop", LOOPBACK)]
            runner = ProbeRunner(_paths(tmp_path), enabled=True, timeout=0.5)

            runner.schedule(_state(), remote, GW)
            await asyncio.sleep(0.4)
            await runner.aclose()

        assert unmanaged.connections == 0
        assert dials.connects == []
        assert dials.lookups == []
        assert runner.results == {}

    async def test_results_are_keyed_by_name_with_outcome_and_target(
        self, tmp_path: Path
    ) -> None:
        """Each probed app gets a ProbeResult under its web-app name."""
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        other = _make_pki(tmp_path, ips=(LOOPBACK,), tag="other")
        async with _tls_server(pki) as good, _tls_server(other) as bad:
            apps = [
                _managed("trusted", f"{LOOPBACK}:{good.port}"),
                _managed("distrusted", f"{LOOPBACK}:{bad.port}"),
            ]
            runner = ProbeRunner(_paths(tmp_path, {"corp": pki.ca_file}), enabled=True)
            await _run_batch(runner, _state(apps), [], {"trusted", "distrusted"}, grace=0.0)
            await runner.aclose()

        assert set(runner.results) == {"trusted", "distrusted"}
        assert runner.results["trusted"].outcome == "ok"
        assert runner.results["trusted"].target == f"{LOOPBACK}:{good.port}"
        assert runner.results["distrusted"].outcome == "untrusted_issuer"

    async def test_an_untrusted_private_ca_is_reported_when_no_bundle_is_configured(
        self, tmp_path: Path
    ) -> None:
        """With no upstream CA bundle copies the private-CA leaf is `untrusted_issuer`."""
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as server:
            runner = ProbeRunner(_paths(tmp_path), enabled=True)
            await _run_batch(runner, _state(_loopback_apps([server])), [], {"app0"}, grace=0.0)
            await runner.aclose()

        assert runner.results["app0"].outcome == "untrusted_issuer"


@pytest.mark.usefixtures("loopback_allowed")
class TestRunnerScheduling:
    async def test_schedule_returns_before_the_probe_completes(self, tmp_path: Path) -> None:
        """schedule does not wait for a slow upstream; the result arrives later."""
        async with _hanging_server() as server:
            runner = ProbeRunner(_paths(tmp_path), enabled=True, timeout=1.0)
            started = time.monotonic()

            runner.schedule(_state(_loopback_apps([server])), [], GW)
            returned_in = time.monotonic() - started

            assert returned_in < 0.2
            assert runner.results == {}
            await _wait_until(lambda: server.connections == 1)
            assert "app0" not in runner.results
            await _wait_until(lambda: "app0" in runner.results)
            await runner.aclose()

        assert runner.results["app0"].outcome == "unreachable"

    async def test_a_schedule_during_a_running_batch_is_coalesced(self, tmp_path: Path) -> None:
        """Repeated schedules while a batch runs start no second batch and no re-run."""
        async with _hanging_server() as server:
            runner = ProbeRunner(_paths(tmp_path), enabled=True, timeout=0.8)
            state = _state(_loopback_apps([server]))

            runner.schedule(state, [], GW)
            runner.schedule(state, [], GW)
            runner.schedule(state, [], GW)
            await _wait_until(lambda: server.connections >= 1)
            await asyncio.sleep(0.2)
            assert server.connections == 1

            await _wait_until(lambda: "app0" in runner.results)
            await asyncio.sleep(0.3)
            assert server.connections == 1

            runner.schedule(state, [], GW)
            await _wait_until(lambda: server.connections == 2)
            await runner.aclose()

    async def test_concurrency_is_capped_at_four_and_each_target_dials_once(
        self, tmp_path: Path
    ) -> None:
        """Eight slow targets are dialled at most four at a time, once each."""
        gauge = _Gauge()
        async with contextlib.AsyncExitStack() as stack:
            servers = [await stack.enter_async_context(_hanging_server(gauge)) for _ in range(8)]
            runner = ProbeRunner(_paths(tmp_path), enabled=True, timeout=0.5)
            names = {f"app{i}" for i in range(8)}

            await _run_batch(runner, _state(_loopback_apps(servers)), [], names, grace=0.3)
            await runner.aclose()

        assert 1 <= gauge.peak <= 4
        assert [s.connections for s in servers] == [1] * 8
        assert {r.outcome for r in runner.results.values()} == {"unreachable"}

    async def test_aclose_cancels_an_in_flight_batch_cleanly(self, tmp_path: Path) -> None:
        """aclose returns promptly mid-batch, drops the connection, and may be repeated."""
        gauge = _Gauge()
        async with _hanging_server(gauge) as server:
            runner = ProbeRunner(_paths(tmp_path), enabled=True, timeout=10.0)
            runner.schedule(_state(_loopback_apps([server])), [], GW)
            await _wait_until(lambda: server.connections == 1)

            started = time.monotonic()
            await runner.aclose()
            await runner.aclose()
            closed_in = time.monotonic() - started

            await _wait_until(lambda: gauge.active == 0)

        assert closed_in < 2.0
        assert "app0" not in runner.results

    async def test_aclose_with_no_batch_is_a_no_op(self, tmp_path: Path) -> None:
        """aclose on a runner that never scheduled anything does not raise."""
        await ProbeRunner(_paths(tmp_path), enabled=True).aclose()
        await ProbeRunner(_paths(tmp_path), enabled=False).aclose()


@pytest.mark.usefixtures("loopback_allowed")
class TestRunnerNeverRaises:
    @staticmethod
    def _capture_loop_errors() -> list[dict[str, Any]]:
        errors: list[dict[str, Any]] = []
        asyncio.get_running_loop().set_exception_handler(lambda _loop, ctx: errors.append(ctx))
        return errors

    async def test_an_exception_in_one_probe_does_not_escape_or_stop_the_batch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A probe that raises leaves no unhandled task error and the other targets finish."""
        errors = self._capture_loop_errors()
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        real_probe_one = webapp_probe.probe_one

        async def flaky(target: ProbeTarget, **kwargs: Any) -> ProbeResult:
            if target.name == "app0":
                raise RuntimeError("boom")
            return await real_probe_one(target, **kwargs)

        monkeypatch.setattr(webapp_probe, "probe_one", flaky)
        async with _tls_server(pki) as first, _tls_server(pki) as second:
            runner = ProbeRunner(_paths(tmp_path, {"corp": pki.ca_file}), enabled=True)

            runner.schedule(_state(_loopback_apps([first, second])), [], GW)
            await _wait_until(lambda: "app1" in runner.results)
            await asyncio.sleep(0.1)
            await runner.aclose()

        gc.collect()
        await asyncio.sleep(0)
        assert runner.results["app1"].outcome == "ok"
        assert errors == []

    async def test_a_failing_target_selection_does_not_raise_from_schedule(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An exception inside target selection is contained and logged nowhere as unhandled."""
        errors = self._capture_loop_errors()

        def broken(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("selection broke")

        monkeypatch.setattr(webapp_probe, "select_targets", broken)
        runner = ProbeRunner(_paths(tmp_path), enabled=True)

        runner.schedule(_state([_managed("grafana", "grafana.corp.internal")]), [], GW)
        await asyncio.sleep(0.1)
        await runner.aclose()

        gc.collect()
        await asyncio.sleep(0)
        assert runner.results == {}
        assert errors == []

    async def test_a_batch_after_a_failed_batch_still_runs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A batch that blew up does not leave the runner stuck in the running state."""
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        real_select = webapp_probe.select_targets
        calls = {"n": 0}

        def broken_once(*args: Any, **kwargs: Any) -> Any:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("first batch broke")
            return real_select(*args, **kwargs)

        monkeypatch.setattr(webapp_probe, "select_targets", broken_once)
        async with _tls_server(pki) as server:
            runner = ProbeRunner(_paths(tmp_path, {"corp": pki.ca_file}), enabled=True)
            state = _state(_loopback_apps([server]))

            runner.schedule(state, [], GW)
            await _wait_until(lambda: calls["n"] == 1)
            await asyncio.sleep(0.1)
            runner.schedule(state, [], GW)
            await _wait_until(lambda: "app0" in runner.results)
            await runner.aclose()

        assert runner.results["app0"].outcome == "ok"


# --- result keys, dedupe and kept state ----------------------------------------------------

LOOP_ALLOW = {"cidrs": ["127.0.0.0/8"]}


class TestResultKeys:
    def test_a_managed_target_is_keyed_by_its_tenant_id_and_by_name_before_it_exists(
        self, tmp_path: Path
    ) -> None:
        """The tenant id when the managed app is listed; the name while it is not yet there."""
        state = _state(
            [_managed("on", "on.corp.internal"), _managed("new", "new.corp.internal")]
        )
        remote = [_remote("on", "on.corp.internal", managed=True)]

        targets, _ = select_targets(state, remote, GW, _paths(tmp_path))

        assert {t.name: t.result_key for t in targets} == {"on": "r-on", "new": "new"}

    def test_a_same_named_unmanaged_app_is_its_own_target_under_its_own_id(
        self, tmp_path: Path
    ) -> None:
        """An unmanaged app named like a declared one cannot share its result key."""
        state = _state([_managed("grafana", "grafana.corp.internal")], allowlist=ALLOWLIST)
        remote = [
            _remote("grafana", "grafana.corp.internal", managed=True),
            _remote("grafana", "other.corp.internal", id="r-dup"),
        ]

        targets, _ = select_targets(state, remote, GW, _paths(tmp_path))

        assert sorted(t.result_key for t in targets) == ["r-dup", "r-grafana"]

    async def test_a_same_named_unmanaged_result_never_lands_on_the_managed_key(
        self, tmp_path: Path
    ) -> None:
        """Both apps probe; each result is stored under its own tenant id."""
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as good, _hanging_server() as hung:
            state = _state(
                [_managed("grafana", f"{LOOPBACK}:{good.port}")], allowlist=LOOP_ALLOW
            )
            remote = [
                _remote("grafana", f"{LOOPBACK}:{good.port}", managed=True),
                _remote("grafana", LOOPBACK, id="r-dup", upstream_port=hung.port),
            ]
            runner = ProbeRunner(_paths(tmp_path, {"corp": pki.ca_file}), enabled=True, timeout=0.5)
            with pytest.MonkeyPatch.context() as mp:
                real = webapp_probe._address_refused
                mp.setattr(
                    webapp_probe, "_address_refused", lambda a: False if a.is_loopback else real(a)
                )
                await _run_batch(runner, state, remote, {"r-grafana", "r-dup"})
            await runner.aclose()

        assert runner.results["r-grafana"].outcome == "ok"
        assert runner.results["r-dup"].outcome == "unreachable"


@pytest.mark.usefixtures("loopback_allowed")
class TestRunnerBehaviour:
    async def test_identical_upstreams_are_dialled_once_and_each_key_gets_the_result(
        self, tmp_path: Path
    ) -> None:
        """Dials are deduplicated on (host, port, mode, ca_files)."""
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as server:
            address = f"{LOOPBACK}:{server.port}"
            state = _state([_managed("one", address), _managed("two", address)])
            runner = ProbeRunner(_paths(tmp_path, {"corp": pki.ca_file}), enabled=True)

            await _run_batch(runner, state, [], {"one", "two"})
            await runner.aclose()

        assert server.handshakes == 1
        assert runner.results["one"] == runner.results["two"]
        assert runner.results["one"].outcome == "ok"

    async def test_different_modes_are_separate_dials(self, tmp_path: Path) -> None:
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as server:
            address = f"{LOOPBACK}:{server.port}"
            state = _state(
                [_managed("full", address), _managed("ca", address, upstream_tls="verify_ca")]
            )
            runner = ProbeRunner(_paths(tmp_path, {"corp": pki.ca_file}), enabled=True)

            await _run_batch(runner, state, [], {"full", "ca"})
            await runner.aclose()

        assert server.handshakes == 2

    async def test_without_a_tenant_listing_unmanaged_state_is_kept(self, tmp_path: Path) -> None:
        """A batch with remote None re-probes declared apps and keeps the unmanaged results."""
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as managed, _tls_server(pki) as stranger:
            state = _state(
                [_managed("grafana", f"{LOOPBACK}:{managed.port}")], allowlist=LOOP_ALLOW
            )
            remote = [
                _remote("grafana", f"{LOOPBACK}:{managed.port}", managed=True),
                _remote("stranger", LOOPBACK, upstream_port=stranger.port),
                _remote("blocked", "10.9.9.9"),
            ]
            runner = ProbeRunner(_paths(tmp_path, {"corp": pki.ca_file}), enabled=True)
            await _run_batch(runner, state, remote, {"r-grafana", "r-stranger"})
            await _wait_until(lambda: runner._task is not None and runner._task.done())
            assert runner.unverifiable == {"r-blocked"}

            runner.schedule(state, None, GW)
            await _wait_until(lambda: runner._task is not None and runner._task.done())
            await runner.aclose()

        assert set(runner.results) == {"r-grafana", "r-stranger"}
        assert runner.unverifiable == {"r-blocked"}
        assert managed.handshakes == 2

    async def test_a_listed_batch_drops_results_of_apps_that_left(self, tmp_path: Path) -> None:
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as stranger:
            state = _state([], allowlist=LOOP_ALLOW)
            remote = [_remote("stranger", LOOPBACK, upstream_port=stranger.port)]
            runner = ProbeRunner(_paths(tmp_path, {"corp": pki.ca_file}), enabled=True)
            await _run_batch(runner, state, remote, {"r-stranger"})
            await _wait_until(lambda: runner._task is not None and runner._task.done())

            runner.schedule(state, [], GW)
            await _wait_until(lambda: not runner.results)
            await runner.aclose()

    async def test_a_probe_that_raises_is_recorded_by_error_type(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The key lands in failed with the exception class and has no result."""
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        real_probe_one = webapp_probe.probe_one

        async def flaky(target: ProbeTarget, **kwargs: Any) -> ProbeResult:
            if target.name == "app0":
                raise RuntimeError("boom")
            return await real_probe_one(target, **kwargs)

        monkeypatch.setattr(webapp_probe, "probe_one", flaky)
        async with _tls_server(pki) as first, _tls_server(pki) as second:
            runner = ProbeRunner(_paths(tmp_path, {"corp": pki.ca_file}), enabled=True)
            runner.results["app0"] = ProbeResult("ok", datetime.now(UTC), "stale")

            await _run_batch(runner, _state(_loopback_apps([first, second])), [], {"app1"})
            await runner.aclose()

        snap = runner.snapshot()
        assert snap.failed == {"app0": "RuntimeError"}
        assert "app0" not in snap.results
        assert snap.last_batch_error is None

    async def test_a_failed_batch_keeps_no_stale_results_and_records_the_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = ProbeRunner(_paths(tmp_path), enabled=True)
        runner.results["app0"] = ProbeResult("ok", datetime.now(UTC), "stale")

        def broken(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("selection broke")

        monkeypatch.setattr(webapp_probe, "select_targets", broken)
        runner.schedule(_state([_managed("grafana", "grafana.corp.internal")]), [], GW)
        await _wait_until(lambda: runner.last_batch_error is not None)
        await runner.aclose()

        snap = runner.snapshot()
        assert snap.last_batch_error == "RuntimeError"
        assert snap.results == {}

    async def test_a_successful_batch_clears_the_batch_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        real_select = webapp_probe.select_targets
        calls = {"n": 0}

        def broken_once(*args: Any, **kwargs: Any) -> Any:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("first")
            return real_select(*args, **kwargs)

        monkeypatch.setattr(webapp_probe, "select_targets", broken_once)
        async with _tls_server(pki) as server:
            runner = ProbeRunner(_paths(tmp_path, {"corp": pki.ca_file}), enabled=True)
            state = _state(_loopback_apps([server]))
            runner.schedule(state, [], GW)
            await _wait_until(lambda: runner.last_batch_error == "RuntimeError")
            await asyncio.sleep(0.05)
            runner.schedule(state, [], GW)
            await _wait_until(lambda: "app0" in runner.results)
            await runner.aclose()

        assert runner.snapshot().last_batch_error is None

    async def test_the_snapshot_is_a_read_only_copy(self, tmp_path: Path) -> None:
        runner = ProbeRunner(_paths(tmp_path), enabled=True)
        runner.results["a"] = ProbeResult("ok", datetime.now(UTC), "h:1")

        snap = runner.snapshot()
        runner.results["b"] = ProbeResult("ok", datetime.now(UTC), "h:2")

        assert set(snap.results) == {"a"}
        with pytest.raises(TypeError):
            snap.results["c"] = snap.results["a"]  # type: ignore[index]
        with pytest.raises(TypeError):
            snap.failed["c"] = "x"  # type: ignore[index]
        await runner.aclose()


@pytest.mark.usefixtures("loopback_allowed")
class TestOutcomeFidelity:
    async def test_a_verification_failure_carries_error_type_and_verify_code(
        self, tmp_path: Path
    ) -> None:
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as server:
            result = await probe_one(_target(server.port))

        assert result.outcome == "untrusted_issuer"
        assert result.error_type == "SSLCertVerificationError"
        assert isinstance(result.verify_code, int) and result.verify_code not in {62, 64}

    async def test_a_hostname_mismatch_carries_its_verify_code(self, tmp_path: Path) -> None:
        pki = _make_pki(tmp_path, dns=("other.corp.internal",))
        async with _tls_server(pki) as server:
            result = await probe_one(_target(server.port, ca=(pki.ca_file,)))

        assert result.outcome == "hostname"
        assert result.verify_code in {62, 64}

    async def test_an_ok_result_has_no_error_fields(self, tmp_path: Path) -> None:
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as server:
            result = await probe_one(_target(server.port, ca=(pki.ca_file,)))

        assert (result.outcome, result.error_type, result.verify_code) == ("ok", None, None)

    async def test_a_refused_connection_names_the_error_type(self) -> None:
        result = await probe_one(_target(_free_port()), timeout=2.0)

        assert result.outcome == "unreachable"
        assert result.error_type is not None and result.verify_code is None

    async def test_a_silent_server_reports_a_timeout_error_type(self) -> None:
        async with _hanging_server() as server:
            result = await probe_one(_target(server.port), timeout=0.3)

        assert (result.outcome, result.error_type) == ("unreachable", "TimeoutError")

    async def test_the_log_carries_error_type_and_verify_code(self, tmp_path: Path) -> None:
        import structlog

        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as server:
            runner = ProbeRunner(_paths(tmp_path), enabled=True)
            with structlog.testing.capture_logs() as logs:
                await _run_batch(runner, _state(_loopback_apps([server])), [], {"app0"})
            await runner.aclose()

        [event] = [e for e in logs if e["event"] == "webapp_probe.result"]
        assert event["error_type"] == "SSLCertVerificationError"
        assert isinstance(event["verify_code"], int)

    async def test_a_slow_close_does_not_turn_a_completed_handshake_into_unreachable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The close is bounded separately, outside the probe timeout."""

        class _Writer:
            def close(self) -> None:
                return None

            async def wait_closed(self) -> None:
                await asyncio.sleep(0.5)

        async def fake_open(*_a: Any, **_k: Any) -> tuple[None, _Writer]:
            await asyncio.sleep(0.15)
            return None, _Writer()

        monkeypatch.setattr(asyncio, "open_connection", fake_open)
        monkeypatch.setattr(webapp_probe, "_CLOSE_WAIT_SECONDS", 0.8)

        result = await probe_one(_target(443), timeout=0.3)

        assert result.outcome == "ok"

    async def test_a_close_that_never_finishes_is_still_bounded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Writer:
            def close(self) -> None:
                return None

            async def wait_closed(self) -> None:
                await asyncio.sleep(30)

        async def fake_open(*_a: Any, **_k: Any) -> tuple[None, _Writer]:
            return None, _Writer()

        monkeypatch.setattr(asyncio, "open_connection", fake_open)
        monkeypatch.setattr(webapp_probe, "_CLOSE_WAIT_SECONDS", 0.2)

        started = time.monotonic()
        result = await probe_one(_target(443), timeout=5.0)

        assert result.outcome == "ok"
        assert time.monotonic() - started < 2.0

    async def test_an_unusable_ca_file_is_ca_unusable_not_untrusted_issuer(
        self, tmp_path: Path
    ) -> None:
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        broken = tmp_path / "corp-broken.pem"
        broken.write_text("not a certificate", encoding="utf-8")
        async with _tls_server(pki) as server:
            result = await probe_one(_target(server.port, ca=(broken,)))

        assert result.outcome == "ca_unusable"
        assert result.error_type == "SSLCertVerificationError"

    async def test_an_unusable_ca_file_is_warned_once_per_file(self, tmp_path: Path) -> None:
        import structlog

        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        broken = tmp_path / "corp-broken.pem"
        broken.write_text("not a certificate", encoding="utf-8")
        async with _tls_server(pki) as first, _tls_server(pki) as second:
            runner = ProbeRunner(_paths(tmp_path, {"corp": broken}), enabled=True)
            state = _state(_loopback_apps([first, second]))
            with structlog.testing.capture_logs() as logs:
                await _run_batch(runner, state, [], {"app0", "app1"})
                await _wait_until(lambda: runner._task is not None and runner._task.done())
                runner.schedule(state, [], GW)
                await _wait_until(lambda: runner._task is not None and runner._task.done())
                await asyncio.sleep(0.1)
            await runner.aclose()

        warned = [e for e in logs if e["event"] == "webapp_probe.ca_file_unusable"]
        assert len(warned) == 1
        assert warned[0]["file"] == "corp-broken.pem"


# --- address safety ----------------------------------------------------------------------


def _fake_getaddrinfo(*addresses: str) -> Callable[..., Any]:
    def getaddrinfo(host: Any, port: Any, *_a: Any, **_k: Any) -> Any:
        return [
            (
                socket.AF_INET6 if ":" in address else socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (address, port or 0),
            )
            for address in addresses
        ]

    return getaddrinfo


class TestAddressSafety:
    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",
            "127.8.8.8",
            "169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "::",
            "ff02::1",
            "::ffff:127.0.0.1",
            "0.1.2.3",
            "0.255.255.255",
            "::127.0.0.1",
            "::169.254.169.254",
            "::ffff:0:127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "2002:7f00:1::1",
            "2002:a9fe:a9fe::1",
            "fd00:ec2::254",
            "100.100.100.200",
        ],
    )
    async def test_a_managed_name_resolving_to_a_refused_address_is_never_dialled(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, address: str
    ) -> None:
        dials = _record_dials(monkeypatch)
        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(address))
        runner = ProbeRunner(_paths(tmp_path), enabled=True)

        runner.schedule(_state([_managed("grafana", "grafana.corp.internal")]), [], GW)
        await _wait_until(lambda: runner.snapshot().refused)
        await runner.aclose()

        snap = runner.snapshot()
        assert snap.refused == {"grafana"}
        assert snap.results == {} and snap.failed == {}
        assert dials.connects == []

    @pytest.mark.parametrize(
        "address",
        [
            "10.0.0.7",
            "172.16.4.2",
            "192.168.1.9",
            "1.2.3.4",
            "100.64.0.1",
            "fd12:3456::7",
            "2001:db8::1",
            "::ffff:10.0.0.7",
            "::10.0.0.7",
            "64:ff9b::a00:7",
            "2002:a00:7::1",
        ],
    )
    def test_internal_and_public_addresses_stay_allowed(self, address: str) -> None:
        """Private, ULA and public ranges (and IPv6 forms embedding them) are not refused."""
        assert webapp_probe._address_refused(ipaddress.ip_address(address)) is False

    async def test_an_unmanaged_name_resolving_to_the_metadata_address_is_refused_by_id(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dials = _record_dials(monkeypatch)
        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("169.254.169.254"))
        runner = ProbeRunner(_paths(tmp_path), enabled=True)
        remote = [_remote("stranger", "stranger.corp.internal")]

        runner.schedule(_state(allowlist=ALLOWLIST), remote, GW)
        await _wait_until(lambda: runner.snapshot().refused)
        await runner.aclose()

        assert runner.snapshot().refused == {"r-stranger"}
        assert dials.connects == []

    @pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254"])
    async def test_an_ip_literal_in_a_refused_range_is_never_dialled(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, address: str
    ) -> None:
        dials = _record_dials(monkeypatch)
        host = f"[{address}]" if ":" in address else address
        runner = ProbeRunner(_paths(tmp_path), enabled=True)

        runner.schedule(_state([_managed("lit", f"{host}:443")]), [], GW)
        await _wait_until(lambda: runner.snapshot().refused)
        await runner.aclose()

        assert dials.connects == []
        assert dials.lookups == []

    async def test_one_refused_address_among_several_refuses_the_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A name that also resolves to a loopback address is not dialled at its public one."""
        dials = _record_dials(monkeypatch)
        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("10.0.0.7", "127.0.0.1"))
        runner = ProbeRunner(_paths(tmp_path), enabled=True)

        runner.schedule(_state([_managed("grafana", "grafana.corp.internal")]), [], GW)
        await _wait_until(lambda: runner.snapshot().refused)
        await runner.aclose()

        assert dials.connects == []

    @pytest.mark.usefixtures("loopback_allowed")
    async def test_the_checked_address_is_dialled_with_the_name_as_the_server_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pki = _make_pki(tmp_path, dns=("grafana.corp.internal",))
        async with _tls_server(pki) as server:
            monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(LOOPBACK))
            runner = ProbeRunner(_paths(tmp_path, {"corp": pki.ca_file}), enabled=True)
            state = _state([_managed("grafana", f"grafana.corp.internal:{server.port}")])

            await _run_batch(runner, state, [], {"grafana"})
            await runner.aclose()

        assert runner.results["grafana"].outcome == "ok"
        assert [s for s in server.sni if s] == ["grafana.corp.internal"]

    async def test_an_unresolvable_name_is_unreachable_with_its_error_type(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def failing(*_a: Any, **_k: Any) -> Any:
            raise socket.gaierror("no such host")

        monkeypatch.setattr(socket, "getaddrinfo", failing)
        runner = ProbeRunner(_paths(tmp_path), enabled=True)

        await _run_batch(
            runner, _state([_managed("grafana", "grafana.corp.internal")]), [], {"grafana"},
            grace=0.0,
        )
        await runner.aclose()

        assert runner.results["grafana"].outcome == "unreachable"
        assert runner.results["grafana"].error_type == "gaierror"

    async def test_resolution_runs_on_the_runners_own_pool_and_aclose_shuts_it_down(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        threads: list[str] = []

        def lookup(host: str, port: int) -> list[Any]:
            threads.append(threading.current_thread().name)
            return [ipaddress.ip_address("127.0.0.1")]

        monkeypatch.setattr(webapp_probe, "_lookup", lookup)
        runner = ProbeRunner(_paths(tmp_path), enabled=True)
        runner.schedule(_state([_managed("grafana", "grafana.corp.internal")]), [], GW)
        await _wait_until(lambda: threads)
        await runner.aclose()

        assert threads[0].startswith("gwops-probe-dns")
        assert runner._executor._max_workers == 4
        assert runner._executor._shutdown is True

    async def test_resolution_is_bounded_by_the_probe_timeout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        release = threading.Event()

        def slow(host: str, port: int) -> list[Any]:
            release.wait(5)
            return []

        monkeypatch.setattr(webapp_probe, "_lookup", slow)
        runner = ProbeRunner(_paths(tmp_path), enabled=True, timeout=0.3)
        started = time.monotonic()

        await _run_batch(
            runner, _state([_managed("grafana", "grafana.corp.internal")]), [], {"grafana"},
            grace=0.0,
        )
        release.set()
        await runner.aclose()

        assert time.monotonic() - started < 2.0
        assert runner.results["grafana"].outcome == "unreachable"


# --- the flag is read per schedule -------------------------------------------------------


@pytest.mark.usefixtures("loopback_allowed")
class TestFlagPerSchedule:
    async def test_the_state_flag_overrides_the_constructor_value_on_schedule(
        self, tmp_path: Path
    ) -> None:
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as server:
            runner = ProbeRunner(_paths(tmp_path, {"corp": pki.ca_file}), enabled=False)

            await _run_batch(runner, _state(_loopback_apps([server]), probe=True), [], {"app0"})
            await runner.aclose()

        assert runner.enabled is True
        assert runner.results["app0"].outcome == "ok"

    async def test_turning_the_flag_off_clears_results_and_stops_future_batches(
        self, tmp_path: Path
    ) -> None:
        pki = _make_pki(tmp_path, ips=(LOOPBACK,))
        async with _tls_server(pki) as server:
            runner = ProbeRunner(_paths(tmp_path, {"corp": pki.ca_file}), enabled=True)
            on = _state(_loopback_apps([server]), probe=True)
            off = _state(_loopback_apps([server]), probe=False)
            await _run_batch(runner, on, [], {"app0"})
            await _wait_until(lambda: runner._task is not None and runner._task.done())
            assert server.handshakes == 1

            runner.schedule(off, [], GW)
            runner.schedule(off, [], GW)
            await asyncio.sleep(0.3)

            assert runner.enabled is False
            assert runner.snapshot().results == {}
            assert server.handshakes == 1

            runner.schedule(on, [], GW)
            await _wait_until(lambda: "app0" in runner.results)
            await runner.aclose()

        assert server.handshakes == 2

    async def test_turning_the_flag_off_cancels_nothing_in_flight_and_discards_its_results(
        self, tmp_path: Path
    ) -> None:
        async with _hanging_server() as server:
            runner = ProbeRunner(_paths(tmp_path), enabled=True, timeout=0.6)
            runner.schedule(_state(_loopback_apps([server]), probe=True), [], GW)
            await _wait_until(lambda: server.connections == 1)
            task = runner._task

            runner.schedule(_state(_loopback_apps([server]), probe=False), [], GW)

            assert task is not None and not task.cancelled()
            await asyncio.wait_for(task, 5)
            await runner.aclose()

        assert runner.results == {}
