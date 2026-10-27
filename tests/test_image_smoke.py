"""Docker image smoke tests for the assembled gwops gateway image.

These are ``@pytest.mark.integration`` and skipped unless Docker is available, so they
never run in the unit suite (or on a host without Docker). Two scenarios,
both exercising the *real* built image (`make image` — the pinned gateway binary):

(a) **Fail-loud startup gate.** A minimal seed whose Kubernetes credential files are not
    mounted, and no ``TWINGATE_API_KEY``. The startup reconcile cannot materialize the
    creds, so the gateway is never started; with upstreams declared, ``bootstrap`` raises
    and PID 1 exits nonzero *fast*. The container logs must name what to fix (the missing
    credential file, and the un-synced tenant) rather than hanging or degrading silently.

(b) **Healthy boot.** A test-only image layer swaps the real gateway binary for
    ``tests/fakes/fake_gateway.py`` (so no live tenant/gateway is needed) and points the
    control plane at a tiny in-network stub Twingate GraphQL API (self-signed TLS, trusted
    via ``SSL_CERT_FILE``, reachable on the derived ``<network>.<host>`` hostname via a
    Docker network alias). With TG sync clean and the fake gateway staying up, the
    composite ``/healthz`` goes 200, and ``docker exec … python -m gwops.healthcheck``
    (the image's own HEALTHCHECK command) exits 0 within the start window. Also asserts
    the process runs as uid 10001 and the HEALTHCHECK is present in ``docker inspect``.

The stub only ever has to answer the handful of GraphQL operations one clean reconcile
issues (list → create resource → resolve remote network → register CAs → rebind), keyed
off the operation name in the query text — see ``_STUB_SERVER``.
"""

import json
import os
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parent.parent
_FAKE_GATEWAY = _REPO_ROOT / "tests" / "fakes" / "fake_gateway.py"

# Derived from the healthy seed below: TGClient targets https://<network>.<host>/…
_TG_NETWORK = "smoke"
_TG_HOST = "tg.test"
_TG_HOSTNAME = f"{_TG_NETWORK}.{_TG_HOST}"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return (
            subprocess.run(
                ["docker", "info"], capture_output=True, timeout=30
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


# Opt-in, like the Gatorcast contract smoke test: these build a real image and run
# containers, so they stay out of the default `make test` run (which would otherwise
# trigger a multi-minute Go build). Enable with GWOPS_SMOKE_IMAGE=1.
requires_docker = pytest.mark.skipif(
    not os.environ.get("GWOPS_SMOKE_IMAGE") or not _docker_available(),
    reason="set GWOPS_SMOKE_IMAGE=1 (with Docker running) to run image smoke tests",
)


def _docker(
    *args: str, check: bool = True, timeout: float = 300.0
) -> subprocess.CompletedProcess[str]:
    """Run a docker CLI command with BuildKit enabled, capturing text output."""
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        check=check,
        timeout=timeout,
        env={**os.environ, "DOCKER_BUILDKIT": "1"},
    )


# --- base image (built once) ---------------------------------------------------------

# Same pin as the Dockerfile (tests/test_pin.py asserts the match).
_DEFAULT_GATEWAY_DIGEST = "sha256:4993a7db015f7c2091d55f1c7a36c3e0c277137cb9937a46e9ced2c17456a6d1"

# lego pin (tag + image-index digest). Lives only in the Dockerfile and here;
# tests/test_pin.py asserts the two agree.
_LEGO_TAG = "v5.5.2"
_LEGO_DIGEST = "sha256:1944e8c36055beec47c7de6f15202b41128be75eea0ffa257f0c14d93c5155fd"

# Python base image pin (tag + image-index digest) for the stub-tenant container. Lives in the
# Dockerfile and here; tests/test_pin.py asserts the two agree.
_PYTHON_TAG = "3.12-slim"
_PYTHON_DIGEST = "sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f"


@pytest.fixture(scope="session")
def base_image() -> str:
    """Build the real image once per session.

    Wraps ``twingate/gateway:$GATEWAY_TAG@$GATEWAY_DIGEST`` (defaults: the Dockerfile
    pin). Set
    ``GWOPS_SMOKE_BASE_IMAGE`` to reuse a prebuilt image and skip the build.
    """
    prebuilt = os.environ.get("GWOPS_SMOKE_BASE_IMAGE")
    if prebuilt:
        return prebuilt
    tag = "gwops-smoke-base:test"
    _docker(
        "build",
        "--build-arg",
        f"GATEWAY_TAG={os.environ.get('GATEWAY_TAG', '2.0.0')}",
        "--build-arg",
        f"GATEWAY_DIGEST={os.environ.get('GATEWAY_DIGEST', _DEFAULT_GATEWAY_DIGEST)}",
        "--build-arg",
        f"LEGO_TAG={_LEGO_TAG}",
        "--build-arg",
        f"LEGO_DIGEST={_LEGO_DIGEST}",
        "-t",
        tag,
        str(_REPO_ROOT),
        timeout=900.0,
    )
    return tag


# --- per-test resource bookkeeping ---------------------------------------------------


@pytest.fixture
def cleanup() -> Iterator[dict[str, list[str]]]:
    """Track docker resources created by a test and force-remove them at teardown."""
    resources: dict[str, list[str]] = {"containers": [], "networks": [], "images": []}
    try:
        yield resources
    finally:
        for cid in resources["containers"]:
            _docker("rm", "-f", cid, check=False, timeout=60)
        for net in resources["networks"]:
            _docker("network", "rm", net, check=False, timeout=60)
        for img in resources["images"]:
            _docker("rmi", "-f", img, check=False, timeout=120)


# --- lego binary ---------------------------------------------------------------------


@requires_docker
def test_lego_binary_runs_as_uid_10001_on_read_only_rootfs(base_image: str) -> None:
    """The pinned lego binary executes as the non-root user with no writable rootfs."""
    run = _docker(
        "run",
        "--rm",
        "--user",
        "10001:10001",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--entrypoint",
        "lego",
        base_image,
        "--version",
        check=False,
        timeout=120,
    )
    output = run.stdout + run.stderr
    assert run.returncode == 0, f"lego --version exited {run.returncode}: {output!r}"
    assert _LEGO_TAG.removeprefix("v") in output, output


# --- scenario (a): fail-loud startup gate --------------------------------------------

_FAILLOUD_SEED = """\
twingate:
  network: acme
  host: twingate.com
  gateway_id: R2F0ZXdheTox
ca:
  x509:
    generate: true
  ssh:
    generate: true
k8s_clusters:
  - name: prod
    address: prod.k8s.internal
    port: 6443
    bearer_token_file: /config/k8s-creds/prod.token
    ca_file: /config/k8s-creds/prod-ca.crt
recording:
  enabled: false
admin_api:
  bind: 127.0.0.1
  port: 8081
"""


@requires_docker
def test_missing_creds_and_api_key_exit_fast_and_loud(
    base_image: str, tmp_path: Path, cleanup: dict[str, list[str]]
) -> None:
    """No creds mounted + no API key ⇒ container exits nonzero fast, logs what to fix."""
    seed = tmp_path / "seed.yaml"
    seed.write_text(_FAILLOUD_SEED, encoding="utf-8")

    name = f"gwops-smoke-fail-{uuid.uuid4().hex[:8]}"
    cleanup["containers"].append(name)

    start = time.monotonic()
    run = _docker(
        "run",
        "--name",
        name,
        "-v",
        f"{seed}:/config/seed.yaml:ro",
        base_image,
        check=False,
        timeout=120,
    )
    elapsed = time.monotonic() - start

    assert run.returncode != 0, f"expected nonzero exit; stdout={run.stdout!r}"
    assert elapsed < 90, f"startup gate took {elapsed:.1f}s; should fail fast"
    logs = _docker("logs", name, check=False).stdout + _docker("logs", name, check=False).stderr
    combined = run.stdout + run.stderr + logs
    # The actionable startup-gate error and the missing-key note both surface.
    assert "startup reconcile could not bring the gateway up" in combined, combined[-2000:]
    assert "credential file" in combined and "file not found" in combined, combined[-2000:]
    assert "TWINGATE_API_KEY is not set" in combined, combined[-2000:]


# --- scenario (b): healthy boot with a fake gateway + stub tenant --------------------

_HEALTHY_SEED = f"""\
twingate:
  network: {_TG_NETWORK}
  host: {_TG_HOST}
  gateway_id: R2F0ZXdheTox
ca:
  x509:
    generate: true
  ssh:
    generate: true
ssh_upstreams:
  - name: web-1
    address: web-1.internal
recording:
  enabled: false
admin_api:
  bind: 127.0.0.1
  port: 8081
"""

# stdlib-only HTTPS stub: answers the operations one clean reconcile issues, keyed off
# the GraphQL operation name embedded in the query text.
_STUB_SERVER = '''\
import json, ssl
from http.server import BaseHTTPRequestHandler, HTTPServer

def data_for(query):
    if "GatewayRemoteNetwork" in query:
        return {"gateway": {"remoteNetwork": {"id": "UmVtb3RlTmV0d29yazox"}}}
    if "ListResources" in query:
        return {"resources": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "edges": []}}
    if "CreateSSHResource" in query:
        return {"sshResourceCreate": {"ok": True, "error": None, "entity": {"id": "U1NIUmVzOjE="}}}
    if "CreateX509CA" in query:
        entity = {"id": "WDUwOTox"}
        return {"x509CertificateAuthorityCreate": {"ok": True, "error": None, "entity": entity}}
    if "CreateSSHCA" in query:
        entity = {"id": "U1NIQ0E6MQ=="}
        return {"sshCertificateAuthorityCreate": {"ok": True, "error": None, "entity": entity}}
    if "UpdateGateway" in query:
        return {"gatewayUpdate": {"ok": True, "error": None}}
    return {}

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        raw = json.dumps({"data": data_for(body.get("query", ""))}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass

server = HTTPServer(("0.0.0.0", 443), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
'''


def _write_stub_tls(cert_dir: Path, hostname: str) -> None:
    """Generate a CA + a server leaf (SAN=hostname, serverAuth) into `cert_dir`.

    The CA PEM is the trust anchor the gwops container loads via SSL_CERT_FILE; the
    server presents the leaf. Uses the project's own ``cryptography`` dependency.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gwops-smoke-ca")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    (cert_dir / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    (cert_dir / "server.crt").write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    (cert_dir / "server.key").write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (cert_dir / "stub.py").write_text(_STUB_SERVER, encoding="utf-8")


def _build_fake_image(base_image: str, tmp_path: Path) -> str:
    """Build a test image = base + the fake gateway binary + the healthy seed."""
    ctx = tmp_path / "fake-image"
    ctx.mkdir()
    shutil.copy(_FAKE_GATEWAY, ctx / "fake_gateway.py")
    (ctx / "seed.yaml").write_text(_HEALTHY_SEED, encoding="utf-8")
    (ctx / "Dockerfile").write_text(
        "FROM " + base_image + "\n"
        "USER root\n"
        "COPY fake_gateway.py /opt/fake/fake_gateway.py\n"
        "COPY seed.yaml /config/seed.yaml\n"
        # Swap the real binary for a shim that execs the fake under python.
        "RUN printf '#!/bin/sh\\nexec python /opt/fake/fake_gateway.py \"$@\"\\n' "
        "> /usr/local/bin/gateway && chmod 0755 /usr/local/bin/gateway\n"
        "USER gwops\n",
        encoding="utf-8",
    )
    tag = f"gwops-smoke-fake:{uuid.uuid4().hex[:8]}"
    _docker("build", "-t", tag, str(ctx), timeout=300)
    return tag


def _wait_stub_ready(container: str) -> None:
    """Block until the stub is accepting TLS connections inside its container."""
    probe = (
        "import socket,sys;"
        "s=socket.create_connection(('127.0.0.1',443),1);s.close()"
    )
    for _ in range(30):
        if _docker("exec", container, "python", "-c", probe, check=False).returncode == 0:
            return
        time.sleep(1)
    raise AssertionError("stub TG server did not come up on :443")


@requires_docker
def test_healthy_boot_reports_healthy_and_runs_nonroot(
    base_image: str, tmp_path: Path, cleanup: dict[str, list[str]]
) -> None:
    """Fake gateway + stub tenant ⇒ /healthz 200, uid 10001, HEALTHCHECK present."""
    certs = tmp_path / "certs"
    certs.mkdir()
    _write_stub_tls(certs, _TG_HOSTNAME)

    fake_image = _build_fake_image(base_image, tmp_path)
    cleanup["images"].append(fake_image)

    net = f"gwops-smoke-net-{uuid.uuid4().hex[:8]}"
    _docker("network", "create", net)
    cleanup["networks"].append(net)

    # Stub tenant: reachable at the derived <network>.<host> via a network alias.
    stub = f"gwops-smoke-stub-{uuid.uuid4().hex[:8]}"
    cleanup["containers"].append(stub)
    _docker(
        "run", "-d", "--name", stub,
        "--network", net, "--network-alias", _TG_HOSTNAME,
        "-v", f"{certs}:/certs:ro",
        f"python:{_PYTHON_TAG}@{_PYTHON_DIGEST}", "python", "/certs/stub.py",
    )
    _wait_stub_ready(stub)

    # gwops: dummy key (any value enables TG sync), CA trusted via SSL_CERT_FILE.
    app = f"gwops-smoke-app-{uuid.uuid4().hex[:8]}"
    cleanup["containers"].append(app)
    _docker(
        "run", "-d", "--name", app, "--network", net,
        "-e", "TWINGATE_API_KEY=smoke-dummy-key",
        "-e", "GWOPS_ADMIN_TOKEN=smoke-admin-token",
        "-e", "SSL_CERT_FILE=/certs/ca.pem",
        "-v", f"{certs}:/certs:ro",
        fake_image,
    )

    # Poll the image's own HEALTHCHECK command from inside the container.
    healthy = False
    last_logs = ""
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        running = _docker("inspect", "-f", "{{.State.Running}}", app, check=False)
        if running.stdout.strip() != "true":
            break  # crashed — stop early and surface logs
        rc = _docker("exec", app, "python", "-m", "gwops.healthcheck", check=False).returncode
        if rc == 0:
            healthy = True
            break
        time.sleep(2)

    last_logs = _docker("logs", app, check=False).stdout + _docker("logs", app, check=False).stderr
    assert healthy, f"/healthz never became healthy within 40s\n{last_logs[-3000:]}"

    # Runs as the non-root gwops user (uid 10001).
    uid = _docker("exec", app, "id", "-u").stdout.strip()
    assert uid == "10001", f"expected uid 10001, got {uid!r}"

    # HEALTHCHECK is present in the image metadata (docker inspect truthful).
    inspected = json.loads(_docker("inspect", fake_image).stdout)
    healthcheck = inspected[0]["Config"].get("Healthcheck")
    assert healthcheck is not None, "image has no HEALTHCHECK"
    assert healthcheck["Test"] == ["CMD", "python", "-m", "gwops.healthcheck"], healthcheck["Test"]
