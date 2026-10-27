#!/usr/bin/env python3
"""A fake lego (v5.5.2) for the AcmeRunner tests.

Stands in for the pinned ``lego`` binary that ``gwops.acme.runner`` spawns with the argv
``gwops.acme.lego.build_argv`` produces. Stdlib only, so an installed copy runs under any
``python3`` on PATH. POSIX only (it is exec'd through its shebang).

The runner never knows about the fake. All test control sits *beside the script*, because the
runner's child environment is an allowlist and drops any variable a test could set:

``fake_lego.control.json``
    Written by the test next to the installed copy; read on every invocation. One scenario,
    or ``{"sequence": [step, ...]}`` where invocation N (counted from 0, over every
    invocation recorded so far, rejected ones included) runs ``sequence[N]`` and the last
    step repeats. Top-level keys other than ``sequence`` are defaults for every step. A
    missing or malformed control file exits 99 with a ``FAKE-LEGO-CONTROL`` message.
``fake_lego.invocations.jsonl``
    Appended by the fake: a ``start`` record per invocation (argv, cwd, selected environment
    values, every environment *name*, never a token) written before anything else, and an
    ``exit`` record when the process finishes (absent when it was killed).

Scenarios (``"scenario"``):

``success``
    Needs ``crt`` (leaf plus chain PEM, as lego's bundle), optional ``issuer`` (issuer PEM)
    and ``key`` (PEM; ``null`` omits ``.key`` as lego does when it did not generate the key).
    Writes lego v5's layout under ``--path`` (31.0 findings) and exits 0.
``fail``
    ``"failure"`` is one of ``rate_limited``, ``dns_auth``, ``dns_propagation``,
    ``unauthorized``, ``acme_unreachable``, ``dns_zone``, ``config``, ``internal``,
    ``acme_problem`` (an ACME problem document, ``"variant"`` names it: ``invalidContact``,
    ``rejectedIdentifier``, ``malformed``, ``accountDoesNotExist``, ``userActionRequired``,
    ``badNonce``, ``serverInternal``; ``"wrapped": true`` nests it in ``invalid
    authorization:``), ``cloudflare_transient`` (``"variant"``: ``rate`` for 429, ``5xx``,
    ``network``), ``custom`` (verbatim ``"error"`` text). ``"variant"`` picks a sub-shape (see
    ``_FAILURES``), ``"status"`` (dns_auth: 400, 401 or 403; cloudflare_transient ``5xx``: the
    code), ``"retry_after"`` (rate_limited: the UTC time in the CA text, ``null`` for none),
    ``"exit_code"`` (default 1). Exit 1, the last line is the ``Error`` log record, everything
    on stdout.
``rate_limit_hang``
    Prints the WARN ``retry: ... rateLimited`` line, then sleeps (lego sleeping out Retry-After).
``hang``
    Prints progress up to ``dns01: waiting for record propagation.``, then sleeps.
``signal``
    Prints the first progress record, then kills itself with ``"signal_number"`` (default 9):
    no exit record, the parent sees a negative return code.
``output``
    Prints each of ``"lines"`` verbatim (no JSON record, no ``Error`` record) and exits with
    ``"exit_code"`` (default 1). For tests of output with no final error chain.

Hangs sleep ``hang_seconds`` (default 3600); ``ignore_sigterm`` makes them survive SIGTERM;
``spawn_child`` starts a sleeping grandchild in the same process group first and writes its pid to
``fake_lego.child.pid`` beside the script (for tests that the whole group is stopped).
Any scenario also honours ``delay`` (seconds before the outcome) and ``noise_lines`` /
``noise_line_bytes`` (filler INFO lines first, for output-bound tests).

Renewal (31.0 findings 7 and 8): when ``certificates/<name>.json`` exists the run is a renewal.
It exits 0 and writes nothing (``Skip renewal``) unless ``--renew-force``, or ``renewal_due`` is
true in the control, or ``--force-cert-domains`` is set and the stored domains differ.

Contract checks (exit 97, ``FAKE-LEGO-VIOLATION[tag]`` lines, never any token text), applied after
flag parsing and before any scenario: ``CF_DNS_API_TOKEN_FILE`` set and readable (and
``CF_ZONE_API_TOKEN_FILE`` if set), the token content in no argv element and no environment value,
no direct ``CF_*_TOKEN`` / ``CLOUDFLARE_*_TOKEN`` variable, no other ``CF_*``, ``CLOUDFLARE_*`` or
``LEGO_*`` variable, no ``GODEBUG``, ``--path`` present, and ``--path`` ending in the directory's
host label (``<host>`` or ``<host>_<port>``, lowercase, as ``GwopsSettings.lego_storage_dir``
derives it from ``--server``), so staging and production never share lego files.

Flags: a strict whitelist of what gwops emits, not all of lego's. Value flags accept both
``--flag value`` and ``--flag=value`` (gwops uses the equals form for ``--cert.name`` and
``--domains``). Global flags (``--log.format``, ``--log.level``) must precede ``run``; the rest
must follow it. An unknown flag exits 1 with
``Incorrect Usage: flag provided but not defined: -<name>`` on stderr and usage on stdout.
"""

import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn
from urllib.parse import urlsplit

HERE = Path(os.path.realpath(__file__))
CONTROL_PATH = HERE.with_name("fake_lego.control.json")
INVOCATIONS_PATH = HERE.with_name("fake_lego.invocations.jsonl")
CHILD_PID_PATH = HERE.with_name("fake_lego.child.pid")

VIOLATION_EXIT = 97
CONTROL_EXIT = 99

ACCOUNT_KEY_MARKER = "FAKE-LEGO-ACCOUNT-KEY-DO-NOT-LOG"
DEFAULT_RETRY_AFTER = "2026-10-21 10:00:00 UTC"
TXT_VALUE = "ZmFrZS10eHQtdmFsdWUtMDEyMzQ1Njc4OWFiY2RlZmc"
NOT_DUE_TEXT = (
    "Skip renewal: The certificate expires at 2027-01-01 00:00:00 +0000 UTC, "
    "the number of days remaining (70.00) is greater than the renewal period (30.00)"
)

# name -> takes a value
ROOT_FLAGS = {"log.format": True, "log.level": True}
RUN_FLAGS = {
    "path": True,
    "server": True,
    "email": True,
    "accept-tos": False,
    "dns": True,
    "dns.propagation.disable-ans": False,
    "dns.resolvers": True,
    "key-type": True,
    "cert.name": True,
    "domains": True,
    "force-cert-domains": False,
    "no-random-sleep": False,
    "renew-force": False,
}
RUN_SHORT = {"a": "accept-tos", "m": "email", "s": "server", "d": "domains", "k": "key-type",
             "c": "cert.name"}  # fmt: skip

# Environment values recorded verbatim (paths and proxy settings, never secrets).
RECORDED_ENV = (
    "CF_DNS_API_TOKEN_FILE",
    "CF_ZONE_API_TOKEN_FILE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)
TOKEN_FILE_VARS = ("CF_DNS_API_TOKEN_FILE", "CF_ZONE_API_TOKEN_FILE")
DIRECT_TOKEN_VARS = (
    "CF_DNS_API_TOKEN",
    "CF_ZONE_API_TOKEN",
    "CLOUDFLARE_DNS_API_TOKEN",
    "CLOUDFLARE_ZONE_API_TOKEN",
)
FORBIDDEN_ENV_PREFIXES = ("CF_", "CLOUDFLARE_", "LEGO_")
FORBIDDEN_ENV_NAMES = ("GODEBUG",)

USAGE = "NAME:\n   lego run - Get or renew a certificate\n\nUSAGE:\n   lego run [options]\n"

_log_format = "colored"


class Exit(Exception):
    """Unwinds to :func:`main` with the process exit code."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


class UsageError(Exception):
    """A flag-parse failure; lego prints ``Incorrect Usage: <message>`` on stderr."""


# --- output ---------------------------------------------------------------------------


def emit(level: str, msg: str, **fields: object) -> None:
    """One lego log record on stdout: JSON with ``--log.format json``, else slog text."""
    stamp = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if _log_format == "json":
        line = json.dumps({"time": stamp, "level": level, "msg": msg, **fields})
    else:
        extra = "".join(f" {key}={json.dumps(value)}" for key, value in fields.items())
        line = f"time={stamp} level={level} msg={json.dumps(msg)}{extra}"
    print(line, flush=True)


def fatal(chain: str, code: int = 1) -> NoReturn:
    """lego's ``log.Fatal``: the ``Error`` record, then exit."""
    emit("ERROR", "Error", error=chain)
    raise Exit(code)


def violations(problems: list[tuple[str, str]]) -> NoReturn:
    for tag, text in problems:
        print(f"FAKE-LEGO-VIOLATION[{tag}]: {text}", flush=True)
    raise Exit(VIOLATION_EXIT)


def control_error(text: str) -> NoReturn:
    print(f"FAKE-LEGO-CONTROL: {text}", flush=True)
    raise Exit(CONTROL_EXIT)


# --- invocation log -------------------------------------------------------------------


def _append(record: dict[str, object]) -> None:
    fd = os.open(INVOCATIONS_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(record) + "\n").encode())
    finally:
        os.close(fd)


def record_start(run_id: str) -> int:
    """Append the start record; return how many invocations were recorded before this one."""
    prior = 0
    if INVOCATIONS_PATH.exists():
        for line in INVOCATIONS_PATH.read_text().splitlines():
            if line.strip() and json.loads(line).get("event") == "start":
                prior += 1
    _append(
        {
            "event": "start",
            "id": run_id,
            "pid": os.getpid(),
            "argv": sys.argv,
            "cwd": os.getcwd(),
            "env": {key: os.environ[key] for key in RECORDED_ENV if key in os.environ},
            "env_keys": sorted(os.environ),
            "started_at": time.time(),
        }
    )
    return prior


def record_exit(run_id: str, code: int) -> None:
    _append({"event": "exit", "id": run_id, "code": code, "ended_at": time.time()})


# --- argv -----------------------------------------------------------------------------


def parse_flags(
    tokens: list[str],
    table: dict[str, bool],
    short: dict[str, str],
    *,
    stop_at_positional: bool,
) -> tuple[dict[str, list[str]], list[str]]:
    """Parse `tokens` against `table`; return the flag values and the unparsed rest."""
    values: dict[str, list[str]] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("-") or token == "-":
            if stop_at_positional:
                return values, tokens[index:]
            raise UsageError(f"unexpected argument: {token}")
        body = token[2:] if token.startswith("--") else token[1:]
        name, has_inline, inline = body.partition("=")
        if not token.startswith("--"):
            name = short.get(name, name)
        if name in ("help", "h"):
            print(USAGE, flush=True)
            raise Exit(0)
        if name not in table:
            raise UsageError(f"flag provided but not defined: -{name}")
        if table[name]:
            if has_inline:
                value = inline
            elif index + 1 < len(tokens):
                index += 1
                value = tokens[index]
            else:
                raise UsageError(f"flag needs an argument: -{name}")
            values.setdefault(name, []).append(value)
        else:
            values[name] = [inline if has_inline else "true"]
        index += 1
    return values, []


def last(flags: dict[str, list[str]], name: str, default: str = "") -> str:
    return flags[name][-1] if name in flags else default


class Run:
    """The parsed ``run`` invocation."""

    def __init__(self, flags: dict[str, list[str]]) -> None:
        self.flags = flags
        self.path = Path(last(flags, "path", ".lego"))
        self.server = last(flags, "server")
        self.email = last(flags, "email")
        self.domains = [d for v in flags.get("domains", []) for d in v.split(",") if d]
        explicit = last(flags, "cert.name")
        self.name = explicit or sanitize(self.domains[0] if self.domains else "")
        self.renew_force = "renew-force" in flags
        self.force_domains = "force-cert-domains" in flags

    @property
    def certs(self) -> Path:
        return self.path / "certificates"

    @property
    def stored(self) -> Path:
        return self.certs / f"{self.name}.json"

    @property
    def first_issuance(self) -> bool:
        return not self.stored.exists()

    @property
    def account_dir(self) -> Path:
        host = urlsplit(self.server).netloc or self.server
        host = host.replace(":", "_").replace("/", "_")
        return self.path / "accounts" / host / (self.email or "noemail@example.com")

    @property
    def storage_label(self) -> str:
        """The directory name ``GwopsSettings.lego_storage_dir`` gives this ``--server``."""
        parts = urlsplit(self.server)
        host = (parts.hostname or "").lower()
        try:
            port = parts.port
        except ValueError:
            port = None
        label = f"{host}_{port}" if port is not None else host
        return re.sub(r"[^a-z0-9._-]", "_", label).strip(".") or "unknown"


def sanitize(name: str) -> str:
    """lego's ``SanitizedName``: a wildcard becomes ``_.example.com``."""
    return "".join("_" if ch in '*:/\\?"<>|' else ch for ch in name)


# --- contract checks ------------------------------------------------------------------


def _read_token(var: str, problems: list[tuple[str, str]]) -> str | None:
    path = os.environ.get(var)
    if path is None:
        if var == TOKEN_FILE_VARS[0]:
            problems.append(("token_file_missing", f"{var} is not set"))
        return None
    try:
        content = Path(path).read_text().rstrip("\r\n")
    except OSError as exc:
        problems.append(("token_file_unreadable", f"{var}={path}: {type(exc).__name__}"))
        return None
    if not content:
        problems.append(("token_file_empty", f"{var}={path} is empty"))
        return None
    return content


def check_contract(run: Run) -> None:
    """Exit 97 when gwops broke the token, environment or ``--path`` contract."""
    problems: list[tuple[str, str]] = []
    if "path" not in run.flags:
        problems.append(("path_missing", "--path was not passed (lego would write ./.lego)"))
    elif run.path.name != run.storage_label:
        problems.append(
            (
                "path_not_host_dir",
                f"--path ends in {run.path.name!r}; expected the directory host label "
                f"{run.storage_label!r} (a per-directory subdirectory of lego's base path)",
            )
        )
    tokens = [t for t in (_read_token(v, problems) for v in TOKEN_FILE_VARS) if t is not None]
    present = [v for v in DIRECT_TOKEN_VARS if v in os.environ]
    if present:
        problems.append(("token_in_env", f"token passed as a variable, not a file: {present}"))
    for token in tokens:
        for position, arg in enumerate(sys.argv):
            leaked = token in arg if len(token) >= 8 else token == arg
            if leaked:
                problems.append(("token_in_argv", f"token content in argv[{position}]"))
        for name, value in os.environ.items():
            if name not in TOKEN_FILE_VARS and token in value:
                problems.append(("token_in_env", f"token content in the value of {name}"))
    stray = sorted(
        name
        for name in os.environ
        if (
            name.startswith(FORBIDDEN_ENV_PREFIXES)
            and name not in TOKEN_FILE_VARS
            and name not in DIRECT_TOKEN_VARS
        )
        or name in FORBIDDEN_ENV_NAMES
    )
    if stray:
        problems.append(("env_name_forbidden", f"variables lego must not inherit: {stray}"))
    if problems:
        violations(problems)


# --- control --------------------------------------------------------------------------


def load_control(prior: int) -> dict[str, object]:
    try:
        control = json.loads(CONTROL_PATH.read_text())
    except (OSError, ValueError) as exc:
        control_error(f"cannot read {CONTROL_PATH}: {type(exc).__name__}")
    if not isinstance(control, dict):
        control_error("control file must hold a JSON object")
    steps = control.pop("sequence", None)
    if steps is None:
        return control
    if not isinstance(steps, list) or not steps:
        control_error("'sequence' must be a non-empty list")
    return {**control, **steps[min(prior, len(steps) - 1)]}


# --- scenarios ------------------------------------------------------------------------


def base_name(domain: str) -> str:
    return domain.removeprefix("*.")


def zone_of(domain: str) -> str:
    return ".".join(base_name(domain).split(".")[-2:])


def chain_prefix(run: Run) -> str:
    if run.first_issuance:
        return "obtain certificate: "
    return f'renew certificate: could not obtain the certificate for "{run.name}": '


def per_domain(run: Run, cause: Callable[[str], str]) -> str:
    problems = " ".join(f"[{d}: {cause(d)}]" for d in run.domains)
    return f"{chain_prefix(run)}resolver: one or more domains had a problem: {problems}"


def api_base(run: Run) -> str:
    """The ACME directory URL without its last path segment."""
    return run.server.rsplit("/", 1)[0]


def _rate_limited_text(run: Run, ctl: dict[str, object]) -> str:
    retry = ctl.get("retry_after", DEFAULT_RETRY_AFTER)  # an explicit null omits the clause
    clause = f", retry after {retry}" if retry else ""
    detail = (
        "too many certificates (5) already issued for this exact set of identifiers "
        f"in the last 168h0m0s{clause}: "
        "see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers"
    )
    return (
        f"acme: error: 429 :: POST :: {api_base(run)}/acme/new-order :: "
        f"urn:ietf:params:acme:error:rateLimited :: {detail}"
    )


def _rate_limited(run: Run, ctl: dict[str, object]) -> str:
    url = f"{api_base(run)}/acme/new-order"
    return (
        f"{chain_prefix(run)}POST {url} giving up after 6 attempt(s): "
        f"{_rate_limited_text(run, ctl)}"
    )


def warn_rate_limited(run: Run, ctl: dict[str, object]) -> None:
    emit("WARN", f"retry: {_rate_limited_text(run, ctl)}")


def stage_lines(run: Run, depth: int) -> None:
    """Progress records up to `depth` (1 obtain, 2 solver chosen, 3 propagation wait)."""
    shown = {1: 1, 2: 3, 3: 4}[depth]
    for domain in run.domains:
        steps = [
            f"[{domain}] acme: Obtaining bundled SAN certificate",
            f"[{domain}] acme: use dns-01 solver",
            f"[{domain}] acme: Preparing to solve DNS-01",
            f"[{domain}] acme: Trying to solve DNS-01",
        ]
        for line in steps[:shown]:
            emit("INFO", line)
    if depth >= 3:
        emit("INFO", "dns01: waiting for record propagation.")


def _dns_auth(run: Run, ctl: dict[str, object]) -> str:
    status = int(str(ctl.get("status", 403)))
    code, message = (9109, "Invalid access token")
    if status == 401:
        code, message = 10000, "Authentication error"
    elif status == 400:
        code, message = 6003, "Invalid request headers"
    variant = ctl.get("variant", "zone_lookup")

    def cause(domain: str) -> str:
        tail = f"[status code {status}] {code}: {message}"
        if variant == "create_record":
            return f"cloudflare: failed to create TXT record: {tail}"
        return f"cloudflare: failed to find zone {zone_of(domain)}: {tail}"

    return per_domain(run, cause)


def _dns_propagation(run: Run, ctl: dict[str, object]) -> str:
    variant = ctl.get("variant", "recursive")

    def cause(domain: str) -> str:
        fqdn = f"_acme-challenge.{base_name(domain)}."
        expected = f"did not return the expected TXT record [fqdn: {fqdn}, value: {TXT_VALUE}]"
        authoritative = "authoritative nameservers: NS ns1.example.net.:53"
        if variant == "authoritative":
            tail = f"{authoritative} {expected}: "
        elif variant == "rcode":
            tail = f"{authoritative} returned NXDOMAIN for {fqdn}"
        else:
            tail = f"recursive nameservers: NS 127.0.0.11:53 {expected}: "
        return f"dns01: time limit exceeded: last error: {tail}"

    return per_domain(run, cause)


def _unauthorized(run: Run, ctl: dict[str, object]) -> str:
    variant = ctl.get("variant", "unauthorized")
    lead = "invalid challenge" if variant == "invalid_challenge" else "invalid authorization"

    def cause(domain: str) -> str:
        fqdn = f"_acme-challenge.{base_name(domain)}"
        urn = "urn:ietf:params:acme:error"
        if variant == "dns":
            problem = f"{urn}:dns :: DNS problem: NXDOMAIN looking up TXT for {fqdn}"
        elif variant == "caa":
            problem = f"{urn}:caa :: CAA record for {base_name(domain)} prevents issuance"
        elif variant == "connection":
            problem = f"{urn}:connection :: Fetching {fqdn}: Timeout during connect"
        else:
            problem = f'{urn}:unauthorized :: Incorrect TXT record "{TXT_VALUE}" found at {fqdn}'
        return f"{lead}: acme: error: 403 :: {problem}"

    return per_domain(run, cause)


def _acme_unreachable(run: Run, ctl: dict[str, object]) -> str:
    variant = ctl.get("variant", "refused")
    url = run.server
    if variant == "5xx":
        why = f"GET {url} giving up after 6 attempt(s): unexpected HTTP status 503"
    elif variant == "tls":
        why = (
            f'Get "{url}": tls: failed to verify certificate: '
            "x509: certificate signed by unknown authority"
        )
    else:
        why = (
            f'Get "{url}": GET {url} giving up after 6 attempt(s): '
            f'Get "{url}": dial tcp 127.0.0.1:1: connect: connection refused'
        )
    return (
        f"registration: get directory at '{url}': unable to communicate with the API server: {why}"
    )


def _dns_zone(run: Run, ctl: dict[str, object]) -> str:
    variant = ctl.get("variant", "soa")

    def cause(domain: str) -> str:
        if variant == "token":
            return f"cloudflare: failed to find zone {zone_of(domain)}: zone could not be found"
        return f'cloudflare: could not find zone for domain "{base_name(domain)}"'

    return per_domain(run, cause)


def _cloudflare_transient(run: Run, ctl: dict[str, object]) -> str:
    """Cloudflare answered 429 or 5xx, or api.cloudflare.com could not be reached."""
    variant = ctl.get("variant", "rate")

    def cause(domain: str) -> str:
        head = f"cloudflare: failed to find zone {zone_of(domain)}: "
        if variant == "network":
            return (
                f'{head}Get "https://api.cloudflare.com/client/v4/zones?name={zone_of(domain)}": '
                "dial tcp: lookup api.cloudflare.com: no such host"
            )
        if variant == "5xx":
            status = int(str(ctl.get("status", 503)))
            return f"{head}[status code {status}] 0: upstream unavailable"
        return f"{head}[status code 429] 10000: Too many requests"

    return per_domain(run, cause)


_PROBLEMS: dict[str, tuple[int, str, str]] = {
    # variant -> (HTTP status, path of the request, CA detail)
    "invalidContact": (400, "new-acct", "Error validating contact(s) :: unable to parse email"),
    "rejectedIdentifier": (400, "new-order", "Invalid identifiers requested :: forbidden name"),
    "malformed": (400, "new-order", "JWS verification error"),
    "accountDoesNotExist": (400, "new-order", "Account does not exist"),
    "userActionRequired": (403, "new-order", "Terms of service have changed"),
    "badNonce": (400, "new-order", "JWS has an invalid anti-replay nonce"),
    "serverInternal": (500, "new-order", "Internal error"),
}


def _acme_problem(run: Run, ctl: dict[str, object]) -> str:
    """An ACME problem document, optionally nested in ``invalid authorization:``."""
    variant = str(ctl.get("variant", "malformed"))
    status, path, detail = _PROBLEMS[variant]
    problem = (
        f"acme: error: {status} :: POST :: {api_base(run)}/acme/{path} :: "
        f"urn:ietf:params:acme:error:{variant} :: {detail}"
    )
    if ctl.get("wrapped"):
        return per_domain(run, lambda _domain: f"invalid authorization: {problem}")
    return f"registration: {problem}" if path == "new-acct" else f"{chain_prefix(run)}{problem}"


def _config(run: Run, ctl: dict[str, object]) -> str:
    return {
        "no_domains": "please specify '--cert.name' and/or '--domains'",
        "tos": "You did not accept the TOS. Unable to proceed.",
        "console": "Could not read from the console",
        "readonly": f"mkdir {run.path}: read-only file system",
        "credentials": (
            "cloudflare: some credentials information are missing: CLOUDFLARE_DNS_API_TOKEN"
        ),
    }[str(ctl.get("variant", "credentials"))]


def _internal(run: Run, ctl: dict[str, object]) -> str:
    variant = ctl.get("variant", "save")
    crt = run.certs / f"{run.name}.crt"
    if variant == "read":
        return f"error while reading the certificate: open {crt}: permission denied"
    if variant == "order":
        return (
            f"{chain_prefix(run)}invalid order: acme: error: 403 :: "
            'urn:ietf:params:acme:error:orderNotReady :: Order\'s status ("invalid") was not ready'
        )
    return f"could not save the resource: open {crt}: no space left on device"


# failure -> (stage depth printed first or 0, builds the final error chain, registers an account)
_FAILURES: dict[str, tuple[int, Callable[[Run, dict[str, object]], str], bool]] = {
    "rate_limited": (1, _rate_limited, True),
    "dns_auth": (2, _dns_auth, True),
    "dns_propagation": (3, _dns_propagation, True),
    "unauthorized": (3, _unauthorized, True),
    "acme_unreachable": (0, _acme_unreachable, False),
    "dns_zone": (2, _dns_zone, True),
    "config": (0, _config, False),
    "internal": (1, _internal, True),
    "acme_problem": (0, _acme_problem, False),
    "cloudflare_transient": (2, _cloudflare_transient, True),
}


def ensure_account(run: Run) -> None:
    """Register an account the way lego does on first use: ``account.json`` and its key."""
    directory = run.account_dir
    if (directory / "account.json").exists():
        return
    emit("INFO", f"acme: Registering account for {run.email or 'noemail@example.com'}")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    account = {
        "email": run.email,
        "registration": {
            "body": {"status": "valid", "contact": [f"mailto:{run.email}"] if run.email else []},
            "uri": f"{api_base(run)}/acme/acct/1234567890",
        },
    }
    write_private(directory / "account.json", json.dumps(account, indent=2))
    key = f"-----BEGIN EC PRIVATE KEY-----\n{ACCOUNT_KEY_MARKER}\n-----END EC PRIVATE KEY-----\n"
    write_private(directory / f"{directory.name}.key", key)


def write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode())
    finally:
        os.close(fd)
    emit("INFO", "Writing file.", filepath=str(path))


def run_success(run: Run, ctl: dict[str, object]) -> None:
    crt = ctl.get("crt")
    if not isinstance(crt, str) or not crt:
        control_error("success needs 'crt' (leaf plus chain PEM)")
    ensure_account(run)
    stage_lines(run, 3)
    for domain in run.domains:
        emit("INFO", f"[{domain}] The server validated our request")
    emit("INFO", f"[{run.name}] Server responded with a certificate.")
    run.certs.mkdir(mode=0o700, parents=True, exist_ok=True)
    stem = run.certs / run.name
    domains = run.domains if (run.first_issuance or run.force_domains) else stored_domains(run)
    write_private(Path(f"{stem}.crt"), str(crt))
    issuer = ctl.get("issuer")
    if isinstance(issuer, str):
        write_private(Path(f"{stem}.issuer.crt"), issuer)
    key = ctl.get("key", "")
    if isinstance(key, str) and key:
        write_private(Path(f"{stem}.key"), key)
    serial = uuid.uuid4().hex[:12]
    resource = {
        "id": run.name,
        "domains": domains,
        "keyType": last(run.flags, "key-type", "EC256"),
        "certUrl": f"{api_base(run)}/acme/cert/{serial}",
        "certStableUrl": f"{api_base(run)}/acme/cert/{serial}",
        "profile": "",
        "origin": "fake_lego",
    }
    write_private(Path(f"{stem}.json"), json.dumps(resource, indent=2))


def stored_domains(run: Run) -> list[str]:
    try:
        value = json.loads(run.stored.read_text()).get("domains", [])
    except (OSError, ValueError):
        return run.domains
    return [str(d) for d in value]


def run_fail(run: Run, ctl: dict[str, object]) -> None:
    failure = str(ctl.get("failure", ""))
    if failure == "custom":
        error = ctl.get("error")
        if not isinstance(error, str):
            control_error("failure 'custom' needs 'error'")
        ensure_account(run)
        fatal(str(error), int(str(ctl.get("exit_code", 1))))
    if failure not in _FAILURES:
        control_error(f"unknown failure class {failure!r}")
    depth, build, registers = _FAILURES[failure]
    if registers:
        ensure_account(run)
    if depth:
        stage_lines(run, depth)
    if failure == "rate_limited":
        warn_rate_limited(run, ctl)
    fatal(build(run, ctl), int(str(ctl.get("exit_code", 1))))


def start_child() -> None:
    """A grandchild in lego's process group that sleeps; its pid goes to ``CHILD_PID_PATH``."""
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(300)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    CHILD_PID_PATH.write_text(str(child.pid))


def run_hang(run: Run, ctl: dict[str, object], *, rate_limited: bool) -> None:
    ensure_account(run)
    if ctl.get("spawn_child"):
        start_child()
    stage_lines(run, 1 if rate_limited else 3)
    if rate_limited:
        warn_rate_limited(run, ctl)
    sys.stdout.flush()
    if ctl.get("ignore_sigterm"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(float(str(ctl.get("hang_seconds", 3600))))
    fatal("fake lego hang elapsed")


def run_signal(run: Run, ctl: dict[str, object]) -> None:
    """Die from a signal after the first progress record (no exit record, no exit code)."""
    ensure_account(run)
    stage_lines(run, 1)
    sys.stdout.flush()
    os.kill(os.getpid(), int(str(ctl.get("signal_number", signal.SIGKILL))))
    time.sleep(30)  # only reached if the signal is ignored
    fatal("fake lego signal was ignored")


def run_output(ctl: dict[str, object]) -> None:
    """Print raw lines (no JSON, no Error record) and exit with ``exit_code``."""
    lines = ctl.get("lines", [])
    if not isinstance(lines, list):
        control_error("'lines' must be a list of strings")
    for line in lines:
        print(str(line), flush=True)
    raise Exit(int(str(ctl.get("exit_code", 1))))


def execute(argv: list[str], prior: int) -> int:
    global _log_format
    try:
        root, rest = parse_flags(argv, ROOT_FLAGS, {}, stop_at_positional=True)
        _log_format = last(root, "log.format", "colored")
        if not rest:
            print(USAGE, flush=True)
            return 0
        if rest[0] != "run":
            print(f"No help topic for '{rest[0]}'", flush=True)
            return 1
        flags, _ = parse_flags(rest[1:], RUN_FLAGS, RUN_SHORT, stop_at_positional=False)
    except UsageError as exc:
        print(f"Incorrect Usage: {exc}", file=sys.stderr, flush=True)
        print(USAGE, flush=True)
        return 1
    run = Run(flags)
    check_contract(run)
    if not run.domains and "cert.name" not in flags:
        fatal("please specify '--cert.name' and/or '--domains'")
    if last(flags, "dns") != "cloudflare":
        fatal(f"unrecognized DNS provider: {last(flags, 'dns')}")
    ctl = load_control(prior)
    noise(ctl)
    time.sleep(float(str(ctl.get("delay", 0))))
    if not run.first_issuance and not renewal_due(run, ctl):
        emit("INFO", NOT_DUE_TEXT)
        return 0
    scenario = ctl.get("scenario")
    if scenario == "success":
        run_success(run, ctl)
    elif scenario == "fail":
        run_fail(run, ctl)
    elif scenario in ("hang", "rate_limit_hang"):
        run_hang(run, ctl, rate_limited=scenario == "rate_limit_hang")
    elif scenario == "signal":
        run_signal(run, ctl)
    elif scenario == "output":
        run_output(ctl)
    else:
        control_error(f"unknown scenario {scenario!r}")
    return 0


def renewal_due(run: Run, ctl: dict[str, object]) -> bool:
    if run.renew_force or ctl.get("renewal_due"):
        return True
    return run.force_domains and sorted(stored_domains(run)) != sorted(run.domains)


def noise(ctl: dict[str, object]) -> None:
    width = int(str(ctl.get("noise_line_bytes", 120)))
    for index in range(int(str(ctl.get("noise_lines", 0)))):
        emit("INFO", f"filler {index} " + "x" * width)


def main() -> None:
    run_id = uuid.uuid4().hex
    prior = record_start(run_id)
    try:
        code = execute(sys.argv[1:], prior)
    except Exit as stop:
        code = stop.code
    sys.stdout.flush()
    sys.stderr.flush()
    record_exit(run_id, code)
    sys.exit(code)


if __name__ == "__main__":
    main()
