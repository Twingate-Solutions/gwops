"""Test-side control of the fake lego (``tests/fakes/fake_lego.py``).

The runner under test never knows about the fake: its child environment is an allowlist, so all
control is a JSON file *beside the installed script* (see the fake's docstring). This module
installs the copy, writes that file, and reads the invocation log the fake appends.

Typical use, through the fixtures in ``tests/acme/conftest.py``::

    fake_lego.succeed()                                  # a chain from rsa_hierarchy()
    fake_lego.fail("rate_limited", retry_after=None)
    fake_lego.configure(failure("dns_auth"), success())  # first run fails, then succeeds
    assert fake_lego.invocations()[0].value("--cert.name") == "wildcard"
"""

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests.fakes.fake_lego import ACCOUNT_KEY_MARKER, CONTROL_EXIT, VIOLATION_EXIT
from tests.public_chain_support import Issued, pem_of, rsa_hierarchy
from tests.public_tls_support import ZONE

__all__ = [
    "ACCOUNT_KEY_MARKER",
    "CONTROL_EXIT",
    "TOKEN_SENTINEL",
    "VIOLATION_EXIT",
    "FakeLego",
    "Invocation",
    "TokenFile",
    "failure",
    "hang",
    "install_fake_lego",
    "output",
    "posix_only",
    "rate_limit_hang",
    "run_lego",
    "signal_death",
    "success",
    "write_token_file",
]

FAKE_SOURCE = Path(__file__).resolve().parents[1] / "fakes" / "fake_lego.py"

TOKEN_SENTINEL = "cfut_SENTINEL_0f1e2d3c4b5a69788796a5b4c3d2e1f0"
"""The DNS token content in every test. It must appear nowhere but the token file."""

# Same condition and wording style as the repo's other POSIX-only tests.
posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="requires a POSIX executable script (shebang)"
)

type Step = dict[str, Any]


# --- scenario steps ---------------------------------------------------------------------


def success(
    issued: Issued | None = None,
    *,
    names: tuple[str, ...] | None = None,
    key: bool = True,
    **extra: Any,
) -> Step:
    """A ``success`` step writing `issued` (default: a leaf from :func:`rsa_hierarchy`).

    ``.crt`` is the leaf plus the served intermediates (lego's bundle), ``.issuer.crt`` the
    first intermediate. Pass a leaf from another hierarchy (or built with a bad profile) to
    make gwops' public validator refuse the output. ``key=False`` omits ``.key``.
    """
    leaf = issued if issued is not None else rsa_hierarchy().issue(names or (f"*.{ZONE}",))
    step: Step = {
        "scenario": "success",
        "crt": leaf.cert_pem.decode(),
        "key": leaf.key_pem.decode() if key else None,
        **extra,
    }
    if leaf.intermediates:
        step["issuer"] = pem_of(leaf.intermediates[0]).decode()
    return step


def failure(kind: str, **options: Any) -> Step:
    """A ``fail`` step: `kind` is a failure class of the fake, `options` its knobs."""
    return {"scenario": "fail", "failure": kind, **options}


def hang(seconds: float = 3600.0, **options: Any) -> Step:
    """Progress up to ``dns01: waiting for record propagation.``, then sleep."""
    return {"scenario": "hang", "hang_seconds": seconds, **options}


def rate_limit_hang(seconds: float = 3600.0, **options: Any) -> Step:
    """The WARN ``retry: ... rateLimited`` line, then sleep (lego sleeping out Retry-After)."""
    return {"scenario": "rate_limit_hang", "hang_seconds": seconds, **options}


def signal_death(signal_number: int = 9, **options: Any) -> Step:
    """Print the first progress record, then die from `signal_number` (no exit code)."""
    return {"scenario": "signal", "signal_number": signal_number, **options}


def output(*lines: str, exit_code: int = 1, **options: Any) -> Step:
    """Print `lines` verbatim (no JSON, no ``Error`` record) and exit with `exit_code`."""
    return {"scenario": "output", "lines": list(lines), "exit_code": exit_code, **options}


# --- invocation log ---------------------------------------------------------------------


@dataclass(frozen=True)
class Invocation:
    """One recorded run of the fake. ``exit_code`` is None when the process was killed."""

    id: str
    argv: list[str]
    cwd: str
    env: dict[str, str]
    env_keys: list[str]
    started_at: float
    ended_at: float | None
    exit_code: int | None

    @property
    def args(self) -> list[str]:
        """argv without the script path."""
        return self.argv[1:]

    def has(self, flag: str) -> bool:
        """Whether `flag` was passed, as ``--flag``, ``--flag value`` or ``--flag=value``."""
        return any(arg == flag or arg.startswith(f"{flag}=") for arg in self.args)

    def value(self, flag: str) -> str:
        """The value of `flag` (the last occurrence): ``--flag=v`` or ``--flag v`` form."""
        args = self.args
        found: str | None = None
        for index, arg in enumerate(args):
            if arg == flag:
                found = args[index + 1]
            elif arg.startswith(f"{flag}="):
                found = arg.partition("=")[2]
        if found is None:
            raise KeyError(flag)
        return found

    def uses_equals_form(self, flag: str) -> bool:
        """Whether `flag` was passed as one ``--flag=value`` argument."""
        return any(arg.startswith(f"{flag}=") for arg in self.args)


@dataclass(frozen=True)
class TokenFile:
    """The sentinel DNS token file handed to lego as ``CF_DNS_API_TOKEN_FILE``."""

    path: Path
    value: str = TOKEN_SENTINEL


def write_token_file(root: Path) -> TokenFile:
    """Write the sentinel token to ``<root>/config/acme/cloudflare-token`` (0600)."""
    path = root / "config" / "acme" / "cloudflare-token"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(TOKEN_SENTINEL + "\n")
    path.chmod(0o600)
    return TokenFile(path)


@dataclass(frozen=True)
class FakeLego:
    """An installed fake lego: the executable and the files that control and record it."""

    binary: Path

    @property
    def control_path(self) -> Path:
        return self.binary.with_name("fake_lego.control.json")

    @property
    def invocations_path(self) -> Path:
        return self.binary.with_name("fake_lego.invocations.jsonl")

    def configure(self, *steps: Step) -> None:
        """One step applies to every run; several run in order, the last repeating."""
        if not steps:
            raise ValueError("configure needs at least one step")
        payload: Step = steps[0] if len(steps) == 1 else {"sequence": list(steps)}
        self.control_path.write_text(json.dumps(payload))

    def succeed(self, issued: Issued | None = None, **kwargs: Any) -> Step:
        """Configure :func:`success`; returns the step (its ``crt`` holds the PEM)."""
        step = success(issued, **kwargs)
        self.configure(step)
        return step

    def fail(self, kind: str, **options: Any) -> None:
        self.configure(failure(kind, **options))

    def invocations(self) -> list[Invocation]:
        """Every recorded run in start order, with its exit record merged in."""
        if not self.invocations_path.exists():
            return []
        starts: dict[str, dict[str, Any]] = {}
        exits: dict[str, dict[str, Any]] = {}
        for line in self.invocations_path.read_text().splitlines():
            record = json.loads(line)
            (starts if record["event"] == "start" else exits)[record["id"]] = record
        return [
            Invocation(
                id=run_id,
                argv=start["argv"],
                cwd=start["cwd"],
                env=start["env"],
                env_keys=start["env_keys"],
                started_at=start["started_at"],
                ended_at=exits[run_id]["ended_at"] if run_id in exits else None,
                exit_code=exits[run_id]["code"] if run_id in exits else None,
            )
            for run_id, start in starts.items()
        ]


def install_fake_lego(directory: Path) -> FakeLego:
    """Copy the fake to ``<directory>/lego`` as an executable with LF line endings.

    The repo file may be CRLF (``* text=auto`` on a Windows checkout) and carries no execute
    bit, so the copy normalises the shebang line and sets 0755.
    """
    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / "lego"
    binary.write_bytes(FAKE_SOURCE.read_bytes().replace(b"\r\n", b"\n"))
    binary.chmod(0o755)
    return FakeLego(binary)


def run_lego(
    argv: list[str], env: dict[str, str], *, timeout: float = 30.0
) -> subprocess.CompletedProcess[str]:
    """Run `argv` the way the runner will: exact `env`, stdin closed, stdout and stderr apart."""
    return subprocess.run(
        argv,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
