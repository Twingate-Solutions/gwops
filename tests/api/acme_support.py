"""Shared builders for the ACME admin-API tests: a public-mode seed with a ``source: acme``
certificate, a stub runner, and snapshot builders.

The stub stands in for :class:`gwops.acme.runner.AcmeRunner` (``request_issue`` and
``snapshot`` are the members the API uses; ``mark_store_invalid`` is recorded for completeness),
so the route and ``/status`` tests do not depend on lego, the state file or the clock.
"""

import dataclasses
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import SecretStr

from gwops.acme.runner import (
    AcmeCertState,
    AcmeSnapshot,
    CertSnapshot,
    IssueOutcome,
    IssueStatus,
)
from gwops.acme.state import AcmeErrorClass
from tests.public_tls_support import ZONE, public_cert, public_seed, ssh, tls_block, webapp

from .conftest import DepsBundle, make_deps

ACME_CERT = "issued"
FILE_CERT = "wild"
ACME_HOST = f"grafana.apps.{ZONE}"
STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
PRODUCTION_URL = "https://acme-v02.api.letsencrypt.org/directory"
AUTOMATION_TOKEN = "automation-token"

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


def acme_block(directory: str = "staging") -> dict[str, Any]:
    """A valid ``public_tls.acme`` block."""
    return {
        "email": "ops@example.com",
        "accept_tos": True,
        "directory": directory,
        "token_file": "/config/acme/cloudflare-token",
    }


def acme_cert(name: str = ACME_CERT, names: list[str] | None = None) -> dict[str, Any]:
    """One ``source: acme`` ``public_tls.certificates`` entry."""
    return {
        "name": name,
        "names": [f"*.apps.{ZONE}"] if names is None else names,
        "source": "acme",
    }


def acme_seed(directory: str = "staging") -> str:
    """A public-mode seed: a file certificate (``wild``) and an ACME one (``issued``).

    ``host1.<zone>`` is served by ``wild``; the web app ``grafana.apps.<zone>`` by ``issued``.
    """
    tls = tls_block(
        certificates=[public_cert(FILE_CERT, [f"*.{ZONE}"]), acme_cert()],
        acme=acme_block(directory),
    )
    seed = public_seed(
        tls,
        ssh_upstreams=[ssh("host1", f"host1.{ZONE}:22")],
        web_apps=[webapp("grafana", ACME_HOST)],
    )
    return yaml.safe_dump(seed, sort_keys=False)


class StubAcmeRunner:
    """Records ``request_issue`` calls and answers with a canned outcome and snapshot."""

    def __init__(
        self,
        outcome: IssueOutcome | None = None,
        snapshot: AcmeSnapshot | None = None,
        snapshot_error: Exception | None = None,
    ) -> None:
        self.outcome = outcome or IssueOutcome(IssueStatus.ACCEPTED, detail="issuance scheduled")
        self.snapshot_value = snapshot
        self.snapshot_error = snapshot_error
        self.issue_calls: list[tuple[str, bool]] = []
        self.snapshot_calls = 0
        self.marked_invalid: list[str] = []

    def request_issue(self, name: str, force: bool = False) -> IssueOutcome:
        self.issue_calls.append((name, force))
        return self.outcome

    def mark_store_invalid(self, name: str) -> None:
        self.marked_invalid.append(name)

    def snapshot(self) -> AcmeSnapshot:
        self.snapshot_calls += 1
        if self.snapshot_error is not None:
            raise self.snapshot_error
        assert self.snapshot_value is not None, "the test did not provide a snapshot"
        return self.snapshot_value


def cert_snapshot(name: str = ACME_CERT, **fields: Any) -> CertSnapshot:
    """A quiet, installed, staging-free production certificate; `fields` override."""
    values: dict[str, Any] = {
        "name": name,
        "names": (f"*.apps.{ZONE}",),
        "directory": PRODUCTION_URL,
        "staging": False,
        "state": AcmeCertState.IDLE,
        "installed": True,
        "installed_at": None,
        "installed_serial": None,
        "last_attempt_at": None,
        "last_success_at": None,
        "next_attempt_at": None,
        "error_code": None,
        "error_excerpt": None,
        "renewal_reason": None,
        "consecutive_failures": 0,
        "in_backoff": False,
        "retry_after": None,
        "last_crash": None,
        "permissions_problem": None,
    }
    values.update(fields)
    return CertSnapshot(**values)


def acme_snapshot(*certs: CertSnapshot, **fields: Any) -> AcmeSnapshot:
    """A configured production snapshot holding `certs`; `fields` override."""
    values: dict[str, Any] = {
        "configured": True,
        "directory": PRODUCTION_URL,
        "staging": False,
        "running": None,
        "state_error": None,
        "certificates": certs,
        "task_dead": False,
    }
    values.update(fields)
    return AcmeSnapshot(**values)


def failed_snapshot(code: AcmeErrorClass = AcmeErrorClass.DNS_AUTH) -> CertSnapshot:
    """A certificate whose last attempt failed with `code` (not in backoff)."""
    return cert_snapshot(
        state=AcmeCertState.FAILED,
        error_code=code,
        error_excerpt="boom",
        consecutive_failures=1,
    )


def acme_bundle(
    tmp_path: Path,
    runner: StubAcmeRunner | None,
    *,
    seed: str | None = None,
    automation_token: str | None = AUTOMATION_TOKEN,
    acme_unavailable: str | None = None,
) -> DepsBundle:
    """Deps for an ACME-mode gateway with `runner` wired as ``deps.acme`` (None: no runner).

    `acme_unavailable` is ``deps.acme_unavailable``: why the runner could not be built.
    """
    bundle = make_deps(tmp_path, seed=acme_seed() if seed is None else seed, ensure_cas=False)
    settings = bundle.deps.settings
    if automation_token is not None:
        settings = settings.model_copy(
            update={"gwops_automation_token": SecretStr(automation_token)}
        )
    bundle.deps = dataclasses.replace(
        bundle.deps,
        settings=settings,
        acme=runner,  # type: ignore[arg-type]
        acme_unavailable=acme_unavailable,
    )
    return bundle
