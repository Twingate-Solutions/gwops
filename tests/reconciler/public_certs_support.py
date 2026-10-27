"""Builders for the public-certificate reconciler tests.

``PublicEnv`` wraps ``test_core.Env`` (a reconciler over tmp dirs, no tenant client) with a
seed in public mode, a confined source root under ``tmp_path`` and helpers that write
certificate material. Material comes from the generated RSA hierarchy in
``tests/public_chain_support.py``; leaf validity is relative to the real clock, because the
reconciler validates at ``datetime.now``.
"""

import dataclasses
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from gwops.reconciler.core import ReconcileResult
from gwops.renderer.capabilities import Capabilities
from tests.public_chain_support import Issued, ec_key, rsa_hierarchy
from tests.public_tls_support import ZONE, public_cert, public_seed, ssh, tls_block

from .test_core import Env

ROOT = rsa_hierarchy().root
DAY = timedelta(days=1)


def host(name: str) -> str:
    """The DNS name a certificate called `name` covers."""
    return f"{name}.{ZONE}"


def issue(
    name: str,
    *,
    lifetime_days: int = 90,
    remaining_days: int = 80,
    new_key: bool = False,
) -> Issued:
    """A leaf for ``host(name)`` valid for `lifetime_days`, with `remaining_days` left.

    Every call returns a distinct certificate (a new serial); `new_key` also uses a new key.
    """
    now = datetime.now(UTC)
    return rsa_hierarchy().issue(
        [host(name)],
        key=ec_key() if new_key else None,
        not_before=now - (lifetime_days - remaining_days) * DAY,
        not_after=now + remaining_days * DAY,
    )


class PublicEnv:
    """A reconciler in public mode over tmp dirs; ``certs`` maps certificate name to names."""

    def __init__(
        self, tmp_path: Path, binary: Path, certs: dict[str, list[str]] | None = None
    ) -> None:
        self.source_root = tmp_path / "public-tls-src"
        self.certs = certs if certs is not None else {"alpha": [host("alpha")]}
        self.env = Env(tmp_path, self._seed_text(), binary, Capabilities(), None)
        self.env.paths = dataclasses.replace(self.env.paths, public_tls_root=self.source_root)
        self.env.reconciler._paths = self.env.paths  # the reconciler reads its own copy
        self.written: dict[str, Issued] = {}

    def _seed_text(self) -> str:
        entries = [
            public_cert(
                name,
                names,
                cert_file=str(self.source_root / name / "fullchain.pem"),
                key_file=str(self.source_root / name / "privkey.pem"),
            )
            for name, names in self.certs.items()
        ]
        hosts = sorted({n for names in self.certs.values() for n in names})
        seed = public_seed(
            tls_block(certificates=entries),
            ssh_upstreams=[ssh(f"h{i}", f"{h}:22") for i, h in enumerate(hosts)],
        )
        return yaml.safe_dump(seed, sort_keys=False)

    def declare(self, certs: dict[str, list[str]]) -> None:
        """Rewrite the seed to declare exactly `certs` (and one upstream per name)."""
        self.certs = certs
        self.env.seed_path.write_text(self._seed_text(), encoding="utf-8")

    def write(self, name: str, issued: Issued | None = None) -> Issued:
        """Write `issued` (default: a fresh leaf for the name) as the source files of `name`."""
        issued = issued if issued is not None else issue(name)
        directory = self.source_root / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "fullchain.pem").write_bytes(issued.cert_pem)
        (directory / "privkey.pem").write_bytes(issued.key_pem)
        self.written[name] = issued
        return issued

    def write_all(self) -> None:
        """Write a fresh valid leaf for every declared certificate."""
        for name in self.certs:
            self.write(name)

    async def run(self, trigger: str = "test") -> ReconcileResult:
        """One full reconcile pass."""
        return await self.env.reconciler.reconcile(trigger)

    def served(self, name: str) -> tuple[bytes, bytes]:
        """The certificate and key bytes the gateway would read at the stable paths."""
        cert_file, key_file = self.env.paths.public_cert_files(name)
        return cert_file.read_bytes(), key_file.read_bytes()

    def public_errors(self, result: ReconcileResult) -> list[str]:
        """The pass's errors that belong to the certificate step."""
        return [e for e in result.errors if e.startswith("public certificate")]


def other_cert_errors(result: ReconcileResult) -> list[Any]:
    """Errors that are not certificate errors (the tenant being unconfigured is expected)."""
    return [e for e in result.errors if not e.startswith(("public certificate", "TG sync"))]
