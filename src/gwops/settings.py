"""gwops runtime settings, driven by environment variables.

General settings use the ``GWOPS_`` prefix (e.g. ``GWOPS_SEED_PATH``). The secrets
keep their canonical unprefixed names: ``TWINGATE_API_KEY``, ``GWOPS_ADMIN_TOKEN``,
``GWOPS_AUTOMATION_TOKEN``, ``GWOPS_RECORDING_TOKEN``.
"""

import re
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class GwopsSettings(BaseSettings):
    """Environment-driven paths, tunables, and secrets for the gwops control plane."""

    # Only declared fields are read from the process environment; any other GWOPS_*
    # variable (e.g. Kubernetes service links such as GWOPS_ADMIN_SERVICE_HOST) is
    # ignored. Keep field names clear of `*_PORT`, `*_SERVICE_HOST`, `*_SERVICE_PORT` and
    # `*_PORT_<n>_<PROTO>`, which Kubernetes can inject for a Service named after the stem.
    model_config = SettingsConfigDict(env_prefix="GWOPS_", frozen=True, extra="ignore")

    # Paths (container-canonical defaults)
    seed_path: Path = Path("/config/seed.yaml")
    data_dir: Path = Path("/data")
    runtime_dir: Path = Path("/run/gateway")
    gateway_binary: Path = Path("/usr/local/bin/gateway")
    # lego, the ACME client for `source: acme` certificates. GWOPS_LEGO_BINARY.
    lego_binary: Path = Path("/usr/local/bin/lego")
    # Wall-clock limit for one lego run; the runner kills the process after it.
    # GWOPS_LEGO_TIMEOUT_SECONDS.
    lego_timeout_seconds: float = Field(default=600.0, gt=0, le=3600, allow_inf_nan=False)

    # Fallback admin API port (a port number) for the container healthcheck when the seed
    # cannot be loaded. The admin API itself listens on the seed's `admin_api.port`.
    # GWOPS_HEALTHCHECK_ADMIN_FALLBACK. Named so Kubernetes service-link variables (for a
    # Service called `gwops-admin`: GWOPS_ADMIN_PORT=tcp://...) cannot collide with it.
    healthcheck_admin_fallback: int = 8081

    # Seconds between periodic reconciles, in addition to event-driven triggers.
    # GWOPS_RECONCILE_TICK_SECONDS.
    reconcile_tick_seconds: float = 600.0

    # Wrapped gateway binary version (e.g. "2.0.0"), set at image build time. Reported
    # in /status, never enforced. Empty outside the built image. GWOPS_GATEWAY_VERSION.
    gateway_version: str = ""

    # Secrets — env only, never from files under version control
    twingate_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("TWINGATE_API_KEY")
    )
    gwops_admin_token: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("GWOPS_ADMIN_TOKEN")
    )
    recording_token: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("GWOPS_RECORDING_TOKEN")
    )
    # Fixed-scope credential for unattended callers: PUT/DELETE/GET on
    # /upstreams/{segment}/{name} only, within the seed's allowlists and its own
    # namespace. Requires both allowlists.
    gwops_automation_token: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("GWOPS_AUTOMATION_TOKEN")
    )

    @field_validator("lego_binary")
    @classmethod
    def _lego_binary_absolute(cls, value: Path) -> Path:
        """Refuse a relative lego path: it would resolve against the runner's cwd."""
        if not (value.is_absolute() or value.as_posix().startswith("/")):
            raise ValueError(
                f"GWOPS_LEGO_BINARY must be an absolute path, got {value.as_posix()!r}; "
                "set it to the lego binary's full path (for example /usr/local/bin/lego)"
            )
        return value

    @property
    def acme_dir(self) -> Path:
        """Persistent ACME state root, ``<data_dir>/acme`` (``/data/acme``)."""
        return self.data_dir / "acme"

    @property
    def lego_path_dir(self) -> Path:
        """Base of lego's storage, ``<data_dir>/acme/lego``; each directory gets a subdirectory."""
        return self.acme_dir / "lego"

    def lego_storage_dir(self, directory_url: str) -> Path:
        """lego's ``--path`` for one ACME directory: ``<lego_path_dir>/<directory host>``.

        The host is lowercased; a port is appended after ``_`` when the URL carries one, and
        anything outside ``[a-z0-9._-]`` becomes ``_``. Staging and production therefore never
        share files, and two URLs on one host share a directory.
        """
        parts = urlsplit(directory_url)
        host = (parts.hostname or "").lower()
        try:
            port = parts.port
        except ValueError:
            port = None
        label = f"{host}_{port}" if port is not None else host
        label = re.sub(r"[^a-z0-9._-]", "_", label).strip(".") or "unknown"
        return self.lego_path_dir / label
