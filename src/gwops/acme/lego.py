"""Build the lego (v5.5.2) command line and environment for one ACME certificate.

A pure function of the seed's ``public_tls.acme`` block, one ``source: acme`` certificate and
the gwops settings. It holds no secret: the DNS token is passed as a *file path* in the
environment (lego's ``_FILE`` convention), and gwops never reads the file.

Flag placement follows lego v5: global flags (``--log.*``) precede ``run``; everything else,
including ``--path``, follows it. ``run`` obtains a certificate when none is stored under
``--path`` and renews otherwise, so there is no separate renew command.
"""

from collections.abc import Mapping

from gwops.configmodel.schema import AcmePublicCertificate, AcmeSettings
from gwops.settings import GwopsSettings
from gwops.supervisor.childenv import child_env

KEY_TYPE = "EC256"
"""Certificate key type passed to ``--key-type``."""

LEGO_LOG_LEVEL = "info"
"""Global ``--log.level``; ``debug`` would add request detail to the captured output."""

TOKEN_ENV_VARS: tuple[str, str] = ("CF_DNS_API_TOKEN_FILE", "CF_ZONE_API_TOKEN_FILE")
"""Cloudflare variables lego reads the token path from (DNS edit and zone lookup)."""

LEGO_ENV_STRIP_PREFIXES: tuple[str, ...] = ("CF_", "CLOUDFLARE_", "LEGO_")
"""Inherited variable prefixes never passed to lego.

Every lego flag also reads ``LEGO_<NAME>``; ``CF_*`` and ``CLOUDFLARE_*`` carry Cloudflare
credentials (a global API key outranks the token) and ``CLOUDFLARE_BASE_URL`` redirects the
token. ``child_env`` is an allowlist and already excludes them; this is the second guard.
"""

LEGO_ENV_STRIP_NAMES: tuple[str, ...] = ("GODEBUG",)
"""Exact inherited variable names never passed to lego (Go runtime debug switches)."""


def build_argv(
    settings: AcmeSettings,
    cert: AcmePublicCertificate,
    *,
    gwops: GwopsSettings,
    force: bool = False,
    environ: Mapping[str, str] | None = None,
    token_path: str | None = None,
) -> tuple[list[str], dict[str, str]]:
    """The lego argv and child environment that obtain or renew `cert`.

    Args:
        settings: The seed's ``public_tls.acme`` block.
        cert: The ``source: acme`` certificate; its `name` becomes lego's ``--cert.name`` (the
            file stem under ``<path>/certificates/``) and its `names` the ``--domains``.
        gwops: Runtime settings: the lego binary and the base of the ``--path`` storage.
        force: Add ``--renew-force`` (the admin route's force; skips the renewal-window check).
        environ: The source environment, default ``os.environ``.
        token_path: The token file path to give lego, normally the symlink-resolved path from
            :func:`gwops.acme.token.resolve_token_file` taken at attempt time. Default:
            ``settings.token_file`` as configured. The file is never read.

    Returns:
        ``(argv, env)``. ``argv[0]`` is the lego binary. No secret appears in argv. `env` is
        :func:`~gwops.supervisor.childenv.child_env` (allowlisted process, proxy and trust
        variables), minus any ``CF_*``, ``CLOUDFLARE_*`` or ``LEGO_*`` name and ``GODEBUG``, plus
        the two token-file variables. ``--path`` is
        :meth:`GwopsSettings.lego_storage_dir` for the directory, so staging and production
        never share files. Values that come from the seed (``--cert.name``, ``--domains``)
        use the ``--flag=value`` form so a leading ``-`` cannot be parsed as a flag. Run lego
        with stdin closed.
    """
    argv = [
        gwops.lego_binary.as_posix(),
        "--log.format", "json",
        "--log.level", LEGO_LOG_LEVEL,
        "run",
        "--path", gwops.lego_storage_dir(settings.directory_url).as_posix(),
        "--server", settings.directory_url,
        "--email", settings.email,
        "--accept-tos",
        "--dns", settings.provider,
    ]  # fmt: skip
    if settings.propagation != "authoritative":
        argv.append("--dns.propagation.disable-ans")
    argv += [
        "--key-type", KEY_TYPE,
        f"--cert.name={cert.name}",
        f"--domains={','.join(cert.names)}",
        "--force-cert-domains",
        "--no-random-sleep",
    ]  # fmt: skip
    if force:
        argv.append("--renew-force")

    env = {
        name: value
        for name, value in child_env(environ).items()
        if not name.upper().startswith(LEGO_ENV_STRIP_PREFIXES)
        and name.upper() not in LEGO_ENV_STRIP_NAMES
    }
    env.update(dict.fromkeys(TOKEN_ENV_VARS, token_path or settings.token_file))
    return argv, env
