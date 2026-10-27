"""The gateway child environment contract, pinned independently of the implementation.

Shared by ``test_childenv.py`` (unit) and ``test_child_env_spawn.py`` (both spawn sites). These
literals are deliberately NOT imported from ``gwops``: a test that read the allowlist from the
code under test would pass whatever the code allowed.
"""

# Names the gateway binary (or the Go runtime beneath it) reads: proxy variables in both
# cases, the TLS trust-store overrides, TZ, locale and the Go runtime tuning knobs. Matching
# is exact and case-sensitive.
ALLOWLIST: tuple[str, ...] = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TZ",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "GOMEMLIMIT",
    "GOMAXPROCS",
    "GOGC",
    "GODEBUG",
)

# Added on win32 only: a Windows process cannot start (or resolve its temp directory) without
# these. ``os.environ`` upper-cases keys on Windows, so these are the exact names it yields.
WIN32_EXTRAS: tuple[str, ...] = ("SYSTEMROOT", "COMSPEC", "PATHEXT", "TEMP", "TMP")

# Every one of these is set in the supervisor's environment in production. None may reach the
# gateway child. Values are derived per name so a leak is attributable.
SECRET_NAMES: tuple[str, ...] = (
    "TWINGATE_API_KEY",
    "GWOPS_ADMIN_TOKEN",
    "GWOPS_AUTOMATION_TOKEN",
    "GWOPS_RECORDING_TOKEN",
    "CF_DNS_API_TOKEN",
    "TWINGATE_CONFIG",
    "FOO",
)


def sentinel(name: str) -> str:
    """A unique, greppable value for `name`, so a leaked value identifies its variable."""
    return f"sentinel-{name.lower()}-value"
