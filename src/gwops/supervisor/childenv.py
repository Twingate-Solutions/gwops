"""The gateway child's environment: an exact allowlist of inherited variables.

gwops holds secrets in its own environment (``TWINGATE_API_KEY``, ``GWOPS_*``,
``GWOPS_RECORDING_TOKEN``, ``CF_*``) that the gateway must never see. The binary reads no
variable of its own beyond ``TWINGATE_CONFIG``, which gwops supersedes with ``--config``;
it needs only the process, locale, proxy, trust-store and Go-runtime variables below. An
allowlist cannot leak a secret added later; a denylist would.
"""

import os
import sys
from collections.abc import Mapping

_ALLOWED: frozenset[str] = frozenset(
    {
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
    }
)

# A Windows process cannot start, or resolve its temp directory, without these. `os.environ`
# upper-cases keys on Windows, so these are the names it yields.
_ALLOWED_WIN32: frozenset[str] = frozenset({"SYSTEMROOT", "COMSPEC", "PATHEXT", "TEMP", "TMP"})


def child_env(
    source: Mapping[str, str] | None = None, *, platform: str | None = None
) -> dict[str, str]:
    """A new environment dict for the gateway child, holding only allowlisted names.

    `source` defaults to ``os.environ`` and `platform` to ``sys.platform``, both read at
    call time. Names match exactly and case-sensitively; absent names are not invented and
    empty values are kept.
    """
    env = os.environ if source is None else source
    allowed = (
        _ALLOWED | _ALLOWED_WIN32 if (sys.platform if platform is None else platform) == "win32"
        else _ALLOWED
    )
    return {name: value for name, value in env.items() if name in allowed}
