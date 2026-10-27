"""Identity of the wrapped gateway binary.

gwops wraps the official ``twingate/gateway`` binary and renders a single config schema
(2.0), so there is no capability probing. This module carries the reported gateway version
and the binary's web-app header template keys.

``gateway_version`` is reported (for example by the admin API ``/status``), never enforced.
"""

from dataclasses import dataclass

from gwops.settings import GwopsSettings

WEB_APP_TEMPLATE_KEYS: frozenset[str] = frozenset(
    {
        "jwt",
        "username",
        "groups",
        "clientGeoLatLong",
        "clientGeoCity",
        "clientGeoRegion",
        "clientGeoCountry",
    }
)
"""Header ``{{key}}`` template keys the gateway binary accepts."""


@dataclass(frozen=True)
class Capabilities:
    """The wrapped gateway binary's identity and the template keys it accepts.

    An empty ``gateway_version`` means ``GWOPS_GATEWAY_VERSION`` was unset (for example,
    outside the built image).
    """

    gateway_version: str = ""
    web_app_template_keys: frozenset[str] = WEB_APP_TEMPLATE_KEYS


def gateway_capabilities(version: str | None = None) -> Capabilities:
    """Return the capabilities of the wrapped gateway binary.

    Args:
        version: The raw gateway version string (for example ``"2.0.0-dev-5ed8e12"``).
            When omitted, reads ``GWOPS_GATEWAY_VERSION`` via
            :class:`~gwops.settings.GwopsSettings`.

    Returns:
        A :class:`Capabilities` with ``gateway_version`` set to the resolved version
        string. The value is not validated.
    """
    if version is None:
        version = GwopsSettings().gateway_version
    return Capabilities(gateway_version=version)
