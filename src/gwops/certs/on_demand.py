"""On-demand issuance (`ca.x509.on_demand_issuance`): CA suitability, mode, warning text."""

from pathlib import Path
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from gwops.certs.validate import load_first_certificate
from gwops.configmodel.schema import EffectiveState

__all__ = [
    "ON_DEMAND_BROWSER_TRUST_WARNING",
    "ON_DEMAND_BYO_TRUST_WARNING",
    "ON_DEMAND_WARNING",
    "TlsMode",
    "require_on_demand_ca",
    "state_tls_warning",
    "tls_mode",
    "tls_warning",
]

TlsMode = Literal["static", "static+on_demand", "public"]

ON_DEMAND_WARNING = (
    "On-demand certificate issuance is active: a client that presents any SNI to :8443 "
    "receives a certificate for that name signed by the gwops X.509 CA (the CA private key "
    "is not disclosed). The exposure is that the gateway loads the gwops X.509 CA private "
    "key and uses it before the access token is authenticated, on a path any client that "
    "can reach :8443 can trigger."
)
ON_DEMAND_BROWSER_TRUST_WARNING = (
    " The CA is gwops-generated and a web app uses downstream tls13, so it is expected in "
    "browser trust stores: such a certificate would be browser-trusted for any name."
)
ON_DEMAND_BYO_TRUST_WARNING = (
    " The CA is bring-your-own, and such a CA is typically already trusted by devices: such "
    "a certificate would be accepted by them for any name."
)


def require_on_demand_ca(cert_path: Path, key_path: Path) -> None:
    """Raise ValueError, naming file and property, if the gateway's issuer would refuse the CA."""
    problems: list[str] = []
    try:
        cert = load_first_certificate(cert_path)
    except ValueError as exc:
        raise ValueError(f"on-demand issuance cannot use the X.509 CA: {exc}") from exc

    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    if not is_ca:
        problems.append(
            f"the CA certificate {cert_path} must have basicConstraints CA:TRUE (the gateway "
            "refuses a non-CA issuer certificate)"
        )

    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        key_usage = None
    if key_usage is not None and not key_usage.key_cert_sign:
        problems.append(
            f"the CA certificate {cert_path} has a keyUsage extension without keyCertSign "
            "(the gateway refuses an issuer certificate that cannot sign certificates)"
        )

    try:
        serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError):
        problems.append(
            f"the CA private key {key_path} is missing or could not be loaded as an "
            "unencrypted PEM private key"
        )

    if problems:
        raise ValueError(
            "ca.x509.on_demand_issuance is true but the X.509 CA is unusable for the gateway's "
            f"local issuer: {'; '.join(problems)}. Supply a suitable CA or set "
            "ca.x509.on_demand_issuance to false."
        )


def tls_mode(state: EffectiveState) -> TlsMode:
    """`public` in public certificate mode, `static+on_demand` when the seed opted in to
    on-demand issuance, else `static`."""
    if state.public_tls is not None:
        return "public"
    return "static+on_demand" if state.ca.x509.on_demand_issuance else "static"


def tls_warning(
    state: EffectiveState, ca_generated: bool, any_tls13_downstream: bool
) -> str | None:
    """The exposure warning, escalated for a BYO CA or a generated CA with tls13 web apps."""
    if not state.ca.x509.on_demand_issuance:
        return None
    if not ca_generated:
        return ON_DEMAND_WARNING + ON_DEMAND_BYO_TRUST_WARNING
    if any_tls13_downstream:
        return ON_DEMAND_WARNING + ON_DEMAND_BROWSER_TRUST_WARNING
    return ON_DEMAND_WARNING


def state_tls_warning(state: EffectiveState) -> str | None:
    """The exposure warning for `state`: what /status shows and what the logs carry.

    None in public mode: there is no gwops CA and no on-demand issuance.
    """
    if state.public_tls is not None:
        return None
    any_tls13 = any(app.downstream.tls == "tls13" for app in state.web_apps)
    return tls_warning(state, state.ca.x509.generate, any_tls13)
