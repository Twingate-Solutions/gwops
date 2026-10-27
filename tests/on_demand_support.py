"""Shared helpers for the on-demand issuance tests: CA builders, seed text, settings."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from gwops.settings import GwopsSettings

BasicConstraintsMode = Literal["ca", "not_ca", "absent"]
KeyUsageMode = Literal["key_cert_sign", "no_key_cert_sign", "absent"]

BASE_SEED = """\
twingate:
  network: acme
  gateway_id: g-1
"""

SSH_UPSTREAM_SEED = BASE_SEED + """\
ssh_upstreams:
  - name: web-1
    address: 10.0.0.5:22
"""


@dataclass(frozen=True)
class CAFiles:
    """A bring-your-own X.509 CA on disk."""

    cert: Path
    key: Path


def build_ca(
    directory: Path,
    *,
    name: str = "byo-ca",
    basic_constraints: BasicConstraintsMode = "ca",
    key_usage: KeyUsageMode = "key_cert_sign",
    write_key: bool = True,
) -> CAFiles:
    """Write an EC P-256 self-signed CA, varying the extensions the issuer cares about."""
    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
    )
    if basic_constraints != "absent":
        builder = builder.add_extension(
            x509.BasicConstraints(ca=basic_constraints == "ca", path_length=None), critical=True
        )
    if key_usage != "absent":
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_usage == "key_cert_sign",
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    cert = builder.sign(key, hashes.SHA256())
    cert_path = directory / f"{name}.crt"
    key_path = directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if write_key:
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return CAFiles(cert=cert_path, key=key_path)


def ca_section(*, on_demand: bool | None = None, byo: CAFiles | None = None) -> str:
    """The seed's ``ca.x509`` block; empty when neither argument asks for anything."""
    lines: list[str] = []
    if byo is not None:
        lines += [
            "    generate: false",
            f"    cert_path: {byo.cert.as_posix()}",
            f"    key_path: {byo.key.as_posix()}",
        ]
    if on_demand is not None:
        lines.append(f"    on_demand_issuance: {'true' if on_demand else 'false'}")
    return "ca:\n  x509:\n" + "\n".join(lines) + "\n" if lines else ""


def make_settings(
    tmp_path: Path, binary: Path, seed_text: str, *, seed_name: str = "seed.yaml"
) -> GwopsSettings:
    """Settings over tmp dirs with no secrets, so nothing reaches the network."""
    seed = tmp_path / seed_name
    seed.write_text(seed_text, encoding="utf-8")
    return GwopsSettings(
        seed_path=seed,
        data_dir=tmp_path / "data",
        runtime_dir=tmp_path / "run",
        gateway_binary=binary,
        **{  # type: ignore[arg-type]
            "TWINGATE_API_KEY": None,
            "GWOPS_ADMIN_TOKEN": None,
            "GWOPS_RECORDING_TOKEN": None,
        },
    )
