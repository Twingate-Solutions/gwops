"""Write throwaway SSH CA, X.509 CA and leaf files for the tls-on-demand golden (CI only).

The leaf goes through gwops' atomic material store, so the golden's stable paths
(``<pki>/leaf/fullchain.pem``, ``<pki>/leaf/privkey.pem``) are symlinks through ``..data``
exactly as in a running image, and the gateway binary is checked against that layout.
"""
import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from gwops.certs.store import MaterialStore

pki = Path(sys.argv[1] if len(sys.argv) > 1 else "/data/pki")
pki.mkdir(parents=True, exist_ok=True)
now = dt.datetime.now(dt.UTC)


def pem_key(k: ec.EllipticCurvePrivateKey) -> bytes:
    """PKCS#8 PEM, unencrypted."""
    return k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption())


ssh = ed25519.Ed25519PrivateKey.generate()
ssh_pem = ssh.private_bytes(s.Encoding.PEM, s.PrivateFormat.OpenSSH, s.NoEncryption())
(pki / "ssh-ca.key").write_bytes(ssh_pem)
cert_sign = x509.KeyUsage(
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
    encipher_only=False, decipher_only=False,
)

ca_key = ec.generate_private_key(ec.SECP256R1())
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "preflight on-demand CA")])
ca = (
    x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
    .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
    .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(cert_sign, critical=True)
    .sign(ca_key, hashes.SHA256())
)
(pki / "x509-ca.crt").write_bytes(ca.public_bytes(s.Encoding.PEM))
(pki / "x509-ca.key").write_bytes(pem_key(ca_key))

leaf_key = ec.generate_private_key(ec.SECP256R1())
leaf = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gateway.preflight")]))
    .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
    .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName("gateway.preflight")]), critical=False)
    .sign(ca_key, hashes.SHA256())
)
MaterialStore(pki).install(
    "leaf",
    leaf.public_bytes(s.Encoding.PEM) + ca.public_bytes(s.Encoding.PEM),
    pem_key(leaf_key),
)
for p in pki.iterdir():
    if p.is_file():  # the leaf/ store directory keeps the modes the store gave it
        p.chmod(0o600)
