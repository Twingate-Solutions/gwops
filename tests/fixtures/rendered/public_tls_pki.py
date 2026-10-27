"""Write throwaway public-mode material for the public-tls golden (CI only).

Usage: ``python public_tls_pki.py [DATA_DIR]`` (default ``/data``).

Writes ``<data>/pki/ssh-ca.key`` and installs two leaves, issued by a throwaway root, through
gwops' atomic material store at ``<data>/public-tls/<name>/``, so the golden's stable paths are
symlinks through ``..data`` exactly as in a running image. The gateway binary does no chain or
SAN checks, so the root is not a real public root.
"""
import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from gwops.certs.store import MaterialStore

data = Path(sys.argv[1] if len(sys.argv) > 1 else "/data")
pki = data / "pki"
pki.mkdir(parents=True, exist_ok=True)
now = dt.datetime.now(dt.UTC)
not_before = now - dt.timedelta(minutes=5)
not_after = now + dt.timedelta(days=1)

# Certificate name -> DNS SANs; mirrors the certificates in public-tls.yaml.
LEAVES = {
    "app-wildcard": ["*.apps.example.com"],
    "ssh-bastion": ["bastion.example.com"],
}


def pem_key(k: ec.EllipticCurvePrivateKey) -> bytes:
    """PKCS#8 PEM, unencrypted."""
    return k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption())


ssh = ed25519.Ed25519PrivateKey.generate()
ssh_key = pki / "ssh-ca.key"
ssh_key.write_bytes(ssh.private_bytes(s.Encoding.PEM, s.PrivateFormat.OpenSSH, s.NoEncryption()))
ssh_key.chmod(0o600)

cert_sign = x509.KeyUsage(
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
    encipher_only=False, decipher_only=False,
)
root_key = ec.generate_private_key(ec.SECP256R1())
root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "preflight public-tls root")])
root = (
    x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
    .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
    .not_valid_before(not_before).not_valid_after(not_after)
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(cert_sign, critical=True)
    .sign(root_key, hashes.SHA256())
)
root_pem = root.public_bytes(s.Encoding.PEM)

store = MaterialStore(data / "public-tls")
for name, dns_names in LEAVES.items():
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_names[0])]))
        .issuer_name(root_name).public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before).not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in dns_names]), critical=False
        )
        .sign(root_key, hashes.SHA256())
    )
    store.install(name, leaf.public_bytes(s.Encoding.PEM) + root_pem, pem_key(leaf_key))
