#!/usr/bin/env python3
"""Generate a folder of deliberately imperfect certificates and keys for the demo.

    python demo/make_demo_certs.py demo/certs

Creates:
  good-ec-p384.pem         fine
  expiring-soon.pem        RSA-2048, expires in 10 days
  expired.pem              expired last month
  weak-rsa1024.pem         RSA-1024 (weak-key-size; SHA-1 signing if your OpenSSL still allows it)
  ed25519.pem              quantum-vulnerable signature cert, otherwise fine
  long-lived-leaf.pem      5-year validity (info)
  orphan-rsa.key           a private key on disk with no register entry
"""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID


def name(cn: str, org: str = "Demo Bank") -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def cert(key, cn: str, days_ago: int, days_valid: int, hash_alg=None, issuer_key=None,
         issuer_cn: str | None = None, ca: bool = False):  # fmt: skip
    now = dt.datetime.now(dt.UTC)
    subject = name(cn)
    issuer = name(issuer_cn) if issuer_cn else subject
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=days_ago))
        .not_valid_after(now - dt.timedelta(days=days_ago) + dt.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=not ca,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),  # fmt: skip
            critical=True,
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(f"{cn}.demo.bank")]), critical=False)
    )
    signer = issuer_key or key
    algo = None if isinstance(signer, ed25519.Ed25519PrivateKey) else (hash_alg or hashes.SHA256())
    return b.sign(signer, algo)


def pem(c) -> bytes:
    return c.public_bytes(serialization.Encoding.PEM)


def main(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    ca_key = rsa.generate_private_key(65537, 2048)
    ca = cert(ca_key, "Demo Bank Internal CA", days_ago=800, days_valid=3650, ca=True)
    (out / "internal-ca.pem").write_bytes(pem(ca))

    def leaf(fname, key, cn, days_ago, days_valid, hash_alg=None):
        c = cert(
            key,
            cn,
            days_ago,
            days_valid,
            hash_alg,
            issuer_key=ca_key,
            issuer_cn="Demo Bank Internal CA",
        )
        (out / fname).write_bytes(pem(c))

    leaf("good-ec-p384.pem", ec.generate_private_key(ec.SECP384R1()), "api.payments", 30, 365)
    leaf("expiring-soon.pem", rsa.generate_private_key(65537, 2048), "gateway.payments", 355, 365)
    leaf("expired.pem", rsa.generate_private_key(65537, 2048), "legacy.batch", 400, 365)
    leaf(
        "long-lived-leaf.pem",
        rsa.generate_private_key(65537, 3072),
        "hsm-client.payments",
        100,
        1825,
    )
    try:
        leaf(
            "weak-rsa1024.pem",
            rsa.generate_private_key(65537, 1024),
            "old.reporting",
            900,
            1095,
            hashes.SHA1(),
        )
    except Exception as exc:  # noqa: BLE001 - some OpenSSL builds refuse SHA-1 signing
        print(f"SHA-1 signing refused ({exc}); writing RSA-1024 with SHA-256 instead", file=sys.stderr)
        leaf("weak-rsa1024.pem", rsa.generate_private_key(65537, 1024), "old.reporting", 900, 1095)
    ed = ed25519.Ed25519PrivateKey.generate()
    (out / "ed25519.pem").write_bytes(pem(cert(ed, "ssh-ca.infra", 10, 365)))

    orphan = rsa.generate_private_key(65537, 2048)
    (out / "orphan-rsa.key").write_bytes(
        orphan.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    print(f"wrote demo certificates to {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "demo/certs"))
