from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from keycensus.config import SourceConfig
from keycensus.model import KIND_CERTIFICATE, KIND_KEY, CryptoAsset, Inventory, SourceResult, utcnow

FIXTURES = Path(__file__).parent / "fixtures"


def make_asset(**kw) -> CryptoAsset:
    base = dict(source="t", source_type="test", kind=KIND_KEY, name="k", native_id="k1")
    base.update(kw)
    return CryptoAsset(**base)


def make_cert(cn="unit", key=None, days_ago=1, days_valid=365, issuer=None, issuer_key=None, ca=False):
    key = key or rsa.generate_private_key(65537, 2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    iss = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]) if issuer else subject
    now = dt.datetime.now(dt.UTC)
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(iss)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=days_ago))
        .not_valid_after(now - dt.timedelta(days=days_ago) + dt.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return key, b.sign(issuer_key or key, hashes.SHA256())


def pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def cert_dir(tmp_path):
    _, good = make_cert("good", key=ec.generate_private_key(ec.SECP384R1()))
    _, expired = make_cert("expired", days_ago=400, days_valid=365)
    _, soon = make_cert("soon", days_ago=360, days_valid=365)
    _, weak = make_cert("weak", key=rsa.generate_private_key(65537, 1024))
    (tmp_path / "good.pem").write_bytes(pem(good))
    (tmp_path / "expired.crt").write_bytes(pem(expired))
    (tmp_path / "soon.pem").write_bytes(pem(soon))
    (tmp_path / "weak.pem").write_bytes(pem(weak))
    (tmp_path / "bundle.pem").write_bytes(pem(good) + pem(soon))
    k = rsa.generate_private_key(65537, 2048)
    (tmp_path / "orphan.key").write_bytes(
        k.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (tmp_path / "notes.txt").write_text("not a cert")
    return tmp_path


def source(name, type_, **opts) -> SourceConfig:
    return SourceConfig(name=name, type=type_, options=opts)


@pytest.fixture
def sample_inventory() -> Inventory:
    """A hand-built inventory with a bit of everything, for exporter tests."""
    now = utcnow()
    assets = [
        make_asset(
            name="aes-good",
            native_id="1",
            algorithm="AES",
            key_size=256,
            key_type="secret-key",
            purposes=["encrypt", "decrypt"],
            created=now - dt.timedelta(days=10),
            state="active",
            hardware_backed=True,
            fips_validated=True,
        ),  # fmt: skip
        make_asset(
            name="rsa-old",
            native_id="2",
            algorithm="RSA",
            key_size=2048,
            key_type="private-key",
            purposes=["sign"],
            created=now - dt.timedelta(days=900),
            state="active",
            exportable=True,
            hardware_backed=False,
        ),  # fmt: skip
        make_asset(
            name="tdes",
            native_id="3",
            algorithm="3DES",
            key_size=192,
            key_type="secret-key",
            purposes=["encrypt"],
            created=now - dt.timedelta(days=3000),
            state="active",
        ),  # fmt: skip
        make_asset(
            kind=KIND_CERTIFICATE,
            name="www",
            native_id="4",
            algorithm="EC",
            key_size=256,
            curve="P-256",
            key_type="public-key",
            purposes=["sign"],
            created=now - dt.timedelta(days=100),
            expires=now + dt.timedelta(days=5),
            subject="CN=www",
            issuer="CN=ca",
            signature_algorithm="ecdsa-with-SHA256",
            signature_hash="SHA256",
            self_signed=False,
            state="active",
        ),  # fmt: skip
        make_asset(
            kind="protocol",
            name="host:443",
            native_id="5",
            protocol="TLS",
            protocol_version="TLSv1.2",
            cipher_suites=["ECDHE-RSA-AES128-GCM-SHA256"],
            weak_versions_accepted=["TLSv1"],
            state="active",
        ),  # fmt: skip
    ]
    from keycensus.analysis.policy import Policy, evaluate

    inv = Inventory(generated_at=now, sources=[SourceResult(name="t", type="test", assets=assets),
                                               SourceResult(name="broken", type="vault", error="boom")])  # fmt: skip
    inv.findings = evaluate(inv.assets, Policy.default())
    return inv
