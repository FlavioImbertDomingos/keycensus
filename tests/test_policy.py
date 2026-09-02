import datetime as dt

import pytest

from keycensus.analysis import strength
from keycensus.analysis.policy import Policy, evaluate
from keycensus.model import KIND_CERTIFICATE, utcnow

from .conftest import make_asset


def rules_for(asset, policy=None):
    return {f.rule_id for f in evaluate([asset], policy or Policy.default())}


def test_weak_algorithm_and_quantum():
    a = make_asset(algorithm="3DES", key_size=192, purposes=["encrypt"], state="active")
    r = rules_for(a)
    assert "weak-algorithm" in r
    assert "quantum-vulnerable-encryption" not in r  # weak already covers it


@pytest.mark.parametrize(
    "alg,size,curve,expect",
    [("RSA", 1024, None, True), ("RSA", 2048, None, False), ("EC", None, "P-192", True),
     ("EC", None, "P-256", False), ("AES", 64, None, True), ("AES", 128, None, False)],
)  # fmt: skip
def test_weak_key_size(alg, size, curve, expect):
    a = make_asset(algorithm=alg, key_size=size, curve=curve)
    assert ("weak-key-size" in rules_for(a)) is expect


def test_rotation_overdue_uses_purpose_then_algorithm():
    old = utcnow() - dt.timedelta(days=800)
    a = make_asset(algorithm="AES", key_size=256, purposes=["encrypt"], created=old, state="active")
    assert "rotation-overdue" in rules_for(a)
    kek = make_asset(algorithm="AES", key_size=256, purposes=["wrap"], created=old, state="active")
    assert "rotation-overdue" not in rules_for(kek)  # wrap = 1095 days
    rotated = make_asset(algorithm="AES", key_size=256, purposes=["encrypt"], created=old,
                         last_rotated=utcnow() - dt.timedelta(days=5), state="active")  # fmt: skip
    assert "rotation-overdue" not in rules_for(rotated)


def test_policy_override(tmp_path):
    (tmp_path / "p.yml").write_text(
        "name: strict\ncryptoperiod_days: {default: 30}\nrules:\n  rotation-overdue: {severity: critical}\n"
        "  quantum-vulnerable: {enabled: false}\n"
    )
    p = Policy.load(tmp_path / "p.yml")
    assert p.name == "strict"
    a = make_asset(algorithm="AES", key_size=256, purposes=["encrypt"],
                   created=utcnow() - dt.timedelta(days=45), state="active")  # fmt: skip
    f = [f for f in evaluate([a], p) if f.rule_id == "rotation-overdue"]
    assert f and f[0].severity == "critical"
    rsa = make_asset(algorithm="RSA", key_size=2048, purposes=["sign"])
    assert "quantum-vulnerable" not in rules_for(rsa, p)
    # other defaults survive the merge
    assert p.enabled("weak-algorithm")


def test_cert_expiry_buckets():
    now = utcnow()
    for days, rule in (
        (-1, "cert-expired"),
        (3, "cert-expiring-critical"),
        (20, "cert-expiring-soon"),
    ):
        a = make_asset(kind=KIND_CERTIFICATE, algorithm="RSA", key_size=2048, key_type="public-key",
                       created=now - dt.timedelta(days=100), expires=now + dt.timedelta(days=days))  # fmt: skip
        assert rule in rules_for(a), rule
    fine = make_asset(kind=KIND_CERTIFICATE, algorithm="RSA", key_size=2048, key_type="public-key",
                      created=now, expires=now + dt.timedelta(days=200))  # fmt: skip
    assert not {"cert-expired", "cert-expiring-critical", "cert-expiring-soon"} & rules_for(fine)


def test_sha1_signature_flagged():
    a = make_asset(kind=KIND_CERTIFICATE, algorithm="RSA", key_size=2048, key_type="public-key",
                   signature_algorithm="sha1WithRSAEncryption", signature_hash="SHA1")  # fmt: skip
    assert "deprecated-signature-hash" in rules_for(a)


def test_quantum_classes():
    enc = make_asset(algorithm="RSA", key_size=4096, purposes=["decrypt"], key_type="private-key")
    assert "quantum-vulnerable-encryption" in rules_for(enc)
    sig = make_asset(algorithm="EC", curve="P-256", purposes=["sign"], key_type="private-key")
    r = rules_for(sig)
    assert "quantum-vulnerable" in r and "quantum-vulnerable-encryption" not in r
    aes128 = make_asset(algorithm="AES", key_size=128, purposes=["encrypt"])
    assert "quantum-reduced" in rules_for(aes128)
    aes256 = make_asset(algorithm="AES", key_size=256, purposes=["encrypt"])
    assert not {"quantum-reduced", "quantum-vulnerable"} & rules_for(aes256)
    cert = make_asset(kind=KIND_CERTIFICATE, algorithm="RSA", key_size=2048, key_type="public-key",
                      purposes=["encrypt"])  # fmt: skip
    assert "quantum-vulnerable-encryption" not in rules_for(cert)  # certs are public keys


def test_strength_levels():
    assert strength.assess(make_asset(algorithm="RSA", key_size=2048)).classical_bits == 112
    assert strength.assess(make_asset(algorithm="RSA", key_size=3072)).classical_bits == 128
    assert strength.assess(make_asset(algorithm="EC", curve="P-384")).classical_bits == 192
    s = strength.assess(make_asset(algorithm="AES", key_size=256))
    assert s.nist_quantum_level == 5 and s.quantum_class == strength.QUANTUM_SAFE
    assert strength.assess(make_asset(algorithm="ML-KEM", key_size=768)).nist_quantum_level == 3


def test_tls_rules():
    a = make_asset(kind="protocol", protocol="TLS", protocol_version="TLSv1.2",
                   cipher_suites=["AES128-SHA"], weak_versions_accepted=["TLSv1.1"])  # fmt: skip
    r = rules_for(a)
    assert {"tls-weak-protocol", "tls-no-forward-secrecy"} <= r
    ok = make_asset(kind="protocol", protocol="TLS", protocol_version="TLSv1.3",
                    cipher_suites=["TLS_AES_256_GCM_SHA384"])  # fmt: skip
    assert not rules_for(ok)


def test_public_half_of_keypair_not_double_counted():
    priv = make_asset(name="k", native_id="p", algorithm="RSA", key_size=1024, key_type="private-key")
    pub = make_asset(name="k", native_id="q", algorithm="RSA", key_size=1024, key_type="public-key")
    findings = [f for f in evaluate([priv, pub], Policy.default()) if f.rule_id == "weak-key-size"]
    assert len(findings) == 1


def test_no_creation_date_is_info():
    a = make_asset(algorithm="AES", key_size=256)
    f = [f for f in evaluate([a], Policy.default()) if f.rule_id == "no-creation-date"]
    assert f and f[0].severity == "info" and "PCI-DSS-4.0:12.3.3" in f[0].controls
