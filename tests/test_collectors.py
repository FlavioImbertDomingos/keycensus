from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading

import pytest
import responses

from keycensus.collectors import REGISTRY, build
from keycensus.collectors.pem_files import PemCollector
from keycensus.collectors.tls_endpoint import TlsCollector
from keycensus.collectors.vault import VaultCollector
from keycensus.collectors.voltage import VoltageCollector, normalise_algorithm
from keycensus.model import KIND_CERTIFICATE, KIND_KEY, KIND_PROTOCOL

from .conftest import make_cert, pem, source


# --------------------------------------------------------------------- registry
def test_registry_has_all_types():
    assert set(REGISTRY) == {
        "pkcs11",
        "vault",
        "aws-kms",
        "voltage",
        "pem",
        "tls",
        "azure-keyvault",
        "gcp-kms",
        "ciphertrust",
        "keysafe5",
    }


def test_unknown_type_is_reported_not_raised():
    from keycensus.collectors import CollectorError

    with pytest.raises(CollectorError):
        build(source("x", "nope"))


# --------------------------------------------------------------------- pem
def test_pem_collector(cert_dir):
    res = PemCollector(source("certs", "pem", paths=[str(cert_dir)])).run()
    assert res.error is None
    names = sorted(a.name for a in res.assets)
    # bundle.pem contributes good + soon again -> 6 certs + 1 key
    assert names.count("good") == 2 and names.count("soon") == 2
    assert "orphan.key" in names
    certs = [a for a in res.assets if a.kind == KIND_CERTIFICATE]
    assert all(a.fingerprint_sha256 for a in certs)
    weak = next(a for a in certs if a.name == "weak")
    assert weak.algorithm == "RSA" and weak.key_size == 1024
    good = next(a for a in certs if a.name == "good")
    assert good.algorithm == "EC" and good.curve == "P-384" and good.self_signed
    key = next(a for a in res.assets if a.kind == KIND_KEY)
    assert key.key_type == "private-key" and key.created is None and key.exportable


def test_pem_collector_missing_paths():
    res = PemCollector(source("certs", "pem")).run()
    assert res.error and "paths" in res.error


# --------------------------------------------------------------------- tls
@pytest.fixture
def tls_server(tmp_path):
    key, cert = make_cert("localhost", days_valid=20)
    from cryptography.hazmat.primitives import serialization

    (tmp_path / "c.pem").write_bytes(pem(cert))
    (tmp_path / "k.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(tmp_path / "c.pem"), str(tmp_path / "k.pem"))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (ssl.SSLError, OSError):
                pass

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    yield port
    stop.set()
    t.join(timeout=2)
    srv.close()


def test_tls_collector(tls_server):
    res = TlsCollector(source("edge", "tls", endpoints=[f"127.0.0.1:{tls_server}"], timeout=3)).run()
    assert res.error is None
    kinds = {a.kind for a in res.assets}
    assert kinds == {KIND_PROTOCOL, KIND_CERTIFICATE}
    proto = next(a for a in res.assets if a.kind == KIND_PROTOCOL)
    assert proto.protocol_version in ("TLSv1.2", "TLSv1.3")
    assert proto.cipher_suites and proto.weak_versions_accepted == []
    cert = next(a for a in res.assets if a.kind == KIND_CERTIFICATE)
    assert cert.name == "localhost" and 18 < cert.days_until_expiry < 21


def test_tls_collector_unreachable():
    res = TlsCollector(source("edge", "tls", endpoints=["127.0.0.1:1"], timeout=1)).run()
    assert res.error is None
    assert res.assets[0].kind == KIND_PROTOCOL and "error" in res.assets[0].extra


# --------------------------------------------------------------------- vault (mocked HTTP)
VAULT = "http://vault.test:8200"


@responses.activate
def test_vault_collector(monkeypatch):
    monkeypatch.setenv("VT", "s.token")
    responses.add(responses.GET, f"{VAULT}/v1/sys/mounts", json={"data": {
        "transit/": {"type": "transit"}, "pki/": {"type": "pki"}, "secret/": {"type": "kv"}}})  # fmt: skip
    responses.add(responses.GET, f"{VAULT}/v1/transit/keys", json={"data": {"keys": ["dek", "rsa"]}})
    responses.add(responses.GET, f"{VAULT}/v1/transit/keys/dek", json={"data": {
        "type": "aes256-gcm96", "keys": {"1": 1700000000, "2": 1720000000}, "latest_version": 2,
        "auto_rotate_period": 2592000, "exportable": False, "supports_encryption": True,
        "supports_signing": False, "deletion_allowed": False}})  # fmt: skip
    responses.add(responses.GET, f"{VAULT}/v1/transit/keys/rsa", json={"data": {
        "type": "rsa-2048", "keys": {"1": {"creation_time": "2024-01-01T00:00:00Z", "name": "rsa-2048"}},
        "latest_version": 1, "auto_rotate_period": 0, "exportable": True,
        "supports_encryption": True, "supports_signing": True}})  # fmt: skip
    _, cert = make_cert("app.demo.bank", days_valid=10, issuer="Root", issuer_key=None)
    responses.add(responses.GET, f"{VAULT}/v1/pki/certs", json={"data": {"keys": ["aa-bb"]}})
    responses.add(
        responses.GET,
        f"{VAULT}/v1/pki/cert/aa-bb",
        json={"data": {"certificate": pem(cert).decode()}},
    )

    res = VaultCollector(source("v", "vault", url=VAULT, token_env="VT")).run()
    assert res.error is None, res.error
    by = {a.name: a for a in res.assets}
    assert by["dek"].algorithm == "AES" and by["dek"].key_size == 256
    assert by["dek"].rotation_enabled is True and by["dek"].last_rotated.year == 2024
    assert by["rsa"].algorithm == "RSA" and by["rsa"].exportable and by["rsa"].rotation_enabled is False
    assert "sign" in by["rsa"].purposes and "encrypt" in by["rsa"].purposes
    assert by["app.demo.bank"].kind == KIND_CERTIFICATE and by["app.demo.bank"].source_type == "vault-pki"
    # every request carried the token
    assert all(c.request.headers.get("X-Vault-Token") == "s.token" for c in responses.calls)


# --------------------------------------------------------------------- voltage (mocked HTTP + csv file)
@pytest.mark.parametrize(
    "text,alg,size,mode",
    [("FF1-AES-256", "AES", 256, "FF1"), ("AES256", "AES", 256, None), ("3DES", "3DES", 192, None),
     ("RSA-2048", "RSA", 2048, None), ("SHA-256 HMAC", "HMAC", 256, None), ("Blowfish", "unknown", None, None)],
)  # fmt: skip
def test_voltage_algorithm_normalisation(text, alg, size, mode):
    a, s, _curve, m = normalise_algorithm(text)
    assert (a, s, m) == (alg, size, mode)


@responses.activate
def test_voltage_collector_url(monkeypatch):
    monkeypatch.setenv("VP", "pw")
    responses.add(responses.GET, "http://v.test/inv.json", json={"keys": [
        {"key_id": "1", "name": "pan", "identity": "p@x", "district": "prod", "algorithm": "FF1-AES-256",
         "purpose": "fpe", "created": "2024-01-01", "rotated": "2025-01-01", "state": "active", "exportable": False},
        {"key_id": "2", "name": "old", "algorithm": "3DES", "purpose": "encrypt", "created": "2015-01-01",
         "state": "retired"}]})  # fmt: skip
    res = VoltageCollector(source("vo", "voltage", url="http://v.test/inv.json", username="u", password_env="VP")).run()
    assert res.error is None
    by = {a.name: a for a in res.assets}
    assert by["pan"].algorithm == "AES" and by["pan"].extra["fpe_mode"] == "FF1"
    assert by["pan"].last_rotated.year == 2025 and by["pan"].hardware_backed is True
    assert by["old"].state == "deactivated" and by["old"].algorithm == "3DES"
    assert responses.calls[0].request.headers["Authorization"].startswith("Basic ")


def test_voltage_collector_csv_with_field_map(tmp_path):
    (tmp_path / "x.csv").write_text("KeyName,Algo,Created,Status\npan,AES-256,2024-05-05,Active\n")
    res = VoltageCollector(source("vo", "voltage", file=str(tmp_path / "x.csv"),
                                  field_map={"name": "KeyName", "algorithm": "Algo", "created": "Created",
                                             "state": "Status"})).run()  # fmt: skip
    assert res.error is None and res.assets[0].name == "pan"
    assert res.assets[0].created == dt.datetime(2024, 5, 5, tzinfo=dt.UTC)
    assert res.assets[0].state == "active"


# --------------------------------------------------------------------- aws kms (moto in-process)
def test_aws_kms_collector(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from moto import mock_aws

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "t")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "t")
    with mock_aws():
        kms = boto3.client("kms", region_name="us-east-1")
        sym = kms.create_key(KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT",
                             Tags=[{"TagKey": "app", "TagValue": "pay"}])["KeyMetadata"]  # fmt: skip
        kms.create_alias(AliasName="alias/pay", TargetKeyId=sym["KeyId"])
        kms.enable_key_rotation(KeyId=sym["KeyId"])
        rsa = kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")["KeyMetadata"]
        off = kms.create_key(KeySpec="SYMMETRIC_DEFAULT")["KeyMetadata"]
        kms.disable_key(KeyId=off["KeyId"])

        from keycensus.collectors.aws_kms import AwsKmsCollector

        res = AwsKmsCollector(source("aws", "aws-kms", region="us-east-1")).run()
    assert res.error is None, res.error
    by = {a.native_id: a for a in res.assets}
    p = by[sym["Arn"]]
    assert p.name == "pay" and p.algorithm == "AES" and p.rotation_enabled is True and p.tags == {"app": "pay"}
    assert p.hardware_backed and p.fips_validated and p.created is not None
    r = by[rsa["Arn"]]
    assert r.algorithm == "RSA" and r.key_size == 2048 and r.purposes == ["sign", "verify"]
    assert by[off["Arn"]].state == "deactivated"


# --------------------------------------------------------------------- pkcs11 (SoftHSM, if installed)
SOFTHSM = "/usr/lib/softhsm/libsofthsm2.so"


@pytest.mark.skipif(not (os.path.exists(SOFTHSM) and shutil.which("softhsm2-util")), reason="softhsm2 not installed")
def test_pkcs11_collector_with_softhsm(tmp_path, monkeypatch):
    pytest.importorskip("pkcs11")
    tokens = tmp_path / "tokens"
    tokens.mkdir()
    conf = tmp_path / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {tokens}\nobjectstore.backend = file\n")
    monkeypatch.setenv("SOFTHSM2_CONF", str(conf))
    monkeypatch.setenv("PIN", "1234")
    subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", "t", "--pin", "1234",
                    "--so-pin", "5678"], check=True, capture_output=True)  # fmt: skip
    import pkcs11
    from pkcs11 import Attribute, KeyType

    lib = pkcs11.lib(SOFTHSM)
    tok = lib.get_token(token_label="t")
    with tok.open(rw=True, user_pin="1234") as s:
        s.generate_key(KeyType.AES, 256, label="aes", store=True,
                       template={Attribute.ENCRYPT: True, Attribute.EXTRACTABLE: False})  # fmt: skip
        s.generate_key(KeyType.DES3, label="tdes", store=True)
        s.generate_keypair(KeyType.RSA, 2048, label="rsa", store=True,
                           private_template={Attribute.SIGN: True, Attribute.EXTRACTABLE: True})  # fmt: skip

    from keycensus.collectors.pkcs11 import Pkcs11Collector

    res = Pkcs11Collector(source("hsm", "pkcs11", module=SOFTHSM, token_label="t", pin_env="PIN",
                                 hardware_backed=False)).run()  # fmt: skip
    assert res.error is None, res.error
    by = {(a.name, a.key_type): a for a in res.assets}
    assert by[("aes", "secret-key")].algorithm == "AES" and by[("aes", "secret-key")].key_size == 256
    assert by[("aes", "secret-key")].exportable is False
    assert by[("tdes", "secret-key")].algorithm == "3DES"
    assert by[("rsa", "private-key")].key_size == 2048 and by[("rsa", "private-key")].exportable is True
    assert ("rsa", "public-key") in by
    assert all(a.hardware_backed is False for a in res.assets)
    assert json.dumps([a.to_dict() for a in res.assets])  # serialisable
