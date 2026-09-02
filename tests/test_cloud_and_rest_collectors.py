"""Azure Key Vault / Managed HSM, Google Cloud KMS, CipherTrust Manager, KeySafe 5 -- all over mocked HTTP."""

from __future__ import annotations

import base64
import datetime as dt

import responses
from cryptography.hazmat.primitives import serialization
from responses import matchers

from keycensus.collectors.azure_keyvault import AzureKeyVaultCollector
from keycensus.collectors.ciphertrust import CipherTrustCollector
from keycensus.collectors.ciphertrust import normalise_algorithm as ctm_alg
from keycensus.collectors.gcp_kms import GcpKmsCollector
from keycensus.collectors.gcp_kms import normalise_algorithm as gcp_alg
from keycensus.collectors.keysafe5 import KeySafe5Collector, normalise_type
from keycensus.model import KIND_CERTIFICATE, KIND_KEY

from .conftest import make_cert, source


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# ===================================================================== Azure Key Vault
KV = "https://pay-kv.vault.azure.net"


@responses.activate
def test_azure_keyvault(monkeypatch):
    monkeypatch.setenv("AZT", "eyJ.token")
    now = int(dt.datetime.now(dt.UTC).timestamp())
    responses.add(
        responses.GET,
        f"{KV}/keys",
        match=[matchers.query_param_matcher({"api-version": "7.5", "maxresults": "25"})],
        json={
            "value": [
                {"kid": f"{KV}/keys/tde", "attributes": {"enabled": True, "created": now - 86400 * 400}},
                {"kid": f"{KV}/keys/sign", "attributes": {"enabled": True}},
                {"kid": f"{KV}/keys/old", "attributes": {"enabled": False}},
            ],
            "nextLink": f"{KV}/keys?api-version=7.5&$skiptoken=abc",
        },
    )
    responses.add(
        responses.GET,
        f"{KV}/keys",
        match=[matchers.query_param_matcher({"api-version": "7.5", "$skiptoken": "abc"})],
        json={"value": [{"kid": f"{KV}/keys/aeskey", "attributes": {"enabled": True}}]},
    )
    responses.add(
        responses.GET,
        f"{KV}/keys/tde",
        json={
            "key": {
                "kid": f"{KV}/keys/tde/v1",
                "kty": "RSA-HSM",
                "n": _b64url(b"\x01" * 256),
                "e": "AQAB",
                "key_ops": ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            "attributes": {
                "enabled": True,
                "created": now - 86400 * 400,
                "exp": now + 86400 * 30,
                "recoveryLevel": "Recoverable+Purgeable",
                "hsmPlatform": "1",
            },
            "tags": {"app": "sqltde"},
        },
    )
    responses.add(
        responses.GET,
        f"{KV}/keys/tde/rotationpolicy",
        json={"lifetimeActions": [{"trigger": {"timeBeforeExpiry": "P30D"}, "action": {"type": "Rotate"}}]},
    )
    responses.add(
        responses.GET,
        f"{KV}/keys/sign",
        json={
            "key": {"kid": f"{KV}/keys/sign/v9", "kty": "EC", "crv": "P-384", "key_ops": ["sign", "verify"]},
            "attributes": {"enabled": True, "created": now - 10},
        },
    )
    responses.add(
        responses.GET,
        f"{KV}/keys/sign/rotationpolicy",
        json={"lifetimeActions": [{"trigger": {"timeBeforeExpiry": "P30D"}, "action": {"type": "Notify"}}]},
    )
    responses.add(
        responses.GET,
        f"{KV}/keys/old",
        json={
            "key": {"kid": f"{KV}/keys/old/v1", "kty": "RSA", "n": _b64url(b"\x01" * 128), "key_ops": ["sign"]},
            "attributes": {"enabled": False, "created": now - 86400 * 2000},
        },
    )
    responses.add(responses.GET, f"{KV}/keys/old/rotationpolicy", status=404, json={"error": {"code": "NotFound"}})
    responses.add(
        responses.GET,
        f"{KV}/keys/aeskey",
        json={
            "key": {"kid": f"{KV}/keys/aeskey/v1", "kty": "oct-HSM", "key_ops": ["encrypt", "decrypt"]},
            "attributes": {"enabled": True, "created": now - 10, "key_size": 256},
        },
    )
    responses.add(responses.GET, f"{KV}/keys/aeskey/rotationpolicy", status=403, json={"error": {"code": "Forbidden"}})
    _, cert = make_cert("app.bank.example", days_valid=20)
    der = cert.public_bytes(serialization.Encoding.DER)
    responses.add(
        responses.GET,
        f"{KV}/certificates",
        json={"value": [{"id": f"{KV}/certificates/app", "attributes": {"enabled": True}}]},
    )
    responses.add(
        responses.GET,
        f"{KV}/certificates/app",
        json={
            "id": f"{KV}/certificates/app/v3",
            "kid": f"{KV}/keys/app/v3",
            "cer": base64.b64encode(der).decode(),
            "attributes": {"enabled": True},
            "policy": {
                "key_props": {"kty": "RSA-HSM", "exportable": False},
                "issuer": {"name": "DigiCert"},
                "lifetime_actions": [{"action": {"action_type": "AutoRenew"}}],
            },
        },
    )

    res = AzureKeyVaultCollector(source("kv", "azure-keyvault", vault_url=KV, auth="token", token_env="AZT")).run()
    assert res.error is None, res.error
    by = {a.name: a for a in res.assets}
    assert set(by) == {"tde", "sign", "old", "aeskey", "app"}  # paging + certificates
    tde = by["tde"]
    assert tde.algorithm == "RSA" and tde.key_size == 2048 and tde.hardware_backed and tde.fips_validated
    assert tde.rotation_enabled is True and "wrap" in tde.purposes and tde.tags["app"] == "sqltde"
    assert 29 < tde.days_until_expiry < 31 and tde.native_id == f"{KV}/keys/tde"  # version-less
    assert by["sign"].algorithm == "EC" and by["sign"].curve == "P-384" and by["sign"].key_size == 384
    assert by["sign"].rotation_enabled is False and by["sign"].hardware_backed is False
    assert by["old"].state == "deactivated" and by["old"].key_size == 1024 and by["old"].rotation_enabled is None
    assert by["aeskey"].algorithm == "AES" and by["aeskey"].key_type == "secret-key" and by["aeskey"].hardware_backed
    cert_asset = by["app"]
    assert cert_asset.kind == KIND_CERTIFICATE and cert_asset.source_type == "azure-keyvault-cert"
    assert cert_asset.hardware_backed and cert_asset.exportable is False and cert_asset.rotation_enabled is True
    assert cert_asset.extra["issuer_provider"] == "DigiCert" and 18 < cert_asset.days_until_expiry < 20
    assert all(c.request.headers["Authorization"] == "Bearer eyJ.token" for c in responses.calls)
    assert all("api-version=7.5" in c.request.url for c in responses.calls)


@responses.activate
def test_azure_managed_hsm_marks_everything_hardware(monkeypatch):
    monkeypatch.setenv("AZT", "t")
    hsm = "https://pay-hsm.managedhsm.azure.net"
    responses.add(
        responses.GET, f"{hsm}/keys", json={"value": [{"kid": f"{hsm}/keys/k1", "attributes": {"enabled": True}}]}
    )
    responses.add(
        responses.GET,
        f"{hsm}/keys/k1",
        json={
            "key": {"kid": f"{hsm}/keys/k1/1", "kty": "oct-HSM", "key_ops": ["wrapKey"]},
            "attributes": {"enabled": True},
        },
    )
    responses.add(responses.GET, f"{hsm}/keys/k1/rotationpolicy", status=404, json={})
    res = AzureKeyVaultCollector(
        source("mh", "azure-keyvault", vault_url=hsm, auth="token", token_env="AZT", include_certificates=False)
    ).run()
    assert res.error is None and res.assets[0].hardware_backed and res.assets[0].fips_validated
    assert "Managed HSM" in res.assets[0].location


def test_azure_missing_token_is_a_source_error():
    res = AzureKeyVaultCollector(source("kv", "azure-keyvault", vault_url=KV, auth="token", token_env="NOPE_AZ")).run()
    assert res.error and "NOPE_AZ" in res.error


# ===================================================================== Google Cloud KMS
GCP = "http://kms.test"
P = "projects/acme/locations/us-east1"


def test_gcp_algorithm_normalisation():
    assert gcp_alg("GOOGLE_SYMMETRIC_ENCRYPTION") == ("AES", 256, None, None)
    assert gcp_alg("RSA_SIGN_PSS_3072_SHA256") == ("RSA", 3072, None, "SHA256")
    assert gcp_alg("RSA_DECRYPT_OAEP_2048_SHA1") == ("RSA", 2048, None, "SHA1")
    assert gcp_alg("EC_SIGN_P384_SHA384") == ("EC", 384, "P-384", "SHA384")
    assert gcp_alg("EC_SIGN_SECP256K1_SHA256") == ("EC", 256, "secp256k1", "SHA256")
    assert gcp_alg("EC_SIGN_ED25519") == ("Ed25519", 256, "Ed25519", None)
    assert gcp_alg("HMAC_SHA256") == ("HMAC", 256, None, "SHA256")
    assert gcp_alg("PQ_SIGN_ML_DSA_65") == ("ML-DSA", 65, None, None)
    assert gcp_alg("AES_128_GCM") == ("AES", 128, None, None)
    assert gcp_alg("SOMETHING_NEW")[0] == "unknown"


@responses.activate
def test_gcp_kms(monkeypatch):
    monkeypatch.setenv("GT", "ya29.token")
    responses.add(responses.GET, f"{GCP}/v1/projects/acme/locations", json={"locations": [{"locationId": "us-east1"}]})
    responses.add(responses.GET, f"{GCP}/v1/{P}/keyRings", json={"keyRings": [{"name": f"{P}/keyRings/payments"}]})
    ring = f"{P}/keyRings/payments"
    responses.add(
        responses.GET,
        f"{GCP}/v1/{ring}/cryptoKeys",
        json={
            "cryptoKeys": [
                {
                    "name": f"{ring}/cryptoKeys/dek",
                    "purpose": "ENCRYPT_DECRYPT",
                    "createTime": "2023-01-01T00:00:00Z",
                    "rotationPeriod": "7776000s",
                    "nextRotationTime": "2026-12-01T00:00:00Z",
                    "labels": {"env": "prod"},
                    "primary": {
                        "name": f"{ring}/cryptoKeys/dek/cryptoKeyVersions/3",
                        "state": "ENABLED",
                        "protectionLevel": "HSM",
                        "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
                        "createTime": "2025-06-01T00:00:00Z",
                    },
                    "versionTemplate": {"protectionLevel": "HSM", "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"},
                },
                {
                    "name": f"{ring}/cryptoKeys/signer",
                    "purpose": "ASYMMETRIC_SIGN",
                    "createTime": "2024-01-01T00:00:00Z",
                    "versionTemplate": {"protectionLevel": "SOFTWARE", "algorithm": "EC_SIGN_P256_SHA256"},
                },
                {
                    "name": f"{ring}/cryptoKeys/gone",
                    "purpose": "ENCRYPT_DECRYPT",
                    "createTime": "2020-01-01T00:00:00Z",
                    "versionTemplate": {"protectionLevel": "SOFTWARE", "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"},
                },
                {
                    "name": f"{ring}/cryptoKeys/ext",
                    "purpose": "ENCRYPT_DECRYPT",
                    "createTime": "2024-01-01T00:00:00Z",
                    "primary": {
                        "name": f"{ring}/cryptoKeys/ext/cryptoKeyVersions/1",
                        "state": "ENABLED",
                        "protectionLevel": "EXTERNAL",
                        "algorithm": "EXTERNAL_SYMMETRIC_ENCRYPTION",
                        "createTime": "2024-01-01T00:00:00Z",
                        "externalProtectionLevelOptions": {"externalKeyUri": "https://ekm.example.com/keys/1"},
                    },
                },
            ]
        },
    )
    responses.add(
        responses.GET,
        f"{GCP}/v1/{ring}/cryptoKeys/dek/cryptoKeyVersions",
        json={
            "cryptoKeyVersions": [
                {
                    "name": f"{ring}/cryptoKeys/dek/cryptoKeyVersions/{i}",
                    "state": s,
                    "createTime": f"202{i}-06-01T00:00:00Z",
                }
                for i, s in ((1, "DESTROYED"), (2, "DISABLED"), (3, "ENABLED"))
            ]
        },
    )
    responses.add(
        responses.GET,
        f"{GCP}/v1/{ring}/cryptoKeys/signer/cryptoKeyVersions",
        json={
            "cryptoKeyVersions": [
                {
                    "name": f"{ring}/cryptoKeys/signer/cryptoKeyVersions/1",
                    "state": "ENABLED",
                    "protectionLevel": "SOFTWARE",
                    "algorithm": "EC_SIGN_P256_SHA256",
                    "createTime": "2024-01-01T00:00:00Z",
                }
            ]
        },
    )
    responses.add(
        responses.GET,
        f"{GCP}/v1/{ring}/cryptoKeys/gone/cryptoKeyVersions",
        json={"cryptoKeyVersions": [{"name": f"{ring}/cryptoKeys/gone/cryptoKeyVersions/1", "state": "DESTROYED"}]},
    )
    responses.add(
        responses.GET,
        f"{GCP}/v1/{ring}/cryptoKeys/ext/cryptoKeyVersions",
        json={
            "cryptoKeyVersions": [
                {
                    "name": f"{ring}/cryptoKeys/ext/cryptoKeyVersions/1",
                    "state": "ENABLED",
                    "protectionLevel": "EXTERNAL",
                }
            ]
        },
    )

    sa = "serviceAccount:payments-api@acme.iam.gserviceaccount.com"
    responses.add(responses.GET, f"{GCP}/v1/{ring}/cryptoKeys/dek:getIamPolicy", json={"bindings": [
        {"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter", "members": [sa, "group:data-eng@acme.com"]},
        {"role": "roles/cloudkms.viewer", "members": ["user:auditor@acme.com"]}]})  # fmt: skip
    responses.add(
        responses.GET, f"{GCP}/v1/{ring}/cryptoKeys/signer:getIamPolicy", status=403, json={"error": {"code": 403}}
    )
    responses.add(responses.GET, f"{GCP}/v1/{ring}/cryptoKeys/ext:getIamPolicy", json={"bindings": []})
    responses.add(responses.GET, f"{GCP}/v1/{ring}/cryptoKeys/gone:getIamPolicy", json={"bindings": []})
    res = GcpKmsCollector(source("g", "gcp-kms", project="acme", auth="token", token_env="GT", endpoint=GCP)).run()
    assert res.error is None, res.error
    by = {a.name: a for a in res.assets}
    assert set(by) == {"dek", "signer", "ext"}  # 'gone' (all versions destroyed) filtered by default
    assert [(u["type"], u["id"]) for u in by["dek"].used_by] == [("service", sa), ("group", "group:data-eng@acme.com")]
    assert (
        by["dek"].used_by[0]["via"] == "iam:cryptoKeyEncrypterDecrypter" and by["signer"].used_by == []
    )  # 403 tolerated
    dek = by["dek"]
    assert dek.algorithm == "AES" and dek.key_size == 256 and dek.hardware_backed and dek.fips_validated
    assert dek.rotation_enabled is True and dek.last_rotated.year == 2025 and dek.created.year == 2023
    assert dek.extra["versions"] == 3 and dek.extra["version_states"]["DESTROYED"] == 1 and dek.tags == {"env": "prod"}
    assert dek.native_id == f"{ring}/cryptoKeys/dek" and dek.location == "us-east1 HSM"
    sg = by["signer"]
    assert (
        sg.algorithm == "EC"
        and sg.curve == "P-256"
        and sg.purposes == ["sign", "verify"]
        and sg.hardware_backed is False
    )
    assert sg.rotation_enabled is None  # asymmetric keys have no automatic rotation in GCP
    assert by["ext"].exportable is True and by["ext"].extra["external_key_uri"].startswith("https://ekm")
    assert all(c.request.headers["Authorization"] == "Bearer ya29.token" for c in responses.calls)

    res = GcpKmsCollector(
        source(
            "g",
            "gcp-kms",
            project="acme",
            auth="token",
            token_env="GT",
            endpoint=GCP,
            locations=["us-east1"],
            include_destroyed=True,
        )
    ).run()
    assert (
        "gone" in {a.name for a in res.assets} and next(a for a in res.assets if a.name == "gone").state == "destroyed"
    )


# ===================================================================== CipherTrust Manager
CTM = "https://ctm.test"


def test_ctm_algorithm_normalisation():
    assert ctm_alg("AES", 256, None) == ("AES", 256, None)
    assert ctm_alg("TDES", 168, None) == ("3DES", 168, None)
    assert ctm_alg("RSA", 4096, None) == ("RSA", 4096, None)
    assert ctm_alg("EC", None, "prime256v1") == ("EC", 256, "P-256")
    assert ctm_alg("EC", None, "ed25519") == ("Ed25519", 256, "Ed25519")
    assert ctm_alg("HMAC-SHA256", None, None) == ("HMAC", 256, None)
    assert ctm_alg("ML-DSA-65", 65, None) == ("ML-DSA", 65, None)
    assert ctm_alg("Blowfish", 128, None)[0] == "unknown"


@responses.activate
def test_ciphertrust(monkeypatch):
    monkeypatch.setenv("CTP", "pw")
    responses.add(responses.POST, f"{CTM}/api/v1/auth/tokens", json={"jwt": "jwt.abc", "duration": 300})
    keys = [
        {
            "id": "1",
            "name": "pan-dek",
            "algorithm": "AES",
            "size": 256,
            "objectType": "Symmetric Key",
            "state": "Active",
            "usageMask": 12 | 1048576 | 2097152,
            "createdAt": "2024-03-01T10:00:00Z",
            "version": 2,
            "unexportable": True,
            "labels": {"pci": "cde"},
            "meta": {"rotationFrequencyDays": 90},
            "application": "payments-api",
            "owner": "local|alice",
        },
        {
            "id": "2",
            "name": "sig",
            "algorithm": "EC",
            "curveid": "secp384r1",
            "objectType": "Private Key",
            "state": "Active",
            "usageMask": 3,
            "createdAt": "2025-01-01T00:00:00Z",
            "version": 0,
            "unexportable": False,
            "deactivationDate": "2027-01-01T00:00:00Z",
        },
        {
            "id": "2p",
            "name": "sig",
            "algorithm": "EC",
            "curveid": "secp384r1",
            "objectType": "Public Key",
            "state": "Active",
            "usageMask": 2,
        },
        {
            "id": "3",
            "name": "legacy",
            "algorithm": "TDES",
            "size": 168,
            "objectType": "Symmetric Key",
            "state": "Deactivated",
            "usageMask": 12,
            "createdAt": "2016-01-01T00:00:00Z",
            "version": 0,
        },
        {
            "id": "4",
            "name": "gone",
            "algorithm": "AES",
            "size": 128,
            "objectType": "Symmetric Key",
            "state": "Destroyed",
            "usageMask": 12,
        },
        {
            "id": "5",
            "name": "tls-cert",
            "objectType": "Certificate",
            "state": "Active",
            "usageMask": 0,
            "createdAt": "2025-05-01T00:00:00Z",
        },
    ]
    responses.add(
        responses.GET, f"{CTM}/api/v1/vault/keys2", json={"skip": 0, "limit": 100, "total": 6, "resources": keys}
    )
    res = CipherTrustCollector(
        source("c", "ciphertrust", url=CTM, username="u", password_env="CTP", domain="pay", hardware_backed=True)
    ).run()
    assert res.error is None, res.error
    by = {a.name: a for a in res.assets}
    assert set(by) == {"pan-dek", "sig", "legacy", "tls-cert"}  # public half and destroyed key filtered
    dek = by["pan-dek"]
    assert dek.algorithm == "AES" and dek.key_size == 256 and dek.exportable is False and dek.hardware_backed
    assert dek.purposes == ["encrypt", "decrypt"] and dek.rotation_enabled is True and dek.tags == {"pci": "cde"}
    assert dek.used_by == [{"type": "application", "id": "payments-api", "via": "ctm-application"},
                           {"type": "user", "id": "local|alice", "via": "ctm-owner"}]  # fmt: skip
    assert dek.last_rotated is not None and by["sig"].last_rotated is None
    assert by["sig"].curve == "P-384" and by["sig"].exportable is True and by["sig"].expires.year == 2027
    assert by["legacy"].algorithm == "3DES" and by["legacy"].state == "deactivated"
    assert by["tls-cert"].kind == KIND_CERTIFICATE
    login = responses.calls[0].request
    assert login.method == "POST" and b'"domain": "pay"' in login.body
    assert responses.calls[1].request.headers["Authorization"] == "Bearer jwt.abc"


@responses.activate
def test_ciphertrust_paging_and_prebuilt_jwt(monkeypatch):
    monkeypatch.setenv("CTJ", "pre.jwt")
    responses.add(
        responses.GET,
        f"{CTM}/api/v1/vault/keys2",
        json={
            "total": 3,
            "resources": [
                {
                    "id": "a",
                    "name": "a",
                    "algorithm": "AES",
                    "size": 128,
                    "objectType": "Symmetric Key",
                    "state": "Active",
                    "usageMask": 4,
                },
                {
                    "id": "b",
                    "name": "b",
                    "algorithm": "AES",
                    "size": 128,
                    "objectType": "Symmetric Key",
                    "state": "Active",
                    "usageMask": 4,
                },
            ],
        },
    )
    responses.add(
        responses.GET,
        f"{CTM}/api/v1/vault/keys2",
        json={
            "total": 3,
            "resources": [
                {
                    "id": "c",
                    "name": "c",
                    "algorithm": "RSA",
                    "size": 2048,
                    "objectType": "Private Key",
                    "state": "Pre-Active",
                    "usageMask": 1,
                }
            ],
        },
    )
    res = CipherTrustCollector(source("c", "ciphertrust", url=CTM, jwt_env="CTJ", page_size=2)).run()
    assert res.error is None and len(res.assets) == 3
    assert next(a for a in res.assets if a.name == "c").state == "pre-activation"
    assert all(c.request.method == "GET" for c in responses.calls)  # no login round-trip
    assert "skip=2" in responses.calls[1].request.url


# ===================================================================== Entrust KeySafe 5
KS5 = "https://ks5.test"


def test_ks5_type_normalisation():
    assert normalise_type("RSAPrivate", 3072, None) == ("RSA", 3072, None, "private-key")
    assert normalise_type("ECDSAPrivate", None, "NISTP256") == ("EC", 256, "P-256", "private-key")
    assert normalise_type("ECDHPublic", 384, "secp384r1") == ("EC", 384, "P-384", "public-key")
    assert normalise_type("Rijndael", 256, None) == ("AES", 256, None, "secret-key")
    assert normalise_type("DES3", None, None) == ("3DES", 192, None, "secret-key")
    assert normalise_type("HMACSHA256", None, None) == ("HMAC", 256, None, "secret-key")
    assert normalise_type("Ed25519Private", None, None) == ("Ed25519", 256, "Ed25519", "private-key")
    assert normalise_type("MLDSA65Private", None, None) == ("ML-DSA", 65, None, "private-key")
    assert normalise_type("Wrapped", 256, None) == ("unknown", 256, None, "secret-key")


@responses.activate
def test_keysafe5(monkeypatch):
    monkeypatch.setenv("KT", "oidc.token")
    responses.add(responses.GET, f"{KS5}/km/v1/keys", status=404, json={"error": "not found"})  # older layout
    responses.add(
        responses.GET,
        f"{KS5}/mgmt/v1/keys",
        json={
            "keys": [
                {
                    "id": "h1",
                    "name": "pan-wrap",
                    "appName": "pkcs11",
                    "type": "Rijndael",
                    "length": 256,
                    "protection": "softcard",
                    "softcard": "payments",
                    "createdAt": "2024-02-02T00:00:00Z",
                    "hsmESNs": ["1234-5678-9ABC"],
                    "exportable": False,
                },
                {
                    "id": "h2",
                    "name": "ca-sign",
                    "appName": "embed",
                    "type": "ECDSAPrivate",
                    "curve": "NISTP384",
                    "protection": "ocs",
                    "cardset": "ca-ops",
                    "createdAt": 1700000000,
                    "hsmESNs": "1234-5678-9ABC, 9999-0000-1111",
                    "keyUsage": "sign,verify",
                },
                {
                    "id": "h3",
                    "name": "old-3des",
                    "appName": "simple",
                    "type": "DES3",
                    "protection": "module",
                    "state": "disabled",
                    "createdAt": "2012-05-05T00:00:00Z",
                },
            ],
            "next": None,
        },
    )
    responses.add(
        responses.GET,
        f"{KS5}/mgmt/v1/hsms",
        json={
            "hsms": [
                {
                    "esn": "1234-5678-9ABC",
                    "model": "nShield 5c",
                    "firmwareVersion": "13.6.3",
                    "mode": "operational",
                    "hostname": "hsm-a",
                }
            ]
        },
    )
    res = KeySafe5Collector(source("k", "keysafe5", url=KS5, auth="bearer", token_env="KT")).run()
    assert res.error is None, res.error
    by = {a.name: a for a in res.assets}
    wrap = by["pan-wrap"]
    assert wrap.algorithm == "AES" and wrap.key_size == 256 and wrap.hardware_backed and wrap.fips_validated
    assert wrap.extra["protection"] == "softcard" and wrap.extra["protector"] == "payments"
    assert wrap.extra["hsms"]["1234-5678-9ABC"]["model"] == "nShield 5c" and wrap.exportable is False
    ca = by["ca-sign"]
    assert ca.algorithm == "EC" and ca.curve == "P-384" and ca.purposes == ["sign", "verify"]
    assert ca.created.year == 2023 and ca.extra["hsm_esns"] == ["1234-5678-9ABC", "9999-0000-1111"]
    assert by["old-3des"].algorithm == "3DES" and by["old-3des"].state == "deactivated"
    assert all(c.request.headers.get("Authorization") == "Bearer oidc.token" for c in responses.calls)


@responses.activate
def test_keysafe5_basic_auth_field_map_and_bare_list(monkeypatch):
    monkeypatch.setenv("KP", "pw")
    responses.add(
        responses.GET,
        f"{KS5}/api/keys",
        json=[{"KeyLabel": "k1", "Algo": "RSAPrivate", "Bits": 2048, "Created": "2024-01-01T00:00:00Z", "Hash": "abc"}],
    )
    res = KeySafe5Collector(
        source(
            "k",
            "keysafe5",
            url=KS5,
            auth="basic",
            username="u",
            password_env="KP",
            keys_path="/api/keys",
            hsms_path=None,
            field_map={"name": "KeyLabel", "type": "Algo", "size": "Bits", "created": "Created", "id": "Hash"},
        )
    ).run()
    assert res.error is None, res.error
    a = res.assets[0]
    assert (
        a.name == "k1" and a.algorithm == "RSA" and a.key_size == 2048 and a.native_id == "abc" and a.kind == KIND_KEY
    )
    assert responses.calls[0].request.headers["Authorization"].startswith("Basic ")
