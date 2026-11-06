"""CycloneDX 1.7 output: schema validity, Cryptography Registry names, and 1.6 left as it was."""

import datetime as dt
import json

import pytest
from click.testing import CliRunner
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from keycensus import registry
from keycensus.analysis.policy import Policy, evaluate
from keycensus.cli import main
from keycensus.collectors.code import _java_sig, _rsa_padding, cipher_spec
from keycensus.config import ConfigError, load
from keycensus.exporters import cbom, render_format
from keycensus.model import KIND_CERTIFICATE, Inventory, SourceResult, utcnow

from .conftest import FIXTURES, make_asset

CDX17 = FIXTURES / "cdx-1.7"


@pytest.fixture(scope="module")
def validator17():
    def res(name):
        return Resource.from_contents(json.loads((CDX17 / name).read_text()))

    deps = ["cryptography-defs.schema.json", "jsf-0.82.schema.json", "spdx.schema.json"]
    reg = Registry().with_resources(
        [(n, res(n)) for n in deps] + [(f"http://cyclonedx.org/schema/{n}", res(n)) for n in deps]
    )
    return Draft7Validator(json.loads((CDX17 / "bom-1.7.schema.json").read_text()), registry=reg)


@pytest.fixture
def wide_inventory(sample_inventory) -> Inventory:
    """The exporter sample plus one asset per registry family keycensus can name."""
    now = utcnow()

    def k(name, **kw):
        return make_asset(name=name, native_id=name, state="active", created=now, **kw)

    extra = [
        k(
            "rsa-oaep",
            algorithm="RSA",
            key_size=3072,
            purposes=["encrypt"],
            extra={"scheme": "OAEP", "hash": "SHA-256"},
        ),
        k("rsa-pss", algorithm="RSA", key_size=4096, purposes=["sign"], extra={"scheme": "PSS"}),
        k("rsa-pkcs1-enc", algorithm="RSA", key_size=2048, purposes=["encrypt"], extra={"scheme": "PKCS1"}),
        k("ecdh", algorithm="EC", curve="P-384", purposes=["derive"]),
        k("ec-both", algorithm="EC", curve="secp256k1", purposes=["sign", "derive"]),
        k("ed", algorithm="Ed25519", purposes=["sign"]),
        k("x", algorithm="X25519", purposes=["derive"]),
        k("aes-gcm", algorithm="AES", key_size=128, extra={"mode": "GCM"}),
        k("aes-wrap", algorithm="AES", key_size=256, purposes=["wrap"]),
        k("chacha", algorithm="ChaCha20-Poly1305", key_size=256),
        k("hmac", algorithm="HMAC", key_size=256, purposes=["sign"], extra={"hash": "SHA-384"}),
        k("mlkem", algorithm="ML-KEM", key_size=768),
        k("mldsa", algorithm="ML-DSA", key_size=65),
        k("dsa", algorithm="DSA", key_size=2048, purposes=["sign"]),
        k("rc4", algorithm="RC4", key_size=128),
        k("brainpool", algorithm="EC", curve="brainpoolP256r1", purposes=["sign"]),
        make_asset(
            kind=KIND_CERTIFICATE,
            name="rsa-cert",
            native_id="rsa-cert",
            algorithm="RSA",
            key_size=2048,
            key_type="public-key",
            purposes=["sign"],
            subject="CN=r",
            issuer="CN=ca",
            signature_algorithm="sha256WithRSAEncryption",
            created=now,
            expires=now + dt.timedelta(days=90),
        ),  # fmt: skip
    ]
    inv = Inventory(
        generated_at=now, sources=[*sample_inventory.sources, SourceResult(name="w", type="test", assets=extra)]
    )
    inv.findings = evaluate(inv.assets, Policy.default())
    return inv


def _errors(validator, bom):
    return [f"{list(e.path)}: {e.message[:160]}" for e in validator.iter_errors(bom)]


def test_17_validates_against_the_17_schema(wide_inventory, validator17):
    bom = cbom.build(wide_inventory, "1.7")
    assert bom["specVersion"] == "1.7"
    assert bom["$schema"] == "http://cyclonedx.org/schema/bom-1.7.schema.json"
    errors = _errors(validator17, bom)
    assert not errors, "\n".join(errors)


def test_17_uses_registry_families_names_and_curves(wide_inventory):
    bom = cbom.build(wide_inventory, "1.7")
    fams = registry.families()
    algs = [c for c in bom["components"] if c["cryptoProperties"]["assetType"] == "algorithm"]
    seen = set()
    for c in algs:
        ap = c["cryptoProperties"]["algorithmProperties"]
        assert "curve" not in ap, "1.7 uses ellipticCurve"
        if "algorithmFamily" in ap:
            fam = ap["algorithmFamily"]
            seen.add(fam)
            assert fam in fams
            assert registry.matches_family(c["name"], fam), (c["name"], fam)
        if "ellipticCurve" in ap:
            assert ap["ellipticCurve"] in registry.curves()
    assert {"RSAES-OAEP", "RSASSA-PSS", "RSAES-PKCS1", "RSASSA-PKCS1", "ECDH", "ECDSA", "EdDSA", "AES",
            "ChaCha20", "HMAC", "ML-KEM", "ML-DSA", "DSA", "RC4"} <= seen  # fmt: skip


def test_17_leaves_ambiguous_families_unset_and_says_why(wide_inventory):
    bom = cbom.build(wide_inventory, "1.7")
    by_name = {c["name"]: c for c in bom["components"]}
    unresolved = [
        c for c in by_name.values()
        if c["cryptoProperties"]["assetType"] == "algorithm"
        and "algorithmFamily" not in c["cryptoProperties"]["algorithmProperties"]
    ]  # fmt: skip
    notes = {p["value"] for c in unresolved for p in c.get("properties", []) if p["name"] == "keycensus:registryNote"}
    assert any("padding scheme" in n for n in notes)  # rsa-old has no scheme
    assert any("ECDSA or ECDH" in n for n in notes)  # ec-both


def test_17_relationships_replace_deprecated_refs(wide_inventory):
    bom = cbom.build(wide_inventory, "1.7")
    text = json.dumps(bom)
    for old in ("algorithmRef", "subjectPublicKeyRef", "signatureAlgorithmRef", '"curve"'):
        assert old not in text
    refs = {c["bom-ref"] for c in bom["components"]}
    cert = next(c for c in bom["components"] if c["name"] == "rsa-cert")
    rel = cert["cryptoProperties"]["certificateProperties"]["relatedCryptographicAssets"]
    assert {r["type"] for r in rel} == {"publicKeyAlgorithm", "signatureAlgorithm"}
    assert all(r["ref"] in refs for r in rel)
    sig = next(
        c for c in bom["components"] if c["bom-ref"] == next(r["ref"] for r in rel if r["type"] == "signatureAlgorithm")
    )
    assert sig["name"] == "RSA-PKCS1-1.5-SHA-256"
    key = next(c for c in bom["components"] if c["name"] == "rsa-oaep")
    (r,) = key["cryptoProperties"]["relatedCryptoMaterialProperties"]["relatedCryptographicAssets"]
    assert r["type"] == "algorithm" and r["ref"] in refs
    assert next(c for c in bom["components"] if c["bom-ref"] == r["ref"])["name"] == "RSA-OAEP-SHA-256-3072"


def test_16_is_still_the_default_and_still_valid(wide_inventory, cdx_validator):
    bom = cbom.build(wide_inventory)
    assert bom["specVersion"] == "1.6" and "$schema" not in bom
    errors = _errors(cdx_validator, bom)
    assert not errors, "\n".join(errors)
    text = json.dumps(bom)
    assert "algorithmFamily" not in text and "relatedCryptographicAssets" not in text
    rsa = next(c for c in bom["components"] if c["name"] == "rsa-oaep")
    assert "algorithmRef" in rsa["cryptoProperties"]["relatedCryptoMaterialProperties"]
    props = {p["name"]: p["value"] for c in bom["components"] for p in c.get("properties", [])}
    assert "keycensus:registryName" in props


def test_unknown_version_is_refused(sample_inventory):
    with pytest.raises(ValueError):
        cbom.build(sample_inventory, "1.5")


def test_cli_and_config_choose_the_version(cert_dir, tmp_path):
    cfg = tmp_path / "c.yml"
    cfg.write_text(f"sources:\n  - name: certs\n    type: pem\n    paths: ['{cert_dir}']\n")
    out = tmp_path / "a"
    r = CliRunner().invoke(main, ["scan", "-c", str(cfg), "-o", str(out), "-f", "cbom", "--cbom-version", "1.7"])
    assert r.exit_code == 0, r.output
    assert json.loads((out / "cbom.json").read_text())["specVersion"] == "1.7"

    cfg.write_text(cfg.read_text() + "cbom:\n  version: '1.7'\n")
    assert load(cfg).cbom_version == "1.7"
    out = tmp_path / "b"
    r = CliRunner().invoke(main, ["scan", "-c", str(cfg), "-o", str(out), "-f", "cbom"])
    assert r.exit_code == 0, r.output
    assert json.loads((out / "cbom.json").read_text())["specVersion"] == "1.7"

    cfg.write_text(cfg.read_text().replace("'1.7'", "'1.5'"))
    with pytest.raises(ConfigError, match="1.5"):
        load(cfg)


def test_render_format_passes_the_version(sample_inventory):
    assert json.loads(render_format("cbom", sample_inventory, cbom_version="1.7"))["specVersion"] == "1.7"
    assert json.loads(render_format("cbom", sample_inventory))["specVersion"] == "1.6"


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", {"scheme": "OAEP", "hash": "SHA-256"}),
        ("RSA/ECB/OAEPPadding", {"scheme": "OAEP", "hash": "SHA-1"}),
        ("RSA/ECB/PKCS1Padding", {"scheme": "PKCS1"}),
        ("RSA/ECB/NoPadding", {}),
    ],
)
def test_code_rsa_padding(spec, expected):
    assert _rsa_padding(spec) == expected
    assert cipher_spec(spec, False)["algorithm"] == "RSA"


def test_code_signature_schemes():
    (rsa,) = _java_sig("SHA256withRSA")
    assert (rsa["scheme"], rsa["hash"]) == ("PKCS1", "SHA-256")
    (pss,) = _java_sig("SHA384withRSA/PSS")
    assert pss["scheme"] == "PSS"
    (ec,) = _java_sig("SHA384withECDSA")
    assert ec["algorithm"] == "EC" and ec["hash"] == "SHA-384" and "scheme" not in ec
    assert _java_sig("RSASSA-PSS")[0]["scheme"] == "PSS"


def test_code_scan_names_rsa_families_and_validates(validator17):
    """tests/fixtures/code-padding compiles with javac, go and node; each RSA call says its padding."""
    from keycensus.collectors import build

    from .conftest import source

    r = build(source("repo", "code", paths=[str(FIXTURES / "code-padding")])).run()
    assert r.error is None, r.error
    fams = {registry.normalise(a).family for a in r.assets if a.kind == "algorithm"}
    assert {"RSAES-OAEP", "RSASSA-PKCS1", "RSASSA-PSS", "ECDSA"} <= fams
    inv = Inventory(generated_at=utcnow(), sources=[r])
    inv.findings = evaluate(inv.assets, Policy.default())
    bom = cbom.build(inv, "1.7")
    errors = _errors(validator17, bom)
    assert not errors, "\n".join(errors)
    names = {c["name"] for c in bom["components"]}
    assert {"RSA-OAEP-SHA-256-3072", "RSA-PKCS1-1.5-SHA-256", "RSA-PSS-SHA-384-2048"} <= names


def test_aws_kms_rsa_encryption_keys_are_oaep():
    import boto3
    from moto import mock_aws

    from keycensus.collectors import build

    from .conftest import source

    with mock_aws():
        kms = boto3.client("kms", region_name="us-east-1")
        kms.create_key(KeySpec="RSA_3072", KeyUsage="ENCRYPT_DECRYPT")
        kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")
        r = build(source("aws", "aws-kms", regions=["us-east-1"])).run()
    by_usage = {a.extra["key_usage"]: a for a in r.assets if a.algorithm == "RSA"}
    assert registry.normalise(by_usage["ENCRYPT_DECRYPT"]).family == "RSAES-OAEP"
    assert registry.normalise(by_usage["SIGN_VERIFY"]).family is None  # PSS or PKCS1, chosen per call
