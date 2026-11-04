"""Code scanning: crypto API calls in the sample repo (each file compiles with javac, go, node, gcc, python),
and private keys pasted into source the ways people paste them."""

from __future__ import annotations

import shutil

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from keycensus.analysis.policy import Policy, evaluate
from keycensus.collectors import build
from keycensus.collectors.code import cipher_spec, hash_name, normalise_pem_literal
from keycensus.exporters import cbom
from keycensus.model import KIND_ALGORITHM, KIND_KEY, Inventory, SourceResult, utcnow

from .conftest import FIXTURES, make_cert, pem, source
from .test_exporters import cdx_validator  # noqa: F401  (fixture)

SAMPLE = FIXTURES / "code-sample"


def _scan(path, **opts):
    r = build(source("repo", "code", paths=[str(path)], **opts)).run()
    assert r.error is None, r.error
    return r


def _groups(r):
    return {a.name.rsplit(" in ", 1)[0]: a for a in r.assets if a.kind == KIND_ALGORITHM}


def test_naming_helpers():
    assert cipher_spec("AES/GCM/NoPadding") == {
        "algorithm": "AES",
        "key_size": None,
        "mode": "GCM",
        "purpose": "encrypt",
    }
    assert cipher_spec("AES", java_default_ecb=True)["mode"] == "ECB"
    assert cipher_spec("aes-256-cbc")["key_size"] == 256
    assert cipher_spec("des_ede3_cbc")["algorithm"] == "3DES"
    assert cipher_spec("chacha20-poly1305", java_default_ecb=True)["mode"] == "POLY1305"
    assert cipher_spec("rc4", java_default_ecb=True)["mode"] is None
    assert cipher_spec("whirlpool") is None
    assert [hash_name(x) for x in ("md5", "SHA-1", "sha256", "SHA3_384", "SHA-512/256", "crc32")] == [
        "MD5", "SHA-1", "SHA-256", "SHA3-384", "SHA-512/256", None]  # fmt: skip


def test_api_usage_across_languages():
    g = _groups(_scan(SAMPLE))
    md5 = g["MD5"]
    assert md5.extra["occurrence_count"] == 4 and set(md5.extra["languages"]) == {"python", "go", "csharp"}
    assert {(o["file"], o["line"]) for o in md5.extra["occurrences"]} >= {("app.py", 12), ("cmd/svc/main.go", 21)}
    assert [o for o in md5.extra["occurrences"] if o.get("test")] == [
        {"file": "tests/digest_helpers.py", "line": 5, "api": "hashlib", "language": "python", "test": True}]  # fmt: skip
    assert not any(o["line"] == 16 for o in g["SHA-1"].extra["occurrences"] if o["file"] == "app.py")  # ignored line
    assert not any(o["line"] == 34 for o in md5.extra["occurrences"] if o["file"] == "app.py")  # comment

    ecb = g["AES/ECB"]
    assert {o["language"] for o in ecb.extra["occurrences"]} == {
        "python",
        "java",
        "csharp",
    }  # incl. Cipher.getInstance("AES")
    assert "AES-128/ECB" in g and "AES-256/GCM" in g and "AES/GCM" in g
    assert g["3DES-168/CBC"].extra["occurrence_count"] == 3
    assert {"RSA-1024", "RSA-2048", "RSA-3072", "RSA-4096", "EC-P-256", "EC-P-384", "X25519", "ML-KEM-768"} <= set(g)
    assert g["ML-KEM-768"].purposes == ["derive"] and g["X25519"].purposes == ["derive"]
    assert not any(
        a.extra["only_in_tests"] for a in g.values() if a.name.startswith("RSA-1024")
    )  # com/example is not a test dir


def test_findings_from_code():
    r = _scan(SAMPLE)
    rules = {(f.rule_id, f.asset_name.rsplit(" in ", 1)[0]) for f in evaluate(r.assets, Policy.default())}
    assert {("weak-hash", "MD5"), ("weak-hash", "SHA-1"), ("weak-cipher-mode", "AES/ECB"),
            ("weak-cipher-mode", "AES-128/ECB"), ("weak-key-size", "RSA-1024"), ("weak-algorithm", "3DES-168/CBC"),
            ("quantum-vulnerable", "RSA-2048"), ("quantum-vulnerable-encryption", "X25519")} <= rules  # fmt: skip
    assert not any(n == "ML-KEM-768" for _, n in rules)
    assert not any(n in ("SHA-256", "AES-256/GCM") and rid.startswith(("weak", "quantum-vuln")) for rid, n in rules)


def _hardcoded_repo(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(SAMPLE, repo)
    rsa_pem = (
        rsa.generate_private_key(65537, 2048)
        .private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        )
        .decode()
    )
    ec_pem = (
        ec.generate_private_key(ec.SECP256R1())
        .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        .decode()
    )
    ssh = (
        ed25519.Ed25519PrivateKey.generate()
        .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
        .decode()
    )
    escaped = rsa_pem.strip().replace("\n", "\\n")
    (repo / "settings.py").write_text(f'API_SIGNING_KEY = "{escaped}"\n')
    java_lines = ec_pem.strip().splitlines()
    concat = " +\n        ".join(f'"{ln}\\n"' for ln in java_lines)
    (repo / "src/main/java/com/example/Keys.java").write_text(
        f"package com.example;\n\nclass Keys {{\n    static final String KEY =\n        {concat};\n}}\n"
    )
    yaml_block = "\n".join("    " + ln for ln in ssh.strip().splitlines())
    (repo / "deploy.yaml").write_text(f"deploy:\n  ssh_key: |\n{yaml_block}\n")
    (repo / "README.md").write_text(
        "Put your key here:\n\n-----BEGIN PRIVATE KEY-----\nREPLACE_ME\n-----END PRIVATE KEY-----\n"
    )
    k, cert = make_cert("bundle")
    (repo / "ca.pem").write_bytes(pem(cert))  # a certificate in a repo is not a secret
    (repo / "keystore.p12").write_bytes(pkcs12.serialize_key_and_certificates(
        b"app", k, cert, None, serialization.BestAvailableEncryption(b"changeit")))  # fmt: skip
    (repo / "tests" / "fixture_key.pem").write_text(ec_pem)
    (repo / "ignored.py").write_text(f'# keycensus:ignore\nK = """{ec_pem}"""\n')
    return repo


def test_hardcoded_keys(tmp_path):
    repo = _hardcoded_repo(tmp_path)
    r = _scan(repo)
    keys = {a.extra["file"]: a for a in r.assets if a.kind == KIND_KEY}
    assert set(keys) == {"settings.py", "src/main/java/com/example/Keys.java", "deploy.yaml", "keystore.p12",
                         "tests/fixture_key.pem"}  # fmt: skip
    assert (keys["settings.py"].algorithm, keys["settings.py"].key_size, keys["settings.py"].extra["line"]) == (
        "RSA",
        2048,
        1,
    )
    assert keys["src/main/java/com/example/Keys.java"].curve == "P-256"
    assert keys["src/main/java/com/example/Keys.java"].extra["line"] == 5
    assert keys["deploy.yaml"].algorithm == "Ed25519" and keys["deploy.yaml"].extra["line"] == 3
    assert "opens with a well-known password" in keys["keystore.p12"].extra["keystore_weak_protection"]
    assert keys["tests/fixture_key.pem"].extra["test_path"] is True
    findings = [f for f in evaluate(r.assets, Policy.default()) if f.rule_id == "hardcoded-private-key"]
    assert len(findings) == 5 and all(f.severity == "critical" for f in findings)
    assert any("test path" in f.detail for f in findings)
    # the inventory never contains the key itself
    blob = str([a.to_dict() for a in r.assets])
    assert "PRIVATE KEY" not in blob and "MII" not in blob


def test_options(tmp_path):
    repo = _hardcoded_repo(tmp_path)
    r = _scan(repo, api_usage=False, exclude=["deploy.yaml"], skip_tests=True)
    assert not any(a.kind == KIND_ALGORITHM for a in r.assets)
    files = {a.extra["file"] for a in r.assets}
    assert "deploy.yaml" not in files and "tests/fixture_key.pem" not in files
    r = _scan(repo, hardcoded_keys=False)
    assert all(a.kind == KIND_ALGORITHM for a in r.assets)
    with pytest.raises(AssertionError):
        _scan(tmp_path / "missing")


def test_normalise_rejects_placeholders():
    assert normalise_pem_literal("PRIVATE KEY", "\\nREPLACE_ME\\n") is None


def test_cbom_carries_call_sites(tmp_path, cdx_validator):  # noqa: F811
    r = _scan(_hardcoded_repo(tmp_path))
    inv = Inventory(generated_at=utcnow(), sources=[SourceResult(name="repo", type="code", assets=r.assets)])
    inv.findings = evaluate(r.assets, Policy.default())
    bom = cbom.build(inv)
    errors = [f"{list(e.path)}: {e.message[:160]}" for e in cdx_validator.iter_errors(bom)]
    assert not errors, "\n".join(errors[:10])
    algs = [c for c in bom["components"] if c.get("evidence") and c["cryptoProperties"]["assetType"] == "algorithm"]
    ecb = next(c for c in algs if c["name"] == "AES/ECB")
    assert ecb["cryptoProperties"]["algorithmProperties"]["mode"] == "ecb"
    assert {"location": "app.py", "line": 29, "additionalContext": "cryptography Cipher (python)"} in ecb["evidence"][
        "occurrences"
    ]
    hard = [c for c in bom["components"] if c["cryptoProperties"]["assetType"] == "related-crypto-material"
            and c.get("evidence")]  # fmt: skip
    assert {c["evidence"]["occurrences"][0]["location"] for c in hard} >= {"settings.py", "deploy.yaml"}
