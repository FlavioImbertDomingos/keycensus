"""Keystores and SSH keys: keyfiles parser and the pem/files collector, against keytool, openssl and ssh-keygen."""

from __future__ import annotations

import subprocess

from keycensus.analysis.policy import Policy, evaluate
from keycensus.collectors import build, keyfiles
from keycensus.model import KIND_CERTIFICATE, KIND_KEY

from .conftest import source
from .keymaterial import need


def _parse(d, name, pw=None):
    return keyfiles.parse((d / name).read_bytes(), name, pw)


@need("keytool")
def test_jks_reads_chains_without_a_password_and_spots_changeit(keymaterial):
    es = _parse(keymaterial, "app.jks", [])
    keys = {e.fields["extra"]["alias"]: e for e in es if e.fields["kind"] == KIND_KEY}
    certs = [e for e in es if e.fields["kind"] == KIND_CERTIFICATE]
    assert (keys["web"].fields["algorithm"], keys["web"].fields["key_size"]) == ("RSA", 2048)
    assert (keys["sign"].fields["algorithm"], keys["sign"].fields["curve"]) == ("EC", "P-384")
    assert {c.fields["subject"] for c in certs} == {"CN=web.example.com", "CN=signer"}
    assert "opens with a well-known password" in keys["web"].weak_protection
    assert any("SHA-1 keystream" in r for r in keys["web"].weak_protection)
    assert keys["web"].fields["created"] is not None  # JKS records when each entry was added


@need("keytool")
def test_jks_with_an_unknown_password_is_still_read(keymaterial):
    es = _parse(keymaterial, "trust.jks")
    assert len(es) == 1 and es[0].fields["extra"]["trusted_entry"] is True
    assert es[0].fields["extra"]["integrity_password_unknown"] is True
    assert not any("well-known" in r for r in es[0].weak_protection)
    assert "integrity_password_unknown" not in _parse(keymaterial, "trust.jks", ["s3cr3t-Pw"])[0].fields["extra"]


@need("keytool")
def test_jceks_secret_keys(keymaterial):
    es = _parse(keymaterial, "hadoop.jceks")
    secret = next(e for e in es if e.fields["key_type"] == "secret-key")
    assert secret.fields["extra"]["seal_algorithm"] == "PBEWithMD5AndTripleDES"
    assert any(e.fields.get("curve") == "P-256" for e in es)  # the entry after the sealed object parsed too


@need("keytool")
def test_modern_pkcs12_needs_its_password(keymaterial):
    locked = _parse(keymaterial, "modern.p12")
    assert len(locked) == 1 and locked[0].fields["extra"]["locked"] is True
    assert locked[0].fields["extra"]["mac"] == "sha256" and locked[0].weak_protection == []
    opened = _parse(keymaterial, "modern.p12", ["Str0ng-pass"])
    key = next(e for e in opened if e.fields["kind"] == KIND_KEY)
    assert (key.fields["algorithm"], key.fields["key_size"], key.fields["extra"]["alias"]) == ("RSA", 3072, "tls")
    assert key.weak_protection == []


@need("openssl")
def test_legacy_pkcs12_protection(keymaterial):
    es = _parse(keymaterial, "legacy.p12")
    key = next(e for e in es if e.fields["kind"] == KIND_KEY)
    assert "rc2-40" in key.fields["extra"]["ciphers"] and "3DES" in key.fields["extra"]["ciphers"]
    assert {"integrity MAC uses SHA1", "opens with a well-known password"} <= set(key.weak_protection)
    locked = _parse(keymaterial, "locked.p12")
    assert locked[0].fields["extra"]["locked"] and locked[0].weak_protection == []


@need("ssh-keygen")
def test_ssh_keys(keymaterial):
    ed = _parse(keymaterial, "id_ed25519")[0].fields
    assert ed["algorithm"] == "Ed25519" and ed["extra"]["passphrase_protected"] is False
    assert ed["extra"]["ssh_role"] == "user-key"
    rsa = _parse(keymaterial, "id_rsa")[0].fields
    assert (rsa["key_size"], rsa["extra"]["ssh_cipher"]) == (3072, "aes256-ctr")
    host = _parse(keymaterial, "ssh_host_rsa_key.pub")[0].fields
    assert host["extra"]["ssh_role"] == "host-key" and host["key_size"] == 1024
    out = subprocess.run(["ssh-keygen", "-lf", str(keymaterial / "id_rsa.pub")], capture_output=True, text=True)
    assert rsa["extra"]["ssh_fingerprint"] == out.stdout.split()[1]  # same fingerprint as ssh-keygen

    ak = _parse(keymaterial, "authorized_keys")
    assert [e.fields["extra"]["ssh_role"] for e in ak] == ["authorized-key"] * 2
    assert ak[0].fields["extra"]["options"] == 'command="/bin/true",no-pty'
    kh = {e.fields["extra"]["hosts"]: e.fields for e in _parse(keymaterial, "known_hosts")}
    assert set(kh) == {"github.com", "(hashed)", "*.example.com"} and kh["*.example.com"]["extra"]["marker"]

    cert = _parse(keymaterial, "id_ed25519-cert.pub")[0].fields
    assert cert["kind"] == KIND_CERTIFICATE and cert["extra"]["principals"] == ["alice", "root"]
    assert cert["expires"] is not None and cert["issuer"].startswith("ssh-ca SHA256:")


@need("keytool", "openssl", "ssh-keygen")
def test_files_collector_and_findings(keymaterial):
    result = build(source("disk", "files", paths=[str(keymaterial)],
                          keystore_passwords=[{"password": "Str0ng-pass"}])).run()  # fmt: skip
    assert result.error is None
    by_loc = {}
    for a in result.assets:
        by_loc.setdefault(a.location.rsplit("/", 1)[-1], []).append(a)
    assert {"app.jks", "hadoop.jceks", "modern.p12", "legacy.p12", "id_rsa", "known_hosts", "l.key"} <= set(by_loc)
    assert len({a.id for a in result.assets}) == len(result.assets)  # ids unique
    assert by_loc["l.key"][0].native_id == str(keymaterial / "l.key")  # plain PEM keys keep their old id
    findings = evaluate(result.assets, Policy.default())
    weak = {f.asset_name for f in findings if f.rule_id == "keystore-weak-protection"}
    assert "app.jks:web" in weak and "legacy.p12" in weak and not any("modern.p12" in n for n in weak)
    weak = [f for f in findings if f.rule_id == "weak-key-size"]
    assert any(f.asset_name == "ssh_host_rsa_key" for f in weak)  # the private host key
    assert any(f.asset_name == "(hashed)" for f in weak)  # the same key trusted in known_hosts
    pub = next(a for a in result.assets if a.location.endswith("ssh_host_rsa_key.pub"))
    assert not any(f.asset_id == pub.id for f in findings)  # the .pub is folded into its private key


def test_garbage_is_ignored():
    assert keyfiles.parse(b"hello world\n" * 10, "notes.txt") == []
    assert keyfiles.looks_like_key_material(b"just some config\n" * 5) is False
