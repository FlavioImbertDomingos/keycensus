"""Asset identity: one certificate or key pair seen in several places, and the relationships between them."""

import base64
import datetime as dt
import json
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from keycensus import identity
from keycensus.analysis.policy import Policy, evaluate
from keycensus.changes import classify
from keycensus.collectors import build
from keycensus.collectors.azure_keyvault import jwk_public_key_sha256
from keycensus.collectors.vault import _transit_public_key_sha256
from keycensus.collectors.x509util import spki_sha256
from keycensus.diff import diff_dicts, render_text
from keycensus.exporters import cbom, html_report
from keycensus.model import Inventory, utcnow

from .conftest import make_asset, source
from .test_cyclonedx17 import validator17  # noqa: F401


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def ca_and_leaf():
    """A CA certificate and a leaf it issued, with subject and authority key identifiers, as a real CA does."""
    now = dt.datetime.now(dt.UTC)
    ca_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), rsa.generate_private_key(65537, 2048)
    ca = (x509.CertificateBuilder().subject_name(_name("Unit Root CA")).issuer_name(_name("Unit Root CA"))
          .public_key(ca_key.public_key()).serial_number(1).not_valid_before(now)
          .not_valid_after(now + dt.timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))  # fmt: skip
    leaf = (x509.CertificateBuilder().subject_name(_name("web.example.com")).issuer_name(ca.subject)
            .public_key(leaf_key.public_key()).serial_number(2).not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=90))
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))  # fmt: skip
    return ca, leaf, leaf_key


def _pem(obj):
    if isinstance(obj, x509.Certificate):
        return obj.public_bytes(serialization.Encoding.PEM)
    return obj.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())  # fmt: skip


def rescan(tmp_path):
    return [build(source(n, "pem", paths=[str(tmp_path / n)])).run() for n in ("app", "ingress")]


def estate(tmp_path):
    """The leaf certificate in two places (an app folder and an ingress folder), its key next to the first
    copy, its public key on its own, and the CA certificate: two sources, real files."""
    ca, leaf, leaf_key = ca_and_leaf()
    app, ing = tmp_path / "app", tmp_path / "ingress"
    app.mkdir()
    ing.mkdir()
    (app / "web.crt").write_bytes(_pem(leaf))
    (app / "web.key").write_bytes(_pem(leaf_key))
    (app / "web.pub").write_bytes(leaf_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))  # fmt: skip
    (ing / "tls.crt").write_bytes(_pem(leaf))
    (ing / "ca.crt").write_bytes(_pem(ca))
    results = [
        build(source("app", "pem", paths=[str(app)])).run(),
        build(source("ingress", "pem", paths=[str(ing)])).run(),
    ]
    inv = Inventory(generated_at=utcnow(), sources=results)
    inv.findings = evaluate(inv.assets, Policy.default())
    return inv, leaf, leaf_key


def by_name(idents, name, kind):
    return next(i for i in idents if i.name == name and i.kind == kind)


# ----------------------------------------------------------------------------- grouping
def test_the_same_certificate_in_two_places_is_one_identity(tmp_path):
    inv, leaf, _ = estate(tmp_path)
    idents = identity.group(inv.assets)
    web = by_name(idents, "web.example.com", "certificate")
    assert web.basis == identity.BASIS_CERT and web.places == 2
    assert {o["source"] for o in web.observations} == {"app", "ingress"}
    s = inv.summary()
    assert s["assets"] == len(inv.assets) and s["assets_distinct"] == len(idents) < len(inv.assets)
    assert s["assets_in_several_places"] == 2  # the certificate (two folders) and the key pair (.key and .pub)


def test_a_private_key_and_its_public_key_are_one_key_pair(tmp_path):
    inv, _, leaf_key = estate(tmp_path)
    keys = [i for i in identity.group(inv.assets) if i.kind == "key"]
    assert len(keys) == 1
    assert keys[0].key == f"key:{spki_sha256(leaf_key)}"
    assert sorted(o["key_type"] for o in keys[0].observations) == ["private-key", "public-key"]


def test_names_never_merge_identities():
    a = make_asset(name="payments", native_id="1", source="hsm-a")
    b = make_asset(name="payments", native_id="2", source="hsm-b")
    assert len(identity.group([a, b])) == 2


def test_aws_multi_region_replicas_are_one_key():
    def kms(region):
        arn = f"arn:aws:kms:{region}:111122223333:key/mrk-1a2b"
        return make_asset(source="aws", source_type="aws-kms", name="mrk", native_id=arn, location=region,
                          extra={"key_id": "mrk-1a2b", "multi_region": True})  # fmt: skip

    (ident,) = identity.group([kms("us-east-1"), kms("eu-west-1")])
    assert ident.basis == identity.BASIS_MRK and ident.places == 2 and ident.key == "aws-mrk:111122223333:mrk-1a2b"


def test_key_store_public_keys_match_the_same_key_elsewhere():
    k = rsa.generate_private_key(65537, 2048)
    n = k.public_key().public_numbers()

    def b64(i):
        return base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).decode().rstrip("=")

    assert jwk_public_key_sha256({"kty": "RSA-HSM", "n": b64(n.n), "e": b64(n.e)}) == spki_sha256(k)
    e = ec.generate_private_key(ec.SECP384R1())
    pn = e.public_key().public_numbers()
    assert jwk_public_key_sha256({"kty": "EC", "crv": "P-384", "x": b64(pn.x), "y": b64(pn.y)}) == spki_sha256(e)
    assert jwk_public_key_sha256({"kty": "oct", "k": "AAAA"}) is None
    pem = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert _transit_public_key_sha256({"2": {"public_key": pem.decode()}}, 2) == spki_sha256(k)
    ed = ed25519.Ed25519PrivateKey.generate()
    raw = base64.b64encode(ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    assert _transit_public_key_sha256({"1": {"public_key": raw.decode()}}, "1") == spki_sha256(ed)
    assert _transit_public_key_sha256({"1": {"creation_time": "x"}}, 1) is None


# ----------------------------------------------------------------------------- relationships
def test_relationships_certifies_and_issued_by(tmp_path):
    inv, _, _ = estate(tmp_path)
    idents = identity.group(inv.assets)
    rels = {(r["type"], r["from"], r["to"]) for r in identity.relationships(inv.assets, idents)}
    web, key = by_name(idents, "web.example.com", "certificate"), next(i for i in idents if i.kind == "key")
    ca = by_name(idents, "Unit Root CA", "certificate")
    assert ("certifies", web.id, key.id) in rels
    assert ("issued-by", web.id, ca.id) in rels
    assert not any(t == "issued-by" and f == ca.id for t, f, _ in rels)  # a root is not issued by itself


def test_azure_certificate_is_backed_by_its_key():
    vault = "https://v.vault.azure.net"
    key = make_asset(source="kv", source_type="azure-keyvault", name="web", native_id=f"{vault}/keys/web")
    cert = make_asset(source="kv", source_type="azure-keyvault", kind="certificate", name="web",
                      native_id=f"{vault}/certificates/web", extra={"kid": f"{vault}/keys/web/0a1b2c"})  # fmt: skip
    idents = identity.group([key, cert])
    (rel,) = identity.relationships([key, cert], idents)
    assert rel["type"] == "backed-by" and rel["evidence"] == "Key Vault certificate kid"


# ----------------------------------------------------------------------------- outputs
def test_inventory_json_names_identities_and_relationships(tmp_path):
    inv, _, _ = estate(tmp_path)
    d = inv.to_dict()
    assert all(a["identity"].startswith("ki-") for a in d["assets"])
    assert [i["name"] for i in d["identities"] if i["kind"] == "certificate"] == ["web.example.com"]
    assert {r["type"] for r in d["relationships"]} == {"certifies", "issued-by"}
    assert (
        Inventory.from_dict(json.loads(json.dumps(d))).summary()["assets_distinct"] == d["summary"]["assets_distinct"]
    )


def test_cbom_has_one_component_per_identity_with_each_place(tmp_path, cdx_validator, validator17):  # noqa: F811
    inv, _, _ = estate(tmp_path)
    for version, validator in (("1.6", cdx_validator), ("1.7", validator17)):
        bom = cbom.build(inv, version)
        errors = [f"{list(e.path)}: {e.message[:160]}" for e in validator.iter_errors(bom)]
        assert not errors, "\n".join(errors[:10])
        webs = [c for c in bom["components"] if c["name"] == "web.example.com"]
        assert len(webs) == 1
        web = webs[0]
        assert web["bom-ref"].startswith("ki-") and web["group"] == "app,ingress"
        assert len(web["evidence"]["occurrences"]) == 2
        refs = {c["bom-ref"] for c in bom["components"]}
        deps = {d["ref"]: set(d["dependsOn"]) for d in bom["dependencies"]}
        key_ref = next(c["bom-ref"] for c in bom["components"]
                       if c["cryptoProperties"]["assetType"] == "related-crypto-material")  # fmt: skip
        ca_ref = next(c["bom-ref"] for c in bom["components"] if c["name"] == "Unit Root CA")
        assert {key_ref, ca_ref} <= deps[web["bom-ref"]]
        assert all(t in refs for targets in deps.values() for t in targets)
        assert all(v["affects"][0]["ref"] in refs for v in bom["vulnerabilities"])


def test_a_single_record_keeps_its_asset_id_as_bom_ref(sample_inventory):
    bom = cbom.build(sample_inventory)
    ids = {a.id for a in sample_inventory.assets}
    assert not any(c["bom-ref"].startswith("ki-") for c in bom["components"])
    assert ids & {c["bom-ref"] for c in bom["components"]}


def test_executive_summary_counts_each_identity_once(tmp_path):
    inv, _, _ = estate(tmp_path)
    ex = inv.executive()
    assert ex["keys_and_certificates"] == 3  # the leaf, the CA and the key pair, whatever the number of copies
    names = [a.name for a in identity.group(inv.assets)]
    assert names.count("web.example.com") == 1


def test_report_lists_places_and_relationships(tmp_path):
    inv, _, _ = estate(tmp_path)
    html = html_report.render(inv)
    assert "Seen in more than one place (2)" in html and "issued-by" in html and "distinct assets" in html


def test_a_copy_that_goes_away_is_not_a_deletion(tmp_path):
    inv, _, _ = estate(tmp_path)
    before = inv.to_dict()
    (tmp_path / "ingress" / "tls.crt").unlink()
    after_inv = Inventory(generated_at=utcnow(), sources=rescan(tmp_path))
    d = diff_dicts(before, after_inv.to_dict())
    (gone,) = d.removed
    assert gone["name"] == "web.example.com" and gone["elsewhere"][0].startswith("app: ")
    kinds = {c.kind: c.urgency for c in classify(d)}
    assert kinds.get("asset-copy-removed") == "digest" and "asset-removed" not in kinds
    assert "also seen: app:" in render_text(d)
    assert d.summary()["assets_removed_still_seen_elsewhere"] == 1


def test_the_last_copy_going_away_still_pages(tmp_path):
    inv, _, _ = estate(tmp_path)
    before = inv.to_dict()
    for f in ("app/web.crt", "ingress/tls.crt"):
        (tmp_path / f).unlink()
    after_inv = Inventory(generated_at=utcnow(), sources=rescan(tmp_path))
    kinds = {c.kind for c in classify(diff_dicts(before, after_inv.to_dict()))}
    assert "asset-removed" in kinds and "asset-copy-removed" not in kinds


@pytest.mark.skipif(not shutil.which("ssh-keygen"), reason="needs ssh-keygen")
def test_openssh_key_pairs_from_ssh_keygen_are_one_identity(tmp_path):
    for args in (["-t", "ed25519", "-f", str(tmp_path / "id_ed25519")],
                 ["-t", "rsa", "-b", "3072", "-f", str(tmp_path / "ssh_host_rsa_key")]):  # fmt: skip
        subprocess.run(["ssh-keygen", "-q", "-N", "", *args], check=True)
    r = build(source("ssh", "files", paths=[str(tmp_path)])).run()
    assert r.error is None and len(r.assets) == 4
    idents = identity.group(r.assets)
    assert sorted((i.basis, len(i.asset_ids)) for i in idents) == [(identity.BASIS_KEY, 2), (identity.BASIS_KEY, 2)]
