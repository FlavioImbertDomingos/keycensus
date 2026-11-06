"""Trustworthy results: a scan that could not look never makes a key disappear or a finding resolve;
coverage inside each source; FIPS levels only from certificate-backed evidence."""

from __future__ import annotations

import json
import shutil

import pytest
import responses
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from prometheus_client import CollectorRegistry, generate_latest

from keycensus.analysis.policy import Policy
from keycensus.changes import PAGE, classify
from keycensus.cli import main
from keycensus.collectors import build
from keycensus.config import Config, SourceConfig
from keycensus.diff import diff_dicts
from keycensus.exporters import cbom, html_report
from keycensus.exporters.prometheus import InventoryCollector
from keycensus.model import (
    GAP_DENIED,
    Coverage,
    Inventory,
    SourceResult,
    fips_level,
    normalise_fips_evidence,
    utcnow,
)
from keycensus.scanner import scan

from .conftest import make_asset, source
from .test_exporters import cdx_validator  # noqa: F401  (fixture)


def _weak_key_dir(tmp_path):
    d = tmp_path / "keys"
    d.mkdir()
    k = rsa.generate_private_key(65537, 1024)
    (d / "legacy.key").write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))  # fmt: skip
    return d


def _config(d) -> Config:
    return Config(sources=[SourceConfig(name="disk", type="files", options={"paths": [str(d)]})])


# ------------------------------------------------------------------ acceptance: outages never close findings
def test_unreachable_path_carries_the_key_and_keeps_the_finding_open(tmp_path):
    d = _weak_key_dir(tmp_path)
    policy = Policy.default()
    first = scan(_config(d), policy).to_dict()
    weak = [f for f in first["findings"] if f["rule_id"] == "weak-key-size"]
    assert weak and first["sources"][0]["status"] == "complete"

    shutil.rmtree(d)  # the mount went away: the path cannot be scanned
    inv = scan(_config(d), policy, baseline=first)
    src = inv.sources[0]
    assert src.status == "partial" and src.carried == 1
    key = inv.assets[0]
    assert (
        key.observed is False
        and key.last_observed is not None
        and "does not exist" in key.extra["not_observed_because"]
    )
    still = [f for f in inv.findings if f.rule_id == "weak-key-size"]
    assert still and still[0].verified is False and still[0].detail.startswith("[Not re-verified")

    d2 = diff_dicts(first, inv.to_dict())
    assert d2.removed == [] and d2.findings_resolved == [] and [a["id"] for a in d2.unverified] == [key.id]
    kinds = {c.kind for c in classify(d2)}
    assert "asset-removed" not in kinds and "finding-resolved" not in kinds and "asset-unverified" in kinds


def test_plain_diff_of_two_scans_is_safe_without_carry_forward(tmp_path):
    d = _weak_key_dir(tmp_path)
    first = scan(_config(d), Policy.default()).to_dict()
    shutil.rmtree(d)
    second = scan(_config(d), Policy.default()).to_dict()  # no baseline: the key is simply absent
    assert second["assets"] == []
    diff = diff_dicts(first, second)
    assert diff.removed == [] and diff.findings_resolved == []
    assert len(diff.unverified) == 1 and diff.findings_unverified
    assert diff.sources_partial and "paths: 1 expected, 0 scanned, 1 unavailable" in diff.sources_partial[0]["coverage"]
    assert any(c.kind == "source-partial" and c.urgency == PAGE for c in classify(diff))


def test_failed_source_never_resolves_anything():
    a = make_asset(source="hsm", name="k1", algorithm="RSA", key_size=1024, key_type="private-key")
    before = Inventory(generated_at=utcnow(), sources=[SourceResult(name="hsm", type="pkcs11", assets=[a])])
    from keycensus.analysis.policy import evaluate

    before.findings = evaluate(before.assets, Policy.default())
    after = Inventory(generated_at=utcnow(), sources=[SourceResult(name="hsm", type="pkcs11", error="timeout")])
    d = diff_dicts(before.to_dict(), after.to_dict())
    assert d.removed == [] and d.findings_resolved == [] and d.unverified and d.findings_unverified
    assert {c.kind for c in classify(d)} >= {"source-broken", "asset-unverified"}


def test_a_real_deletion_still_counts(tmp_path):
    d = _weak_key_dir(tmp_path)
    first = scan(_config(d), Policy.default()).to_dict()
    (d / "legacy.key").unlink()  # the directory was scanned completely: the key is gone
    inv = scan(_config(d), Policy.default(), baseline=first)
    assert inv.sources[0].status == "complete" and inv.assets == []
    diff = diff_dicts(first, inv.to_dict())
    assert len(diff.removed) == 1 and diff.findings_resolved and not diff.unverified


def test_partial_source_only_holds_back_the_unscanned_scope():
    cov = Coverage()
    cov.expect("regions", 2)
    cov.ok("regions")
    cov.gap("regions", "111/eu-west-1", "AccessDenied", GAP_DENIED)
    src = SourceResult(name="aws", type="aws-kms", coverage=cov)
    in_gap = {"extra": {"coverage_scope": ["accounts:111", "regions:111/eu-west-1"]}}
    scanned = {"extra": {"coverage_scope": ["accounts:111", "regions:111/us-east-1"]}}
    no_scope = {"extra": {}}
    assert src.unverified(in_gap) and not src.unverified(scanned) and src.unverified(no_scope)


def test_cli_require_complete_and_carry_forward(tmp_path):
    d = _weak_key_dir(tmp_path)
    cfg = tmp_path / "k.yml"
    cfg.write_text(f"sources:\n  - {{name: disk, type: files, paths: [{d}]}}\n")
    runner = CliRunner()
    r = runner.invoke(main, ["scan", "-c", str(cfg), "-o", str(tmp_path / "a"), "-f", "json", "--require-complete"])
    assert r.exit_code == 0, r.output
    shutil.rmtree(d)
    r = runner.invoke(main, ["scan", "-c", str(cfg), "-o", str(tmp_path / "b"), "-f", "json", "-f", "html",
                             "--baseline", str(tmp_path / "a" / "inventory.json"), "--require-complete"])  # fmt: skip
    assert r.exit_code == 6 and "PARTIAL" in r.output and "carried forward" in r.output, r.output
    assert "unverified: 1 finding" in r.output or "unverified:" in r.output
    inv = json.loads((tmp_path / "b" / "inventory.json").read_text())
    assert inv["summary"]["scan_status"] == "partial" and inv["summary"]["assets_unobserved"] == 1
    assert inv["assets"][0]["observed"] is False
    html = (tmp_path / "b" / "report.html").read_text()
    assert "Scan partial" in html and "not observed since" in html and "not re-verified" in html
    r = runner.invoke(main, ["scan", "-c", str(cfg), "-o", str(tmp_path / "c"), "-f", "json", "--baseline",
                             str(tmp_path / "a" / "inventory.json"), "--no-carry-forward"])  # fmt: skip
    assert json.loads((tmp_path / "c" / "inventory.json").read_text())["assets"] == []


# ------------------------------------------------------------------ coverage inside cloud sources
def test_aws_denied_region_makes_the_source_partial(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.exceptions import ClientError
    from moto import mock_aws

    from keycensus.collectors.aws_kms import AwsKmsCollector

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "t")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "t")
    real = AwsKmsCollector._collect_one

    def flaky(self, kms):
        if kms.meta.region_name == "eu-west-1":
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "not authorized"}}, "ListKeys")
        return real(self, kms)

    monkeypatch.setattr(AwsKmsCollector, "_collect_one", flaky)
    with mock_aws():
        boto3.client("kms", region_name="us-east-1").create_key(Description="east")
        res = build(source("aws", "aws-kms", regions=["us-east-1", "eu-west-1"])).run()
    assert res.error is None and res.status == "partial"
    regions = res.coverage.scopes["regions"]
    assert (regions.expected, regions.scanned) == (2, 1) and regions.gaps[0]["kind"] == GAP_DENIED
    assert res.coverage.scopes["accounts"].scanned == 1
    assert "regions: 2 expected, 1 scanned, 1 denied" in res.coverage.describe()
    east = res.assets[0]
    assert any(s.startswith("regions:") and s.endswith("/us-east-1") for s in east.extra["coverage_scope"])
    assert not res.unverified(east.to_dict())  # its region was scanned: if it vanished, that is real


@responses.activate
def test_azure_forbidden_vault_is_a_gap(monkeypatch):
    from .test_cloud_discovery import ARM, _azure_vault

    monkeypatch.setenv("AZT", "eyJ.data")
    monkeypatch.setenv("ARMT", "eyJ.arm")
    base = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/"
    responses.add(responses.GET, f"{ARM}/subscriptions/s/resources", json={"value": [
        {"id": base + "ok-kv", "name": "ok-kv", "type": "Microsoft.KeyVault/vaults"},
        {"id": base + "locked-kv", "name": "locked-kv", "type": "Microsoft.KeyVault/vaults"}]})  # fmt: skip
    _azure_vault("https://ok-kv.vault.azure.net", "k")
    responses.add(responses.GET, "https://locked-kv.vault.azure.net/keys", status=403, json={"error": "Forbidden"})
    res = build(source("az", "azure-keyvault", discover=True, subscriptions=["s"], auth="token", token_env="AZT",
                       arm_token_env="ARMT", include_rbac=False)).run()  # fmt: skip
    assert res.status == "partial"
    vaults = res.coverage.scopes["vaults"]
    assert (vaults.expected, vaults.scanned) == (2, 1)
    assert vaults.gaps == [{"id": "vaults:locked-kv", "kind": GAP_DENIED, "reason": vaults.gaps[0]["reason"]}]
    assert res.assets[0].extra["coverage_scope"] == ["subscriptions:s", "vaults:ok-kv"]


@responses.activate
def test_gcp_denied_project_and_location(monkeypatch):
    from .test_cloud_discovery import GCP, _gcp_project

    monkeypatch.setenv("GT", "ya29.token")
    _gcp_project("pay", "signer")
    responses.add(responses.GET, f"{GCP}/v1/projects/pay/locations/europe-west1/keyRings", status=403,
                  json={"error": {"status": "PERMISSION_DENIED"}})  # fmt: skip
    responses.add(responses.GET, f"{GCP}/v1/projects/hr/locations/global/keyRings", status=403,
                  json={"error": {"status": "PERMISSION_DENIED"}})  # fmt: skip
    responses.add(responses.GET, f"{GCP}/v1/projects/hr/locations/europe-west1/keyRings", status=403,
                  json={"error": {"status": "PERMISSION_DENIED"}})  # fmt: skip
    res = build(source("g", "gcp-kms", projects=["pay", "hr"], auth="token", token_env="GT",
                       locations=["global", "europe-west1"], include_iam=False)).run()  # fmt: skip
    assert res.status == "partial"
    assert {g["id"] for g in res.coverage.scopes["projects"].gaps} == {"projects:hr"}
    assert {g["id"] for g in res.coverage.scopes["locations"].gaps} == {"locations:pay/europe-west1"}
    assert res.assets[0].extra["coverage_scope"] == ["projects:pay", "locations:pay/global"]


def test_kubernetes_forbidden_namespace(tmp_path):
    pytest.importorskip("kubernetes")
    from .test_kubernetes import FakeKube

    class Locked(FakeKube):
        def route(self, path):
            if "/namespaces/locked/" in path:
                return 403, {"kind": "Status", "code": 403, "reason": "Forbidden"}
            return super().route(path)

    kube = Locked(None, cert_manager=False)
    try:
        res = build(source("k", "kubernetes", kubeconfig=kube.kubeconfig(tmp_path), namespaces=["payments", "locked"],
                           find_consumers=False)).run()  # fmt: skip
    finally:
        kube.close()
    assert res.error is None and res.status == "partial"
    ns = res.coverage.scopes["namespaces"]
    assert (ns.expected, ns.scanned) == (2, 1) and ns.gaps[0]["id"] == "namespaces:locked"
    assert all(a.extra["namespace"] == "payments" for a in res.assets)


def test_metrics_expose_completeness_and_coverage():
    cov = Coverage()
    cov.expect("accounts", 3)
    cov.ok("accounts", 2)
    cov.gap("accounts", "222", "AccessDenied", GAP_DENIED)
    inv = Inventory(generated_at=utcnow(), sources=[SourceResult(name="aws", type="aws-kms", coverage=cov, carried=4)])
    reg = CollectorRegistry()
    c = InventoryCollector(per_asset=False)
    c.inventory = inv
    reg.register(c)
    text = generate_latest(reg).decode()
    assert 'keycensus_source_complete{source="aws",type="aws-kms"} 1.0' in text
    assert 'keycensus_source_coverage{scope="accounts",source="aws",state="denied"} 1.0' in text
    assert 'keycensus_source_coverage{scope="accounts",source="aws",state="expected"} 3.0' in text
    assert 'keycensus_source_assets_not_observed{source="aws"} 4.0' in text


# ------------------------------------------------------------------ FIPS evidence
def test_fips_evidence_rules():
    ev = normalise_fips_evidence({"standard": "fips 140-3", "level": "3", "certificate": "#4884", "module": "X"})
    assert ev["basis"] == "cmvp-certificate" and ev["standard"] == "FIPS 140-3" and ev["certificate"] == "4884"
    assert ev["url"].endswith("/certificate/4884") and fips_level(ev) == "fips140-3-l3"
    partial = normalise_fips_evidence({"standard": "FIPS 140-2", "level": 3})  # no certificate
    assert partial["basis"] == "configured" and fips_level(partial) is None
    assert fips_level({"basis": "vendor-documentation"}) is None
    for bad, msg in (({"standard": "FIPS 199"}, "standard"), ({"level": 5}, "level"),
                     ({"certificate": "abc"}, "certificate"), ({"lvl": 3}, "unknown field")):  # fmt: skip
        with pytest.raises(ValueError, match=msg):
            normalise_fips_evidence(bad)


def _cbom_level(inv):
    bom = cbom.build(inv)
    return {c["bom-ref"]: c["cryptoProperties"]["algorithmProperties"].get("certificationLevel")
            for c in bom["components"] if c["bom-ref"].startswith("alg:")}, bom  # fmt: skip


def test_cbom_levels_need_certificates(cdx_validator):  # noqa: F811
    cert_ev = normalise_fips_evidence({"standard": "FIPS 140-3", "level": 3, "certificate": "4884"})
    vendor = {"basis": "vendor-documentation"}
    a1 = make_asset(name="a", algorithm="AES", key_size=256, fips_validated=True, fips_evidence=cert_ev)
    a2 = make_asset(name="b", native_id="2", algorithm="AES", key_size=256, fips_validated=True, fips_evidence=cert_ev)
    r1 = make_asset(name="c", native_id="3", algorithm="RSA", key_size=3072, fips_validated=True, fips_evidence=vendor)
    e1 = make_asset(name="d", native_id="4", algorithm="EC", curve="P-256", key_size=256, fips_validated=True,
                    fips_evidence=cert_ev)  # fmt: skip
    e2 = make_asset(name="e", native_id="5", algorithm="EC", curve="P-256", key_size=256, fips_validated=None)
    inv = Inventory(generated_at=utcnow(), sources=[SourceResult(name="t", type="t", assets=[a1, a2, r1, e1, e2])])
    levels, bom = _cbom_level(inv)
    assert levels["alg:AES-256"] == ["fips140-3-l3"]  # every user proves the same level
    assert levels["alg:RSA-3072"] == ["unknown"]  # claimed, not proven
    assert levels["alg:EC-P-256"] is None  # mixed: no level rather than a misleading one
    assert not list(cdx_validator.iter_errors(bom))
    key = next(c for c in bom["components"] if c["bom-ref"] == a1.id)
    props = {p["name"]: p["value"] for p in key["properties"]}
    assert props["keycensus:fipsCertificate"] == "4884" and props["keycensus:fipsEvidence"] == "cmvp-certificate"


def test_collectors_attach_vendor_or_configured_evidence(tmp_path):
    from keycensus.collectors.base import Collector

    class Fake(Collector):
        type_name = "fake"

        def collect(self):
            return [self.asset(kind="key", name="k", native_id="1", fips_validated=True)]

    vendor = Fake(SourceConfig(name="f", type="fake", options={})).run().assets[0]
    assert vendor.fips_evidence["basis"] == "vendor-documentation"
    configured = Fake(SourceConfig(name="f", type="fake", options={"fips_evidence": {
        "standard": "FIPS 140-3", "level": 3, "certificate": "4884", "module": "Example HSM"}})).run().assets[0]  # fmt: skip
    assert fips_level(configured.fips_evidence) == "fips140-3-l3"
    html = html_report.render(Inventory(generated_at=utcnow(), sources=[SourceResult(name="f", type="fake",
                                                                                     assets=[vendor])]))  # fmt: skip
    assert "Scan complete" in html
