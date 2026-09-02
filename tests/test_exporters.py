import csv
import io
import json

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from keycensus.exporters import cbom, csv_export, html_report, json_export
from keycensus.exporters.prometheus import InventoryCollector

from .conftest import FIXTURES


@pytest.fixture(scope="module")
def cdx_validator():
    schema = json.loads((FIXTURES / "bom-1.6.schema.json").read_text())
    jsf = json.loads((FIXTURES / "jsf-0.82.schema.json").read_text())
    spdx = json.loads((FIXTURES / "spdx.schema.json").read_text())
    reg = Registry().with_resources(
        [
            ("jsf-0.82.SNAPSHOT.schema.json", Resource.from_contents(jsf)),
            ("spdx.SNAPSHOT.schema.json", Resource.from_contents(spdx)),
            (
                "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json",
                Resource.from_contents(jsf),
            ),
            ("http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json", Resource.from_contents(spdx)),
        ]
    )
    return Draft7Validator(schema, registry=reg)


def test_cbom_is_schema_valid(sample_inventory, cdx_validator):
    bom = cbom.build(sample_inventory)
    errors = [f"{list(e.path)}: {e.message[:120]}" for e in cdx_validator.iter_errors(bom)]
    assert not errors, "\n".join(errors)
    assert bom["specVersion"] == "1.6"
    types = {c["cryptoProperties"]["assetType"] for c in bom["components"]}
    assert types == {"algorithm", "related-crypto-material", "certificate", "protocol"}


def test_cbom_links_and_findings(sample_inventory):
    bom = cbom.build(sample_inventory)
    refs = {c["bom-ref"] for c in bom["components"]}
    for c in bom["components"]:
        cp = c["cryptoProperties"]
        if cp["assetType"] == "related-crypto-material":
            assert cp["relatedCryptoMaterialProperties"]["algorithmRef"] in refs
        if cp["assetType"] == "certificate":
            assert cp["certificateProperties"]["subjectPublicKeyRef"] in refs
            assert cp["certificateProperties"]["signatureAlgorithmRef"] in refs
    assert bom["vulnerabilities"], "findings should be exported as vulnerabilities"
    for v in bom["vulnerabilities"]:
        assert v["affects"][0]["ref"] in refs
        assert v["id"].startswith("KEYCENSUS-")
    alg = next(c for c in bom["components"] if c["bom-ref"] == "alg:AES-256")
    props = alg["cryptoProperties"]["algorithmProperties"]
    assert props["nistQuantumSecurityLevel"] == 5 and props["classicalSecurityLevel"] == 256
    assert props["certificationLevel"] == ["fips140-3-l3"]


def test_json_and_csv(sample_inventory):
    data = json.loads(json_export.render(sample_inventory))
    assert data["summary"]["assets"] == 5 and data["summary"]["sources_failed"] == 1
    assert data["sources"][1]["error"] == "boom"
    rows = list(csv.DictReader(io.StringIO(csv_export.render(sample_inventory))))
    assert len(rows) == 5
    tdes = next(r for r in rows if r["name"] == "tdes")
    assert "high:weak-algorithm" in tdes["findings"]
    assert tdes["quantum_class"] == "quantum-vulnerable"


def test_html_report_renders(sample_inventory):
    html = html_report.render(sample_inventory)
    assert "<!doctype html>" in html.lower()
    assert "Certificate expires in" in html
    assert "3DES is a broken" in html
    assert "PCI-DSS-4.0:3.7.5" in html
    assert "boom" in html  # failed source is visible


def test_prometheus_collector(sample_inventory):
    c = InventoryCollector()
    c.inventory = sample_inventory
    c.scan_count = 1
    families = {f.name: f for f in c.collect()}
    assert "keycensus_findings_by_severity" in families
    assert "keycensus_key_age_days" in families
    up = {tuple(s.labels.values()): s.value for s in families["keycensus_source_up"].samples}
    assert up[("t", "test")] == 1.0 and up[("broken", "vault")] == 0.0
    ages = families["keycensus_key_age_days"].samples
    assert any(s.labels["name"] == "rsa-old" and s.value > 800 for s in ages)
