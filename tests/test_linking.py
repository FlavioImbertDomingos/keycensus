"""SBOM <-> CBOM linking: selectors, SBOM ingestion, auto-match, findings, exporters, CLI."""

from __future__ import annotations

import csv
import io
import json
import uuid

import pytest
from click.testing import CliRunner

from keycensus.analysis.policy import Policy, evaluate
from keycensus.cli import main
from keycensus.diff import diff_inventories
from keycensus.exporters import cbom, csv_export, html_report, json_export
from keycensus.exporters.prometheus import InventoryCollector
from keycensus.linking import LinkingError, apply, impact, link, load_applications, selector_matches
from keycensus.model import KIND_CERTIFICATE, Application, Inventory, SourceResult, utcnow

from .conftest import make_asset
from .test_exporters import cdx_validator  # noqa: F401 - fixture


def sbom(path, name, version="1.0.0", purl=None, supplier="team-a", components=2):
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": purl or f"pkg:generic/{name}@{version}",
                "name": name,
                "version": version,
                "purl": purl or f"pkg:generic/{name}@{version}",
                "supplier": {"name": supplier},
            }
        },
        "components": [{"type": "library", "name": f"lib{i}", "version": "1"} for i in range(components)],
    }
    path.write_text(json.dumps(doc))
    return doc


@pytest.fixture
def inv():
    now = utcnow()
    assets = [
        make_asset(
            source="hsm",
            name="pan-dek",
            native_id="1",
            algorithm="AES",
            key_size=256,
            key_type="secret-key",
            purposes=["encrypt"],
            created=now,
            state="active",
            tags={"app": "payments"},
        ),  # fmt: skip
        make_asset(
            source="aws",
            name="jwt-signing",
            native_id="arn:2",
            algorithm="RSA",
            key_size=2048,
            key_type="private-key",
            purposes=["sign"],
            created=now,
            state="active",
            used_by=[{"type": "principal", "id": "arn:aws:iam::1:role/auth-service", "via": "grant:auth"}],
        ),  # fmt: skip
        make_asset(
            source="vault",
            name="orphan",
            native_id="3",
            algorithm="AES",
            key_size=128,
            key_type="secret-key",
            purposes=["encrypt"],
            created=now,
            state="active",
            used_by=[{"type": "policy", "id": "batch-reporting", "via": "vault-policy:decrypt"}],
        ),  # fmt: skip
        make_asset(
            source="certs",
            kind=KIND_CERTIFICATE,
            name="api.payments.example.com",
            native_id="4",
            algorithm="EC",
            key_size=256,
            curve="P-256",
            key_type="public-key",
            purposes=["verify"],
            created=now,
            state="active",
        ),  # fmt: skip
    ]
    by = {}
    for a in assets:
        by.setdefault(a.source, []).append(a)
    i = Inventory(generated_at=now, sources=[SourceResult(name=s, type="test", assets=v) for s, v in by.items()])
    i.findings = evaluate(i.assets, Policy.default())
    return i


# --------------------------------------------------------------------- selectors
def test_selectors(inv):
    a = {x.name: x for x in inv.assets}
    assert selector_matches({"source": "hsm", "name": "pan-*"}, a["pan-dek"])
    assert selector_matches({"tag": {"app": "pay*"}}, a["pan-dek"])
    assert not selector_matches({"source": "hsm", "name": "nope"}, a["pan-dek"])
    assert selector_matches({"principal": "arn:aws:iam::*:role/auth-*"}, a["jwt-signing"]) == (
        "used_by arn:aws:iam::1:role/auth-service"
    )
    assert selector_matches({"kind": "certificate", "name": "*.payments.example.com"}, a["api.payments.example.com"])
    assert not selector_matches({"kind": "certificate"}, a["pan-dek"])
    assert selector_matches({"id": a["orphan"].id}, a["orphan"])


def test_load_applications_from_sbom_and_validation(tmp_path):
    sbom(tmp_path / "pay.cdx.json", "payments-api", "1.4.2", supplier="payments-team", components=4)
    apps = load_applications([{"sbom": "pay.cdx.json", "uses": [{"name": "pan-*"}]}], base_dir=tmp_path)
    app = apps[0]
    assert app.name == "payments-api" and app.version == "1.4.2" and app.owner == "payments-team"
    assert app.purl == "pkg:generic/payments-api@1.4.2" and app.sbom_components == 4 and app.sbom_serial
    assert app.ref == app.purl  # bom-ref taken from the SBOM
    # explicit fields win over SBOM fields
    apps = load_applications([{"sbom": "pay.cdx.json", "owner": "me", "version": "9"}], base_dir=tmp_path)
    assert apps[0].owner == "me" and apps[0].version == "9"
    with pytest.raises(LinkingError, match="unknown selector"):
        load_applications([{"name": "x", "uses": [{"colour": "red"}]}])
    with pytest.raises(LinkingError, match="needs a name"):
        load_applications([{"owner": "x"}])
    with pytest.raises(LinkingError, match="duplicate"):
        load_applications([{"name": "x"}, {"name": "x"}])
    (tmp_path / "spdx.json").write_text('{"spdxVersion": "SPDX-2.3"}')
    with pytest.raises(LinkingError, match="not a CycloneDX"):
        load_applications([{"sbom": str(tmp_path / "spdx.json")}])
    with pytest.raises(LinkingError, match="cannot read"):
        load_applications([{"sbom": str(tmp_path / "missing.json")}])


# --------------------------------------------------------------------- linking
def test_link_declared_and_auto(inv):
    apps = [
        Application(
            name="payments-api",
            uses=[{"source": "hsm", "name": "pan-*"}, {"kind": "certificate", "name": "*.payments.*"}],
        ),
        Application(name="auth-service"),  # no selectors: only auto-match on inferred consumers
        Application(name="batch_reporting", uses=[]),  # underscore vs dash: still matches the Vault policy
    ]  # fmt: skip
    link(inv, apps)
    by = {a.name: a for a in inv.assets}
    assert by["pan-dek"].applications == ["payments-api"] and by["api.payments.example.com"].applications == [
        "payments-api"
    ]
    assert by["jwt-signing"].applications == ["auth-service"]
    assert apps[1].matches[by["jwt-signing"].id] == ["auto:used_by arn:aws:iam::1:role/auth-service"]
    assert by["orphan"].applications == ["batch_reporting"]
    assert sorted(apps[0].asset_ids) == sorted([by["pan-dek"].id, by["api.payments.example.com"].id])
    # idempotent
    link(inv, apps)
    assert by["pan-dek"].applications == ["payments-api"]
    # auto-match off
    link(inv, apps, auto_match=False)
    assert by["jwt-signing"].applications == [] and by["orphan"].applications == []


def test_apply_adds_unlinked_findings_and_summary(inv):
    policy = Policy.default()
    apply(inv, [{"name": "payments-api", "uses": [{"source": "hsm"}]}], policy)
    unlinked = [f for f in inv.findings if f.rule_id == "unlinked-asset"]
    names = {f.asset_name for f in unlinked}
    assert names == {"jwt-signing", "orphan", "api.payments.example.com"}  # pan-dek is linked
    assert "batch-reporting" in next(f.detail for f in unlinked if f.asset_name == "orphan")
    s = inv.summary()
    assert s["applications"] == 1 and s["assets_linked"] == 1 and s["assets_unlinked"] == 3
    # disable the rule via policy
    p2 = Policy({"name": "x", "rules": {"unlinked-asset": {"enabled": False}}})
    apply(inv, [{"name": "payments-api", "uses": [{"source": "hsm"}]}], p2)
    assert not [f for f in inv.findings if f.rule_id == "unlinked-asset"]
    # no applications -> no findings, summary says None
    inv2 = Inventory(generated_at=utcnow(), sources=inv.sources)
    assert inv2.summary()["assets_unlinked"] is None


def test_impact_table(inv):
    apply(inv, [{"name": "payments-api", "uses": [{"source": "hsm"}]}, {"name": "auth-service"}], Policy.default())
    rows = {r["name"]: r for r in impact(inv)}
    assert rows["payments-api"]["assets"] == 1
    assert rows["auth-service"]["assets"] == 1 and rows["auth-service"]["worst_severity"] in (
        "low",
        "medium",
        "high",
        "info",
    )


# --------------------------------------------------------------------- exporters
def test_exporters_carry_links(inv, cdx_validator, tmp_path):  # noqa: F811
    sbom(tmp_path / "pay.cdx.json", "payments-api", "1.4.2", purl="pkg:github/acme/payments-api@1.4.2")
    apply(inv, [{"sbom": str(tmp_path / "pay.cdx.json"), "uses": [{"source": "hsm"}]}, {"name": "auth-service"}],
          Policy.default())  # fmt: skip
    bom = cbom.build(inv)
    errors = [f"{list(e.path)}: {e.message[:120]}" for e in cdx_validator.iter_errors(bom)]
    assert not errors, "\n".join(errors)
    apps = [c for c in bom["components"] if c["type"] == "application"]
    assert {c["name"] for c in apps} == {"payments-api", "auth-service"}
    pay = next(c for c in apps if c["name"] == "payments-api")
    assert pay["bom-ref"] == "pkg:github/acme/payments-api@1.4.2" and pay["externalReferences"][0]["type"] == "bom"
    by = {a.name: a for a in inv.assets}
    deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    assert deps[pay["bom-ref"]] == [by["pan-dek"].id] and deps["app:auth-service"] == [by["jwt-signing"].id]
    key = next(c for c in bom["components"] if c["bom-ref"] == by["jwt-signing"].id)
    props = {p["name"]: p["value"] for p in key["properties"]}
    assert (
        props["keycensus:application"] == "auth-service"
        and "arn:aws:iam::1:role/auth-service" in props["keycensus:usedBy:principal"]
    )
    assert next(p["value"] for p in bom["metadata"]["properties"] if p["name"] == "keycensus:applications") == "2"

    js = json.loads(json_export.render(inv))
    assert {a["name"] for a in js["applications"]} == {"payments-api", "auth-service"}
    assert next(a for a in js["assets"] if a["name"] == "pan-dek")["applications"] == ["payments-api"]
    assert js["summary"]["assets_linked"] == 2

    rows = list(csv.DictReader(io.StringIO(csv_export.render(inv))))
    assert next(r for r in rows if r["name"] == "jwt-signing")["applications"] == "auth-service"
    assert "arn:aws:iam::1:role/auth-service" in next(r for r in rows if r["name"] == "jwt-signing")["used_by"]

    html = html_report.render(inv)
    assert "Applications (2)" in html and 'class="pill app">payments-api' in html and "role/auth-service" in html

    coll = InventoryCollector()
    coll.inventory = inv
    text = {m.name: m for m in coll.collect()}
    assert "keycensus_application_assets" in text and "keycensus_assets_unlinked" in text
    samples = {tuple(sorted(s.labels.items())): s.value for s in text["keycensus_application_assets"].samples}
    assert samples[(("application", "payments-api"), ("owner", "team-a"))] == 1.0

    # diff notices link changes
    before = inv.to_dict()
    apply(inv, [{"name": "payments-api", "uses": [{"source": "hsm"}, {"source": "aws"}]}], Policy.default())
    d = diff_inventories(before, inv)
    changed = {c.name: c.changes for c in d.changed}
    assert "applications" in changed["jwt-signing"]


# --------------------------------------------------------------------- CLI
def test_scan_and_link_cli(cert_dir, tmp_path):
    sbom(tmp_path / "web.cdx.json", "web-frontend", "3.1.0")
    cfg = tmp_path / "c.yml"
    cfg.write_text(
        f"sources:\n  - name: certs\n    type: pem\n    paths: ['{cert_dir}']\n"
        "applications:\n  - sbom: web.cdx.json\n    uses: [{name: 'good'}, {name: 'soon'}]\n"
    )
    out = tmp_path / "out"
    r = CliRunner().invoke(main, ["scan", "-c", str(cfg), "-o", str(out)])
    assert r.exit_code == 0, r.output
    assert "apps:     1 linked to 4 assets" in r.output  # good + soon, each also in bundle.pem
    js = json.loads((out / "inventory.json").read_text())
    assert js["applications"][0]["name"] == "web-frontend" and js["applications"][0]["assets"] == 4
    assert any(f["rule_id"] == "unlinked-asset" for f in js["findings"])
    bom = json.loads((out / "cbom.json").read_text())
    assert any(c["type"] == "application" for c in bom["components"])

    # re-link an existing inventory with an extra SBOM, no rescan
    sbom(tmp_path / "other.cdx.json", "orphan-app")
    out2 = tmp_path / "out2"
    r = CliRunner().invoke(main, ["link", "-c", str(cfg), "-i", str(out / "inventory.json"), "-o", str(out2),
                                  "--sbom", str(tmp_path / "other.cdx.json")])  # fmt: skip
    assert r.exit_code == 0, r.output
    assert "web-frontend" in r.output and "orphan-app" in r.output
    js2 = json.loads((out2 / "inventory.json").read_text())
    assert {a["name"] for a in js2["applications"]} == {"web-frontend", "orphan-app"}
    assert (out2 / "report.html").exists()

    # bad config surfaces cleanly
    cfg.write_text(f"sources:\n  - name: certs\n    type: pem\n    paths: ['{cert_dir}']\napplications: {{a: 1}}\n")
    r = CliRunner().invoke(main, ["validate", "-c", str(cfg)])
    assert r.exit_code != 0 and "must be a list" in r.output
