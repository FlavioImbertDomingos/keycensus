"""SARIF 2.1.0 output: valid against the OASIS schema, physical locations for files, logical ones for key stores,
stable fingerprints, and the severity mapping GitHub code scanning reads."""

from __future__ import annotations

import json
import shutil

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jsonschema import Draft4Validator

from keycensus.analysis.policy import Policy, evaluate
from keycensus.cli import main
from keycensus.collectors import build
from keycensus.exporters import FORMATS, sarif
from keycensus.model import Inventory, SourceResult, utcnow

from .conftest import FIXTURES, source


@pytest.fixture(scope="module")
def validator():
    return Draft4Validator(json.loads((FIXTURES / "sarif-2.1.0.schema.json").read_text()))


@pytest.fixture
def repo_inv(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "code-sample", repo)
    key = rsa.generate_private_key(65537, 2048)
    (repo / "config").mkdir()
    (repo / "config" / "signing.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))  # fmt: skip
    results = [build(source("repo", "code", paths=[str(repo)])).run()]
    inv = Inventory(generated_at=utcnow(), sources=results)
    inv.findings = evaluate(inv.assets, Policy.default())
    return inv, repo


def test_sarif_is_valid_and_lists_one_rule_per_finding_type(sample_inventory, validator):
    log = json.loads(sarif.render(sample_inventory))
    assert not [e.message for e in validator.iter_errors(log)]
    run = log["runs"][0]
    rules = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert rules == sorted({f.rule_id for f in sample_inventory.findings})
    assert len(run["results"]) == len(sample_inventory.findings)
    for r in run["results"]:
        assert rules[r["ruleIndex"]] == r["ruleId"] and r["locations"]
    assert run["automationDetails"]["id"] == "keycensus/"


def test_key_store_findings_get_a_logical_location(sample_inventory):
    log = json.loads(sarif.render(sample_inventory))
    hsm = [r for r in log["runs"][0]["results"] if r["properties"]["source"] != "certs"]
    assert hsm and all("physicalLocation" not in loc for r in hsm for loc in r["locations"])
    logical = hsm[0]["locations"][0]["logicalLocations"][0]
    assert logical["kind"] == "resource" and "/" in logical["fullyQualifiedName"]


def test_code_findings_point_at_file_and_line_relative_to_the_scan_directory(repo_inv, validator):
    inv, repo = repo_inv
    log = json.loads(sarif.render(inv, cwd=repo))
    assert not [e.message for e in validator.iter_errors(log)]
    results = log["runs"][0]["results"]
    uri = lambda r: r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]  # noqa: E731
    hard = next(r for r in results if r["ruleId"] == "hardcoded-private-key" and uri(r) == "config/signing.pem")
    assert hard["level"] == "error" and hard["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    weak = next(r for r in results if r["ruleId"] == "weak-hash")
    uris = {loc["physicalLocation"]["artifactLocation"]["uri"] for loc in weak["locations"]}
    assert uris and not any(u.startswith(("/", "file:")) for u in uris)
    assert all(loc["physicalLocation"]["region"]["startLine"] >= 1 for loc in weak["locations"])
    rule = next(r for r in log["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "hardcoded-private-key")
    assert rule["properties"]["security-severity"] == "9.5" and rule["properties"]["precision"] == "medium"
    assert "security" in rule["properties"]["tags"]


def test_paths_outside_the_scan_directory_are_absolute_uris(repo_inv, tmp_path):
    inv, _ = repo_inv
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    log = json.loads(sarif.render(inv, cwd=elsewhere))
    uri = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith("file:///")


def test_fingerprints_are_stable_across_runs_and_unique_per_finding(repo_inv):
    inv, repo = repo_inv
    a = json.loads(sarif.render(inv, cwd=repo))["runs"][0]["results"]
    b = json.loads(sarif.render(inv, cwd=repo))["runs"][0]["results"]
    fa = [r["partialFingerprints"]["keycensusFinding/v1"] for r in a]
    assert fa == [r["partialFingerprints"]["keycensusFinding/v1"] for r in b]
    assert len(set(fa)) == len(fa)


def test_severity_mapping():
    assert sarif.LEVEL == {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    assert all(0.1 <= float(v) <= 10 for v in sarif.SECURITY_SEVERITY.values())
    assert float(sarif.SECURITY_SEVERITY["critical"]) > 9.0 and 7.0 <= float(sarif.SECURITY_SEVERITY["high"]) < 9.0


def test_cli_writes_keycensus_sarif(sample_inventory, tmp_path):
    assert FORMATS["sarif"][1] == "keycensus.sarif"
    (tmp_path / "inv.json").write_text(json.dumps(sample_inventory.to_dict()))
    cfg = tmp_path / "k.yml"
    cfg.write_text("sources:\n  - {name: x, type: pem, paths: [/nonexistent]}\napplications:\n  - name: demo\n")
    res = CliRunner().invoke(main, ["link", "-c", str(cfg), "-i", str(tmp_path / "inv.json"), "-o", str(tmp_path / "o"),
                                    "-f", "sarif"])  # fmt: skip
    assert res.exit_code == 0, res.output
    log = json.loads((tmp_path / "o" / "keycensus.sarif").read_text())
    assert log["version"] == "2.1.0" and log["runs"][0]["tool"]["driver"]["name"] == "keycensus"


def test_serve_routes_include_sarif():
    src = (sarif.__file__.rsplit("/exporters/", 1)[0]) + "/serve.py"
    assert '"/findings.sarif"' in open(src).read()


def test_empty_inventory_is_still_valid(validator):
    inv = Inventory(generated_at=utcnow(), sources=[SourceResult(name="x", type="pem", assets=[])])
    log = json.loads(sarif.render(inv))
    assert not list(validator.iter_errors(log)) and log["runs"][0]["results"] == []
