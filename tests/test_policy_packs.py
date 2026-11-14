"""Versioned policy packs: metadata, validation, dated rules, applicability, and what a scan records."""

import datetime as dt
import json
import re

import pytest
from click.testing import CliRunner

from keycensus.analysis.policy import Policy, PolicyError, builtin_packs, diff_policies, evaluate
from keycensus.audit import policy_sha256
from keycensus.cli import main
from keycensus.diff import diff_dicts, render_markdown, render_text
from keycensus.model import Inventory, SourceResult, utcnow

from .conftest import make_asset

TODAY = dt.date(2026, 11, 14)


def rsa_encrypt_key(**kw):
    return make_asset(name=kw.pop("name", "kek"), native_id=kw.pop("native_id", "kek"), algorithm="RSA",
                      key_size=3072, key_type="private-key", purposes=["encrypt"], state="active",
                      created=utcnow(), **kw)  # fmt: skip


def pack(tmp_path, text, name="p.yml"):
    f = tmp_path / name
    f.write_text(text)
    return str(f)


def rules_of(findings):
    return {f.rule_id: f for f in findings}


# ----------------------------------------------------------------------------- built-in packs
@pytest.mark.parametrize("name", sorted(builtin_packs()))
def test_every_builtin_pack_is_versioned_dated_and_valid(name):
    p = Policy.load(name)
    assert p.version and p.effective and p.review_by and p.review_by > p.effective
    assert all(r.get("id") for r in p.data.get("references") or [])
    assert p.ref == f"{name}@{p.version}"
    assert len(p.digest) == 64


def test_custom_pack_does_not_inherit_the_defaults_version(tmp_path):
    p = Policy.load(pack(tmp_path, "name: acme\nrules:\n  rotation-overdue: {severity: high}\n"))
    assert p.version is None and p.ref == "acme@unversioned" and p.base == "default@2026.11.0"
    assert p.severity("rotation-overdue") == "high" and p.severity("weak-algorithm") == "high"


def test_an_edit_without_a_version_bump_still_changes_the_digest(tmp_path):
    a = Policy.load(pack(tmp_path, 'name: acme\nversion: "1"\nrules:\n  weak-hash: {severity: high}\n', "a.yml"))
    b = Policy.load(pack(tmp_path, 'name: acme\nversion: "1"\nrules:\n  weak-hash: {severity: low}\n', "b.yml"))
    assert a.ref == b.ref and a.digest != b.digest


# ----------------------------------------------------------------------------- validation
@pytest.mark.parametrize(
    "text,expect",
    [
        ("rules:\n  rotation-overdu: {severity: high}\n", "unknown rule (did you mean rotation-overdue?)"),
        ("rules:\n  weak-hash: {severity: urgent}\n", "severity 'urgent' is not one of"),
        ("rules:\n  weak-hash: {enabld: false}\n", "unknown setting 'enabld'"),
        ("rules:\n  weak-hash: {enabled: 'no'}\n", "enabled must be true or false"),
        ("rules:\n  weak-hash: {effective: soon}\n", "effective 'soon' is not a date"),
        ("rules:\n  weak-hash: {schedule: [{severity: high}]}\n", "schedule[0] needs a from: date"),
        ("rules:\n  weak-hash: {applies_to: {kind: [key]}}\n", "unknown key 'kind'"),
        ("effective: 2027-01-01\nreview_by: 2026-01-01\n", "is not after effective"),
        ("polcy: x\n", "unknown key 'polcy'"),
        ("extends: nope\n", "not a built-in pack"),
    ],
)
def test_validation_catches_what_would_silently_change_meaning(tmp_path, text, expect):
    with pytest.raises(PolicyError, match=re.escape(expect)):
        Policy.load(pack(tmp_path, text))


def test_a_missing_file_names_the_builtin_packs():
    with pytest.raises(PolicyError, match="built-in: default, nist-pqc"):
        Policy.load("no-such-pack")


# ----------------------------------------------------------------------------- dated rules
def test_a_rule_with_a_future_effective_date_raises_nothing_until_then(tmp_path):
    p = Policy.load(pack(tmp_path, "rules:\n  quantum-vulnerable-encryption: {effective: 2027-06-01}\n"))
    key = rsa_encrypt_key()
    assert "quantum-vulnerable-encryption" not in rules_of(evaluate([key], p, today=TODAY))
    assert "quantum-vulnerable-encryption" in rules_of(evaluate([key], p, today=dt.date(2027, 6, 1)))
    assert p.describe(TODAY)["upcoming"] == [
        {"rule": "quantum-vulnerable-encryption", "from": "2027-06-01", "change": "rule takes effect"}]  # fmt: skip


@pytest.mark.parametrize(
    "day,sev", [(TODAY, "medium"), (dt.date(2031, 1, 1), "high"), (dt.date(2036, 1, 1), "critical")]
)
def test_nist_pqc_grades_quantum_encryption_up_on_ir8547_dates(day, sev):
    f = rules_of(evaluate([rsa_encrypt_key()], Policy.load("nist-pqc"), today=day))["quantum-vulnerable-encryption"]
    assert f.severity == sev
    assert "NIST-IR-8547" in f.references and f.policy == "nist-pqc@2026.11.0"


def test_the_default_pack_does_not_change_with_the_date():
    for day in (TODAY, dt.date(2036, 1, 1)):
        f = rules_of(evaluate([rsa_encrypt_key()], Policy.default(), today=day))["quantum-vulnerable-encryption"]
        assert f.severity == "medium"


# ----------------------------------------------------------------------------- applicability and references
def test_applies_to_narrows_a_rule_and_the_whole_pack(tmp_path):
    hsm = rsa_encrypt_key(name="a", native_id="a", source="hsm", source_type="pkcs11")
    kms = rsa_encrypt_key(name="b", native_id="b", source="kms", source_type="aws-kms")
    p = Policy.load(pack(tmp_path, "rules:\n  quantum-vulnerable-encryption:\n"
                                   "    applies_to: {source_types: [pkcs11]}\n"))  # fmt: skip
    hit = [f.asset_name for f in evaluate([hsm, kms], p, today=TODAY) if f.rule_id == "quantum-vulnerable-encryption"]
    assert hit == ["a"]
    p2 = Policy.load(pack(tmp_path, "applies_to: {exclude_sources: [kms]}\n", "q.yml"))
    assert {f.source for f in evaluate([hsm, kms], p2, today=TODAY)} == {"hsm"}


def test_pack_controls_replace_and_references_add(tmp_path):
    p = Policy.load(pack(tmp_path, 'name: acme\nversion: "4"\nrules:\n  quantum-vulnerable-encryption:\n'
                                   "    controls: [ACME-CRYPTO-7]\n    references: [ACME-STD-2026]\n"))  # fmt: skip
    f = rules_of(evaluate([rsa_encrypt_key()], p, today=TODAY))["quantum-vulnerable-encryption"]
    assert f.controls == ["ACME-CRYPTO-7"] and "ACME-STD-2026" in f.references and f.policy == "acme@4"


def test_every_finding_records_the_pack(sample_inventory):
    p = Policy.load("nist-pqc")
    assert {f.policy for f in evaluate(sample_inventory.assets, p, today=TODAY)} == {"nist-pqc@2026.11.0"}


# ----------------------------------------------------------------------------- what a scan records
def _scan(tmp_path, cert_dir, policy_text=None):
    cfg = tmp_path / "c.yml"
    body = f"sources:\n  - name: certs\n    type: pem\n    paths: ['{cert_dir}']\n"
    if policy_text:
        body += f"policy: {pack(tmp_path, policy_text, 'pol.yml')}\n"
    cfg.write_text(body)
    out = tmp_path / "out"
    r = CliRunner().invoke(main, ["scan", "-c", str(cfg), "-o", str(out), "-f", "json", "-f", "cbom"])
    assert r.exit_code == 0, r.output
    return r, json.loads((out / "inventory.json").read_text()), json.loads((out / "cbom.json").read_text())


def test_the_scan_records_the_exact_pack(tmp_path, cert_dir):
    r, inv, bom = _scan(tmp_path, cert_dir)
    pp = inv["policy_pack"]
    assert pp["ref"] == "default@2026.11.0" and pp["digest"] == Policy.default().digest
    assert pp["source"] == "builtin:default" and pp["review_by"] == "2027-05-14"
    assert all(f["policy"] == "default@2026.11.0" for f in inv["findings"])
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["keycensus:policy"] == "default@2026.11.0" and props["keycensus:policyDigest"] == pp["digest"]
    assert "policy: default@2026.11.0" in r.output
    assert Inventory.from_dict(inv).policy_pack == pp


def test_an_overdue_review_is_said_out_loud(tmp_path, cert_dir):
    r, inv, _ = _scan(tmp_path, cert_dir, 'name: acme\nversion: "1"\neffective: 2025-01-01\nreview_by: 2025-06-01\n')
    assert inv["policy_pack"]["review_overdue"] is True
    assert "was due for review on 2025-06-01" in r.output
    html = (tmp_path / "out").glob("*.html")
    assert all("due for review" in h.read_text() for h in html)


# ----------------------------------------------------------------------------- diffs say why
def _inv(assets, policy, day):
    inv = Inventory(generated_at=utcnow(), sources=[SourceResult(name="kms", type="aws-kms", assets=assets)])
    inv.findings = evaluate(inv.assets, policy, today=day)
    inv.policy_pack = policy.describe(day)
    return inv.to_dict()


def test_a_diff_tells_policy_from_asset_from_time(tmp_path):
    key = rsa_encrypt_key(source="kms", source_type="aws-kms")
    base = Policy.default()
    stricter = Policy.load(pack(tmp_path, 'name: acme\nversion: "2"\nrules:\n  quantum-vulnerable-encryption: '
                                          "{severity: high}\n  key-software-backed: {enabled: false}\n"))  # fmt: skip
    d = diff_dicts(_inv([key], base, TODAY), _inv([key], stricter, TODAY))
    assert d.policy_changed == {"before": "default@2026.11.0", "after": "acme@2"}
    regraded = {f["rule_id"]: f for f in d.findings_regraded}
    assert regraded["quantum-vulnerable-encryption"]["severity_before"] == "medium"
    assert regraded["quantum-vulnerable-encryption"]["cause"] == "policy"
    assert all(f["cause"] == "policy" for f in d.findings_resolved)  # key-software-backed switched off
    assert "(policy change)" in render_text(d) and "Policy changed" in render_markdown(d)

    # same pack, a later date: the schedule step is "time", not "policy"
    pqc = Policy.load("nist-pqc")
    d2 = diff_dicts(_inv([key], pqc, TODAY), _inv([key], pqc, dt.date(2031, 1, 2)))
    assert d2.policy_changed is None
    (g,) = d2.findings_regraded
    assert (g["severity_before"], g["severity"], g["cause"]) == ("medium", "high", "time")

    # a new asset: "asset"
    other = rsa_encrypt_key(name="new", native_id="new", source="kms", source_type="aws-kms")
    d3 = diff_dicts(_inv([key], base, TODAY), _inv([key, other], base, TODAY))
    assert {f["cause"] for f in d3.findings_new} == {"asset"}
    assert d3.summary()["findings_new_by_cause"]["asset"] == len(d3.findings_new) > 0


# ----------------------------------------------------------------------------- the commands
def test_policy_commands(tmp_path):
    r = CliRunner().invoke(main, ["policy", "show", "nist-pqc", "--as-of", "2031-06-01"])
    assert r.exit_code == 0 and "nist-pqc@2026.11.0" in r.output
    assert any(line.startswith("quantum-vulnerable-encryption") and " high " in line for line in r.output.splitlines())
    body = json.loads(CliRunner().invoke(main, ["policy", "show", "default", "--json"]).output)
    assert body["ref"] == "default@2026.11.0" and body["rules"]

    bad = pack(tmp_path, "rules:\n  weak-hsh: {severity: high}\n", "bad.yml")
    r = CliRunner().invoke(main, ["policy", "validate", bad])
    assert r.exit_code == 1 and "did you mean weak-hash?" in r.output
    r = CliRunner().invoke(main, ["policy", "validate", "default"])
    assert r.exit_code == 0 and "ok: default@2026.11.0" in r.output
    r = CliRunner().invoke(main, ["policy", "validate", pack(tmp_path, "name: x\n", "nov.yml")])
    assert r.exit_code == 0 and "no version" in r.output

    r = CliRunner().invoke(main, ["policy", "diff", "default", "nist-pqc"])
    assert r.exit_code == 0 and 'rules.quantum-vulnerable-encryption.schedule: - -> [{"from": "2031-01-01"' in r.output
    assert CliRunner().invoke(main, ["rules", "-p", "nist-pqc"]).exit_code == 0


def test_diff_policies_lists_thresholds_and_rules(tmp_path):
    p = Policy.load(pack(tmp_path, "certificate: {expiring_soon_days: 60}\nrules:\n  weak-hash: {enabled: false}\n"))
    what = {c["what"] for c in diff_policies(Policy.default(), p)}
    assert {"certificate", "rules.weak-hash.enabled", "name"} <= what


def test_the_audit_hash_of_a_builtin_pack_is_that_pack():
    assert policy_sha256("nist-pqc") != policy_sha256("default")


def test_every_example_pack_in_the_docs_loads(tmp_path):
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent / "docs" / "POLICY.md").read_text()
    blocks = [b.split("```", 1)[0] for b in text.split("```yaml\n")[1:]]
    examples = [b for b in blocks if b.startswith("name:")]
    assert len(examples) >= 3
    for i, b in enumerate(examples):
        Policy.load(pack(tmp_path, b, f"ex{i}.yml"))
