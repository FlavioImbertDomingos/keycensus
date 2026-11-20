"""Observed use: recorded CloudTrail, Vault audit, Key Vault AuditEvent and Cloud Audit Logs samples, matched to
keys, compared with the authorised consumers, and carried into every output."""

from __future__ import annotations

import csv
import gzip
import io
import json
from datetime import UTC, datetime

import pytest
from click.testing import CliRunner

from keycensus.analysis.policy import Policy
from keycensus.cli import main
from keycensus.config import ConfigError, load
from keycensus.exporters import cbom, csv_export, html_report
from keycensus.exporters.prometheus import InventoryCollector
from keycensus.model import STATE_ACTIVE, Inventory, SourceResult
from keycensus.usage import UsageError, apply, read_log

from .conftest import FIXTURES, make_asset
from .test_cyclonedx17 import validator17  # noqa: F401

LOGS = FIXTURES / "usage"
NOW = datetime(2026, 11, 19, tzinfo=UTC)
ACCT = "arn:aws:kms:eu-west-1:111122223333:key/"
KEY_A = ACCT + "1234abcd-12ab-34cd-56ef-1234567890ab"


def estate() -> Inventory:
    role = "arn:aws:iam::111122223333:role/"
    aws = [
        make_asset(source="aws", source_type="aws-kms", name="payments", native_id=KEY_A, state=STATE_ACTIVE,
                   used_by=[{"type": "principal", "id": role + "payments-api", "via": "grant:s3"},
                            {"type": "principal", "id": role + "old-batch", "via": "key-policy:Allow"}]),
        make_asset(source="aws", source_type="aws-kms", name="idle", native_id=ACCT + "idle-0000", state=STATE_ACTIVE,
                   used_by=[{"type": "principal", "id": role + "payments-api", "via": "key-policy:Allow"}]),
        make_asset(source="aws", source_type="aws-kms", name="other-region", state=STATE_ACTIVE,
                   native_id="arn:aws:kms:us-east-1:111122223333:key/far-away"),
    ]  # fmt: skip
    vault = [
        make_asset(source="vault", source_type="vault", name="payments", native_id="transit/keys/payments",
                   state=STATE_ACTIVE,
                   used_by=[{"type": "policy", "id": "payments-transit", "via": "vault-policy:encrypt"},
                            {"type": "policy", "id": "old-batch", "via": "vault-policy:decrypt"}]),
        make_asset(source="vault", source_type="vault", name="jwt", native_id="transit/keys/jwt", state=STATE_ACTIVE,
                   used_by=[{"type": "policy", "id": "auth-signer", "via": "vault-policy:sign"}]),
    ]  # fmt: skip
    azure = [
        make_asset(source="azure", source_type="azure-keyvault", name="payments", state=STATE_ACTIVE,
                   native_id="https://kv-prod.vault.azure.net/keys/payments",
                   used_by=[{"type": "service", "id": "payments-app", "via": "rbac:Key Vault Crypto User",
                             "object_id": "1111aaaa-2222-3333-4444-555566667777"}]),
    ]  # fmt: skip
    gcp = [
        make_asset(source="gcp", source_type="gcp-kms", name="payments-kek", state=STATE_ACTIVE,
                   native_id="projects/acme-prod/locations/global/keyRings/payments/cryptoKeys/payments-kek",
                   used_by=[{"type": "service", "id": "serviceAccount:payments@acme-prod.iam.gserviceaccount.com",
                             "via": "iam:cryptoKeyEncrypterDecrypter"}]),
        make_asset(source="gcp", source_type="gcp-kms", name="signing", state=STATE_ACTIVE,
                   native_id="projects/acme-prod/locations/global/keyRings/payments/cryptoKeys/signing"),
    ]  # fmt: skip
    pem = [make_asset(source="files", source_type="pem", name="web.key", native_id="/etc/ssl/web.key")]
    return Inventory(generated_at=NOW, sources=[
        SourceResult(name="aws", type="aws-kms", assets=aws), SourceResult(name="vault", type="vault", assets=vault),
        SourceResult(name="azure", type="azure-keyvault", assets=azure),
        SourceResult(name="gcp", type="gcp-kms", assets=gcp),
        SourceResult(name="files", type="pem", assets=pem),
    ])  # fmt: skip


ALL = [
    {"type": "cloudtrail", "path": str(LOGS / "cloudtrail.json")},
    {"type": "vault-audit", "path": str(LOGS / "vault-audit.log")},
    {"type": "azure-keyvault", "path": str(LOGS / "azure-keyvault.json")},
    {"type": "gcp-audit", "path": str(LOGS / "gcp-audit.json")},
]


@pytest.fixture
def inv() -> Inventory:
    i = estate()
    apply(i, ALL, Policy.default())
    return i


def asset(inv, source, name):
    return next(a for a in inv.assets if a.source == source and a.name == name)


def test_cloudtrail_reads_kms_calls_only_and_names_the_role_not_the_session():
    events, stats = read_log("cloudtrail", LOGS / "cloudtrail.json")
    assert stats.records == 8 and stats.events == 6  # DescribeKey and an S3 call are not cryptographic use
    assert {e.principal for e in events} == {
        "arn:aws:iam::111122223333:role/payments-api", "arn:aws:iam::111122223333:role/batch-reporting",
        "arn:aws:iam::111122223333:user/jdoe",
    }  # fmt: skip
    assert stats.scopes == {"111122223333:eu-west-1"}
    assert [e.via for e in events if e.operation == "GenerateDataKey"] == ["s3.amazonaws.com"]


def test_cloudtrail_s3_objects_are_gzipped(tmp_path):
    (tmp_path / "AWSLogs").mkdir()
    gz = tmp_path / "AWSLogs" / "111122223333_CloudTrail_eu-west-1_20261118T0800Z_abc.json.gz"
    gz.write_bytes(gzip.compress((LOGS / "cloudtrail.json").read_bytes()))
    _, stats = read_log("cloudtrail", tmp_path)
    assert stats.events == 6


def test_aws_key_used_by_its_grantee_and_a_refused_caller(inv):
    u = asset(inv, "aws", "payments").observed_use
    assert u["logs"] == ["cloudtrail"] and u["succeeded"] == 4 and u["denied"] == 1
    role = next(p for p in u["principals"] if p["id"].endswith("role/payments-api"))
    assert role["operations"] == {"Decrypt": 3, "GenerateDataKey": 1} and role["authorized"] is True
    assert role["via"] == ["s3.amazonaws.com"] and role["last_seen"] == "2026-11-18T08:00:00Z"
    jdoe = next(p for p in u["principals"] if p["id"].endswith("user/jdoe"))
    assert jdoe["operations"] == {} and jdoe["denied"] == 1 and jdoe["authorized"] is False
    assert u["authorized_not_seen"] == [{"id": "arn:aws:iam::111122223333:role/old-batch", "via": "key-policy:Allow"}]
    assert u["window"] == {"from": "2026-11-01T08:00:00Z", "to": "2026-11-18T08:00:00Z"}


def test_covered_but_unused_is_not_the_same_as_not_covered(inv):
    idle = asset(inv, "aws", "idle").observed_use
    assert idle is not None and idle["succeeded"] == 0 and idle["principals"] == []
    assert asset(inv, "aws", "other-region").observed_use is None  # the trail has nothing from us-east-1
    assert asset(inv, "files", "web.key").observed_use is None
    finding = [f for f in inv.findings if f.rule_id == "key-not-used"]
    assert {(f.source, f.asset_name) for f in finding} == {("aws", "idle"), ("vault", "jwt"), ("gcp", "signing")}
    detail = next(f.detail for f in finding if f.asset_name == "idle")
    assert "between 2026-11-01 and 2026-11-18 (17 days)" in detail and "AWS CloudTrail" in detail


def test_keys_used_but_not_in_the_inventory_are_reported(inv):
    ct = next(lg for lg in inv.usage["logs"] if lg["type"] == "cloudtrail")
    assert ct["events"] == 6 and ct["matched"] == 5
    assert ct["unmatched"] == [{"key": ACCT + "9999ffff-0000-1111-2222-333344445555", "events": 1}]


def test_vault_audit_counts_responses_and_compares_policies(inv):
    u = asset(inv, "vault", "payments").observed_use
    assert u["succeeded"] == 3
    p = u["principals"][0]
    assert p["id"] == "approle-payments" and p["operations"] == {"encrypt": 2, "decrypt": 1}
    assert p["policies"] == ["payments-transit"] and p["authorized"] is True
    assert [x["id"] for x in u["authorized_not_seen"]] == ["old-batch"]
    jwt = asset(inv, "vault", "jwt").observed_use
    assert jwt["succeeded"] == 0 and jwt["denied"] == 1  # sign/jwt/sha2-256 refused
    assert jwt["principals"][0]["authorized"] is False  # policy "auth" is not the one that grants sign


def test_azure_matches_the_versionless_key_id_case_insensitively(inv):
    u = asset(inv, "azure", "payments").observed_use
    app = next(p for p in u["principals"] if p["id"].startswith("1111aaaa"))
    assert app["operations"] == {"KeyDecrypt": 2} and app["authorized"] is True
    eve = next(p for p in u["principals"] if p["id"].startswith("9999bbbb"))
    assert eve["name"] == "eve@example.com" and eve["denied"] == 1 and eve["authorized"] is False
    assert u["authorized_not_seen"] == []


def test_gcp_matches_service_account_members(inv):
    u = asset(inv, "gcp", "payments-kek").observed_use
    assert u["principals"][0]["operations"] == {"Decrypt": 2} and u["principals"][0]["authorized"] is True
    signing = asset(inv, "gcp", "signing").observed_use
    assert signing["denied"] == 1 and signing["principals"][0]["authorized"] is None  # no consumers recorded


def test_window_days_drops_older_calls():
    i = estate()
    apply(i, ALL[:1], Policy.default(), window_days=5, now=NOW)
    u = asset(i, "aws", "payments").observed_use
    assert u["succeeded"] == 2 and u["window"]["from"] == "2026-11-15T09:30:00Z"
    assert i.usage["window_days"] == 5


def test_a_log_can_be_limited_to_named_sources():
    i = estate()
    apply(i, [{"type": "vault-audit", "path": str(LOGS / "vault-audit.log"), "sources": ["other-vault"]}],
          Policy.default())  # fmt: skip
    assert asset(i, "vault", "payments").observed_use is None


def test_summary_inventory_json_and_round_trip(inv):
    s = inv.summary()
    assert (s["assets_usage_covered"], s["assets_used"], s["assets_not_used"]) == (7, 4, 3)
    d = json.loads(json.dumps(inv.to_dict()))
    assert d["usage"]["logs"][0]["title"] == "AWS CloudTrail"
    again = Inventory.from_dict(d)
    assert asset(again, "aws", "payments").observed_use == asset(inv, "aws", "payments").observed_use
    assert again.summary()["assets_not_used"] == 3
    assert estate().summary()["assets_usage_covered"] is None  # no log read: unknown, not zero


def test_cbom_carries_observed_use_and_stays_valid(inv, cdx_validator, validator17):  # noqa: F811
    for version, validator in (("1.6", cdx_validator), ("1.7", validator17)):
        bom = json.loads(cbom.render(inv, version))
        assert not list(validator.iter_errors(bom))
        comp = next(c for c in bom["components"] if c.get("name") == "payments" and c.get("group") == "aws")
        props = {(p["name"], p["value"]) for p in comp["properties"]}
        assert ("keycensus:observedUseEvents", "4") in props
        assert any(n == "keycensus:observedUse" and "Decrypt=3,GenerateDataKey=1" in v for n, v in props)
        assert any(n == "keycensus:authorizedNotSeen" and "old-batch" in v for n, v in props)
        assert any(p["name"] == "keycensus:auditLog:cloudtrail" for p in bom["metadata"]["properties"])


def test_csv_report_and_metrics(inv):
    rows = {(r["source"], r["name"]): r for r in csv.DictReader(io.StringIO(csv_export.render(inv)))}
    assert rows[("aws", "payments")]["observed_use"] == "arn:aws:iam::111122223333:role/payments-api(4)"
    assert rows[("aws", "idle")]["observed_use"] == "none"
    assert rows[("aws", "other-region")]["observed_use"] == ""
    html = html_report.render(inv)
    assert "Observed use (" in html and "Authorised, not seen (4)" in html and "Covered, not used (3)" in html
    assert "not in Used by" in html and "9999ffff" in html
    coll = InventoryCollector()
    coll.inventory = inv
    m = {f.name: f for f in coll.collect()}
    assert m["keycensus_assets_not_used"].samples[0].value == 3.0
    calls = {tuple(sorted(s.labels.items())): s.value for s in m["keycensus_audit_log_calls"].samples}
    assert calls[(("log", "cloudtrail"), ("matched", "false"))] == 1.0


def test_policy_can_turn_the_finding_off():
    i = estate()
    apply(i, ALL, Policy({"name": "x", "rules": {"key-not-used": {"enabled": False}}}))
    assert not [f for f in i.findings if f.rule_id == "key-not-used"]


def test_cli_usage_rewrites_a_saved_scan(tmp_path):
    (tmp_path / "in.json").write_text(json.dumps(estate().to_dict()))
    res = CliRunner().invoke(main, ["usage", "-i", str(tmp_path / "in.json"), "-o", str(tmp_path / "out"),
                                    "--log", f"cloudtrail:{LOGS / 'cloudtrail.json'}", "-f", "json"])  # fmt: skip
    assert res.exit_code == 0, res.output
    assert "AWS CloudTrail" in res.output and "1 key(s) used but not in the inventory" in res.output
    out = json.loads((tmp_path / "out" / "inventory.json").read_text())
    assert out["summary"]["assets_used"] == 1
    bad = CliRunner().invoke(main, ["usage", "-i", str(tmp_path / "in.json"), "--log", "syslog:/tmp/x"])
    assert bad.exit_code != 0 and "log type 'syslog'" in bad.output


def test_config_usage_block(tmp_path):
    base = "sources:\n  - {name: aws, type: aws-kms}\n"
    good = tmp_path / "good.yml"
    good.write_text(base + "usage:\n  window_days: 30\n  logs:\n    - {type: cloudtrail, path: ct/, sources: [aws]}\n")
    cfg = load(good)
    assert cfg.usage_window_days == 30 and cfg.usage_logs[0]["type"] == "cloudtrail"
    for body, msg in (
        ("usage:\n  logs:\n    - {type: syslog, path: x}\n", "log type"),
        ("usage:\n  logs:\n    - {type: cloudtrail}\n", "'type' and 'path'"),
        ("usage:\n  window_days: 0\n  logs: []\n", "window_days"),
        ("usage:\n  logs:\n    - {type: cloudtrail, path: x, sources: [nope]}\n", "not in 'sources'"),
    ):
        p = tmp_path / "bad.yml"
        p.write_text(base + body)
        with pytest.raises(ConfigError, match=msg):
            load(p)


def test_missing_log_path_is_an_error():
    with pytest.raises(UsageError, match="no such file"):
        read_log("cloudtrail", LOGS / "nope")
