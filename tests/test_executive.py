"""Executive summary: share of quantum-vulnerable keys and what falls due before each PQC date."""

from __future__ import annotations

import datetime as dt
import re

from click.testing import CliRunner
from prometheus_client import CollectorRegistry, generate_latest

from keycensus.analysis.executive import summarize
from keycensus.analysis.policy import Policy, evaluate
from keycensus.cli import main
from keycensus.exporters.html_report import render
from keycensus.exporters.prometheus import InventoryCollector
from keycensus.model import KIND_CERTIFICATE, KIND_PROTOCOL, Inventory, SourceResult, utcnow

from .conftest import make_asset

TODAY = dt.date(2026, 11, 4)
UTC = dt.UTC


def _inv(assets):
    inv = Inventory(generated_at=utcnow(), sources=[SourceResult(name="t", type="test", assets=assets)])
    inv.findings = evaluate(assets, Policy.default())
    return inv


def _estate():
    far = dt.datetime(2033, 6, 1, tzinfo=UTC)
    return [
        make_asset(name="rsa-wrap", native_id="1", algorithm="RSA", key_size=3072, key_type="private-key",
                   purposes=["wrap", "unwrap"]),
        make_asset(name="rsa-wrap", native_id="1p", algorithm="RSA", key_size=3072, key_type="public-key",
                   purposes=["wrap"]),  # public half of the same pair: not counted twice
        make_asset(name="ecdsa-sign", native_id="2", algorithm="EC", curve="P-256", key_size=256,
                   key_type="private-key", purposes=["sign"]),
        make_asset(name="rsa-both", native_id="3", algorithm="RSA", key_size=2048, key_type="private-key",
                   purposes=["sign", "decrypt"]),  # falls due at the earlier date
        make_asset(name="mystery", native_id="4", algorithm="RSA", key_size=2048, key_type="private-key"),
        make_asset(kind=KIND_CERTIFICATE, name="www", native_id="5", algorithm="RSA", key_size=2048,
                   key_type="public-key", expires=far, signature_hash="SHA256"),
        make_asset(kind=KIND_CERTIFICATE, name="legacy", native_id="6", algorithm="RSA", key_size=1024,
                   key_type="public-key", signature_hash="SHA1",
                   expires=dt.datetime(2027, 1, 1, tzinfo=UTC)),
        make_asset(name="aes", native_id="7", algorithm="AES", key_size=256, key_type="secret-key",
                   purposes=["encrypt"]),
        make_asset(name="mlkem", native_id="8", algorithm="ML-KEM", key_size=768, key_type="private-key"),
        make_asset(kind=KIND_PROTOCOL, name="a:443", native_id="9", protocol="TLS", key_exchange="x25519"),
        make_asset(kind=KIND_PROTOCOL, name="b:443", native_id="10", protocol="TLS", key_exchange="X25519MLKEM768"),
        make_asset(kind=KIND_PROTOCOL, name="c:443", native_id="11", protocol="TLS"),  # not probed
    ]  # fmt: skip


def test_shares_and_milestones():
    ex = summarize(_inv(_estate()), today=TODAY)
    assert ex["keys_and_certificates"] == 8  # the public half is folded into its private key
    assert ex["quantum_vulnerable"] == 6
    assert ex["quantum_vulnerable_percent"] == 75.0
    assert ex["vulnerable_by_use"] == {"key-establishment": 2, "signature": 3, "unknown": 1}
    assert ex["harvest_now_decrypt_later"] == 2
    assert ex["endpoints"] == {"probed": 2, "unprobed": 1, "classical": 1, "hybrid": 1, "post_quantum": 0}

    m = {x["id"]: x for x in ex["milestones"]}
    assert list(m) == ["now", "key-establishment-2030", "signatures-2031", "disallowed-2035"]
    assert m["now"]["past"] and m["now"]["assets"] >= 1  # the RSA-1024 / SHA-1 certificate
    assert m["key-establishment-2030"]["assets"] == 2 and m["key-establishment-2030"]["endpoints"] == 1
    assert m["key-establishment-2030"]["days_left"] == (dt.date(2030, 12, 31) - TODAY).days
    assert not m["key-establishment-2030"]["past"]
    assert m["signatures-2031"]["assets"] == 3 and m["signatures-2031"]["valid_past_date"] == 1  # www, 2033
    assert m["disallowed-2035"]["assets"] == 6 and m["disallowed-2035"]["endpoints"] == 1
    assert "6 of 8 keys and certificates (75.0%)" in ex["headline"]
    assert "1 of 2 probed endpoints still use classical key exchange (1 hybrid" in ex["headline"]


def test_past_dates_after_the_deadline():
    ex = summarize(_inv(_estate()), today=dt.date(2032, 1, 2))
    m = {x["id"]: x for x in ex["milestones"]}
    assert m["key-establishment-2030"]["past"] and m["signatures-2031"]["past"]
    assert not m["disallowed-2035"]["past"]


def test_empty_inventory():
    ex = summarize(_inv([]), today=TODAY)
    assert ex["quantum_vulnerable_percent"] == 0.0
    assert ex["headline"] == "No keys or certificates were found."
    assert all(m["assets"] == 0 for m in ex["milestones"])


def test_report_puts_the_summary_first():
    inv = _inv(_estate())
    html = render(inv)
    top = html.index('id="executive-summary"')
    assert top < html.index("At a glance") < html.index("Post-quantum readiness")
    section = html[top : html.index("</section>", top)]
    assert "75.0%" in section
    for d in ("2030-12-31", "2031-12-31", "2035-12-31"):
        assert d in section
    assert "EO 14412" in section and "IR 8547" in section and "12.3.3" in section
    assert "purpose unknown" in section and "hybrid endpoint" in section
    assert not re.search(r"<script", section)


def test_inventory_json_and_metrics():
    inv = _inv(_estate())
    d = inv.to_dict()
    assert d["executive"]["quantum_vulnerable"] == 6
    assert d["executive"]["as_of"] == inv.generated_at.date().isoformat()

    reg = CollectorRegistry()
    c = InventoryCollector(per_asset=False)
    c.inventory = inv
    reg.register(c)
    text = generate_latest(reg).decode()
    assert "keycensus_quantum_vulnerable_ratio 0.75" in text
    assert 'keycensus_pqc_milestone_assets{date="2031-12-31",kind="asset",milestone="signatures-2031"} 3.0' in text
    assert 'keycensus_pqc_milestone_days_left{date="2035-12-31",milestone="disallowed-2035"}' in text


def test_scan_prints_the_summary(tmp_path, cert_dir, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "k.yml").write_text(f"sources:\n  - {{name: certs, type: pem, paths: [{cert_dir}]}}\n")
    r = CliRunner().invoke(main, ["scan", "-c", "k.yml", "-o", "out"])
    assert "quantum:  " in r.output and "2031-12-31" in r.output and "Post-quantum signatures" in r.output
