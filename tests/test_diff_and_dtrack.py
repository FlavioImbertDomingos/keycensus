"""Diff mode (what changed since the last scan) and the Dependency-Track upload helper."""

from __future__ import annotations

import base64
import copy
import datetime as dt
import json

import responses
from click.testing import CliRunner

from keycensus.analysis.policy import Policy, evaluate
from keycensus.cli import main
from keycensus.diff import diff_dicts, diff_files, diff_inventories, render_json, render_markdown, render_text
from keycensus.dtrack import DependencyTrack, DependencyTrackError
from keycensus.exporters import cbom, json_export
from keycensus.model import Inventory, SourceResult, utcnow

from .conftest import make_asset


# --------------------------------------------------------------------- diff
def _inv(assets, sources=None, findings=True) -> dict:
    srcs = sources or [SourceResult(name="t", type="test", assets=list(assets))]
    inv = Inventory(generated_at=utcnow(), sources=srcs)
    if findings:
        inv.findings = evaluate(inv.assets, Policy.load("default"))
    return inv.to_dict()


def test_diff_no_changes(sample_inventory):
    d = diff_inventories(sample_inventory, sample_inventory)
    assert d.empty and "no changes" in render_text(d) and "**No changes.**" in render_markdown(d)
    assert d.summary()["worst_new_severity"] is None


def test_diff_added_removed_changed_and_findings():
    now = utcnow()
    aes = make_asset(
        name="aes",
        native_id="1",
        algorithm="AES",
        key_size=256,
        key_type="secret-key",
        purposes=["encrypt"],
        created=now - dt.timedelta(days=10),
        state="active",
    )
    rsa = make_asset(
        name="rsa",
        native_id="2",
        algorithm="RSA",
        key_size=2048,
        key_type="private-key",
        purposes=["sign"],
        created=now - dt.timedelta(days=100),
        state="active",
    )
    before = _inv([aes, rsa])

    # after: rsa rotated + deactivated, aes gone, a weak 3DES key appeared
    rsa2 = copy.deepcopy(rsa)
    rsa2.state = "deactivated"
    rsa2.last_rotated = now
    tdes = make_asset(
        name="legacy",
        native_id="9",
        algorithm="3DES",
        key_size=192,
        key_type="secret-key",
        purposes=["encrypt"],
        created=now - dt.timedelta(days=3000),
        state="active",
    )
    after = _inv([rsa2, tdes])

    d = diff_dicts(before, after)
    assert [a["name"] for a in d.added] == ["legacy"]
    assert [a["name"] for a in d.removed] == ["aes"]
    assert len(d.changed) == 1 and d.changed[0].name == "rsa"
    assert set(d.changed[0].changes) == {"state", "last_rotated"}
    assert d.changed[0].changes["state"] == {"before": "active", "after": "deactivated"}
    assert {f["asset_name"] for f in d.findings_new} == {"legacy", "rsa"}  # weak 3DES + rsa now deactivated
    assert d.worst_new_severity() in ("critical", "high")
    assert all(f["asset_name"] != "aes" for f in d.findings_new)
    s = d.summary()
    assert s["assets_added"] == 1 and s["assets_removed"] == 1 and s["assets_changed"] == 1

    text = render_text(d)
    assert "+ t/legacy [3DES-192]" in text and "- t/aes [AES-256]" in text and "state: active -> deactivated" in text
    md = render_markdown(d)
    assert "## New findings" in md and "| t | rsa | state | active | deactivated |" in md
    js = json.loads(render_json(d))
    assert js["tool"] == "keycensus-diff" and js["summary"]["findings_new"] == len(d.findings_new)
    assert js["assets_changed"][0]["changes"]["state"]["after"] == "deactivated"


def test_diff_sources_broken_and_fixed():
    a = make_asset(name="k", native_id="1", algorithm="AES", key_size=256)
    before = _inv(
        [a],
        sources=[
            SourceResult(name="hsm", type="pkcs11", assets=[a]),
            SourceResult(name="vault", type="vault", error="401"),
        ],
        findings=False,
    )
    after = _inv(
        [a],
        sources=[
            SourceResult(name="hsm", type="pkcs11", error="connection refused"),
            SourceResult(name="vault", type="vault", assets=[a]),
            SourceResult(name="kv", type="azure-keyvault", assets=[]),
        ],
        findings=False,
    )
    d = diff_dicts(before, after)
    assert d.sources_broken == [{"name": "hsm", "error": "connection refused"}]
    assert d.sources_fixed == ["vault"] and d.sources_added == ["kv"] and d.sources_removed == []
    assert "BROKEN hsm" in render_text(d) and "**BROKEN** `hsm`" in render_markdown(d)
    assert not d.added and not d.removed and not d.changed  # same asset (same source label) both times


def test_diff_cli_and_scan_baseline(cert_dir, tmp_path):
    cfg = tmp_path / "c.yml"
    cfg.write_text(f"sources:\n  - name: certs\n    type: pem\n    paths: ['{cert_dir}']\n")
    out1, out2 = tmp_path / "o1", tmp_path / "o2"
    r = CliRunner().invoke(main, ["scan", "-c", str(cfg), "-o", str(out1), "-f", "json"])
    assert r.exit_code == 0, r.output
    # second scan with a baseline: nothing changed
    r = CliRunner().invoke(
        main,
        [
            "scan",
            "-c",
            str(cfg),
            "-o",
            str(out2),
            "-f",
            "json",
            "--baseline",
            str(out1 / "inventory.json"),
            "--fail-on-new",
            "high",
        ],
    )
    assert r.exit_code == 0, r.output
    assert (out2 / "diff.json").exists() and (out2 / "diff.md").exists() and "no changes" in r.output
    # now remove a cert and add a weak one -> diff sees it; --fail-on-new trips
    (cert_dir / "good.pem").unlink()
    (cert_dir / "weak2.pem").write_bytes((cert_dir / "weak.pem").read_bytes().replace(b"weak", b"weak"))
    out3 = tmp_path / "o3"
    r = CliRunner().invoke(
        main,
        [
            "scan",
            "-c",
            str(cfg),
            "-o",
            str(out3),
            "-f",
            "json",
            "--baseline",
            str(out1 / "inventory.json"),
            "--fail-on-new",
            "high",
        ],
    )
    assert r.exit_code == 3, r.output
    assert "- certs/good" in r.output and "new findings" in r.output

    r = CliRunner().invoke(main, ["diff", str(out1 / "inventory.json"), str(out3 / "inventory.json"), "-f", "markdown"])
    assert r.exit_code == 0 and "## Assets removed" in r.output
    r = CliRunner().invoke(
        main, ["diff", str(out1 / "inventory.json"), str(out1 / "inventory.json"), "--fail-on-change"]
    )
    assert r.exit_code == 0
    r = CliRunner().invoke(
        main, ["diff", str(out1 / "inventory.json"), str(out3 / "inventory.json"), "--fail-on-change"]
    )
    assert r.exit_code == 4
    d = diff_files(out1 / "inventory.json", out3 / "inventory.json")
    assert d.summary()["assets_removed"] == 1
    # not an inventory -> clean error
    (tmp_path / "x.json").write_text("{}")
    r = CliRunner().invoke(main, ["diff", str(tmp_path / "x.json"), str(out1 / "inventory.json")])
    assert r.exit_code != 0 and "not a keycensus inventory" in r.output


# --------------------------------------------------------------------- dependency-track
DT = "https://dtrack.test"


@responses.activate
def test_dtrack_upload_and_wait(sample_inventory, tmp_path):
    bom = tmp_path / "cbom.json"
    bom.write_text(cbom.render(sample_inventory))
    responses.add(responses.PUT, f"{DT}/api/v1/bom", json={"token": "tok-1"})
    responses.add(responses.GET, f"{DT}/api/v1/bom/token/tok-1", json={"processing": True})
    responses.add(responses.GET, f"{DT}/api/v1/bom/token/tok-1", json={"processing": False})
    responses.add(responses.GET, f"{DT}/api/v1/project/lookup", json={"uuid": "u-1", "name": "hsm-estate"})

    dt_ = DependencyTrack(DT, "key-123")
    token = dt_.upload(bom, project="hsm-estate", version="2026-09-02", parent_name="crypto")
    assert token == "tok-1"
    put = responses.calls[0].request
    assert put.headers["X-Api-Key"] == "key-123"
    body = json.loads(put.body)
    assert body["projectName"] == "hsm-estate" and body["projectVersion"] == "2026-09-02" and body["autoCreate"] is True
    assert body["parentName"] == "crypto"
    assert json.loads(base64.b64decode(body["bom"]))["bomFormat"] == "CycloneDX"
    assert dt_.wait("tok-1", timeout=5, interval=0) is True
    assert dt_.project_url(dt_.project("hsm-estate", "2026-09-02")) == f"{DT}/projects/u-1"


@responses.activate
def test_dtrack_errors(sample_inventory, tmp_path):
    bom = tmp_path / "cbom.json"
    bom.write_text(cbom.render(sample_inventory))
    (tmp_path / "inv.json").write_text(json_export.render(sample_inventory))
    dt_ = DependencyTrack(DT, "k")
    try:
        dt_.upload(tmp_path / "inv.json", project="p")
        raise AssertionError("expected DependencyTrackError")
    except DependencyTrackError as exc:
        assert "not a CycloneDX BOM" in str(exc)
    responses.add(responses.PUT, f"{DT}/api/v1/bom", status=401)
    try:
        dt_.upload(bom, project="p")
        raise AssertionError("expected DependencyTrackError")
    except DependencyTrackError as exc:
        assert "BOM_UPLOAD" in str(exc)


@responses.activate
def test_dtrack_cli(sample_inventory, tmp_path, monkeypatch):
    bom = tmp_path / "cbom.json"
    bom.write_text(cbom.render(sample_inventory))
    monkeypatch.setenv("DTRACK_API_KEY", "k")
    responses.add(responses.PUT, f"{DT}/api/v1/bom", json={"token": "t"})
    responses.add(responses.GET, f"{DT}/api/v1/bom/token/t", json={"processing": False})
    responses.add(responses.GET, f"{DT}/api/v1/project/lookup", json={"uuid": "abc"})
    r = CliRunner().invoke(
        main, ["upload", "dtrack", "--url", DT, "--cbom", str(bom), "--project", "hsm", "--version", "v1"]
    )
    assert r.exit_code == 0, r.output
    assert f"{DT}/projects/abc" in r.output
    monkeypatch.delenv("DTRACK_API_KEY")
    r = CliRunner().invoke(main, ["upload", "dtrack", "--url", DT, "--cbom", str(bom), "--project", "hsm"])
    assert r.exit_code != 0 and "no API key" in r.output
