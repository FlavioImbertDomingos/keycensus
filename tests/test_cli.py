import json

from click.testing import CliRunner

from keycensus.cli import main


def test_scan_pem_and_fail_on(cert_dir, tmp_path):
    cfg = tmp_path / "c.yml"
    cfg.write_text(f"sources:\n  - name: certs\n    type: pem\n    paths: ['{cert_dir}']\n")
    out = tmp_path / "out"
    r = CliRunner().invoke(main, ["scan", "-c", str(cfg), "-o", str(out)])
    assert r.exit_code == 0, r.output
    assert (out / "cbom.json").exists() and (out / "report.html").exists()
    inv = json.loads((out / "inventory.json").read_text())
    assert inv["summary"]["assets"] == 7
    assert "cert-expired" in {f["rule_id"] for f in inv["findings"]}

    r = CliRunner().invoke(main, ["scan", "-c", str(cfg), "-o", str(out), "--fail-on", "critical"])
    assert r.exit_code == 1


def test_scan_exit_2_when_source_fails(tmp_path):
    cfg = tmp_path / "c.yml"
    cfg.write_text("sources:\n  - name: v\n    type: vault\n    url: http://127.0.0.1:1\n    token: x\n")
    r = CliRunner().invoke(main, ["scan", "-c", str(cfg), "-o", str(tmp_path / "o"), "-f", "json"])
    assert r.exit_code == 2
    assert "ERROR" in r.output


def test_validate_and_listings(tmp_path):
    cfg = tmp_path / "c.yml"
    cfg.write_text("sources:\n  - name: a\n    type: pem\n    paths: [/x]\n  - name: b\n    type: nope\n")
    r = CliRunner().invoke(main, ["validate", "-c", str(cfg)])
    assert r.exit_code != 0 and "nope" in r.output
    assert "pkcs11" in CliRunner().invoke(main, ["collectors"]).output
    assert "weak-algorithm" in CliRunner().invoke(main, ["rules"]).output
    assert "PCI-DSS-4.0:12.3.3" in CliRunner().invoke(main, ["controls"]).output
