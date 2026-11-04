"""serve authentication and TLS, the hash-chained audit log, signed scan records."""

from __future__ import annotations

import base64
import json
import ssl
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization

from keycensus import audit as audit_mod
from keycensus import signing
from keycensus.audit import AuditLog
from keycensus.cli import main
from keycensus.config import ConfigError
from keycensus.serve import ServeSettings, State, make_handler

from .conftest import make_cert, pem

TOKEN = "kc-test-token-0123456789"


# ===================================================================== serve settings
def test_non_loopback_without_auth_is_refused(monkeypatch):
    monkeypatch.delenv("KEYCENSUS_SERVE_TOKEN", raising=False)
    monkeypatch.delenv("KEYCENSUS_LISTEN", raising=False)
    monkeypatch.delenv("KEYCENSUS_ALLOW_UNAUTHENTICATED", raising=False)
    assert ServeSettings.from_config({}).listen == "127.0.0.1"
    with pytest.raises(ConfigError, match="without authentication"):
        ServeSettings.from_config({"listen": "0.0.0.0"})
    assert ServeSettings.from_config({"listen": "0.0.0.0", "allow_unauthenticated": True}).allow_unauthenticated
    assert ServeSettings.from_config({}, listen="0.0.0.0", insecure_no_auth=True).allow_unauthenticated
    monkeypatch.setenv("KEYCENSUS_SERVE_TOKEN", TOKEN)
    s = ServeSettings.from_config({"listen": "0.0.0.0"})
    assert list(s.tokens) == ["default"] and TOKEN.encode() not in b"".join(s.tokens.values())


def test_token_validation(monkeypatch):
    monkeypatch.setenv("SHORT", "abc")
    with pytest.raises(ConfigError, match="shorter than 16"):
        ServeSettings.from_config({"auth": {"tokens": [{"name": "x", "token_env": "SHORT"}]}})
    with pytest.raises(ConfigError, match="token_vault"):
        ServeSettings.from_config({"auth": {"tokens": [{"name": "x", "token": "inline-is-not-allowed-here"}]}})
    with pytest.raises(ConfigError, match="both cert_file and key_file"):
        ServeSettings.from_config({"tls": {"cert_file": "/x"}})


# ===================================================================== serve over HTTP(S)
def _start(settings, audit=None, tls_ctx=None):
    state = State()
    state.ready = True
    state.outputs = {"/report.html": ("text/html", "<h1>report</h1>"), "/cbom.json": ("application/json", "{}")}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state, settings, audit))
    if tls_ctx:
        srv.socket = tls_ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"{'https' if tls_ctx else 'http'}://127.0.0.1:{srv.server_address[1]}"


def _get(url, headers=None, ctx=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_tokens_protect_reports_not_metrics(monkeypatch, tmp_path):
    monkeypatch.setenv("KC_T", TOKEN)
    monkeypatch.delenv("KEYCENSUS_SERVE_TOKEN", raising=False)
    settings = ServeSettings.from_config({"auth": {"tokens": [{"name": "grafana", "token_env": "KC_T"}]}})
    log = AuditLog(tmp_path / "audit.jsonl")
    srv, base = _start(settings, log)
    try:
        code, hdrs, _ = _get(f"{base}/report.html")
        assert code == 401 and "Basic" in hdrs["WWW-Authenticate"]
        assert _get(f"{base}/cbom.json", {"Authorization": "Bearer wrong-token-xxxxxxxxx"})[0] == 401
        code, hdrs, body = _get(f"{base}/cbom.json", {"Authorization": f"Bearer {TOKEN}"})
        assert code == 200 and body == b"{}" and hdrs["X-Content-Type-Options"] == "nosniff"
        basic = base64.b64encode(f"anyone:{TOKEN}".encode()).decode()
        assert _get(f"{base}/report.html", {"Authorization": f"Basic {basic}"})[0] == 200
        assert _get(f"{base}/metrics")[0] == 200
        assert _get(f"{base}/healthz")[0] == 200 and _get(f"{base}/livez")[0] == 200
    finally:
        srv.shutdown()
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [e["event"] for e in events] == ["serve.denied", "serve.denied", "serve.read", "serve.read"]
    assert events[1]["reason"] == "invalid token" and events[2]["token"] == "grafana"
    assert TOKEN not in (tmp_path / "audit.jsonl").read_text()
    assert audit_mod.verify(tmp_path / "audit.jsonl")[0]


def test_metrics_can_be_protected_too(monkeypatch):
    monkeypatch.setenv("KC_T", TOKEN)
    settings = ServeSettings.from_config({"auth": {"tokens": [{"token_env": "KC_T"}], "public_paths": []}})
    srv, base = _start(settings)
    try:
        assert _get(f"{base}/metrics")[0] == 401
        assert _get(f"{base}/livez")[0] == 200  # liveness never needs a token
    finally:
        srv.shutdown()


def test_tls(tmp_path, monkeypatch):
    monkeypatch.delenv("KEYCENSUS_SERVE_TOKEN", raising=False)
    key, cert = make_cert("localhost")
    (tmp_path / "c.pem").write_bytes(pem(cert))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))  # fmt: skip
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(str(tmp_path / "c.pem"), str(tmp_path / "k.pem"))
    srv, base = _start(ServeSettings(allow_unauthenticated=True), tls_ctx=sctx)
    cctx = ssl.create_default_context(cafile=str(tmp_path / "c.pem"))
    cctx.check_hostname = False
    try:
        assert base.startswith("https://") and _get(f"{base}/report.html", ctx=cctx)[0] == 200
    finally:
        srv.shutdown()


# ===================================================================== audit log
def test_audit_chain_detects_edits_and_deletions(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(4):
        log.write("serve.read", path=f"/r{i}", token="t")
    assert audit_mod.verify(p) == (True, 4, "4 entries, chain intact")
    lines = p.read_text().splitlines()

    edited = lines.copy()
    e = json.loads(edited[1])
    e["token"] = "someone-else"
    edited[1] = json.dumps(e, sort_keys=True)
    p.write_text("\n".join(edited) + "\n")
    ok, n, msg = audit_mod.verify(p)
    assert not ok and n == 1 and "does not match" in msg

    p.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
    ok, _, msg = audit_mod.verify(p)
    assert not ok and "chain broken" in msg


def test_audit_hmac_and_continuation_after_rotation(tmp_path, monkeypatch):
    monkeypatch.setenv("AK", "audit-hmac-key")
    p = tmp_path / "a.jsonl"
    log = AuditLog.from_config({"path": str(p), "hmac_key_env": "AK"})
    log.write("scan.start", config_sha256="c1", policy_sha256="p1", sources=[])
    assert audit_mod.verify(p, b"audit-hmac-key")[0]
    assert not audit_mod.verify(p)[0]  # without the key the hashes do not match
    last = json.loads(p.read_text().splitlines()[-1])
    p.rename(tmp_path / "a.jsonl.1")  # rotate

    log2 = AuditLog.from_config({"path": str(p), "hmac_key_env": "AK"})
    entry = log2.write("serve.read", path="/cbom.json", token="t")
    assert entry["prev"] == last["hash"] and entry["seq"] == last["seq"] + 1
    ok, _, msg = audit_mod.verify(p, b"audit-hmac-key")
    assert ok and f"continues from hash {last['hash']}" in msg


def test_audit_records_config_change(tmp_path):
    class Cfg:
        config_sha256 = "aaa"
        sources = []

    log = AuditLog(tmp_path / "a.jsonl")
    log.scan_started(Cfg, "p")
    Cfg.config_sha256 = "bbb"
    AuditLog(tmp_path / "a.jsonl").scan_started(Cfg, "p")  # a new process reads the last hashes back
    events = [json.loads(x)["event"] for x in (tmp_path / "a.jsonl").read_text().splitlines()]
    assert events == ["scan.start", "config.changed", "scan.start"]


# ===================================================================== scan: audit + signing end to end
def test_scan_writes_audit_and_signed_manifest(tmp_path, cert_dir, monkeypatch):
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(main, ["keygen", "--out", "sk"]).exit_code == 0
    assert runner.invoke(main, ["keygen", "--out", "sk"]).exit_code != 0  # never overwrites a key
    open("k.yml", "w").write(
        f"sources:\n  - {{name: certs, type: pem, paths: [{cert_dir}], password_env: NOPE}}\n"
        "audit: {path: audit.jsonl}\nsigning: {private_key_file: sk.pem}\n"
    )
    r = runner.invoke(main, ["scan", "-c", "k.yml", "-o", "out"])
    assert "signed out/manifest.json" in r.output, r.output
    assert runner.invoke(main, ["verify", "out", "--public-key", "sk.pub.pem"]).exit_code == 0

    events = [json.loads(x) for x in open("audit.jsonl").read().splitlines()]
    assert [e["event"] for e in events] == ["scan.start", "scan.signed", "scan.end"]
    assert events[0]["sources"][0]["credentials"] == ["password_env=NOPE"]
    assert set(events[2]["outputs"]) == {"inventory.json", "cbom.json", "inventory.csv", "report.html"}
    assert runner.invoke(main, ["audit", "verify", "audit.jsonl"]).exit_code == 0

    with open("out/cbom.json", "a") as fh:
        fh.write(" ")
    r = runner.invoke(main, ["verify", "out", "--public-key", "sk.pub.pem"])
    assert r.exit_code == 1 and "MODIFIED  cbom.json" in r.output

    signing.keygen("other")
    r = runner.invoke(main, ["verify", "out", "--public-key", "other.pub.pem"])
    assert r.exit_code == 1 and "INVALID" in r.output


def test_signing_rejects_non_ed25519_keys(tmp_path):
    key, _ = make_cert("x")
    (tmp_path / "rsa.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                         serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))  # fmt: skip
    with pytest.raises(signing.SigningError, match="Ed25519"):
        signing.load_private_key({"private_key_file": str(tmp_path / "rsa.pem")})


def test_serve_refuses_to_start_open_on_all_interfaces(tmp_path, monkeypatch):
    monkeypatch.delenv("KEYCENSUS_SERVE_TOKEN", raising=False)
    monkeypatch.delenv("KEYCENSUS_ALLOW_UNAUTHENTICATED", raising=False)
    (tmp_path / "k.yml").write_text("sources:\n  - {name: a, type: pem, paths: [/tmp]}\n")
    r = CliRunner().invoke(main, ["serve", "-c", str(tmp_path / "k.yml"), "--listen", "0.0.0.0"])
    assert r.exit_code != 0 and "without authentication" in r.output
