"""RFC 3161 timestamps on signed scans, against a local `openssl ts` TSA."""

from __future__ import annotations

import datetime as dt
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from keycensus import signing
from keycensus import timestamp as ts
from keycensus.cli import main

pytestmark = pytest.mark.skipif(
    not shutil.which("openssl")
    or subprocess.run(["openssl", "ts", "-help"], capture_output=True).returncode not in (0, 1),
    reason="needs openssl with the ts command",
)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _pem_key(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _make_tsa(tmp_path, cn="Test TSA", eku=True):
    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(_name(f"{cn} Root")).issuer_name(_name(f"{cn} Root"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))  # fmt: skip
    key = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca.subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
         .not_valid_after(now + dt.timedelta(days=90))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))  # fmt: skip
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
    cert = b.sign(ca_key, hashes.SHA256())
    d = tmp_path / cn.replace(" ", "_")
    d.mkdir()
    (d / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (d / "tsa.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "tsa.key").write_bytes(_pem_key(key))
    (d / "serial").write_text("01\n")
    (d / "ts.cnf").write_text(
        "[ tsa ]\ndefault_tsa = t\n[ t ]\n"
        f"serial = {d}/serial\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256, sha384\n"
        "accuracy = secs:1\nordering = no\ntsa_name = yes\ness_cert_id_alg = sha256\n"
    )
    return d


class Tsa:
    """`openssl ts -reply` behind HTTP: a real, independent RFC 3161 implementation."""

    def __init__(self, d, status=200):
        self.d, self.status, self.requests = d, status, 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):  # noqa: N802
                outer.requests += 1
                body = self.rfile.read(int(self.headers["Content-Length"]))
                if outer.status != 200:
                    self.send_response(outer.status)
                    self.end_headers()
                    return
                (outer.d / "q.tsq").write_bytes(body)
                subprocess.run(["openssl", "ts", "-reply", "-config", str(outer.d / "ts.cnf"), "-queryfile",
                                str(outer.d / "q.tsq"), "-signer", str(outer.d / "tsa.pem"), "-inkey",
                                str(outer.d / "tsa.key"), "-out", str(outer.d / "r.tsr")],
                               check=True, capture_output=True)  # fmt: skip
                out = (outer.d / "r.tsr").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/timestamp-reply")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/tsr"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def tsa(tmp_path):
    t = Tsa(_make_tsa(tmp_path))
    yield t
    t.close()


def test_request_and_verify(tsa):
    der, stamp, url = ts.request(b"signature", [tsa.url], str(tsa.d / "ca.pem"))
    assert url == tsa.url and stamp.chain_verified and stamp.tsa == "CN=Test TSA"
    assert abs((stamp.gen_time - dt.datetime.now(dt.UTC)).total_seconds()) < 60
    assert ts.verify(der, b"signature", str(tsa.d / "ca.pem")).serial == stamp.serial
    with pytest.raises(ts.TimestampError, match="different data"):
        ts.verify(der, b"another signature", str(tsa.d / "ca.pem"))
    with pytest.raises(ts.TimestampError, match="nonce"):
        ts.verify(der, b"signature", expect_nonce=12345)
    assert ts.verify(der, b"signature").chain_verified is False  # signature checked, TSA not trusted


def test_untrusted_tsa_is_rejected(tsa, tmp_path):
    other = _make_tsa(tmp_path, cn="Other TSA")
    der, _, _ = ts.request(b"sig", [tsa.url])
    with pytest.raises(ts.TimestampError, match="does not chain"):
        ts.verify(der, b"sig", str(other / "ca.pem"))


def test_falls_back_to_the_next_tsa(tsa, tmp_path):
    down = Tsa(_make_tsa(tmp_path, cn="Down TSA"), status=503)
    try:
        _, stamp, url = ts.request(b"sig", [down.url, tsa.url], str(tsa.d / "ca.pem"))
    finally:
        down.close()
    assert url == tsa.url and down.requests == 1
    with pytest.raises(ts.TimestampError, match="no TSA gave a valid timestamp"):
        ts.request(b"sig", ["http://127.0.0.1:1/tsr"], timeout=1)


def test_tsa_trusted_by_the_wrong_root_is_refused_at_request_time(tsa, tmp_path):
    other = _make_tsa(tmp_path, cn="Elsewhere")
    with pytest.raises(ts.TimestampError, match="does not chain"):
        ts.request(b"sig", [tsa.url], str(other / "ca.pem"))


def test_scan_timestamps_the_signature_and_verify_checks_it(tsa, tmp_path, cert_dir, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    assert runner.invoke(main, ["keygen", "--out", "sk"]).exit_code == 0
    ca = tsa.d / "ca.pem"
    (tmp_path / "k.yml").write_text(
        f"sources:\n  - {{name: certs, type: pem, paths: [{cert_dir}]}}\n"
        f"signing:\n  private_key_file: sk.pem\n  timestamp: {{urls: [{tsa.url}], ca_file: {ca}}}\n"
    )
    r = runner.invoke(main, ["scan", "-c", "k.yml", "-o", "out"])
    assert "timestamped by" in r.output, r.output
    assert (tmp_path / "out" / "manifest.json.tsr").exists()

    r = runner.invoke(main, ["verify", "out", "--public-key", "sk.pub.pem", "--tsa-ca-file", str(ca),
                             "--require-timestamp"])  # fmt: skip
    assert r.exit_code == 0 and "TSA chain verified" in r.output, r.output
    r = runner.invoke(main, ["verify", "out", "--public-key", "sk.pub.pem", "--require-timestamp"])
    assert r.exit_code == 1 and "TSA NOT verified" in r.output

    # openssl agrees, without keycensus
    sig = signing.base64.b64decode((tmp_path / "out" / "manifest.json.sig").read_bytes().strip())
    (tmp_path / "sig.bin").write_bytes(sig)
    ok = subprocess.run(["openssl", "ts", "-verify", "-in", "out/manifest.json.tsr", "-data", "sig.bin",
                         "-CAfile", str(ca)], capture_output=True, text=True)  # fmt: skip
    assert "Verification: OK" in ok.stdout + ok.stderr

    # a timestamp moved next to another signature fails
    tsr = (tmp_path / "out" / "manifest.json.tsr").read_bytes()
    assert runner.invoke(main, ["scan", "-c", "k.yml", "-o", "out2"]).exit_code in (0, 2)
    (tmp_path / "out2" / "manifest.json.tsr").write_bytes(tsr)
    r = runner.invoke(main, ["verify", "out2", "--public-key", "sk.pub.pem", "--tsa-ca-file", str(ca)])
    assert r.exit_code == 1 and "timestamp INVALID" in r.output


def test_required_timestamp_fails_the_scan(tmp_path, cert_dir, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    runner.invoke(main, ["keygen", "--out", "sk"])
    (tmp_path / "k.yml").write_text(
        f"sources:\n  - {{name: certs, type: pem, paths: [{cert_dir}]}}\naudit: {{path: audit.jsonl}}\n"
        "signing:\n  private_key_file: sk.pem\n  timestamp: {urls: ['http://127.0.0.1:1/tsr'], required: true, "
        "timeout: 1}\n"
    )
    r = runner.invoke(main, ["scan", "-c", "k.yml", "-o", "out"])
    assert r.exit_code != 0 and "required and failed" in r.output
    assert '"event": "scan.signing_failed"' in (tmp_path / "audit.jsonl").read_text()

    # optional: the scan succeeds with a warning and no .tsr
    (tmp_path / "k.yml").write_text((tmp_path / "k.yml").read_text().replace("required: true", "required: false"))
    r = runner.invoke(main, ["scan", "-c", "k.yml", "-o", "out"])
    assert "warning: no trusted timestamp" in r.output and not (tmp_path / "out" / "manifest.json.tsr").exists()
