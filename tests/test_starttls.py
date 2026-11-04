"""LDAP StartTLS on port 389, against a real OpenLDAP slapd."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from keycensus.analysis.policy import Policy, evaluate
from keycensus.collectors import build
from keycensus.collectors.starttls import (
    StartTlsError,
    ldap_starttls_request,
    open_socket,
    parse_ldap_extended_response,
)
from keycensus.collectors.tls_endpoint import _parse_endpoint
from keycensus.model import KIND_CERTIFICATE, KIND_PROTOCOL

from .conftest import source

SLAPD = shutil.which("slapd") or ("/usr/sbin/slapd" if Path("/usr/sbin/slapd").exists() else None)
SCHEMA = Path("/etc/ldap/schema/core.schema")
needs_slapd = pytest.mark.skipif(not SLAPD or not SCHEMA.exists() or not shutil.which("openssl"),
                                 reason="needs OpenLDAP slapd and openssl")  # fmt: skip


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Slapd:
    def __init__(self, d: Path, tls: bool):
        d.mkdir(parents=True, exist_ok=True)
        (d / "db").mkdir(exist_ok=True)
        conf = [f"include {SCHEMA}", f"pidfile {d}/slapd.pid", "modulepath /usr/lib/ldap", "moduleload back_mdb",
                "database mdb", 'suffix "dc=example,dc=com"',
                f"directory {d}/db", "maxsize 10485760"]  # fmt: skip
        if tls:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                            "-nodes", "-days", "30", "-subj", "/CN=dc01.example.com", "-keyout", str(d / "k.pem"),
                            "-out", str(d / "c.pem")], check=True, capture_output=True)  # fmt: skip
            conf[1:1] = [f"TLSCertificateFile {d}/c.pem", f"TLSCertificateKeyFile {d}/k.pem"]
        (d / "slapd.conf").write_text("\n".join(conf) + "\n")
        self.port = _free_port()
        # -d 256 logs connections and errors, so a failure to start says why. A file, not a pipe: nothing reads
        # the log while slapd runs, and a full pipe would block it.
        self.log = d / "slapd.log"
        with open(self.log, "wb") as log:
            self.proc = subprocess.Popen([SLAPD, "-f", str(d / "slapd.conf"), "-h", f"ldap://127.0.0.1:{self.port}/",
                                          "-d", "256"], stdout=subprocess.DEVNULL, stderr=log)  # fmt: skip
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                if self.proc.poll() is not None:
                    tail = self.log.read_text(errors="replace")[-2000:]
                    self._unavailable(f"exit code {self.proc.returncode}: {tail}")
                time.sleep(0.05)
        self.proc.kill()
        self._unavailable("did not listen within 5 seconds")

    @staticmethod
    def _unavailable(why: str):
        """slapd is installed but cannot run here (on Ubuntu, usually its AppArmor profile, which confines it
        to /etc/ldap and /var/lib/ldap). Skip, unless KEYCENSUS_REQUIRE_SLAPD says this machine must run it."""
        msg = f"slapd could not start ({why}). On Ubuntu: sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.slapd"
        if os.environ.get("KEYCENSUS_REQUIRE_SLAPD"):
            raise RuntimeError(msg)
        pytest.skip(msg)

    def close(self):
        self.proc.terminate()
        self.proc.wait(5)


@pytest.fixture
def slapd_tls(tmp_path):
    s = Slapd(tmp_path / "tls", tls=True)
    yield s
    s.close()


@pytest.fixture
def slapd_plain(tmp_path):
    s = Slapd(tmp_path / "plain", tls=False)
    yield s
    s.close()


def test_request_encoding_and_response_parsing():
    req = ldap_starttls_request()
    assert req == bytes.fromhex("301d02010177188016") + b"1.3.6.1.4.1.1466.20037"
    ok = bytes.fromhex("300c02010178070a010004000400")
    assert parse_ldap_extended_response(ok) == (0, "")
    diag = b"TLS not configured"
    body = bytes.fromhex("0a0134") + b"\x04\x00" + bytes([0x04, len(diag)]) + diag
    msg = b"\x30" + bytes([5 + len(body)]) + bytes.fromhex("020101") + b"\x78" + bytes([len(body)]) + body
    assert parse_ldap_extended_response(msg) == (52, "TLS not configured")


def test_endpoint_schemes():
    assert _parse_endpoint("ldap://dc01.corp") == ("dc01.corp", 389, "ldap")
    assert _parse_endpoint("ldap://dc01.corp:3268") == ("dc01.corp", 3268, "ldap")
    assert _parse_endpoint("ldaps://dc01.corp") == ("dc01.corp", 636, None)
    assert _parse_endpoint("api.example.com:8443") == ("api.example.com", 8443, None)
    assert _parse_endpoint("api.example.com") == ("api.example.com", 443, None)
    assert _parse_endpoint("[2001:db8::1]:443") == ("2001:db8::1", 443, None)
    assert _parse_endpoint("ldap://[2001:db8::1]") == ("2001:db8::1", 389, "ldap")
    with pytest.raises(ValueError, match="scheme"):
        _parse_endpoint("smtp://mail:25")


@needs_slapd
def test_tls_collector_upgrades_ldap(slapd_tls):
    col = build(source("ad", "tls", endpoints=[f"ldap://127.0.0.1:{slapd_tls.port}"], timeout=3))
    result = col.run()
    assert result.error is None
    proto = next(a for a in result.assets if a.kind == KIND_PROTOCOL)
    cert = next(a for a in result.assets if a.kind == KIND_CERTIFICATE)
    assert proto.protocol == "TLS" and proto.extra["starttls"] == "ldap" and "error" not in proto.extra
    assert proto.protocol_version in ("TLSv1.2", "TLSv1.3")
    if proto.protocol_version == "TLSv1.3":
        assert proto.key_exchange  # the key exchange probe also went through StartTLS
    assert cert.subject == "CN=dc01.example.com" and cert.algorithm == "EC"


@needs_slapd
def test_network_discovers_starttls_and_cleartext_ldap(slapd_tls, slapd_plain):
    col = build(source("dc", "network", cidrs=["127.0.0.1/32"], timeout=3, connect_timeout=0.5,
                       ports={slapd_tls.port: "ldap-starttls", slapd_plain.port: "ldap-starttls"}))  # fmt: skip
    result = col.run()
    assert result.error is None
    by = {(a.kind, a.name): a for a in result.assets}
    up = by[(KIND_PROTOCOL, f"127.0.0.1:{slapd_tls.port}")]
    assert up.protocol == "TLS" and up.extra["service"] == "ldap-starttls" and up.extra["starttls"] == "ldap"
    assert KIND_CERTIFICATE in {k for k, _ in by}
    clear = by[(KIND_PROTOCOL, f"127.0.0.1:{slapd_plain.port}")]
    assert clear.protocol == "LDAP" and "refused" in clear.extra["starttls_error"]
    rules = {(f.rule_id, f.asset_name) for f in evaluate(result.assets, Policy.default())}
    assert ("ldap-cleartext", clear.name) in rules and ("ldap-cleartext", up.name) not in rules


@needs_slapd
def test_refusal_is_reported(slapd_plain):
    with pytest.raises(StartTlsError, match="refused"):
        open_socket("127.0.0.1", slapd_plain.port, 3, "ldap")


def test_non_ldap_port_is_not_ldap(tmp_path):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    import threading

    def serve():
        c, _ = srv.accept()
        c.recv(100)
        c.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
        c.close()

    threading.Thread(target=serve, daemon=True).start()
    with pytest.raises(StartTlsError, match="not an LDAP server"):
        open_socket("127.0.0.1", port, 2, "ldap")
    srv.close()
