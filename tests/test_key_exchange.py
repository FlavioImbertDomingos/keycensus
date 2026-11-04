"""TLS 1.3 key exchange probe: classical, hybrid and pure ML-KEM groups."""

from __future__ import annotations

import os
import shutil
import socket
import struct
import subprocess
import threading
import time

import pytest

from keycensus.analysis import strength
from keycensus.analysis.policy import Policy, evaluate
from keycensus.changes import classify
from keycensus.collectors import build
from keycensus.collectors import tls_groups as t
from keycensus.diff import diff_inventories
from keycensus.model import KIND_PROTOCOL, Inventory, SourceResult, utcnow

from .conftest import make_asset, source


# --------------------------------------------------------------------- a scripted TLS 1.3 server
def _parse_client_hello(data: bytes) -> tuple[list[int], list[int]]:
    """(supported_groups, key_share groups) out of a ClientHello record."""
    body = data[9:]
    p = 2 + 32
    p += 1 + body[p]
    p += 2 + struct.unpack("!H", body[p : p + 2])[0]
    p += 1 + body[p]
    end = p + 2 + struct.unpack("!H", body[p : p + 2])[0]
    p += 2
    groups, shares = [], []
    while p < end:
        etype, elen = struct.unpack("!HH", body[p : p + 4])
        e = body[p + 4 : p + 4 + elen]
        p += 4 + elen
        if etype == 0x000A:
            groups = [struct.unpack("!H", e[i : i + 2])[0] for i in range(2, len(e), 2)]
        elif etype == 0x0033:
            q = 2
            while q < len(e):
                g, ln = struct.unpack("!HH", e[q : q + 4])
                shares.append(g)
                q += 4 + ln
    return groups, shares


def _server_hello(group: int | None, retry: bool, tls12: bool = False) -> bytes:
    exts = b""
    if not tls12:
        exts += struct.pack("!HHH", 0x002B, 2, 0x0304)
        share = struct.pack("!H", group) if retry else struct.pack("!HH", group, 32) + os.urandom(32)
        exts += struct.pack("!HH", 0x0033, len(share)) + share
    random = t.HRR_RANDOM if retry else os.urandom(32)
    body = struct.pack("!H", 0x0303) + random + b"\x00" + struct.pack("!H", 0x1301) + b"\x00"
    body += struct.pack("!H", len(exts)) + exts
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


class FakeTls13:
    """Picks the first group in `prefer` that the client offers, like a server-preference TLS stack."""

    def __init__(self, prefer: list[int], tls12: bool = False):
        self.prefer, self.tls12 = prefer, tls12
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                data = conn.recv(65536)
                while len(data) < 5 or len(data) < 5 + struct.unpack("!H", data[3:5])[0]:
                    more = conn.recv(65536)
                    if not more:
                        break
                    data += more
                if self.tls12:
                    conn.sendall(_server_hello(None, False, tls12=True))
                    continue
                offered, shares = _parse_client_hello(data)
                pick = next((g for g in self.prefer if g in offered), None)
                if pick is None:
                    conn.sendall(b"\x15\x03\x03\x00\x02\x02\x28")  # handshake_failure
                else:
                    conn.sendall(_server_hello(pick, retry=pick not in shares))

    def close(self):
        self.sock.close()


@pytest.fixture
def fake():
    servers = []

    def make(prefer, tls12=False):
        s = FakeTls13(prefer, tls12)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()


# --------------------------------------------------------------------- probe
def test_mlkem_key_is_well_formed():
    for param, size in ((512, 800), (768, 1184), (1024, 1568)):
        ek = t._mlkem_ek(param)
        assert len(ek) == size
        packed = ek[:-32]
        for i in range(0, len(packed), 3):  # FIPS 203 modulus check: every 12-bit coefficient < q
            a = packed[i] | ((packed[i + 1] & 0x0F) << 8)
            b = (packed[i + 1] >> 4) | (packed[i + 2] << 4)
            assert a < 3329 and b < 3329
    assert len(t.key_share(0x11EC)) == 1184 + 32
    assert len(t.key_share(0x11EB)) == 65 + 1184
    assert len(t.key_share(0x11ED)) == 97 + 1568


def test_parse_replies():
    r = t.parse_server_reply(_server_hello(0x11EC, retry=False))
    assert (r.outcome, r.group_name) == ("selected", "X25519MLKEM768")
    r = t.parse_server_reply(_server_hello(0x11EB, retry=True))
    assert (r.outcome, r.group_name) == ("retry", "SecP256r1MLKEM768")
    assert t.parse_server_reply(_server_hello(None, False, tls12=True)).outcome == "tls12"
    assert t.parse_server_reply(b"\x15\x03\x03\x00\x02\x02\x28").outcome == "alert"
    assert t.parse_server_reply(b"").outcome == "error"


def test_hybrid_preferred(fake):
    s = fake([0x11EC, 0x001D])
    k = t.assess("127.0.0.1", s.port, 2)
    assert (k.negotiated, k.negotiated_kind, k.pq_supported) == ("X25519MLKEM768", "hybrid", ["X25519MLKEM768"])


def test_hybrid_supported_but_not_preferred_lists_every_pq_group(fake):
    s = fake([0x001D, 0x11EB, 0x0201, 0x11EC])  # SecP256r1MLKEM768 and MLKEM768 only via HelloRetryRequest
    k = t.assess("127.0.0.1", s.port, 2)
    assert k.negotiated == "x25519" and k.negotiated_kind == "classical"
    assert set(k.pq_supported) == {"X25519MLKEM768", "SecP256r1MLKEM768", "MLKEM768"}


def test_classical_only_and_tls12(fake):
    k = t.assess("127.0.0.1", fake([0x001D, 0x0017]).port, 2)
    assert k.negotiated == "x25519" and k.pq_supported == []
    k = t.assess("127.0.0.1", fake([], tls12=True).port, 2)
    assert k.tls13 is False and k.negotiated is None


def test_unreachable_is_reported_not_raised():
    k = t.assess("127.0.0.1", 1, 0.5)
    assert k.negotiated is None and "Error" in k.detail


def test_sni_never_carries_an_ip():
    assert t.sni_for("10.0.0.1") is None and t.sni_for("::1") is None and t.sni_for("api.example.com")


# --------------------------------------------------------------------- against a real OpenSSL 3.5 server
def _node_with_mlkem() -> str | None:
    node = shutil.which("node")
    if not node:
        return None
    out = subprocess.run([node, "-e", "console.log(require('crypto').getCurves ? process.versions.openssl : '')"],
                         capture_output=True, text=True, timeout=10).stdout.strip()  # fmt: skip
    major, _, rest = out.partition(".")
    return node if out and (int(major), int(rest.split(".")[0])) >= (3, 5) else None


@pytest.mark.skipif(not _node_with_mlkem(), reason="needs node linked against OpenSSL 3.5+")
def test_against_openssl35(tmp_path, cert_dir):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from .conftest import make_cert, pem

    key, cert = make_cert("localhost", key=ec.generate_private_key(ec.SECP256R1()))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))  # fmt: skip
    (tmp_path / "c.pem").write_bytes(pem(cert))
    script = (
        "const tls=require('tls'),fs=require('fs');"
        "const s=tls.createServer({key:fs.readFileSync('k.pem'),cert:fs.readFileSync('c.pem'),"
        "ecdhCurve:process.argv[1]},c=>c.end());"
        "s.listen(0,'127.0.0.1',()=>console.log(s.address().port));"
    )
    results = {}
    for curves in ("X25519MLKEM768:X25519", "X25519:SecP256r1MLKEM768"):
        proc = subprocess.Popen([_node_with_mlkem(), "-e", script, curves], cwd=tmp_path, stdout=subprocess.PIPE,
                                text=True)  # fmt: skip
        try:
            port = int(proc.stdout.readline())
            time.sleep(0.2)
            results[curves] = t.assess("127.0.0.1", port, 3)
            col = build(source("edge", "tls", endpoints=[f"127.0.0.1:{port}"], probe_legacy=False))
            assets = col.collect()
            proto = next(a for a in assets if a.kind == KIND_PROTOCOL)
            results[curves + "/asset"] = proto
        finally:
            proc.terminate()
    assert results["X25519MLKEM768:X25519"].negotiated == "X25519MLKEM768"
    assert results["X25519MLKEM768:X25519/asset"].key_exchange == "X25519MLKEM768"
    other = results["X25519:SecP256r1MLKEM768"]
    assert other.negotiated == "x25519" and other.pq_supported == ["SecP256r1MLKEM768"]


# --------------------------------------------------------------------- classification and rules
def _endpoint(kex, pq=()):
    return make_asset(kind=KIND_PROTOCOL, name="api:443", protocol="TLS", protocol_version="TLSv1.3",
                      cipher_suites=["TLS_AES_128_GCM_SHA256"], key_exchange=kex,
                      extra={"key_exchange": {"negotiated": kex, "pq_supported": list(pq)}})  # fmt: skip


def test_key_exchange_classes():
    assert strength.key_exchange_class("x25519")[0] == strength.QUANTUM_VULNERABLE
    assert strength.key_exchange_class("X25519MLKEM768")[0] == strength.QUANTUM_HYBRID
    assert strength.key_exchange_class("mlkem768x25519-sha256")[0] == strength.QUANTUM_HYBRID
    assert strength.key_exchange_class("sntrup761x25519-sha512@openssh.com")[0] == strength.QUANTUM_HYBRID
    assert "not a NIST standard" in strength.key_exchange_class("X25519Kyber768Draft00")[1]
    assert strength.key_exchange_class("MLKEM1024")[0] == strength.QUANTUM_SAFE
    assert strength.key_exchange_class(None)[0] == strength.QUANTUM_UNKNOWN
    assert strength.assess(_endpoint("X25519MLKEM768")).quantum_class == strength.QUANTUM_HYBRID


def test_rules():
    by = {f.rule_id: f for f in evaluate([_endpoint("x25519")], Policy.default())}
    f = by["quantum-vulnerable-key-exchange"]
    assert f.severity == "medium" and {"NIST-IR-8547", "US-EO-14412"} <= set(f.controls)
    assert "X25519MLKEM768" in f.remediation
    f = {x.rule_id: x for x in evaluate([_endpoint("x25519", ["X25519MLKEM768"])], Policy.default())}
    assert "already accepts X25519MLKEM768" in f["quantum-vulnerable-key-exchange"].remediation
    h = {x.rule_id: x for x in evaluate([_endpoint("X25519MLKEM768", ["X25519MLKEM768"])], Policy.default())}
    assert "quantum-vulnerable-key-exchange" not in h
    assert h["hybrid-key-exchange"].severity == "info" and "temporary" in h["hybrid-key-exchange"].title
    assert not {"quantum-vulnerable-key-exchange", "hybrid-key-exchange"} & {
        x.rule_id for x in evaluate([_endpoint(None)], Policy.default())
    }


def test_losing_hybrid_pages():
    def inv(kex):
        return Inventory(generated_at=utcnow(), sources=[SourceResult("edge", "tls", assets=[_endpoint(kex)])])

    lost = [c.kind for c in classify(diff_inventories(inv("X25519MLKEM768"), inv("x25519")))]
    assert "pq-key-exchange-lost" in lost
    gained = [c for c in classify(diff_inventories(inv("x25519"), inv("X25519MLKEM768")))]
    assert [c.kind for c in gained] == ["pq-key-exchange-gained"] and gained[0].urgency == "ignore"
