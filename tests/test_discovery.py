"""Network discovery (TLS, LDAPS, SSH) and the SSH probe."""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import struct
import subprocess
import threading
import time

import pytest
from cryptography.hazmat.primitives import serialization

from keycensus.analysis import strength
from keycensus.analysis.policy import Policy, evaluate
from keycensus.collectors import build, ssh_probe
from keycensus.collectors.base import CollectorError
from keycensus.collectors.network import expand
from keycensus.model import KIND_CERTIFICATE, KIND_PROTOCOL

from .conftest import make_cert, pem, source

OPENSSH_96_KEX = ["sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "curve25519-sha256@libssh.org",
                  "ecdh-sha2-nistp256", "ext-info-s", "kex-strict-s-v00@openssh.com"]  # fmt: skip


# --------------------------------------------------------------------- scripted servers
def _kexinit(kex, hostkey=("ssh-ed25519",), ciphers=("aes256-gcm@openssh.com",), macs=("hmac-sha2-256",)) -> bytes:
    def nl(items):
        raw = ",".join(items).encode()
        return struct.pack("!I", len(raw)) + raw

    payload = b"\x14" + os.urandom(16)
    for lst in (kex, hostkey, ciphers, ciphers, macs, macs, ["none"], ["none"], [], []):
        payload += nl(lst)
    payload += b"\x00" + b"\x00\x00\x00\x00"
    pad = 8 - ((len(payload) + 5) % 8) + 8
    return struct.pack("!IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad


class FakeSsh:
    def __init__(self, kex, banner=b"SSH-2.0-OpenSSH_9.6\r\n", pre=b"", **kw):
        self.payload = pre + banner + _kexinit(kex, **kw)
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
                conn.sendall(self.payload)
                try:
                    conn.settimeout(1)
                    conn.recv(256)
                except OSError:
                    pass

    def close(self):
        self.sock.close()


class TlsServer:
    def __init__(self, tmp_path):
        key, cert = make_cert("localhost", days_valid=20)
        (tmp_path / "c.pem").write_bytes(pem(cert))
        (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                           serialization.PrivateFormat.PKCS8,
                                                           serialization.NoEncryption()))  # fmt: skip
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(tmp_path / "c.pem"), str(tmp_path / "k.pem"))
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
            try:
                with self.ctx.wrap_socket(conn, server_side=True) as t:
                    t.recv(1)
            except (OSError, ssl.SSLError):
                pass

    def close(self):
        self.sock.close()


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------------- ssh probe
def test_ssh_probe_reads_kexinit():
    srv = FakeSsh(OPENSSH_96_KEX, pre=b"Welcome to the bastion\r\n")
    try:
        info = ssh_probe.probe("127.0.0.1", srv.port, 2)
    finally:
        srv.close()
    assert info.banner == "SSH-2.0-OpenSSH_9.6"
    assert "ext-info-s" not in info.kex and "kex-strict-s-v00@openssh.com" not in info.kex
    assert info.negotiated_kex == "sntrup761x25519-sha512@openssh.com"
    assert info.host_key_algorithms == ["ssh-ed25519"] and info.weak == []


def test_ssh_negotiation_follows_client_order():
    info = ssh_probe.SshInfo(kex=["diffie-hellman-group14-sha1", "curve25519-sha256", "mlkem768x25519-sha256"])
    assert info.negotiated_kex == "mlkem768x25519-sha256"
    assert ssh_probe.SshInfo(kex=["diffie-hellman-group14-sha1"]).negotiated_kex == "diffie-hellman-group14-sha1"


def test_ssh_collector_and_rules():
    weak = FakeSsh(["diffie-hellman-group14-sha1", "curve25519-sha256"], hostkey=("ssh-rsa", "rsa-sha2-512"),
                   ciphers=("aes128-cbc", "aes256-ctr"), macs=("hmac-md5", "hmac-sha2-256"))  # fmt: skip
    pq = FakeSsh(["mlkem768x25519-sha256", "curve25519-sha256"])
    try:
        col = build(source("ssh", "ssh", endpoints=[f"127.0.0.1:{weak.port}", f"127.0.0.1:{pq.port}",
                                                     f"127.0.0.1:{_closed_port()}"], timeout=1))  # fmt: skip
        assets = col.collect()
    finally:
        weak.close()
        pq.close()
    a_weak, a_pq, a_dead = assets
    assert a_weak.protocol == "SSH" and a_weak.protocol_version == "2.0" and a_weak.key_exchange == "curve25519-sha256"
    assert set(a_weak.extra["weak_algorithms"]) == {"diffie-hellman-group14-sha1", "ssh-rsa", "aes128-cbc", "hmac-md5"}
    assert a_pq.key_exchange == "mlkem768x25519-sha256" and strength.assess(a_pq).quantum_class == "hybrid"
    assert a_dead.state == "unknown" and "error" in a_dead.extra

    rules = {(f.rule_id, f.asset_name) for f in evaluate(assets, Policy.default())}
    assert ("ssh-weak-algorithm", a_weak.name) in rules
    assert ("quantum-vulnerable-key-exchange", a_weak.name) in rules
    assert ("hybrid-key-exchange", a_pq.name) in rules
    assert not any(r.startswith("tls-") for r, _ in rules)  # TLS rules do not run on SSH endpoints


def test_ssh_rejects_non_ssh(tmp_path):
    srv = TlsServer(tmp_path)
    try:
        with pytest.raises((OSError, ValueError)):
            ssh_probe.probe("127.0.0.1", srv.port, 1)
    finally:
        srv.close()


@pytest.mark.skipif(not (shutil.which("sshd") or os.path.exists("/usr/sbin/sshd")) or not shutil.which("ssh-keygen")
                    or os.geteuid() != 0, reason="needs OpenSSH sshd and root (privilege separation)")  # fmt: skip
def test_against_real_sshd(tmp_path):
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp_path / "hk")], check=True)
    port = _closed_port()
    (tmp_path / "cfg").write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {tmp_path}/hk\nUsePAM no\n"
                                  f"PidFile {tmp_path}/pid\n")  # fmt: skip
    os.makedirs("/run/sshd", exist_ok=True)
    proc = subprocess.Popen([sshd, "-D", "-f", str(tmp_path / "cfg")])
    try:
        for _ in range(50):
            try:
                info = ssh_probe.probe("127.0.0.1", port, 2)
                break
            except OSError:
                time.sleep(0.1)
        assert info.banner.startswith("SSH-2.0-OpenSSH")
        assert info.negotiated_kex and "ssh-ed25519" in info.host_key_algorithms
    finally:
        proc.terminate()


# --------------------------------------------------------------------- network discovery
def test_expand_limits():
    assert expand(["127.0.0.1"], [], 10, False) == ["127.0.0.1"]
    assert len(expand(["10.0.0.0/29"], ["10.0.0.4/31"], 64, False)) == 4  # .1-.6 minus .4 and .5
    with pytest.raises(CollectorError, match="max_hosts"):
        expand(["10.0.0.0/16"], [], 4096, False)
    with pytest.raises(CollectorError, match="allow_public"):
        expand(["8.8.8.0/30"], [], 4096, False)
    assert expand(["8.8.8.0/30"], [], 4096, True) == ["8.8.8.1", "8.8.8.2"]


def test_network_discovers_tls_ssh_and_skips_the_rest(tmp_path):
    tls = TlsServer(tmp_path)
    ssh = FakeSsh(["curve25519-sha256"])
    not_tls = FakeSsh(["curve25519-sha256"])  # open, but SSH on a port configured as TLS
    closed = _closed_port()
    try:
        col = build(source("lab", "network", cidrs=["127.0.0.1/32"], timeout=2, connect_timeout=0.5,
                           ports={tls.port: "ldaps", ssh.port: "ssh", not_tls.port: "tls", closed: "tls"}))  # fmt: skip
        result = col.run()
    finally:
        tls.close()
        ssh.close()
        not_tls.close()
    assert result.error is None
    by = {(a.kind, a.name): a for a in result.assets}
    ldaps = by[(KIND_PROTOCOL, f"127.0.0.1:{tls.port}")]
    assert ldaps.protocol == "TLS" and ldaps.extra["service"] == "ldaps" and ldaps.extra["discovered_by"] == "network"
    assert ldaps.key_exchange  # probed: the local OpenSSL negotiates a TLS 1.3 group
    assert any(a.kind == KIND_CERTIFICATE and a.extra.get("service") == "ldaps" for a in result.assets)
    assert by[(KIND_PROTOCOL, f"127.0.0.1:{ssh.port}")].protocol == "SSH"
    assert (KIND_PROTOCOL, f"127.0.0.1:{not_tls.port}") not in by
    assert len([a for a in result.assets if a.kind == KIND_PROTOCOL]) == 2


def test_network_config_errors():
    assert "cidrs" in build(source("x", "network")).run().error
    assert "unknown service" in build(source("x", "network", cidrs=["127.0.0.1"], ports={80: "http"})).run().error
    assert "allow_public" in build(source("x", "network", cidrs=["1.1.1.1"])).run().error
