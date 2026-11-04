"""What an SSH server offers: key exchange, host key, cipher and MAC algorithms.

An SSH server sends its version banner and then its SSH_MSG_KEXINIT in the clear, before any key
exchange (RFC 4253 sections 4.2 and 7.1). This module reads exactly that and disconnects: no
authentication, no key exchange, nothing logged in as. It cannot see the host key itself (that
needs a completed key exchange), only which host key algorithms the server offers.

`negotiated` is what a current OpenSSH client would get: the first algorithm in OpenSSH 10's
default client order that the server also offers, which is how SSH negotiation works
(RFC 4253 section 7.1: the client's preference wins).
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

# OpenSSH 10.0 default client KexAlgorithms order.
CLIENT_KEX_ORDER = [
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
    # not in OpenSSH 10's defaults, but older clients still offer them
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
]

# Algorithms with a known weakness (SHA-1, small DH groups, CBC/RC4/3DES, MD5 MACs, DSA).
WEAK = {
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
    "ssh-dss", "ssh-rsa",  # ssh-rsa is the SHA-1 signature; rsa-sha2-256/512 are fine
    "3des-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256", "des-cbc",
    "aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc@lysator.liu.se",
    "hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
    "hmac-sha1-96-etm@openssh.com",
}  # fmt: skip
# Not algorithms: extension and strict-kex markers servers put in the kex list (RFC 8308, CVE-2023-48795 fix).
_MARKERS = ("ext-info-", "kex-strict-")


@dataclass
class SshInfo:
    banner: str = ""
    kex: list[str] = field(default_factory=list)
    host_key_algorithms: list[str] = field(default_factory=list)
    ciphers: list[str] = field(default_factory=list)
    macs: list[str] = field(default_factory=list)
    compression: list[str] = field(default_factory=list)

    @property
    def negotiated_kex(self) -> str | None:
        offered = set(self.kex)
        return next((k for k in CLIENT_KEX_ORDER if k in offered), self.kex[0] if self.kex else None)

    @property
    def weak(self) -> list[str]:
        everything = self.kex + self.host_key_algorithms + self.ciphers + self.macs
        return sorted({a for a in everything if a in WEAK})

    def to_dict(self) -> dict:
        return {
            "banner": self.banner,
            "kex": self.kex,
            "host_key_algorithms": self.host_key_algorithms,
            "ciphers": self.ciphers,
            "macs": self.macs,
            "compression": self.compression,
        }


def parse_kexinit(payload: bytes) -> SshInfo:
    """payload = SSH_MSG_KEXINIT (20) + 16-byte cookie + ten name-lists."""
    if not payload or payload[0] != 20:
        raise ValueError("not an SSH_MSG_KEXINIT")
    p = 17
    lists: list[list[str]] = []
    for _ in range(10):
        (n,) = struct.unpack("!I", payload[p : p + 4])
        raw = payload[p + 4 : p + 4 + n]
        if len(raw) != n:
            raise ValueError("truncated KEXINIT")
        lists.append([x for x in raw.decode("ascii", "replace").split(",") if x])
        p += 4 + n
    kex, hostkey, enc_cs, _enc_sc, mac_cs, _mac_sc, comp_cs = lists[:7]
    kex = [k for k in kex if not k.startswith(_MARKERS)]
    return SshInfo(kex=kex, host_key_algorithms=hostkey, ciphers=enc_cs, macs=mac_cs, compression=comp_cs)


def _recv_exact(sock: socket.socket, n: int, buf: bytearray) -> bytes:
    while len(buf) < n:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("connection closed during SSH handshake")
        buf += chunk
    out = bytes(buf[:n])
    del buf[:n]
    return out


def probe(host: str, port: int = 22, timeout: float = 5.0) -> SshInfo:
    """Read the server banner and KEXINIT. Raises OSError / ValueError if it is not SSH."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        buf = bytearray()
        banner = ""
        for _ in range(32):  # servers may send other lines before the version line (RFC 4253 4.2)
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    raise ConnectionError("no SSH banner")
                buf += chunk
                if len(buf) > 8192:
                    raise ValueError("no SSH banner in the first 8 KiB")
            line, _, rest = bytes(buf).partition(b"\n")
            buf = bytearray(rest)
            text = line.rstrip(b"\r").decode("utf-8", "replace")
            if text.startswith("SSH-"):
                banner = text
                break
        if not banner:
            raise ValueError("no SSH banner")
        sock.sendall(b"SSH-2.0-keycensus\r\n")
        (length,) = struct.unpack("!I", _recv_exact(sock, 4, buf))
        if not 5 <= length <= 256 * 1024:
            raise ValueError(f"implausible SSH packet length {length}")
        packet = _recv_exact(sock, length, buf)
        pad = packet[0]
        info = parse_kexinit(packet[1 : length - pad])
        info.banner = banner
        return info
