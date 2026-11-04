"""Which TLS 1.3 key-exchange group does a server pick? Classical, hybrid or pure post-quantum.

Python's `ssl` module cannot tell you the negotiated group on the OpenSSL versions most hosts
run, and cannot offer ML-KEM at all before OpenSSL 3.5. So this module speaks just enough
TLS 1.3 itself: it sends a ClientHello and reads the server's first reply, which in TLS 1.3 is
in the clear and names the chosen group in its `key_share` extension (or, in a HelloRetryRequest,
the group the server wants instead). It never completes a handshake, sends no application data
and needs no private key: the ML-KEM encapsulation keys it offers are well-formed (every
coefficient below q, so they pass the FIPS 203 input check) but random, and the classical shares
are fresh throwaway keys.

Two probes:

* **preference** -- offers what a current browser offers (X25519MLKEM768 first, then X25519,
  P-256, P-384) and records what the server picks. This is what real clients get today.
* **support** -- offers only hybrid and pure ML-KEM groups, removing each one the server picks,
  until the server refuses. This lists every post-quantum group the server accepts, including
  ones it supports but does not prefer.

Group code points: IANA "TLS Supported Groups" registry, and draft-ietf-tls-ecdhe-mlkem /
draft-ietf-tls-mlkem for the hybrid and pure ML-KEM groups.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# code point -> (name, kind)   kind: classical | hybrid | pqc | hybrid-draft
GROUPS: dict[int, tuple[str, str]] = {
    0x0017: ("secp256r1", "classical"),
    0x0018: ("secp384r1", "classical"),
    0x0019: ("secp521r1", "classical"),
    0x001D: ("x25519", "classical"),
    0x001E: ("x448", "classical"),
    0x0100: ("ffdhe2048", "classical"),
    0x0101: ("ffdhe3072", "classical"),
    0x0102: ("ffdhe4096", "classical"),
    0x0103: ("ffdhe6144", "classical"),
    0x0104: ("ffdhe8192", "classical"),
    0x0200: ("MLKEM512", "pqc"),
    0x0201: ("MLKEM768", "pqc"),
    0x0202: ("MLKEM1024", "pqc"),
    0x11EB: ("SecP256r1MLKEM768", "hybrid"),
    0x11EC: ("X25519MLKEM768", "hybrid"),
    0x11ED: ("SecP384r1MLKEM1024", "hybrid"),
    0x6399: ("X25519Kyber768Draft00", "hybrid-draft"),  # pre-FIPS 203 Kyber; browsers dropped it in 2024
}
BY_NAME = {name.lower(): code for code, (name, _) in GROUPS.items()}

PREFERENCE_OFFER = [0x11EC, 0x001D, 0x0017, 0x0018]  # what Chrome / Firefox offered in 2026
SUPPORT_OFFER = [0x11EC, 0x11EB, 0x11ED, 0x0201, 0x0202, 0x0200, 0x6399]

# SHA-256("HelloRetryRequest"), RFC 8446 section 4.1.3
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
TLS13 = 0x0304
_MLKEM_K = {512: 2, 768: 3, 1024: 4}
_Q = 3329


def group_name(code: int) -> str:
    return GROUPS.get(code, (f"0x{code:04x}", "unknown"))[0]


def group_kind(name_or_code) -> str:
    code = name_or_code if isinstance(name_or_code, int) else BY_NAME.get(str(name_or_code).lower())
    return GROUPS.get(code, ("", "unknown"))[1] if code is not None else "unknown"


# ---------------------------------------------------------------- key shares
def _mlkem_ek(param: int) -> bytes:
    """A well-formed, random ML-KEM encapsulation key: k polynomials of 256 12-bit coefficients
    below q (ByteEncode12), then a 32-byte seed rho. Nobody holds a matching decapsulation key,
    which is fine: the probe never reads the server's ciphertext."""
    k = _MLKEM_K[param]
    raw = os.urandom(2 * 256 * k)
    coeffs = [int.from_bytes(raw[i : i + 2], "little") % _Q for i in range(0, len(raw), 2)]
    out = bytearray()
    for i in range(0, len(coeffs), 2):
        a, b = coeffs[i], coeffs[i + 1]
        out += bytes((a & 0xFF, (a >> 8) | ((b & 0x0F) << 4), b >> 4))
    return bytes(out) + os.urandom(32)


def _x25519() -> bytes:
    return x25519.X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _ec(curve) -> bytes:
    return ec.generate_private_key(curve).public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def key_share(code: int) -> bytes:
    if code == 0x001D:
        return _x25519()
    if code == 0x0017:
        return _ec(ec.SECP256R1())
    if code == 0x0018:
        return _ec(ec.SECP384R1())
    if code == 0x11EC:  # X25519MLKEM768: ML-KEM first, then X25519
        return _mlkem_ek(768) + _x25519()
    if code == 0x11EB:  # SecP256r1MLKEM768: ECDH first, then ML-KEM
        return _ec(ec.SECP256R1()) + _mlkem_ek(768)
    if code == 0x11ED:
        return _ec(ec.SECP384R1()) + _mlkem_ek(1024)
    if code in (0x0200, 0x0201, 0x0202):
        return _mlkem_ek({0x0200: 512, 0x0201: 768, 0x0202: 1024}[code])
    if code == 0x6399:  # X25519Kyber768Draft00: X25519 first, then Kyber768
        return _x25519() + _mlkem_ek(768)
    raise ValueError(f"no key share builder for group 0x{code:04x}")


# ---------------------------------------------------------------- ClientHello
def _ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(body)) + body


def client_hello(server_name: str | None, groups: list[int], share_groups: list[int]) -> bytes:
    """A TLS 1.3-only ClientHello record offering `groups`, with key shares for `share_groups`."""
    exts = b""
    if server_name:
        name = server_name.encode("idna")
        entry = b"\x00" + struct.pack("!H", len(name)) + name
        exts += _ext(0x0000, struct.pack("!H", len(entry)) + entry)
    sg = b"".join(struct.pack("!H", g) for g in groups)
    exts += _ext(0x000A, struct.pack("!H", len(sg)) + sg)
    sigalgs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807, 0x0808]
    sa = b"".join(struct.pack("!H", s) for s in sigalgs)
    exts += _ext(0x000D, struct.pack("!H", len(sa)) + sa)
    exts += _ext(0x002B, b"\x02" + struct.pack("!H", TLS13))  # supported_versions: TLS 1.3 only
    exts += _ext(0x002D, b"\x01\x01")  # psk_key_exchange_modes: psk_dhe_ke (some servers insist)
    shares = b""
    for g in share_groups:
        ks = key_share(g)
        shares += struct.pack("!HH", g, len(ks)) + ks
    exts += _ext(0x0033, struct.pack("!H", len(shares)) + shares)

    suites = b"".join(struct.pack("!H", s) for s in (0x1301, 0x1302, 0x1303))
    body = (
        struct.pack("!H", 0x0303) + os.urandom(32)
        + b"\x20" + os.urandom(32)  # legacy_session_id: 32 bytes, middlebox compatibility mode
        + struct.pack("!H", len(suites)) + suites
        + b"\x01\x00"
        + struct.pack("!H", len(exts)) + exts
    )  # fmt: skip
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


# ---------------------------------------------------------------- ServerHello
@dataclass
class Reply:
    """The server's first answer to one ClientHello."""

    outcome: str  # selected | retry | alert | tls12 | error
    group: int | None = None
    alert: int | None = None
    detail: str = ""

    @property
    def group_name(self) -> str | None:
        return group_name(self.group) if self.group is not None else None


def parse_server_reply(data: bytes) -> Reply:
    """Parse the first handshake message (or alert) out of raw TLS records."""
    hs = b""
    pos = 0
    while pos + 5 <= len(data):
        ctype, _, length = struct.unpack("!BHH", data[pos : pos + 5])
        payload = data[pos + 5 : pos + 5 + length]
        if len(payload) < length:
            break
        pos += 5 + length
        if ctype == 0x15 and len(payload) >= 2:
            return Reply("alert", alert=payload[1], detail=f"alert {payload[1]}")
        if ctype == 0x16:
            hs += payload
            if len(hs) >= 4 and len(hs) >= 4 + int.from_bytes(hs[1:4], "big"):
                break
    if len(hs) < 4 or hs[0] != 0x02:
        return Reply("error", detail="no ServerHello in reply")
    body = hs[4 : 4 + int.from_bytes(hs[1:4], "big")]
    try:
        random = body[2:34]
        sid_len = body[34]
        p = 35 + sid_len + 2 + 1  # session id, cipher suite, compression
        ext_len = struct.unpack("!H", body[p : p + 2])[0]
        exts = body[p + 2 : p + 2 + ext_len]
    except (IndexError, struct.error):
        return Reply("error", detail="truncated ServerHello")
    version, share = None, None
    q = 0
    while q + 4 <= len(exts):
        etype, elen = struct.unpack("!HH", exts[q : q + 4])
        ebody = exts[q + 4 : q + 4 + elen]
        q += 4 + elen
        if etype == 0x002B and len(ebody) >= 2:
            version = struct.unpack("!H", ebody[:2])[0]
        elif etype == 0x0033 and len(ebody) >= 2:
            share = struct.unpack("!H", ebody[:2])[0]
    if version != TLS13:
        return Reply("tls12", detail="server answered without TLS 1.3")
    if share is None:
        return Reply("error", detail="TLS 1.3 ServerHello without key_share")
    return Reply("retry" if random == HRR_RANDOM else "selected", group=share)


def _read_reply(sock: socket.socket) -> bytes:
    """Read until the first handshake message or an alert is complete (or the peer stops)."""
    buf = b""
    while True:
        try:
            chunk = sock.recv(16384)
        except TimeoutError:
            return buf
        if not chunk:
            return buf
        buf += chunk
        if parse_server_reply(buf).outcome != "error":
            return buf
        if len(buf) > 65536:
            return buf


def probe(host: str, port: int, groups: list[int], share_groups: list[int], timeout: float = 5.0,
          server_name: str | None = None, starttls: str | None = None) -> Reply:  # fmt: skip
    from .starttls import open_socket  # noqa: PLC0415

    try:
        with open_socket(host, port, timeout, starttls) as sock:
            sock.sendall(client_hello(server_name, groups, share_groups))
            return parse_server_reply(_read_reply(sock))
    except OSError as exc:
        return Reply("error", detail=f"{type(exc).__name__}: {exc}")


@dataclass
class KeyExchange:
    """What one endpoint does with TLS 1.3 key exchange."""

    negotiated: str | None = None  # what the preference probe got
    negotiated_kind: str = "unknown"  # classical | hybrid | hybrid-draft | pqc | unknown
    pq_supported: list[str] = field(default_factory=list)  # every hybrid / pure ML-KEM group accepted
    tls13: bool = True
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "negotiated": self.negotiated,
            "negotiated_kind": self.negotiated_kind,
            "pq_supported": self.pq_supported,
            "tls13": self.tls13,
            "detail": self.detail,
            "probe": "tls13-clienthello",
        }


def sni_for(host: str) -> str | None:
    try:
        ipaddress.ip_address(host)
        return None  # SNI must not carry an IP literal
    except ValueError:
        return host


def assess(host: str, port: int, timeout: float = 5.0, server_name: str | None = None,
           starttls: str | None = None) -> KeyExchange:  # fmt: skip
    sni = server_name if server_name is not None else sni_for(host)
    out = KeyExchange()
    first = probe(host, port, PREFERENCE_OFFER, [0x11EC, 0x001D], timeout, sni, starttls)
    if first.outcome == "tls12":
        out.tls13, out.detail = False, "TLS 1.2 only: key exchange group not probed"
        return out
    if first.outcome in ("selected", "retry"):
        out.negotiated = first.group_name
        out.negotiated_kind = group_kind(first.group)
    else:
        out.detail = first.detail
    remaining = list(SUPPORT_OFFER)
    for _ in range(len(SUPPORT_OFFER)):
        if not remaining:
            break
        reply = probe(host, port, remaining, [remaining[0]], timeout, sni, starttls)
        if reply.outcome not in ("selected", "retry") or reply.group not in remaining:
            break
        out.pq_supported.append(group_name(reply.group))
        remaining.remove(reply.group)
    return out
