"""Plaintext protocols that upgrade to TLS on the same port.

Only LDAP for now: port 389 with the StartTLS extended operation (RFC 4511 section 4.14,
OID 1.3.6.1.4.1.1466.20037). Active Directory domain controllers answer it whenever they have a
certificate for LDAPS, and OpenLDAP does when `olcTLSCertificateFile` is set. Nothing is bound and
no credentials are sent: the extended request is allowed before any bind.

`open_socket()` returns a TCP socket on which the next byte the client sends is a TLS ClientHello,
so the same handshake, legacy-version and key-exchange probes work as on a TLS port.
"""

from __future__ import annotations

import socket

LDAP_STARTTLS_OID = b"1.3.6.1.4.1.1466.20037"
PROTOCOLS = {"ldap"}

_LDAP_RESULT = {
    0: "success",
    1: "operationsError",
    2: "protocolError (StartTLS not supported)",
    52: "unavailable (no server certificate configured?)",
    53: "unwillingToPerform",
}


class StartTlsError(OSError):
    """The port answered, but would not upgrade to TLS."""


def _tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + body


def ldap_starttls_request(message_id: int = 1) -> bytes:
    """LDAPMessage { messageID, ExtendedRequest [APPLICATION 23] { requestName [0] OID } }."""
    op = _tlv(0x77, _tlv(0x80, LDAP_STARTTLS_OID))
    return _tlv(0x30, _tlv(0x02, bytes([message_id])) + op)


def _read_len(buf: bytes, i: int) -> tuple[int, int]:
    """(length, index of the first content byte) for the BER length at buf[i]."""
    first = buf[i]
    if first < 0x80:
        return first, i + 1
    n = first & 0x7F
    if n == 0 or n > 4 or i + 1 + n > len(buf):
        raise ValueError("unsupported or truncated BER length")
    return int.from_bytes(buf[i + 1 : i + 1 + n], "big"), i + 1 + n


def _read_message(sock: socket.socket) -> bytes:
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise StartTlsError("connection closed before the StartTLS response")
        buf += chunk
        if len(buf) >= 2 and buf[0] == 0x30:
            try:
                length, start = _read_len(buf, 1)
            except ValueError:
                if len(buf) > 16:
                    raise
                continue
            if len(buf) >= start + length:
                return buf[: start + length]
        elif buf and buf[0] != 0x30:
            raise StartTlsError("not an LDAP server (reply is not a BER SEQUENCE)")
        if len(buf) > 65536:
            raise StartTlsError("StartTLS response too large")


def parse_ldap_extended_response(msg: bytes) -> tuple[int, str]:
    """(resultCode, diagnosticMessage) from an LDAPMessage carrying an ExtendedResponse."""
    if not msg or msg[0] != 0x30:
        raise ValueError("not an LDAPMessage")
    _, i = _read_len(msg, 1)
    if msg[i] != 0x02:
        raise ValueError("missing messageID")
    n, j = _read_len(msg, i + 1)
    i = j + n
    if msg[i] != 0x78:  # ExtendedResponse [APPLICATION 24]
        raise ValueError(f"expected ExtendedResponse, got tag 0x{msg[i]:02x}")
    _, i = _read_len(msg, i + 1)
    if msg[i] != 0x0A:
        raise ValueError("missing resultCode")
    n, j = _read_len(msg, i + 1)
    code = int.from_bytes(msg[j : j + n], "big")
    i = j + n
    diag = ""
    if i < len(msg) and msg[i] == 0x04:  # matchedDN
        n, j = _read_len(msg, i + 1)
        i = j + n
        if i < len(msg) and msg[i] == 0x04:  # diagnosticMessage
            n, j = _read_len(msg, i + 1)
            diag = msg[j : j + n].decode("utf-8", "replace")
    return code, diag


def ldap_upgrade(sock: socket.socket) -> None:
    sock.sendall(ldap_starttls_request())
    try:
        code, diag = parse_ldap_extended_response(_read_message(sock))
    except (ValueError, IndexError) as exc:
        raise StartTlsError(f"unreadable StartTLS response: {exc}") from exc
    if code != 0:
        what = _LDAP_RESULT.get(code, f"resultCode {code}")
        raise StartTlsError(f"LDAP StartTLS refused: {what}{': ' + diag if diag else ''}")


def open_socket(host: str, port: int, timeout: float, starttls: str | None = None) -> socket.socket:
    """A connected socket, upgraded with `starttls` first when given. The caller closes it."""
    if starttls and starttls not in PROTOCOLS:
        raise ValueError(f"unknown starttls protocol {starttls!r}; known: {sorted(PROTOCOLS)}")
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        if starttls == "ldap":
            ldap_upgrade(sock)
    except BaseException:
        sock.close()
        raise
    return sock
