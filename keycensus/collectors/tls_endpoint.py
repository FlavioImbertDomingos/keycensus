"""Collector: what a TLS port actually negotiates.

    - name: edge
      type: tls
      endpoints:
        - api.example.com:443
        - 10.0.0.5:8443
        - ldap://dc01.corp.example.com       # LDAP StartTLS on 389 (or ldap://host:port)
        - ldaps://dc01.corp.example.com      # LDAP over TLS on 636
      timeout: 5
      probe_legacy: true      # also try TLS 1.0 / 1.1 handshakes to see if they are accepted
      probe_pqc: true         # which TLS 1.3 key exchange group: classical, hybrid or ML-KEM

Produces one `protocol` asset per endpoint (negotiated version + cipher suite,
plus which legacy versions the server *also* accepts, plus the TLS 1.3 key
exchange group a current browser would get) and one `certificate` asset for the
leaf certificate. This is the "cipher suites and protocols in use" half of
PCI DSS 12.3.3. The key exchange probe is in `tls_groups.py`, StartTLS in `starttls.py`.
"""

from __future__ import annotations

import logging
import ssl
import warnings

from cryptography import x509

from ..model import KIND_PROTOCOL, STATE_ACTIVE, CryptoAsset
from . import tls_groups
from .base import Collector
from .starttls import open_socket
from .x509util import certificate_fields

log = logging.getLogger(__name__)

_LEGACY = [
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
]


_SCHEMES = {"https": (443, None), "tls": (443, None), "ldaps": (636, None), "ldap": (389, "ldap")}


def _parse_endpoint(ep: str) -> tuple[str, int, str | None]:
    """(host, port, starttls) from host:port, [v6]:port or scheme://host[:port]."""
    default_port, starttls = 443, None
    scheme, sep, rest = ep.partition("://")
    if sep:
        if scheme.lower() not in _SCHEMES:
            raise ValueError(f"unknown endpoint scheme {scheme!r}; use {', '.join(sorted(_SCHEMES))}")
        default_port, starttls = _SCHEMES[scheme.lower()]
        ep = rest.split("/", 1)[0]
    host, colon, port = ep.rpartition(":")
    if not colon or host.endswith(":") or (host.count(":") and not host.startswith("[")):
        return ep.strip("[]"), default_port, starttls  # no port, or a bare IPv6 literal
    return host.strip("[]"), int(port), starttls


class TlsCollector(Collector):
    type_name = "tls"

    def collect(self) -> list[CryptoAsset]:
        endpoints = self.opt.get("endpoints") or []
        if not endpoints:
            raise ValueError("tls collector needs 'endpoints'")
        timeout = float(self.opt.get("timeout", 5))
        probe_legacy = bool(self.opt.get("probe_legacy", True))
        probe_pqc = bool(self.opt.get("probe_pqc", True))
        assets: list[CryptoAsset] = []
        for ep in endpoints:
            host, port, starttls = _parse_endpoint(str(ep))
            extra = {"starttls": starttls} if starttls else None
            try:
                assets += scan_endpoint(self, host, port, timeout, probe_legacy, probe_pqc, extra=extra,
                                        starttls=starttls)  # fmt: skip
            except (OSError, ssl.SSLError) as exc:
                log.warning("[%s] %s:%d: %s", self.name, host, port, exc)
                assets.append(
                    self.asset(
                        kind=KIND_PROTOCOL,
                        name=f"{host}:{port}",
                        native_id=f"{host}:{port}",
                        protocol="TLS",
                        state="unknown",
                        location=f"{host}:{port}",
                        extra={"error": str(exc)},
                    )  # fmt: skip
                )
        return assets


def scan_endpoint(collector: Collector, host: str, port: int, timeout: float, probe_legacy: bool,
                  probe_pqc: bool = True, extra: dict | None = None, starttls: str | None = None
                  ) -> list[CryptoAsset]:  # fmt: skip
    """Handshake once for version, cipher and certificate; optionally probe legacy versions and the
    TLS 1.3 key exchange group. With `starttls` ("ldap"), every connection upgrades first.
    Raises OSError / ssl.SSLError when the port does not speak TLS."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we're inventorying, not trusting
    with open_socket(host, port, timeout, starttls) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            version = tls.version() or "unknown"
            cipher = tls.cipher()  # (name, protocol, bits)
            der = tls.getpeercert(binary_form=True)
    cipher_name = cipher[0] if cipher else "unknown"

    weak_accepted: list[str] = []
    if probe_legacy:
        for label, ver in _LEGACY:
            if _accepts(host, port, timeout, ver, starttls):
                weak_accepted.append(label)

    kex = tls_groups.assess(host, port, timeout, starttls=starttls) if probe_pqc and version == "TLSv1.3" else None
    info = {"cipher_bits": cipher[2] if cipher else None, **(extra or {})}
    if starttls:
        info["starttls"] = starttls
    if kex is not None:
        info["key_exchange"] = kex.to_dict()

    proto = collector.asset(
        kind=KIND_PROTOCOL,
        name=f"{host}:{port}",
        native_id=f"{host}:{port}",
        protocol="TLS",
        protocol_version=version,
        cipher_suites=[cipher_name],
        weak_versions_accepted=weak_accepted,
        state=STATE_ACTIVE,
        location=f"{host}:{port}",
        key_exchange=kex.negotiated if kex else None,
        extra=info,
    )
    out = [proto]
    if der:
        cert = x509.load_der_x509_certificate(der)
        fields = certificate_fields(cert)
        fields["extra"].update(extra or {})
        out.append(
            collector.asset(
                native_id=f"{host}:{port}#{fields['fingerprint_sha256'][:16]}",
                location=f"{host}:{port}",
                hardware_backed=None,
                **fields,
            )
        )
    return out


def _accepts(host: str, port: int, timeout: float, version: ssl.TLSVersion, starttls: str | None = None) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # yes, we know TLS 1.0 is old
            ctx.minimum_version = version
            ctx.maximum_version = version
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return False  # local OpenSSL refuses to even try -> can't tell; assume no
    try:
        with open_socket(host, port, timeout, starttls) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (OSError, ssl.SSLError):
        return False
