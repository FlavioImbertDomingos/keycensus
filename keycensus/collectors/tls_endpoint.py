"""Collector: what a TLS port actually negotiates.

    - name: edge
      type: tls
      endpoints: ["api.example.com:443", "10.0.0.5:8443"]
      timeout: 5
      probe_legacy: true      # also try TLS 1.0 / 1.1 handshakes to see if they are accepted

Produces one `protocol` asset per endpoint (negotiated version + cipher suite,
plus which legacy versions the server *also* accepts) and one `certificate`
asset for the leaf certificate. This is the "cipher suites and protocols in
use" half of PCI DSS 12.3.3.
"""

from __future__ import annotations

import logging
import socket
import ssl
import warnings

from cryptography import x509

from ..model import KIND_PROTOCOL, STATE_ACTIVE, CryptoAsset
from .base import Collector
from .x509util import certificate_fields

log = logging.getLogger(__name__)

_LEGACY = [
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
]


def _parse_endpoint(ep: str) -> tuple[str, int]:
    host, _, port = ep.rpartition(":")
    if not host:
        return ep, 443
    return host.strip("[]"), int(port)


class TlsCollector(Collector):
    type_name = "tls"

    def collect(self) -> list[CryptoAsset]:
        endpoints = self.opt.get("endpoints") or []
        if not endpoints:
            raise ValueError("tls collector needs 'endpoints'")
        timeout = float(self.opt.get("timeout", 5))
        probe_legacy = bool(self.opt.get("probe_legacy", True))
        assets: list[CryptoAsset] = []
        for ep in endpoints:
            host, port = _parse_endpoint(str(ep))
            try:
                assets += self._scan(host, port, timeout, probe_legacy)
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

    def _scan(self, host: str, port: int, timeout: float, probe_legacy: bool) -> list[CryptoAsset]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we're inventorying, not trusting
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                version = tls.version() or "unknown"
                cipher = tls.cipher()  # (name, protocol, bits)
                der = tls.getpeercert(binary_form=True)
        cipher_name = cipher[0] if cipher else "unknown"

        weak_accepted: list[str] = []
        if probe_legacy:
            for label, ver in _LEGACY:
                if self._accepts(host, port, timeout, ver):
                    weak_accepted.append(label)

        proto = self.asset(
            kind=KIND_PROTOCOL,
            name=f"{host}:{port}",
            native_id=f"{host}:{port}",
            protocol="TLS",
            protocol_version=version,
            cipher_suites=[cipher_name],
            weak_versions_accepted=weak_accepted,
            state=STATE_ACTIVE,
            location=f"{host}:{port}",
            extra={"cipher_bits": cipher[2] if cipher else None},
        )
        out = [proto]
        if der:
            cert = x509.load_der_x509_certificate(der)
            fields = certificate_fields(cert)
            out.append(
                self.asset(
                    native_id=f"{host}:{port}#{fields['fingerprint_sha256'][:16]}",
                    location=f"{host}:{port}",
                    hardware_backed=None,
                    **fields,
                )
            )
        return out

    @staticmethod
    def _accepts(host: str, port: int, timeout: float, version: ssl.TLSVersion) -> bool:
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
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except (OSError, ssl.SSLError):
            return False
