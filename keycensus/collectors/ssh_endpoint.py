"""Collector: what listed SSH servers offer.

    - name: bastions
      type: ssh
      endpoints: ["bastion.example.com", "10.0.0.7:2222"]   # port defaults to 22
      timeout: 5

One `protocol` asset per endpoint: the banner, and the key exchange, host key, cipher and MAC
algorithms the server offers, read from its KEXINIT before any login (see `ssh_probe.py`).
`key_exchange` is what a current OpenSSH client would negotiate, so a server that offers
mlkem768x25519-sha256 or sntrup761x25519-sha512 shows up as hybrid. The `network` collector
uses the same code for SSH ports it discovers.
"""

from __future__ import annotations

import logging

from ..analysis.strength import QUANTUM_HYBRID, QUANTUM_SAFE, key_exchange_class
from ..model import KIND_PROTOCOL, STATE_ACTIVE, CryptoAsset
from . import ssh_probe
from .base import Collector

log = logging.getLogger(__name__)


def _parse(ep: str) -> tuple[str, int]:
    host, sep, port = ep.rpartition(":")
    if not sep or "]" in port or (host.count(":") and not host.startswith("[")):
        return ep.strip("[]"), 22
    return host.strip("[]"), int(port)


def ssh_asset(collector: Collector, host: str, port: int, info: ssh_probe.SshInfo, extra: dict | None = None
              ) -> CryptoAsset:  # fmt: skip
    version = info.banner.split("-", 2)[1] if info.banner.count("-") >= 2 else None
    pq = [k for k in info.kex if key_exchange_class(k)[0] in (QUANTUM_HYBRID, QUANTUM_SAFE)]
    return collector.asset(
        kind=KIND_PROTOCOL,
        name=f"{host}:{port}",
        native_id=f"{host}:{port}",
        protocol="SSH",
        protocol_version=version,
        state=STATE_ACTIVE,
        location=f"{host}:{port}",
        key_exchange=info.negotiated_kex,
        extra={**(extra or {}), "ssh": info.to_dict(), "weak_algorithms": info.weak,
               "key_exchange": {"negotiated": info.negotiated_kex, "pq_supported": pq, "probe": "ssh-kexinit"}},
    )  # fmt: skip


class SshCollector(Collector):
    type_name = "ssh"

    def collect(self) -> list[CryptoAsset]:
        endpoints = self.opt.get("endpoints") or []
        if not endpoints:
            raise ValueError("ssh collector needs 'endpoints'")
        timeout = float(self.opt.get("timeout", 5))
        out: list[CryptoAsset] = []
        for ep in endpoints:
            host, port = _parse(str(ep))
            try:
                out.append(ssh_asset(self, host, port, ssh_probe.probe(host, port, timeout)))
            except (OSError, ValueError) as exc:
                log.warning("[%s] %s:%d: %s", self.name, host, port, exc)
                out.append(self.asset(kind=KIND_PROTOCOL, name=f"{host}:{port}", native_id=f"{host}:{port}",
                                      protocol="SSH", state="unknown", location=f"{host}:{port}",
                                      extra={"error": str(exc)}))  # fmt: skip
        return out
