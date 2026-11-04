"""Collector: find TLS, LDAP and SSH endpoints in a network range nobody listed.

    - name: dc-east
      type: network
      cidrs: [10.20.0.0/22, 10.20.8.15]
      exclude: [10.20.1.0/28]               # never touched, not even a TCP connect
      ports:                                 # port -> service; this is the default
        443: tls
        8443: tls
        389: ldap-starttls                   # LDAP, upgraded with the StartTLS extended operation
        636: ldaps                           # LDAP over TLS
        3269: ldaps                          # Active Directory global catalog over TLS
        22: ssh
      connect_timeout: 1.0                   # seconds per TCP connect
      timeout: 5                             # seconds per TLS / SSH probe
      concurrency: 64                        # parallel TCP connects
      max_hosts: 4096                        # refuse larger ranges unless raised on purpose
      allow_public: false                    # refuse public addresses unless set
      probe_legacy: false                    # also try TLS 1.0 / 1.1 (two extra handshakes per endpoint)
      probe_pqc: true                        # TLS 1.3 key exchange group: classical, hybrid or ML-KEM
      resolve_names: false                   # reverse DNS for each endpoint found

Two passes. First a TCP connect to every host and port in range (no raw packets, no root, no
SYN scan), then a protocol probe on each open port:

* `tls` / `ldaps` -- the same handshake the `tls` collector does: a `protocol` asset (version,
  cipher suite, key exchange group) and a `certificate` asset for the leaf.
* `ldap-starttls` -- sends the LDAP StartTLS extended request (no bind, no credentials), then the
  same TLS probes over the upgraded connection. A server that answers LDAP but refuses StartTLS is
  reported as a `protocol` asset with `extra.starttls_error`, because cleartext-only LDAP is
  itself worth knowing about (simple binds would cross the wire in the clear).
* `ssh` -- reads the banner and the server's KEXINIT, which SSH sends in the clear: a `protocol`
  asset with the offered kex, host key, cipher and MAC algorithms. No login is attempted.

A port that is open but does not speak the expected protocol is logged and skipped.

**Only scan networks you are authorized to scan.** Defaults are deliberately conservative:
private and loopback ranges only, at most 4096 hosts, six ports. Raise `max_hosts` or set
`allow_public: true` on purpose, in writing.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

from ..model import KIND_PROTOCOL, STATE_ACTIVE, CryptoAsset
from . import ssh_probe
from .base import Collector, CollectorError
from .ssh_endpoint import ssh_asset
from .starttls import StartTlsError
from .tls_endpoint import scan_endpoint

log = logging.getLogger(__name__)

DEFAULT_PORTS = {443: "tls", 8443: "tls", 389: "ldap-starttls", 636: "ldaps", 3269: "ldaps", 22: "ssh"}
SERVICES = {"tls", "ldaps", "ldap-starttls", "ssh"}


def expand(cidrs: list, exclude: list, max_hosts: int, allow_public: bool) -> list[str]:
    """Every host address in `cidrs` minus `exclude`, with the safety limits applied."""
    nets = [ipaddress.ip_network(str(c), strict=False) for c in cidrs]
    excl = [ipaddress.ip_network(str(c), strict=False) for c in exclude or []]
    total = sum(n.num_addresses for n in nets)
    if total > max_hosts:
        raise CollectorError(
            f"range covers {total} addresses, more than max_hosts={max_hosts}. Split the range or raise max_hosts."
        )
    for n in nets:
        if not allow_public and not (n.is_private or n.is_loopback or n.is_link_local):
            raise CollectorError(
                f"{n} is not a private range. Scanning public addresses needs allow_public: true, and permission."
            )
    seen: set = set()
    out: list[str] = []
    for n in nets:
        hosts = [n.network_address] if n.num_addresses == 1 else list(n.hosts())
        for h in hosts:
            if h in seen or any(h in e for e in excl):
                continue
            seen.add(h)
            out.append(str(h))
    return out


def _open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class NetworkCollector(Collector):
    type_name = "network"

    def collect(self) -> list[CryptoAsset]:
        cidrs = self.opt.get("cidrs") or []
        if not cidrs:
            raise CollectorError(f"[{self.name}] network collector needs 'cidrs'")
        ports = {int(p): str(s).lower() for p, s in (self.opt.get("ports") or DEFAULT_PORTS).items()}
        bad = {s for s in ports.values() if s not in SERVICES}
        if bad:
            raise CollectorError(f"[{self.name}] unknown service(s) {sorted(bad)}; use {sorted(SERVICES)}")
        hosts = expand(cidrs, self.opt.get("exclude") or [], int(self.opt.get("max_hosts", 4096)),
                       bool(self.opt.get("allow_public", False)))  # fmt: skip
        connect_timeout = float(self.opt.get("connect_timeout", 1.0))
        targets = [(h, p) for h in hosts for p in ports]
        with ThreadPoolExecutor(max_workers=max(1, int(self.opt.get("concurrency", 64)))) as pool:
            open_flags = list(pool.map(lambda t: _open(*t, connect_timeout), targets))
        found = [t for t, ok in zip(targets, open_flags, strict=True) if ok]
        log.info("[%s] %d host(s), %d port(s) checked, %d open", self.name, len(hosts), len(targets), len(found))

        assets: list[CryptoAsset] = []
        with ThreadPoolExecutor(max_workers=max(1, min(16, int(self.opt.get("concurrency", 64))))) as pool:
            for result in pool.map(lambda t: self._probe(t[0], t[1], ports[t[1]]), found):
                assets.extend(result)
        return assets

    def _probe(self, host: str, port: int, service: str) -> list[CryptoAsset]:
        timeout = float(self.opt.get("timeout", 5))
        extra = {"service": service, "discovered_by": "network"}
        if self.opt.get("resolve_names"):
            try:
                extra["hostname"] = socket.gethostbyaddr(host)[0]
            except OSError:
                pass
        try:
            if service in ("tls", "ldaps", "ldap-starttls"):
                return scan_endpoint(self, host, port, timeout, bool(self.opt.get("probe_legacy", False)),
                                     bool(self.opt.get("probe_pqc", True)), extra=extra,
                                     starttls="ldap" if service == "ldap-starttls" else None)  # fmt: skip
            return [ssh_asset(self, host, port, ssh_probe.probe(host, port, timeout), extra)]
        except StartTlsError as exc:
            if "refused" not in str(exc):
                log.info("[%s] %s:%d open but no %s: %s", self.name, host, port, service, exc)
                return []
            # An LDAP server that will not upgrade: cleartext only.
            return [self.asset(kind=KIND_PROTOCOL, name=f"{host}:{port}", native_id=f"{host}:{port}", protocol="LDAP",
                               state=STATE_ACTIVE, location=f"{host}:{port}",
                               extra={**extra, "starttls": "ldap", "starttls_error": str(exc)})]  # fmt: skip
        except (OSError, ssl.SSLError, ValueError) as exc:
            log.info("[%s] %s:%d open but no %s: %s", self.name, host, port, service, exc)
            return []
