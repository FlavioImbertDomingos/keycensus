"""Collector: certificates, keys, keystores and SSH keys lying around on disk.

    - name: app-certs
      type: pem                       # `files` is the same collector
      paths: [/etc/ssl/app, /opt/payments/keys, /etc/ssh, /home]
      recursive: true
      # patterns: [...]               # default: DEFAULT_PATTERNS below
      keystore_passwords:             # tried on PKCS#12, JKS/JCEKS and encrypted PEM keys
        - password_env: APP_KEYSTORE_PASSWORD
        - password_vault: secret/data/keystores#payments
      max_file_bytes: 10000000

What it reads (see keycensus.collectors.keyfiles):

* PEM and DER certificates, private keys and public keys.
* PKCS#12 (.p12, .pfx) and Java keystores (.jks, .jceks, .keystore, .truststore). The protection
  (cipher, MAC, JKS proprietary key protection) is read without a password; a keystore that opens
  with an empty or well-known password (changeit, ...) gets a `keystore-weak-protection` finding.
  A PKCS#12 file whose password is not configured is still reported, as locked.
* SSH: private keys (algorithm and whether a passphrase protects them, read without the passphrase),
  `*.pub`, `authorized_keys`, `known_hosts`, host keys (`ssh_host_*_key`) and OpenSSH certificates.
  Each SSH key carries `extra.ssh_role`: host-key, user-key, authorized-key or known-host.

Private keys are reported with no creation date (files carry none), which the policy flags as
"no-creation-date": a key on disk with no register entry is what an inventory should surface.
Key material is never stored: only the algorithm, size, fingerprints and protection.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path

from .. import secrets
from ..model import KIND_KEY, CryptoAsset
from . import keyfiles
from .base import GAP_DENIED, GAP_UNAVAILABLE, Collector

log = logging.getLogger(__name__)

DEFAULT_PATTERNS = [
    "*.pem", "*.crt", "*.cer", "*.key", "*.der", "*.pub",
    "*.p12", "*.pfx", "*.jks", "*.jceks", "*.keystore", "*.truststore", "*.bcfks",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk", "*-cert.pub",
    "authorized_keys", "authorized_keys2", "known_hosts", "ssh_host_*_key",
]  # fmt: skip


def keystore_passwords(opt: dict, owner: str) -> list[str]:
    out = []
    for item in opt.get("keystore_passwords") or []:
        if isinstance(item, str):
            item = {"password": item}
        val = secrets.resolve(item, "password", owner=owner)
        if val is not None:
            out.append(val)
    return out


def entries_to_assets(collector: Collector, entries: list[keyfiles.Entry], native_base: str, location: str,
                      extra: dict | None = None, compat_single_key_id: bool = True) -> list[CryptoAsset]:  # fmt: skip
    """Entries from keyfiles.parse() -> assets with ids `<native_base>#<sub>`."""
    keys = [e for e in entries if e.fields.get("kind") == KIND_KEY]
    out = []
    for e in entries:
        f = dict(e.fields)
        f["extra"] = {**(f.get("extra") or {}), **(extra or {})}
        if e.weak_protection:
            f["extra"]["keystore_weak_protection"] = e.weak_protection
        single = (compat_single_key_id and len(keys) == 1 and e is keys[0]
                  and e.sub.startswith(("key0", "pub0", "private-key", "public-key")))  # fmt: skip
        native_id = native_base if single else f"{native_base}#{e.sub}"
        out.append(collector.asset(native_id=native_id, location=location, **f))
    return out


class PemCollector(Collector):
    type_name = "pem"

    def collect(self) -> list[CryptoAsset]:
        paths = self.opt.get("paths") or []
        if isinstance(paths, str):
            paths = [paths]
        if not paths:
            raise ValueError(f"{self.type_name} collector needs 'paths'")
        patterns = self.opt.get("patterns") or DEFAULT_PATTERNS
        recursive = bool(self.opt.get("recursive", True))
        self.max_bytes = int(self.opt.get("max_file_bytes", 10_000_000))
        self.passwords = keystore_passwords(self.opt, self.name)
        assets: list[CryptoAsset] = []
        self.coverage.expect("paths", len(paths))
        for root in paths:
            root = Path(root).expanduser()
            if not root.exists() or not os.access(root, os.R_OK):
                why = "does not exist" if not root.exists() else "not readable"
                self.coverage.gap("paths", str(root), why, GAP_UNAVAILABLE if why == "does not exist" else GAP_DENIED)
                log.warning("[%s] %s %s", self.name, root, why)
                continue
            self.coverage.ok("paths")
            if root.is_file():
                files = [root]
            else:
                files = []
                for pat in patterns:
                    files += list(root.rglob(pat) if recursive else root.glob(pat))
            for f in sorted({p for p in files if p.is_file()}):
                found = self._parse_file(f)
                for a in found:
                    a.extra["coverage_scope"] = [f"paths:{root}", *a.extra.get("coverage_scope", [])]
                assets += found
        return assets

    def _parse_file(self, path: Path) -> list[CryptoAsset]:
        try:
            if path.stat().st_size > self.max_bytes:
                log.info("[%s] skipping %s: larger than max_file_bytes", self.name, path)
                return []
            data = path.read_bytes()
        except OSError as exc:
            self.coverage.gap("files", str(path), exc, GAP_DENIED)
            log.warning("[%s] cannot read %s: %s", self.name, path, exc)
            return []
        try:
            entries = keyfiles.parse(data, path.name, self.passwords)
        except (keyfiles.KeyfileError, ValueError) as exc:
            log.warning("[%s] %s: %s", self.name, path, exc)
            return []
        mtime = datetime.fromtimestamp(path.stat().st_mtime).astimezone().isoformat()
        assets = entries_to_assets(self, entries, str(path), str(path))
        for a in assets:
            a.extra["coverage_scope"] = [f"files:{path}"]
        for a in assets:
            if a.kind == KIND_KEY:
                a.extra.setdefault("file_mtime", mtime)
        return assets


class FilesCollector(PemCollector):
    """Same collector under a name that says what it reads now."""

    type_name = "files"
