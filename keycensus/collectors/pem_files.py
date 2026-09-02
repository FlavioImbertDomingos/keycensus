"""Collector: certificates and keys lying around on disk (PEM / DER).

    - name: app-certs
      type: pem
      paths: [/etc/ssl/app, /opt/payments/keys]
      patterns: ["*.pem", "*.crt", "*.cer", "*.key", "*.der"]   # default
      recursive: true

Private-key files are reported as keys with no creation date (PEM has none),
which the policy flags as "no-creation-date" -- that's intentional: a key on
disk with no register entry is exactly the thing an inventory should surface.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..model import KIND_KEY, STATE_UNKNOWN, CryptoAsset
from .base import Collector
from .x509util import certificate_fields, describe_public_key

log = logging.getLogger(__name__)

_PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", re.DOTALL)
DEFAULT_PATTERNS = ["*.pem", "*.crt", "*.cer", "*.key", "*.der", "*.pub"]


class PemCollector(Collector):
    type_name = "pem"

    def collect(self) -> list[CryptoAsset]:
        paths = self.opt.get("paths") or []
        if isinstance(paths, str):
            paths = [paths]
        if not paths:
            raise ValueError("pem collector needs 'paths'")
        patterns = self.opt.get("patterns") or DEFAULT_PATTERNS
        recursive = bool(self.opt.get("recursive", True))
        assets: list[CryptoAsset] = []
        for root in paths:
            root = Path(root)
            if root.is_file():
                files = [root]
            else:
                files = []
                for pat in patterns:
                    files += list(root.rglob(pat) if recursive else root.glob(pat))
            for f in sorted(set(files)):
                assets += self._parse_file(f)
        return assets

    def _parse_file(self, path: Path) -> list[CryptoAsset]:
        try:
            data = path.read_bytes()
        except OSError as exc:
            log.warning("[%s] cannot read %s: %s", self.name, path, exc)
            return []
        out: list[CryptoAsset] = []
        blocks = _PEM_BLOCK.findall(data)
        if blocks:
            for m in _PEM_BLOCK.finditer(data):
                out += self._parse_block(path, m.group(1).decode(), m.group(0))
        else:
            out += self._parse_der(path, data)
        return out

    def _parse_block(self, path: Path, label: str, block: bytes) -> list[CryptoAsset]:
        try:
            if label == "CERTIFICATE":
                cert = x509.load_pem_x509_certificate(block)
                return [self._cert_asset(path, cert)]
            if "PRIVATE KEY" in label:
                if "ENCRYPTED" in label:
                    return [self._opaque_key(path, "private-key", encrypted=True)]
                key = serialization.load_pem_private_key(block, password=None)
                return [self._key_asset(path, key, "private-key")]
            if "PUBLIC KEY" in label:
                key = serialization.load_pem_public_key(block)
                return [self._key_asset(path, key, "public-key")]
        except (ValueError, TypeError) as exc:
            log.warning("[%s] %s: cannot parse %s block: %s", self.name, path, label, exc)
        return []

    def _parse_der(self, path: Path, data: bytes) -> list[CryptoAsset]:
        for loader, kind in (
            (x509.load_der_x509_certificate, "cert"),
            (lambda d: serialization.load_der_private_key(d, password=None), "private-key"),
            (serialization.load_der_public_key, "public-key"),
        ):
            try:
                obj = loader(data)
            except (ValueError, TypeError):
                continue
            if kind == "cert":
                return [self._cert_asset(path, obj)]
            return [self._key_asset(path, obj, kind)]
        return []

    def _cert_asset(self, path: Path, cert: x509.Certificate) -> CryptoAsset:
        fields = certificate_fields(cert)
        return self.asset(
            native_id=f"{path}#{fields['fingerprint_sha256'][:16]}",
            location=str(path),
            hardware_backed=False,
            **fields,
        )

    def _key_asset(self, path: Path, key, key_type: str) -> CryptoAsset:
        alg, size, curve = describe_public_key(key)
        mtime = datetime.fromtimestamp(path.stat().st_mtime).astimezone()
        return self.asset(
            kind=KIND_KEY,
            name=path.name,
            native_id=str(path),
            algorithm=alg,
            key_size=size,
            curve=curve,
            key_type=key_type,
            purposes=["sign", "decrypt"] if key_type == "private-key" else ["verify", "encrypt"],
            created=None,  # PEM carries no creation date; file mtime is only a hint
            state=STATE_UNKNOWN,
            exportable=True if key_type == "private-key" else None,
            hardware_backed=False,
            location=str(path),
            extra={"file_mtime": mtime.isoformat()},
        )

    def _opaque_key(self, path: Path, key_type: str, encrypted: bool) -> CryptoAsset:
        return self.asset(
            kind=KIND_KEY,
            name=path.name,
            native_id=str(path),
            key_type=key_type,
            purposes=["sign", "decrypt"],
            exportable=True,
            hardware_backed=False,
            location=str(path),
            extra={"encrypted_pem": encrypted},
        )
