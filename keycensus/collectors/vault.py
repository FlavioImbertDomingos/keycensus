"""Collector: HashiCorp Vault -- Transit keys and PKI certificates.

    - name: vault-prod
      type: vault
      url: https://vault.example.com:8200
      token_env: VAULT_TOKEN
      namespace: payments              # Vault Enterprise, optional
      transit_mounts: [transit]        # default: auto-discover from sys/mounts
      pki_mounts: [pki, pki_int]       # default: auto-discover
      verify_tls: true                 # or a CA bundle path
      hardware_backed: false           # true if Transit uses Managed Keys / Seal HSM
      include_policies: true           # who uses the key: ACL policies granting transit/<op>/<name> -> used_by

Needs a token that can `list` and `read` the key/cert metadata, plus `sys/policies/acl` (list + read)
for `include_policies` -- a 403 there is tolerated. Nothing more.
Uses plain HTTP so there is no extra dependency.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime

import requests
from cryptography import x509

from ..model import (
    ALG_AES,
    ALG_CHACHA20,
    ALG_EC,
    ALG_ED25519,
    ALG_HMAC,
    ALG_ML_DSA,
    ALG_RSA,
    ALG_UNKNOWN,
    KIND_KEY,
    STATE_ACTIVE,
    CryptoAsset,
)
from .base import Collector
from .x509util import certificate_fields

log = logging.getLogger(__name__)

# Vault transit key type -> (algorithm, key_size, curve)
TRANSIT_TYPES = {
    "aes128-gcm96": (ALG_AES, 128, None),
    "aes256-gcm96": (ALG_AES, 256, None),
    "chacha20-poly1305": (ALG_CHACHA20, 256, None),
    "xchacha20-poly1305": (ALG_CHACHA20, 256, None),
    "ed25519": (ALG_ED25519, 256, "Ed25519"),
    "ecdsa-p256": (ALG_EC, 256, "P-256"),
    "ecdsa-p384": (ALG_EC, 384, "P-384"),
    "ecdsa-p521": (ALG_EC, 521, "P-521"),
    "rsa-2048": (ALG_RSA, 2048, None),
    "rsa-3072": (ALG_RSA, 3072, None),
    "rsa-4096": (ALG_RSA, 4096, None),
    "hmac": (ALG_HMAC, None, None),
    "ml-dsa-44": (ALG_ML_DSA, 44, None),
    "ml-dsa-65": (ALG_ML_DSA, 65, None),
    "ml-dsa-87": (ALG_ML_DSA, 87, None),
}


class VaultCollector(Collector):
    type_name = "vault"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.url = str(self.opt.get("url", "http://127.0.0.1:8200")).rstrip("/")
        self.session = requests.Session()
        token = self.cfg.secret("token", required=True)
        self.session.headers["X-Vault-Token"] = token
        if self.opt.get("namespace"):
            self.session.headers["X-Vault-Namespace"] = str(self.opt["namespace"])
        verify = self.opt.get("verify_tls", True)
        self.session.verify = verify if isinstance(verify, str) else bool(verify)
        self.timeout = float(self.opt.get("timeout", 10))
        self.hardware = self.opt.get("hardware_backed", False)

    # ------------------------------------------------------------ http
    def _get(self, path: str, params: dict | None = None, ok404: bool = True):
        r = self.session.get(f"{self.url}/v1/{path}", params=params, timeout=self.timeout)
        if r.status_code == 404 and ok404:
            return None
        if r.status_code >= 400:
            raise RuntimeError(f"GET {path} -> {r.status_code}: {r.text[:200]}")
        return r.json().get("data")

    def _list(self, path: str) -> list[str]:
        data = self._get(path, params={"list": "true"})
        return list((data or {}).get("keys") or [])

    # ------------------------------------------------------------ discovery
    def _mounts(self, engine: str, explicit) -> list[str]:
        if explicit:
            return [str(m).strip("/") for m in explicit]
        mounts = self._get("sys/mounts", ok404=False) or {}
        return [p.strip("/") for p, m in mounts.items() if isinstance(m, dict) and m.get("type") == engine]

    # ------------------------------------------------------------ collect
    def collect(self) -> list[CryptoAsset]:
        assets: list[CryptoAsset] = []
        policies = self._policies() if self.opt.get("include_policies", True) else {}
        for mount in self._mounts("transit", self.opt.get("transit_mounts")):
            for name in self._list(f"{mount}/keys"):
                data = self._get(f"{mount}/keys/{name}")
                if data:
                    asset = self._transit_asset(mount, name, data)
                    asset.used_by = _policy_consumers(policies, mount, name)
                    assets.append(asset)
        for mount in self._mounts("pki", self.opt.get("pki_mounts")):
            for serial in self._list(f"{mount}/certs"):
                data = self._get(f"{mount}/cert/{serial}")
                pem = (data or {}).get("certificate")
                if pem:
                    try:
                        cert = x509.load_pem_x509_certificate(pem.encode())
                    except ValueError:
                        continue
                    assets.append(self._pki_asset(mount, serial, cert, data))
        return assets

    def _policies(self) -> dict[str, str]:
        """ACL policy name -> HCL/JSON text (root/default skipped). Empty when not permitted."""
        try:
            names = self._list("sys/policies/acl")
        except RuntimeError as exc:
            log.debug("[%s] cannot list policies: %s", self.name, exc)
            return {}
        out = {}
        for n in names:
            if n in ("root", "default"):
                continue
            try:
                data = self._get(f"sys/policies/acl/{n}")
            except RuntimeError:
                continue
            if data and data.get("policy"):
                out[n] = str(data["policy"])
        return out

    def _transit_asset(self, mount: str, name: str, d: dict) -> CryptoAsset:
        ktype = str(d.get("type", ""))
        alg, size, curve = TRANSIT_TYPES.get(ktype, (ALG_UNKNOWN, None, None))
        if ktype == "hmac" and d.get("key_size"):
            size = int(d["key_size"]) * 8
        versions = d.get("keys") or {}
        created = last = None
        times = []
        for v in versions.values():
            ts = v.get("creation_time") if isinstance(v, dict) else v
            t = _parse_ts(ts)
            if t:
                times.append(t)
        if times:
            created, last = min(times), max(times)
        purposes = []
        if d.get("supports_encryption"):
            purposes += ["encrypt", "decrypt"]
        if d.get("supports_signing"):
            purposes += ["sign", "verify"]
        if d.get("supports_derivation"):
            purposes.append("derive")
        if ktype == "hmac":
            purposes.append("mac")
        auto = d.get("auto_rotate_period")
        rotation = bool(auto) if auto is not None else None
        return self.asset(
            kind=KIND_KEY,
            name=name,
            native_id=f"{mount}/keys/{name}",
            algorithm=alg,
            key_size=size,
            curve=curve,
            key_type="secret-key" if alg in (ALG_AES, ALG_CHACHA20, ALG_HMAC) else "private-key",
            purposes=purposes,
            created=created,
            last_rotated=last,
            state=STATE_ACTIVE,
            rotation_enabled=rotation,
            exportable=bool(d.get("exportable")),
            hardware_backed=bool(self.hardware),
            location=f"{self.url} {mount}/keys/{name}",
            extra={
                "vault_type": ktype,
                "latest_version": d.get("latest_version"),
                "min_decryption_version": d.get("min_decryption_version"),
                "auto_rotate_period_seconds": auto,
                "deletion_allowed": d.get("deletion_allowed"),
                "versions": len(versions),
            },
        )

    def _pki_asset(self, mount: str, serial: str, cert: x509.Certificate, d: dict) -> CryptoAsset:
        fields = certificate_fields(cert)
        return self.asset(
            source_type="vault-pki",
            native_id=f"{mount}/cert/{serial}",
            location=f"{self.url} {mount}/cert/{serial}",
            hardware_backed=bool(self.hardware),
            extra={**fields.pop("extra"), "revocation_time": d.get("revocation_time")},
            **fields,
        )


_TRANSIT_OPS = ("encrypt", "decrypt", "sign", "verify", "hmac", "rewrap", "datakey", "keys", "export", "backup")


def _policy_consumers(policies: dict[str, str], mount: str, key: str) -> list[dict]:
    """Which ACL policies grant an operation on this transit key (exact path or glob covering it)."""
    out = []
    for pname, text in policies.items():
        for m in re.finditer(r'path\s+"([^"]+)"', text):
            path = m.group(1)
            if not path.startswith(mount + "/"):
                continue
            parts = path[len(mount) + 1 :].split("/", 1)
            if len(parts) != 2 or parts[0] not in _TRANSIT_OPS:
                continue
            pattern = parts[1]
            if (
                pattern == key
                or (pattern.endswith("*") and key.startswith(pattern[:-1]))
                or pattern == "+"
                or pattern == "*"
            ):
                out.append({"type": "policy", "id": pname, "via": f"vault-policy:{parts[0]}"})
                break
    return out


def _parse_ts(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, int | float):
        return datetime.fromtimestamp(value, UTC)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None
