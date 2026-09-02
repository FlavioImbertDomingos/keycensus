"""Collector: Thales CipherTrust Manager (CM) key vault, over the REST API.

    - name: ctm-prod
      type: ciphertrust
      url: https://ctm.example.com
      username: keycensus              # a user with read access to the key vault
      password_env: CTM_PASSWORD
      domain: root                     # CM domain to log into (optional)
      # jwt_env: CTM_JWT               # or a pre-issued JWT / API-key token instead of username+password
      verify_tls: /etc/ssl/certs/corp-ca.pem
      hardware_backed: true            # true if the domain is HSM-anchored (Luna / nShield root of trust)
      include_destroyed: false
      include_public_keys: false       # public halves of key pairs are usually noise

Auth: `POST /api/v1/auth/tokens` (password grant, optional domain) -> `jwt`.
Keys: `GET /api/v1/vault/keys2?limit=&skip=` (paged; `resources[]`), the same list the
CM UI shows. Nothing is exported; `keys2` returns metadata only.

Mapping (fields as CipherTrust names them):

* `algorithm` (AES, TDES, RSA, EC, HMAC-SHA256, ARIA, SEED, ML-DSA-65 ...), `size`, `curveid`
  (prime256v1, secp384r1, secp521r1, secp256k1, brainpoolP256r1, ...) -> algorithm / size / curve.
* `usageMask` bits -> purposes (Sign 1, Verify 2, Encrypt 4, Decrypt 8, WrapKey 16, UnwrapKey 32,
  Export 64, MACGenerate 128, MACVerify 256, DeriveKey 512, ... FPEEncrypt 1048576).
* `state` (Pre-Active, Active, Deactivated, Compromised, Destroyed, Destroyed Compromised),
  `createdAt`, `activationDate`, `deactivationDate`, `unexportable`, `objectType`, `version`, `labels`, `meta`.

Verified against the bundled mock, not a live CM -- see docs/COLLECTORS.md for what to send back
if your firmware's field names differ.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import requests

from ..model import (
    ALG_3DES,
    ALG_AES,
    ALG_EC,
    ALG_ED25519,
    ALG_HMAC,
    ALG_ML_DSA,
    ALG_ML_KEM,
    ALG_RSA,
    ALG_UNKNOWN,
    KIND_CERTIFICATE,
    KIND_KEY,
    STATE_ACTIVE,
    STATE_COMPROMISED,
    STATE_DEACTIVATED,
    STATE_DESTROYED,
    STATE_PRE_ACTIVATION,
    STATE_UNKNOWN,
    CryptoAsset,
)
from .base import Collector

log = logging.getLogger(__name__)

USAGE_BITS = [
    (1, "sign"),
    (2, "verify"),
    (4, "encrypt"),
    (8, "decrypt"),
    (16, "wrap"),
    (32, "unwrap"),
    (64, "export"),
    (128, "mac"),
    (256, "mac"),
    (512, "derive"),
    (2048, "derive"),
    (4096, "sign"),
    (8192, "sign"),
    (1048576, "encrypt"),
    (2097152, "decrypt"),
]

STATES = {
    "pre-active": STATE_PRE_ACTIVATION,
    "active": STATE_ACTIVE,
    "deactivated": STATE_DEACTIVATED,
    "compromised": STATE_COMPROMISED,
    "destroyed": STATE_DESTROYED,
    "destroyed compromised": STATE_DESTROYED,
}

CURVES = {
    "prime256v1": ("P-256", 256),
    "secp256r1": ("P-256", 256),
    "secp384r1": ("P-384", 384),
    "secp521r1": ("P-521", 521),
    "secp256k1": ("secp256k1", 256),
    "brainpoolp256r1": ("brainpoolP256r1", 256),
    "brainpoolp384r1": ("brainpoolP384r1", 384),
    "brainpoolp512r1": ("brainpoolP512r1", 512),
    "ed25519": ("Ed25519", 256),
}


def normalise_algorithm(alg: str, size, curveid: str | None) -> tuple[str, int | None, str | None]:
    a = (alg or "").upper()
    size = int(size) if size not in (None, "", 0) else None
    if a in ("AES", "ARIA", "SEED"):
        return (ALG_AES if a == "AES" else a), size, None
    if a in ("TDES", "3DES", "DES3"):
        return ALG_3DES, size or 192, None
    if a == "DES":
        return "DES", 64, None
    if a == "RSA":
        return ALG_RSA, size, None
    if a in ("EC", "ECDSA", "ECC", "ECDH"):
        curve, bits = CURVES.get((curveid or "").lower(), (curveid, size))
        return (ALG_ED25519 if curve == "Ed25519" else ALG_EC), bits or size, curve
    if a.startswith("HMAC"):
        digest = a.split("-", 1)[1] if "-" in a else ""
        bits = {"SHA1": 160, "SHA224": 224, "SHA256": 256, "SHA384": 384, "SHA512": 512}.get(digest)
        return ALG_HMAC, size or bits, None
    if a.startswith("ML-DSA") or a.startswith("ML_DSA"):
        return ALG_ML_DSA, size, None
    if a.startswith("ML-KEM") or a.startswith("ML_KEM"):
        return ALG_ML_KEM, size, None
    return ALG_UNKNOWN, size, None


class CipherTrustCollector(Collector):
    type_name = "ciphertrust"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.url = str(self.opt.get("url", "")).rstrip("/")
        if not self.url:
            raise ValueError(f"[{self.name}] url is required")
        self.session = requests.Session()
        verify = self.opt.get("verify_tls", True)
        self.session.verify = verify if isinstance(verify, str) else bool(verify)
        self.timeout = float(self.opt.get("timeout", 15))
        self.hardware = self.opt.get("hardware_backed", False)
        self.page = int(self.opt.get("page_size", 100))

    # ------------------------------------------------------------ auth
    def _login(self):
        jwt = self.cfg.secret("jwt")
        if not jwt:
            body = {
                "grant_type": "password",
                "username": self.cfg.secret("username", required=True),
                "password": self.cfg.secret("password", required=True),
            }
            if self.opt.get("domain"):
                body["domain"] = str(self.opt["domain"])
            r = self.session.post(f"{self.url}/api/v1/auth/tokens", json=body, timeout=self.timeout)
            if r.status_code >= 400:
                raise RuntimeError(f"login failed: {r.status_code} {r.text[:200]}")
            jwt = r.json().get("jwt")
            if not jwt:
                raise RuntimeError("login response carried no 'jwt'")
        self.session.headers["Authorization"] = f"Bearer {jwt}"

    def _get(self, path: str, params: dict | None = None) -> dict:
        r = self.session.get(f"{self.url}{path}", params=params, timeout=self.timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"GET {path} -> {r.status_code}: {r.text[:200]}")
        return r.json()

    # ------------------------------------------------------------ collect
    def collect(self) -> list[CryptoAsset]:
        self._login()
        include_destroyed = bool(self.opt.get("include_destroyed", False))
        include_public = bool(self.opt.get("include_public_keys", False))
        assets: list[CryptoAsset] = []
        skip = 0
        while True:
            page = self._get("/api/v1/vault/keys2", {"limit": self.page, "skip": skip})
            resources = page.get("resources") or []
            for k in resources:
                otype = str(k.get("objectType", ""))
                if otype == "Public Key" and not include_public:
                    continue
                if otype in ("Secret Data", "Opaque Object"):
                    continue
                a = self._asset(k)
                if a.state == STATE_DESTROYED and not include_destroyed:
                    continue
                assets.append(a)
            skip += len(resources)
            total = page.get("total")
            if not resources or (total is not None and skip >= int(total)):
                return assets

    def _asset(self, k: dict) -> CryptoAsset:
        otype = str(k.get("objectType", ""))
        alg, size, curve = normalise_algorithm(k.get("algorithm"), k.get("size"), k.get("curveid"))
        mask = int(k.get("usageMask") or 0)
        purposes = []
        for bit, label in USAGE_BITS:
            if mask & bit and label not in purposes:
                purposes.append(label)
        state = STATES.get(str(k.get("state", "")).lower(), STATE_UNKNOWN)
        meta = k.get("meta") or {}
        rotation = None
        if isinstance(meta, dict) and any("rotat" in str(key).lower() for key in meta):
            rotation = True
        kind = KIND_CERTIFICATE if otype == "Certificate" else KIND_KEY
        key_type = {
            "Symmetric Key": "secret-key",
            "Private Key": "private-key",
            "Public Key": "public-key",
            "Certificate": "public-key",
        }.get(otype, "key")
        exportable = None
        if "unexportable" in k:
            exportable = not bool(k["unexportable"])
        elif "neverExportable" in k:
            exportable = not bool(k["neverExportable"])
        used_by = []
        if k.get("application"):
            used_by.append({"type": "application", "id": str(k["application"]), "via": "ctm-application"})
        owner = k.get("owner") or (meta.get("ownerId") if isinstance(meta, dict) else None)
        if owner:
            used_by.append({"type": "user", "id": str(owner), "via": "ctm-owner"})
        return self.asset(
            used_by=used_by,
            kind=kind,
            name=str(k.get("name") or k.get("id")),
            native_id=str(k.get("id") or k.get("uri") or k.get("name")),
            algorithm=alg,
            key_size=size,
            curve=curve,
            key_type=key_type,
            purposes=purposes,
            created=_ts(k.get("createdAt")),
            last_rotated=_ts(k.get("createdAt")) if int(k.get("version") or 0) > 0 else None,
            expires=_ts(k.get("deactivationDate")),
            state=state,
            rotation_enabled=rotation,
            exportable=exportable,
            hardware_backed=bool(self.hardware),
            fips_validated=bool(self.hardware) or None,
            location=f"{self.url} {k.get('domain') or self.opt.get('domain') or 'root'}",
            tags={str(a): str(b) for a, b in (k.get("labels") or {}).items()},
            extra={
                "object_type": otype,
                "version": k.get("version"),
                "usage_mask": mask,
                "ctm_algorithm": k.get("algorithm"),
                "curveid": k.get("curveid"),
                "activation_date": k.get("activationDate"),
                "undeletable": k.get("undeletable"),
                "never_exported": k.get("neverExported"),
                "sha256_fingerprint": k.get("sha256Fingerprint"),
                "owner": k.get("owner") or k.get("account"),
                "application": k.get("application"),
                "aliases": [a.get("alias") for a in (k.get("aliases") or []) if isinstance(a, dict)],
                "meta": meta if isinstance(meta, dict) else None,
            },
        )


def _ts(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None
