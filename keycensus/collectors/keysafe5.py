"""Collector: Entrust KeySafe 5 (nShield fleet management) over its REST API.

KeySafe 5 is the central management plane for Entrust nShield HSMs: it knows every
application key (the Security World key blobs), which HSMs / hosts / pools hold them, and
how each key is protected (module, softcard, OCS card set). That is a richer view than
PKCS#11 on one host, and it is available even where the nShield client is not installed.

    - name: ks5
      type: keysafe5
      url: https://keysafe5.example.com
      auth: bearer                     # bearer (OIDC / API token from token_env|token_file) | basic
      token_env: KS5_TOKEN
      # username: keycensus            # with auth: basic
      # password_env: KS5_PASSWORD
      verify_tls: /etc/ssl/certs/corp-ca.pem
      keys_path: /km/v1/keys           # default; the collector also tries /mgmt/v1/keys on 404
      hsms_path: /mgmt/v1/hsms         # optional inventory of HSMs (ESN, model, firmware) -> extra
      field_map: {}                    # rename fields if your version differs (see below)

The key records are mapped tolerantly. Recognised field names (first match wins, override
with `field_map`): name (`name`, `keyName`, `ident`), app (`appName`, `application`),
type (`type`, `keyType`, `algorithm`), size (`length`, `size`, `bits`), curve (`curve`),
protection (`protection`, `protectionType`), protector (`cardset`, `softcard`, `protectorName`),
created (`createdAt`, `creationTime`, `created`), id (`id`, `keyId`, `hash`),
hsm_esns (`hsmESNs`, `esns`, `hsms`), exportable (`exportable`), state (`state`, `status`).

nShield key types such as `RSAPrivate`, `ECDSAPrivate`, `ECDHPrivate`, `Rijndael` (AES),
`DES3`, `HMACSHA256`, `Ed25519`, `MLDSA65` are normalised to keycensus algorithms. Every key in
a Security World is HSM-protected, so `hardware_backed` is true; nShield modules are FIPS 140-3
validated, so `fips_validated` is true unless you say otherwise.

Verified against the bundled mock, not a live KeySafe 5 -- the API paths and field names come
from the KeySafe 5 REST API reference and may need `keys_path` / `field_map` on your version.
Please open an issue with a redacted `GET keys` response so the defaults can be corrected.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime

import requests

from ..model import (
    ALG_3DES,
    ALG_AES,
    ALG_DES,
    ALG_DH,
    ALG_DSA,
    ALG_EC,
    ALG_ED25519,
    ALG_HMAC,
    ALG_ML_DSA,
    ALG_ML_KEM,
    ALG_RSA,
    ALG_UNKNOWN,
    KIND_KEY,
    STATE_ACTIVE,
    STATE_DEACTIVATED,
    STATE_DESTROYED,
    STATE_UNKNOWN,
    CryptoAsset,
)
from .base import Collector

log = logging.getLogger(__name__)

FIELDS = {
    "name": ("name", "keyName", "ident", "label"),
    "app": ("appName", "application", "app"),
    "type": ("type", "keyType", "algorithm"),
    "size": ("length", "size", "bits", "keySize"),
    "curve": ("curve", "curveName"),
    "protection": ("protection", "protectionType", "protectionMethod"),
    "protector": ("cardset", "cardsetName", "softcard", "softcardName", "protectorName"),
    "created": ("createdAt", "creationTime", "created", "timestamp"),
    "id": ("id", "keyId", "hash", "keyHash"),
    "hsm_esns": ("hsmESNs", "esns", "hsms", "moduleESNs"),
    "exportable": ("exportable", "isExportable"),
    "state": ("state", "status"),
    "purposes": ("keyUsage", "usage", "purposes"),
}

CURVES = {
    "nistp256": ("P-256", 256),
    "p256": ("P-256", 256),
    "secp256r1": ("P-256", 256),
    "prime256v1": ("P-256", 256),
    "nistp384": ("P-384", 384),
    "p384": ("P-384", 384),
    "secp384r1": ("P-384", 384),
    "nistp521": ("P-521", 521),
    "p521": ("P-521", 521),
    "secp521r1": ("P-521", 521),
    "secp256k1": ("secp256k1", 256),
    "brainpoolp256r1": ("brainpoolP256r1", 256),
    "brainpoolp384r1": ("brainpoolP384r1", 384),
    "brainpoolp512r1": ("brainpoolP512r1", 512),
    "ed25519": ("Ed25519", 256),
    "x25519": ("X25519", 256),
}


def normalise_type(ktype: str, size, curve: str | None) -> tuple[str, int | None, str | None, str]:
    """nShield/KeySafe key type -> (algorithm, key_size, curve, key_type)."""
    t = (ktype or "").strip()
    low = t.lower()
    size = int(size) if size not in (None, "", 0) else None
    key_type = "private-key"
    if "public" in low:
        key_type = "public-key"
    if curve:
        c, bits = CURVES.get(curve.lower().replace("-", "").replace("_", ""), (curve, size))
    else:
        c, bits = None, size
    if low.startswith("rsa"):
        return ALG_RSA, size, None, key_type
    if low.startswith(("ecdsa", "ecdh", "ec")) and not low.startswith("ed"):
        if c == "Ed25519":
            return ALG_ED25519, 256, c, key_type
        m = re.search(r"(\d{3})", low)
        if c is None and m:
            c, bits = f"P-{m.group(1)}", int(m.group(1))
        return ALG_EC, bits, c, key_type
    if low.startswith("ed25519"):
        return ALG_ED25519, 256, "Ed25519", key_type
    if low.startswith("x25519"):
        return "X25519", 256, "X25519", key_type
    if low in ("rijndael", "aes") or low.startswith("aes"):
        return ALG_AES, size, None, "secret-key"
    if low in ("des3", "3des", "tdes", "des2"):
        return ALG_3DES, size or 192, None, "secret-key"
    if low == "des":
        return ALG_DES, 64, None, "secret-key"
    if low.startswith("hmac"):
        m = re.search(r"sha(\d+)", low)
        return (
            ALG_HMAC,
            size or ({"1": 160, "224": 224, "256": 256, "384": 384, "512": 512}.get(m.group(1)) if m else None),
            None,
            "secret-key",
        )
    if low.startswith("dsa"):
        return ALG_DSA, size, None, key_type
    if low.startswith("dh") or low.startswith("diffie"):
        return ALG_DH, size, None, key_type
    if low.startswith("mldsa") or low.startswith("ml-dsa") or low.startswith("ml_dsa"):
        m = re.search(r"(44|65|87)", low)
        return ALG_ML_DSA, int(m.group(1)) if m else size, None, key_type
    if low.startswith("mlkem") or low.startswith("ml-kem") or low.startswith("ml_kem"):
        m = re.search(r"(512|768|1024)", low)
        return ALG_ML_KEM, int(m.group(1)) if m else size, None, key_type
    if low in ("wrapped", "generic", "random", "opaque"):
        return ALG_UNKNOWN, size, None, "secret-key"
    return ALG_UNKNOWN, size, c, key_type


class KeySafe5Collector(Collector):
    type_name = "keysafe5"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.url = str(self.opt.get("url", "")).rstrip("/")
        if not self.url:
            raise ValueError(f"[{self.name}] url is required")
        self.session = requests.Session()
        verify = self.opt.get("verify_tls", True)
        self.session.verify = verify if isinstance(verify, str) else bool(verify)
        self.timeout = float(self.opt.get("timeout", 15))
        self.field_map = {str(k): str(v) for k, v in (self.opt.get("field_map") or {}).items()}
        self.keys_paths = [str(self.opt.get("keys_path", "/km/v1/keys"))]
        if self.keys_paths[0] == "/km/v1/keys":
            self.keys_paths.append("/mgmt/v1/keys")
        self.hsms_path = self.opt.get("hsms_path", "/mgmt/v1/hsms")

    # ------------------------------------------------------------ auth + http
    def _authenticate(self):
        mode = str(self.opt.get("auth", "bearer"))
        if mode == "basic":
            self.session.auth = (self.cfg.secret("username", required=True), self.cfg.secret("password", required=True))
        else:
            self.session.headers["Authorization"] = f"Bearer {self.cfg.secret('token', required=True)}"

    def _get(self, path: str, params: dict | None = None):
        r = self.session.get(f"{self.url}{path}", params=params, timeout=self.timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"GET {path} -> {r.status_code}: {r.text[:200]}")
        return r.json()

    def _list(self, path: str) -> list[dict]:
        """KeySafe 5 lists come either as a bare array or as {"keys"|"items"|"data": [...]} with paging."""
        out: list[dict] = []
        params: dict = {}
        page = 0
        while True:
            data = self._get(path, params or None)
            if isinstance(data, list):
                return data
            items = next(
                (data[k] for k in ("keys", "hsms", "items", "data", "results") if isinstance(data.get(k), list)), []
            )
            out.extend(items)
            nxt = data.get("next") or data.get("nextPage") or data.get("nextLink")
            if not nxt or not items or page > 1000:
                return out
            page += 1
            params = {"page": nxt} if not str(nxt).startswith("http") else {}
            if str(nxt).startswith("http"):
                path = str(nxt).replace(self.url, "", 1)

    # ------------------------------------------------------------ collect
    def collect(self) -> list[CryptoAsset]:
        self._authenticate()
        keys: list[dict] | None = None
        errors = []
        for path in self.keys_paths:
            try:
                keys = self._list(path)
                break
            except RuntimeError as exc:
                errors.append(str(exc))
                if "404" not in str(exc):
                    raise
        if keys is None:
            raise RuntimeError("no key listing endpoint answered: " + "; ".join(errors))
        hsms = {}
        if self.hsms_path:
            try:
                for h in self._list(str(self.hsms_path)):
                    esn = str(h.get("esn") or h.get("ESN") or h.get("serial") or h.get("id") or "")
                    hsms[esn] = {
                        "model": h.get("model") or h.get("type"),
                        "firmware": h.get("firmwareVersion") or h.get("firmware"),
                        "mode": h.get("mode"),
                        "hostname": h.get("hostname") or h.get("host"),
                    }
            except RuntimeError as exc:  # optional
                log.debug("[%s] hsm inventory unavailable: %s", self.name, exc)
        return [self._asset(k, hsms) for k in keys if isinstance(k, dict)]

    def _field(self, rec: dict, key: str):
        names = (self.field_map[key],) if key in self.field_map else FIELDS[key]
        for n in names:
            if n in rec and rec[n] not in (None, ""):
                return rec[n]
        return None

    def _asset(self, rec: dict, hsms: dict) -> CryptoAsset:
        f = lambda k: self._field(rec, k)  # noqa: E731
        alg, size, curve, key_type = normalise_type(str(f("type") or ""), f("size"), f("curve"))
        protection = str(f("protection") or "module").lower()
        esns = f("hsm_esns") or []
        if isinstance(esns, str):
            esns = [e.strip() for e in esns.split(",") if e.strip()]
        state_raw = str(f("state") or "").lower()
        state = STATE_ACTIVE
        if state_raw in ("deleted", "destroyed", "retired"):
            state = STATE_DESTROYED
        elif state_raw in ("disabled", "inactive", "deactivated", "expired"):
            state = STATE_DEACTIVATED
        elif state_raw and state_raw not in ("active", "enabled", "ok"):
            state = STATE_UNKNOWN
        purposes = f("purposes") or []
        if isinstance(purposes, str):
            purposes = [p.strip().lower() for p in re.split(r"[,\s]+", purposes) if p.strip()]
        app = str(f("app") or "")
        name = str(f("name") or f("id") or "key")
        exportable = f("exportable")
        return self.asset(
            kind=KIND_KEY,
            name=name,
            native_id=str(f("id") or f"{app}:{name}"),
            algorithm=alg,
            key_size=size,
            curve=curve,
            key_type=key_type,
            purposes=[str(p) for p in purposes],
            created=_ts(f("created")),
            state=state,
            exportable=bool(exportable)
            if exportable is not None
            else False,  # Security World blobs never leave in clear
            hardware_backed=bool(self.opt.get("hardware_backed", True)),
            fips_validated=bool(self.opt.get("fips_validated", True)),
            location=f"{self.url} {app} ({protection}{': ' + str(f('protector')) if f('protector') else ''})",
            extra={
                "app": app,
                "ks5_type": f("type"),
                "protection": protection,
                "protector": f("protector"),
                "hsm_esns": esns,
                "hsms": {e: hsms[e] for e in esns if e in hsms},
                "raw_state": f("state"),
            },
        )


def _ts(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, int | float):
        return datetime.fromtimestamp(value / (1000 if value > 1e11 else 1), UTC)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None
