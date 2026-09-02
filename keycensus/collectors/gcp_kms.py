"""Collector: Google Cloud KMS (software, HSM and external protection levels).

    - name: gcp-payments
      type: gcp-kms
      project: acme-payments-prod
      locations: [global, us-east1, europe-west4]   # default: every location the project has
      auth: default            # default (Application Default Credentials) | token (bearer from token_env/_file)
      token_env: GCP_TOKEN     # only with auth: token -- CI, tests, `gcloud auth print-access-token`
      include_destroyed: false
      endpoint: https://cloudkms.googleapis.com      # override for tests / emulators

Uses the REST API with `requests`; `pip install 'keycensus[gcp]'` adds `google-auth` for
`auth: default` (workload identity, service-account JSON via GOOGLE_APPLICATION_CREDENTIALS,
`gcloud auth application-default login`). Needs `roles/cloudkms.viewer` on the project.

One asset per **CryptoKey**, described by its primary version (or the newest one when there
is no primary): algorithm from the version, `protectionLevel` (SOFTWARE / HSM / EXTERNAL /
EXTERNAL_VPC) -> `hardware_backed` + `fips_validated`, `rotationPeriod` -> `rotation_enabled`,
`primary.createTime` -> `last_rotated`. Version counts and states go to `extra`.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime

import requests

from ..model import (
    ALG_AES,
    ALG_EC,
    ALG_ED25519,
    ALG_HMAC,
    ALG_ML_DSA,
    ALG_RSA,
    ALG_UNKNOWN,
    KIND_KEY,
    STATE_ACTIVE,
    STATE_DEACTIVATED,
    STATE_DESTROYED,
    STATE_PRE_ACTIVATION,
    STATE_UNKNOWN,
    CryptoAsset,
)
from .base import Collector

log = logging.getLogger(__name__)

SCOPE = "https://www.googleapis.com/auth/cloudkms"

PURPOSES = {
    "ENCRYPT_DECRYPT": ["encrypt", "decrypt"],
    "RAW_ENCRYPT_DECRYPT": ["encrypt", "decrypt"],
    "ASYMMETRIC_SIGN": ["sign", "verify"],
    "ASYMMETRIC_DECRYPT": ["decrypt"],
    "MAC": ["mac"],
    "KEY_AGREEMENT": ["derive"],
}

VERSION_STATES = {
    "ENABLED": STATE_ACTIVE,
    "DISABLED": STATE_DEACTIVATED,
    "DESTROYED": STATE_DESTROYED,
    "DESTROY_SCHEDULED": STATE_DESTROYED,
    "PENDING_GENERATION": STATE_PRE_ACTIVATION,
    "PENDING_IMPORT": STATE_PRE_ACTIVATION,
    "IMPORT_FAILED": STATE_UNKNOWN,
    "GENERATION_FAILED": STATE_UNKNOWN,
    "PENDING_EXTERNAL_DESTRUCTION": STATE_DESTROYED,
    "EXTERNAL_DESTRUCTION_FAILED": STATE_UNKNOWN,
}


def normalise_algorithm(name: str) -> tuple[str, int | None, str | None, str | None]:
    """GCP algorithm enum -> (algorithm, key_size, curve, hash)."""
    n = (name or "").upper()
    if n in ("GOOGLE_SYMMETRIC_ENCRYPTION",):
        return ALG_AES, 256, None, None
    if n.startswith("AES_"):
        m = re.match(r"AES_(\d+)_", n)
        return ALG_AES, int(m.group(1)) if m else None, None, None
    if n.startswith("HMAC_"):
        h = n.removeprefix("HMAC_")
        return ALG_HMAC, {"SHA1": 160, "SHA224": 224, "SHA256": 256, "SHA384": 384, "SHA512": 512}.get(h), None, h
    if n.startswith(("RSA_SIGN_", "RSA_DECRYPT_")):
        m = re.search(r"_(\d{4})_(SHA\d+|RAW)?", n)
        return ALG_RSA, int(m.group(1)) if m else None, None, (m.group(2) if m else None)
    if n.startswith("EC_SIGN_"):
        if "SECP256K1" in n:
            return ALG_EC, 256, "secp256k1", "SHA256"
        if "ED25519" in n:
            return ALG_ED25519, 256, "Ed25519", None
        m = re.match(r"EC_SIGN_P(\d+)_(SHA\d+)", n)
        return ALG_EC, int(m.group(1)) if m else None, f"P-{m.group(1)}" if m else None, (m.group(2) if m else None)
    if n.startswith("PQ_SIGN_ML_DSA_"):
        return ALG_ML_DSA, int(n.rsplit("_", 1)[1]), None, None
    if n.startswith("PQ_SIGN_SLH_DSA") or n.startswith("PQ_SIGN_HASH_SLH_DSA"):
        return "SLH-DSA", None, None, None
    if n.startswith("EXTERNAL_SYMMETRIC_ENCRYPTION"):
        return ALG_AES, None, None, None
    return ALG_UNKNOWN, None, None, None


class GcpKmsCollector(Collector):
    type_name = "gcp-kms"
    requires_extra = "gcp"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.project = str(self.opt.get("project", "")).strip()
        if not self.project:
            raise ValueError(f"[{self.name}] project is required")
        self.endpoint = str(self.opt.get("endpoint", "https://cloudkms.googleapis.com")).rstrip("/")
        self.timeout = float(self.opt.get("timeout", 15))
        self.session = requests.Session()

    # ------------------------------------------------------------ auth
    def _authenticate(self):
        if str(self.opt.get("auth", "default")) == "token":
            self.session.headers["Authorization"] = f"Bearer {self.cfg.secret('token', required=True)}"
            return
        import google.auth  # noqa: PLC0415 - optional dependency
        from google.auth.transport.requests import AuthorizedSession  # noqa: PLC0415

        creds, _ = google.auth.default(scopes=[SCOPE])
        self.session = AuthorizedSession(creds)

    # ------------------------------------------------------------ http
    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self.endpoint}/v1/{path}"
        r = self.session.get(url, params=params, timeout=self.timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"GET {path} -> {r.status_code}: {r.text[:200]}")
        return r.json()

    def _paged(self, path: str, key: str, params: dict | None = None) -> list[dict]:
        out: list[dict] = []
        token = None
        while True:
            p = dict(params or {})
            p["pageSize"] = 200
            if token:
                p["pageToken"] = token
            page = self._get(path, p)
            out.extend(page.get(key) or [])
            token = page.get("nextPageToken")
            if not token:
                return out

    # ------------------------------------------------------------ collect
    def collect(self) -> list[CryptoAsset]:
        self._authenticate()
        locations = self.opt.get("locations")
        if not locations:
            locations = [loc["locationId"] for loc in self._paged(f"projects/{self.project}/locations", "locations")]
        include_destroyed = bool(self.opt.get("include_destroyed", False))
        assets: list[CryptoAsset] = []
        for loc in locations:
            for ring in self._paged(f"projects/{self.project}/locations/{loc}/keyRings", "keyRings"):
                for key in self._paged(f"{ring['name']}/cryptoKeys", "cryptoKeys"):
                    versions = self._paged(f"{key['name']}/cryptoKeyVersions", "cryptoKeyVersions")
                    asset = self._asset(key, versions, ring["name"])
                    if asset.state == STATE_DESTROYED and not include_destroyed:
                        continue
                    assets.append(asset)
        return assets

    def _asset(self, key: dict, versions: list[dict], ring: str) -> CryptoAsset:
        name = key["name"]  # projects/p/locations/l/keyRings/r/cryptoKeys/k
        short = name.rsplit("/", 1)[1]
        primary = key.get("primary") or {}
        if not primary and versions:
            primary = max(versions, key=lambda v: v.get("createTime", ""))
        tmpl = key.get("versionTemplate") or {}
        algorithm = primary.get("algorithm") or tmpl.get("algorithm") or ""
        protection = primary.get("protectionLevel") or tmpl.get("protectionLevel") or "SOFTWARE"
        alg, size, curve, digest = normalise_algorithm(algorithm)
        hsm = protection == "HSM"
        external = protection.startswith("EXTERNAL")
        states = {}
        for v in versions:
            s = v.get("state", "")
            states[s] = states.get(s, 0) + 1
        live = [v for v in versions if v.get("state") in ("ENABLED", "DISABLED")]
        state = VERSION_STATES.get(primary.get("state", ""), STATE_UNKNOWN)
        if not live and versions and all(v.get("state", "").startswith("DESTROY") for v in versions):
            state = STATE_DESTROYED
        rotation = bool(key.get("rotationPeriod")) if key.get("purpose") == "ENCRYPT_DECRYPT" else None
        labels = {k: str(v) for k, v in (key.get("labels") or {}).items()}
        return self.asset(
            kind=KIND_KEY,
            name=short,
            native_id=name,
            algorithm=alg,
            key_size=size,
            curve=curve,
            key_type="secret-key" if alg in (ALG_AES, ALG_HMAC) else "private-key",
            purposes=list(PURPOSES.get(key.get("purpose", ""), [])),
            created=_ts(key.get("createTime")),
            last_rotated=_ts(primary.get("createTime") or primary.get("generateTime")),
            expires=_ts(primary.get("destroyTime")) if primary.get("state") == "DESTROY_SCHEDULED" else None,
            state=state,
            rotation_enabled=rotation,
            exportable=bool(primary.get("importJob")) or external,  # imported / externally held material
            hardware_backed=hsm,
            fips_validated=hsm,  # Cloud HSM is FIPS 140-2 Level 3 validated
            location=f"{name.split('/')[3]} {protection}",
            tags=labels,
            extra={
                "purpose": key.get("purpose"),
                "gcp_algorithm": algorithm,
                "digest": digest,
                "protection_level": protection,
                "key_ring": ring.rsplit("/", 1)[1],
                "primary_version": primary.get("name", "").rsplit("/", 1)[-1] or None,
                "versions": len(versions),
                "version_states": states,
                "rotation_period": key.get("rotationPeriod"),
                "next_rotation_time": key.get("nextRotationTime"),
                "import_only": key.get("importOnly"),
                "import_job": primary.get("importJob"),
                "external_key_uri": (primary.get("externalProtectionLevelOptions") or {}).get("externalKeyUri"),
                "destroy_scheduled_duration": key.get("destroyScheduledDuration"),
            },
        )


def _ts(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None
