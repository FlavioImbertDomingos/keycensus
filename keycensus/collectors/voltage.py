"""Collector: OpenText (formerly Micro Focus / HP) Voltage SecureData key inventory.

Voltage SecureData does not publish a public REST inventory API, so this
collector reads an **inventory export**: either a JSON document served over
HTTP (from an internal adapter or a scheduled export job) or a local file
(JSON or CSV exported from the Management Console / KMS reports).

    - name: voltage-prod
      type: voltage
      url: https://voltage-export.internal/inventory.json    # or:
      file: /exports/voltage-keys.csv
      username: monitor
      password_env: VOLTAGE_PASSWORD
      hardware_backed: true            # Voltage KMS keys usually sit behind an HSM
      field_map:                       # rename your export's columns to ours
        name: KeyName
        identity: Identity
        district: District
        algorithm: Algorithm
        created: CreatedDate
        rotated: LastRotation
        state: Status

Expected (canonical) shape:

    {"keys": [
       {"name": "pan-fpe", "identity": "payments@example.com", "district": "prod",
        "algorithm": "FF1-AES-256", "purpose": "fpe", "created": "2024-01-15",
        "rotated": "2025-01-15", "state": "active", "exportable": false}
    ]}

`algorithm` strings are normalised: "AES-256", "FF1-AES-256" (FPE), "AES256",
"RSA-2048", "3DES", "SHA-256 HMAC" ... The mock server in `mock-voltage/`
serves this exact shape so the demo runs without a Voltage licence.
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import requests

from ..model import (
    ALG_3DES,
    ALG_AES,
    ALG_DES,
    ALG_EC,
    ALG_HMAC,
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

_ALG_RE = re.compile(r"(FF1|FF3|FPE)?[-_ ]?(AES|3DES|TDES|TDEA|DES|RSA|HMAC|SHA|EC|ECDSA|ECC)[-_ ]?(\d+)?", re.I)

STATES = {
    "active": STATE_ACTIVE,
    "enabled": STATE_ACTIVE,
    "current": STATE_ACTIVE,
    "retired": STATE_DEACTIVATED,
    "disabled": STATE_DEACTIVATED,
    "inactive": STATE_DEACTIVATED,
    "deprecated": STATE_DEACTIVATED,
    "destroyed": STATE_DESTROYED,
    "deleted": STATE_DESTROYED,
}

PURPOSES = {
    "fpe": ["encrypt", "decrypt"],
    "tokenize": ["encrypt", "decrypt"],
    "tokenization": ["encrypt", "decrypt"],
    "encrypt": ["encrypt", "decrypt"],
    "encryption": ["encrypt", "decrypt"],
    "sign": ["sign", "verify"],
    "signing": ["sign", "verify"],
    "mac": ["mac"],
    "hmac": ["mac"],
    "kek": ["wrap", "unwrap"],
    "wrap": ["wrap", "unwrap"],
}


def normalise_algorithm(text: str | None) -> tuple[str, int | None, str | None, str | None]:
    """-> (algorithm, key_size, curve, fpe_mode)"""
    if not text:
        return ALG_UNKNOWN, None, None, None
    m = _ALG_RE.search(text)
    if not m:
        return ALG_UNKNOWN, None, None, None
    fam = m.group(2).upper()
    bits = int(m.group(3)) if m.group(3) else None
    mode = (m.group(1) or "").upper()
    if fam == "AES":
        return ALG_AES, bits or 256, None, (mode or None)
    if fam in ("3DES", "TDES", "TDEA"):
        return ALG_3DES, 192, None, None
    if fam == "DES":
        return ALG_DES, 64, None, None
    if fam == "RSA":
        return ALG_RSA, bits, None, None
    if fam in ("HMAC", "SHA"):
        return ALG_HMAC, bits or 256, None, None
    if fam in ("EC", "ECDSA", "ECC"):
        return ALG_EC, bits, f"P-{bits}" if bits else None, None
    return ALG_UNKNOWN, None, None, None


class VoltageCollector(Collector):
    type_name = "voltage"

    def collect(self) -> list[CryptoAsset]:
        rows = self._load_rows()
        fmap = {k: str(v) for k, v in (self.opt.get("field_map") or {}).items()}
        hardware = self.opt.get("hardware_backed", True)
        assets: list[CryptoAsset] = []
        for row in rows:

            def g(key, default=None, row=row, fmap=fmap):
                return row.get(fmap.get(key, key), default)

            alg, size, curve, mode = normalise_algorithm(g("algorithm"))
            purpose = str(g("purpose", "") or "").lower()
            state = STATES.get(str(g("state", "") or "").lower(), STATE_UNKNOWN)
            name = str(g("name") or g("key_id") or g("identity") or "voltage-key")
            identity, district = g("identity"), g("district")
            native = str(g("key_id") or f"{district}/{identity}/{name}")
            exportable = g("exportable")
            assets.append(
                self.asset(
                    kind=KIND_KEY,
                    name=name,
                    native_id=native,
                    algorithm=alg,
                    key_size=size,
                    curve=curve,
                    key_type="secret-key" if alg in (ALG_AES, ALG_3DES, ALG_DES, ALG_HMAC) else "private-key",
                    purposes=PURPOSES.get(purpose, ["encrypt", "decrypt"]),
                    created=_dt(g("created")),
                    last_rotated=_dt(g("rotated")),
                    expires=_dt(g("expires")),
                    state=state,
                    rotation_enabled=_bool(g("auto_rotate")),
                    exportable=_bool(exportable),
                    hardware_backed=_bool(g("hsm_backed"), default=bool(hardware)),
                    location=f"district={district} identity={identity}",
                    extra={
                        "identity": identity,
                        "district": district,
                        "purpose": purpose,
                        "fpe_mode": mode,
                        "raw_algorithm": g("algorithm"),
                    },
                )
            )
        return assets

    def _load_rows(self) -> list[dict]:
        if self.opt.get("file"):
            path = Path(self.opt["file"])
            text = path.read_text()
            if path.suffix.lower() == ".csv":
                return list(csv.DictReader(io.StringIO(text)))
            data = json.loads(text)
        elif self.opt.get("url"):
            auth = None
            user = self.opt.get("username")
            if user:
                auth = (str(user), self.cfg.secret("password") or "")
            verify = self.opt.get("verify_tls", True)
            r = requests.get(
                str(self.opt["url"]),
                auth=auth,
                timeout=float(self.opt.get("timeout", 10)),
                verify=verify if isinstance(verify, str) else bool(verify),
            )
            r.raise_for_status()
            ctype = r.headers.get("content-type", "")
            if "csv" in ctype:
                return list(csv.DictReader(io.StringIO(r.text)))
            data = r.json()
        else:
            raise ValueError("voltage collector needs 'url' or 'file'")
        if isinstance(data, list):
            return data
        for key in ("keys", "items", "data", "results"):
            if isinstance(data.get(key), list):
                return data[key]
        raise ValueError("voltage export: expected a list or an object with a 'keys' list")


def _dt(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, int | float):
        return datetime.fromtimestamp(value, UTC)
    s = str(value).strip().replace("Z", "+00:00")
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y", "%d/%m/%Y"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=UTC)
        except ValueError:
            pass
    try:
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=UTC)
    except ValueError:
        return None


def _bool(value, default=None):
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}
