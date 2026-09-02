"""Collector: anything that speaks PKCS#11 -- Thales Luna, Entrust nShield,
AWS CloudHSM, Utimaco, YubiHSM, SoftHSM ...

    - name: prod-luna
      type: pkcs11
      module: /usr/safenet/lunaclient/lib/libCryptoki2_64.so
      token_label: payments-partition       # or slot: 0
      pin_env: LUNA_PARTITION_PIN
      hardware_backed: true                 # default true; SoftHSM sets false
      fips_validated: true

Requires `pip install 'keycensus[pkcs11]'` (python-pkcs11) and the vendor's
PKCS#11 library on the same machine -- PKCS#11 is an in-process API, so the
collector has to run wherever the client library is installed (exactly like
the application that uses the HSM).

We only ever call C_FindObjects / C_GetAttributeValue on *public* attributes
(label, id, key type, size, usage flags, dates). Key values are never read.
"""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime

from ..model import (
    ALG_3DES,
    ALG_AES,
    ALG_DES,
    ALG_DH,
    ALG_DSA,
    ALG_EC,
    ALG_ED25519,
    ALG_HMAC,
    ALG_RSA,
    ALG_UNKNOWN,
    KIND_KEY,
    STATE_ACTIVE,
    CryptoAsset,
)
from .base import Collector

log = logging.getLogger(__name__)

# Named-curve OIDs (DER of the OID) -> friendly name.  CKA_EC_PARAMS is DER.
_EC_OIDS = {
    b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07": ("P-256", 256),
    b"\x06\x05\x2b\x81\x04\x00\x22": ("P-384", 384),
    b"\x06\x05\x2b\x81\x04\x00\x23": ("P-521", 521),
    b"\x06\x05\x2b\x81\x04\x00\x21": ("P-224", 224),
    b"\x06\x05\x2b\x81\x04\x00\x0a": ("secp256k1", 256),
    b"\x06\x03\x2b\x65\x70": ("Ed25519", 256),
}


class Pkcs11Collector(Collector):
    type_name = "pkcs11"
    requires_extra = "pkcs11"

    def collect(self) -> list[CryptoAsset]:
        import pkcs11
        from pkcs11 import Attribute, KeyType, ObjectClass

        module = self.opt.get("module")
        if not module:
            raise ValueError("pkcs11 collector needs 'module' (path to the PKCS#11 .so/.dll)")
        lib = pkcs11.lib(module)
        token = self._find_token(lib)
        pin = self.cfg.secret("pin")
        hardware = bool(self.opt.get("hardware_backed", True))
        fips = self.opt.get("fips_validated")

        assets: list[CryptoAsset] = []
        with token.open(user_pin=pin) if pin else token.open() as session:
            for cls, key_type_name in (
                (ObjectClass.SECRET_KEY, "secret-key"),
                (ObjectClass.PRIVATE_KEY, "private-key"),
                (ObjectClass.PUBLIC_KEY, "public-key"),
            ):
                for obj in session.get_objects({Attribute.CLASS: cls}):
                    try:
                        assets.append(self._describe(obj, key_type_name, token, hardware, fips, KeyType, Attribute))
                    except Exception as exc:  # noqa: BLE001 - one odd object shouldn't stop the scan
                        log.warning("[%s] skipping object: %s", self.name, exc)
        return assets

    def _find_token(self, lib):
        label = self.opt.get("token_label")
        slot_no = self.opt.get("slot")
        if label:
            return lib.get_token(token_label=label)
        slots = lib.get_slots(token_present=True)
        if slot_no is not None:
            for s in slots:
                if s.slot_id == int(slot_no):
                    return s.get_token()
            raise ValueError(f"slot {slot_no} not found")
        if not slots:
            raise ValueError("no token present")
        return slots[0].get_token()

    def _describe(self, obj, key_type_name, token, hardware, fips, KeyType, Attribute) -> CryptoAsset:  # noqa: N803
        def attr(a, default=None):
            try:
                return obj[a]
            except Exception:  # noqa: BLE001 - attribute not present / not readable
                return default

        label = attr(Attribute.LABEL) or ""
        cka_id = attr(Attribute.ID) or b""
        kt = attr(Attribute.KEY_TYPE)
        alg, size, curve = self._algorithm(kt, obj, KeyType, Attribute, attr)

        purposes = []
        for a, p in (
            (Attribute.ENCRYPT, "encrypt"), (Attribute.DECRYPT, "decrypt"),
            (Attribute.SIGN, "sign"), (Attribute.VERIFY, "verify"),
            (Attribute.WRAP, "wrap"), (Attribute.UNWRAP, "unwrap"),
            (Attribute.DERIVE, "derive"),
        ):  # fmt: skip
            if attr(a):
                purposes.append(p)

        extractable = attr(Attribute.EXTRACTABLE)
        start = _ck_date(attr(Attribute.START_DATE))
        end = _ck_date(attr(Attribute.END_DATE))

        native = cka_id.hex() if cka_id else f"{key_type_name}:{label}"
        return self.asset(
            kind=KIND_KEY,
            name=label or f"<unlabelled {key_type_name}>",
            native_id=f"{token.label}/{native}/{key_type_name}",
            algorithm=alg,
            key_size=size,
            curve=curve,
            key_type=key_type_name,
            purposes=purposes,
            created=start,
            expires=end,
            state=STATE_ACTIVE,
            exportable=bool(extractable) if extractable is not None else None,
            hardware_backed=hardware,
            fips_validated=fips,
            location=f"token={token.label} manufacturer={token.manufacturer_id.strip()}",
            extra={
                "cka_id": cka_id.hex() if cka_id else None,
                "sensitive": attr(Attribute.SENSITIVE),
                "private": attr(Attribute.PRIVATE),
                "modifiable": attr(Attribute.MODIFIABLE),
                "token_model": token.model.strip(),
                "token_serial": token.serial.decode(errors="replace").strip()
                if isinstance(token.serial, bytes)
                else str(token.serial).strip(),
            },
        )

    @staticmethod
    def _algorithm(kt, obj, KeyType, Attribute, attr):  # noqa: N803
        if kt == KeyType.AES:
            return ALG_AES, (attr(Attribute.VALUE_LEN) or 0) * 8 or None, None
        if kt == KeyType.DES3:
            return ALG_3DES, 192, None
        if kt == getattr(KeyType, "DES2", None):
            return ALG_3DES, 128, None
        if kt == getattr(KeyType, "DES", getattr(KeyType, "_DES", None)):
            return ALG_DES, 64, None
        if kt == KeyType.RSA:
            mod = attr(Attribute.MODULUS)
            bits = attr(Attribute.MODULUS_BITS) or (len(mod) * 8 if mod else None)
            return ALG_RSA, bits, None
        if kt == KeyType.EC:
            params = attr(Attribute.EC_PARAMS) or b""
            curve, bits = _EC_OIDS.get(bytes(params), (None, None))
            return ALG_EC, bits, curve
        if kt == KeyType.DSA:
            prime = attr(Attribute.PRIME)
            return ALG_DSA, len(prime) * 8 if prime else None, None
        if kt == KeyType.DH:
            prime = attr(Attribute.PRIME)
            return ALG_DH, len(prime) * 8 if prime else None, None
        if kt == KeyType.GENERIC_SECRET:
            return ALG_HMAC, (attr(Attribute.VALUE_LEN) or 0) * 8 or None, None
        if kt == getattr(KeyType, "EC_EDWARDS", None):
            return ALG_ED25519, 256, "Ed25519"
        return ALG_UNKNOWN, None, None


def _ck_date(value) -> datetime | None:
    """CK_DATE -> datetime (UTC midnight). python-pkcs11 gives date or None."""
    if not value:
        return None
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=UTC)
    return None
