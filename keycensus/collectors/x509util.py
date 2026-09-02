"""Shared helpers to turn an x509 certificate / public key into a CryptoAsset.

Used by the PEM collector, the TLS collector and Vault PKI.
"""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.serialization import Encoding

from ..model import (
    ALG_DSA,
    ALG_EC,
    ALG_ED448,
    ALG_ED25519,
    ALG_RSA,
    ALG_UNKNOWN,
    ALG_X25519,
    KIND_CERTIFICATE,
    STATE_ACTIVE,
    STATE_DEACTIVATED,
    utcnow,
)

_CURVE_NAMES = {
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
    "secp224r1": "P-224",
    "secp192r1": "P-192",
}


def describe_public_key(key: Any) -> tuple[str, int | None, str | None]:
    """(algorithm, key_size, curve) for any cryptography public/private key."""
    if isinstance(key, rsa.RSAPublicKey | rsa.RSAPrivateKey):
        return ALG_RSA, key.key_size, None
    if isinstance(key, ec.EllipticCurvePublicKey | ec.EllipticCurvePrivateKey):
        name = key.curve.name
        return ALG_EC, key.curve.key_size, _CURVE_NAMES.get(name, name)
    if isinstance(key, ed25519.Ed25519PublicKey | ed25519.Ed25519PrivateKey):
        return ALG_ED25519, 256, "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey | ed448.Ed448PrivateKey):
        return ALG_ED448, 448, "Ed448"
    if isinstance(key, x25519.X25519PublicKey | x25519.X25519PrivateKey):
        return ALG_X25519, 256, "X25519"
    if isinstance(key, x448.X448PublicKey | x448.X448PrivateKey):
        return "X448", 448, "X448"
    if isinstance(key, dsa.DSAPublicKey | dsa.DSAPrivateKey):
        return ALG_DSA, key.key_size, None
    return ALG_UNKNOWN, None, None


def signature_hash_name(cert: x509.Certificate) -> str | None:
    try:
        h = cert.signature_hash_algorithm
    except Exception:  # noqa: BLE001 - e.g. Ed25519 has no separate hash
        return None
    return h.name.upper() if h else None


def certificate_fields(cert: x509.Certificate) -> dict[str, Any]:
    """Everything CryptoAsset needs from a certificate, as kwargs."""
    alg, size, curve = describe_public_key(cert.public_key())
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    cn = None
    try:
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except (IndexError, ValueError):
        pass
    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(n.value) for n in ext.value]
    except x509.ExtensionNotFound:
        pass
    is_ca = False
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        pass
    key_usage: list[str] = []
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        for attr, label in (
            ("digital_signature", "sign"),
            ("key_encipherment", "encrypt"),
            ("key_cert_sign", "sign"),
            ("crl_sign", "sign"),
            ("key_agreement", "derive"),
        ):
            if getattr(ku, attr, False) and label not in key_usage:
                key_usage.append(label)
    except (x509.ExtensionNotFound, ValueError):
        pass
    not_after = cert.not_valid_after_utc
    return {
        "kind": KIND_CERTIFICATE,
        "name": cn or subject or "certificate",
        "algorithm": alg,
        "key_size": size,
        "curve": curve,
        "key_type": "public-key",
        "purposes": key_usage or ["verify"],
        "created": cert.not_valid_before_utc,
        "expires": not_after,
        "state": STATE_ACTIVE if not_after > utcnow() else STATE_DEACTIVATED,
        "subject": subject,
        "issuer": issuer,
        "signature_algorithm": _sig_alg_name(cert),
        "signature_hash": signature_hash_name(cert),
        "self_signed": subject == issuer,
        "fingerprint_sha256": hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest(),
        "extra": {"serial": format(cert.serial_number, "x"), "sans": sans, "is_ca": is_ca},
    }


def _sig_alg_name(cert: x509.Certificate) -> str:
    try:
        return cert.signature_algorithm_oid._name  # noqa: SLF001 - friendly name is only here
    except AttributeError:
        return cert.signature_algorithm_oid.dotted_string
