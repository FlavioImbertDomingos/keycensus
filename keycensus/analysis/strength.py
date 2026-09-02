"""How strong is this algorithm, classically and against a quantum computer?

Two questions every inventory has to answer per asset:

1. **Classical security level** (bits) -- what everyone has cared about since
   the 90s. RSA-2048 ≈ 112 bits, P-256 = 128 bits, AES-256 = 256 bits.
   Sources: NIST SP 800-57 Part 1 Rev. 5, Table 2.

2. **Quantum readiness** -- since NIST IR 8547 (2024) set the clock:
   quantum-vulnerable public-key algorithms (RSA, ECDSA, ECDH, DH, DSA, EdDSA)
   are *deprecated after 2030* and *disallowed after 2035*. Symmetric ciphers
   and hashes only lose ~half their bits to Grover's algorithm, so AES-256 and
   SHA-256 are fine; AES-128 is "acceptable but plan to move".

`nist_quantum_level` follows the NIST PQC evaluation levels used by CycloneDX:
1 = at least as hard as AES-128 key search, 2 = SHA-256 collision,
3 = AES-192, 4 = SHA-384 collision, 5 = AES-256. 0 = broken by Shor.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..model import (
    ALG_3DES,
    ALG_AES,
    ALG_CHACHA20,
    ALG_DES,
    ALG_DH,
    ALG_DSA,
    ALG_EC,
    ALG_ED448,
    ALG_ED25519,
    ALG_HMAC,
    ALG_ML_DSA,
    ALG_ML_KEM,
    ALG_RC4,
    ALG_RSA,
    ALG_SLH_DSA,
    ALG_X25519,
    CryptoAsset,
)

QUANTUM_VULNERABLE = "quantum-vulnerable"  # broken by Shor's algorithm
QUANTUM_REDUCED = "quantum-reduced"  # Grover halves the strength; may still be OK
QUANTUM_SAFE = "quantum-safe"  # PQC algorithm or symmetric ≥ 256-bit
QUANTUM_UNKNOWN = "unknown"

PUBLIC_KEY_CLASSICAL = {ALG_RSA, ALG_EC, ALG_DSA, ALG_DH, ALG_ED25519, ALG_ED448, ALG_X25519}
PQC = {ALG_ML_KEM, ALG_ML_DSA, ALG_SLH_DSA}
SYMMETRIC = {ALG_AES, ALG_3DES, ALG_DES, ALG_RC4, ALG_CHACHA20, ALG_HMAC}

# NIST SP 800-57 Pt.1 Rev.5 Table 2: security strength of asymmetric key sizes.
_RSA_DH_DSA_STRENGTH = [(1024, 80), (2048, 112), (3072, 128), (7680, 192), (15360, 256)]
_EC_STRENGTH = [(160, 80), (224, 112), (256, 128), (384, 192), (512, 256)]

CURVE_BITS = {
    "P-256": 256, "secp256r1": 256, "prime256v1": 256,
    "P-384": 384, "secp384r1": 384,
    "P-521": 521, "secp521r1": 521,
    "P-224": 224, "secp224r1": 224,
    "P-192": 192, "secp192r1": 192,
    "secp256k1": 256,
    "brainpoolP256r1": 256, "brainpoolP384r1": 384, "brainpoolP512r1": 512,
    "Ed25519": 256, "X25519": 256, "Ed448": 448, "X448": 448,
}  # fmt: skip


def _table_lookup(bits: int, table: list[tuple[int, int]]) -> int:
    strength = 0
    for size, s in table:
        if bits >= size:
            strength = s
    return strength


@dataclass
class Strength:
    classical_bits: int | None
    quantum_class: str
    nist_quantum_level: int | None
    note: str


def assess(asset: CryptoAsset) -> Strength:
    alg = asset.algorithm
    size = asset.key_size
    if asset.curve and not size:
        size = CURVE_BITS.get(asset.curve)

    if alg in (ALG_RSA, ALG_DSA, ALG_DH):
        bits = _table_lookup(size or 0, _RSA_DH_DSA_STRENGTH) if size else None
        return Strength(
            bits,
            QUANTUM_VULNERABLE,
            0,
            "Broken by Shor's algorithm; migrate to ML-KEM / ML-DSA (NIST IR 8547: deprecated 2030, disallowed 2035).",
        )
    if alg in (ALG_EC, ALG_ED25519, ALG_ED448, ALG_X25519):
        bits = _table_lookup(size or 0, _EC_STRENGTH) if size else None
        return Strength(
            bits,
            QUANTUM_VULNERABLE,
            0,
            "Elliptic-curve: broken by Shor's algorithm; migrate to ML-KEM / ML-DSA "
            "(NIST IR 8547: deprecated 2030, disallowed 2035).",
        )
    if alg in PQC:
        level = {512: 1, 768: 3, 1024: 5, 44: 2, 65: 3, 87: 5}.get(size or 0)
        return Strength(None, QUANTUM_SAFE, level, "NIST FIPS 203/204/205 post-quantum algorithm.")
    if alg == ALG_AES:
        if size == 256:
            return Strength(
                256,
                QUANTUM_SAFE,
                5,
                "AES-256: Grover reduces to ~128-bit effective; considered quantum-safe.",
            )
        if size == 192:
            return Strength(192, QUANTUM_REDUCED, 3, "AES-192: acceptable; prefer AES-256 for long-lived data.")
        if size == 128:
            return Strength(
                128,
                QUANTUM_REDUCED,
                1,
                "AES-128: ~64-bit effective against Grover; acceptable today, plan to move to AES-256 "
                "for data that must stay secret past 2035.",
            )
        return Strength(size, QUANTUM_UNKNOWN, None, "AES with unusual key size.")
    if alg == ALG_CHACHA20:
        return Strength(256, QUANTUM_SAFE, 5, "ChaCha20 256-bit key; quantum-safe.")
    if alg == ALG_HMAC:
        if size and size >= 256:
            return Strength(
                size,
                QUANTUM_SAFE,
                5 if size >= 384 else 2,
                "HMAC with ≥256-bit key/hash; quantum-safe.",
            )
        return Strength(size, QUANTUM_REDUCED, 1, "HMAC with short key/hash.")
    if alg == ALG_3DES:
        return Strength(
            112 if (size or 192) >= 168 else 80,
            QUANTUM_VULNERABLE,
            0,
            "Triple-DES is disallowed by NIST SP 800-131A Rev.2 after 2023 and 'weak' under PCI DSS v4.",
        )
    if alg in (ALG_DES, ALG_RC4):
        return Strength(
            56 if alg == ALG_DES else 0,
            QUANTUM_VULNERABLE,
            0,
            f"{alg} is broken classically; retire immediately.",
        )
    return Strength(None, QUANTUM_UNKNOWN, None, "Algorithm not recognised.")


# PCI DSS v4.0 glossary, "Strong Cryptography": AES ≥128, TDEA ≥112 (three-key, legacy),
# RSA ≥2048, ECC ≥224, DSA/DH ≥2048/224. Below these = weak.
def is_weak_key_size(asset: CryptoAsset) -> bool:
    alg, size = asset.algorithm, asset.key_size
    if asset.curve and not size:
        size = CURVE_BITS.get(asset.curve)
    if size is None:
        return False
    if alg in (ALG_RSA, ALG_DSA, ALG_DH):
        return size < 2048
    if alg == ALG_EC:
        return size < 224
    if alg == ALG_AES:
        return size < 128
    if alg == ALG_HMAC:
        return size < 128
    return False


def primitive_for(asset: CryptoAsset) -> str:
    """CycloneDX algorithmProperties.primitive."""
    alg = asset.algorithm
    if alg in (ALG_AES, ALG_3DES, ALG_DES):
        return "block-cipher"
    if alg in (ALG_RC4, ALG_CHACHA20):
        return "stream-cipher"
    if alg == ALG_HMAC:
        return "mac"
    if alg in (ALG_RSA,):
        return "pke" if "encrypt" in asset.purposes and "sign" not in asset.purposes else "signature"
    if alg in (ALG_EC, ALG_ED25519, ALG_ED448, ALG_DSA, ALG_ML_DSA, ALG_SLH_DSA):
        return "signature" if "derive" not in asset.purposes else "key-agree"
    if alg in (ALG_X25519, ALG_DH):
        return "key-agree"
    if alg == ALG_ML_KEM:
        return "kem"
    return "unknown"
