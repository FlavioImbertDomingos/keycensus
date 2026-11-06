"""Algorithm names from the CycloneDX Cryptography Registry.

The registry (keycensus/data/cyclonedx/cryptography-defs.json, from the CycloneDX specification, tag
1.7.2) lists algorithm families, each with naming patterns such as `AES[-(128|192|256)][-(GCM|CCM)]`, and
elliptic curve identifiers such as `nist/P-256`. A CBOM that uses them names RSA-OAEP with SHA-256 the
same way whichever tool wrote it.

`normalise(asset)` gives the family, a name that matches one of the family's patterns, the primitive
and the curve identifier. It only names a family the source actually establishes:

* An RSA key is RSAES-OAEP, RSAES-PKCS1, RSASSA-PKCS1 or RSASSA-PSS depending on the padding scheme it is
  used with. Key stores rarely say which (AWS KMS allows both PKCS#1 v1.5 and PSS on one signing key),
  so the family is set only when the scheme is known: code that calls OAEP or SHA256withRSA, or AWS KMS
  encryption keys, which only support OAEP. Otherwise the family stays unset and `note` says why.
* An EC key is ECDSA when it only signs and ECDH when it only agrees keys; one that does both, or whose
  use is not reported, gets no family.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any

from .model import KIND_CERTIFICATE, CryptoAsset

REGISTRY_SOURCE = "CycloneDX specification 1.7.2, schema/cryptography-defs.json"


@lru_cache(maxsize=1)
def registry() -> dict[str, Any]:
    with resources.files("keycensus").joinpath("data/cyclonedx/cryptography-defs.json").open("rb") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def families() -> dict[str, list[dict[str, str]]]:
    """family -> its variants ({pattern, primitive})."""
    return {a["family"]: a["variant"] for a in registry()["algorithms"]}


@lru_cache(maxsize=1)
def curves() -> set[str]:
    return {f"{group['name']}/{c['name']}" for group in registry()["ellipticCurves"] for c in group["curves"]}


@lru_cache(maxsize=256)
def pattern_regex(pattern: str) -> re.Pattern:
    """`RSA-OAEP[-{hashAlgorithm}][-{keyLength}]` -> a regex: [x] optional, (a|b) alternatives, {p} a value.
    A parenthesised group with no alternatives, as in `FFDH(E)`, is read as optional: the registry writes the
    same idea as `ECDH[E]` elsewhere."""
    out, i, groups = [], 0, []
    while i < len(pattern):
        c = pattern[i]
        if c == "[":
            out.append("(?:")
        elif c == "]":
            out.append(")?")
        elif c == "(":
            depth, j = 0, i
            while j < len(pattern):
                depth += {"(": 1, ")": -1}.get(pattern[j], 0)
                if depth == 0:
                    break
                j += 1
            groups.append("|" not in pattern[i + 1 : j])
            out.append("(?:")
        elif c == ")":
            out.append(")?" if groups.pop() else ")")
        elif c == "|":
            out.append("|")
        elif c == "{":
            j = pattern.index("}", i)
            out.append(r"[A-Za-z0-9_./]+(?:-[A-Za-z0-9_./]+)*?")
            i = j
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out))


def matches_family(name: str, family: str) -> bool:
    return any(pattern_regex(v["pattern"]).fullmatch(name) for v in families().get(family, []))


@dataclass(frozen=True)
class RegistryName:
    name: str  # follows one of the family's patterns when family is set
    family: str | None
    primitive: str | None  # CycloneDX primitive (ae, block-cipher, signature, kem ...)
    curve: str | None = None  # registry curve identifier, e.g. nist/P-256
    note: str | None = None  # why the family is unset, or what is assumed

    @property
    def resolved(self) -> bool:
        return self.family is not None


_CURVES = {"P-224": "nist/P-224", "P-256": "nist/P-256", "P-384": "nist/P-384", "P-521": "nist/P-521",
           "secp256k1": "secg/secp256k1", "Ed25519": "other/Ed25519", "Ed448": "other/Ed448",
           "X25519": "other/Curve25519", "X448": "other/Curve448"}  # fmt: skip
_BRAINPOOL = re.compile(r"brainpoolP(\d+)[rt]1", re.I)
_HASHES = {"MD5": "MD5", "MD4": "MD4", "MD2": "MD2", "SHA-1": "SHA-1"}
_SIMPLE_CIPHERS = {  # keycensus algorithm -> (registry family, name prefix, size in name?)
    "3DES": ("3DES", "3DES", True), "DES": ("DES", "DES", True), "RC4": ("RC4", "RC4", True),
    "RC2": ("RC2", "RC2", True), "Blowfish": ("Blowfish", "Blowfish", True), "IDEA": ("IDEA", "IDEA", False),
    "CAST5": ("CAST5", "CAST5", True), "SM4": ("SM4", "SM4", False),
}  # fmt: skip
_AE_MODES = {"GCM", "CCM", "OCB", "SIV"}
_WRAP_MODES = {"KW", "KWP"}


def curve_id(curve: str | None) -> str | None:
    if not curve:
        return None
    if curve in _CURVES:
        return _CURVES[curve]
    m = _BRAINPOOL.fullmatch(curve)
    if m:
        cid = f"brainpool/{curve[0].lower()}{curve[1:]}"
        return cid if cid in curves() else None
    for prefix in ("secg/", "nist/", "x962/"):
        if f"{prefix}{curve}" in curves():
            return f"{prefix}{curve}"
    return None


def _hash_token(h: str | None) -> str | None:
    """'SHA-256', 'sha256', 'SHA256' -> 'SHA-256' (the registry's SHA-2 spelling)."""
    if not h:
        return None
    s = h.upper().replace("_", "-")
    m = re.fullmatch(r"SHA-?(1|224|256|384|512)", s)
    if m:
        return "SHA-1" if m.group(1) == "1" else f"SHA-{m.group(1)}"
    m = re.fullmatch(r"SHA3-?(224|256|384|512)", s)
    return f"SHA3-{m.group(1)}" if m else None


def _join(*parts: Any) -> str:
    return "-".join(str(p) for p in parts if p not in (None, ""))


def _purposes(asset: CryptoAsset) -> set[str]:
    p = {x.lower() for x in asset.purposes}
    if asset.kind == KIND_CERTIFICATE and not p & {"derive"}:
        p |= {"sign"}  # a certificate's key signs (TLS handshakes, code, documents) unless it says key agreement
    return p


def _rsa(asset: CryptoAsset) -> RegistryName:
    ex = asset.extra or {}
    scheme = str(ex.get("scheme") or "").upper()
    h = _hash_token(ex.get("hash"))
    size = asset.key_size
    if scheme == "OAEP":
        return RegistryName(_join("RSA-OAEP", h, size), "RSAES-OAEP", "pke")
    if scheme == "PSS":
        return RegistryName(_join("RSA-PSS", h, size), "RSASSA-PSS", "signature")
    if scheme in ("PKCS1", "PKCS1V15", "PKCS1-1.5"):
        p = _purposes(asset)
        if p & {"sign", "verify"} and not p & {"encrypt", "decrypt", "wrap", "unwrap"}:
            return RegistryName(_join("RSA-PKCS1-1.5", h, size), "RSASSA-PKCS1", "signature")
        if p & {"encrypt", "decrypt", "wrap", "unwrap"} and not p & {"sign", "verify"}:
            return RegistryName(_join("RSA-PKCS1-1.5", size), "RSAES-PKCS1", "pke")
    return RegistryName(_join("RSA", size), None, "pke" if _purposes(asset) & {"encrypt", "decrypt"} else "signature",
                        note="RSA padding scheme (PKCS#1 v1.5, PSS or OAEP) is not reported by the source")  # fmt: skip


def _ec(asset: CryptoAsset) -> RegistryName:
    cid = curve_id(asset.curve)
    token = asset.curve if cid else None
    p = _purposes(asset)
    signs, agrees = bool(p & {"sign", "verify"}), "derive" in p
    if signs and not agrees:
        return RegistryName(_join("ECDSA", token, _hash_token((asset.extra or {}).get("hash"))), "ECDSA",
                            "signature", cid)  # fmt: skip
    if agrees and not signs:
        return RegistryName(_join("ECDH", token), "ECDH", "key-agree", cid)
    return RegistryName(_join("EC", asset.curve), None, None, cid,
                        note="EC key used for both or unreported purposes: ECDSA or ECDH")  # fmt: skip


def _aes(asset: CryptoAsset) -> RegistryName:
    mode = str((asset.extra or {}).get("mode") or "").upper() or None
    if mode in _AE_MODES:
        return RegistryName(_join("AES", asset.key_size, mode), "AES", "ae")
    if mode in _WRAP_MODES:
        return RegistryName(_join("AES", asset.key_size, mode), "AES", "key-wrap")
    if mode in ("ECB", "CBC", "CFB", "OFB", "CTR", "XTS", "CTS"):
        return RegistryName(_join("AES", asset.key_size, mode), "AES", "block-cipher")
    return RegistryName(_join("AES", asset.key_size), "AES", "block-cipher")


def normalise(asset: CryptoAsset) -> RegistryName:
    """Registry family and name for the algorithm of a key, certificate key or code call site."""
    alg = asset.algorithm or ""
    ex = asset.extra or {}
    mode = str(ex.get("mode") or "").upper() or None
    if alg == "RSA":
        return _rsa(asset)
    if alg == "EC":
        return _ec(asset)
    if alg in ("Ed25519", "Ed448"):
        return RegistryName(alg, "EdDSA", "signature", _CURVES[alg])
    if alg in ("X25519", "X448"):
        return RegistryName(alg.lower(), "ECDH", "key-agree", _CURVES[alg])
    if alg == "AES":
        return _aes(asset)
    if alg in _SIMPLE_CIPHERS:
        family, prefix, sized = _SIMPLE_CIPHERS[alg]
        stream = alg == "RC4"
        return RegistryName(_join(prefix, asset.key_size if sized else None, None if stream else mode), family,
                            "stream-cipher" if stream else "block-cipher")  # fmt: skip
    if alg == "Camellia":
        return RegistryName(_join("CAMELLIA", asset.key_size or 128, mode), "CAMELLIA", "block-cipher")
    if alg == "SEED":
        return RegistryName(_join("SEED-128", mode), "SEED", "block-cipher")
    if alg in ("ChaCha20-Poly1305", "CHACHA20-POLY1305"):
        return RegistryName("ChaCha20-Poly1305", "ChaCha20", "ae")
    if alg == "ChaCha20":
        if mode == "POLY1305":
            return RegistryName("ChaCha20-Poly1305", "ChaCha20", "ae")
        return RegistryName("ChaCha20", "ChaCha20", "stream-cipher")
    if alg == "HMAC":
        return RegistryName(_join("HMAC", _hash_token(ex.get("hash"))), "HMAC", "mac")
    if alg in _HASHES:
        return RegistryName(_HASHES[alg], _HASHES[alg], "hash")
    m = re.fullmatch(r"SHA-(224|256|384|512(?:/224|/256)?)", alg)
    if m:
        return RegistryName(alg, "SHA-2", "hash")
    m = re.fullmatch(r"SHA3-(224|256|384|512)", alg)
    if m:
        return RegistryName(alg, "SHA-3", "hash")
    if alg == "ML-KEM":
        return RegistryName(_join("ML-KEM", asset.key_size if asset.key_size in (512, 768, 1024) else None), "ML-KEM",
                            "kem")  # fmt: skip
    if alg == "ML-DSA":
        return RegistryName(_join("ML-DSA", asset.key_size if asset.key_size in (44, 65, 87) else None), "ML-DSA",
                            "signature")  # fmt: skip
    if alg == "SLH-DSA":
        return RegistryName("SLH-DSA", "SLH-DSA", "signature", note="parameter set not reported")
    if alg == "DSA":
        return RegistryName(_join("DSA", asset.key_size), "DSA", "signature")
    if alg == "DH":
        return RegistryName("FFDH", "FFDH", "key-agree")
    return RegistryName(asset.display_algorithm, None, None, curve_id(asset.curve),
                        note=f"{alg or 'algorithm'} is not mapped to a registry family")  # fmt: skip


# X.509 signature algorithms, by the names cryptography gives them
_X509_SIG = re.compile(r"(sha1|sha224|sha256|sha384|sha512|sha3-\d+|md5|md2)WithRSAEncryption", re.I)
_X509_ECDSA = re.compile(r"ecdsa-with-(SHA\d+|SHA3-\d+)", re.I)


def signature_algorithm(name: str | None) -> RegistryName | None:
    """`sha256WithRSAEncryption` -> RSA-PKCS1-1.5-SHA-256 (RSASSA-PKCS1); `ecdsa-with-SHA384` -> ECDSA-SHA-384."""
    if not name:
        return None
    m = _X509_SIG.fullmatch(name)
    if m:
        h = m.group(1).upper()
        token = {"MD5": "MD5", "MD2": "MD2"}.get(h) or _hash_token(h)
        return RegistryName(_join("RSA-PKCS1-1.5", token), "RSASSA-PKCS1", "signature")
    m = _X509_ECDSA.fullmatch(name)
    if m:
        return RegistryName(_join("ECDSA", _hash_token(m.group(1))), "ECDSA", "signature")
    low = name.lower()
    if low in ("rsassa-pss", "rsassapss"):
        return RegistryName("RSA-PSS", "RSASSA-PSS", "signature")
    if low in ("ed25519", "ed448"):
        return RegistryName(name[:2].capitalize() + name[2:], "EdDSA", "signature")
    if low.startswith("dsa-with-"):
        return RegistryName(_join("DSA", _hash_token(low[9:])), "DSA", "signature")
    if low.startswith(("ml-dsa", "id-ml-dsa")):
        n = re.search(r"(44|65|87)", low)
        return RegistryName(_join("ML-DSA", n.group(1) if n else None), "ML-DSA", "signature")
    return RegistryName(name, None, "signature", note="signature algorithm not mapped to a registry family")
