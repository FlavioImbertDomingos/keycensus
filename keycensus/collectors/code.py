"""Collector: cryptography in source code. Hard-coded private keys, and which algorithms the code calls.

    - name: payments-api
      type: code
      paths: [/src/payments-api, /src/batch-jobs]
      exclude: ["docs/**"]               # globs on the path relative to each root, added to the defaults
      hardcoded_keys: true               # private keys and keystores committed to the tree
      api_usage: true                    # crypto API calls in Python, Java/Kotlin, Go, JS/TS, C#, C/C++
      skip_tests: false                  # tests often hold throwaway keys; they are flagged, not skipped
      max_file_bytes: 1000000
      keystore_passwords: [{password_env: TEST_KEYSTORE_PASSWORD}]

Hard-coded keys: any file in the tree, including private keys pasted into string literals
("-----BEGIN RSA PRIVATE KEY-----\\nMIIE..." with escaped newlines and string concatenation), OpenSSH
private keys, and committed keystores (.p12, .pfx, .jks ...). Each becomes a `key` asset with
`extra.hardcoded` and the file and line, and gets a `hardcoded-private-key` finding. Placeholders
that do not parse as a key are ignored. The key itself is never stored, only its algorithm, size
and public-key fingerprint, so the inventory does not become a second copy of the leak.

API usage: one `algorithm` asset per algorithm (and size, curve and mode) per root, with every call
site in `extra.occurrences` and in the CBOM as CycloneDX evidence occurrences. That is what a PQC
migration plan needs from code: where RSA and ECDH are used, where MD5, SHA-1, DES or ECB mode still
are. Detection is pattern-based on the standard APIs of each language; it does not follow variables
or wrapper libraries, and it reads the working tree, not git history (use gitleaks or trufflehog for
that).

A line containing `keycensus:ignore` (or the line before it) is skipped, for the MD5 that only
computes a cache key.
"""

from __future__ import annotations

import base64
import fnmatch
import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..model import KIND_KEY, CryptoAsset
from . import keyfiles
from .base import Collector, CollectorError
from .pem_files import keystore_passwords

log = logging.getLogger(__name__)

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "third_party", "dist", "build", "target", ".venv", "venv",
    "__pycache__", ".tox", "site-packages", ".mypy_cache", ".pytest_cache", ".idea", ".gradle", "bower_components",
}  # fmt: skip
LANGUAGES = {
    ".py": "python",
    ".java": "java", ".kt": "java", ".kts": "java", ".scala": "java", ".groovy": "java",
    ".go": "go",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".mts": "javascript", ".cts": "javascript",
    ".cs": "csharp",
    ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".cxx": "c", ".hpp": "c", ".hh": "c", ".m": "c",
}  # fmt: skip
KEYSTORE_FILES = (".p12", ".pfx", ".jks", ".jceks", ".keystore", ".bcfks")
# Plural examples/samples only: com/example is a Java package, not a demo folder.
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|testdata|test-data|fixtures?|examples|samples|mocks?)(/|$)"
                       r"|(_test\.go|Test\.java|Tests?\.cs|\.test\.[jt]sx?|\.spec\.[jt]sx?)$|(^|/)test_[^/]*\.py$")  # fmt: skip
COMMENT = re.compile(r"^\s*(#|//|\*|/\*|--)")
IGNORE = "keycensus:ignore"
PRIVATE_PEM = re.compile(r"-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----(.*?)-----END \1-----", re.DOTALL)
_CONCAT = re.compile(r"[\"'`]\s*[+,]?\s*(?:\\\s*)?\n?\s*[\"'`]")


# ----------------------------------------------------------------- algorithm naming
def hash_name(raw: str) -> str | None:
    s = raw.lower().replace("_", "-").replace(" ", "")
    s = re.sub(r"^(?:digest|hash)-?", "", s)
    if s in ("md5", "md-5"):
        return "MD5"
    if s in ("md4", "md2"):
        return s.upper()
    if s in ("sha1", "sha-1", "sha"):
        return "SHA-1"
    m = re.fullmatch(r"sha-?(224|256|384|512)(?:[-/]?(224|256))?", s)
    if m:
        return f"SHA-{m.group(1)}" + (f"/{m.group(2)}" if m.group(2) else "")
    m = re.fullmatch(r"sha3-?(224|256|384|512)", s)
    if m:
        return f"SHA3-{m.group(1)}"
    return None


_BLOCK = {"aes": "AES", "des": "DES", "desede": "3DES", "tripledes": "3DES", "des3": "3DES", "3des": "3DES",
          "rc4": "RC4", "arc4": "RC4", "arcfour": "RC4", "rc2": "RC2", "arc2": "RC2", "bf": "Blowfish",
          "blowfish": "Blowfish", "chacha20": "ChaCha20", "camellia": "Camellia", "idea": "IDEA",
          "rijndael": "AES", "seed": "SEED", "sm4": "SM4", "cast5": "CAST5"}  # fmt: skip
_MODES = {"ecb", "cbc", "gcm", "ctr", "cfb", "ofb", "ccm", "xts", "siv", "ocb", "poly1305", "wrap", "kw"}
STREAM = {"RC4", "ChaCha20"}


def cipher_spec(spec: str, java_default_ecb: bool = False) -> dict | None:
    """'aes-256-gcm', 'AES/CBC/PKCS5Padding', 'des_ede3_cbc', 'DESede' -> {algorithm, key_size, mode}."""
    tokens = [t for t in re.split(r"[-_/ ]+", spec.strip().lower()) if t]
    if not tokens:
        return None
    first = tokens[0]
    size = None
    m = re.fullmatch(r"(aes|camellia)(128|192|256)", first)
    if m:
        first, size = m.group(1), int(m.group(2))
    if first == "des" and len(tokens) > 1 and tokens[1] in ("ede3", "ede"):
        alg, rest = "3DES", tokens[2:]
    elif first == "rsa":
        return dict(_rsa_padding(spec), algorithm="RSA", key_size=None, mode=None, purpose="encrypt")
    elif first in _BLOCK:
        alg, rest = _BLOCK[first], tokens[1:]
    else:
        return None
    mode = None
    for t in rest:
        if t.isdigit() and t in ("128", "192", "256") and size is None:
            size = int(t)
        elif t in _MODES:
            mode = t.upper()
    if alg == "AES" and mode == "WRAP":
        mode = "KW"
    if mode is None and java_default_ecb and alg not in STREAM and len(rest) == 0:
        mode = "ECB"  # Cipher.getInstance("AES") is AES/ECB/PKCS5Padding in SunJCE
    if alg in ("DES", "3DES") and size is None:
        size = 56 if alg == "DES" else 168
    return {"algorithm": alg, "key_size": size, "mode": mode, "purpose": "encrypt"}


_CURVES = {"secp256r1": "P-256", "prime256v1": "P-256", "p256": "P-256", "p-256": "P-256", "nistp256": "P-256",
           "x9-62-prime256v1": "P-256", "secp384r1": "P-384", "p384": "P-384", "p-384": "P-384", "nistp384": "P-384",
           "secp521r1": "P-521", "p521": "P-521", "p-521": "P-521", "nistp521": "P-521", "secp224r1": "P-224",
           "secp256k1": "secp256k1"}  # fmt: skip


def curve_name(raw: str) -> str | None:
    return _CURVES.get(raw.lower().replace("_", "-"))


def _pk(alg: str, size: int | None = None, curve: str | None = None, purpose: str = "sign") -> dict:
    bits = {"P-256": 256, "P-384": 384, "P-521": 521, "P-224": 224, "secp256k1": 256}.get(curve or "")
    return {"algorithm": alg, "key_size": size or bits, "curve": curve, "mode": None, "purpose": purpose}


def _hash(raw: str) -> dict | None:
    h = hash_name(raw)
    return {"algorithm": h, "key_size": None, "mode": None, "purpose": "digest"} if h else None


def _size_ahead(lines: list[str], i: int, pattern: str, window: int = 6) -> int | None:
    text = "\n".join(lines[i : i + window])
    m = re.search(pattern, text)
    return int(m.group(1)) if m else None


def _hash_ahead(lines: list[str], i: int, pattern: str, window: int = 4) -> str | None:
    m = re.search(pattern, "\n".join(lines[i : i + window]))
    return hash_name(m.group(1)) if m else None


def _curve_ahead(lines: list[str], i: int, pattern: str, window: int = 6) -> str | None:
    m = re.search(pattern, "\n".join(lines[i : i + window]))
    return curve_name(m.group(1)) if m else None


def _java_kpg(alg: str, lines: list[str], i: int) -> dict | None:
    a = alg.upper()
    if a in ("RSA", "RSASSA-PSS"):
        return _pk("RSA", _size_ahead(lines, i, r"\.initialize\(\s*(\d{3,5})"))
    if a in ("EC", "ECDSA"):
        return _pk("EC", curve=_curve_ahead(lines, i, r"ECGenParameterSpec\(\s*\"([\w-]+)\"") or None)
    if a in ("ED25519", "EDDSA"):
        return _pk("Ed25519")
    if a in ("X25519", "XDH"):
        return _pk("X25519", purpose="derive")
    if a in ("DH", "DIFFIEHELLMAN"):
        return _pk("DH", _size_ahead(lines, i, r"\.initialize\(\s*(\d{3,5})"), purpose="derive")
    if a == "DSA":
        return _pk("DSA", _size_ahead(lines, i, r"\.initialize\(\s*(\d{3,5})"))
    m = re.fullmatch(r"ML-(KEM|DSA)(?:-(\d+))?", a)
    if m:
        return _pk(f"ML-{m.group(1)}", int(m.group(2)) if m.group(2) else None,
                   purpose="derive" if m.group(1) == "KEM" else "sign")  # fmt: skip
    return None


def _rsa_padding(spec: str) -> dict:
    """Padding scheme in a Java/OpenSSL transformation: RSA/ECB/OAEPWithSHA-256AndMGF1Padding, RSA/ECB/PKCS1Padding."""
    m = re.search(r"OAEP(?:With(SHA-?\d+|SHA3-\d+))?", spec, re.I)
    if m:
        h = hash_name(m.group(1)) if m.group(1) else None
        return {"scheme": "OAEP", "hash": h or ("SHA-1" if re.search(r"OAEPPadding", spec, re.I) else None)}
    if re.search(r"PKCS1", spec, re.I):
        return {"scheme": "PKCS1"}
    return {}


def _java_sig(spec: str) -> list[dict]:
    if spec.upper() == "RSASSA-PSS":
        return [dict(_pk("RSA"), scheme="PSS")]
    m = re.fullmatch(r"(\w+?)with(RSA|ECDSA|DSA|RSA/PSS|RSAandMGF1)", spec, re.I)
    if not m:
        return {"ed25519": [_pk("Ed25519")], "ml-dsa": [_pk("ML-DSA")]}.get(spec.lower(), [])
    kind = m.group(2).lower()
    pub = {"rsa": "RSA", "ecdsa": "EC", "dsa": "DSA"}.get(kind.split("/")[0].replace("andmgf1", ""), "RSA")
    h = _hash(m.group(1))
    key = _pk(pub)
    if h:
        key["hash"] = h["algorithm"]
    if pub == "RSA":
        key["scheme"] = "PSS" if ("pss" in kind or "mgf1" in kind) else "PKCS1"
    out = [key]
    if h and h["algorithm"] in ("MD5", "SHA-1", "MD2"):
        out.append(dict(h, purpose="sign"))
    return out


def _pycryptodome(alg: str, args: str) -> dict | None:
    mode = re.search(r"MODE_(\w+)", args)
    return cipher_spec(f"{alg}-{mode.group(1) if mode else ''}")


def _js_keypair(kind: str, lines: list[str], i: int) -> dict | None:
    k = kind.lower()
    if k in ("rsa", "rsa-pss"):
        return _pk("RSA", _size_ahead(lines, i, r"modulusLength\s*:\s*(\d{3,5})"))
    if k == "ec":
        return _pk("EC", curve=_curve_ahead(lines, i, r"namedCurve\s*:\s*['\"`]([\w-]+)"))
    return {"ed25519": _pk("Ed25519"), "ed448": _pk("Ed448"), "x25519": _pk("X25519", purpose="derive"),
            "x448": _pk("X448", purpose="derive"), "dsa": _pk("DSA"), "dh": _pk("DH", purpose="derive")}.get(k)  # fmt: skip


def _webcrypto(name: str, lines: list[str], i: int) -> dict | None:
    if not any("subtle" in ln for ln in lines[max(0, i - 4) : i + 1]):
        return None
    n = name.upper()
    if n.startswith("RSA"):
        key = _pk("RSA", _size_ahead(lines, i, r"modulusLength\s*:\s*(\d{3,5})"),
                  purpose="encrypt" if n == "RSA-OAEP" else "sign")  # fmt: skip
        key["scheme"] = {"RSA-OAEP": "OAEP", "RSA-PSS": "PSS", "RSASSA-PKCS1-V1_5": "PKCS1"}.get(n)
        hm = re.search(r"hash\s*:\s*['\"`](SHA-\d+)", "\n".join(lines[i : i + 6]))
        key["hash"] = hash_name(hm.group(1)) if hm else None
        return key
    if n in ("ECDSA", "ECDH"):
        return _pk("EC", curve=_curve_ahead(lines, i, r"namedCurve\s*:\s*['\"`]([\w-]+)"),
                   purpose="derive" if n == "ECDH" else "sign")  # fmt: skip
    if n.startswith("AES-"):
        return {"algorithm": "AES", "key_size": _size_ahead(lines, i, r"length\s*:\s*(128|192|256)"),
                "mode": n.split("-")[1], "purpose": "encrypt"}  # fmt: skip
    return None


# ----------------------------------------------------------------- patterns
Handler = Callable[[re.Match, list[str], int], "dict | list[dict] | None"]


@dataclass
class Pattern:
    api: str
    regex: re.Pattern
    handler: Handler


def P(api: str, rx: str, handler: Handler) -> Pattern:  # noqa: N802
    return Pattern(api, re.compile(rx), handler)


_PY_CURVES = {"SECP256R1": "P-256", "SECP384R1": "P-384", "SECP521R1": "P-521", "SECP256K1": "secp256k1",
              "SECP224R1": "P-224"}  # fmt: skip

PATTERNS: dict[str, list[Pattern]] = {
    "python": [
        P("hashlib", r"\bhashlib\.(md5|sha1|sha224|sha256|sha384|sha512|sha3_\d+)\s*\(", lambda m, L, i: _hash(m[1])),
        P("hashlib.new", r"\bhashlib\.new\(\s*['\"]([\w-]+)['\"]", lambda m, L, i: _hash(m[1])),
        P("cryptography hashes", r"\bhashes\.(MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3_\d+)\s*\(",
          lambda m, L, i: _hash(m[1])),
        P("cryptography Cipher", r"\balgorithms\.(TripleDES|ARC4|Blowfish|CAST5|IDEA|SEED|AES|AES128|AES256|ChaCha20|"
          r"Camellia|SM4)\s*\((?:[^()]|\([^()]*\))*\)(?:\s*,\s*modes\.(\w+))?",
          lambda m, L, i: cipher_spec(f"{m[1]}-{m[2] or ''}")),
        P("pycryptodome", r"\b(DES3|DES|ARC4|ARC2|Blowfish|AES|ChaCha20|CAST)\.new\s*\(([^)]*)",
          lambda m, L, i: _pycryptodome(m[1], m[2])),
        P("cryptography rsa", r"\brsa\.generate_private_key\(",
          lambda m, L, i: _pk("RSA", _size_ahead(L, i, r"key_size\s*=\s*(\d{3,5})", 4))),
        P("cryptography ec", r"\bec\.generate_private_key\(\s*(?:curve\s*=\s*)?ec\.(SECP\w+)",
          lambda m, L, i: _pk("EC", curve=_PY_CURVES.get(m[1]))),
        P("cryptography ecdh", r"\.exchange\(\s*ec\.ECDH\(\)", lambda m, L, i: _pk("EC", purpose="derive")),
        P("cryptography eddsa/x25519", r"\b(Ed25519|Ed448|X25519|X448)PrivateKey\.generate\(",
          lambda m, L, i: _pk(m[1], purpose="derive" if m[1].startswith("X") else "sign")),
        P("cryptography dsa", r"\bdsa\.generate_private_key\(",
          lambda m, L, i: _pk("DSA", _size_ahead(L, i, r"key_size\s*=\s*(\d{3,5})", 4))),
        P("pycryptodome RSA", r"\bRSA\.generate\(\s*(\d{3,5})", lambda m, L, i: _pk("RSA", int(m[1]))),
        P("cryptography OAEP", r"\bpadding\.OAEP\(",
          lambda m, L, i: dict(_pk("RSA", purpose="encrypt"), scheme="OAEP",
                               hash=_hash_ahead(L, i, r"algorithm\s*=\s*hashes\.(SHA\d+|SHA3_\d+)\("))),
        P("cryptography PSS", r"\bpadding\.PSS\(", lambda m, L, i: dict(_pk("RSA"), scheme="PSS")),
        P("pycryptodome ECC", r"\bECC\.generate\(\s*curve\s*=\s*['\"]([\w-]+)['\"]",
          lambda m, L, i: _pk("EC", curve=curve_name(m[1]))),
    ],
    "java": [
        P("Cipher.getInstance", r"\bCipher\.getInstance\(\s*\"([^\"]+)\"",
          lambda m, L, i: cipher_spec(m[1], java_default_ecb=True)),
        P("MessageDigest", r"\bMessageDigest\.getInstance\(\s*\"([^\"]+)\"", lambda m, L, i: _hash(m[1])),
        P("KeyPairGenerator", r"\bKeyPairGenerator\.getInstance\(\s*\"([^\"]+)\"",
          lambda m, L, i: _java_kpg(m[1], L, i)),
        P("KeyGenerator", r"\bKeyGenerator\.getInstance\(\s*\"(AES|DES|DESede|TripleDES|RC4|ARCFOUR|Blowfish|RC2)\"",
          lambda m, L, i: (lambda c: c and dict(c, key_size=_size_ahead(L, i, r"\.init\(\s*(\d{2,3})")
                                                or c["key_size"]))(cipher_spec(m[1]))),
        P("Signature", r"\bSignature\.getInstance\(\s*\"([^\"]+)\"", lambda m, L, i: _java_sig(m[1])),
        P("KeyAgreement", r"\bKeyAgreement\.getInstance\(\s*\"(ECDH|DH|X25519|XDH|DiffieHellman)\"",
          lambda m, L, i: _pk({"ECDH": "EC", "X25519": "X25519", "XDH": "X25519"}.get(m[1], "DH"), purpose="derive")),
        P("KEM", r"\bKEM\.getInstance\(\s*\"(ML-KEM(?:-\d+)?)\"", lambda m, L, i: _java_kpg(m[1], L, i)),
    ],
    "go": [
        P("crypto/md5", r"\bmd5\.(New|Sum)\b", lambda m, L, i: _hash("md5")),
        P("crypto/sha1", r"\bsha1\.(New|Sum)\b", lambda m, L, i: _hash("sha1")),
        P("crypto/sha256", r"\bsha256\.(New|Sum256|New224|Sum224)\b",
          lambda m, L, i: _hash("sha224" if "224" in m[1] else "sha256")),
        P("crypto/sha512", r"\bsha512\.(New|Sum512|New384|Sum384)\b",
          lambda m, L, i: _hash("sha384" if "384" in m[1] else "sha512")),
        P("crypto/des", r"\bdes\.(NewTripleDESCipher|NewCipher)\(",
          lambda m, L, i: cipher_spec("des-ede3" if "Triple" in m[1] else "des")),
        P("crypto/rc4", r"\brc4\.NewCipher\(", lambda m, L, i: cipher_spec("rc4")),
        P("crypto/rsa", r"\brsa\.GenerateKey\(\s*[\w.]+\s*,\s*(\d{3,5})", lambda m, L, i: _pk("RSA", int(m[1]))),
        P("crypto/ecdsa", r"\becdsa\.GenerateKey\(\s*elliptic\.(P\d+)\(\)", lambda m, L, i: _pk("EC", curve=curve_name(m[1]))),
        P("crypto/ecdh", r"\becdh\.(P256|P384|P521|X25519)\(\)\.GenerateKey",
          lambda m, L, i: _pk("X25519", purpose="derive") if m[1] == "X25519"
          else _pk("EC", curve=curve_name(m[1]), purpose="derive")),
        P("crypto/ed25519", r"\bed25519\.GenerateKey\(", lambda m, L, i: _pk("Ed25519")),
        P("crypto/rsa OAEP", r"\brsa\.(?:Encrypt|Decrypt)OAEP\(\s*(?:sha(\d+)\.New(\d*)\(\))?",
          lambda m, L, i: dict(_pk("RSA", purpose="encrypt"), scheme="OAEP",
                               hash=hash_name(f"sha{m[2] or m[1]}") if m[1] else None)),
        P("crypto/rsa PSS", r"\brsa\.(?:Sign|Verify)PSS\((?:[^)\n]*?\bcrypto\.(SHA\d+))?",
          lambda m, L, i: dict(_pk("RSA"), scheme="PSS", hash=hash_name(m[1]) if m[1] else None)),
        P("crypto/rsa PKCS1v15", r"\brsa\.(Sign|Verify|Encrypt|Decrypt)PKCS1v15\((?:[^)\n]*?\bcrypto\.(SHA\d+))?",
          lambda m, L, i: dict(_pk("RSA", purpose="sign" if m[1] in ("Sign", "Verify") else "encrypt"), scheme="PKCS1",
                               hash=hash_name(m[2]) if m[2] else None)),
        P("crypto/mlkem", r"\bmlkem\.GenerateKey(768|1024)\(", lambda m, L, i: _pk("ML-KEM", int(m[1]), purpose="derive")),
    ],
    "javascript": [
        P("crypto.createHash", r"\bcreateHash\(\s*['\"`]([\w-]+)['\"`]", lambda m, L, i: _hash(m[1])),
        P("crypto.createCipheriv", r"\bcreate(?:De)?[Cc]ipher(?:iv)?\(\s*['\"`]([\w-]+)['\"`]",
          lambda m, L, i: cipher_spec(m[1])),
        P("crypto.generateKeyPair", r"\bgenerateKeyPair(?:Sync)?\(\s*['\"`]([\w-]+)['\"`]",
          lambda m, L, i: _js_keypair(m[1], L, i)),
        P("WebCrypto", r"\bname\s*:\s*['\"`](RSA-OAEP|RSASSA-PKCS1-v1_5|RSA-PSS|ECDSA|ECDH|AES-CBC|AES-GCM|AES-CTR|AES-KW)"
          r"['\"`]", lambda m, L, i: _webcrypto(m[1], L, i)),
    ],
    "csharp": [
        P("System.Security.Cryptography hash", r"\b(MD5|SHA1|SHA256|SHA384|SHA512)\.(Create|HashData)\(",
          lambda m, L, i: _hash(m[1])),
        P("CryptoServiceProvider hash", r"\bnew\s+(MD5|SHA1|SHA256|SHA384|SHA512)(?:CryptoServiceProvider|Managed|Cng)\(",
          lambda m, L, i: _hash(m[1])),
        P("System.Security.Cryptography cipher", r"\b(DES|TripleDES|RC2|Aes|Rijndael)\.Create\(",
          lambda m, L, i: cipher_spec(m[1])),
        P("CryptoServiceProvider cipher", r"\bnew\s+(DES|TripleDES|RC2|Rijndael|Aes)(?:CryptoServiceProvider|Managed|Cng)\(",
          lambda m, L, i: cipher_spec(m[1])),
        P("RSA", r"\b(?:new\s+RSACryptoServiceProvider|RSA\.Create)\(\s*(\d{3,5})?\s*\)",
          lambda m, L, i: _pk("RSA", int(m[1]) if m[1] else None)),
        P("ECDsa", r"\bECDsa\.Create\(\s*(?:ECCurve\.NamedCurves\.(nist\w+))?",
          lambda m, L, i: _pk("EC", curve=curve_name(m[1]) if m[1] else None)),
        P("ECDiffieHellman", r"\bECDiffieHellman\.Create\(", lambda m, L, i: _pk("EC", purpose="derive")),
        P("RSAEncryptionPadding", r"\bRSAEncryptionPadding\.(Oaep(SHA\d+|SHA3_\d+)?|Pkcs1)\b",
          lambda m, L, i: dict(_pk("RSA", purpose="encrypt"), scheme="PKCS1" if m[1] == "Pkcs1" else "OAEP",
                               hash=hash_name(m[2]) if m[2] else ("SHA-1" if m[1] == "Oaep" else None))),
        P("RSASignaturePadding", r"\bRSASignaturePadding\.(Pss|Pkcs1)\b",
          lambda m, L, i: dict(_pk("RSA"), scheme="PSS" if m[1] == "Pss" else "PKCS1")),
    ],
    "c": [
        P("OpenSSL EVP digest", r"\bEVP_(md5|sha1|sha224|sha256|sha384|sha512|sha3_\d+)\s*\(", lambda m, L, i: _hash(m[1])),
        P("OpenSSL digest", r"\b(MD5|SHA1)(?:_Init|_Final)?\s*\(", lambda m, L, i: _hash(m[1])),
        P("OpenSSL EVP cipher", r"\bEVP_((?:aes|des|bf|rc4|rc2|chacha20|camellia|idea|cast5|sm4)\w*)\s*\(",
          lambda m, L, i: cipher_spec(m[1])),
        P("OpenSSL RSA keygen", r"\b(?:RSA_generate_key(?:_ex)?\(\s*(?:\w+\s*,\s*)?|EVP_PKEY_CTX_set_rsa_keygen_bits\(\s*\w+\s*,\s*)"
          r"(\d{3,5})", lambda m, L, i: _pk("RSA", int(m[1]))),
        P("OpenSSL EC curve", r"\bNID_(X9_62_prime256v1|secp384r1|secp521r1|secp256k1)\b",
          lambda m, L, i: _pk("EC", curve=curve_name(m[1]))),
        P("OpenSSL keygen by name", r"\bEVP_PKEY_(?:CTX_new_from_name|Q_keygen)\([^\"]*\"(RSA|EC|ED25519|X25519|DH|"
          r"ML-KEM-\d+|ML-DSA-\d+)\"", lambda m, L, i: _java_kpg(m[1], L, i)),
    ],
}  # fmt: skip
STANDALONE_MODE = {
    "csharp": re.compile(r"\bCipherMode\.(ECB|CBC|CFB|CTS|OFB)\b"),
    "python": re.compile(r"\bmodes\.(ECB)\s*\("),
}


# ----------------------------------------------------------------- data
@dataclass
class Hit:
    algorithm: str
    key_size: int | None
    curve: str | None
    mode: str | None
    purpose: str
    file: str
    line: int
    api: str
    language: str
    test: bool
    scheme: str | None = None  # RSA padding: OAEP, PSS, PKCS1
    hash: str | None = None  # the hash an RSA/ECDSA signature or OAEP uses


@dataclass
class _Group:
    hits: list[Hit] = field(default_factory=list)


def _norm(d: dict, api: str, rel: str, line: int, lang: str, test: bool) -> Hit:
    return Hit(d["algorithm"], d.get("key_size"), d.get("curve"), d.get("mode"), d.get("purpose", "encrypt"), rel,
               line, api, lang, test, d.get("scheme"), d.get("hash"))  # fmt: skip


def scan_api(text: str, lang: str, rel: str, test: bool) -> list[Hit]:
    lines = text.splitlines()
    hits: list[Hit] = []
    for i, line in enumerate(lines):
        if IGNORE in line or (i and IGNORE in lines[i - 1]) or COMMENT.match(line):
            continue
        for p in PATTERNS.get(lang, []):
            for m in p.regex.finditer(line):
                try:
                    res = p.handler(m, lines, i)
                except (ValueError, TypeError, IndexError):
                    res = None
                for d in [res] if isinstance(res, dict) else (res or []):
                    if d and d.get("algorithm"):
                        hits.append(_norm(d, p.api, rel, i + 1, lang, test))
        rx = STANDALONE_MODE.get(lang)
        if rx and (m := rx.search(line)):
            # `aes.Mode = CipherMode.ECB;` -- attach to the last block cipher created above, in this file
            prior = [h for h in hits if h.line > i + 1 - 30 and h.algorithm not in STREAM and h.purpose == "encrypt"
                     and h.algorithm in set(_BLOCK.values())]  # fmt: skip
            if prior and prior[-1].mode is None:
                prior[-1].mode = m[1].upper()
    return hits


def normalise_pem_literal(label: str, body: str) -> bytes | None:
    """A PEM private key pasted into source: escaped newlines, quotes, concatenation, indentation."""
    body = body.replace("\\r", "").replace("\\n", "\n")
    body = _CONCAT.sub("\n", body)
    headers, b64 = [], []
    for ln in body.splitlines():
        ln = ln.strip().strip("\"'`,;\\").strip()  # never strip "+": it is a base64 character
        if not ln:
            continue
        if ":" in ln and not b64:
            headers.append(ln)
            continue
        b64.append(re.sub(r"[^A-Za-z0-9+/=]", "", ln))
    data = "".join(b64)
    if len(data) < 64:
        return None
    try:
        base64.b64decode(data + "=" * (-len(data) % 4), validate=False)
    except ValueError:
        return None
    wrapped = "\n".join(data[i : i + 64] for i in range(0, len(data), 64))
    head = ("\n".join(headers) + "\n\n") if headers else ""
    return f"-----BEGIN {label}-----\n{head}{wrapped}\n-----END {label}-----\n".encode()


# ----------------------------------------------------------------- collector
class CodeCollector(Collector):
    type_name = "code"

    def collect(self) -> list[CryptoAsset]:
        paths = self.opt.get("paths") or []
        if isinstance(paths, str):
            paths = [paths]
        if not paths:
            raise CollectorError(f"[{self.name}] code collector needs 'paths'")
        self.max_bytes = int(self.opt.get("max_file_bytes", 1_000_000))
        self.exclude = [str(g) for g in self.opt.get("exclude") or []]
        self.skip_tests = bool(self.opt.get("skip_tests", False))
        self.passwords = keystore_passwords(self.opt, self.name)
        do_keys, do_api = bool(self.opt.get("hardcoded_keys", True)), bool(self.opt.get("api_usage", True))
        assets: list[CryptoAsset] = []
        for root in paths:
            root = Path(root).expanduser().resolve()
            if not root.is_dir():
                raise CollectorError(f"[{self.name}] {root} is not a directory")
            hits: list[Hit] = []
            for path, rel in self._walk(root):
                test = bool(TEST_PATH.search(rel))
                if test and self.skip_tests:
                    continue
                try:
                    data = path.read_bytes()
                except OSError as exc:
                    log.info("[%s] cannot read %s: %s", self.name, path, exc)
                    continue
                if do_keys:
                    assets += self._hardcoded(root, path, rel, data, test)
                lang = LANGUAGES.get(path.suffix.lower())
                if do_api and lang and b"\x00" not in data[:8192]:
                    hits += scan_api(data.decode("utf-8", "replace"), lang, rel, test)
            assets += self._group(root, hits)
        return assets

    def _walk(self, root: Path):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in DEFAULT_EXCLUDE_DIRS)
            for fn in sorted(filenames):
                p = Path(dirpath) / fn
                rel = p.relative_to(root).as_posix()
                if any(fnmatch.fnmatch(rel, g) for g in self.exclude):
                    continue
                try:
                    if p.is_symlink() or not p.is_file() or p.stat().st_size > self.max_bytes:
                        continue
                except OSError:
                    continue
                yield p, rel

    # ---------------------------------------------------- hard-coded keys
    def _hardcoded(self, root: Path, path: Path, rel: str, data: bytes, test: bool) -> list[CryptoAsset]:
        found: list[tuple[keyfiles.Entry, int]] = []
        if path.suffix.lower() in KEYSTORE_FILES or (b"\x00" in data[:8192] and keyfiles.looks_like_key_material(data)):
            try:
                found += [(e, 1) for e in keyfiles.parse(data, path.name, self.passwords)]
            except (keyfiles.KeyfileError, ValueError):
                pass
        elif b"PRIVATE KEY-----" in data:
            text = data.decode("utf-8", "replace")
            for m in PRIVATE_PEM.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                line_start = text.rfind("\n", 0, m.start()) + 1
                prev_start = text.rfind("\n", 0, max(line_start - 1, 0)) + 1
                if IGNORE in text[prev_start : m.start()]:  # on this line or the one before
                    continue
                pem = normalise_pem_literal(m[1], m[2])
                if pem is None:
                    continue
                try:
                    entries = keyfiles.parse(pem, path.name, self.passwords)
                except (keyfiles.KeyfileError, ValueError):
                    continue
                found += [(e, line) for e in entries]
        out: list[CryptoAsset] = []
        for e, line in found:
            if e.fields.get("kind") != KIND_KEY or e.fields.get("key_type") not in ("private-key", "secret-key"):
                continue  # certificates and public keys in a repo are not secrets
            f = dict(e.fields)
            f["extra"] = {**(f.get("extra") or {}), "hardcoded": True, "file": rel, "line": line, "repository": str(root),
                          "test_path": test}  # fmt: skip
            if e.weak_protection:
                f["extra"]["keystore_weak_protection"] = e.weak_protection
            f["name"] = f"{rel}:{line}" if not f.get("name") or f["name"] == path.name else f"{rel}:{f['name']}"
            out.append(self.asset(native_id=f"code:{root}:{rel}:{line}#{e.sub}", location=f"{root}/{rel}:{line}",
                                  **f))  # fmt: skip
        return out

    # ---------------------------------------------------------- grouping
    def _group(self, root: Path, hits: list[Hit]) -> list[CryptoAsset]:
        groups: dict[tuple, list[Hit]] = {}
        for h in hits:
            groups.setdefault((h.algorithm, h.key_size, h.curve, h.mode, h.scheme, h.hash), []).append(h)
        out = []
        for (alg, size, curve, mode, scheme, hsh), hs in sorted(groups.items(), key=lambda kv: str(kv[0])):
            label = alg + (f"-{curve}" if curve else f"-{size}" if size else "") + (f"/{mode}" if mode else "")
            if scheme or hsh:
                label += f" ({', '.join(x for x in (scheme, hsh) if x)})"
            purposes = sorted({h.purpose for h in hs})
            occ = [{"file": h.file, "line": h.line, "api": h.api, "language": h.language, **({"test": True} if h.test
                    else {})} for h in hs[:200]]  # fmt: skip
            out.append(self.asset(
                kind="algorithm", name=f"{label} in {root.name}", native_id=f"code:{root}:{label}",
                algorithm=alg, key_size=size, curve=curve, key_type="algorithm",
                purposes=[{"digest": "digest", "derive": "derive"}.get(p, p) for p in purposes],
                location=str(root), state="active",
                extra={"mode": mode, "scheme": scheme, "hash": hsh, "occurrences": occ, "occurrence_count": len(hs),
                       "files": len({h.file for h in hs}), "languages": sorted({h.language for h in hs}),
                       "only_in_tests": all(h.test for h in hs), "repository": str(root)},
            ))  # fmt: skip
        return out
