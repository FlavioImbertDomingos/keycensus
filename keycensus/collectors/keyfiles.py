"""Read cryptographic material out of bytes, whatever the container.

Used by the `pem` collector (files on disk), the `kubernetes` collector (secret values) and the
`code` collector (keys committed to a repository). Formats:

* PEM: certificates, PKCS#1/PKCS#8/SEC1 private keys (encrypted ones are reported, not opened),
  public keys, and `OPENSSH PRIVATE KEY` blocks.
* DER: a certificate, a PKCS#8 private key or a SubjectPublicKeyInfo.
* PKCS#12 (.p12, .pfx): the protection algorithms are read without a password; contents are read
  with the configured passwords, then with a few well-known ones (empty, changeit, ...). A keystore
  that opens with a well-known password is reported as such.
* JKS and JCEKS (Java keystores): certificate chains are stored unencrypted, so every entry is read
  without a password. The integrity digest is checked against the configured and well-known passwords.
* OpenSSH: private keys (the public half and the cipher are readable without the passphrase),
  public keys, authorized_keys, known_hosts and OpenSSH certificates.

Nothing here keeps key material: each entry is a description (algorithm, size, fingerprint,
dates, protection) that becomes a CryptoAsset.
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from ..model import KIND_CERTIFICATE, KIND_KEY, STATE_ACTIVE, STATE_DEACTIVATED, STATE_UNKNOWN, utcnow
from .x509util import certificate_fields, describe_public_key

WELL_KNOWN_PASSWORDS = ["", "changeit", "changeme", "password", "secret", "123456"]
PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL)
SSH_KEY_TYPES = (
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ssh-ed448", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
)  # fmt: skip
SSH_LINE = re.compile(
    r"(?:^|\s)((?:" + "|".join(re.escape(t) for t in SSH_KEY_TYPES) + r")(?:-cert-v01@openssh\.com)?)"
    r"\s+(AAAA[0-9A-Za-z+/]+={0,3})(?:\s+(\S.*))?$"
)
JKS_MAGIC, JCEKS_MAGIC = 0xFEEDFEED, 0xCECECECE
_OID_NAMES = {
    "1.3.6.1.4.1.42.2.17.1.1": "JKS proprietary key protection (SHA-1 keystream)",
    "1.3.6.1.4.1.42.2.19.1": "PBEWithMD5AndTripleDES",
}


@dataclass
class Entry:
    """One thing found: kwargs for Collector.asset() minus source and location, plus a sub-id."""

    sub: str  # unique within the container (alias, fingerprint, line number)
    fields: dict[str, Any]
    weak_protection: list[str] = field(default_factory=list)


class KeyfileError(ValueError):
    pass


# ----------------------------------------------------------------- helpers
def _key_fields(key, key_type: str, name: str, **extra) -> dict[str, Any]:
    alg, size, curve = describe_public_key(key)
    private = key_type == "private-key"
    return {
        "kind": KIND_KEY,
        "name": name,
        "algorithm": alg,
        "key_size": size,
        "curve": curve,
        "key_type": key_type,
        "purposes": ["sign", "decrypt"] if private else ["verify", "encrypt"],
        "state": STATE_UNKNOWN,
        "exportable": True if private else None,
        "hardware_backed": False,
        "extra": {k: v for k, v in extra.items() if v is not None},
    }


def _spki_fingerprint(pub) -> str:
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def _cert_entry(cert: x509.Certificate, sub_prefix: str = "", **extra) -> Entry:
    f = certificate_fields(cert)
    f["extra"].update({k: v for k, v in extra.items() if v is not None})
    return Entry(f"{sub_prefix}{f['fingerprint_sha256'][:16]}", f)


def _purposes_from_cert(cert: x509.Certificate | None) -> list[str] | None:
    if cert is None:
        return None
    p = certificate_fields(cert)["purposes"]
    return sorted(set(p) | ({"decrypt"} if "encrypt" in p else set()))


# --------------------------------------------------------------------- PEM
def _pem_entries(data: bytes, name: str, passwords: list[str]) -> list[Entry]:
    out: list[Entry] = []
    for i, m in enumerate(PEM_BLOCK.finditer(data)):
        label, block = m.group(1).decode(), m.group(0)
        try:
            out += _pem_block(label, block, name, i, passwords)
        except (ValueError, TypeError, KeyfileError, struct.error, IndexError):
            continue
    return out


def _pem_block(label: str, block: bytes, name: str, i: int, passwords: list[str]) -> list[Entry]:
    if label in ("CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE"):
        return [_cert_entry(x509.load_pem_x509_certificate(block.replace(b"TRUSTED ", b"").replace(b"X509 ", b"")))]
    if label == "OPENSSH PRIVATE KEY":
        body = base64.b64decode(b"".join(block.splitlines()[1:-1]))
        return [openssh_private(body, name)]
    if "PRIVATE KEY" in label:
        encrypted = "ENCRYPTED" in label or b"Proc-Type: 4,ENCRYPTED" in block
        if encrypted:
            for pw in passwords:
                try:
                    key = serialization.load_pem_private_key(block, password=pw.encode() or None)
                except (ValueError, TypeError):
                    continue
                f = _key_fields(key, "private-key", name, encrypted_pem=True)
                return [Entry(f"key{i}:{_spki_fingerprint(key.public_key())[:16]}", f,
                              ["opens with a well-known password"] if pw in WELL_KNOWN_PASSWORDS else [])]  # fmt: skip
            alg = {"RSA": "RSA", "EC": "EC", "DSA": "DSA"}.get(label.split()[0], "unknown")
            return [Entry(f"key{i}", {"kind": KIND_KEY, "name": name, "algorithm": alg, "key_type": "private-key",
                                      "purposes": ["sign", "decrypt"], "exportable": True, "hardware_backed": False,
                                      "extra": {"encrypted_pem": True}})]  # fmt: skip
        key = serialization.load_pem_private_key(block, password=None)
        return [Entry(f"key{i}:{_spki_fingerprint(key.public_key())[:16]}",
                      _key_fields(key, "private-key", name, encrypted_pem=False))]  # fmt: skip
    if "PUBLIC KEY" in label:
        if label == "SSH2 PUBLIC KEY":
            return []
        key = serialization.load_pem_public_key(block)
        return [Entry(f"pub{i}:{_spki_fingerprint(key)[:16]}", _key_fields(key, "public-key", name))]
    return []


# --------------------------------------------------------------------- DER
def _der_entries(data: bytes, name: str) -> list[Entry]:
    for loader, kind in (
        (x509.load_der_x509_certificate, "cert"),
        (lambda d: serialization.load_der_private_key(d, password=None), "private-key"),
        (serialization.load_der_public_key, "public-key"),
    ):
        try:
            obj = loader(data)
        except (ValueError, TypeError):
            continue
        if kind == "cert":
            return [_cert_entry(obj)]
        pub = obj.public_key() if kind == "private-key" else obj
        return [Entry(f"{kind}:{_spki_fingerprint(pub)[:16]}", _key_fields(obj, kind, name))]
    return []


# ----------------------------------------------------------------- PKCS#12
def looks_like_pkcs12(data: bytes) -> bool:
    return len(data) > 32 and data[0] == 0x30 and b"\x02\x01\x03" in data[:8]


def pkcs12_protection(data: bytes) -> dict[str, Any]:
    """MAC and encryption algorithms of a PFX, readable without the password."""
    from asn1crypto import pkcs12 as a12  # noqa: PLC0415

    pfx = a12.Pfx.load(data)
    info: dict[str, Any] = {"mac": None, "mac_iterations": None, "ciphers": []}
    mac = pfx["mac_data"]
    if mac.native is not None:
        info["mac"] = mac["mac"]["digest_algorithm"]["algorithm"].native
        info["mac_iterations"] = mac["iterations"].native
    auth = pfx["auth_safe"]
    if auth["content_type"].native != "data":
        return info  # public-key integrity mode: rare
    safe = a12.AuthenticatedSafe.load(auth["content"].native)
    for ci in safe:
        if ci["content_type"].native == "encrypted_data":
            alg = ci["content"]["encrypted_content_info"]["content_encryption_algorithm"]
            info["ciphers"].append(_enc_name(alg))
        elif ci["content_type"].native == "data":
            for bag in a12.SafeContents.load(ci["content"].native):
                if bag["bag_id"].native == "pkcs8_shrouded_key_bag":
                    info["ciphers"].append(_enc_name(bag["bag_value"]["encryption_algorithm"]))
    return info


def _enc_name(alg) -> str:
    try:
        cipher = alg.encryption_cipher
        bits = alg.key_length * 8
        return f"{cipher}-{bits}" if cipher != "tripledes" else "3DES"
    except (ValueError, KeyError, AttributeError, NotImplementedError):
        return alg["algorithm"].dotted


def _pkcs12_weakness(info: dict[str, Any]) -> list[str]:
    out = []
    for c in info["ciphers"]:
        if c.startswith(("rc2", "rc4", "des-")) or c == "3DES":
            out.append(f"encrypted with {c} (legacy PKCS#12)")
    if info["mac"] in ("md5", "sha1"):
        out.append(f"integrity MAC uses {info['mac'].upper()}")
    if info["mac_iterations"] is not None and info["mac_iterations"] < 1000:
        out.append(f"MAC key derived with only {info['mac_iterations']} iterations")
    return sorted(set(out))


def pkcs12_entries(data: bytes, name: str, passwords: list[str]) -> list[Entry]:
    try:
        info = pkcs12_protection(data)
    except (ValueError, TypeError, KeyError) as exc:
        raise KeyfileError(f"not a PKCS#12 file: {exc}") from exc
    weak = _pkcs12_weakness(info)
    protection = {"keystore": "PKCS12", "mac": info["mac"], "ciphers": sorted(set(info["ciphers"]))}
    for pw in passwords:
        try:
            p12 = pkcs12.load_pkcs12(data, pw.encode())
        except (ValueError, TypeError):
            continue
        reasons = list(weak)
        if pw in WELL_KNOWN_PASSWORDS:
            reasons.append("no password" if pw == "" else "opens with a well-known password")
        out: list[Entry] = []
        leaf = p12.cert.certificate if p12.cert else None
        if p12.key is not None:
            alias = (p12.cert.friendly_name or b"").decode("utf-8", "replace") if p12.cert else ""
            f = _key_fields(p12.key, "private-key", f"{name}:{alias}" if alias else name, **protection, alias=alias)
            f["purposes"] = _purposes_from_cert(leaf) or f["purposes"]
            out.append(Entry(f"key:{_spki_fingerprint(p12.key.public_key())[:16]}", f, reasons))
        for c in ([p12.cert] if p12.cert else []) + list(p12.additional_certs):
            alias = (c.friendly_name or b"").decode("utf-8", "replace") or None
            out.append(_cert_entry(c.certificate, "cert:", keystore="PKCS12", alias=alias))
        return out
    # Locked: report that it exists and how it is protected.
    return [Entry("locked", {"kind": KIND_KEY, "name": name, "key_type": "private-key", "purposes": ["sign", "decrypt"],
                             "exportable": True, "hardware_backed": False,
                             "extra": {**protection, "locked": True,
                                       "note": "password unknown: add it to keystore_passwords to read the entries"}},
                  weak)]  # fmt: skip


# ---------------------------------------------------------------- JKS/JCEKS
class _Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.d, self.p = data, pos

    def take(self, n: int) -> bytes:
        if self.p + n > len(self.d):
            raise KeyfileError("truncated")
        b = self.d[self.p : self.p + n]
        self.p += n
        return b

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def utf(self) -> str:
        return self.take(self.u16()).decode("utf-8", "replace")


def _skip_java_object(r: _Reader) -> dict[str, Any]:
    """Walk one Java-serialized object (a JCEKS SealedObject) far enough to find where it ends.
    Returns the String fields seen (sealAlg, paramsAlg)."""
    if r.take(4) != b"\xac\xed\x00\x05":
        raise KeyfileError("JCEKS secret entry is not a serialized Java object")
    strings: list[str] = []
    handles: list[Any] = []

    def content():
        tc = r.u8()
        if tc == 0x70:  # TC_NULL
            return None
        if tc == 0x71:  # TC_REFERENCE
            r.u32()
            return None
        if tc == 0x74:  # TC_STRING
            s = r.utf()
            handles.append(s)
            strings.append(s)
            return s
        if tc == 0x72:  # TC_CLASSDESC
            return classdesc(tc)
        if tc == 0x75:  # TC_ARRAY
            desc = content()
            handles.append("array")
            n = r.u32()
            elem = (desc or {}).get("name", "[B")[1:2]
            size = {"B": 1, "Z": 1, "C": 2, "S": 2, "I": 4, "F": 4, "J": 8, "D": 8}.get(elem)
            if size is None:
                for _ in range(n):
                    content()
            else:
                r.take(n * size)
            return None
        if tc == 0x73:  # TC_OBJECT
            desc = content()
            handles.append("object")
            chain = []
            d = desc
            while d:
                chain.append(d)
                d = d.get("super")
            for d in reversed(chain):
                for ftype, _fname in d["fields"]:
                    if ftype in "BZ":
                        r.take(1)
                    elif ftype in "CS":
                        r.take(2)
                    elif ftype in "IF":
                        r.take(4)
                    elif ftype in "JD":
                        r.take(8)
                    else:
                        content()
                if d["flags"] & 0x01:  # SC_WRITE_METHOD: block data until TC_ENDBLOCKDATA
                    annotations()
            return None
        if tc == 0x77:  # TC_BLOCKDATA
            r.take(r.u8())
            return None
        raise KeyfileError(f"unsupported Java serialization tag 0x{tc:02x}")

    def classdesc(_tc):
        name = r.utf()
        r.take(8)  # serialVersionUID
        handles.append(name)
        flags = r.u8()
        fields = []
        for _ in range(r.u16()):
            ftype = chr(r.u8())
            fname = r.utf()
            if ftype in "[L":
                content()  # class name string
            fields.append((ftype, fname))
        annotations()
        sup = content()
        return {"name": name, "flags": flags, "fields": fields, "super": sup}

    def annotations():
        while True:
            if r.d[r.p] == 0x78:  # TC_ENDBLOCKDATA
                r.p += 1
                return
            content()

    content()
    return {"strings": strings}


def jks_entries(data: bytes, name: str, passwords: list[str]) -> list[Entry]:
    r = _Reader(data)
    magic = r.u32()
    if magic not in (JKS_MAGIC, JCEKS_MAGIC):
        raise KeyfileError("not a JKS/JCEKS keystore")
    store = "JKS" if magic == JKS_MAGIC else "JCEKS"
    version = r.u32()
    count = r.u32()
    weak: list[str] = [f"{store} is a proprietary format; Java has defaulted to PKCS#12 since Java 9"]
    opened_with = None
    for pw in passwords:
        if hashlib.sha1(pw.encode("utf-16-be") + b"Mighty Aphrodite" + data[:-20]).digest() == data[-20:]:  # noqa: S324
            opened_with = pw
            break
    if opened_with is not None and opened_with in WELL_KNOWN_PASSWORDS:
        weak.append("no password" if opened_with == "" else "opens with a well-known password")
    out: list[Entry] = []
    for _ in range(count):
        tag = r.u32()
        alias = r.utf()
        created = datetime.fromtimestamp(r.u64() / 1000, UTC)
        base = {"keystore": store, "alias": alias}
        if tag == 1:
            enc = r.take(r.u32())
            protection = _jks_key_protection(enc)
            chain = []
            for _c in range(r.u32()):
                if version == 2:
                    r.utf()
                chain.append(x509.load_der_x509_certificate(r.take(r.u32())))
            reasons = list(weak) + ([protection] if protection in _OID_NAMES.values() else [])
            if chain:
                pub = chain[0].public_key()
                f = _key_fields(pub, "private-key", f"{name}:{alias}", **base, key_protection=protection)
                f["purposes"] = _purposes_from_cert(chain[0]) or f["purposes"]
            else:
                f = {"kind": KIND_KEY, "name": f"{name}:{alias}", "key_type": "private-key", "hardware_backed": False,
                     "purposes": ["sign", "decrypt"], "extra": {**base, "key_protection": protection}}  # fmt: skip
            f["created"] = created
            f["exportable"] = True
            out.append(Entry(f"{alias}:key", f, reasons))
            for i, c in enumerate(chain):
                out.append(_cert_entry(c, f"{alias}:chain{i}:", **base))
        elif tag == 2:
            if version == 2:
                r.utf()
            out.append(_cert_entry(x509.load_der_x509_certificate(r.take(r.u32())), f"{alias}:trusted:", **base,
                                   trusted_entry=True))  # fmt: skip
        elif tag == 3 and store == "JCEKS":
            sealed = _skip_java_object(r)
            seal_alg = next((s for s in sealed["strings"] if s.startswith("PBE")), None)
            reasons = list(weak) + ([f"secret key sealed with {seal_alg}"] if seal_alg and "MD5" in seal_alg else [])
            out.append(Entry(f"{alias}:secret", {
                "kind": KIND_KEY, "name": f"{name}:{alias}", "key_type": "secret-key", "created": created,
                "purposes": ["encrypt", "decrypt"], "exportable": True, "hardware_backed": False,
                "extra": {**base, "seal_algorithm": seal_alg,
                          "note": "JCEKS hides the secret key's algorithm inside the sealed entry"}},
                reasons))  # fmt: skip
        else:
            raise KeyfileError(f"unknown {store} entry tag {tag}")
    if opened_with is None:
        for e in out:
            e.fields.setdefault("extra", {})["integrity_password_unknown"] = True
    return out


def _jks_key_protection(enc: bytes) -> str:
    try:
        from asn1crypto.keys import EncryptedPrivateKeyInfo  # noqa: PLC0415

        oid = EncryptedPrivateKeyInfo.load(enc)["encryption_algorithm"]["algorithm"].dotted
    except (ValueError, KeyError):
        return "unknown"
    return _OID_NAMES.get(oid, oid)


# ----------------------------------------------------------------- OpenSSH
def _ssh_string(r: _Reader) -> bytes:
    return r.take(r.u32())


def _ssh_blob_key(blob: bytes):
    """(cryptography public key | None, key type, extra) for an SSH wire-format public key blob."""
    r = _Reader(blob)
    ktype = _ssh_string(r).decode()
    if ktype.startswith("sk-"):
        alg = "Ed25519" if "ed25519" in ktype else "EC"
        return None, ktype, {"algorithm": alg, "key_size": 256, "curve": "Ed25519" if alg == "Ed25519" else "P-256",
                             "hardware_backed": True}  # fmt: skip
    key = serialization.load_ssh_public_key(f"{ktype} {base64.b64encode(blob).decode()}".encode())
    return key, ktype, {}


def ssh_fingerprint(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _ssh_key_fields(blob: bytes, key_type: str, name: str, **extra) -> dict[str, Any]:
    key, ktype, over = _ssh_blob_key(blob)
    if key is not None:
        f = _key_fields(key, key_type, name)
    else:
        f = {"kind": KIND_KEY, "name": name, "key_type": key_type, "state": STATE_UNKNOWN,
             "purposes": ["sign"] if key_type == "private-key" else ["verify"], "extra": {}}  # fmt: skip
    f.update(over)
    f["purposes"] = ["sign"] if key_type == "private-key" else ["verify"]
    if over.get("hardware_backed"):
        f["exportable"] = False
    f["extra"].update({"ssh_key_type": ktype, "ssh_fingerprint": ssh_fingerprint(blob)}, **extra)
    return f


def openssh_private(body: bytes, name: str) -> Entry:
    r = _Reader(body)
    if r.take(15) != b"openssh-key-v1\x00":
        raise KeyfileError("not an openssh-key-v1 private key")
    cipher = _ssh_string(r).decode()
    kdf = _ssh_string(r).decode()
    kdfopts = _ssh_string(r)
    rounds = None
    if kdf == "bcrypt" and kdfopts:
        kr = _Reader(kdfopts)
        _ssh_string(kr)
        rounds = kr.u32()
    if r.u32() < 1:
        raise KeyfileError("no keys in OpenSSH private key")
    blob = _ssh_string(r)
    f = _ssh_key_fields(blob, "private-key", name, ssh_cipher=cipher, passphrase_protected=cipher != "none",
                        bcrypt_rounds=rounds, ssh_role=ssh_role_for(name))  # fmt: skip
    if not f.get("hardware_backed"):
        f["exportable"] = True
        f["hardware_backed"] = False
    return Entry(f"sshkey:{f['extra']['ssh_fingerprint']}", f)


def _ssh_cert_entry(line: str, name: str, role: str | None) -> Entry:
    cert = serialization.load_ssh_public_identity(line.encode())
    pub = cert.public_key()
    alg, size, curve = describe_public_key(pub)
    forever = 0xFFFFFFFFFFFFFFFF
    va, vb = cert.valid_after, cert.valid_before
    expires = None if vb >= forever else datetime.fromtimestamp(vb, UTC)
    ca = cert.signature_key()
    ca_blob = ca.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).split()[1]
    principals = [p.decode() for p in cert.valid_principals]
    ctype = "host" if cert.type == serialization.SSHCertificateType.HOST else "user"
    blob = base64.b64decode(line.split()[1])
    return Entry(f"sshcert:{ssh_fingerprint(blob)}", {
        "kind": KIND_CERTIFICATE, "name": cert.key_id.decode("utf-8", "replace") or name,
        "algorithm": alg, "key_size": size, "curve": curve, "key_type": "public-key", "purposes": ["verify"],
        "created": datetime.fromtimestamp(va, UTC) if va else None, "expires": expires,
        "state": STATE_ACTIVE if expires is None or expires > utcnow() else STATE_DEACTIVATED,
        "subject": f"ssh-{ctype}-cert: {', '.join(principals) or '(any principal)'}",
        "issuer": f"ssh-ca {ssh_fingerprint(base64.b64decode(ca_blob))}",
        "self_signed": False, "fingerprint_sha256": hashlib.sha256(blob).hexdigest(),
        "extra": {"ssh_certificate": ctype, "principals": principals, "serial": cert.serial, "ssh_role": role,
                  "no_expiry": expires is None}})  # fmt: skip


def ssh_role_for(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    if base.startswith("ssh_host_"):
        return "host-key"
    if base.startswith("authorized_keys"):
        return "authorized-key"
    if base.startswith("known_hosts"):
        return "known-host"
    return "user-key"


def ssh_public_entries(text: str, name: str) -> list[Entry]:
    role = ssh_role_for(name)
    out: list[Entry] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = SSH_LINE.search(line)
        if not m:
            continue
        ktype, b64, comment = m.group(1), m.group(2), (m.group(3) or "").strip() or None
        prefix = line[: m.start(1)].strip()
        try:
            if ktype.endswith("-cert-v01@openssh.com"):
                out.append(_ssh_cert_entry(f"{ktype} {b64}", name, role))
                continue
            blob = base64.b64decode(b64)
            f = _ssh_key_fields(blob, "public-key", comment or f"{name}:{lineno}", ssh_role=role, line=lineno,
                                comment=comment)  # fmt: skip
        except (ValueError, TypeError, KeyfileError, struct.error, IndexError, UnsupportedSsh):
            continue
        if role == "known-host" and prefix:
            marker = prefix.split()[0] if prefix.startswith("@") else None
            hosts = prefix.split()[-1]
            f["extra"]["hosts"] = "(hashed)" if hosts.startswith("|1|") else hosts
            if marker:
                f["extra"]["marker"] = marker
            f["name"] = f["extra"]["hosts"] if not comment else comment
        elif role == "authorized-key" and prefix:
            f["extra"]["options"] = prefix
        out.append(Entry(f"ssh:{f['extra']['ssh_fingerprint']}:{lineno}", f))
    return out


class UnsupportedSsh(Exception):  # noqa: N818
    pass


# ---------------------------------------------------------------- dispatch
def parse(data: bytes, name: str, passwords: list[str] | None = None) -> list[Entry]:
    """Everything recognisable in `data`. `name` is the file name or secret key (used for SSH roles
    and as the display name). `passwords` are tried before the well-known ones."""
    pw = list(dict.fromkeys([*(passwords or []), *WELL_KNOWN_PASSWORDS]))
    if len(data) >= 4 and struct.unpack(">I", data[:4])[0] in (JKS_MAGIC, JCEKS_MAGIC):
        return jks_entries(data, name, pw)
    if b"-----BEGIN " in data:
        return _pem_entries(data, name, pw)
    head = data[:4096]
    if SSH_LINE.search(head.decode("utf-8", "replace").splitlines()[0] if head else "") or (
        name.rsplit("/", 1)[-1].startswith(("authorized_keys", "known_hosts")) or name.endswith(".pub")
    ):
        try:
            entries = ssh_public_entries(data.decode("utf-8"), name)
        except UnicodeDecodeError:
            entries = []
        if entries:
            return entries
    if looks_like_pkcs12(data):
        try:
            return pkcs12_entries(data, name, pw)
        except KeyfileError:
            pass
    return _der_entries(data, name)


def looks_like_key_material(data: bytes) -> bool:
    """Cheap test before parse(): worth looking at?"""
    if len(data) < 32:
        return False
    if data[:4] in (b"\xfe\xed\xfe\xed", b"\xce\xce\xce\xce") or b"-----BEGIN " in data[:65536]:
        return True
    if looks_like_pkcs12(data):
        return True
    try:
        return bool(SSH_LINE.search(data[:8192].decode("utf-8")))
    except UnicodeDecodeError:
        return data[0] == 0x30  # DER
