"""Signed scan records: proof that a CBOM or report existed on a date and has not changed since.

    signing:
      private_key_file: /run/secrets/keycensus-signing.pem    # or _env, _vault, _aws_secret, ...

After writing its outputs, `keycensus scan` writes `manifest.json` next to them, listing the SHA-256
of every output file, the scan time, the keycensus version, the config and policy hashes and the
signing key's fingerprint, then `manifest.json.sig`: an Ed25519 signature over the exact bytes of
manifest.json. `keycensus serve` signs each rescan the same way and serves both at /manifest.json and
/manifest.json.sig.

    keycensus keygen --out keycensus-signing              # writes keycensus-signing.pem + .pub.pem
    keycensus verify ./out --public-key keycensus-signing.pub.pem

An assessor needs the public key and the folder. Keep the private key where the scanner can read it
and nobody else can; anyone holding it can sign a different inventory. For evidence that must also
prove *when* it was signed against a party you do not control, add an RFC 3161 timestamp or a
Sigstore / Rekor entry on top: this signature proves who, the manifest's timestamp is the signer's
own claim. `signing.timestamp` adds exactly that: an RFC 3161 timestamp over the signature, stored as
manifest.json.tsr (see keycensus.timestamp).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import __version__, secrets
from .model import iso, utcnow

MANIFEST = "manifest.json"
SIGNATURE = "manifest.json.sig"
TIMESTAMP = "manifest.json.tsr"


class SigningError(Exception):
    pass


def keygen(prefix: str | Path) -> tuple[Path, Path]:
    priv = Ed25519PrivateKey.generate()
    key_path, pub_path = Path(f"{prefix}.pem"), Path(f"{prefix}.pub.pem")
    if key_path.exists():
        raise SigningError(f"{key_path} already exists; refusing to overwrite a signing key")
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))  # fmt: skip
    pub_path.write_bytes(priv.public_key().public_bytes(serialization.Encoding.PEM,
                                                        serialization.PublicFormat.SubjectPublicKeyInfo))  # fmt: skip
    return key_path, pub_path


def fingerprint(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load_private_key(block: dict[str, Any]) -> Ed25519PrivateKey:
    pem = secrets.resolve(block, "private_key", owner="signing", required=True, allow_inline=False)
    try:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
    except ValueError as exc:
        raise SigningError("signing: private key is not an unencrypted PEM key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningError("signing: the private key must be Ed25519 (create one with `keycensus keygen`)")
    return key


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise SigningError(f"{path} is not an Ed25519 public key")
    return key


def build_manifest(files: dict[str, bytes], key: Ed25519PrivateKey, meta: dict[str, Any] | None = None
                   ) -> tuple[bytes, bytes]:  # fmt: skip
    """(manifest bytes, signature bytes) for these outputs."""
    manifest = {
        "tool": "keycensus",
        "version": __version__,
        "signed_at": iso(utcnow()),
        "key": fingerprint(key.public_key()),
        **(meta or {}),
        "files": {name: hashlib.sha256(body).hexdigest() for name, body in sorted(files.items())},
    }
    body = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    return body, base64.b64encode(key.sign(body)) + b"\n"


def stamp_signature(sig_b64: bytes, ts_cfg: dict[str, Any] | None) -> tuple[bytes | None, dict | None]:
    """RFC 3161 timestamp over the raw signature, if `signing.timestamp` is configured.
    Returns (DER reply, stamp info) or (None, error info); raises when `required` and it failed."""
    if not ts_cfg or not ts_cfg.get("urls"):
        return None, None
    from .timestamp import TimestampError, request  # noqa: PLC0415

    raw = base64.b64decode(sig_b64.strip())
    try:
        der, stamp, url = request(raw, [str(u) for u in ts_cfg["urls"]], ts_cfg.get("ca_file"),
                                  float(ts_cfg.get("timeout", 10)))  # fmt: skip
    except TimestampError as exc:
        if ts_cfg.get("required"):
            raise SigningError(f"signing.timestamp is required and failed: {exc}") from exc
        return None, {"error": str(exc)}
    return der, {**stamp.to_dict(), "url": url}


def sign_dir(out_dir: str | Path, names: list[str], key: Ed25519PrivateKey, meta: dict[str, Any] | None = None,
             ts_cfg: dict[str, Any] | None = None) -> dict[str, Any]:  # fmt: skip
    out = Path(out_dir)
    files = {n: (out / n).read_bytes() for n in names if (out / n).is_file()}
    body, sig = build_manifest(files, key, meta)
    (out / MANIFEST).write_bytes(body)
    (out / SIGNATURE).write_bytes(sig)
    result: dict[str, Any] = {"manifest_sha256": hashlib.sha256(body).hexdigest(), "key": fingerprint(key.public_key()),
                              "files": len(files)}  # fmt: skip
    tsr, info = stamp_signature(sig, ts_cfg)
    (out / TIMESTAMP).unlink(missing_ok=True)  # never leave a stale timestamp next to a new signature
    if tsr:
        (out / TIMESTAMP).write_bytes(tsr)
    if info:
        result["timestamp"] = info
    return result


def verify_dir(out_dir: str | Path, pub: Ed25519PublicKey, tsa_ca_file: str | None = None,
               require_timestamp: bool = False) -> tuple[bool, list[str]]:  # fmt: skip
    """(ok, report lines). Checks the signature, the RFC 3161 timestamp if there is one, then every file."""
    out = Path(out_dir)
    lines: list[str] = []
    try:
        body = (out / MANIFEST).read_bytes()
        sig = base64.b64decode((out / SIGNATURE).read_bytes().strip())
    except FileNotFoundError as exc:
        return False, [f"missing {exc.filename}"]
    try:
        pub.verify(sig, body)
    except InvalidSignature:
        return False, ["signature INVALID: manifest.json was changed, or signed with a different key"]
    manifest = json.loads(body)
    if manifest.get("key") != fingerprint(pub):
        return False, [f"manifest names key {manifest.get('key')}, not this public key"]
    lines.append(f"signature ok: key {manifest['key']}, signed {manifest.get('signed_at')} (scanner's clock), "
                 f"keycensus {manifest.get('version')}")  # fmt: skip
    ok = True
    tsr = out / TIMESTAMP
    if tsr.exists():
        from .timestamp import TimestampError  # noqa: PLC0415
        from .timestamp import verify as verify_ts  # noqa: PLC0415

        try:
            stamp = verify_ts(tsr.read_bytes(), sig, tsa_ca_file)
        except TimestampError as exc:
            return False, lines + [f"timestamp INVALID: {exc}"]
        trust = "TSA chain verified" if stamp.chain_verified else "TSA NOT verified (pass --tsa-ca-file)"
        lines.append(f"timestamp ok: existed by {stamp.gen_time.isoformat()} per {stamp.tsa} ({trust})")
        if require_timestamp and not stamp.chain_verified:
            ok = False
    elif require_timestamp:
        ok = False
        lines.append("MISSING   manifest.json.tsr (a trusted timestamp was required)")
    for name, digest in manifest.get("files", {}).items():
        p = out / name
        if not p.exists():
            ok = False
            lines.append(f"MISSING   {name}")
        elif hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            ok = False
            lines.append(f"MODIFIED  {name}")
        else:
            lines.append(f"ok        {name}")
    return ok, lines
