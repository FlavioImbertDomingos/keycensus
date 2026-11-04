"""RFC 3161 trusted timestamps, so a signed scan's time does not rest on the scanner's own clock.

    signing:
      private_key_file: /run/secrets/keycensus-signing.pem
      timestamp:
        urls: [http://timestamp.digicert.com, https://freetsa.org/tsr]   # tried in order
        ca_file: /etc/keycensus/tsa-roots.pem   # roots of those TSAs, for checking the reply
        required: false                         # true: a scan with no timestamp is an error
        timeout: 10

After `manifest.json.sig` is written, keycensus sends the SHA-256 of the signature to a Time Stamping
Authority and stores the signed reply as `manifest.json.tsr`. The TSA signs "this hash existed at this
time" with its own key, so the timestamp proves the signature (and therefore the manifest and every
output it lists) existed no later than that moment, whatever the scanner's clock said.

What is checked, both when the reply arrives and in `keycensus verify`:

* the TSA answered `granted`, for exactly our hash (SHA-256 message imprint) and our nonce
* the CMS signature over the timestamp, with the signer certificate the reply carries
* that certificate has the timeStamping extended key usage, was valid at the time it states, and
  chains to a root in `ca_file`

The reply is a standard `.tsr`, so `openssl ts -verify -in manifest.json.tsr -data <sig> -CAfile ...`
checks it too, without keycensus.
"""

from __future__ import annotations

import hashlib
import os
import warnings
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import requests
from asn1crypto import algos, cms, tsp
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

_HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512, "sha1": hashes.SHA1}


class TimestampError(Exception):
    pass


@dataclass
class Stamp:
    gen_time: datetime
    tsa: str  # signer certificate subject
    serial: int
    policy: str
    chain_verified: bool

    def to_dict(self) -> dict:
        return {"gen_time": self.gen_time.isoformat(), "tsa": self.tsa, "serial": str(self.serial),
                "policy": self.policy, "chain_verified": self.chain_verified}  # fmt: skip


def build_request(data: bytes) -> tuple[bytes, bytes, int]:
    """(DER TimeStampReq, sha256 digest, nonce) for `data`."""
    digest = hashlib.sha256(data).digest()
    nonce = int.from_bytes(os.urandom(8), "big")
    req = tsp.TimeStampReq({
        "version": 1,
        "message_imprint": {"hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}), "hashed_message": digest},
        "nonce": nonce,
        "cert_req": True,
    })  # fmt: skip
    return req.dump(), digest, nonce


def request(data: bytes, urls: list[str], ca_file: str | None = None, timeout: float = 10.0
            ) -> tuple[bytes, Stamp, str]:  # fmt: skip
    """Ask each TSA in turn; return (DER TimeStampResp, parsed stamp, url) from the first good answer."""
    errors = []
    for url in urls:
        der, digest, nonce = build_request(data)
        try:
            r = requests.post(url, data=der, timeout=timeout, headers={"Content-Type": "application/timestamp-query"})
            if r.status_code != 200:
                raise TimestampError(f"HTTP {r.status_code}")
            stamp = verify(r.content, data, ca_file, expect_nonce=nonce)
            return r.content, stamp, url
        except (requests.RequestException, TimestampError, ValueError) as exc:
            errors.append(f"{url}: {exc}")
    raise TimestampError("no TSA gave a valid timestamp: " + "; ".join(errors))


def _token(resp_der: bytes) -> cms.ContentInfo:
    resp = tsp.TimeStampResp.load(resp_der)
    status = resp["status"]["status"].native
    if status not in ("granted", "granted_with_mods"):
        text = resp["status"]["status_string"].native if resp["status"]["status_string"] else ""
        raise TimestampError(f"TSA refused: {status} {text or ''}".strip())
    return resp["time_stamp_token"]


def verify(resp_der: bytes, data: bytes, ca_file: str | None = None, expect_nonce: int | None = None) -> Stamp:
    """Check a TimeStampResp for `data`. Without `ca_file` the signature is checked but the TSA is
    not trusted (chain_verified=False)."""
    token = _token(resp_der)
    sd = token["content"]
    encap = sd["encap_content_info"]
    if encap["content_type"].native != "tst_info":
        raise TimestampError("token does not carry TSTInfo")
    tst_der = encap["content"].contents
    tst = tsp.TSTInfo.load(tst_der)

    mi = tst["message_imprint"]
    algo = mi["hash_algorithm"]["algorithm"].native
    if algo not in _HASHES or algo == "sha1":
        raise TimestampError(f"message imprint uses {algo}")
    h = hashes.Hash(_HASHES[algo]())
    h.update(data)
    if mi["hashed_message"].native != h.finalize():
        raise TimestampError("timestamp is for different data (message imprint mismatch)")
    if expect_nonce is not None and tst["nonce"].native != expect_nonce:
        raise TimestampError("nonce mismatch: the reply was not made for this request")

    signer = sd["signer_infos"][0]
    certs = [x509.load_der_x509_certificate(c.chosen.dump()) for c in sd["certificates"] or []
             if c.name == "certificate"]  # fmt: skip
    cert = _signer_cert(signer, certs)
    _check_cms_signature(signer, tst_der, cert)

    gen_time = tst["gen_time"].native
    if not (cert.not_valid_before_utc <= gen_time <= cert.not_valid_after_utc):
        raise TimestampError("TSA certificate was not valid at the time it stamped")
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise TimestampError("TSA certificate has no extended key usage") from exc
    if ExtendedKeyUsageOID.TIME_STAMPING not in eku:
        raise TimestampError("TSA certificate is not for timestamping (no timeStamping EKU)")

    chained = False
    if ca_file:
        _check_chain(cert, certs, _load_bundle(ca_file), gen_time)
        chained = True
    return Stamp(gen_time=gen_time, tsa=cert.subject.rfc4514_string(), serial=tst["serial_number"].native,
                 policy=tst["policy"].native, chain_verified=chained)  # fmt: skip


def _signer_cert(signer, certs: list[x509.Certificate]) -> x509.Certificate:
    sid = signer["sid"]
    for c in certs:
        if sid.name == "issuer_and_serial_number":
            want = sid.chosen
            if c.serial_number == want["serial_number"].native and \
                    c.issuer.public_bytes() == want["issuer"].dump():  # fmt: skip
                return c
        else:
            try:
                ski = c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            except x509.ExtensionNotFound:
                continue
            if ski == sid.chosen.native:
                return c
    raise TimestampError("the reply does not include the TSA's signing certificate (cert_req ignored?)")


def _check_cms_signature(signer, content: bytes, cert: x509.Certificate) -> None:
    digest_algo = signer["digest_algorithm"]["algorithm"].native
    if digest_algo not in _HASHES or digest_algo == "sha1":
        raise TimestampError(f"TSA signature uses {digest_algo}")
    hash_cls = _HASHES[digest_algo]
    attrs = signer["signed_attrs"]
    if not attrs:
        raise TimestampError("timestamp has no signed attributes")
    md = next((a["values"][0].native for a in attrs if a["type"].native == "message_digest"), None)
    h = hashes.Hash(hash_cls())
    h.update(content)
    if md != h.finalize():
        raise TimestampError("CMS message digest does not match the timestamp content")
    signed = b"\x31" + attrs.dump()[1:]  # signed attributes are signed as a SET, not as [0]
    sig = signer["signature"].native
    algo = signer["signature_algorithm"].signature_algo
    pub = cert.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pad = padding.PSS(padding.MGF1(hash_cls()), padding.PSS.AUTO) if algo == "rsassa_pss" \
                else padding.PKCS1v15()  # fmt: skip
            pub.verify(sig, signed, pad, hash_cls())
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, signed, ec.ECDSA(hash_cls()))
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(sig, signed)
        else:
            raise TimestampError(f"unsupported TSA key type {type(pub).__name__}")
    except InvalidSignature as exc:
        raise TimestampError("TSA signature is INVALID") from exc


def _load_bundle(path: str) -> list[x509.Certificate]:
    """Every certificate in a PEM bundle; malformed ones (a system bundle may carry a few) are skipped."""
    out = []
    for block in Path(path).read_bytes().split(b"-----END CERTIFICATE-----"):
        if b"-----BEGIN CERTIFICATE-----" not in block:
            continue
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                out.append(x509.load_pem_x509_certificate(block + b"-----END CERTIFICATE-----\n"))
            except ValueError:
                continue
    if not out:
        raise TimestampError(f"no certificates in {path}")
    return out


def _check_chain(cert: x509.Certificate, extra: list[x509.Certificate], trusted: list[x509.Certificate],
                 at: datetime) -> None:  # fmt: skip
    roots = {c.fingerprint(hashes.SHA256()) for c in trusted}
    pool = trusted + extra
    current = cert
    for _ in range(8):
        if current.fingerprint(hashes.SHA256()) in roots:
            return
        issuer = None
        for cand in pool:
            if cand.subject != current.issuer or cand is current:
                continue
            try:
                current.verify_directly_issued_by(cand)
            except (ValueError, TypeError, InvalidSignature):
                continue
            issuer = cand
            break
        if issuer is None:
            stuck = current.issuer.rfc4514_string()
            raise TimestampError(f"TSA certificate does not chain to ca_file (stuck at {stuck})")
        if not (issuer.not_valid_before_utc <= at <= issuer.not_valid_after_utc):
            raise TimestampError(f"{issuer.subject.rfc4514_string()} was not valid at the stamped time")
        current = issuer
    raise TimestampError("TSA certificate chain is too long")
