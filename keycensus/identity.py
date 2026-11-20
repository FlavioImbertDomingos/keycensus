"""Asset identity: the same certificate or key seen in several places is one asset with several observations.

Collectors report what they see, where they see it: a certificate in a PEM file, the same certificate in a
Kubernetes secret, on a TLS endpoint and in a Certificate Transparency log is four records. Each record stays
(it carries the location, the coverage scope and the findings for that place), and this module groups them:

* a certificate is identified by the SHA-256 of its DER encoding (`fingerprint_sha256`)
* a key whose public half a collector can see is identified by the SHA-256 of its SubjectPublicKeyInfo
  (`public_key_sha256`): a private key file, its public key, the same key in a keystore or a Vault Transit
  key with an exported public key are one key pair
* an AWS KMS multi-region key and its replicas share key material and their `mrk-` key id
* anything else (a secret key in an HSM, a KMS key whose public part is not read) is its own identity

and records the relationships the data supports:

* `certifies`: a certificate for a key the inventory also holds (same public key)
* `issued-by`: a certificate and the CA certificate that issued it (authority key id = subject key id)
* `backed-by`: an Azure Key Vault certificate and the key Key Vault keeps for it (the certificate's `kid`)

Nothing is guessed from names: two keys called "payments" in different places stay two identities.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from .model import KIND_CERTIFICATE, KIND_KEY, CryptoAsset, iso

BASIS_CERT = "certificate fingerprint"
BASIS_KEY = "public key"
BASIS_MRK = "AWS multi-region key"
BASIS_SINGLE = "single record"


@dataclass
class Identity:
    id: str  # ki-<12 hex>, stable for the same certificate, key pair or multi-region key
    key: str  # what grouped it: cert:<sha256> | key:<spki sha256> | aws-mrk:<account>:<key id> | asset:<asset id>
    basis: str
    kind: str
    name: str
    asset_ids: list[str] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)
    versions: dict[str, Any] | None = None

    @property
    def places(self) -> int:
        return len({(o["source"], o["location"]) for o in self.observations})

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["places"] = self.places
        return d


def identity_key(a: CryptoAsset) -> tuple[str, str]:
    """(grouping key, basis) for one asset record."""
    if a.kind == KIND_CERTIFICATE and a.fingerprint_sha256:
        return f"cert:{a.fingerprint_sha256}", BASIS_CERT
    if a.kind == KIND_KEY and a.public_key_sha256:
        return f"key:{a.public_key_sha256}", BASIS_KEY
    key_id = str(a.extra.get("key_id") or "")
    if a.source_type == "aws-kms" and a.extra.get("multi_region") and key_id.startswith("mrk-"):
        arn = str(a.native_id)
        account = arn.split(":")[4] if arn.startswith("arn:") and arn.count(":") >= 5 else ""
        return f"aws-mrk:{account}:{key_id}", BASIS_MRK
    return f"asset:{a.id}", BASIS_SINGLE


def _ident_id(key: str) -> str:
    return "ki-" + hashlib.sha256(key.encode()).hexdigest()[:12]


def key_versions(a: CryptoAsset) -> dict[str, Any] | None:
    """The version facts each key store reports, under one shape: current, count, decryptable_from."""
    e = a.extra
    if a.source_type == "vault" and e.get("latest_version") is not None:
        return {"current": e.get("latest_version"), "count": e.get("versions"),
                "decryptable_from": e.get("min_decryption_version")}  # fmt: skip
    if a.source_type == "gcp-kms" and e.get("versions") is not None:
        return {"current": e.get("primary_version"), "count": e.get("versions"), "states": e.get("version_states")}
    if a.source_type == "azure-keyvault" and e.get("version"):
        return {"current": e.get("version")}
    return None


def group(assets: Iterable[CryptoAsset]) -> list[Identity]:
    """Every asset record, grouped by identity, in a stable order."""
    by_key: dict[str, Identity] = {}
    for a in assets:
        key, basis = identity_key(a)
        ident = by_key.get(key)
        if ident is None:
            ident = by_key[key] = Identity(id=_ident_id(key), key=key, basis=basis, kind=a.kind, name=a.name,
                                           versions=key_versions(a))  # fmt: skip
        ident.asset_ids.append(a.id)
        ident.observations.append({
            "asset_id": a.id, "source": a.source, "source_type": a.source_type, "location": a.location or a.native_id,
            "key_type": a.key_type, "observed": a.observed, "last_observed": iso(a.last_observed),
        })  # fmt: skip
        if ident.versions is None:
            ident.versions = key_versions(a)
    return sorted(by_key.values(), key=lambda i: (i.kind, i.name.lower(), i.id))


def index(identities: Iterable[Identity]) -> dict[str, str]:
    """asset id -> identity id."""
    return {aid: ident.id for ident in identities for aid in ident.asset_ids}


def relationships(assets: Iterable[CryptoAsset], identities: list[Identity]) -> list[dict[str, str]]:
    """certifies, issued-by and backed-by edges between identities, each with the evidence for it."""
    assets = list(assets)
    idx = index(identities)
    edges: dict[tuple[str, str, str], dict[str, str]] = {}

    def add(kind: str, frm: str, to: str, evidence: str) -> None:
        if frm != to:
            edges.setdefault((kind, frm, to), {"type": kind, "from": frm, "to": to, "evidence": evidence})

    keys_by_spki: dict[str, set[str]] = {}
    certs_by_ski: dict[str, set[str]] = {}
    keys_by_native: dict[str, str] = {}
    for a in assets:
        if a.kind == KIND_KEY and a.public_key_sha256:
            keys_by_spki.setdefault(a.public_key_sha256, set()).add(idx[a.id])
        if a.kind == KIND_KEY:
            keys_by_native[str(a.native_id)] = idx[a.id]
        if a.kind == KIND_CERTIFICATE and a.extra.get("ski"):
            certs_by_ski.setdefault(str(a.extra["ski"]), set()).add(idx[a.id])
    for a in assets:
        if a.kind != KIND_CERTIFICATE:
            continue
        me = idx[a.id]
        for key_ident in keys_by_spki.get(a.public_key_sha256 or "", ()):
            add("certifies", me, key_ident, "same public key")
        aki = a.extra.get("aki")
        parents = certs_by_ski.get(str(aki), set()) if aki and not a.self_signed else set()
        if len(parents) == 1:  # two different CA certificates with one key id: say nothing rather than guess
            add("issued-by", me, next(iter(parents)), "authority key identifier")
        kid = str(a.extra.get("kid") or "")
        if a.source_type == "azure-keyvault" and kid:
            versionless = kid.rsplit("/", 1)[0] if kid.count("/") >= 5 else kid
            target = keys_by_native.get(versionless) or keys_by_native.get(kid)
            if target:
                add("backed-by", me, target, "Key Vault certificate kid")
    return sorted(edges.values(), key=lambda e: (e["type"], e["from"], e["to"]))
