"""The two things keycensus produces: **assets** (what you have) and
**findings** (what's wrong with it).

Every collector, whatever it talks to (an HSM over PKCS#11, Vault over HTTP,
AWS KMS over boto3, a folder of PEM files, a TLS port), normalises what it sees
into `CryptoAsset` objects. Everything downstream -- policy rules, the CBOM,
the HTML report, Prometheus metrics -- only ever sees this model. That is what
makes the collectors pluggable.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------- vocab
KIND_KEY = "key"
KIND_CERTIFICATE = "certificate"
KIND_PROTOCOL = "protocol"

# Canonical algorithm names. Collectors map vendor spellings onto these.
ALG_RSA = "RSA"
ALG_EC = "EC"  # ECDSA / ECDH on Weierstrass curves (P-256 ...)
ALG_ED25519 = "Ed25519"
ALG_ED448 = "Ed448"
ALG_X25519 = "X25519"
ALG_DSA = "DSA"
ALG_DH = "DH"
ALG_AES = "AES"
ALG_3DES = "3DES"
ALG_DES = "DES"
ALG_RC4 = "RC4"
ALG_CHACHA20 = "ChaCha20"
ALG_HMAC = "HMAC"
ALG_ML_KEM = "ML-KEM"
ALG_ML_DSA = "ML-DSA"
ALG_SLH_DSA = "SLH-DSA"
ALG_UNKNOWN = "unknown"

STATE_ACTIVE = "active"
STATE_PRE_ACTIVATION = "pre-activation"
STATE_SUSPENDED = "suspended"
STATE_DEACTIVATED = "deactivated"
STATE_COMPROMISED = "compromised"
STATE_DESTROYED = "destroyed"
STATE_UNKNOWN = "unknown"

SEVERITIES = ("critical", "high", "medium", "low", "info")


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime | None) -> str | None:
    return dt.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z") if dt else None


@dataclass
class CryptoAsset:
    """One key, certificate, or protocol endpoint, described the same way
    regardless of where it came from."""

    source: str  # name of the configured source, e.g. "prod-hsm"
    source_type: str  # collector type, e.g. "pkcs11"
    kind: str  # key | certificate | protocol
    name: str  # human label (key label, cert CN, host:port)
    native_id: str  # id in the source system (CKA_ID, ARN, path ...)
    algorithm: str = ALG_UNKNOWN
    key_size: int | None = None  # bits (RSA modulus, AES key, EC field size)
    curve: str | None = None  # P-256, secp384r1, ...
    key_type: str = "key"  # secret-key | private-key | public-key | key
    purposes: list[str] = field(default_factory=list)  # encrypt decrypt sign verify wrap ...
    created: datetime | None = None
    last_rotated: datetime | None = None
    expires: datetime | None = None
    state: str = STATE_UNKNOWN
    rotation_enabled: bool | None = None  # automatic rotation configured?
    exportable: bool | None = None
    hardware_backed: bool | None = None
    fips_validated: bool | None = None
    location: str = ""  # where it lives, for humans (slot/token, mount path, region)
    # certificate-only
    subject: str | None = None
    issuer: str | None = None
    signature_algorithm: str | None = None  # e.g. sha256WithRSAEncryption
    signature_hash: str | None = None  # SHA256 / SHA1 / MD5
    self_signed: bool | None = None
    fingerprint_sha256: str | None = None
    # protocol-only
    protocol: str | None = None  # TLS
    protocol_version: str | None = None  # TLSv1.2
    cipher_suites: list[str] = field(default_factory=list)
    weak_versions_accepted: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)
    # who uses it -- inferred by the collector (IAM principals, grants, Vault policies, NTLS clients,
    # CipherTrust application/owner ...). Each entry: {"type": principal|policy|application|client|user,
    # "id": "...", "via": "iam-policy|grant|vault-policy|owner|..."}
    used_by: list[dict[str, str]] = field(default_factory=list)
    # applications linked to this asset (names), filled by keycensus.linking
    applications: list[str] = field(default_factory=list)

    # ------------------------------------------------------------ identity
    @property
    def id(self) -> str:
        """Stable, unique, URL-safe id: kc-<12 hex> derived from source + native id."""
        digest = hashlib.sha256(f"{self.source}|{self.kind}|{self.native_id}".encode()).hexdigest()
        return f"kc-{digest[:12]}"

    @property
    def age_days(self) -> float | None:
        if self.created is None:
            return None
        return (utcnow() - self.created).total_seconds() / 86400

    @property
    def days_since_rotation(self) -> float | None:
        anchor = self.last_rotated or self.created
        if anchor is None:
            return None
        return (utcnow() - anchor).total_seconds() / 86400

    @property
    def days_until_expiry(self) -> float | None:
        if self.expires is None:
            return None
        return (self.expires - utcnow()).total_seconds() / 86400

    @property
    def display_algorithm(self) -> str:
        if self.curve and self.curve != self.algorithm:
            return f"{self.algorithm}-{self.curve}"
        if self.key_size:
            return f"{self.algorithm}-{self.key_size}"
        return self.algorithm

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["id"] = self.id
        for k in ("created", "last_rotated", "expires"):
            d[k] = iso(getattr(self, k))
        d["age_days"] = round(self.age_days, 1) if self.age_days is not None else None
        d["days_until_expiry"] = round(self.days_until_expiry, 1) if self.days_until_expiry is not None else None
        d["display_algorithm"] = self.display_algorithm
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CryptoAsset:
        """Inverse of to_dict() (for re-linking / re-reporting a saved inventory.json)."""
        names = {f.name for f in cls.__dataclass_fields__.values()}
        kw = {k: v for k, v in d.items() if k in names}
        for k in ("created", "last_rotated", "expires"):
            v = kw.get(k)
            if isinstance(v, str):
                kw[k] = datetime.fromisoformat(v.replace("Z", "+00:00"))
            elif v is not None and not isinstance(v, datetime):
                kw[k] = None
        return cls(**kw)


@dataclass
class Finding:
    """Something a policy rule didn't like about an asset."""

    rule_id: str
    severity: str  # critical | high | medium | low | info
    title: str
    detail: str
    remediation: str
    asset_id: str
    asset_name: str
    source: str
    controls: list[str] = field(default_factory=list)  # e.g. ["PCI-DSS-4.0:3.7.4"]
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Application:
    """An application (usually described by an SBOM) and the cryptographic assets it uses."""

    name: str
    version: str | None = None
    bom_ref: str | None = None  # bom-ref of the application component (from its SBOM, or generated)
    purl: str | None = None
    owner: str | None = None
    description: str | None = None
    sbom_path: str | None = None
    sbom_serial: str | None = None  # serialNumber (CycloneDX) or documentNamespace (SPDX)
    sbom_components: int | None = None
    sbom_format: str | None = None  # "cyclonedx" | "spdx"
    uses: list[dict[str, Any]] = field(default_factory=list)  # selectors from the config
    asset_ids: list[str] = field(default_factory=list)
    matches: dict[str, list[str]] = field(default_factory=dict)  # asset id -> why it matched

    @property
    def ref(self) -> str:
        return self.bom_ref or f"app:{self.name}" + (f"@{self.version}" if self.version else "")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["ref"] = self.ref
        d["assets"] = len(self.asset_ids)
        return d


@dataclass
class SourceResult:
    """What one collector produced, plus whether it worked."""

    name: str
    type: str
    assets: list[CryptoAsset] = field(default_factory=list)
    error: str | None = None
    duration_seconds: float = 0.0


@dataclass
class Inventory:
    """A complete scan: all assets from all sources, plus findings."""

    generated_at: datetime
    sources: list[SourceResult]
    findings: list[Finding] = field(default_factory=list)
    policy_name: str = "default"
    applications: list[Application] = field(default_factory=list)

    @property
    def assets(self) -> list[CryptoAsset]:
        return [a for s in self.sources for a in s.assets]

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Inventory:
        """Rebuild an Inventory from inventory.json (assets, findings, sources, applications)."""
        by_source: dict[str, list[CryptoAsset]] = {}
        for a in d.get("assets") or []:
            by_source.setdefault(a["source"], []).append(CryptoAsset.from_dict(a))
        sources = [
            SourceResult(name=s["name"], type=s["type"], assets=by_source.get(s["name"], []), error=s.get("error"),
                         duration_seconds=float(s.get("duration_seconds") or 0))
            for s in d.get("sources") or []
        ]  # fmt: skip
        generated = d.get("generated_at")
        inv = cls(
            generated_at=datetime.fromisoformat(generated.replace("Z", "+00:00")) if generated else utcnow(),
            sources=sources,
            policy_name=str(d.get("policy", "default")),
        )
        fnames = {f.name for f in Finding.__dataclass_fields__.values()}
        inv.findings = [Finding(**{k: v for k, v in f.items() if k in fnames}) for f in d.get("findings") or []]
        anames = {f.name for f in Application.__dataclass_fields__.values()}
        inv.applications = [
            Application(**{k: v for k, v in a.items() if k in anames}) for a in d.get("applications") or []
        ]
        return inv

    def summary(self) -> dict[str, Any]:
        by_sev = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            by_sev[f.severity] += 1
        by_kind: dict[str, int] = {}
        by_alg: dict[str, int] = {}
        for a in self.assets:
            by_kind[a.kind] = by_kind.get(a.kind, 0) + 1
            by_alg[a.display_algorithm] = by_alg.get(a.display_algorithm, 0) + 1
        linked = sum(1 for a in self.assets if a.applications)
        return {
            "assets": len(self.assets),
            "sources": len(self.sources),
            "sources_failed": sum(1 for s in self.sources if s.error),
            "applications": len(self.applications),
            "assets_linked": linked,
            "assets_unlinked": len(self.assets) - linked if self.applications else None,
            "findings": len(self.findings),
            "findings_by_severity": by_sev,
            "assets_by_kind": by_kind,
            "assets_by_algorithm": dict(sorted(by_alg.items(), key=lambda kv: -kv[1])),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "keycensus",
            "generated_at": iso(self.generated_at),
            "policy": self.policy_name,
            "summary": self.summary(),
            "sources": [
                {
                    "name": s.name,
                    "type": s.type,
                    "assets": len(s.assets),
                    "error": s.error,
                    "duration_seconds": round(s.duration_seconds, 3),
                }
                for s in self.sources
            ],
            "applications": [a.to_dict() for a in self.applications],
            "assets": [a.to_dict() for a in self.assets],
            "findings": [f.to_dict() for f in self.findings],
        }
