"""The rules. Each rule is a small function: asset in, zero or more findings out.

Thresholds and severities come from a policy YAML (see data/default-policy.yml)
so an organisation can tune them without touching code.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from ..model import (
    ALG_3DES,
    ALG_DES,
    ALG_RC4,
    ALG_UNKNOWN,
    KIND_CERTIFICATE,
    KIND_KEY,
    KIND_PROTOCOL,
    STATE_ACTIVE,
    STATE_UNKNOWN,
    CryptoAsset,
    Finding,
)
from . import strength

WEAK_ALGORITHMS = {ALG_DES, ALG_RC4, ALG_3DES}
WEAK_HASHES = {"MD2", "MD4", "MD5", "SHA1", "SHA-1"}
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "anon", "MD5", "RC2", "IDEA")
PROTECTIVE_PURPOSES = {"encrypt", "decrypt", "wrap", "unwrap", "sign"}


class Policy:
    def __init__(self, data: dict[str, Any]):
        self.data = data
        self.name = str(data.get("name", "custom"))
        self.rules: dict[str, dict] = data.get("rules") or {}

    @classmethod
    def default(cls) -> Policy:
        text = resources.files("keycensus.data").joinpath("default-policy.yml").read_text()
        return cls(yaml.safe_load(text))

    @classmethod
    def load(cls, path: str | Path | None) -> Policy:
        if not path or str(path) == "default":
            return cls.default()
        base = cls.default().data
        with open(path) as fh:
            override = yaml.safe_load(fh) or {}
        merged = _deep_merge(base, override)
        return cls(merged)

    def enabled(self, rule: str) -> bool:
        return bool(self.rules.get(rule, {}).get("enabled", True))

    def severity(self, rule: str, default: str = "medium") -> str:
        return str(self.rules.get(rule, {}).get("severity", default))

    def cryptoperiod_days(self, asset: CryptoAsset) -> int:
        cp = self.data.get("cryptoperiod_days") or {}
        for purpose in asset.purposes:
            if purpose in (cp.get("by_purpose") or {}):
                return int(cp["by_purpose"][purpose])
        by_alg = cp.get("by_algorithm") or {}
        if asset.algorithm in by_alg:
            return int(by_alg[asset.algorithm])
        return int(cp.get("default", 365))

    def cert(self, key: str, default: int) -> int:
        return int((self.data.get("certificate") or {}).get(key, default))


# Blocks a custom policy replaces wholesale (your numbers are the numbers);
# everything else (notably `rules`) merges per key so you only list what changes.
_REPLACE_WHOLE = {"cryptoperiod_days", "certificate"}


def _deep_merge(base: dict, override: dict, _top: bool = True) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict) and not (_top and k in _REPLACE_WHOLE):
            out[k] = _deep_merge(out[k], v, _top=False)
        else:
            out[k] = v
    return out


# ---------------------------------------------------------------- rule helpers
def _f(policy: Policy, rule: str, asset: CryptoAsset, title: str, detail: str, remediation: str,
       controls: list[str], refs: list[str] | None = None, default_sev: str = "medium") -> Finding:  # fmt: skip
    return Finding(
        rule_id=rule,
        severity=policy.severity(rule, default_sev),
        title=title,
        detail=detail,
        remediation=remediation,
        asset_id=asset.id,
        asset_name=asset.name,
        source=asset.source,
        controls=controls,
        references=refs or [],
    )


Rule = Callable[[Policy, CryptoAsset], Iterable[Finding]]


# ---------------------------------------------------------------- rules
def rule_weak_algorithm(p: Policy, a: CryptoAsset):
    if a.kind in (KIND_KEY, KIND_CERTIFICATE) and a.algorithm in WEAK_ALGORITHMS:
        yield _f(p, "weak-algorithm", a,
                 f"{a.algorithm} is a broken or deprecated algorithm",
                 f"{a.name} uses {a.display_algorithm}. {strength.assess(a).note}",
                 "Re-encrypt / re-sign with AES-256 (or ML-KEM/ML-DSA for public-key) and destroy this key.",
                 ["PCI-DSS-4.0:3.5.1", "PCI-DSS-4.0:3.7.5", "NIST-SP-800-131A"], default_sev="high")  # fmt: skip


def rule_weak_key_size(p: Policy, a: CryptoAsset):
    if a.kind in (KIND_KEY, KIND_CERTIFICATE) and strength.is_weak_key_size(a):
        yield _f(p, "weak-key-size", a,
                 f"{a.display_algorithm} is below the strong-cryptography minimum",
                 f"{a.name}: PCI DSS strong cryptography requires RSA/DSA/DH ≥ 2048, ECC ≥ 224, AES ≥ 128 bits.",
                 "Generate a replacement key of adequate size and retire this one.",
                 ["PCI-DSS-4.0:3.7.1", "PCI-DSS-4.0:3.5.1", "NIST-SP-800-131A"], default_sev="high")  # fmt: skip


def rule_deprecated_signature_hash(p: Policy, a: CryptoAsset):
    if a.kind == KIND_CERTIFICATE and (a.signature_hash or "").upper() in WEAK_HASHES:
        yield _f(p, "deprecated-signature-hash", a,
                 f"Certificate signed with {a.signature_hash}",
                 f"{a.name} is signed with {a.signature_algorithm}; {a.signature_hash} collisions are practical.",
                 "Re-issue the certificate with SHA-256 or stronger.",
                 ["PCI-DSS-4.0:4.2.1", "PCI-DSS-4.0:3.7.5", "NIST-SP-800-131A"], default_sev="high")  # fmt: skip


def rule_rotation_overdue(p: Policy, a: CryptoAsset):
    if a.kind != KIND_KEY or a.state not in (STATE_ACTIVE, STATE_UNKNOWN):
        return
    days = a.days_since_rotation
    if days is None:
        return
    limit = p.cryptoperiod_days(a)
    if days > limit:
        yield _f(p, "rotation-overdue", a,
                 f"Key is {days:.0f} days old, cryptoperiod is {limit} days",
                 f"{a.name} ({a.display_algorithm}) was last rotated {days:.0f} days ago.",
                 "Rotate the key (create a new version, re-wrap/re-encrypt as needed, retire the old material).",
                 ["PCI-DSS-4.0:3.7.4", "NIST-SP-800-57"])  # fmt: skip


def rule_rotation_disabled(p: Policy, a: CryptoAsset):
    if a.kind == KIND_KEY and a.rotation_enabled is False and a.state == STATE_ACTIVE:
        yield _f(p, "rotation-disabled", a,
                 "Automatic rotation is available but switched off",
                 f"{a.name} in {a.source} supports automatic rotation and it is disabled.",
                 "Enable automatic rotation (or document the manual rotation procedure and evidence).",
                 ["PCI-DSS-4.0:3.7.4"], default_sev="low")  # fmt: skip


def rule_no_creation_date(p: Policy, a: CryptoAsset):
    if a.kind == KIND_KEY and a.created is None and a.last_rotated is None:
        yield _f(p, "no-creation-date", a,
                 "No creation date: cryptoperiod cannot be assessed",
                 f"{a.name} in {a.source} reports no creation/rotation timestamp.",
                 "Record key creation dates in the source system or a key register "
                 "(PCI DSS 3.6.1.1 / 12.3.3 inventory).",
                 ["PCI-DSS-4.0:12.3.3", "PCI-DSS-4.0:3.6.1.1"], default_sev="info")  # fmt: skip


def rule_cert_expiry(p: Policy, a: CryptoAsset):
    if a.kind != KIND_CERTIFICATE or a.days_until_expiry is None:
        return
    d = a.days_until_expiry
    if d < 0:
        yield _f(p, "cert-expired", a, "Certificate has EXPIRED",
                 f"{a.name} expired {-d:.0f} days ago.",
                 "Renew immediately; anything validating it is failing or about to.",
                 ["PCI-DSS-4.0:4.2.1"], default_sev="critical")  # fmt: skip
    elif d < p.cert("expiring_critical_days", 7):
        yield _f(p, "cert-expiring-critical", a, f"Certificate expires in {d:.0f} days",
                 f"{a.name} expires on {a.expires:%Y-%m-%d}.", "Renew now.",
                 ["PCI-DSS-4.0:4.2.1"], default_sev="high")  # fmt: skip
    elif d < p.cert("expiring_soon_days", 30):
        yield _f(p, "cert-expiring-soon", a, f"Certificate expires in {d:.0f} days",
                 f"{a.name} expires on {a.expires:%Y-%m-%d}.", "Schedule renewal.",
                 ["PCI-DSS-4.0:4.2.1"])  # fmt: skip


def rule_cert_self_signed(p: Policy, a: CryptoAsset):
    if a.kind == KIND_CERTIFICATE and a.self_signed and a.source_type != "vault-pki":
        yield _f(p, "cert-self-signed", a, "Self-signed certificate",
                 f"{a.name} is self-signed (subject == issuer).",
                 "Fine for a private root CA; for a server cert, issue from a managed CA so trust can be revoked.",
                 ["PCI-DSS-4.0:4.2.1"], default_sev="info")  # fmt: skip


def rule_cert_long_validity(p: Policy, a: CryptoAsset):
    if a.kind == KIND_CERTIFICATE and a.created and a.expires and not a.self_signed:
        validity = (a.expires - a.created).days
        limit = p.cert("max_validity_days", 398)
        if validity > limit:
            yield _f(p, "cert-long-validity", a, f"Certificate valid for {validity} days",
                     f"{a.name} has a {validity}-day validity; limit in policy is {limit}.",
                     "Shorter-lived certificates limit the blast radius of a key compromise.",
                     ["PCI-DSS-4.0:3.7.4"], default_sev="info")  # fmt: skip


def rule_key_exportable(p: Policy, a: CryptoAsset):
    if a.kind == KIND_KEY and a.exportable is True and a.key_type != "public-key":
        yield _f(p, "key-exportable", a, "Key is marked exportable / extractable",
                 f"{a.name} in {a.source} can be exported in plaintext or wrapped form.",
                 "Unless there is a documented backup/escrow need, regenerate as non-exportable.",
                 ["PCI-DSS-4.0:3.7.3", "PCI-DSS-4.0:3.6.1"])  # fmt: skip


def rule_key_software_backed(p: Policy, a: CryptoAsset):
    if (a.kind == KIND_KEY and a.hardware_backed is False and a.key_type != "public-key"
            and set(a.purposes) & PROTECTIVE_PURPOSES):  # fmt: skip
        yield _f(p, "key-software-backed", a, "Key material lives in software, not an HSM",
                 f"{a.name} in {a.source} is not hardware-backed.",
                 "Move high-value keys (KEKs, PAN-encrypting keys, CA keys) into an HSM or a KMS with HSM backing.",
                 ["PCI-DSS-4.0:3.6.1", "NIST-FIPS-140-3"], default_sev="low")  # fmt: skip


def rule_key_not_active(p: Policy, a: CryptoAsset):
    if a.kind == KIND_KEY and a.state not in (STATE_ACTIVE, STATE_UNKNOWN):
        yield _f(p, "key-not-active", a, f"Key state is '{a.state}'",
                 f"{a.name} in {a.source} is {a.state}.",
                 "Confirm it is scheduled for destruction and nothing still references it.",
                 ["PCI-DSS-4.0:3.7.5"], default_sev="info")  # fmt: skip


def rule_quantum(p: Policy, a: CryptoAsset):
    if a.kind == KIND_PROTOCOL:
        return
    s = strength.assess(a)
    if s.quantum_class == strength.QUANTUM_VULNERABLE and a.algorithm not in WEAK_ALGORITHMS:
        # Certificates only carry public keys: the exposure is signature forgery, not decryption.
        encrypts = a.kind == KIND_KEY and bool({"encrypt", "decrypt", "wrap", "unwrap", "derive"} & set(a.purposes))
        if encrypts:
            yield _f(p, "quantum-vulnerable-encryption", a,
                     f"{a.display_algorithm} protects confidentiality and is quantum-vulnerable",
                     f"{a.name}: data encrypted or wrapped under this key can be harvested now and "
                     f"decrypted once a CRQC exists. {s.note}",
                     "Prioritise for hybrid / ML-KEM migration; shorten the lifetime of data protected by it.",
                     ["NIST-IR-8547", "PCI-DSS-4.0:12.3.3"])  # fmt: skip
        else:
            yield _f(p, "quantum-vulnerable", a,
                     f"{a.display_algorithm} is quantum-vulnerable",
                     f"{a.name}: {s.note}",
                     "Add to the PQC migration plan required by PCI DSS 12.3.3; "
                     "target ML-DSA / SLH-DSA for signatures.",
                     ["NIST-IR-8547", "PCI-DSS-4.0:12.3.3"], default_sev="low")  # fmt: skip
    elif s.quantum_class == strength.QUANTUM_REDUCED:
        yield _f(p, "quantum-reduced", a,
                 f"{a.display_algorithm}: reduced strength against quantum attack",
                 f"{a.name}: {s.note}",
                 "Prefer 256-bit symmetric keys for data that must stay confidential beyond 2035.",
                 ["NIST-IR-8547"], default_sev="info")  # fmt: skip


def rule_unknown_algorithm(p: Policy, a: CryptoAsset):
    if a.kind != KIND_PROTOCOL and a.algorithm == ALG_UNKNOWN:
        yield _f(p, "unknown-algorithm", a, "Algorithm could not be determined",
                 f"{a.name} in {a.source}: the collector could not identify the algorithm.",
                 "Check the source's metadata; an inventory with unknowns fails PCI DSS 12.3.3.",
                 ["PCI-DSS-4.0:12.3.3"], default_sev="info")  # fmt: skip


def rule_tls(p: Policy, a: CryptoAsset):
    if a.kind != KIND_PROTOCOL:
        return
    weak_versions = set(a.weak_versions_accepted) | (
        {a.protocol_version} if a.protocol_version in WEAK_TLS_VERSIONS else set()
    )
    if weak_versions:
        yield _f(p, "tls-weak-protocol", a,
                 f"Endpoint accepts {', '.join(sorted(weak_versions))}",
                 f"{a.name} negotiates deprecated protocol versions.",
                 "Disable everything below TLS 1.2 on the server / load balancer.",
                 ["PCI-DSS-4.0:4.2.1", "PCI-DSS-4.0:12.3.3"], default_sev="high")  # fmt: skip
    weak_ciphers = [c for c in a.cipher_suites if any(m in c for m in WEAK_CIPHER_MARKERS)]
    if weak_ciphers:
        yield _f(p, "tls-weak-cipher", a,
                 f"Weak cipher suite(s): {', '.join(weak_ciphers)}",
                 f"{a.name} negotiated or offers weak cipher suites.",
                 "Restrict to AEAD suites (AES-GCM, ChaCha20-Poly1305) with ECDHE key exchange.",
                 ["PCI-DSS-4.0:4.2.1", "PCI-DSS-4.0:12.3.3"], default_sev="high")  # fmt: skip
    if a.cipher_suites and not any(("ECDHE" in c or "DHE" in c or c.startswith("TLS_")) for c in a.cipher_suites):
        yield _f(p, "tls-no-forward-secrecy", a,
                 "Negotiated cipher suite lacks forward secrecy",
                 f"{a.name}: {', '.join(a.cipher_suites)}",
                 "Prefer ECDHE suites so a future key compromise cannot decrypt past traffic.",
                 ["PCI-DSS-4.0:4.2.1"], default_sev="low")  # fmt: skip


RULES: dict[str, Rule] = {
    "weak-algorithm": rule_weak_algorithm,
    "weak-key-size": rule_weak_key_size,
    "deprecated-signature-hash": rule_deprecated_signature_hash,
    "rotation-overdue": rule_rotation_overdue,
    "rotation-disabled": rule_rotation_disabled,
    "no-creation-date": rule_no_creation_date,
    "cert-expiry": rule_cert_expiry,  # emits cert-expired / cert-expiring-*
    "cert-self-signed": rule_cert_self_signed,
    "cert-long-validity": rule_cert_long_validity,
    "key-exportable": rule_key_exportable,
    "key-software-backed": rule_key_software_backed,
    "key-not-active": rule_key_not_active,
    "quantum": rule_quantum,  # emits quantum-vulnerable(-encryption) / quantum-reduced
    "unknown-algorithm": rule_unknown_algorithm,
    "tls": rule_tls,  # emits tls-*
}


def evaluate(assets: Iterable[CryptoAsset], policy: Policy) -> list[Finding]:
    assets = list(assets)
    # The public half of a key pair is the same key: don't report it twice.
    private_pairs = {(a.source, a.name) for a in assets if a.key_type == "private-key"}
    findings: list[Finding] = []
    for asset in assets:
        if asset.key_type == "public-key" and (asset.source, asset.name) in private_pairs:
            continue
        for rule in RULES.values():
            for finding in rule(policy, asset):
                if policy.enabled(finding.rule_id):
                    findings.append(finding)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 9), f.source, f.asset_name))
    return findings


def rule_catalogue() -> list[dict[str, str]]:
    """Human list of every rule id, for `keycensus rules` and the docs."""
    p = Policy.default()
    return [{"rule": rid, "severity": p.severity(rid), "enabled": str(p.enabled(rid)).lower()} for rid in p.rules]
