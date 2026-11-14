"""The rules. Each rule is a small function: asset in, zero or more findings out.

Thresholds and severities come from a policy YAML (see data/default-policy.yml)
so an organisation can tune them without touching code.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from collections.abc import Callable, Iterable
from datetime import UTC, date, datetime
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from ..model import (
    ALG_3DES,
    ALG_DES,
    ALG_RC4,
    ALG_UNKNOWN,
    KIND_ALGORITHM,
    KIND_CERTIFICATE,
    KIND_KEY,
    KIND_PROTOCOL,
    STATE_ACTIVE,
    STATE_UNKNOWN,
    CryptoAsset,
    Finding,
)
from . import strength

WEAK_ALGORITHMS = {ALG_DES, ALG_RC4, ALG_3DES} | strength.LEGACY_CIPHERS
WEAK_HASHES = {"MD2", "MD4", "MD5", "SHA1", "SHA-1"}
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "anon", "MD5", "RC2", "IDEA")
PROTECTIVE_PURPOSES = {"encrypt", "decrypt", "wrap", "unwrap", "sign"}


SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info")
RULE_KEYS = {"enabled", "severity", "effective", "schedule", "applies_to", "controls", "references", "rationale"}
APPLIES_KEYS = {"kinds", "sources", "source_types", "exclude_sources", "exclude_source_types"}
PACK_KEYS = {"name", "version", "effective", "review_by", "owner", "description", "references", "extends",
             "applies_to", "rules", "cryptoperiod_days", "certificate"}  # fmt: skip


class PolicyError(ValueError):
    """A policy pack that cannot be used: every problem found, one per line."""


def _as_date(v: Any) -> date | None:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, date):
        return v
    return date.fromisoformat(str(v))


def builtin_packs() -> dict[str, Any]:
    """Built-in pack name -> resource. `default` is the base every other pack extends."""
    data = resources.files("keycensus.data")
    out = {"default": data.joinpath("default-policy.yml")}
    for f in data.joinpath("policies").iterdir():
        if f.name.endswith(".yml"):
            out[f.name[:-4]] = f
    return out


class Policy:
    """A policy pack: thresholds, rules and the metadata that make a scan's result reproducible.

    `name` and `version` say which pack it is; `digest` (SHA-256 of the merged content) says exactly what
    it contained, so an edit without a version bump still shows. `as_of` is the date rules are evaluated
    on: it decides which `effective` dates have passed and which `schedule` step applies."""

    def __init__(self, data: dict[str, Any], source: str = "builtin:default", base: str | None = None):
        self.data = data
        self.name = str(data.get("name", "custom"))
        self.version = str(data["version"]) if data.get("version") not in (None, "") else None
        self.effective = _as_date(data.get("effective"))
        self.review_by = _as_date(data.get("review_by"))
        self.rules: dict[str, dict] = data.get("rules") or {}
        self.source = source
        self.base = base
        self.as_of: date = datetime.now(UTC).date()
        self.digest = hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()

    # ------------------------------------------------------------ loading
    @classmethod
    def default(cls) -> Policy:
        return cls(yaml.safe_load(builtin_packs()["default"].read_text()))

    @classmethod
    def load(cls, path: str | Path | None) -> Policy:
        """A built-in pack by name (`default`, `nist-pqc`) or a YAML file. Packs are merged over the pack
        they extend (`extends:`, default `default`) so they list only what changes. Raises PolicyError."""
        ref = str(path) if path else "default"
        packs = builtin_packs()
        if ref == "default":
            return cls.default()
        if ref in packs and not Path(ref).exists():
            override, source = yaml.safe_load(packs[ref].read_text()) or {}, f"builtin:{ref}"
        else:
            try:
                with open(ref) as fh:
                    override = yaml.safe_load(fh) or {}
            except FileNotFoundError:
                raise PolicyError(f"no policy file {ref}, and no built-in pack of that name "
                                  f"(built-in: {', '.join(sorted(packs))})") from None  # fmt: skip
            source = ref
        if not isinstance(override, dict):
            raise PolicyError(f"{ref}: a policy pack is a YAML mapping")
        parent_name = str(override.get("extends") or "default")
        if parent_name == "default":
            parent = cls.default()
        elif parent_name in packs and parent_name != ref:
            parent = cls.load(parent_name)
        else:
            raise PolicyError(f"{ref}: extends {parent_name!r}, which is not a built-in pack")
        problems = validate_pack(override, known_rules=set(parent.rules), where=ref)
        if problems:
            raise PolicyError("\n".join(problems))
        merged = _deep_merge(parent.data, override)
        for k in ("version", "effective", "review_by", "description", "references", "owner"):
            if k not in override:  # metadata describes this pack, never inherited from the parent
                merged.pop(k, None)
        merged["name"] = override.get("name", Path(ref).stem)
        merged.pop("extends", None)
        return cls(merged, source=source, base=parent.ref)

    # ------------------------------------------------------------ identity
    @property
    def ref(self) -> str:
        return f"{self.name}@{self.version or 'unversioned'}"

    def review_overdue(self, today: date | None = None) -> bool:
        return bool(self.review_by and (today or self.as_of) > self.review_by)

    def describe(self, today: date | None = None) -> dict[str, Any]:
        """What a scan records about the pack it used (inventory.json `policy_pack`)."""
        today = today or self.as_of
        upcoming = []
        for rid, r in sorted(self.rules.items()):
            eff = _as_date(r.get("effective"))
            if eff and eff > today and r.get("enabled", True):
                upcoming.append({"rule": rid, "from": eff.isoformat(), "change": "rule takes effect"})
            for step in r.get("schedule") or []:
                when = _as_date(step.get("from"))
                if when and when > today:
                    upcoming.append({"rule": rid, "from": when.isoformat(), "change": f"severity {step['severity']}"})
        upcoming.sort(key=lambda u: (u["from"], u["rule"]))
        return {
            "name": self.name,
            "version": self.version,
            "ref": self.ref,
            "digest": self.digest,
            "source": self.source,
            "extends": self.base,
            "effective": self.effective.isoformat() if self.effective else None,
            "review_by": self.review_by.isoformat() if self.review_by else None,
            "review_overdue": self.review_overdue(today),
            "evaluated_on": today.isoformat(),
            "references": self.data.get("references") or [],
            "upcoming": upcoming,
        }

    # ------------------------------------------------------------ rules
    def enabled(self, rule: str) -> bool:
        return bool(self.rules.get(rule, {}).get("enabled", True))

    def in_effect(self, rule: str) -> bool:
        eff = _as_date(self.rules.get(rule, {}).get("effective"))
        return self.enabled(rule) and not (eff and eff > self.as_of)

    def severity(self, rule: str, default: str = "medium") -> str:
        r = self.rules.get(rule, {})
        sev = str(r.get("severity", default))
        for step in sorted(r.get("schedule") or [], key=lambda st: _as_date(st.get("from")) or date.min):
            if (_as_date(step.get("from")) or date.min) <= self.as_of:
                sev = str(step["severity"])
        return sev

    def applies(self, rule: str, asset: CryptoAsset) -> bool:
        for scope in (self.data.get("applies_to") or {}, self.rules.get(rule, {}).get("applies_to") or {}):
            if scope.get("kinds") and asset.kind not in scope["kinds"]:
                return False
            if scope.get("sources") and asset.source not in scope["sources"]:
                return False
            if scope.get("source_types") and asset.source_type not in scope["source_types"]:
                return False
            if asset.source in (scope.get("exclude_sources") or []):
                return False
            if asset.source_type in (scope.get("exclude_source_types") or []):
                return False
        return True

    def finalize(self, finding: Finding, asset: CryptoAsset | None) -> Finding | None:
        """Apply the pack to a finding a rule produced: drop it when the rule is off, not yet in effect or
        does not apply to the asset; otherwise stamp the pack version and the pack's controls/references."""
        rid = finding.rule_id
        if not self.in_effect(rid) or (asset is not None and not self.applies(rid, asset)):
            return None
        r = self.rules.get(rid, {})
        if r.get("controls"):
            finding.controls = list(r["controls"])
        for ref in r.get("references") or []:
            if ref not in finding.references:
                finding.references.append(ref)
        finding.policy = self.ref
        return finding

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


def validate_pack(pack: dict, known_rules: set[str], where: str = "policy") -> list[str]:
    """Problems that would make a pack mean something other than what its author wrote. An unknown rule
    id is an error, because a typo would otherwise switch nothing off and nobody would notice."""
    out: list[str] = []
    for k in pack:
        if k not in PACK_KEYS:
            out.append(f"{where}: unknown key {k!r} (known: {', '.join(sorted(PACK_KEYS))})")
    if "version" in pack and not str(pack.get("version") or "").strip():
        out.append(f"{where}: version is empty")
    for k in ("effective", "review_by"):
        try:
            _as_date(pack.get(k))
        except (TypeError, ValueError):
            out.append(f"{where}: {k} {pack.get(k)!r} is not a date (YYYY-MM-DD)")
    eff, rev = (_safe_date(pack.get("effective")), _safe_date(pack.get("review_by")))
    if eff and rev and rev <= eff:
        out.append(f"{where}: review_by {rev} is not after effective {eff}")
    for ref in pack.get("references") or []:
        if not isinstance(ref, dict) or not ref.get("id"):
            out.append(f"{where}: each reference needs an id (and ideally a title and url): {ref!r}")
    out += _validate_applies(pack.get("applies_to"), f"{where}: applies_to")
    rules = pack.get("rules") or {}
    if not isinstance(rules, dict):
        return out + [f"{where}: rules must be a mapping of rule id to settings"]
    for rid, r in rules.items():
        at = f"{where}: rules.{rid}"
        if rid not in known_rules:
            close = difflib.get_close_matches(rid, sorted(known_rules), n=1)
            out.append(f"{at}: unknown rule" + (f" (did you mean {close[0]}?)" if close else ""))
            continue
        if not isinstance(r, dict):
            out.append(f"{at}: expected a mapping such as {{enabled: false}} or {{severity: high}}")
            continue
        for k in r:
            if k not in RULE_KEYS:
                out.append(f"{at}: unknown setting {k!r} (known: {', '.join(sorted(RULE_KEYS))})")
        if "enabled" in r and not isinstance(r["enabled"], bool):
            out.append(f"{at}: enabled must be true or false")
        if "severity" in r and r["severity"] not in SEVERITY_LEVELS:
            out.append(f"{at}: severity {r['severity']!r} is not one of {', '.join(SEVERITY_LEVELS)}")
        if "effective" in r and _safe_date(r["effective"]) is None:
            out.append(f"{at}: effective {r['effective']!r} is not a date (YYYY-MM-DD)")
        for i, step in enumerate(r.get("schedule") or []):
            if not isinstance(step, dict) or _safe_date(step.get("from")) is None:
                out.append(f"{at}: schedule[{i}] needs a from: date")
            elif step.get("severity") not in SEVERITY_LEVELS:
                out.append(f"{at}: schedule[{i}] severity {step.get('severity')!r} is not one of "
                           f"{', '.join(SEVERITY_LEVELS)}")  # fmt: skip
        for k in ("controls", "references"):
            if k in r and not (isinstance(r[k], list) and all(isinstance(x, str) for x in r[k])):
                out.append(f"{at}: {k} must be a list of ids")
        out += _validate_applies(r.get("applies_to"), f"{at}: applies_to")
    return out


def _safe_date(v: Any) -> date | None:
    try:
        return _as_date(v)
    except (TypeError, ValueError):
        return None


def _validate_applies(scope: Any, at: str) -> list[str]:
    if scope is None:
        return []
    if not isinstance(scope, dict):
        return [f"{at}: expected a mapping"]
    out = [
        f"{at}: unknown key {k!r} (known: {', '.join(sorted(APPLIES_KEYS))})" for k in scope if k not in APPLIES_KEYS
    ]
    for k, v in scope.items():
        if k in APPLIES_KEYS and not (isinstance(v, list) and all(isinstance(x, str) for x in v)):
            out.append(f"{at}: {k} must be a list")
    return out


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


def diff_policies(old: Policy, new: Policy) -> list[dict[str, Any]]:
    """What changed between two packs, rule by rule and threshold by threshold (for review before rollout)."""
    out: list[dict[str, Any]] = []
    for k in ("name", "version", "effective", "review_by"):
        ov, nv = old.data.get(k), new.data.get(k)
        if str(ov) != str(nv):
            out.append({"what": k, "before": ov, "after": nv})
    for block in ("cryptoperiod_days", "certificate", "applies_to"):
        ov, nv = old.data.get(block), new.data.get(block)
        if ov != nv:
            out.append({"what": block, "before": ov, "after": nv})
    for rid in sorted(set(old.rules) | set(new.rules)):
        ov, nv = old.rules.get(rid), new.rules.get(rid)
        if ov == nv:
            continue
        for k in sorted(set(ov or {}) | set(nv or {})):
            a, b = (ov or {}).get(k), (nv or {}).get(k)
            if a != b:
                out.append({"what": f"rules.{rid}.{k}", "before": a, "after": b})
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
    if a.kind in (KIND_KEY, KIND_CERTIFICATE, KIND_ALGORITHM) and a.algorithm in WEAK_ALGORITHMS:
        yield _f(p, "weak-algorithm", a,
                 f"{a.algorithm} is a broken or deprecated algorithm",
                 f"{a.name} uses {a.display_algorithm}. {strength.assess(a).note}",
                 "Re-encrypt / re-sign with AES-256 (or ML-KEM/ML-DSA for public-key) and destroy this key.",
                 ["PCI-DSS-4.0:3.5.1", "PCI-DSS-4.0:3.7.5", "NIST-SP-800-131A"], default_sev="high")  # fmt: skip


def rule_weak_key_size(p: Policy, a: CryptoAsset):
    if a.kind in (KIND_KEY, KIND_CERTIFICATE, KIND_ALGORITHM) and strength.is_weak_key_size(a):
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
                 ["PCI-DSS-4.0:4.2.1", "PCI-DSS-4.0:3.7.5", "NIST-SP-800-131A", "NIST-IR-8547"],
                 default_sev="high")  # fmt: skip


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


def _hardcoded(a: CryptoAsset) -> bool:
    """A key committed to source: hardcoded-private-key says everything; storage findings would repeat it."""
    return bool((a.extra or {}).get("hardcoded"))


def rule_no_creation_date(p: Policy, a: CryptoAsset):
    if a.kind == KIND_KEY and a.created is None and a.last_rotated is None and not _hardcoded(a):
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
    # The limit is for end-entity certificates. CA certificates are meant to outlive what they issue.
    if (a.kind == KIND_CERTIFICATE and a.created and a.expires and not a.self_signed
            and not (a.extra or {}).get("is_ca")):  # fmt: skip
        validity = (a.expires - a.created).days
        limit = p.cert("max_validity_days", 398)
        if validity > limit:
            yield _f(p, "cert-long-validity", a, f"Certificate valid for {validity} days",
                     f"{a.name} has a {validity}-day validity; limit in policy is {limit}.",
                     "Shorter-lived certificates limit the blast radius of a key compromise.",
                     ["PCI-DSS-4.0:3.7.4"], default_sev="info")  # fmt: skip


def rule_key_exportable(p: Policy, a: CryptoAsset):
    if a.kind == KIND_KEY and a.exportable is True and a.key_type != "public-key" and not _hardcoded(a):
        yield _f(p, "key-exportable", a, "Key is marked exportable / extractable",
                 f"{a.name} in {a.source} can be exported in plaintext or wrapped form.",
                 "Unless there is a documented backup/escrow need, regenerate as non-exportable.",
                 ["PCI-DSS-4.0:3.7.3", "PCI-DSS-4.0:3.6.1"])  # fmt: skip


def rule_key_software_backed(p: Policy, a: CryptoAsset):
    if (a.kind == KIND_KEY and a.hardware_backed is False and a.key_type != "public-key"
            and set(a.purposes) & PROTECTIVE_PURPOSES and not _hardcoded(a)):  # fmt: skip
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
        encrypts = a.kind in (KIND_KEY, KIND_ALGORITHM) and bool({"encrypt", "decrypt", "wrap", "unwrap", "derive"}
                                                                  & set(a.purposes))  # fmt: skip
        if encrypts:
            yield _f(p, "quantum-vulnerable-encryption", a,
                     f"{a.display_algorithm} protects confidentiality and is quantum-vulnerable",
                     f"{a.name}: data encrypted or wrapped under this key can be harvested now and "
                     f"decrypted once a CRQC exists. {s.note}",
                     "Prioritise for ML-KEM migration (ML-KEM-768 is NIST's default; a hybrid is an accepted "
                     "bridge, not the end state); shorten the lifetime of data protected by it.",
                     ["NIST-IR-8547", "US-EO-14412", "PCI-DSS-4.0:12.3.3"])  # fmt: skip
        else:
            yield _f(p, "quantum-vulnerable", a,
                     f"{a.display_algorithm} is quantum-vulnerable",
                     f"{a.name}: {s.note}",
                     "Add to the PQC migration plan required by PCI DSS 12.3.3; "
                     "target ML-DSA / SLH-DSA for signatures.",
                     ["NIST-IR-8547", "US-EO-14412", "PCI-DSS-4.0:12.3.3"], default_sev="low")  # fmt: skip
    elif s.quantum_class == strength.QUANTUM_REDUCED:
        # Not a NIST requirement: IR 8547 keeps AES-128/192. A margin note for long-lived data, so no control.
        yield _f(p, "quantum-reduced", a,
                 f"{a.display_algorithm}: reduced strength against quantum attack",
                 f"{a.name}: {s.note}",
                 "No action required by NIST. Prefer 256-bit keys for data that must stay confidential for decades.",
                 [], default_sev="info")  # fmt: skip


def rule_unknown_algorithm(p: Policy, a: CryptoAsset):
    if a.kind != KIND_PROTOCOL and a.algorithm == ALG_UNKNOWN:
        yield _f(p, "unknown-algorithm", a, "Algorithm could not be determined",
                 f"{a.name} in {a.source}: the collector could not identify the algorithm.",
                 "Check the source's metadata; an inventory with unknowns fails PCI DSS 12.3.3.",
                 ["PCI-DSS-4.0:12.3.3"], default_sev="info")  # fmt: skip


def rule_adcs_template_weak_key_size(p: Policy, a: CryptoAsset):
    """An AD CS CA that publishes a template allowing weak keys will keep issuing weak certificates."""
    if a.kind != KIND_CERTIFICATE:
        return
    for t in (a.extra or {}).get("templates") or []:
        size, alg = t.get("min_key_size"), t.get("key_algorithm")
        if not size or not alg:
            continue
        probe = CryptoAsset(source=a.source, source_type=a.source_type, kind=KIND_KEY, name=t.get("name", "?"),
                            native_id="template", algorithm=alg, key_size=int(size))  # fmt: skip
        if strength.is_weak_key_size(probe):
            yield _f(p, "adcs-template-weak-key-size", a,
                     f"Template {t.get('name')} allows {alg}-{size} keys",
                     f"{a.name} publishes certificate template {t.get('name')}, whose minimum key size is "
                     f"{alg}-{size}. Every certificate enrolled from it can be below the strong-cryptography minimum.",
                     "Raise msPKI-Minimal-Key-Size to 2048 (RSA) or move to an ECDSA P-256/P-384 template, "
                     "supersede the old template, and re-enroll the certificates issued from it.",
                     ["PCI-DSS-4.0:3.7.1", "NIST-SP-800-131A"])  # fmt: skip


def rule_key_exchange(p: Policy, a: CryptoAsset):
    """TLS 1.3 groups and SSH kex: classical (harvest-now-decrypt-later) or hybrid (allowed, temporary)."""
    if a.kind != KIND_PROTOCOL or not a.key_exchange:
        return
    q, note = strength.key_exchange_class(a.key_exchange)
    info = (a.extra or {}).get("key_exchange") or {}
    pq = [g for g in info.get("pq_supported") or [] if g != a.key_exchange]
    proto = a.protocol or "the endpoint"
    if q == strength.QUANTUM_VULNERABLE:
        if pq:
            fix = (f"The server already accepts {', '.join(pq)} but prefers {a.key_exchange}: put the hybrid first "
                   "in its group / kex preference order.")  # fmt: skip
        elif proto == "SSH":
            fix = "Enable mlkem768x25519-sha256 (OpenSSH 9.9+) and list it first in KexAlgorithms."
        else:
            fix = ("Enable X25519MLKEM768 (OpenSSL 3.5+, BoringSSL, Go 1.24+, current load balancers and CDNs) and "
                   "prefer it.")  # fmt: skip
        yield _f(p, "quantum-vulnerable-key-exchange", a,
                 f"{proto} key exchange {a.key_exchange} is quantum-vulnerable",
                 f"{a.name}: {note}", fix,
                 ["NIST-IR-8547", "US-EO-14412", "PCI-DSS-4.0:12.3.3"])  # fmt: skip
    elif q == strength.QUANTUM_HYBRID:
        yield _f(p, "hybrid-key-exchange", a,
                 f"{proto} key exchange {a.key_exchange} is hybrid: allowed, but temporary",
                 f"{a.name}: {note}",
                 "Nothing to fix today. Track it: plan the second move to ML-KEM only when your clients support it.",
                 ["NIST-IR-8547"], default_sev="info")  # fmt: skip


def rule_ssh(p: Policy, a: CryptoAsset):
    if a.kind != KIND_PROTOCOL or a.protocol != "SSH":
        return
    weak = (a.extra or {}).get("weak_algorithms") or []
    if weak:
        yield _f(p, "ssh-weak-algorithm", a,
                 f"SSH server offers {', '.join(weak)}",
                 f"{a.name} offers algorithms with known weaknesses (SHA-1, small DH groups, CBC, RC4, 3DES, MD5, "
                 "DSA). A client that prefers them, or an attacker in the middle, can push the session down to them.",
                 "Remove them from KexAlgorithms / HostKeyAlgorithms / Ciphers / MACs in sshd_config.",
                 ["NIST-SP-800-131A", "PCI-DSS-4.0:12.3.3"], default_sev="high")  # fmt: skip


def rule_tls(p: Policy, a: CryptoAsset):
    if a.kind != KIND_PROTOCOL or (a.protocol or "TLS") != "TLS":
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


def _where(a: CryptoAsset) -> str:
    """'3 call sites in 2 files, e.g. src/app.py:12' for code-scanning assets."""
    ex = a.extra or {}
    occ = ex.get("occurrences") or []
    if not occ:
        return a.location
    first = occ[0]
    tests = " (tests only)" if ex.get("only_in_tests") else ""
    return (
        f"{ex.get('occurrence_count', len(occ))} call site(s) in {ex.get('files', 1)} file(s){tests}, "
        f"e.g. {first['file']}:{first['line']}"
    )


def rule_weak_hash(p: Policy, a: CryptoAsset):
    if a.kind == KIND_ALGORITHM and a.algorithm in strength.BROKEN_HASHES:
        yield _f(p, "weak-hash", a, f"Code uses {a.algorithm}",
                 f"{a.name}: {_where(a)}. {strength.assess(a).note}",
                 "Use SHA-256 or SHA-3. If a use is not security-relevant (a cache key, a checksum against "
                 "accidents), mark the line with `keycensus:ignore` (in Python also pass usedforsecurity=False).",
                 ["NIST-SP-800-131A", "PCI-DSS-4.0:3.5.1", "PCI-DSS-4.0:12.3.3"])  # fmt: skip


def rule_weak_cipher_mode(p: Policy, a: CryptoAsset):
    if a.kind == KIND_ALGORITHM and (a.extra or {}).get("mode") == "ECB":
        yield _f(p, "weak-cipher-mode", a, f"{a.algorithm} in ECB mode",
                 f"{a.name}: {_where(a)}. ECB encrypts equal blocks to equal ciphertext, so patterns in the data "
                 "show through. In Java, Cipher.getInstance(\"AES\") with no mode means AES/ECB.",
                 "Use an authenticated mode: AES-GCM (or AES-GCM-SIV / ChaCha20-Poly1305), with a unique nonce.",
                 ["PCI-DSS-4.0:3.5.1", "NIST-SP-800-131A"], default_sev="high")  # fmt: skip


def rule_hardcoded_private_key(p: Policy, a: CryptoAsset):
    ex = a.extra or {}
    if a.kind == KIND_KEY and ex.get("hardcoded"):
        test = (
            " It is under a test path; if it is a throwaway test key, say so in the exception."
            if ex.get("test_path")
            else ""
        )
        yield _f(p, "hardcoded-private-key", a, f"{a.display_algorithm} private key committed to source",
                 f"{ex.get('file')}:{ex.get('line')} in {ex.get('repository')} holds a private key. Anyone with read "
                 f"access to the repository, its forks, CI logs or build artefacts has it.{test}",
                 "Treat the key as compromised: revoke or rotate it, remove it from the tree and from git history, "
                 "and load the replacement from a secret store or KMS at run time.",
                 ["PCI-DSS-4.0:3.6.1", "PCI-DSS-4.0:3.7.3"], default_sev="critical")  # fmt: skip


def rule_keystore_weak_protection(p: Policy, a: CryptoAsset):
    reasons = (a.extra or {}).get("keystore_weak_protection") or []
    if reasons and a.kind == KIND_KEY:
        yield _f(p, "keystore-weak-protection", a, "Keystore protection is weak",
                 f"{a.name}: {'; '.join(reasons)}.",
                 "Convert to PKCS#12 with AES-256 and HMAC-SHA-256 (keytool -importkeystore -deststoretype pkcs12, "
                 "or openssl pkcs12 -export without -legacy) and a password from a secret store.",
                 ["PCI-DSS-4.0:3.6.1", "PCI-DSS-4.0:3.7.3"])  # fmt: skip


def rule_ct_unexpected_issuer(p: Policy, a: CryptoAsset):
    ex = a.extra or {}
    if a.kind == KIND_CERTIFICATE and ex.get("unexpected_issuer"):
        yield _f(p, "ct-unexpected-issuer", a, f"Public certificate from an unexpected CA: {a.issuer}",
                 f"Certificate Transparency shows a certificate for {', '.join(ex.get('dns_names') or [a.name])} "
                 f"issued by {a.issuer}, which is not in expected_issuers "
                 f"({', '.join(ex.get('expected_issuers') or [])}).",
                 "Find out who requested it. If nobody in the organisation did, have the CA revoke it and add CAA "
                 "records that name only your CAs.",
                 ["PCI-DSS-4.0:4.2.1"], default_sev="high")  # fmt: skip


def rule_ldap_cleartext(p: Policy, a: CryptoAsset):
    ex = a.extra or {}
    if a.kind == KIND_PROTOCOL and a.protocol == "LDAP" and ex.get("starttls_error"):
        yield _f(p, "ldap-cleartext", a, "LDAP server refuses StartTLS",
                 f"{a.name}: {ex['starttls_error']}. Simple binds to this server send passwords in the clear.",
                 "Install a server certificate (AD: an LDAPS certificate in the DC's personal store; OpenLDAP: "
                 "olcTLSCertificateFile), then require TLS (LDAP signing / channel binding, or olcSecurity tls=1).",
                 ["PCI-DSS-4.0:4.2.1", "PCI-DSS-4.0:12.3.3"])  # fmt: skip


def rule_key_reuse_on_renewal(p: Policy, a: CryptoAsset):
    cm = (a.extra or {}).get("cert_manager") or {}
    if a.kind == KIND_CERTIFICATE and cm.get("rotation_policy") == "Never":
        yield _f(p, "key-reuse-on-renewal", a, "Private key is reused at every renewal",
                 f"cert-manager Certificate {cm.get('certificate')} has privateKey.rotationPolicy: Never, so the "
                 "same key stays in use however often the certificate renews.",
                 "Set spec.privateKey.rotationPolicy: Always (the default from cert-manager 1.18).",
                 ["PCI-DSS-4.0:3.7.4", "NIST-SP-800-57"], default_sev="low")  # fmt: skip


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
    "key-exchange": rule_key_exchange,
    "ssh": rule_ssh,  # emits ssh-weak-algorithm  # emits quantum-vulnerable-key-exchange / hybrid-key-exchange
    "adcs-template-weak-key-size": rule_adcs_template_weak_key_size,
    "weak-hash": rule_weak_hash,
    "weak-cipher-mode": rule_weak_cipher_mode,
    "hardcoded-private-key": rule_hardcoded_private_key,
    "keystore-weak-protection": rule_keystore_weak_protection,
    "ct-unexpected-issuer": rule_ct_unexpected_issuer,
    "ldap-cleartext": rule_ldap_cleartext,
    "key-reuse-on-renewal": rule_key_reuse_on_renewal,
}


def public_halves(assets: Iterable[CryptoAsset]) -> set[str]:
    """Ids of public keys that are the public half of a private key in the same source: by name (HSMs, KMS),
    or by SSH fingerprint for an id_rsa.pub / ssh_host_*_key.pub next to its private key. known_hosts and
    authorized_keys entries are trust records elsewhere, so they stay."""
    assets = list(assets)
    names = {(a.source, a.name) for a in assets if a.key_type == "private-key"}
    fps = {(a.source, (a.extra or {}).get("ssh_fingerprint")) for a in assets
           if a.key_type == "private-key" and (a.extra or {}).get("ssh_fingerprint")}  # fmt: skip
    out = set()
    for a in assets:
        if a.kind != KIND_KEY or a.key_type != "public-key":
            continue
        ex = a.extra or {}
        if (a.source, a.name) in names or (
            ex.get("ssh_role") in ("host-key", "user-key") and (a.source, ex.get("ssh_fingerprint")) in fps
        ):
            out.add(a.id)
    return out


def evaluate(assets: Iterable[CryptoAsset], policy: Policy, today: date | None = None) -> list[Finding]:
    """Every finding the pack produces for these assets, as of `today` (the scan date; default: now)."""
    assets = list(assets)
    if today is not None:
        policy.as_of = today
    skip = public_halves(assets)  # the public half of a key pair is the same key: don't report it twice
    findings: list[Finding] = []
    for asset in assets:
        if asset.id in skip:
            continue
        for rule in RULES.values():
            for finding in rule(policy, asset):
                kept = policy.finalize(finding, asset)
                if kept is not None:
                    findings.append(kept)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 9), f.source, f.asset_name))
    return findings


def rule_catalogue(policy: Policy | None = None) -> list[dict[str, str]]:
    """Human list of every rule id, for `keycensus rules` and the docs."""
    p = policy or Policy.default()
    return [{"rule": rid, "severity": p.severity(rid), "enabled": str(p.in_effect(rid)).lower()} for rid in p.rules]
