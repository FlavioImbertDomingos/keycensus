"""Executive summary: how much of the estate is quantum-vulnerable, and what falls due when.

The dates come from docs/PQC-TIMELINE.md. Each milestone counts the assets the scan found that
must have moved by that date, how many days are left, and how many of those assets are still
valid on the date (a certificate that expires after 31 Dec 2031 will be in service when the
signature deadline passes, so replacing it on its normal renewal is not enough).

Who is bound by what:

* PCI DSS 4.0.1 12.3.3 (in force since 31 Mar 2025) binds anyone with cardholder data in scope;
  it asks for an inventory and a plan, and broken crypto is a finding today.
* EO 14412 (22 Jun 2026) binds US federal agencies for high-value assets and high-impact systems:
  post-quantum key establishment by 31 Dec 2030, post-quantum signatures by 31 Dec 2031.
* NIST IR 8547 (final, 27 Oct 2026) deprecates RSA, ECDSA, EdDSA, DH and ECDH after 2030 and
  disallows them after 2035 at every key size. It governs FIPS-validated use and is what auditors
  and vendors follow outside government too.
* The G7 roadmap (Jan 2026) aims at 2030 to 2032 for critical systems and 2035 overall. Not binding.

Hybrid endpoints (X25519MLKEM768 and friends) meet the key-establishment dates: their ML-KEM half
protects the traffic. IR 8547 treats hybrids as a transition step, so they are counted separately
as a second change still to make, never as overdue.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from ..model import ALG_DH, ALG_X25519, KIND_CERTIFICATE, KIND_KEY, KIND_PROTOCOL, CryptoAsset, Inventory
from . import strength

# Findings that mean the crypto is broken or disallowed already, whatever the quantum timeline says.
BROKEN_NOW_RULES = frozenset({
    "weak-algorithm",
    "weak-key-size",
    "deprecated-signature-hash",
    "adcs-template-weak-key-size",
    "tls-weak-protocol",
    "tls-weak-cipher",
    "ssh-weak-algorithm",
})  # fmt: skip

KEY_ESTABLISHMENT_PURPOSES = frozenset({"encrypt", "decrypt", "wrap", "unwrap", "derive"})
SIGNATURE_PURPOSES = frozenset({"sign", "verify"})

MILESTONES: list[dict[str, Any]] = [
    {
        "id": "now",
        "date": date(2025, 3, 31),
        "title": "Broken or disallowed crypto",
        "basis": "PCI DSS 4.0.1 12.3.3 (in force 31 Mar 2025); NIST SP 800-131A",
        "binding": "PCI DSS: anyone with cardholder data in scope",
        "covers": "Assets with a weak algorithm, short key, SHA-1 or MD5 signature, weak TLS or SSH setting",
    },
    {
        "id": "key-establishment-2030",
        "date": date(2030, 12, 31),
        "title": "Post-quantum key establishment",
        "basis": "EO 14412; NIST IR 8547 deprecates RSA, ECDH and DH after 2030",
        "binding": "EO 14412: US federal high-value assets and high-impact systems. IR 8547: FIPS-validated use",
        "covers": "Quantum-vulnerable encryption, wrapping and key-agreement keys, and endpoints with "
        "classical key exchange",
    },
    {
        "id": "signatures-2031",
        "date": date(2031, 12, 31),
        "title": "Post-quantum signatures",
        "basis": "EO 14412; NIST IR 8547 deprecates RSA, ECDSA and EdDSA after 2030",
        "binding": "EO 14412: US federal high-value assets and high-impact systems. IR 8547: FIPS-validated use",
        "covers": "Quantum-vulnerable signing keys and certificates",
    },
    {
        "id": "disallowed-2035",
        "date": date(2035, 12, 31),
        "title": "Classical public-key crypto disallowed",
        "basis": "NIST IR 8547: RSA, ECDSA, EdDSA, DH and ECDH disallowed after 2035 at every strength",
        "binding": "FIPS-validated use; G7 general target",
        "covers": "Everything still quantum-vulnerable, whatever its purpose",
    },
]

G7_NOTE = "G7 roadmap (Jan 2026, not binding): critical systems by 2030 to 2032, everything else by 2035."


def _today(today: date | datetime | None) -> date:
    if today is None:
        return datetime.now(UTC).date()
    return today.date() if isinstance(today, datetime) else today


def _population(inv: Inventory) -> list[CryptoAsset]:
    """Keys and certificates, without the public half of a key pair already counted as its private key."""
    private = {(a.source, a.name) for a in inv.assets if a.kind == KIND_KEY and a.key_type == "private-key"}
    return [
        a for a in inv.assets
        if a.kind != KIND_PROTOCOL
        and not (a.kind == KIND_KEY and a.key_type == "public-key" and (a.source, a.name) in private)
    ]  # fmt: skip


def _use(a: CryptoAsset) -> str:
    """key-establishment | signature | unknown, for a quantum-vulnerable key or certificate."""
    if a.kind == KIND_CERTIFICATE:
        return "signature"
    purposes = {p.lower() for p in a.purposes}
    if a.algorithm in (ALG_DH, ALG_X25519) or purposes & KEY_ESTABLISHMENT_PURPOSES:
        return "key-establishment"  # an RSA key that both signs and decrypts falls due at the earlier date
    if purposes & SIGNATURE_PURPOSES:
        return "signature"
    return "unknown"


def _pct(n: int, total: int) -> float:
    return round(100.0 * n / total, 1) if total else 0.0


def summarize(inv: Inventory, today: date | datetime | None = None) -> dict[str, Any]:
    day = _today(today)
    population = _population(inv)
    vulnerable = [a for a in population if strength.assess(a).quantum_class == strength.QUANTUM_VULNERABLE]
    by_use: dict[str, list[CryptoAsset]] = {"key-establishment": [], "signature": [], "unknown": []}
    for a in vulnerable:
        by_use[_use(a)].append(a)

    endpoints = [a for a in inv.assets if a.kind == KIND_PROTOCOL]
    ep_class = {a.id: strength.assess(a).quantum_class for a in endpoints if a.key_exchange}
    classical_eps = [a for a in endpoints if ep_class.get(a.id) == strength.QUANTUM_VULNERABLE]
    hybrid_eps = [a for a in endpoints if ep_class.get(a.id) == strength.QUANTUM_HYBRID]
    pqc_eps = [a for a in endpoints if ep_class.get(a.id) == strength.QUANTUM_SAFE]

    broken_ids = {f.asset_id for f in inv.findings if f.rule_id in BROKEN_NOW_RULES}
    broken = [a for a in inv.assets if a.id in broken_ids]

    members: dict[str, tuple[list[CryptoAsset], list[CryptoAsset]]] = {
        "now": ([a for a in broken if a.kind != KIND_PROTOCOL], [a for a in broken if a.kind == KIND_PROTOCOL]),
        "key-establishment-2030": (by_use["key-establishment"], classical_eps),
        "signatures-2031": (by_use["signature"], []),
        "disallowed-2035": (vulnerable, classical_eps),
    }

    milestones = []
    for m in MILESTONES:
        assets, eps = members[m["id"]]
        due = m["date"]
        days_left = (due - day).days
        outlive = sum(1 for a in assets if a.expires and a.expires.date() > due)
        milestones.append({
            "id": m["id"],
            "date": due.isoformat(),
            "title": m["title"],
            "basis": m["basis"],
            "binding": m["binding"],
            "covers": m["covers"],
            "assets": len(assets),
            "endpoints": len(eps),
            "valid_past_date": outlive,
            "days_left": days_left,
            "past": days_left < 0,
            "asset_ids": sorted(a.id for a in assets) + sorted(a.id for a in eps),
        })  # fmt: skip

    src_rows: dict[str, list[int]] = {}
    for a in population:
        row = src_rows.setdefault(a.source, [0, 0])
        row[1] += 1
    for a in vulnerable:
        src_rows[a.source][0] += 1
    sources = sorted(
        ({"source": s, "vulnerable": v, "total": t, "percent": _pct(v, t)} for s, (v, t) in src_rows.items() if v),
        key=lambda r: (-r["vulnerable"], r["source"]),
    )

    total = len(population)
    nvuln = len(vulnerable)
    probed = len(ep_class)
    if total:
        headline = (f"{nvuln} of {total} keys and certificates ({_pct(nvuln, total)}%) use quantum-vulnerable "
                    "algorithms.")  # fmt: skip
    else:
        headline = "No keys or certificates were found."
    if probed:
        headline += (f" {len(classical_eps)} of {probed} probed endpoints still use classical key exchange"
                     f" ({len(hybrid_eps)} hybrid, {len(pqc_eps)} pure post-quantum).")  # fmt: skip
    nb = len(broken)
    if nb:
        headline += f" {nb} asset{'s' if nb != 1 else ''} already fail{'' if nb != 1 else 's'} today's rules."

    return {
        "as_of": day.isoformat(),
        "headline": headline,
        "keys_and_certificates": total,
        "quantum_vulnerable": nvuln,
        "quantum_vulnerable_percent": _pct(nvuln, total),
        "harvest_now_decrypt_later": len(by_use["key-establishment"]),
        "vulnerable_by_use": {k: len(v) for k, v in by_use.items()},
        "endpoints": {
            "probed": probed,
            "unprobed": len(endpoints) - probed,
            "classical": len(classical_eps),
            "hybrid": len(hybrid_eps),
            "post_quantum": len(pqc_eps),
        },
        "broken_now": nb,
        "milestones": milestones,
        "top_sources": sources[:5],
        "notes": [
            G7_NOTE,
            "Hybrid endpoints meet the key-establishment dates; NIST IR 8547 treats hybrids as temporary, "
            "so plan a second move to pure ML-KEM.",
        ],
    }
