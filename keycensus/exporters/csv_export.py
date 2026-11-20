import csv
import io

from ..analysis import strength
from ..model import Inventory

COLUMNS = [
    "id", "source", "source_type", "kind", "name", "algorithm", "key_size", "curve", "key_type",
    "purposes", "created", "last_rotated", "expires", "age_days", "days_until_expiry", "state",
    "rotation_enabled", "exportable", "hardware_backed", "fips_validated", "fips_standard", "fips_level",
    "fips_certificate", "classical_bits", "observed", "last_observed",
    "quantum_class", "signature_hash", "subject", "issuer", "protocol_version", "cipher_suites",
    "key_exchange",
    "location", "applications", "used_by", "observed_use", "findings",
]  # fmt: skip


def _observed(u: dict | None) -> str:
    """Empty: no log covers the key. 'none': covered, nobody used it. Else principal(calls) ..."""
    if u is None:
        return ""
    used = [f"{p['id']}({sum(p['operations'].values())})" for p in u.get("principals") or [] if p["operations"]]
    return " ".join(used) or "none"


def render(inv: Inventory) -> str:
    by_asset: dict[str, list[str]] = {}
    for f in inv.findings:
        by_asset.setdefault(f.asset_id, []).append(f"{f.severity}:{f.rule_id}")
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS, extrasaction="ignore")
    w.writeheader()
    for a in inv.assets:
        d = a.to_dict()
        s = strength.assess(a)
        d["purposes"] = " ".join(a.purposes)
        d["cipher_suites"] = " ".join(a.cipher_suites)
        d["classical_bits"] = s.classical_bits
        d["quantum_class"] = s.quantum_class
        d["applications"] = " ".join(a.applications)
        d["used_by"] = " ".join(u.get("id", "") for u in a.used_by)
        d["observed_use"] = _observed(a.observed_use)
        d["findings"] = " ".join(by_asset.get(a.id, []))
        for k in ("standard", "level", "certificate"):
            d[f"fips_{k}"] = (a.fips_evidence or {}).get(k)
        w.writerow(d)
    return buf.getvalue()
