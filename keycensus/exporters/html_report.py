"""Self-contained HTML report: one file, no external assets, prints nicely."""

from __future__ import annotations

from importlib import resources

from jinja2 import Environment

from .. import __version__
from ..analysis import strength
from ..analysis.controls import describe
from ..linking import impact
from ..model import KIND_ALGORITHM, KIND_PROTOCOL, Inventory, iso

_Q_CSS = {
    strength.QUANTUM_VULNERABLE: "vuln",
    strength.QUANTUM_REDUCED: "reduced",
    strength.QUANTUM_SAFE: "safe",
    strength.QUANTUM_HYBRID: "hybrid",
    strength.QUANTUM_UNKNOWN: "",
}


def _env() -> Environment:
    env = Environment(autoescape=True)  # the report is HTML; never render unescaped
    return env


def render(inv: Inventory) -> str:
    template_text = resources.files("keycensus.templates").joinpath("report.html").read_text()
    tpl = _env().from_string(template_text)

    assets = []
    pqc = {"vulnerable": 0, "reduced": 0, "safe": 0, "unknown": 0, "total": 0}
    kex = {"classical": 0, "hybrid": 0, "pqc": 0, "unprobed": 0}
    for a in inv.assets:
        d = a.to_dict()
        s = strength.assess(a)
        probed = a.kind != KIND_PROTOCOL or a.key_exchange
        d["quantum_class"] = s.quantum_class if probed else "n/a"
        d["q_css"] = _Q_CSS.get(s.quantum_class, "") if probed else ""
        if a.kind == KIND_PROTOCOL:
            kex[{strength.QUANTUM_VULNERABLE: "classical", strength.QUANTUM_HYBRID: "hybrid",
                 strength.QUANTUM_SAFE: "pqc"}.get(s.quantum_class, "unprobed")] += 1  # fmt: skip
        d["created"] = (iso(a.created) or "")[:10] or None
        d["last_rotated"] = (iso(a.last_rotated) or "")[:10] or None
        d["expires"] = (iso(a.expires) or "")[:10] or None
        d["used_by_ids"] = [u.get("id", "") for u in a.used_by]
        assets.append(d)
        if a.kind not in (KIND_PROTOCOL, KIND_ALGORITHM):
            pqc["total"] += 1
            key = {
                strength.QUANTUM_VULNERABLE: "vulnerable",
                strength.QUANTUM_REDUCED: "reduced",
                strength.QUANTUM_SAFE: "safe",
            }.get(s.quantum_class, "unknown")
            pqc[key] += 1

    control_counts: dict[str, int] = {}
    for f in inv.findings:
        for c in f.controls:
            control_counts[c] = control_counts.get(c, 0) + 1
    controls = [
        {"id": cid, "count": n, **describe(cid)}
        for cid, n in sorted(control_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    control_titles = {cid: describe(cid)["title"] for cid in control_counts}

    return tpl.render(
        generated_at=iso(inv.generated_at),
        policy=(inv.policy_pack or {}).get("ref") or inv.policy_name,
        policy_pack=inv.policy_pack or {},
        summary=inv.summary(),
        findings=[f.to_dict() for f in inv.findings],
        assets=assets,
        sources=[
            {
                "name": s.name,
                "type": s.type,
                "assets": len(s.assets),
                "error": s.error,
                "status": s.status,
                "coverage": s.coverage.describe(),
                "optional_denied": sorted(s.coverage.optional_denied),
                "carried": s.carried,
                "duration_seconds": round(s.duration_seconds, 2),
            }
            for s in inv.sources
        ],
        scan_status=inv.status,
        pqc=pqc,
        executive=inv.executive(),
        kex=kex,
        applications=impact(inv),
        controls=controls,
        control_titles=control_titles,
        version=__version__,
        **_identity_context(inv),
        **_usage_context(inv),
    )


def _usage_context(inv) -> dict:
    """Observed use from the audit logs: per key and principal, authorised but unseen, unknown keys."""
    from ..usage import LOG_TITLES, rows  # noqa: PLC0415

    if not inv.usage:
        return {"usage": None}
    not_seen = [{"asset": a.name, "source": a.source, **u} for a in inv.assets
                for u in (a.observed_use or {}).get("authorized_not_seen") or []]  # fmt: skip
    idle = [{"asset": a.name, "source": a.source, "denied": a.observed_use.get("denied", 0)} for a in inv.assets
            if a.observed_use is not None and not a.observed_use.get("succeeded")]  # fmt: skip
    logs = [lg | {"title": LOG_TITLES.get(lg["type"], lg["type"])} for lg in inv.usage.get("logs") or []]
    return {"usage": {"logs": logs, "error": inv.usage.get("error"), "rows": rows(inv), "not_seen": not_seen,
                      "idle": idle, "window_days": inv.usage.get("window_days")}}  # fmt: skip


def _identity_context(inv) -> dict:
    """Identities seen in more than one place, and the relationships between identities, by name."""
    from ..identity import group, relationships  # noqa: PLC0415

    idents = group(inv.assets)
    names = {i.id: f"{i.name} ({i.kind})" for i in idents}
    return {
        "multi_place": [i.to_dict() for i in idents if i.places > 1],
        "relationships": [
            r | {"from_name": names.get(r["from"], r["from"]), "to_name": names.get(r["to"], r["to"])}
            for r in relationships(inv.assets, idents)
        ],  # fmt: skip
    }
