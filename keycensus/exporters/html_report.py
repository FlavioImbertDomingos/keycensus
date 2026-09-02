"""Self-contained HTML report: one file, no external assets, prints nicely."""

from __future__ import annotations

from importlib import resources

from jinja2 import Environment, select_autoescape

from .. import __version__
from ..analysis import strength
from ..analysis.controls import describe
from ..model import KIND_PROTOCOL, Inventory, iso

_Q_CSS = {
    strength.QUANTUM_VULNERABLE: "vuln",
    strength.QUANTUM_REDUCED: "reduced",
    strength.QUANTUM_SAFE: "safe",
    strength.QUANTUM_UNKNOWN: "",
}


def _env() -> Environment:
    env = Environment(autoescape=select_autoescape(["html"]))
    return env


def render(inv: Inventory) -> str:
    template_text = resources.files("keycensus.templates").joinpath("report.html").read_text()
    tpl = _env().from_string(template_text)

    assets = []
    pqc = {"vulnerable": 0, "reduced": 0, "safe": 0, "unknown": 0, "total": 0}
    for a in inv.assets:
        d = a.to_dict()
        s = strength.assess(a)
        d["quantum_class"] = s.quantum_class if a.kind != KIND_PROTOCOL else "n/a"
        d["q_css"] = _Q_CSS.get(s.quantum_class, "") if a.kind != KIND_PROTOCOL else ""
        d["created"] = (iso(a.created) or "")[:10] or None
        d["last_rotated"] = (iso(a.last_rotated) or "")[:10] or None
        d["expires"] = (iso(a.expires) or "")[:10] or None
        assets.append(d)
        if a.kind != KIND_PROTOCOL:
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
        policy=inv.policy_name,
        summary=inv.summary(),
        findings=[f.to_dict() for f in inv.findings],
        assets=assets,
        sources=[
            {
                "name": s.name,
                "type": s.type,
                "assets": len(s.assets),
                "error": s.error,
                "duration_seconds": round(s.duration_seconds, 2),
            }
            for s in inv.sources
        ],
        pqc=pqc,
        controls=controls,
        control_titles=control_titles,
        version=__version__,
    )
