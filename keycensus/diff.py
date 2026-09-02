"""Diff mode: what changed between two scans.

Works on the `inventory.json` files the JSON exporter writes (or on `Inventory` objects),
matching assets by their stable `id` (source + kind + native id) and findings by
`(rule_id, asset_id)`. Answers the four questions an auditor asks:

* what appeared / disappeared (new keys, deleted certificates, a source that vanished),
* what changed on the things that stayed (state, expiry, rotation, algorithm, purposes ...),
* which findings are new and which were fixed,
* did a source stop working.

    keycensus diff out/previous/inventory.json out/inventory.json [--format text|markdown|json]
    keycensus scan ... --baseline out/previous/inventory.json      # writes diff.json + diff.md too
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .model import SEVERITIES, Inventory

# Fields worth reporting when they change on an asset that exists in both scans.
WATCHED = (
    "state",
    "algorithm",
    "key_size",
    "curve",
    "expires",
    "last_rotated",
    "rotation_enabled",
    "exportable",
    "hardware_backed",
    "fips_validated",
    "purposes",
    "signature_hash",
    "protocol_version",
    "weak_versions_accepted",
    "fingerprint_sha256",
    "location",
    "name",
)


@dataclass
class AssetChange:
    id: str
    name: str
    source: str
    kind: str
    algorithm: str
    changes: dict[str, dict[str, Any]] = field(default_factory=dict)  # field -> {before, after}


@dataclass
class Diff:
    before_generated_at: str | None
    after_generated_at: str | None
    added: list[dict] = field(default_factory=list)  # asset dicts
    removed: list[dict] = field(default_factory=list)
    changed: list[AssetChange] = field(default_factory=list)
    findings_new: list[dict] = field(default_factory=list)
    findings_resolved: list[dict] = field(default_factory=list)
    sources_added: list[str] = field(default_factory=list)
    sources_removed: list[str] = field(default_factory=list)
    sources_broken: list[dict] = field(default_factory=list)  # ok before, error now
    sources_fixed: list[str] = field(default_factory=list)

    # ------------------------------------------------------------ views
    @property
    def empty(self) -> bool:
        return not any(
            (
                self.added,
                self.removed,
                self.changed,
                self.findings_new,
                self.findings_resolved,
                self.sources_added,
                self.sources_removed,
                self.sources_broken,
                self.sources_fixed,
            )
        )

    def worst_new_severity(self) -> str | None:
        rank = {s: i for i, s in enumerate(SEVERITIES)}
        sev = [f["severity"] for f in self.findings_new if f.get("severity") in rank]
        return min(sev, key=lambda s: rank[s]) if sev else None

    def summary(self) -> dict[str, Any]:
        by_sev = {s: 0 for s in SEVERITIES}
        for f in self.findings_new:
            if f.get("severity") in by_sev:
                by_sev[f["severity"]] += 1
        return {
            "assets_added": len(self.added),
            "assets_removed": len(self.removed),
            "assets_changed": len(self.changed),
            "findings_new": len(self.findings_new),
            "findings_new_by_severity": by_sev,
            "findings_resolved": len(self.findings_resolved),
            "sources_added": len(self.sources_added),
            "sources_removed": len(self.sources_removed),
            "sources_broken": len(self.sources_broken),
            "sources_fixed": len(self.sources_fixed),
            "worst_new_severity": self.worst_new_severity(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "keycensus-diff",
            "before": self.before_generated_at,
            "after": self.after_generated_at,
            "summary": self.summary(),
            "assets_added": [_brief(a) for a in self.added],
            "assets_removed": [_brief(a) for a in self.removed],
            "assets_changed": [asdict(c) for c in self.changed],
            "findings_new": self.findings_new,
            "findings_resolved": self.findings_resolved,
            "sources": {
                "added": self.sources_added,
                "removed": self.sources_removed,
                "broken": self.sources_broken,
                "fixed": self.sources_fixed,
            },
        }


def _brief(a: dict) -> dict:
    return {
        k: a.get(k)
        for k in ("id", "name", "source", "source_type", "kind", "display_algorithm", "state", "expires", "location")
    }


# ------------------------------------------------------------------ core
def load_inventory_dict(path: str | Path) -> dict:
    with open(path) as fh:
        data = json.load(fh)
    if data.get("tool") != "keycensus" or "assets" not in data:
        raise ValueError(f"{path}: not a keycensus inventory.json")
    return data


def diff_dicts(before: dict, after: dict) -> Diff:
    """Compare two inventory.json documents (already parsed)."""
    b_assets = {a["id"]: a for a in before.get("assets", [])}
    a_assets = {a["id"]: a for a in after.get("assets", [])}
    d = Diff(before_generated_at=before.get("generated_at"), after_generated_at=after.get("generated_at"))

    for aid in a_assets.keys() - b_assets.keys():
        d.added.append(a_assets[aid])
    for aid in b_assets.keys() - a_assets.keys():
        d.removed.append(b_assets[aid])
    for aid in a_assets.keys() & b_assets.keys():
        old, new = b_assets[aid], a_assets[aid]
        changes = {}
        for f in WATCHED:
            ov, nv = old.get(f), new.get(f)
            if isinstance(ov, list) and isinstance(nv, list):
                ov, nv = sorted(map(str, ov)), sorted(map(str, nv))
            if ov != nv:
                changes[f] = {"before": old.get(f), "after": new.get(f)}
        if changes:
            d.changed.append(
                AssetChange(
                    id=aid,
                    name=new.get("name", ""),
                    source=new.get("source", ""),
                    kind=new.get("kind", ""),
                    algorithm=new.get("display_algorithm", ""),
                    changes=changes,
                )
            )

    def fkey(f: dict) -> tuple[str, str]:
        return (f.get("rule_id", ""), f.get("asset_id", ""))

    b_find = {fkey(f): f for f in before.get("findings", [])}
    a_find = {fkey(f): f for f in after.get("findings", [])}
    d.findings_new = [a_find[k] for k in a_find.keys() - b_find.keys()]
    d.findings_resolved = [b_find[k] for k in b_find.keys() - a_find.keys()]

    b_src = {s["name"]: s for s in before.get("sources", [])}
    a_src = {s["name"]: s for s in after.get("sources", [])}
    d.sources_added = sorted(a_src.keys() - b_src.keys())
    d.sources_removed = sorted(b_src.keys() - a_src.keys())
    for name in sorted(a_src.keys() & b_src.keys()):
        was_ok, is_ok = not b_src[name].get("error"), not a_src[name].get("error")
        if was_ok and not is_ok:
            d.sources_broken.append({"name": name, "error": a_src[name].get("error")})
        elif not was_ok and is_ok:
            d.sources_fixed.append(name)

    # deterministic order: by severity, then name
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    d.findings_new.sort(key=lambda f: (rank.get(f.get("severity"), 99), f.get("asset_name", "")))
    d.findings_resolved.sort(key=lambda f: (rank.get(f.get("severity"), 99), f.get("asset_name", "")))
    d.added.sort(key=lambda a: (a.get("source", ""), a.get("name", "")))
    d.removed.sort(key=lambda a: (a.get("source", ""), a.get("name", "")))
    d.changed.sort(key=lambda c: (c.source, c.name))
    return d


def diff_files(before: str | Path, after: str | Path) -> Diff:
    return diff_dicts(load_inventory_dict(before), load_inventory_dict(after))


def diff_inventories(before: Inventory | dict, after: Inventory) -> Diff:
    b = before.to_dict() if isinstance(before, Inventory) else before
    return diff_dicts(b, after.to_dict())


# ------------------------------------------------------------------ rendering
def render_text(d: Diff) -> str:
    s = d.summary()
    lines = [f"keycensus diff: {d.before_generated_at or '?'} -> {d.after_generated_at or '?'}", ""]
    if d.empty:
        lines.append("no changes")
        return "\n".join(lines) + "\n"
    lines.append(
        f"assets: +{s['assets_added']} -{s['assets_removed']} ~{s['assets_changed']}    "
        f"findings: +{s['findings_new']} resolved {s['findings_resolved']}"
        + (f"    worst new: {s['worst_new_severity']}" if s["worst_new_severity"] else "")
    )
    for label, items in (("added", d.added), ("removed", d.removed)):
        if items:
            lines += ["", f"{label} ({len(items)}):"]
            lines += [
                f"  + {a['source']}/{a['name']} [{a.get('display_algorithm')}] {a.get('state', '')}".rstrip()
                if label == "added"
                else f"  - {a['source']}/{a['name']} [{a.get('display_algorithm')}]"
                for a in items
            ]
    if d.changed:
        lines += ["", f"changed ({len(d.changed)}):"]
        for c in d.changed:
            lines.append(f"  ~ {c.source}/{c.name} [{c.algorithm}]")
            for fld, ch in c.changes.items():
                lines.append(f"      {fld}: {_fmt(ch['before'])} -> {_fmt(ch['after'])}")
    if d.findings_new:
        lines += ["", f"new findings ({len(d.findings_new)}):"]
        lines += [f"  ! [{f['severity']:8}] {f['asset_name']} — {f['title']}" for f in d.findings_new]
    if d.findings_resolved:
        lines += ["", f"resolved findings ({len(d.findings_resolved)}):"]
        lines += [f"  ✓ [{f['severity']:8}] {f['asset_name']} — {f['title']}" for f in d.findings_resolved]
    if d.sources_broken or d.sources_fixed or d.sources_added or d.sources_removed:
        lines += ["", "sources:"]
        lines += [f"  BROKEN {b['name']}: {b['error']}" for b in d.sources_broken]
        lines += [f"  fixed  {n}" for n in d.sources_fixed]
        lines += [f"  added  {n}" for n in d.sources_added]
        lines += [f"  removed {n}" for n in d.sources_removed]
    return "\n".join(lines) + "\n"


def render_markdown(d: Diff) -> str:
    s = d.summary()
    out = ["# keycensus diff", "", f"`{d.before_generated_at or '?'}` → `{d.after_generated_at or '?'}`", ""]
    if d.empty:
        out.append("**No changes.**")
        return "\n".join(out) + "\n"
    out += [
        "| Assets added | Assets removed | Assets changed | New findings | Resolved findings | Worst new |",
        "|---|---|---|---|---|---|",
        f"| {s['assets_added']} | {s['assets_removed']} | {s['assets_changed']} | {s['findings_new']} | "
        f"{s['findings_resolved']} | {s['worst_new_severity'] or '-'} |",
        "",
    ]
    if d.findings_new:
        out += ["## New findings", "", "| Severity | Asset | Finding | Source |", "|---|---|---|---|"]
        out += [f"| {f['severity']} | {f['asset_name']} | {f['title']} | {f['source']} |" for f in d.findings_new]
        out.append("")
    if d.findings_resolved:
        out += ["## Resolved findings", "", "| Severity | Asset | Finding |", "|---|---|---|"]
        out += [f"| {f['severity']} | {f['asset_name']} | {f['title']} |" for f in d.findings_resolved]
        out.append("")
    if d.added:
        out += ["## Assets added", "", "| Source | Asset | Algorithm | State |", "|---|---|---|---|"]
        out += [f"| {a['source']} | {a['name']} | {a.get('display_algorithm')} | {a.get('state')} |" for a in d.added]
        out.append("")
    if d.removed:
        out += ["## Assets removed", "", "| Source | Asset | Algorithm |", "|---|---|---|"]
        out += [f"| {a['source']} | {a['name']} | {a.get('display_algorithm')} |" for a in d.removed]
        out.append("")
    if d.changed:
        out += ["## Assets changed", "", "| Source | Asset | Field | Before | After |", "|---|---|---|---|---|"]
        for c in d.changed:
            for fld, ch in c.changes.items():
                out.append(f"| {c.source} | {c.name} | {fld} | {_fmt(ch['before'])} | {_fmt(ch['after'])} |")
        out.append("")
    if d.sources_broken or d.sources_fixed or d.sources_added or d.sources_removed:
        out += ["## Sources", ""]
        out += [f"- **BROKEN** `{b['name']}`: {b['error']}" for b in d.sources_broken]
        out += [f"- fixed `{n}`" for n in d.sources_fixed]
        out += [f"- added `{n}`" for n in d.sources_added]
        out += [f"- removed `{n}`" for n in d.sources_removed]
        out.append("")
    return "\n".join(out) + "\n"


def render_json(d: Diff) -> str:
    return json.dumps(d.to_dict(), indent=2, default=str) + "\n"


RENDERERS = {"text": render_text, "markdown": render_markdown, "json": render_json}


def _fmt(v: Any) -> str:
    if v is None:
        return "∅"
    if isinstance(v, list):
        return ", ".join(map(str, v)) or "∅"
    return str(v)
