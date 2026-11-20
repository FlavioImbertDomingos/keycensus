"""SARIF 2.1.0: findings for GitHub code scanning and any other SARIF viewer.

One rule per finding type, one result per finding. A finding on something in a file (a hard-coded key or a
weak call site found by the `code` collector, a key or certificate file found by `pem` or `files`) gets a
physical location: the file, and the line where the collector knows it. Paths under the directory keycensus
ran in are written relative to it, which is what GitHub code scanning expects when the scan runs from the
repository root; other paths are absolute `file://` URIs. Findings on keys in an HSM, a KMS or Vault have no
file, so they get a logical location (source and native id) instead.

Each result carries a partial fingerprint built from the rule and the asset id, so GitHub keeps one alert per
finding across runs.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .. import __version__
from ..model import Inventory, iso

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/FlavioImbertDomingos/keycensus"
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# GitHub: > 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low; 0 or absent means no security severity
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "2.0"}
_CODE = "code"
_FILE_SOURCES = {"pem", "files"}


def _uri(path: Path, cwd: Path) -> str:
    try:
        return path.resolve().relative_to(cwd).as_posix()
    except ValueError:
        return path.resolve().as_uri()


def _physical(path: Path, line: int | None, cwd: Path) -> dict[str, Any]:
    loc: dict[str, Any] = {"artifactLocation": {"uri": _uri(path, cwd)}}
    if line:
        loc["region"] = {"startLine": int(line)}
    return {"physicalLocation": loc}


def _locations(a, cwd: Path) -> list[dict[str, Any]]:
    """Physical locations for what lives in a file; a logical location for everything else."""
    out: list[dict[str, Any]] = []
    extra = a.extra or {}
    repo = extra.get("repository")
    if a.source_type == _CODE and repo:
        if extra.get("file"):
            out.append(_physical(Path(repo) / extra["file"], extra.get("line"), cwd))
        for o in extra.get("occurrences") or []:
            if o.get("file"):
                out.append(_physical(Path(repo) / o["file"], o.get("line"), cwd))
    elif a.source_type in _FILE_SOURCES and a.location:
        p = Path(str(a.location).split("#", 1)[0])
        if p.is_absolute():
            out.append(_physical(p, None, cwd))
    logical = {"name": a.name, "fullyQualifiedName": f"{a.source}/{a.native_id}", "kind": "resource"}
    if out:
        out[0]["logicalLocations"] = [logical]
        return out[:1000]
    return [{"logicalLocations": [logical]}]


def _rule(rule_id: str, findings: list, sources: set[str]) -> dict[str, Any]:
    first = findings[0]
    worst = min((f.severity for f in findings), key=lambda s: list(LEVEL).index(s) if s in LEVEL else 9)
    tags = ["security", "cryptography"] + sorted({c for f in findings for c in f.controls})
    props: dict[str, Any] = {"tags": tags[:20], "precision": "medium" if sources == {_CODE} else "high"}
    if worst in SECURITY_SEVERITY:
        props["security-severity"] = SECURITY_SEVERITY[worst]
    return {
        "id": rule_id,
        "name": "".join(w.capitalize() for w in rule_id.split("-")),
        "shortDescription": {"text": first.title[:1024]},
        "help": {"text": first.remediation or first.title},
        "defaultConfiguration": {"level": LEVEL.get(worst, "warning")},
        "properties": props,
    }


def render(inv: Inventory, cwd: str | Path | None = None) -> str:
    base = Path(cwd or Path.cwd()).resolve()
    assets = {a.id: a for a in inv.assets}
    by_rule: dict[str, list] = {}
    for f in inv.findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    rule_ids = sorted(by_rule)
    rules = [
        _rule(r, by_rule[r], {assets[f.asset_id].source_type for f in by_rule[r] if f.asset_id in assets})
        for r in rule_ids
    ]
    index = {r: i for i, r in enumerate(rule_ids)}
    results = []
    for f in inv.findings:
        a = assets.get(f.asset_id)
        locs = _locations(a, base) if a else [{"logicalLocations": [{"name": f.asset_name, "kind": "resource"}]}]
        fp = hashlib.sha256(f"{f.rule_id}|{f.asset_id}".encode()).hexdigest()[:32]
        props: dict[str, Any] = {"severity": f.severity, "asset_id": f.asset_id, "source": f.source,
                                 "verified": f.verified}  # fmt: skip
        if f.controls:
            props["controls"] = f.controls
        if f.policy:
            props["policy"] = f.policy
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": index[f.rule_id],
            "level": LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title}: {f.detail}" if f.detail else f.title},
            "locations": locs,
            "partialFingerprints": {"keycensusFinding/v1": fp},
            "properties": props,
        })  # fmt: skip
    log = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "keycensus", "version": __version__, "semanticVersion": __version__,
                                "informationUri": INFO_URI, "rules": rules}},
            # one category for every scan: a new policy version must not open a second set of alerts
            "automationDetails": {"id": "keycensus/"},
            "results": results,
            "properties": {"scan_status": inv.status, "generated_at": iso(inv.generated_at),
                           "policy": (inv.policy_pack or {}).get("ref") or inv.policy_name},
        }],
    }  # fmt: skip
    return json.dumps(log, indent=2)
