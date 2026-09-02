"""SBOM <-> CBOM linking: which application uses which key.

A CBOM tells you *what* cryptography you have; an SBOM tells you *what software* you run.
The question that matters in an incident ("this key is weak / expiring / compromised --
which applications break?") needs the edge between the two. keycensus builds that edge
from two kinds of evidence:

1. **Inferred consumers** -- what the key store itself knows: AWS KMS grants and key-policy
   principals, GCP KMS IAM bindings, Vault ACL policies that grant `transit/<op>/<key>`,
   CipherTrust `application` / owner. Collectors put these on `asset.used_by`.
2. **Declared applications** -- an `applications:` list in the config, each optionally backed by
   a CycloneDX SBOM (name, version, purl and bom-ref are taken from `metadata.component`), with
   selectors saying which assets it uses:

       applications:
         - name: payments-api
           sbom: sboms/payments-api.cdx.json      # optional CycloneDX SBOM
           owner: payments-team
           uses:
             - {source: luna-payments, name: "pan-*"}          # AND within an entry, OR across entries
             - {tag: {app: payments}}
             - {principal: "arn:aws:iam::*:role/payments-api*"} # matches inferred used_by ids
             - {kind: certificate, name: "*.payments.example.com"}

   Plus automatic matching (`auto_match: true`, the default): an asset whose inferred consumer
   ids contain the application's name (as a word) is linked with reason `auto:used_by`.

Output: `asset.applications`, `Application.asset_ids` / `matches`, an `unlinked-asset`
finding (info) for assets no application claims when applications are declared, and in the
CBOM an `application` component per application with `dependencies` on its crypto assets --
Dependency-Track and other CycloneDX consumers then show the dependency graph.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import re
from pathlib import Path
from typing import Any

from .analysis.policy import Policy
from .model import Application, CryptoAsset, Finding, Inventory

log = logging.getLogger(__name__)

SELECTOR_KEYS = {"source", "source_type", "name", "native_id", "kind", "algorithm", "tag", "principal", "used_by", "id"}


class LinkingError(Exception):
    pass


# ------------------------------------------------------------------ config -> applications
def load_applications(entries: list[dict] | None, base_dir: str | Path | None = None) -> list[Application]:
    apps: list[Application] = []
    seen = set()
    for raw in entries or []:
        if not isinstance(raw, dict):
            raise LinkingError(f"applications entries must be mappings: {raw!r}")
        app = Application(
            name=str(raw.get("name") or ""),
            version=_str_or_none(raw.get("version")),
            purl=_str_or_none(raw.get("purl")),
            bom_ref=_str_or_none(raw.get("bom_ref")),
            owner=_str_or_none(raw.get("owner")),
            description=_str_or_none(raw.get("description")),
            uses=[u for u in (raw.get("uses") or []) if isinstance(u, dict)],
        )
        for u in app.uses:
            bad = set(u) - SELECTOR_KEYS
            if bad:
                raise LinkingError(f"application {app.name or '?'}: unknown selector key(s) {sorted(bad)}")
        if raw.get("sbom"):
            path = Path(raw["sbom"])
            if base_dir and not path.is_absolute():
                path = Path(base_dir) / path
            _apply_sbom(app, path)
        if not app.name:
            raise LinkingError("every application needs a name (or an SBOM whose metadata.component has one)")
        if app.name in seen:
            raise LinkingError(f"duplicate application name {app.name!r}")
        seen.add(app.name)
        apps.append(app)
    return apps


def read_sbom(path: str | Path) -> dict:
    """Load a CycloneDX JSON SBOM; raise LinkingError with a useful message otherwise."""
    p = Path(path)
    try:
        doc = json.loads(p.read_text())
    except OSError as exc:
        raise LinkingError(f"cannot read SBOM {p}: {exc}") from exc
    except ValueError as exc:
        raise LinkingError(f"{p} is not JSON: {exc} (SPDX / XML SBOMs are not supported yet)") from exc
    if doc.get("bomFormat") != "CycloneDX":
        raise LinkingError(f"{p}: not a CycloneDX BOM (bomFormat={doc.get('bomFormat')!r})")
    return doc


def _apply_sbom(app: Application, path: Path) -> None:
    doc = read_sbom(path)
    comp = (doc.get("metadata") or {}).get("component") or {}
    app.sbom_path = str(path)
    app.sbom_serial = doc.get("serialNumber")
    app.sbom_components = len(doc.get("components") or [])
    app.name = app.name or str(comp.get("name") or path.stem)
    app.version = app.version or _str_or_none(comp.get("version"))
    app.purl = app.purl or _str_or_none(comp.get("purl"))
    app.bom_ref = app.bom_ref or _str_or_none(comp.get("bom-ref"))
    app.description = app.description or _str_or_none(comp.get("description"))
    if not app.owner:
        supplier = comp.get("supplier") or {}
        app.owner = _str_or_none(supplier.get("name")) if isinstance(supplier, dict) else None


def _str_or_none(v) -> str | None:
    return str(v) if v not in (None, "") else None


# ------------------------------------------------------------------ matching
def _glob(pattern: str, value: str | None) -> bool:
    if value is None:
        return False
    return fnmatch.fnmatchcase(value, pattern) or fnmatch.fnmatchcase(value.lower(), pattern.lower())


def selector_matches(sel: dict[str, Any], asset: CryptoAsset) -> str | None:
    """Return a human reason when every key in the selector matches the asset, else None."""
    reasons = []
    for key, want in sel.items():
        if key == "tag":
            tags = want if isinstance(want, dict) else {}
            if not all(_glob(str(v), asset.tags.get(k)) for k, v in tags.items()):
                return None
            reasons.append("tag " + ",".join(f"{k}={v}" for k, v in tags.items()))
        elif key in ("principal", "used_by"):
            ids = [u.get("id", "") for u in asset.used_by]
            hit = next((i for i in ids if _glob(str(want), i)), None)
            if hit is None:
                return None
            reasons.append(f"used_by {hit}")
        elif key == "id":
            if not _glob(str(want), asset.id):
                return None
            reasons.append(f"id {asset.id}")
        else:
            actual = getattr(asset, key, None)
            if not _glob(str(want), actual if actual is None else str(actual)):
                return None
            reasons.append(f"{key} {actual}")
    return " & ".join(reasons) if reasons else None


_WORD = re.compile(r"[A-Za-z0-9]+")


def _auto_match(app: Application, asset: CryptoAsset) -> str | None:
    """Link when an inferred consumer id contains the application name as a whole token."""
    name = app.name.lower()
    tokens = {t.lower() for t in _WORD.findall(app.name)}
    for u in asset.used_by:
        ident = str(u.get("id", ""))
        low = ident.lower()
        if name in low.replace("_", "-") or (tokens and tokens <= {t.lower() for t in _WORD.findall(ident)}):
            return f"auto:used_by {ident}"
    return None


def link(inv: Inventory, apps: list[Application], auto_match: bool = True) -> list[Application]:
    """Attach applications to assets (and vice versa). Idempotent."""
    for a in inv.assets:
        a.applications = []
    for app in apps:
        app.asset_ids, app.matches = [], {}
        for a in inv.assets:
            reasons = [r for r in (selector_matches(sel, a) for sel in app.uses) if r]
            if auto_match:
                r = _auto_match(app, a)
                if r:
                    reasons.append(r)
            if reasons:
                app.asset_ids.append(a.id)
                app.matches[a.id] = reasons
                a.applications.append(app.name)
    inv.applications = apps
    for app in apps:
        log.info("[link] %s%s: %d asset(s)", app.name, f"@{app.version}" if app.version else "", len(app.asset_ids))
    return apps


def unlinked_findings(inv: Inventory, policy: Policy) -> list[Finding]:
    """`unlinked-asset` (info by default): keys/certs no application claims -- only when apps are declared."""
    if not inv.applications or not policy.enabled("unlinked-asset"):
        return []
    out = []
    for a in inv.assets:
        if a.applications or a.kind == "protocol" or (a.kind == "key" and a.key_type == "public-key"):
            continue  # protocols aren't owned; public halves of key pairs are reported via their private key
        out.append(
            Finding(
                rule_id="unlinked-asset",
                severity=policy.severity("unlinked-asset", "info"),
                title="No application is linked to this asset",
                detail=f"{a.name} in {a.source} is not claimed by any of the {len(inv.applications)} "
                "declared application(s)"
                + (f"; inferred consumers: {', '.join(u['id'] for u in a.used_by[:5])}" if a.used_by else "")
                + ".",
                remediation="Add a selector under an application's `uses:` (or an SBOM whose consumers match), "
                "or retire the key if nothing uses it.",
                asset_id=a.id,
                asset_name=a.name,
                source=a.source,
                controls=["PCI-DSS-4.0:12.3.3"],
            )
        )
    return out


def apply(inv: Inventory, entries: list[dict] | None, policy: Policy, base_dir=None, auto_match: bool = True) -> None:
    """Config -> applications -> links -> findings, in one call (used by scan and link)."""
    apps = load_applications(entries, base_dir)
    if not apps:
        return
    link(inv, apps, auto_match=auto_match)
    inv.findings = [f for f in inv.findings if f.rule_id != "unlinked-asset"] + unlinked_findings(inv, policy)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    inv.findings.sort(key=lambda f: (order.get(f.severity, 9), f.source, f.asset_name))


# ------------------------------------------------------------------ views
def impact(inv: Inventory) -> list[dict[str, Any]]:
    """Per application: assets, worst finding severity, counts -- the 'blast radius' table."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    by_asset: dict[str, list[Finding]] = {}
    for f in inv.findings:
        by_asset.setdefault(f.asset_id, []).append(f)
    out = []
    for app in inv.applications:
        sev = [f.severity for aid in app.asset_ids for f in by_asset.get(aid, [])]
        worst = min(sev, key=lambda s: order.get(s, 9)) if sev else None
        out.append(
            {
                "name": app.name,
                "version": app.version,
                "owner": app.owner,
                "purl": app.purl,
                "sbom": app.sbom_path,
                "assets": len(app.asset_ids),
                "findings": len(sev),
                "worst_severity": worst,
                "asset_ids": app.asset_ids,
            }
        )
    return out
