"""Change classification: turning a diff into something that can page someone.

`keycensus diff` answers "what changed". That is the right output for a human
reading a report, and the wrong input for an alerting system, which needs to know
*which* changes matter enough to wake someone at 3am and which ones belong in a
weekly digest.

So every raw field change is classified into a **kind** with an **urgency**:

    page      something got weaker, disappeared, or became reachable in a way it
              was not before. Someone should look now.
    digest    real, worth reviewing, not worth interrupting anyone. Weekly.
    ignore    noise, or good news (a key was rotated, a finding was resolved).

The classification is deliberately conservative about `page`: an alert that fires
on routine change teaches people to close the page without reading it, which is
worse than having no alert at all.

Both the kinds and their urgency are data, not code -- `DEFAULT_URGENCY` below is
the shipped opinion, and `changes.urgency` in the config overrides any entry:

    changes:
      urgency:
        consumer-added: page          # a new principal on a payment key IS a page here
        certificate-replaced: ignore  # we rotate these hourly, stop telling me

Feeds three consumers: the Prometheus exporter (`keycensus_change_total`), the
webhook notifier (`keycensus.notify`), and the `diff` command's own output.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .analysis import strength
from .diff import AssetChange, Diff
from .model import (
    STATE_COMPROMISED,
    STATE_DEACTIVATED,
    STATE_DESTROYED,
    CryptoAsset,
)

log = logging.getLogger(__name__)

PAGE = "page"
DIGEST = "digest"
IGNORE = "ignore"
URGENCIES = (PAGE, DIGEST, IGNORE)

# ---------------------------------------------------------------------------
#  The shipped opinion. Every kind keycensus can emit appears here exactly once;
#  `keycensus changes --kinds` prints this table so nobody has to read the source
#  to find out what a rule can fire on.
# ---------------------------------------------------------------------------
DEFAULT_URGENCY: dict[str, str] = {
    # --- the estate got weaker ------------------------------------------
    "algorithm-weakened": PAGE,
    "key-became-exportable": PAGE,
    "hardware-backing-lost": PAGE,
    "fips-validation-lost": PAGE,
    "rotation-disabled": PAGE,
    "protocol-weakened": PAGE,
    "state-compromised": PAGE,
    # --- the estate lost something ---------------------------------------
    "asset-removed": PAGE,
    "source-broken": PAGE,
    "source-removed": PAGE,
    # --- new problems ----------------------------------------------------
    "finding-new-critical": PAGE,
    "finding-new-high": PAGE,
    "finding-new": DIGEST,
    # --- real, but not urgent --------------------------------------------
    "asset-added": DIGEST,
    "asset-retired": DIGEST,
    "state-changed": DIGEST,
    "algorithm-changed": DIGEST,
    "certificate-replaced": DIGEST,
    "expiry-shortened": DIGEST,
    "consumer-added": DIGEST,
    "consumer-removed": DIGEST,
    "application-link-changed": DIGEST,
    "key-rotated": DIGEST,
    "source-added": DIGEST,
    # --- good news, or noise ---------------------------------------------
    "algorithm-strengthened": IGNORE,
    "hardware-backing-gained": IGNORE,
    "rotation-enabled": IGNORE,
    "finding-resolved": IGNORE,
    "source-fixed": IGNORE,
    "metadata-changed": IGNORE,
}

# Why each page-worthy kind is page-worthy. Shown in the alert annotation and in
# the webhook payload, because "why am I awake" is the first question.
WHY: dict[str, str] = {
    "algorithm-weakened": "Effective strength went down. Either something re-keyed to a weaker algorithm or a "
    "stronger key was replaced by a shorter one.",
    "key-became-exportable": "Private material that could not leave the module now can. This is the attribute an "
    "attacker changes before exfiltrating a key, and it is rarely changed on purpose.",
    "hardware-backing-lost": "A key that lived in an HSM is now software-held. Compliance scope changes with it.",
    "fips-validation-lost": "The key is no longer in a FIPS-validated module -- an audit finding as well as a "
    "security one.",
    "rotation-disabled": "Automatic rotation was turned off. Nothing breaks today; the cryptoperiod quietly "
    "becomes unbounded.",
    "protocol-weakened": "An endpoint started accepting a protocol version it previously refused.",
    "state-compromised": "A key was marked compromised. Everything it protects is now suspect.",
    "asset-removed": "A key or certificate that existed in the last scan is gone. Either it was deleted, or the "
    "source stopped reporting it -- both are worth knowing within minutes.",
    "source-broken": "A source that worked now errors, so the inventory is incomplete and every other alert on "
    "it is unreliable.",
    "source-removed": "A source disappeared from the configuration; its assets are no longer being watched.",
    "finding-new-critical": "A new critical finding -- typically an expired certificate in use or a broken algorithm.",
    "finding-new-high": "A new high-severity finding since the last scan.",
}


@dataclass
class Change:
    """One classified change. The unit both the exporter and the notifier count."""

    kind: str
    urgency: str
    summary: str
    asset_id: str = ""
    asset_name: str = ""
    source: str = ""
    asset_kind: str = ""
    field_name: str = ""
    before: Any = None
    after: Any = None
    applications: list[str] = field(default_factory=list)
    severity: str | None = None

    @property
    def why(self) -> str:
        return WHY.get(self.kind, "")

    def to_dict(self) -> dict[str, Any]:
        d = {
            "kind": self.kind,
            "urgency": self.urgency,
            "summary": self.summary,
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "source": self.source,
            "asset_kind": self.asset_kind,
            "field": self.field_name,
            "before": _plain(self.before),
            "after": _plain(self.after),
        }
        if self.applications:
            d["applications"] = self.applications
        if self.severity:
            d["severity"] = self.severity
        if self.why:
            d["why"] = self.why
        return d


def _plain(v: Any) -> Any:
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


# ---------------------------------------------------------------------------
#  Strength comparison
# ---------------------------------------------------------------------------
def _bits(asset_dict: dict) -> int | None:
    """Effective classical strength of an asset, or None when it cannot be judged."""
    try:
        return strength.assess(CryptoAsset.from_dict(asset_dict)).classical_bits
    except Exception as exc:  # a malformed baseline should not break alerting
        log.debug("strength assessment failed for %s: %s", asset_dict.get("id"), exc)
        return None


def _strength_direction(change: AssetChange, before: dict, after: dict) -> str:
    """weaker / stronger / same, from the fields that actually decide strength."""
    b, a = _bits(before), _bits(after)
    if b is None or a is None:
        # Fall back to key size within the same algorithm family, which is the
        # common case (RSA-3072 replaced by RSA-2048) and needs no table.
        bs, as_ = before.get("key_size"), after.get("key_size")
        if before.get("algorithm") == after.get("algorithm") and isinstance(bs, int) and isinstance(as_, int):
            return "weaker" if as_ < bs else "stronger" if as_ > bs else "same"
        return "same"
    return "weaker" if a < b else "stronger" if a > b else "same"


# ---------------------------------------------------------------------------
#  Classification
# ---------------------------------------------------------------------------
_STRENGTH_FIELDS = ("algorithm", "key_size", "curve")
_RETIRED_STATES = {STATE_DEACTIVATED, STATE_DESTROYED}


def classify(diff: Diff, urgency: dict[str, str] | None = None) -> list[Change]:
    """Diff -> classified changes, ordered page first."""
    table = dict(DEFAULT_URGENCY)
    for kind, level in (urgency or {}).items():
        if level not in URGENCIES:
            raise ValueError(f"changes.urgency[{kind}]: {level!r} is not one of {', '.join(URGENCIES)}")
        table[kind] = level

    out: list[Change] = []

    def emit(kind: str, summary: str, **kw) -> None:
        out.append(Change(kind=kind, urgency=table.get(kind, DIGEST), summary=summary, **kw))

    # --- assets that appeared -------------------------------------------
    for a in diff.added:
        emit(
            "asset-added",
            f"{a.get('source')}/{a.get('name')} appeared ({a.get('display_algorithm') or '?'})",
            asset_id=a.get("id", ""),
            asset_name=a.get("name", ""),
            source=a.get("source", ""),
            asset_kind=a.get("kind", ""),
            after=a.get("display_algorithm"),
        )

    # --- assets that vanished -------------------------------------------
    for a in diff.removed:
        # A key that was already deactivated or destroyed disappearing is
        # housekeeping. One that was ACTIVE disappearing is an incident until
        # proven otherwise.
        retired = a.get("state") in _RETIRED_STATES
        emit(
            "asset-retired" if retired else "asset-removed",
            f"{a.get('source')}/{a.get('name')} is gone"
            + (f" (was {a.get('state')})" if retired else " and was active at the last scan"),
            asset_id=a.get("id", ""),
            asset_name=a.get("name", ""),
            source=a.get("source", ""),
            asset_kind=a.get("kind", ""),
            before=a.get("state"),
            applications=list(a.get("applications") or []),
        )

    # --- assets that changed --------------------------------------------
    for c in diff.changed:
        out.extend(_classify_asset(c, table))

    # --- findings --------------------------------------------------------
    for f in diff.findings_new:
        sev = f.get("severity", "info")
        kind = f"finding-new-{sev}" if f"finding-new-{sev}" in table else "finding-new"
        emit(
            kind,
            f"new {sev} finding on {f.get('asset_name')}: {f.get('title')}",
            asset_id=f.get("asset_id", ""),
            asset_name=f.get("asset_name", ""),
            source=f.get("source", ""),
            severity=sev,
        )
    for f in diff.findings_resolved:
        emit(
            "finding-resolved",
            f"resolved on {f.get('asset_name')}: {f.get('title')}",
            asset_id=f.get("asset_id", ""),
            asset_name=f.get("asset_name", ""),
            source=f.get("source", ""),
            severity=f.get("severity"),
        )

    # --- sources ---------------------------------------------------------
    for s in diff.sources_broken:
        emit("source-broken", f"source {s.get('name')} is failing: {s.get('error')}", source=s.get("name", ""))
    for n in diff.sources_removed:
        emit("source-removed", f"source {n} is no longer configured", source=n)
    for n in diff.sources_added:
        emit("source-added", f"source {n} was added", source=n)
    for n in diff.sources_fixed:
        emit("source-fixed", f"source {n} is working again", source=n)

    rank = {PAGE: 0, DIGEST: 1, IGNORE: 2}
    out.sort(key=lambda c: (rank.get(c.urgency, 9), c.kind, c.source, c.asset_name))
    return out


def _classify_asset(c: AssetChange, table: dict[str, str]) -> list[Change]:
    """One asset's field changes -> zero or more classified changes."""
    out: list[Change] = []
    ch = c.changes

    def emit(kind: str, summary: str, fld: str = "", before=None, after=None) -> None:
        out.append(
            Change(
                kind=kind,
                urgency=table.get(kind, DIGEST),
                summary=summary,
                asset_id=c.id,
                asset_name=c.name,
                source=c.source,
                asset_kind=c.kind,
                field_name=fld,
                before=before,
                after=after,
            )
        )

    who = f"{c.source}/{c.name}"

    # Strength first: it is the change that matters most and it is decided by
    # three fields together, not one at a time.
    if any(f in ch for f in _STRENGTH_FIELDS):
        before = {f: ch[f]["before"] for f in _STRENGTH_FIELDS if f in ch}
        after = {f: ch[f]["after"] for f in _STRENGTH_FIELDS if f in ch}
        # _strength_direction wants whole assets; give it the fields it reads.
        b_asset = {"algorithm": ch.get("algorithm", {}).get("before"), "key_size": ch.get("key_size", {}).get("before"),
                   "curve": ch.get("curve", {}).get("before"), "kind": c.kind}  # fmt: skip
        a_asset = {"algorithm": ch.get("algorithm", {}).get("after"), "key_size": ch.get("key_size", {}).get("after"),
                   "curve": ch.get("curve", {}).get("after"), "kind": c.kind}  # fmt: skip
        for f in _STRENGTH_FIELDS:  # unchanged fields keep their value on both sides
            if f not in ch:
                b_asset[f] = a_asset[f] = None
        direction = _strength_direction(c, b_asset, a_asset)
        kind = {"weaker": "algorithm-weakened", "stronger": "algorithm-strengthened"}.get(
            direction, "algorithm-changed"
        )
        emit(kind, f"{who}: {_fmt(before)} -> {_fmt(after)}", "algorithm", before, after)

    # Attribute flips, each with its own kind so a rule can target one.
    flips = {
        "exportable": ("key-became-exportable", "metadata-changed", "can now be exported", "is no longer exportable"),
        "hardware_backed": ("hardware-backing-gained", "hardware-backing-lost", "moved into hardware", "left hardware"),
        "fips_validated": ("metadata-changed", "fips-validation-lost", "is FIPS validated", "lost FIPS validation"),
        "rotation_enabled": ("rotation-enabled", "rotation-disabled", "rotation enabled", "rotation DISABLED"),
    }
    for fld, (on_true, on_false, said_true, said_false) in flips.items():
        if fld not in ch:
            continue
        before, after = ch[fld]["before"], ch[fld]["after"]
        if bool(after) and not bool(before):
            emit(on_true, f"{who} {said_true}", fld, before, after)
        elif bool(before) and not bool(after):
            emit(on_false, f"{who} {said_false}", fld, before, after)

    if "state" in ch:
        before, after = ch["state"]["before"], ch["state"]["after"]
        if after == STATE_COMPROMISED:
            emit("state-compromised", f"{who} was marked COMPROMISED", "state", before, after)
        elif after in _RETIRED_STATES:
            emit("asset-retired", f"{who} moved to {after}", "state", before, after)
        else:
            emit("state-changed", f"{who}: state {before} -> {after}", "state", before, after)

    if "weak_versions_accepted" in ch:
        before = set(ch["weak_versions_accepted"]["before"] or [])
        after = set(ch["weak_versions_accepted"]["after"] or [])
        if after - before:
            emit(
                "protocol-weakened",
                f"{who} now accepts {', '.join(sorted(after - before))}",
                "weak_versions_accepted",
                sorted(before),
                sorted(after),
            )

    if "fingerprint_sha256" in ch:
        emit("certificate-replaced", f"{who} was replaced (new fingerprint)", "fingerprint_sha256")

    if "expires" in ch:
        before, after = ch["expires"]["before"], ch["expires"]["after"]
        if _shortened(before, after):
            emit("expiry-shortened", f"{who} now expires sooner: {before} -> {after}", "expires", before, after)

    if "last_rotated" in ch:
        emit("key-rotated", f"{who} was rotated", "last_rotated",
             ch["last_rotated"]["before"], ch["last_rotated"]["after"])  # fmt: skip

    if "used_by" in ch:
        before = {_ident(u) for u in (ch["used_by"]["before"] or [])}
        after = {_ident(u) for u in (ch["used_by"]["after"] or [])}
        if after - before:
            emit("consumer-added", f"{who}: new consumer(s) {', '.join(sorted(after - before))}",
                 "used_by", sorted(before), sorted(after))  # fmt: skip
        if before - after:
            emit("consumer-removed", f"{who}: consumer(s) gone {', '.join(sorted(before - after))}",
                 "used_by", sorted(before), sorted(after))  # fmt: skip

    if "applications" in ch:
        emit("application-link-changed", f"{who}: applications {_fmt(ch['applications']['before'])} -> "
             f"{_fmt(ch['applications']['after'])}", "applications",
             ch["applications"]["before"], ch["applications"]["after"])  # fmt: skip

    for fld in ("name", "location", "purposes", "signature_hash", "protocol_version"):
        if fld in ch and not any(o.field_name == fld for o in out):
            emit("metadata-changed", f"{who}: {fld} changed", fld, ch[fld]["before"], ch[fld]["after"])

    return out


def _ident(u: Any) -> str:
    return str(u.get("id", u)) if isinstance(u, dict) else str(u)


def _shortened(before: Any, after: Any) -> bool:
    try:
        b = datetime.fromisoformat(str(before).replace("Z", "+00:00"))
        a = datetime.fromisoformat(str(after).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return False
    return a < b


def _fmt(v: Any) -> str:
    if isinstance(v, dict):
        return ", ".join(f"{k}={v[k]}" for k in sorted(v) if v[k] is not None) or "∅"
    if isinstance(v, list):
        return ", ".join(map(str, v)) or "∅"
    return "∅" if v is None else str(v)


# ---------------------------------------------------------------------------
#  Views
# ---------------------------------------------------------------------------
def summarize(changes: list[Change]) -> dict[str, Any]:
    by_urgency = {u: 0 for u in URGENCIES}
    by_kind: dict[str, int] = {}
    for c in changes:
        by_urgency[c.urgency] = by_urgency.get(c.urgency, 0) + 1
        by_kind[c.kind] = by_kind.get(c.kind, 0) + 1
    return {
        "total": len(changes),
        "by_urgency": by_urgency,
        "by_kind": dict(sorted(by_kind.items())),
        "page_worthy": [c.to_dict() for c in changes if c.urgency == PAGE],
    }


def render_text(changes: list[Change], include_ignored: bool = False) -> str:
    shown = [c for c in changes if include_ignored or c.urgency != IGNORE]
    if not shown:
        return "no changes worth reporting\n"
    lines: list[str] = []
    for urgency in URGENCIES:
        group = [c for c in shown if c.urgency == urgency]
        if not group:
            continue
        lines += ["", f"{urgency.upper()} ({len(group)}):"]
        for c in group:
            lines.append(f"  [{c.kind}] {c.summary}")
            if urgency == PAGE and c.why:
                lines.append(f"      why: {c.why}")
    return "\n".join(lines).lstrip("\n") + "\n"


def kinds_table() -> str:
    """`keycensus changes --kinds`: every kind this build can emit, and its default urgency."""
    width = max(len(k) for k in DEFAULT_URGENCY)
    lines = [f"{'kind'.ljust(width)}  urgency  why", f"{'-' * width}  -------  ---"]
    for kind, urgency in sorted(DEFAULT_URGENCY.items(), key=lambda kv: (URGENCIES.index(kv[1]), kv[0])):
        lines.append(f"{kind.ljust(width)}  {urgency.ljust(7)}  {WHY.get(kind, '')}")
    return "\n".join(lines) + "\n"
