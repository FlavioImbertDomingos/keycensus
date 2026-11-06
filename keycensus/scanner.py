"""Run every configured collector (in parallel), apply the policy, return an Inventory.

With a `baseline` (the previous scan's inventory.json), assets that were seen before and are missing now
because their source failed, or because the part of the source that holds them was not scanned, are
carried forward with `observed: false` and their old `last_observed`. Their findings stay open, marked
`verified: false`. A scan that could not look never makes a key disappear or a finding resolve.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from .analysis.policy import Policy, evaluate
from .collectors import CollectorError, build
from .config import Config
from .model import CryptoAsset, Inventory, SourceResult, utcnow

log = logging.getLogger(__name__)


def carry_forward(results: list[SourceResult], baseline: dict | None) -> int:
    """Put assets the baseline saw, and this scan could not have seen, back into their source. Returns how many."""
    if not baseline:
        return 0
    by_name = {r.name: r for r in results}
    base_time = baseline.get("generated_at")
    total = 0
    for a in baseline.get("assets") or []:
        src = by_name.get(a.get("source"))
        if src is None:
            continue  # the source left the config: the asset really is gone from the inventory
        if any(x.id == a.get("id") for x in src.assets) or not src.unverified(a):
            continue
        asset = CryptoAsset.from_dict(a)
        asset.observed = False
        if asset.last_observed is None and base_time:  # a baseline from before 0.12 has no last_observed
            asset.last_observed = datetime.fromisoformat(base_time.replace("Z", "+00:00"))
        asset.extra = {**asset.extra, "not_observed_because": src.why_unverified(a)}
        src.assets.append(asset)
        src.carried += 1
        total += 1
    return total


def scan(config: Config, policy: Policy | None = None, max_workers: int = 8, baseline: dict | None = None) -> Inventory:
    policy = policy or Policy.load(config.policy)
    collectors = []
    results: list[SourceResult] = []
    for src in config.sources:
        try:
            collectors.append(build(src))
        except (CollectorError, Exception) as exc:  # noqa: BLE001 - bad config for one source
            results.append(SourceResult(name=src.name, type=src.type, error=str(exc)))
            log.error("[%s] %s", src.name, exc)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results += list(pool.map(lambda c: c.run(), collectors))

    # keep config order
    order = {s.name: i for i, s in enumerate(config.sources)}
    results.sort(key=lambda r: order.get(r.name, 999))

    now = utcnow()
    for r in results:
        for a in r.assets:
            a.last_observed = now
    carried = carry_forward(results, baseline)
    if carried:
        log.warning("%d asset(s) carried forward from the previous scan: their sources failed or were partly "
                    "unreachable, so they were not observed and their findings stay open", carried)  # fmt: skip

    inv = Inventory(generated_at=now, sources=results, policy_name=policy.name)
    inv.findings = evaluate(inv.assets, policy)
    unobserved = {a.id: a for a in inv.assets if not a.observed}
    for f in inv.findings:
        if f.asset_id in unobserved:
            f.verified = False
            seen = unobserved[f.asset_id].last_observed
            f.detail = f"[Not re-verified: not observed in this scan; last observed {seen:%Y-%m-%d}] {f.detail}"
    if config.applications:
        from .linking import apply as link_apply

        link_apply(inv, config.applications, policy, base_dir=config.base_dir, auto_match=config.auto_match)
    return inv
