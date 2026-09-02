"""Run every configured collector (in parallel), apply the policy, return an Inventory."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from .analysis.policy import Policy, evaluate
from .collectors import CollectorError, build
from .config import Config
from .model import Inventory, SourceResult, utcnow

log = logging.getLogger(__name__)


def scan(config: Config, policy: Policy | None = None, max_workers: int = 8) -> Inventory:
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

    inv = Inventory(generated_at=utcnow(), sources=results, policy_name=policy.name)
    inv.findings = evaluate(inv.assets, policy)
    return inv
