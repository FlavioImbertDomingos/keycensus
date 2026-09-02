"""Prometheus metrics for `keycensus serve`.

Cardinality note: per-asset series (age, expiry) carry the asset name. That's
fine for hundreds of keys; for tens of thousands, set `per_asset_metrics: false`
in the serve config and rely on the aggregate counters.
"""

from __future__ import annotations

from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, InfoMetricFamily

from .. import __version__
from ..analysis import strength
from ..model import KIND_CERTIFICATE, KIND_KEY, SEVERITIES, Inventory

NS = "keycensus"


class InventoryCollector:
    """Wraps the latest Inventory; `serve` swaps it after every rescan."""

    def __init__(self, per_asset: bool = True):
        self.inventory: Inventory | None = None
        self.per_asset = per_asset
        self.scan_count = 0
        self.scan_errors = 0
        self.last_duration = 0.0

    def describe(self):
        return []

    def collect(self):
        info = InfoMetricFamily(f"{NS}_build", "keycensus build info")
        info.add_metric([], {"version": __version__})
        yield info

        scans = CounterMetricFamily(f"{NS}_scans", "Completed scans")
        scans.add_metric([], float(self.scan_count))
        yield scans
        errs = CounterMetricFamily(f"{NS}_scan_failures", "Scans that raised")
        errs.add_metric([], float(self.scan_errors))
        yield errs
        dur = GaugeMetricFamily(f"{NS}_scan_duration_seconds", "Duration of the last scan")
        dur.add_metric([], self.last_duration)
        yield dur

        inv = self.inventory
        if inv is None:
            return
        ts = GaugeMetricFamily(f"{NS}_last_scan_timestamp_seconds", "Unix time of the last scan")
        ts.add_metric([], inv.generated_at.timestamp())
        yield ts

        src_up = GaugeMetricFamily(f"{NS}_source_up", "1 if the source scanned OK", labels=["source", "type"])
        src_assets = GaugeMetricFamily(f"{NS}_source_assets", "Assets per source", labels=["source", "type"])
        src_dur = GaugeMetricFamily(f"{NS}_source_duration_seconds", "Scan time per source", labels=["source", "type"])
        for s in inv.sources:
            src_up.add_metric([s.name, s.type], 0.0 if s.error else 1.0)
            src_assets.add_metric([s.name, s.type], float(len(s.assets)))
            src_dur.add_metric([s.name, s.type], s.duration_seconds)
        yield src_up
        yield src_assets
        yield src_dur

        if inv.applications:
            from ..linking import impact

            app_assets = GaugeMetricFamily(f"{NS}_application_assets", "Crypto assets linked to the application",
                                           labels=["application", "owner"])  # fmt: skip
            app_worst = GaugeMetricFamily(
                f"{NS}_application_worst_finding",
                "Worst open finding on any asset the application uses (0 none, 1 info .. 5 critical)",
                labels=["application", "owner"],
            )
            rank = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
            for row in impact(inv):
                labels = [row["name"], row["owner"] or ""]
                app_assets.add_metric(labels, float(row["assets"]))
                app_worst.add_metric(labels, float(rank.get(row["worst_severity"] or "", 0)))
            yield app_assets
            yield app_worst
            unlinked = GaugeMetricFamily(f"{NS}_assets_unlinked", "Keys/certs no declared application uses")
            unlinked.add_metric([], float(inv.summary().get("assets_unlinked") or 0))
            yield unlinked

        assets = GaugeMetricFamily(
            f"{NS}_assets", "Assets by source, kind, algorithm and quantum class",
            labels=["source", "kind", "algorithm", "quantum_class"],
        )  # fmt: skip
        counts: dict[tuple, int] = {}
        for a in inv.assets:
            q = strength.assess(a).quantum_class
            k = (a.source, a.kind, a.display_algorithm, q)
            counts[k] = counts.get(k, 0) + 1
        for k, n in counts.items():
            assets.add_metric(list(k), float(n))
        yield assets

        findings = GaugeMetricFamily(
            f"{NS}_findings",
            "Open findings by severity, rule and source",
            labels=["severity", "rule", "source"],
        )
        fcounts: dict[tuple, int] = {}
        for f in inv.findings:
            k = (f.severity, f.rule_id, f.source)
            fcounts[k] = fcounts.get(k, 0) + 1
        for k, n in fcounts.items():
            findings.add_metric(list(k), float(n))
        yield findings

        by_sev = GaugeMetricFamily(f"{NS}_findings_by_severity", "Open findings by severity", labels=["severity"])
        sev_counts = {s: 0 for s in SEVERITIES}
        for f in inv.findings:
            sev_counts[f.severity] += 1
        for s, n in sev_counts.items():
            by_sev.add_metric([s], float(n))
        yield by_sev

        if not self.per_asset:
            return
        age = GaugeMetricFamily(
            f"{NS}_key_age_days", "Days since key creation or last rotation",
            labels=["source", "name", "algorithm", "asset_id"],
        )  # fmt: skip
        exp = GaugeMetricFamily(
            f"{NS}_certificate_expiry_timestamp_seconds", "Unix time the certificate expires",
            labels=["source", "name", "subject", "asset_id"],
        )  # fmt: skip
        for a in inv.assets:
            if a.kind == KIND_KEY and a.days_since_rotation is not None:
                age.add_metric([a.source, a.name, a.display_algorithm, a.id], a.days_since_rotation)
            if a.kind == KIND_CERTIFICATE and a.expires:
                exp.add_metric([a.source, a.name, a.subject or "", a.id], a.expires.timestamp())
        yield age
        yield exp
