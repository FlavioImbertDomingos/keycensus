#!/usr/bin/env python3
"""Generates grafana/dashboards/keycensus.json. Edit this, not the JSON.

python grafana/build_dashboard.py
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).parent / "dashboards" / "keycensus.json"
DS = {"type": "prometheus", "uid": "prometheus"}
_id = 0


def nid():
    global _id
    _id += 1
    return _id


def target(expr, legend="__auto", instant=False):
    t = {"datasource": DS, "expr": expr, "legendFormat": legend, "refId": f"R{nid()}"}
    if instant:
        t["instant"] = True
    return t


def thresholds(*steps):
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for c, v in steps]}


def stat(title, expr, x, y, w=4, h=4, thr=None, unit=None):
    fc = {"thresholds": thr or thresholds(("green", None))}
    if unit:
        fc["unit"] = unit
    return {
        "id": nid(), "type": "stat", "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": DS, "targets": [target(expr, instant=True)],
        "fieldConfig": {"defaults": fc, "overrides": []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "value", "graphMode": "none"},
    }  # fmt: skip


def timeseries(title, targets, x, y, w=12, h=8, unit=None, stack=False):
    d = {"custom": {"drawStyle": "line", "lineWidth": 2, "fillOpacity": 12,
                    "stacking": {"mode": "normal" if stack else "none"}}}  # fmt: skip
    if unit:
        d["unit"] = unit
    return {
        "id": nid(), "type": "timeseries", "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": DS, "targets": targets, "fieldConfig": {"defaults": d, "overrides": []},
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}},
    }  # fmt: skip


def piechart(title, expr, legend, x, y, w=8, h=8):
    return {
        "id": nid(), "type": "piechart", "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": DS, "targets": [target(expr, legend, instant=True)],
        "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "pieType": "donut",
                    "legend": {"displayMode": "list", "placement": "right"}},
    }  # fmt: skip


def table(title, expr, x, y, w=24, h=8):
    return {
        "id": nid(), "type": "table", "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": DS, "targets": [target(expr, instant=True)],
        "transformations": [{"id": "organize", "options": {"excludeByName": {"Time": True, "__name__": True, "job": True, "instance": True}}}],
        "fieldConfig": {"defaults": {}, "overrides": []},
    }  # fmt: skip


sev = lambda s: f'keycensus_findings_by_severity{{severity="{s}"}}'  # noqa: E731

panels = [
    stat("Assets", "sum(keycensus_assets)", 0, 0),
    stat("Critical", sev("critical"), 4, 0, thr=thresholds(("green", None), ("red", 1))),
    stat("High", sev("high"), 8, 0, thr=thresholds(("green", None), ("orange", 1))),
    stat("Medium", sev("medium"), 12, 0, thr=thresholds(("green", None), ("yellow", 1))),
    stat("Quantum-vulnerable", 'sum(keycensus_assets{quantum_class="quantum-vulnerable"})', 16, 0),
    stat(
        "Sources OK",
        "sum(keycensus_source_up) / count(keycensus_source_up)",
        20,
        0,
        unit="percentunit",
        thr=thresholds(("red", None), ("green", 1)),
    ),  # fmt: skip
    timeseries(
        "Findings over time by severity",
        [target("keycensus_findings_by_severity", "{{severity}}")],
        0,
        4,
        stack=True,
    ),
    piechart(
        "Post-quantum readiness",
        "sum by (quantum_class) (keycensus_assets)",
        "{{quantum_class}}",
        12,
        4,
        w=6,
    ),
    piechart("Assets by algorithm", "sum by (algorithm) (keycensus_assets)", "{{algorithm}}", 18, 4, w=6),
    timeseries("Assets per source", [target("keycensus_source_assets", "{{source}}")], 0, 12, stack=True),
    timeseries("Findings by rule", [target("sum by (rule) (keycensus_findings)", "{{rule}}")], 12, 12),
    table(
        "Certificates: days to expiry",
        "sort((keycensus_certificate_expiry_timestamp_seconds - time()) / 86400)",
        0,
        20,
    ),
    table("Oldest keys (days since rotation)", "sort_desc(keycensus_key_age_days)", 0, 28),
]

dashboard = {
    "uid": "keycensus", "title": "keycensus — crypto inventory", "tags": ["keycensus", "crypto", "pci"],
    "timezone": "browser", "editable": True, "refresh": "1m", "schemaVersion": 39, "version": 1,
    "time": {"from": "now-7d", "to": "now"}, "panels": panels,
}  # fmt: skip
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(dashboard, indent=2) + "\n")
print(f"wrote {OUT} ({len(panels)} panels)")
