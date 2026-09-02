"""`keycensus serve`: rescan on a timer and expose

    /metrics          Prometheus
    /report.html      the HTML report
    /inventory.json   native JSON
    /cbom.json        CycloneDX CBOM
    /findings.json    just the findings
    /healthz          200 once the first scan has finished

One thread scans; the HTTP server just hands out the latest rendered outputs.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from prometheus_client import REGISTRY, generate_latest
from prometheus_client.exposition import CONTENT_TYPE_LATEST

from .analysis.policy import Policy
from .config import Config
from .exporters import cbom, html_report, json_export
from .exporters.prometheus import InventoryCollector
from .scanner import scan

log = logging.getLogger(__name__)


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.outputs: dict[str, tuple[str, str]] = {}  # path -> (content-type, body)
        self.ready = False


def _rescan_loop(config: Config, policy: Policy, collector: InventoryCollector, state: State, interval: float):
    while True:
        started = time.perf_counter()
        try:
            inv = scan(config, policy)
            collector.inventory = inv
            collector.scan_count += 1
            rendered = {
                "/report.html": ("text/html; charset=utf-8", html_report.render(inv)),
                "/inventory.json": ("application/json", json_export.render(inv)),
                "/cbom.json": ("application/vnd.cyclonedx+json; version=1.6", cbom.render(inv)),
                "/findings.json": (
                    "application/json",
                    json.dumps([f.to_dict() for f in inv.findings], indent=2),
                ),
            }
            with state.lock:
                state.outputs = rendered
                state.ready = True
            s = inv.summary()
            log.info(
                "scan complete: %d assets, %d findings (%s)", s["assets"], s["findings"],
                ", ".join(f"{k}={v}" for k, v in s["findings_by_severity"].items() if v),
            )  # fmt: skip
        except Exception as exc:  # noqa: BLE001 - keep serving the last good result
            collector.scan_errors += 1
            log.exception("scan failed: %s", exc)
        collector.last_duration = time.perf_counter() - started
        time.sleep(max(1.0, interval))


def make_handler(state: State):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # quieter than the default
            log.debug("%s " + fmt, self.address_string(), *args)

        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/metrics":
                body = generate_latest(REGISTRY)
                return self._send(200, CONTENT_TYPE_LATEST, body)
            if path == "/healthz":
                return self._send(
                    200 if state.ready else 503,
                    "text/plain",
                    b"ok\n" if state.ready else b"scanning\n",
                )
            if path == "/":
                path = "/report.html"
            with state.lock:
                hit = state.outputs.get(path)
            if hit is None:
                if not state.ready:
                    return self._send(503, "text/plain", b"first scan not finished yet\n")
                return self._send(404, "text/plain", b"not found\n")
            ctype, body = hit
            return self._send(200, ctype, body.encode())

        def _send(self, code: int, ctype: str, body: bytes):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def serve(config: Config, policy: Policy, port: int, interval_seconds: float, listen: str = "0.0.0.0",
          per_asset_metrics: bool = True) -> None:  # fmt: skip
    collector = InventoryCollector(per_asset=per_asset_metrics)
    REGISTRY.register(collector)
    state = State()
    threading.Thread(
        target=_rescan_loop, args=(config, policy, collector, state, interval_seconds), daemon=True
    ).start()
    server = ThreadingHTTPServer((listen, port), make_handler(state))
    log.info(
        "keycensus serving on http://%s:%d/ (report at /report.html, metrics at /metrics)",
        listen,
        port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
