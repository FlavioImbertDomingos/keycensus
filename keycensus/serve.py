"""`keycensus serve`: rescan on a timer and expose

    /metrics            Prometheus                          public by default
    /healthz            200 once the first scan has finished  public
    /livez              200 while the process is up          public
    /report.html        the HTML report                     token required
    /inventory.json     native JSON                         token required
    /cbom.json          CycloneDX CBOM                      token required
    /findings.json      just the findings                   token required
    /diff.json, /changes.json, /manifest.json(.sig)         token required

The report and the CBOM are a map of every key you own and what is wrong with it, so they need a
token. Configure it in the `serve:` block:

    serve:
      listen: 127.0.0.1            # default; anything else needs tokens or allow_unauthenticated
      port: 9742
      auth:
        tokens:
          - {name: grafana, token_env: KC_TOKEN_GRAFANA}      # any secret reference works
          - {name: auditor, token_file: /run/secrets/kc-auditor}
        public_paths: [/metrics, /healthz, /livez]          # the default; [] protects /metrics too
      tls: {cert_file: /etc/keycensus/tls.crt, key_file: /etc/keycensus/tls.key}
      allow_unauthenticated: false

$KEYCENSUS_SERVE_TOKEN, when set, is one more token named "default" (the Helm chart uses it).
Clients send `Authorization: Bearer <token>`; browsers get a Basic prompt, where the password is
the token and the user name is ignored. Every protected read and every refusal goes to the audit
log, with the token's name and never the token.

One thread scans; the HTTP server just hands out the latest rendered outputs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import ssl
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from prometheus_client import REGISTRY, generate_latest
from prometheus_client.exposition import CONTENT_TYPE_LATEST

from . import secrets
from .analysis.policy import Policy
from .audit import AuditLog, policy_sha256, webhook_sent
from .changes import classify, summarize
from .changes import render_text as render_changes
from .config import Config, ConfigError
from .diff import diff_dicts
from .diff import render_json as render_diff_json
from .exporters import cbom, html_report, json_export
from .exporters.prometheus import InventoryCollector
from .notify import NotifyConfig, send
from .scanner import scan

log = logging.getLogger(__name__)

DEFAULT_PUBLIC = ("/metrics", "/healthz", "/livez")
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
    "img-src data:; frame-ancestors 'none'",
}


@dataclass
class ServeSettings:
    listen: str = "127.0.0.1"
    port: int = 9742
    tokens: dict[str, bytes] = field(default_factory=dict)  # name -> sha256(token); the token itself is not kept
    public_paths: tuple[str, ...] = DEFAULT_PUBLIC
    allow_unauthenticated: bool = False
    tls_cert: str | None = None
    tls_key: str | None = None

    @classmethod
    def from_config(cls, block: dict | None, listen: str | None = None, port: int | None = None,
                    tls_cert: str | None = None, tls_key: str | None = None,
                    insecure_no_auth: bool = False) -> ServeSettings:  # fmt: skip
        block = dict(block or {})
        auth = dict(block.get("auth") or {})
        tls = dict(block.get("tls") or {})
        s = cls(
            listen=str(listen or block.get("listen") or os.environ.get("KEYCENSUS_LISTEN") or "127.0.0.1"),
            port=int(port or block.get("port") or 9742),
            public_paths=tuple(auth.get("public_paths", DEFAULT_PUBLIC)),
            allow_unauthenticated=bool(
                insecure_no_auth
                or block.get("allow_unauthenticated")
                or os.environ.get("KEYCENSUS_ALLOW_UNAUTHENTICATED") == "1"
            ),  # fmt: skip
            tls_cert=tls_cert or tls.get("cert_file"),
            tls_key=tls_key or tls.get("key_file"),
        )
        for i, t in enumerate(auth.get("tokens") or []):
            name = str(t.get("name") or f"token{i + 1}")
            try:
                value = secrets.resolve(t, "token", owner=f"serve.auth.tokens[{name}]", required=True,
                                        allow_inline=False)  # fmt: skip
            except secrets.SecretError as exc:
                raise ConfigError(str(exc)) from exc
            if len(value) < 16:
                raise ConfigError(f"serve token {name!r} is shorter than 16 characters")
            s.tokens[name] = hashlib.sha256(value.encode()).digest()
        env_token = os.environ.get("KEYCENSUS_SERVE_TOKEN")
        if env_token:
            s.tokens.setdefault("default", hashlib.sha256(env_token.encode()).digest())
        if bool(s.tls_cert) != bool(s.tls_key):
            raise ConfigError("serve.tls needs both cert_file and key_file")
        if not s.tokens and not s.allow_unauthenticated and not _loopback(s.listen):
            raise ConfigError(
                f"refusing to serve the report and CBOM on {s.listen} without authentication. Add a token "
                "(serve.auth.tokens, or $KEYCENSUS_SERVE_TOKEN), listen on 127.0.0.1, or set "
                "serve.allow_unauthenticated: true if something in front of keycensus does the auth."
            )
        return s

    def who(self, header: str | None) -> str | None:
        """The name of the token in an Authorization header, or None."""
        if not header:
            return None
        scheme, _, value = header.partition(" ")
        value = value.strip()
        if scheme.lower() == "basic":
            try:
                value = base64.b64decode(value).decode().partition(":")[2]
            except (ValueError, UnicodeDecodeError):
                return None
        elif scheme.lower() != "bearer":
            return None
        digest = hashlib.sha256(value.encode()).digest()
        found = None
        for name, want in self.tokens.items():  # compare against every token: no early exit
            if hmac.compare_digest(digest, want):
                found = name
        return found


def _loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return host == "localhost"
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.outputs: dict[str, tuple[str, str]] = {}  # path -> (content-type, body)
        self.ready = False
        self.previous: dict | None = None  # last scan, for the change diff


def _rescan_loop(config: Config, policy: Policy, collector: InventoryCollector, state: State, interval: float,
                 audit: AuditLog | None = None, signing_key=None, policy_hash: str | None = None):  # fmt: skip
    while True:
        started = time.perf_counter()
        try:
            if audit:
                audit.scan_started(config, policy_hash)
            inv = scan(config, policy)
            collector.inventory = inv
            collector.scan_count += 1

            # ---- what changed since the last scan --------------------------
            # State metrics cannot answer "a key became exportable an hour ago",
            # so every rescan is diffed against the previous one and the result
            # is counted, exposed and (optionally) sent to a webhook.
            current = inv.to_dict()
            change_outputs: dict[str, tuple[str, str]] = {}
            if state.previous is not None:
                d = diff_dicts(state.previous, current)
                changes = classify(d, config.change_urgency)
                collector.record_changes(changes)
                change_outputs = {
                    "/diff.json": ("application/json", render_diff_json(d)),
                    "/changes.json": ("application/json", json.dumps(summarize(changes), indent=2, default=str)),
                }
                if changes:
                    s_ch = summarize(changes)
                    log.info(
                        "changes since last scan: %d page, %d digest (%s)",
                        s_ch["by_urgency"].get("page", 0), s_ch["by_urgency"].get("digest", 0),
                        ", ".join(f"{k}={v}" for k, v in s_ch["by_kind"].items()),
                    )  # fmt: skip
                    for line in render_changes(changes).splitlines():
                        if line.strip():
                            log.info("  %s", line)
                _maybe_notify(config, changes, audit)
            state.previous = current

            rendered = {
                "/report.html": ("text/html; charset=utf-8", html_report.render(inv)),
                "/inventory.json": ("application/json", json_export.render(inv)),
                "/cbom.json": ("application/vnd.cyclonedx+json; version=1.6", cbom.render(inv)),
                "/findings.json": (
                    "application/json",
                    json.dumps([f.to_dict() for f in inv.findings], indent=2),
                ),
                **change_outputs,
            }
            if signing_key is not None:
                from .signing import build_manifest  # noqa: PLC0415

                files = {p.lstrip("/"): b.encode() for p, (_, b) in rendered.items()}
                meta = {"generated_at": inv.to_dict()["generated_at"], "config_sha256": config.config_sha256,
                        "policy_sha256": policy_hash}  # fmt: skip
                body, sig = build_manifest(files, signing_key, meta)
                rendered["/manifest.json"] = ("application/json", body.decode())
                rendered["/manifest.json.sig"] = ("text/plain", sig.decode())
                if audit:
                    audit.write("scan.signed", manifest_sha256=hashlib.sha256(body).hexdigest(), files=len(files))
            if audit:
                audit.scan_finished(
                    inv,
                    time.perf_counter() - started,
                    {p.lstrip("/"): hashlib.sha256(b.encode()).hexdigest() for p, (_, b) in rendered.items()},
                )
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


def _maybe_notify(config: Config, changes, audit: AuditLog | None = None) -> None:
    """Fire the webhook if one is configured. A delivery failure is logged and
    swallowed: the scanner's job is to keep scanning."""
    try:
        cfg = NotifyConfig.from_dict(config.notifications)
    except Exception as exc:  # noqa: BLE001 - a bad notify block must not stop scanning
        log.warning("notifications config is invalid, not sending: %s", exc)
        return
    if cfg is None:
        return
    result = send(changes, cfg, context={"environment": config.serve.get("environment", ""), "source": "serve"})
    webhook_sent(audit, cfg, result, len(changes))
    if result["reason"] not in ("ok",) and result["payload"] is not None:
        log.warning("notification not delivered: %s", result["reason"])


def make_handler(state: State, settings: ServeSettings | None = None, audit: AuditLog | None = None):
    settings = settings or ServeSettings(allow_unauthenticated=True)
    open_access = settings.allow_unauthenticated and not settings.tokens

    class Handler(BaseHTTPRequestHandler):
        server_version = "keycensus"
        sys_version = ""

        def log_message(self, fmt, *args):  # quieter than the default
            log.debug("%s " + fmt, self.address_string(), *args)

        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/livez":
                return self._send(200, "text/plain", b"alive\n")
            who = "public" if path in settings.public_paths else settings.who(self.headers.get("Authorization"))
            if who is None and open_access:
                who = "anonymous"
            if who is None:
                if audit:
                    audit.write(
                        "serve.denied",
                        path=path,
                        client=self.client_address[0],
                        reason="no token" if not self.headers.get("Authorization") else "invalid token",
                    )
                return self._send(
                    401,
                    "text/plain",
                    b"authentication required\n",
                    extra={"WWW-Authenticate": 'Basic realm="keycensus", charset="UTF-8"'},
                )
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
            if audit and who != "public":
                audit.write("serve.read", path=path, status=200, token=who, client=self.client_address[0])
            return self._send(200, ctype, body.encode())

        def _send(self, code: int, ctype: str, body: bytes, extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in {**SECURITY_HEADERS, **(extra or {})}.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

    return Handler


def serve(config: Config, policy: Policy, settings: ServeSettings, interval_seconds: float,
          per_asset_metrics: bool = True, policy_path: str | None = None, signing_key=None) -> None:  # fmt: skip
    audit = AuditLog.from_config(config.audit)
    collector = InventoryCollector(per_asset=per_asset_metrics)
    REGISTRY.register(collector)
    state = State()
    threading.Thread(
        target=_rescan_loop,
        args=(config, policy, collector, state, interval_seconds, audit, signing_key,
              policy_sha256(policy_path or config.policy)),
        daemon=True,
    ).start()  # fmt: skip
    server = ThreadingHTTPServer((settings.listen, settings.port), make_handler(state, settings, audit))
    scheme = "http"
    if settings.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(settings.tls_cert, settings.tls_key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    access = (f"{len(settings.tokens)} token(s): {', '.join(sorted(settings.tokens))}" if settings.tokens
              else "NO AUTHENTICATION (allow_unauthenticated)" if settings.allow_unauthenticated
              else "loopback only, no tokens")  # fmt: skip
    log.info("keycensus serving on %s://%s:%d/ (%s; public: %s)", scheme, settings.listen, settings.port, access,
             ", ".join(settings.public_paths) or "none")  # fmt: skip
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
