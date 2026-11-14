"""A tamper-evident audit log: one JSON object per line, each carrying the hash of the line before.

    audit:
      path: /var/log/keycensus/audit.jsonl
      hmac_key_env: KEYCENSUS_AUDIT_KEY     # optional; any secret reference works (_file, _vault, ...)

Every entry has `seq`, `ts`, `event`, the event's fields, `prev` (the previous entry's `hash`, or 64
zeros for the first) and `hash`. Without a key, `hash` is SHA-256 of the entry; that catches an edit
or a deleted line, but someone who can rewrite the whole file can recompute every hash. With a key,
`hash` is HMAC-SHA-256, and forging it needs the key, which should live somewhere the log's readers
cannot reach. `keycensus audit verify FILE` checks the whole chain.

What is written:

    scan.start      config and policy hashes, every source with its type and credential references
    scan.end        assets, findings by severity, failed sources, duration, output file hashes
    config.changed  the config or policy hash differs from the previous scan's
    serve.read      a protected path was served: path, status, token name, client address
    serve.denied    a request without a valid token
    webhook.sent    the change notification: endpoint host, result, number of changes
    scan.signed     the signed manifest's hash and the signing key's fingerprint

Credential values never appear, only references such as `password_vault=secret/data/kc#ctm`.

Rotation: move the file aside and keycensus starts a new one whose first entry continues the old
chain (its `prev` is the old file's last `hash`). `verify` on the new file reports that anchor, so
the two files can be checked as one chain.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import secrets

log = logging.getLogger(__name__)

GENESIS = "0" * 64


def _canonical(entry: dict[str, Any]) -> bytes:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()


def _digest(entry: dict[str, Any], key: bytes | None) -> str:
    data = _canonical(entry)
    if key:
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path, key: bytes | None = None):
        self.path = Path(path)
        self.key = key
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.prev, self.seq, self.last_hashes = GENESIS, 0, {}
        self.head = self.path.with_name(self.path.name + ".head")  # last seq + hash, survives rotation
        if not self.path.exists() and self.head.exists():
            try:
                h = json.loads(self.head.read_text())
                self.prev, self.seq = str(h["hash"]), int(h["seq"])
                self.last_hashes = h.get("last_hashes") or {}
            except (ValueError, KeyError):
                log.warning("audit: %s is unreadable; starting a new chain", self.head)
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                self.prev, self.seq = e.get("hash", self.prev), int(e.get("seq", self.seq))
                if e.get("event") == "scan.start":
                    self.last_hashes = {"config": e.get("config_sha256"), "policy": e.get("policy_sha256")}

    @classmethod
    def from_config(cls, block: dict[str, Any] | None) -> AuditLog | None:
        if not block:
            return None
        if not block.get("path"):
            raise ValueError("audit: needs a path")
        key = secrets.resolve(block, "hmac_key", owner="audit", allow_inline=False)
        return cls(block["path"], key.encode() if key else None)

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            entry = {"seq": self.seq + 1, "ts": datetime.now(UTC).isoformat(timespec="milliseconds"), "event": event,
                     **fields, "prev": self.prev}  # fmt: skip
            entry["hash"] = _digest(entry, self.key)
            line = json.dumps(entry, sort_keys=True, default=str) + "\n"
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            try:
                os.write(fd, line.encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            self.prev, self.seq = entry["hash"], entry["seq"]
            if event == "scan.start":
                self.last_hashes = {"config": fields.get("config_sha256"), "policy": fields.get("policy_sha256")}
            tmp = self.head.with_name(self.head.name + ".tmp")
            tmp.write_text(json.dumps({"seq": self.seq, "hash": self.prev, "last_hashes": self.last_hashes}))
            tmp.replace(self.head)
            return entry

    # ---------------------------------------------------------------- scan events
    def scan_started(self, config, policy_sha256: str | None, policy_ref: str | None = None) -> None:
        current = {"config": config.config_sha256, "policy": policy_sha256}
        if self.last_hashes and self.last_hashes != current:
            self.write("config.changed", before=self.last_hashes, after=current)
        self.last_hashes = current
        self.write("scan.start", config_sha256=config.config_sha256, policy_sha256=policy_sha256,
                   policy=policy_ref, sources=[
            {"name": s.name, "type": s.type, "credentials": secrets.describe(s.options)} for s in config.sources
        ])  # fmt: skip

    def scan_finished(self, inv, duration: float, outputs: dict[str, str] | None = None) -> None:
        s = inv.summary()
        self.write("scan.end", assets=s["assets"], findings=s["findings_by_severity"],
                   sources_failed=[x.name for x in inv.sources if x.error], duration_seconds=round(duration, 3),
                   outputs=outputs or {})  # fmt: skip


def verify(path: str | Path, key: bytes | None = None) -> tuple[bool, int, str]:
    """(ok, entries checked, message). Stops at the first broken link."""
    prev, n, expected_seq, anchor = None, 0, None, ""
    for lineno, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except ValueError:
            return False, n, f"line {lineno}: not JSON"
        if prev is None:  # first entry: a fresh log starts at GENESIS, a rotated one continues an older file
            prev, expected_seq = e.get("prev"), e.get("seq")
            if prev != GENESIS:
                anchor = f"; continues from hash {prev} (seq {int(expected_seq or 1) - 1}) of the previous file"
        if e.get("prev") != prev:
            return False, n, f"line {lineno} (seq {e.get('seq')}): chain broken; an earlier entry was removed or edited"
        if e.get("seq") != expected_seq:
            return False, n, f"line {lineno}: seq {e.get('seq')}, expected {expected_seq}"
        if not hmac.compare_digest(str(e.get("hash", "")), _digest(e, key)):
            hint = " (wrong or missing HMAC key?)" if n == 0 else ""
            return False, n, f"line {lineno} (seq {e.get('seq')}): hash does not match its content{hint}"
        prev, expected_seq, n = e["hash"], expected_seq + 1, n + 1
    return True, n, f"{n} entries, chain intact{anchor}"


def file_hashes(paths: dict[str, Path]) -> dict[str, str]:
    return {name: hashlib.sha256(p.read_bytes()).hexdigest() for name, p in paths.items() if p.exists()}


def policy_sha256(policy_path: str | None) -> str | None:
    if policy_path and policy_path != "default" and Path(policy_path).exists():
        return hashlib.sha256(Path(policy_path).read_bytes()).hexdigest()
    from .analysis.policy import builtin_packs  # noqa: PLC0415

    packs = builtin_packs()
    pack = packs.get(str(policy_path or "default"), packs["default"])
    return hashlib.sha256(pack.read_bytes()).hexdigest()


def webhook_sent(audit, ncfg, result: dict, changes: int) -> None:
    """Record a webhook delivery: the endpoint host only, because the URL itself is a credential."""
    if audit is None or result.get("reason") == "dry run":
        return
    host = urlparse(os.environ.get(ncfg.url_env, "")).hostname
    audit.write("webhook.sent", host=host, format=ncfg.format, sent=bool(result.get("sent")),
                reason=result.get("reason"), status=result.get("status"), changes=changes)  # fmt: skip
