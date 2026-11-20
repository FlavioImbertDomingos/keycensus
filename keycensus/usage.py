"""Observed use: who actually called a key, read from the audit logs of the key stores.

Collectors report who is *allowed* to use a key (`asset.used_by`: KMS grants and key policies, IAM bindings,
Vault policies, Key Vault RBAC). Applications are *declared* (`asset.applications`). Neither says whether
anyone used the key. The key stores log every cryptographic call, and this module reads those logs:

* AWS CloudTrail: KMS `Encrypt`, `Decrypt`, `GenerateDataKey*`, `ReEncrypt`, `Sign`, `Verify`, `GenerateMac`,
  `VerifyMac` and `DeriveSharedSecret` events, matched to `aws-kms` keys by key ARN
* HashiCorp Vault audit device: Transit `encrypt`, `decrypt`, `rewrap`, `sign`, `verify`, `hmac` and
  `datakey` responses, matched to `vault` keys by mount and key name
* Azure Key Vault `AuditEvent` diagnostic logs: `KeyEncrypt`, `KeyDecrypt`, `KeySign`, `KeyVerify`,
  `KeyWrap` and `KeyUnwrap`, matched to `azure-keyvault` keys by key id
* Google Cloud Audit Logs (Data Access) for `cloudkms.googleapis.com`: `Encrypt`, `Decrypt`,
  `AsymmetricSign`, `AsymmetricDecrypt`, `MacSign`, `MacVerify`, `RawEncrypt` and `RawDecrypt`, matched to
  `gcp-kms` keys by resource name

The result goes on `asset.observed_use`, apart from `used_by` and `applications`:

* `None`: no log covers the key, so nothing is known about its use
* a window with no events: the logs cover the key's account, mount, vault or project and nobody used it
* one entry per principal that called it: operations, counts, refused calls, first and last call, and
  whether the principal is among the ones the key store authorises (`authorized`)

plus `authorized_not_seen`, the authorised consumers that did not call the key in the window.

A log covers a key when the log holds events from the key's scope (AWS account and region, Vault mount,
Key Vault, GCP project). Logs are read from files: CloudTrail's S3 objects, a Vault audit file, Key Vault
diagnostic logs exported to storage or Log Analytics, `gcloud logging read --format=json`. JSON, JSON lines
and gzip all work.
"""

from __future__ import annotations

import glob
import gzip
import json
import logging
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .model import KIND_KEY, STATE_ACTIVE, CryptoAsset, Finding, Inventory, iso

log = logging.getLogger(__name__)

LOG_CLOUDTRAIL = "cloudtrail"
LOG_VAULT = "vault-audit"
LOG_AZURE = "azure-keyvault"
LOG_GCP = "gcp-audit"
LOG_TYPES = {
    LOG_CLOUDTRAIL: "aws-kms",
    LOG_VAULT: "vault",
    LOG_AZURE: "azure-keyvault",
    LOG_GCP: "gcp-kms",
}
LOG_TITLES = {
    LOG_CLOUDTRAIL: "AWS CloudTrail",
    LOG_VAULT: "Vault audit device",
    LOG_AZURE: "Azure Key Vault AuditEvent",
    LOG_GCP: "Google Cloud Audit Logs",
}

_KMS_OPS = {
    "Encrypt", "Decrypt", "ReEncrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext", "GenerateDataKeyPair",
    "GenerateDataKeyPairWithoutPlaintext", "Sign", "Verify", "GenerateMac", "VerifyMac", "DeriveSharedSecret",
}  # fmt: skip
_AZURE_OPS = {"KeyEncrypt", "KeyDecrypt", "KeySign", "KeyVerify", "KeyWrap", "KeyUnwrap"}
_GCP_OPS = {"Encrypt", "Decrypt", "AsymmetricSign", "AsymmetricDecrypt", "MacSign", "MacVerify", "RawEncrypt",
            "RawDecrypt"}  # fmt: skip
_VAULT_PATH = re.compile(
    r"^(?P<mount>.+?)/(?P<op>encrypt|decrypt|rewrap|sign|verify|hmac|datakey/(?:plaintext|wrapped))/(?P<name>[^/]+)"
)
_AZ_OID = ("oid", "http://schemas.microsoft.com/identity/claims/objectidentifier")
_AZ_UPN = ("upn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", "unique_name")
_AZ_APPID = ("appid", "azp")


class UsageError(Exception):
    pass


@dataclass
class Event:
    log: str  # LOG_* type
    target: str  # what the asset is matched on (key ARN, <mount>/keys/<name>, Key Vault key id, GCP key name)
    scope: str  # the unit a log covers (account:region, mount, vault host, project)
    principal: str
    operation: str
    time: datetime
    ok: bool
    via: str | None = None  # an AWS service calling on the principal's behalf
    policies: list[str] = field(default_factory=list)  # Vault token policies
    alias: str | None = None  # a readable name next to an opaque id (Azure UPN or app id)


@dataclass
class LogStats:
    type: str
    path: str
    sources: list[str] | None = None  # the keycensus sources this log belongs to; None = every source of its type
    records: int = 0
    events: int = 0  # cryptographic calls
    matched: int = 0
    first: datetime | None = None
    last: datetime | None = None
    scopes: set[str] = field(default_factory=set)
    unmatched: dict[str, int] = field(default_factory=dict)  # target -> calls, for keys not in the inventory
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        top = sorted(self.unmatched.items(), key=lambda kv: (-kv[1], kv[0]))[:20]
        return {
            "type": self.type,
            "title": LOG_TITLES[self.type],
            "path": self.path,
            "sources": self.sources,
            "records": self.records,
            "events": self.events,
            "matched": self.matched,
            "from": iso(self.first),
            "to": iso(self.last),
            "scopes": sorted(self.scopes),
            "unmatched_keys": len(self.unmatched),
            "unmatched": [{"key": k, "events": n} for k, n in top],
            "errors": self.errors[:10],
        }


# ------------------------------------------------------------------ reading
def _files(path: Path) -> list[Path]:
    if path.is_dir():
        return sorted(p for p in path.rglob("*") if p.is_file() and not p.name.startswith("."))
    if path.exists():
        return [path]
    matches = sorted(Path(m) for m in glob.glob(str(path), recursive=True))
    if not matches:
        raise UsageError(f"{path}: no such file or directory")
    return [m for m in matches if m.is_file()]


def _records(f: Path, errors: list[str]) -> Iterator[dict]:
    """JSON (an object with Records/records/entries, an array, or one record) or JSON lines, maybe gzipped."""
    raw = f.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        doc = None
    if doc is not None:
        if isinstance(doc, dict):
            for k in ("Records", "records", "entries", "value"):
                if isinstance(doc.get(k), list):
                    yield from (r for r in doc[k] if isinstance(r, dict))
                    return
            yield doc
        elif isinstance(doc, list):
            yield from (r for r in doc if isinstance(r, dict))
        return
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"{f}:{n}: not JSON")
            continue
        if isinstance(r, dict):
            if isinstance(r.get("records"), list):  # Azure storage export: {"records": [...]} per line
                yield from (x for x in r["records"] if isinstance(x, dict))
            else:
                yield r


def _time(v: Any) -> datetime | None:
    if not isinstance(v, str) or not v:
        return None
    s = v.strip().replace("Z", "+00:00")
    m = re.match(r"^(.*T\d\d:\d\d:\d\d)(\.\d+)?(.*)$", s)
    if m:  # Vault and Azure write nanoseconds; fromisoformat takes at most microseconds
        frac = (m.group(2) or "")[:7]
        s = m.group(1) + frac + m.group(3)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _cloudtrail(r: dict) -> Event | None:
    if r.get("eventSource") != "kms.amazonaws.com" or r.get("eventName") not in _KMS_OPS:
        return None
    arns = [str(x.get("ARN")) for x in r.get("resources") or [] if x.get("type") == "AWS::KMS::Key" and x.get("ARN")]
    key_id = str((r.get("requestParameters") or {}).get("keyId") or "")
    if not arns and key_id.startswith("arn:aws") and ":key/" in key_id:
        arns = [key_id]
    t = _time(r.get("eventTime"))
    if not arns or t is None:
        return None
    uid = r.get("userIdentity") or {}
    utype = uid.get("type")
    issuer = ((uid.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn")
    if utype == "AssumedRole" and issuer:
        principal = str(issuer)  # the role, as key policies and grants name it, not the session
    elif utype == "AWSService":
        principal = str(uid.get("invokedBy") or "aws-service")
    elif utype == "AWSAccount":
        principal = f"arn:aws:iam::{uid.get('accountId')}:root"
    else:
        principal = str(uid.get("arn") or uid.get("principalId") or "unknown")
    via = uid.get("invokedBy") if utype != "AWSService" else None
    return Event(log=LOG_CLOUDTRAIL, target=arns[0], scope=f"{r.get('recipientAccountId')}:{r.get('awsRegion')}",
                 principal=principal, operation=str(r["eventName"]), time=t, ok=not r.get("errorCode"),
                 via=str(via) if via else None)  # fmt: skip


def _vault(r: dict) -> Event | None:
    if r.get("type") != "response":  # every call is logged twice; the response carries the outcome
        return None
    req = r.get("request") or {}
    m = _VAULT_PATH.match(str(req.get("path") or ""))
    t = _time(r.get("time"))
    if not m or t is None:
        return None
    auth = r.get("auth") or {}
    pols = sorted({str(p) for p in (auth.get("policies") or []) + (auth.get("token_policies") or [])} - {"default"})
    principal = str(auth.get("display_name") or auth.get("entity_id") or "token")
    return Event(log=LOG_VAULT, target=f"{m['mount']}/keys/{m['name']}", scope=m["mount"], principal=principal,
                 operation=m["op"].split("/")[0], time=t, ok=not r.get("error"), policies=pols)  # fmt: skip


def _claim(claims: dict, names: Iterable[str]) -> str | None:
    for n in names:
        if claims.get(n):
            return str(claims[n])
    return None


def _azure(r: dict) -> Event | None:
    op = str(r.get("operationName") or "")
    if op not in _AZURE_OPS:
        return None
    props = r.get("properties") or {}
    kid = str(props.get("id") or r.get("id") or "")
    m = re.match(r"^(https://([^/]+)/keys/[^/]+)", kid, re.I)
    t = _time(r.get("time") or r.get("TimeGenerated"))
    if not m or t is None:
        return None
    claims = (r.get("identity") or {}).get("claim") or {}
    oid, upn, appid = _claim(claims, _AZ_OID), _claim(claims, _AZ_UPN), _claim(claims, _AZ_APPID)
    status = r.get("httpStatusCode")
    try:
        ok = int(status) < 400 if status is not None else str(r.get("resultType", "Success")) == "Success"
    except (TypeError, ValueError):
        ok = str(r.get("resultSignature", "")).upper() in ("OK", "SUCCESS")
    return Event(log=LOG_AZURE, target=m.group(1).lower(), scope=m.group(2).lower(),
                 principal=oid or upn or appid or "unknown", operation=op, time=t, ok=ok,
                 alias=upn or appid)  # fmt: skip


def _gcp(r: dict) -> Event | None:
    pp = r.get("protoPayload") or {}
    if pp.get("serviceName") != "cloudkms.googleapis.com":
        return None
    op = str(pp.get("methodName") or "").rsplit(".", 1)[-1]
    if op not in _GCP_OPS:
        return None
    name = str(pp.get("resourceName") or "").split("/cryptoKeyVersions/")[0]
    t = _time(r.get("timestamp") or r.get("receiveTimestamp"))
    if not name.startswith("projects/") or t is None:
        return None
    email = (pp.get("authenticationInfo") or {}).get("principalEmail") or "unknown"
    return Event(log=LOG_GCP, target=name, scope=name.split("/")[1], principal=str(email), operation=op, time=t,
                 ok=not (pp.get("status") or {}).get("code"))  # fmt: skip


_PARSERS = {LOG_CLOUDTRAIL: _cloudtrail, LOG_VAULT: _vault, LOG_AZURE: _azure, LOG_GCP: _gcp}


def read_log(kind: str, path: str | Path, since: datetime | None = None, until: datetime | None = None,
             sources: list[str] | None = None) -> tuple[list[Event], LogStats]:  # fmt: skip
    """Every cryptographic call in the log at `path` (a file, a directory or a glob), inside [since, until]."""
    if kind not in _PARSERS:
        raise UsageError(f"unknown log type {kind!r}; expected one of {', '.join(sorted(_PARSERS))}")
    stats = LogStats(type=kind, path=str(path), sources=sources)
    parse = _PARSERS[kind]
    events: list[Event] = []
    for f in _files(Path(path)):
        try:
            for r in _records(f, stats.errors):
                stats.records += 1
                ev = parse(r)
                if ev is None or (since and ev.time < since) or (until and ev.time > until):
                    continue
                events.append(ev)
        except OSError as exc:
            stats.errors.append(f"{f}: {exc}")
    for ev in events:
        stats.events += 1
        stats.scopes.add(ev.scope)
        stats.first = ev.time if stats.first is None or ev.time < stats.first else stats.first
        stats.last = ev.time if stats.last is None or ev.time > stats.last else stats.last
    return events, stats


# ------------------------------------------------------------------ matching
def _asset_target(a: CryptoAsset) -> str:
    return str(a.native_id).lower() if a.source_type == "azure-keyvault" else str(a.native_id)


def asset_scope(a: CryptoAsset) -> str | None:
    """The unit of coverage this asset belongs to, in the same form as Event.scope."""
    nid = str(a.native_id)
    if a.source_type == "aws-kms" and nid.startswith("arn:") and nid.count(":") >= 5:
        p = nid.split(":")
        return f"{p[4]}:{p[3]}"
    if a.source_type == "vault" and "/keys/" in nid:
        return nid.split("/keys/")[0]
    if a.source_type == "azure-keyvault":
        m = re.match(r"^https://([^/]+)/", nid, re.I)
        return m.group(1).lower() if m else None
    if a.source_type == "gcp-kms" and nid.startswith("projects/"):
        return nid.split("/")[1]
    return None


def authorized(
    a: CryptoAsset, principal: str, policies: list[str] | None = None, alias: str | None = None
) -> bool | None:  # noqa: E501
    """Is this principal among the consumers the key store authorises? None when no consumers were recorded."""
    if not a.used_by:
        return None
    p = principal.lower()
    for u in a.used_by:
        uid = str(u.get("id") or "").lower()
        if a.source_type == "vault":
            if u.get("type") == "policy" and uid in {x.lower() for x in policies or []}:
                return True
            continue
        if uid == p or str(u.get("object_id") or "").lower() == p:
            return True
        if alias and uid == alias.lower():
            return True
        if a.source_type == "gcp-kms" and uid.split(":", 1)[-1] == p:
            return True
    return False


def _covering_logs(a: CryptoAsset, stats: list[LogStats]) -> list[LogStats]:
    scope = asset_scope(a)
    return [s for s in stats if LOG_TYPES[s.type] == a.source_type and scope in s.scopes
            and (s.sources is None or a.source in s.sources)]  # fmt: skip


def attach(
    inv: Inventory, events: list[tuple[Event, LogStats]], stats: list[LogStats], window_days: int | None = None
) -> None:
    """Put observed use on every asset a log covers; record what was read on the inventory."""
    keys: dict[tuple[str, str], list[CryptoAsset]] = {}
    for a in inv.assets:
        a.observed_use = None
        if a.source_type in LOG_TYPES.values():
            keys.setdefault((a.source_type, _asset_target(a)), []).append(a)
    per_asset: dict[str, list[Event]] = {}
    for ev, st in events:
        targets = [a for a in keys.get((LOG_TYPES[ev.log], ev.target), [])
                   if st.sources is None or a.source in st.sources]  # fmt: skip
        if not targets:
            st.unmatched[ev.target] = st.unmatched.get(ev.target, 0) + 1
            continue
        st.matched += 1
        for a in targets:
            per_asset.setdefault(a.id, []).append(ev)
    for a in inv.assets:
        if a.source_type not in LOG_TYPES.values():
            continue
        cover = _covering_logs(a, stats)
        if cover:  # a matched event always puts its scope in its log's stats, so used keys are covered too
            a.observed_use = _summarise(a, per_asset.get(a.id, []), cover)
    inv.usage = {
        "window_days": window_days,
        "logs": [s.to_dict() for s in stats],
    }


def _summarise(a: CryptoAsset, evs: list[Event], cover: list[LogStats]) -> dict[str, Any]:
    firsts = [s.first for s in cover if s.first]
    lasts = [s.last for s in cover if s.last]
    principals: dict[tuple[str, str], dict[str, Any]] = {}
    for ev in sorted(evs, key=lambda e: e.time):
        p = principals.get((ev.log, ev.principal))
        if p is None:
            p = principals[(ev.log, ev.principal)] = {
                "id": ev.principal, "log": ev.log, "operations": {}, "events": 0, "denied": 0,
                "first_seen": iso(ev.time), "last_seen": iso(ev.time),
                "authorized": authorized(a, ev.principal, ev.policies, ev.alias),
            }  # fmt: skip
            if ev.alias and ev.alias != ev.principal:
                p["name"] = ev.alias
            if ev.policies:
                p["policies"] = ev.policies
        if ev.via:
            p.setdefault("via", [])
            if ev.via not in p["via"]:
                p["via"].append(ev.via)
        p["events"] += 1
        if ev.ok:
            p["operations"][ev.operation] = p["operations"].get(ev.operation, 0) + 1
        else:
            p["denied"] += 1
        p["last_seen"] = iso(ev.time)
    rows = sorted(principals.values(), key=lambda p: (-p["events"], p["id"]))
    used_policies = {x.lower() for ev in evs if ev.ok for x in ev.policies}
    used_ids = ({ev.principal.lower() for ev in evs if ev.ok} | {(ev.alias or "").lower() for ev in evs if ev.ok}) - {
        ""
    }
    not_seen = []
    for u in a.used_by:
        uid = str(u.get("id") or "")
        seen = (
            uid.lower() in used_policies
            if a.source_type == "vault"
            else bool({uid.lower(), str(u.get("object_id") or "").lower()} & used_ids)
            or (a.source_type == "gcp-kms" and uid.split(":", 1)[-1].lower() in used_ids)
        )
        if not seen:
            not_seen.append({"id": uid, "via": u.get("via")})
    return {
        "logs": sorted({s.type for s in cover}),
        "window": {"from": iso(min(firsts)) if firsts else None, "to": iso(max(lasts)) if lasts else None},
        "events": sum(p["events"] for p in rows),
        "succeeded": sum(sum(p["operations"].values()) for p in rows),
        "denied": sum(p["denied"] for p in rows),
        "principals": rows,
        "authorized_not_seen": not_seen,
    }


# ------------------------------------------------------------------ findings
def unused_findings(inv: Inventory, policy) -> list[Finding]:
    """`key-not-used` (info by default): an active key a log covers that nobody used in the window."""
    if not policy.in_effect("key-not-used"):
        return []
    out = []
    for a in inv.assets:
        u = a.observed_use
        if u is None or u.get("succeeded") or a.kind != KIND_KEY or a.state != STATE_ACTIVE:
            continue
        if a.key_type == "public-key":
            continue
        w = u.get("window") or {}
        span = ""
        if w.get("from") and w.get("to"):
            days = (_time(w["to"]) - _time(w["from"])).total_seconds() / 86400  # type: ignore[operator]
            span = f" between {w['from'][:10]} and {w['to'][:10]} ({days:.0f} days)"
        refused = f"; {u['denied']} call(s) were refused" if u.get("denied") else ""
        logs = ", ".join(LOG_TITLES[x] for x in u.get("logs") or [])
        finding = policy.finalize(
            Finding(
                rule_id="key-not-used",
                severity=policy.severity("key-not-used", "info"),
                title="No observed use of this key",
                detail=f"{a.name} in {a.source}: no successful cryptographic call in {logs}{span}{refused}."
                + (f" {len(a.used_by)} consumer(s) are authorised to use it." if a.used_by else ""),
                remediation="Confirm with the owner whether the key is still needed. A key nobody uses can be "
                "disabled, scheduled for deletion, or have its grants removed. Keys used rarely (yearly "
                "re-encryption, disaster recovery) need a longer log window before they are judged.",
                asset_id=a.id,
                asset_name=a.name,
                source=a.source,
            ),
            a,
        )
        if finding is not None:
            out.append(finding)
    return out


# ------------------------------------------------------------------ entry point
def parse_log_spec(spec: str) -> dict[str, Any]:
    """`cloudtrail:logs/ct/` -> {"type": "cloudtrail", "path": "logs/ct/"} (for --log)."""
    kind, sep, path = spec.partition(":")
    if not sep or not path:
        raise UsageError(f"--log {spec!r}: expected TYPE:PATH, e.g. cloudtrail:logs/cloudtrail/")
    return {"type": kind, "path": path}


def validate(entries: list[dict] | None, where: str = "usage") -> list[dict]:
    out = []
    for e in entries or []:
        if not isinstance(e, dict) or not e.get("type") or not e.get("path"):
            raise UsageError(f"{where}: every log needs 'type' and 'path': {e!r}")
        if e["type"] not in LOG_TYPES:
            raise UsageError(f"{where}: log type {e['type']!r}; expected one of {', '.join(sorted(LOG_TYPES))}")
        srcs = e.get("sources")
        if srcs is not None and (not isinstance(srcs, list) or not all(isinstance(s, str) for s in srcs)):
            raise UsageError(f"{where}: 'sources' of a log must be a list of source names")
        out.append(e)
    return out


def apply(inv: Inventory, logs: list[dict], policy, base_dir: str | None = None, window_days: int | None = None,
          now: datetime | None = None) -> None:  # fmt: skip
    """Read every log, attach observed use to the assets, and add `key-not-used` findings."""
    logs = validate(logs)
    if not logs:
        return
    since = (now or inv.generated_at) - timedelta(days=window_days) if window_days else None
    pairs: list[tuple[Event, LogStats]] = []
    stats: list[LogStats] = []
    for e in logs:
        p = Path(e["path"]).expanduser()
        if base_dir and not p.is_absolute():
            p = Path(base_dir) / p
        evs, st = read_log(e["type"], p, since=since, sources=e.get("sources"))
        stats.append(st)
        pairs.extend((ev, st) for ev in evs)
        log.info("[usage] %s %s: %d call(s) in %d record(s)", e["type"], p, st.events, st.records)
    attach(inv, pairs, stats, window_days=window_days)
    inv.findings = [f for f in inv.findings if f.rule_id != "key-not-used"] + unused_findings(inv, policy)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    inv.findings.sort(key=lambda f: (order.get(f.severity, 9), f.source, f.asset_name))


# ------------------------------------------------------------------ views
def rows(inv: Inventory) -> list[dict[str, Any]]:
    """One row per (key, principal) for the report and the CSV."""
    out = []
    for a in inv.assets:
        for p in (a.observed_use or {}).get("principals") or []:
            out.append({"asset_id": a.id, "asset": a.name, "source": a.source, **p})
    return out
