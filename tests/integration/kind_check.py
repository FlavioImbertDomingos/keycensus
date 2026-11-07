"""Check a scan and a doctor run against the kind cluster that kind_seed.sh prepared.

    python tests/integration/kind_check.py out/inventory.json doctor.json

Exits non-zero, listing every failed check, if keycensus did not see what the cluster holds, saw what it
must not, or doctor did not name the missing grant.
"""

from __future__ import annotations

import json
import sys


def check(inv: dict, doc: dict) -> list[str]:  # noqa: C901 - a flat list of checks reads best
    fails: list[str] = []

    def need(cond: bool, what: str) -> None:
        if not cond:
            fails.append(what)

    assets = inv["assets"]
    by_secret = {}
    for a in assets:
        if a["extra"].get("secret"):
            by_secret.setdefault((a["extra"]["namespace"], a["extra"]["secret"]), []).append(a)

    web = [a for a in by_secret.get(("apps", "web-tls"), []) if a["kind"] == "certificate"]
    need(len(web) == 1, f"one certificate from apps/web-tls, got {len(web)}")
    if web:
        w = web[0]
        need(
            (w["algorithm"], w["key_size"]) == ("RSA", 2048),
            f"web-tls is RSA-2048, got {w['algorithm']}-{w['key_size']}",
        )
        need(w["extra"].get("key_matches_certificate") is True, "web-tls: tls.key matches tls.crt")
        need(any(u["id"].startswith("apps/ReplicaSet/web-") and u["via"] == "k8s-volume" for u in w["used_by"]),
             f"web-tls used_by names the web Deployment's ReplicaSet, got {w['used_by']}")  # fmt: skip

    signer = by_secret.get(("apps", "signer"), [])
    need(any(a["algorithm"] == "EC" and a["curve"] == "P-256" for a in signer),
         f"the EC P-256 key in apps/signer, got {[(a['algorithm'], a['curve']) for a in signer]}")  # fmt: skip

    cm = [a for a in assets if (a["extra"].get("cert_manager") or {}).get("certificate") == "certs/internal"]
    need(len(cm) == 1, f"one asset for Certificate certs/internal, got {len(cm)}")
    if cm:
        info = cm[0]["extra"]["cert_manager"]
        need(info.get("issuer") == "Issuer/selfsigned", f"issuer Issuer/selfsigned, got {info.get('issuer')}")
        need(info.get("rotation_policy") == "Never", f"rotationPolicy Never, got {info.get('rotation_policy')}")
        need(info.get("ready") is True, "Certificate is Ready")
        need(cm[0]["algorithm"] == "EC", f"Certificate key is EC, got {cm[0]['algorithm']}")
        rules = {f["rule_id"] for f in inv["findings"] if f["asset_id"] == cm[0]["id"]}
        need("key-reuse-on-renewal" in rules, f"key-reuse-on-renewal on certs/internal, got {sorted(rules)}")

    need(not any(a["extra"].get("namespace") == "locked" for a in assets), "nothing from the locked namespace")

    (src,) = inv["sources"]
    need(src["status"] == "partial", f"source is partial, got {src['status']}")
    gaps = {g["id"]: g["kind"] for s in src["coverage"]["scopes"].values() for g in s.get("gaps", [])}
    need(gaps.get("namespaces:locked") == "denied", f"namespaces:locked is a denied gap, got {gaps}")
    need(set(gaps) <= {"namespaces:locked", "namespaces-opaque:locked", "cert-manager:issuers/locked",
                       "cert-manager:certificates/locked"}, f"no other gaps, got {sorted(gaps)}")  # fmt: skip

    (d,) = doc["sources"]
    need(doc["status"] == "partial", f"doctor status partial, got {doc['status']}")
    need(not any(p["level"] == "failed" for p in d["problems"]), "doctor reports no failure")
    ns = [p for p in d["problems"] if p["level"] == "gap" and p["scope"] == "namespaces"]
    need(len(ns) == 1 and ns[0]["items"] == ["locked"], f"doctor names namespace locked, got {ns}")
    if ns:
        need((ns[0].get("fix") or {}).get("file") == "deploy/kubernetes/keycensus-reader.yaml",
             f"doctor points to deploy/kubernetes/keycensus-reader.yaml, got {ns[0].get('fix')}")  # fmt: skip
    optional = {p["scope"] for p in d["problems"] if p["level"] == "optional"}
    need("clusterissuers/list" in optional, f"ClusterIssuers are an optional read, got {sorted(optional)}")
    return fails


def main(argv: list[str]) -> int:
    inv = json.load(open(argv[1]))
    doc = json.load(open(argv[2]))
    fails = check(inv, doc)
    for f in fails:
        print(f"FAIL: {f}", file=sys.stderr)
    print(f"{len(fails)} check(s) failed" if fails else "all checks passed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
