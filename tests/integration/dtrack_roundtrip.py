"""Round-trip a keycensus CBOM through a real Dependency-Track and record what survives.

Used by the `dependency-track` CI job. It bootstraps a fresh Dependency-Track (changes the default admin
password, gives the Automation team PROJECT_CREATION_UPLOAD and creates its API key), uploads the CBOM
with `keycensus upload dtrack`, exports the project back as CycloneDX and compares the two:

* components: every distinct identity (group, name, version, purl) comes back, as the same type
* properties: the keycensus:* properties on each component come back
* dependencies: every edge between components comes back
* cryptoProperties and vulnerabilities: recorded, not required (no Dependency-Track version stores them)

    python tests/integration/dtrack_roundtrip.py --url http://localhost:8080 --cbom out/cbom.json \\
        --expect roundtrip --summary "$GITHUB_STEP_SUMMARY" --report dtrack-report.json

`--expect rejected` is for versions that cannot hold cryptographic assets: the job then checks that the
project came back empty instead of partly imported, so the docs can say so.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

import requests

ADMIN_PASSWORD = "keycensus-ci-only"  # a throwaway container; never reused


def identity(c: dict) -> tuple:
    """How Dependency-Track tells components apart when it processes a BOM."""
    return (c.get("group") or "", c.get("name") or "", c.get("version") or "", c.get("purl") or "")


def _props(c: dict) -> set[tuple[str, str]]:
    # Dependency-Track trims values and drops empty ones, so compare on the same terms.
    out = set()
    for p in c.get("properties") or []:
        value = str(p.get("value") if p.get("value") is not None else "").strip()
        if p.get("name", "").startswith("keycensus:") and value:
            out.add((p["name"], value))
    return out


def _edges(bom: dict) -> set[tuple[tuple, tuple]]:
    by_ref = {c.get("bom-ref"): identity(c) for c in bom.get("components") or []}
    meta = (bom.get("metadata") or {}).get("component")
    if meta:
        by_ref[meta.get("bom-ref")] = ("<project>",)
    out = set()
    for d in bom.get("dependencies") or []:
        src = by_ref.get(d.get("ref"))
        for t in d.get("dependsOn") or []:
            dst = by_ref.get(t)
            if src and dst and src != ("<project>",) and src != dst:
                out.add((src, dst))
    return out


def compare(sent: dict, back: dict) -> dict:
    """What came back from Dependency-Track, against what was sent. Pure: unit-tested offline."""
    sent_c, back_c = sent.get("components") or [], back.get("components") or []
    sent_ids, back_ids = Counter(identity(c) for c in sent_c), Counter(identity(c) for c in back_c)
    merged = {k: n for k, n in sent_ids.items() if n > 1}
    back_by_id = {identity(c): c for c in back_c}
    type_changed, props_missing = [], []
    for c in sent_c:
        b = back_by_id.get(identity(c))
        if not b:
            continue
        if b.get("type") != c.get("type"):
            type_changed.append(f"{c['name']}: {c.get('type')} -> {b.get('type')}")
        lost = _props(c) - _props(b)
        if lost and sent_ids[identity(c)] == 1:  # merged components keep one set of properties
            props_missing.append(f"{c['name']}: {sorted(k for k, _ in lost)}")
    sent_edges, back_edges = _edges(sent), _edges(back)
    crypto_sent = sum(1 for c in sent_c if c.get("cryptoProperties"))
    return {
        "components_sent": len(sent_c),
        "distinct_identities_sent": len(sent_ids),
        "components_back": len(back_c),
        "merged_by_identity": {"/".join(x for x in k if x): n for k, n in merged.items()},
        # Asset components carry their source as group; only shared algorithm components may coincide.
        "assets_merged": sorted("/".join(x for x in k if x) for k in merged if k[0]),
        "missing": sorted("/".join(x for x in k if x) for k in set(sent_ids) - set(back_ids)),
        "unexpected": sorted("/".join(x for x in k if x) for k in set(back_ids) - set(sent_ids)),
        "type_changed": type_changed,
        "properties_missing": props_missing,
        "dependency_edges_sent": len(sent_edges),
        "dependency_edges_missing": sorted(f"{a[1]} -> {b[1]}" for a, b in sent_edges - back_edges),
        "crypto_properties_sent": crypto_sent,
        "crypto_properties_back": sum(1 for c in back_c if c.get("cryptoProperties")),
        "vulnerabilities_sent": len(sent.get("vulnerabilities") or []),
        "vulnerabilities_back": len(back.get("vulnerabilities") or []),
    }


def roundtrip_ok(r: dict) -> list[str]:
    """The claims the docs make; each failure is a reason."""
    problems = []
    if r.get("assets_merged"):
        problems.append(f"asset components share an identity and were merged: {r['assets_merged'][:5]}")
    if r["missing"] or r["unexpected"]:
        problems.append(f"components differ: missing {r['missing']}, unexpected {r['unexpected']}")
    if r["type_changed"]:
        problems.append(f"component types changed: {r['type_changed'][:5]}")
    if r["properties_missing"]:
        problems.append(f"keycensus properties lost: {r['properties_missing'][:5]}")
    if r["dependency_edges_missing"]:
        problems.append(f"dependency edges lost: {r['dependency_edges_missing'][:5]}")
    return problems


def summary_markdown(version: str, cbom_version: str, r: dict, problems: list[str]) -> str:
    rows = [
        ("Components (distinct identities)", f"{r['distinct_identities_sent']} sent, {r['components_back']} back"),
        ("Merged by Dependency-Track (same name and version)", ", ".join(f"{k} x{n}" for k, n in
                                                                       r["merged_by_identity"].items()) or "none"),
        ("Component types kept", "yes" if not r["type_changed"] else f"no: {r['type_changed'][:3]}"),
        ("keycensus properties kept", "yes" if not r["properties_missing"] else "no"),
        ("Dependency edges kept", f"{r['dependency_edges_sent'] - len(r['dependency_edges_missing'])} of "
                                  f"{r['dependency_edges_sent']}"),
        ("cryptoProperties kept", f"{r['crypto_properties_back']} of {r['crypto_properties_sent']}"),
        ("Vulnerabilities (findings) kept", f"{r['vulnerabilities_back']} of {r['vulnerabilities_sent']}"),
    ]  # fmt: skip
    out = [f"### Dependency-Track {version}, CycloneDX {cbom_version}", "", "| | |", "|---|---|"]
    out += [f"| {a} | {b} |" for a, b in rows]
    out += ["", "Result: " + ("round-trip holds" if not problems else "; ".join(problems)), ""]
    return "\n".join(out)


class Client:
    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.s = requests.Session()

    def wait_up(self, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                r = self.s.get(f"{self.url}/api/version", timeout=5)
                if r.ok:
                    return r.json().get("version", "?")
            except requests.RequestException:
                pass
            time.sleep(5)
        raise SystemExit(f"Dependency-Track did not answer at {self.url}/api/version within {timeout:.0f}s")

    def bootstrap(self) -> str:
        """Default admin -> new password -> JWT -> Automation team API key with PROJECT_CREATION_UPLOAD."""
        self.s.post(f"{self.url}/api/v1/user/forceChangePassword", timeout=30, data={
            "username": "admin", "password": "admin", "newPassword": ADMIN_PASSWORD,
            "confirmPassword": ADMIN_PASSWORD})  # fmt: skip
        r = self.s.post(f"{self.url}/api/v1/user/login", timeout=30,
                        data={"username": "admin", "password": ADMIN_PASSWORD})  # fmt: skip
        r.raise_for_status()
        self.s.headers["Authorization"] = f"Bearer {r.text.strip()}"
        teams = self.s.get(f"{self.url}/api/v1/team", timeout=30)
        teams.raise_for_status()
        team = next(t for t in teams.json() if t["name"] == "Automation")
        p = self.s.post(f"{self.url}/api/v1/permission/PROJECT_CREATION_UPLOAD/team/{team['uuid']}", timeout=30)
        if p.status_code not in (200, 304):
            p.raise_for_status()
        k = self.s.put(f"{self.url}/api/v1/team/{team['uuid']}/key", timeout=30)
        k.raise_for_status()
        return k.json()["key"]

    def export(self, project: str, version: str, cdx_version: str) -> dict | None:
        r = self.s.get(f"{self.url}/api/v1/project/lookup", params={"name": project, "version": version}, timeout=30)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        uuid = r.json()["uuid"]
        e = self.s.get(f"{self.url}/api/v1/bom/cyclonedx/project/{uuid}", timeout=60,
                       params={"format": "json", "variant": "withVulnerabilities", "version": cdx_version})  # fmt: skip
        e.raise_for_status()
        return e.json()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--url", default="http://localhost:8080")
    ap.add_argument("--cbom", required=True)
    ap.add_argument("--expect", choices=["roundtrip", "rejected"], default="roundtrip")
    ap.add_argument("--startup-timeout", type=float, default=600)
    ap.add_argument("--summary", help="Append a Markdown table here (e.g. $GITHUB_STEP_SUMMARY).")
    ap.add_argument("--report", help="Write the comparison as JSON here.")
    a = ap.parse_args(argv)

    sent = json.loads(Path(a.cbom).read_text())
    cdx_version = sent["specVersion"]
    dt = Client(a.url)
    dt_version = dt.wait_up(a.startup_timeout)
    print(f"Dependency-Track {dt_version} is up; sending a CycloneDX {cdx_version} CBOM", flush=True)
    key = dt.bootstrap()
    project, version = "keycensus-roundtrip", f"cdx-{cdx_version}"
    up = subprocess.run(  # noqa: S603 - our own CLI, fixed arguments
        [sys.executable, "-m", "keycensus.cli", "upload", "dtrack", "--url", a.url, "--api-key-env", "DT_KEY",
         "--cbom", a.cbom, "--project", project, "--version", version, "--timeout", "300"],
        env={**os.environ, "DT_KEY": key}, capture_output=True, text=True, check=False,
    )  # fmt: skip
    print(up.stdout + up.stderr, flush=True)
    time.sleep(5)  # the project's component list settles after the processing flag clears
    back = dt.export(project, version, cdx_version) or {}
    report = compare(sent, back) | {"dependency_track": dt_version, "upload_exit": up.returncode,
                                    "upload_output": (up.stdout + up.stderr).strip()[-2000:]}  # fmt: skip
    problems = roundtrip_ok(report)
    if a.expect == "rejected":
        problems = (
            []
            if report["components_back"] == 0
            else [
                f"expected Dependency-Track {dt_version} to import nothing, got {report['components_back']} components"
            ]
        )
    elif up.returncode:
        problems.insert(0, f"keycensus upload dtrack exited {up.returncode}")
    print(json.dumps(report, indent=2))
    if a.report:
        Path(a.report).write_text(json.dumps(report, indent=2) + "\n")
    if a.summary:
        with open(a.summary, "a") as fh:
            fh.write(summary_markdown(dt_version, cdx_version, report, problems if a.expect == "roundtrip" else []))
            if a.expect == "rejected":
                fh.write(f"Expected: no import. Result: {'as expected' if not problems else problems[0]}\n")
    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
