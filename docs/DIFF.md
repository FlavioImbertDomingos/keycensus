# Diff mode — what changed since the last scan

An inventory is only interesting the second time you take it. Diff mode compares two
`inventory.json` files (the JSON output of `keycensus scan`) and answers:

* **What appeared / disappeared** — new keys, deleted certificates, a source that vanished.
* **What changed on the things that stayed** — state, expiry, last rotation, rotation setting,
  algorithm/size/curve, exportability, hardware backing, purposes, TLS version, fingerprint, location.
* **Which findings are new and which were resolved** — matched by `(rule, asset)`.
* **Which sources broke or got fixed** — a collector that errored this time but not last time.

Assets are matched by their stable id (`source` + `kind` + native id — ARN, key URI, PKCS#11 id,
cert serial…). Rotating a key in Azure/GCP/Vault keeps the same id (version-less), so it shows as
`last_rotated` changing, not as a delete + create. Renaming a *source* in the config changes every
id under it — the diff will honestly say everything was removed and added.

## Commands

```bash
# compare two scans
keycensus diff out/2026-08-01/inventory.json out/2026-09-01/inventory.json
keycensus diff old.json new.json -f markdown -o CHANGES.md
keycensus diff old.json new.json -f json | jq .summary

# scan and diff in one go: also writes out/diff.json and out/diff.md
keycensus scan -c keycensus.yml -o out --baseline last/inventory.json
```

### Exit codes (CI gates)

| Command | Flag | Exit | Meaning |
|---|---|---|---|
| `scan` | `--fail-on high` | 1 | any finding ≥ high exists (absolute gate) |
| `scan` | *(always)* | 2 | a source failed to scan |
| `scan` / `diff` | `--fail-on-new high` | 3 | a finding ≥ high exists **that was not in the baseline** (drift gate: existing debt is tolerated, new debt is not) |
| `diff` | `--fail-on-change` | 4 | anything at all changed (change-freeze gate) |

`--fail-on-new` is the one most teams want in a pipeline: it lets you adopt keycensus on an estate
with known problems and still block *new* ones.

## Example output

```
keycensus diff: 2026-08-01T02:00:11Z -> 2026-09-01T02:00:09Z

assets: +2 -1 ~3    findings: +2 resolved 1    worst new: high

added (2):
  + kv-payments/tde-2026 [RSA-3072] active
  + gcp-payments/dek-eu [AES-256] active

removed (1):
  - app-certs/legacy-portal [RSA-2048]

changed (3):
  ~ vault-prod/dek [AES-256]
      last_rotated: 2026-05-01T00:00:00Z -> 2026-08-28T00:00:00Z
  ~ luna-payments/pin-kek [3DES-192]
      state: active -> deactivated
  ~ edges/api.example.com:443 [EC-P-256]
      expires: 2026-09-10T00:00:00Z -> 2027-09-10T00:00:00Z
      fingerprint_sha256: 3f…a1 -> 9c…04

new findings (2):
  ! [high    ] dek-eu — Key has no automatic rotation
  ! [medium  ] tde-2026 — Exportable key

resolved findings (1):
  ✓ [critical] api.example.com:443 — Certificate expires in 9 days
```

`diff.md` is the same as a Markdown report (tables), `diff.json` the machine-readable form:

```json
{"tool": "keycensus-diff", "before": "...", "after": "...",
 "summary": {"assets_added": 2, "assets_removed": 1, "assets_changed": 3, "findings_new": 2,
             "findings_new_by_severity": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
             "findings_resolved": 1, "sources_broken": 0, "worst_new_severity": "high"},
 "assets_added": [...], "assets_removed": [...], "assets_changed": [{"id": "...", "changes": {"state": {"before": "active", "after": "deactivated"}}}],
 "findings_new": [...], "findings_resolved": [...], "sources": {"added": [], "removed": [], "broken": [], "fixed": []}}
```

## Keeping a baseline

Anything that keeps the previous `inventory.json` works: a directory per scan date, an artifact in your
CI system, an S3 prefix. The Helm chart's CronJob keeps `/out/latest` on a PVC and diffs against it
automatically. In GitHub Actions:

```yaml
- uses: actions/download-artifact@v4
  with: { name: keycensus-baseline, path: last }
  continue-on-error: true
- run: keycensus scan -c keycensus.yml -o out --baseline last/inventory.json --fail-on-new high
- uses: actions/upload-artifact@v4
  if: always()
  with: { name: keycensus-baseline, path: out/inventory.json, overwrite: true }
```

## From a diff to an alert

A diff is a report; an alert needs to know which changes are worth interrupting someone for. `keycensus
changes` classifies every change into a **kind** with an **urgency** (`page` / `digest` / `ignore`),
`serve` exports it as `keycensus_change_total{kind,urgency}`, and a webhook can post the page-worthy
ones straight to Slack or Teams.

```bash
keycensus changes --kinds                              # the vocabulary and its default urgency
keycensus changes before/inventory.json out/inventory.json
keycensus scan -c keycensus.yml -o out --baseline last/inventory.json --fail-on-page   # exit 5
```

See **[ALERTING.md](ALERTING.md)** for the metric names, the shipped alert rules, the urgency table and
how to re-map it for your estate.
