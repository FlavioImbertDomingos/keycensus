# Changelog

## 0.5.0 — 2026-09-03

**Who uses this key — the last two gaps.** AWS grants, GCP IAM bindings and CipherTrust owners have
fed `used_by` since 0.3.0; Azure was the one cloud that could not answer, and SPDX users could not
declare an application at all.

**Azure RBAC consumers** (`include_rbac`, on by default)

- Azure authorizes three different ways and the collector reads whichever the vault uses: ARM role
  assignments at the vault scope for RBAC vaults, `properties.accessPolicies` for the older model,
  and the HSM's own data-plane local RBAC for Managed HSM — which needs no ARM call and no extra
  permission at all.
- Roles that only *list* (Key Vault Reader, Managed HSM Crypto Auditor) are deliberately not
  consumers: they can see that a key exists, not use it. Same for `get`+`list` access policies.
- The management plane is a different endpoint and a different token audience, so `auth: token` now
  takes `arm_token_env` alongside `token_env`. With `auth: default` the credential chain handles it.
- `used_by` is filled at the **vault** scope, because that is where Azure authorizes. AWS and GCP are
  per key; pretending Azure is too would invent precision the platform does not have.
- Optional Microsoft Graph name resolution (`resolve_principal_names`), off by default because
  `Directory.Read.All` is a much larger permission than reading an inventory. Without it, principals
  are reported as object ids.
- A 403 anywhere in this path is logged and tolerated — no consumer information is worse than no
  inventory.

**SPDX SBOMs for linking**

- `applications: - sbom: foo.spdx.json` now works for SPDX 2.2 and 2.3 JSON alongside CycloneDX.
  Identity comes from the package the document **DESCRIBES** — not the document name (usually the
  file) and not the first package (usually a dependency). Falls back to the 2.2 `documentDescribes`
  shorthand, then to the single package when there is exactly one.
- purl from the `externalRefs` entry with `referenceType: purl`; owner from `supplier`, else
  `originator`, unwrapping `"Organization: ACME (a@b)"` to `ACME` and ignoring `NOASSERTION`.
- `Application.sbom_format` records which reader ran. A test pins that both formats link an
  application to exactly the same assets — the format must never change the answer.
- Unreadable SBOMs now say what to do: XML and SPDX tag-value point at `syft convert`.
- The demo's third application ships an SPDX SBOM, so `make demo` exercises both readers.

## 0.4.0 — 2026-09-03

**Alerting on change, not just on state.** The diff existed as a CLI command and an exit code and
exported no metrics, so "a key became exportable an hour ago" could not fire anything. Suggested by
[Jitendra Bhargude](https://www.linkedin.com/in/jitendrabhargude/), who pointed out that diff mode without alerts is half a
feature.

- `keycensus/changes.py` — every raw field change is classified into a **kind** with an **urgency**
  (`page` / `digest` / `ignore`). 30 kinds; 12 page by default. Weakening is judged with the same
  strength model the findings use, so RSA-3072 → RSA-2048 pages and RSA-2048 → RSA-4096 does not, and
  a key that was already `destroyed` disappearing is a digest rather than a page.
- `keycensus changes` — `--kinds` prints the vocabulary and its default urgency; two inventory files
  print the classified diff, with the *reason* each page-worthy change matters.
- **Metrics**: `keycensus_change_total{kind,urgency,source}`, `keycensus_changes_last_scan{kind,urgency}`,
  `keycensus_last_change_timestamp_seconds`, `keycensus_diffs_total`. `serve` diffs every rescan
  against the previous one and publishes `/diff.json` and `/changes.json` beside the report.
- **Alert rules**: six new rules in `prometheus/alerts/keycensus.rules.yml` — a catch-all on
  `urgency="page"`, dedicated pages for a vanished key / a key that became exportable / crypto that
  weakened / rotation being switched off, a digest rule that never pages, and
  `KeycensusNoChangeDetectionRunning` for when the diff itself stops running.
- **Webhooks** (`keycensus/notify.py`) for teams without Prometheus: `generic`, `slack` and `teams`
  payloads, `on: page|any|never`. The URL comes from the environment and an inline `webhook_url:` is
  rejected — a webhook URL is a credential. A delivery failure never changes the exit code.
- `changes.urgency` in the config re-maps any kind; an unknown kind is a config error, not a silent
  no-op, so a typo cannot quietly disable an alert.
- `--fail-on-page` on `scan` and `diff`: **exit 5** when the estate got worse. Ignores the churn of
  new keys and rotations that `--fail-on-change` (exit 4) catches.
- Docs: [docs/ALERTING.md](docs/ALERTING.md), with a short opinion on what should page and what
  should not.


## [0.3.0] - 2026-09-02

### Added
- SBOM <-> CBOM linking (`docs/LINKING.md`): `applications:` in the config, each optionally backed by a
  CycloneDX SBOM, with selectors (`source`, `name`, `tag`, `principal`, `kind`, ...) and automatic matching
  against inferred consumers. Collectors now report who may use each key (`asset.used_by`): AWS KMS grants and
  key-policy principals, Google Cloud KMS IAM bindings, Vault ACL policies on transit paths, CipherTrust
  application/owner. Outputs: `application` components + `dependsOn` in the CBOM, an Applications table and
  *Used by* column in the HTML report, `applications`/`used_by` in JSON and CSV, `keycensus_application_*`
  metrics, diff-mode awareness, and an `unlinked-asset` finding for orphan keys. New `keycensus link` command
  re-links a saved scan with new SBOMs without rescanning.
- Live integration tests for Azure Key Vault and Google Cloud KMS (`tests/integration/`, skipped without
  credentials), fixture bootstrap/teardown scripts, and an OIDC-only workflow gated on repository variables.
- Demo: two SBOMs, KMS grants and Vault policies so the compose stack shows linking end to end.

### Changed
- `Inventory.from_dict` / `CryptoAsset.from_dict` round-trip `inventory.json` (used by `link`).

## [0.2.0] - 2026-09-02

### Added
- Collectors: `azure-keyvault` (Azure Key Vault + Managed HSM, keys and certificates, rotation policy),
  `gcp-kms` (Google Cloud KMS, all locations, protection levels, version states), `ciphertrust` (Thales
  CipherTrust Manager REST: JWT login, `vault/keys2`, usage mask, lifecycle states) and `keysafe5` (Entrust
  KeySafe 5 REST: Security World keys, protection method, HSM ESNs, tolerant field mapping).
  Optional extras `keycensus[azure]` (azure-identity) and `keycensus[gcp]` (google-auth); token auth works without them.
- Diff mode: `keycensus diff BEFORE AFTER` (text / markdown / json, `--fail-on-new`, `--fail-on-change`) and
  `keycensus scan --baseline previous/inventory.json` writing `diff.json` + `diff.md` (exit 3 with `--fail-on-new`).
- `keycensus upload dtrack`: push the CBOM to OWASP Dependency-Track (`PUT /api/v1/bom`, auto-create, parent
  project, wait for processing, prints the project URL).
- Helm chart `helm/keycensus`: serve Deployment (Service, optional ServiceMonitor / Ingress) and/or scan CronJob
  with a persistent baseline, diff, fail gates and Dependency-Track upload; secrets via `existingSecret`.

### Changed
- `keycensus scan` exit codes: 1 findings at/above `--fail-on`, 2 a source failed, 3 new findings at/above
  `--fail-on-new` (with `--baseline`). Lower codes win when several apply.

## [0.1.0] - 2026-09-02

### Added
- Collectors: PKCS#11 (any HSM), HashiCorp Vault (Transit + PKI), AWS KMS, Voltage SecureData
  export (JSON/CSV, file or URL, field mapping), PEM/DER files, live TLS endpoints.
- Policy engine with 21 rules covering weak algorithms/sizes, cryptoperiods, rotation, certificate
  expiry, key storage, TLS hygiene and post-quantum readiness; YAML-tunable thresholds and severities.
- Control mapping to PCI DSS v4.0.1 (3.5.1, 3.6.1, 3.6.1.1, 3.7.1/3/4/5, 4.2.1, 12.3.3),
  NIST SP 800-57, SP 800-131A, IR 8547, FIPS 140-3.
- Outputs: CycloneDX 1.6 CBOM (schema-validated), self-contained HTML report, JSON, CSV,
  Prometheus metrics via `keycensus serve`.
- Demo stack: real Vault, SoftHSM, moto KMS, mock Voltage, imperfect demo certs; optional
  Prometheus + Grafana profile with alert rules and dashboard.
- CI: lint, tests on 3.11/3.12 with SoftHSM, promtool, compose smoke test, GHCR publish.
