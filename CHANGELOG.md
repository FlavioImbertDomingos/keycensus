# Changelog

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
