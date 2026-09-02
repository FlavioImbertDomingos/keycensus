# Changelog

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
