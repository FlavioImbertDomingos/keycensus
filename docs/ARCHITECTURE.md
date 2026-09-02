# Architecture

```
 config.yml ──► scanner.scan()
                  │  builds one Collector per source, runs them in a thread pool
                  ▼
        ┌── collectors/ ───────────────────────────────────────────┐
        │ pkcs11  vault  aws_kms  voltage  pem_files  tls_endpoint │   each returns list[CryptoAsset]
        └──────────────────────────────────────────────────────────┘
                  │
                  ▼
            model.Inventory  (sources + assets)
                  │
                  ▼
        analysis/policy.evaluate()  ──► list[Finding]      (rules × assets, thresholds from policy YAML)
        analysis/strength.assess()  ──► classical bits, quantum class, NIST level
        analysis/controls           ──► control catalogue text
                  │
                  ▼
        exporters/  json · csv · cbom (CycloneDX 1.6) · html_report · prometheus
                  │
                  ▼
        cli.py (scan / serve / rules / collectors / controls / validate)
        serve.py (rescan loop + tiny HTTP server: /metrics /report.html /cbom.json ...)
```

## The one model everything speaks

`CryptoAsset` (in `model.py`) is deliberately flat and vendor-neutral: source, kind
(key / certificate / protocol), canonical algorithm name, size/curve, key type, purposes,
created / last_rotated / expires, state, rotation_enabled, exportable, hardware_backed,
fips_validated, plus certificate-only and protocol-only fields, `tags`, and a free-form `extra`
dict for source specifics. Its `id` is a stable hash of `source|kind|native_id`, so ids survive
re-scans and CBOMs can be diffed.

Collectors *only* build assets. Rules *only* read assets. Exporters *only* read the inventory.
Nothing else crosses those lines — that's what makes each part independently replaceable and
testable.

## Design decisions

**Canonical algorithm names, not vendor strings.** `aes256-gcm96` (Vault), `SYMMETRIC_DEFAULT`
(KMS), `CKK_AES` (PKCS#11), `FF1-AES-256` (Voltage) all become `algorithm: AES, key_size: 256`.
Rules and the CBOM never see vendor spellings; the original is kept in `extra`.

**Findings are data, not log lines.** Each carries rule id, severity, what/why/how-to-fix, and
control ids. That lets the same finding become an HTML row, a CBOM vulnerability, a CSV cell and
a Prometheus label without re-deriving anything.

**Policy is YAML, rules are code.** Thresholds and severities change per organisation; the logic
of "what is a weak key" doesn't. Rules are tiny generator functions; adding one is ~10 lines.

**One bad source doesn't spoil the scan.** `Collector.run()` catches everything, records the
error on the `SourceResult`, and the report shows the failure prominently (a missing source is
an inventory gap, which is itself a PCI 12.3.3 issue).

**Read-only by construction.** No collector has a code path that writes to a source. The
PKCS#11 collector reads attributes, never values.

**Real backends in the demo wherever possible.** SoftHSM is real PKCS#11; Vault is real Vault;
moto is close enough that boto3 code is unmodified. Only Voltage is mocked, because there is
nothing public to be faithful to.

**Keypair halves are one key.** The public half of a PKCS#11 key pair is exported as an asset
(it exists) but skipped by rules when the private half is present, so RSA-1024 is one finding,
not two.

## Adding a rule

```python
# keycensus/analysis/policy.py
def rule_shared_label(p: Policy, a: CryptoAsset):
    if a.kind == KIND_KEY and a.name.lower() in {"test", "temp", "key1"}:
        yield _f(p, "suspicious-label", a, "Key has a placeholder name",
                 f"{a.name} in {a.source}", "Name keys by purpose and owner.",
                 ["PCI-DSS-4.0:12.3.3"], default_sev="info")

RULES["suspicious-label"] = rule_shared_label
```

Then add `suspicious-label: {enabled: true, severity: info}` to `data/default-policy.yml`, a test
in `tests/test_policy.py`, and a row in `docs/POLICY.md`.

## Adding a collector

See the bottom of [COLLECTORS.md](COLLECTORS.md). Subclass `Collector`, implement `collect()`,
register in `collectors/__init__.py`, mock the SDK in a test.

## Adding an exporter

A function `render(inv: Inventory) -> str`, registered in `exporters/__init__.py::FORMATS`
with a default filename. The serve loop picks up new formats automatically if you add them to
`serve._rescan_loop`.

## Repository map

| Path | What |
|---|---|
| `keycensus/model.py` | CryptoAsset, Finding, SourceResult, Inventory |
| `keycensus/config.py` | YAML loading, secret resolution (`*_env`, `*_file`) |
| `keycensus/collectors/` | one module per source type + `x509util.py` shared cert parsing |
| `keycensus/analysis/strength.py` | security strength & quantum classification tables |
| `keycensus/analysis/policy.py` | rules engine + policy loading/merging |
| `keycensus/analysis/controls.py` | control catalogue (PCI, NIST) |
| `keycensus/exporters/` | json, csv, cbom, html_report (+ `templates/report.html`), prometheus |
| `keycensus/scanner.py` | orchestration |
| `keycensus/serve.py` | long-running mode |
| `keycensus/cli.py` | click CLI |
| `demo/` | seed scripts (SoftHSM, Vault, KMS), demo cert generator, container entrypoint |
| `mock-voltage/` | Flask mock of a Voltage export + an HTTPS port |
| `tests/` | pytest; `fixtures/` holds the vendored CycloneDX schemas |
| `prometheus/`, `grafana/` | optional monitoring profile |
