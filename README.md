# keycensus

**A census of every cryptographic key, certificate and TLS endpoint you own — and what's wrong with them.**

<img width="1259" height="691" alt="image" src="https://github.com/user-attachments/assets/72bfa9da-9c43-49be-8ff0-c0693996d0e7" />


One command scans your HSMs (PKCS#11, CipherTrust Manager, KeySafe 5), Vault, AWS KMS, Azure Key Vault /
Managed HSM, Google Cloud KMS, Voltage, certificate folders and TLS ports; produces a
standards-based **CBOM** (CycloneDX 1.6), an HTML report a human can read, and Prometheus metrics;
and grades every asset against **PCI DSS v4.0**, **NIST SP 800-57 / 800-131A** and the
**NIST IR 8547 post-quantum timeline**.

<img width="791" height="795" alt="image" src="https://github.com/user-attachments/assets/4fbf4273-ffa2-49c1-9bc3-b476d63d0a16" />


[![CI](https://github.com/FlavioImbertDomingos/keycensus/actions/workflows/ci.yml/badge.svg)](https://github.com/FlavioImbertDomingos/keycensus/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CycloneDX 1.6](https://img.shields.io/badge/CBOM-CycloneDX%201.6-orange.svg)](docs/CBOM.md)

---

## Non-techinical explanation

Imagine your school has hundreds of lockers, and every locker has a key. Some keys are in the
office safe, some are with teachers, some are taped under desks. Some locks are the good new kind,
some are the flimsy kind from 1995 that open with a paperclip. And nobody has a list.

**keycensus walks around, finds every key, and writes the list.** For each one it notes:
*what kind of lock it opens, how strong the lock is, how old the key is, where it's kept,
and whether it's the paperclip kind.* Then it hands you two things:

1. A **report** with the problems at the top — "this lock is the paperclip kind", "this key is
   8 years old", "this door pass expires next Tuesday".
2. The **list itself in a standard format** (a *CBOM*), so auditors and other tools can read it
   without asking you.

Why now? Two reasons. **PCI DSS 4.0** now *requires* the list (requirement 12.3.3, mandatory since
March 2025). And **quantum computers** will eventually open a whole category of today's locks
(RSA and elliptic-curve), so NIST says: know which ones you have by 2030, replace them by 2035.
You can't replace what you haven't counted.


---

## Try it in 3 minutes (no HSM, no AWS account, no Voltage licence)

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/) or Docker Engine + compose.

```bash
git clone https://github.com/FlavioImbertDomingos/keycensus.git
cd keycensus
docker compose up -d
```

Give it ~60 seconds (Vault boots, gets seeded, a SoftHSM token is created, a fake KMS is populated),
then open **http://localhost:9742/report.html**.

| What | Where |
|---|---|
| HTML report | http://localhost:9742/report.html |
| CBOM (CycloneDX 1.6) | http://localhost:9742/cbom.json |
| Raw inventory | http://localhost:9742/inventory.json |
| Prometheus metrics | http://localhost:9742/metrics |
| Vault UI (token `root`) | http://localhost:8200 |

Want charts and alerts too? `docker compose --profile monitoring up -d` adds Prometheus and Grafana
(http://localhost:3000, admin/admin) with a pre-built dashboard.

### What the demo scans

Nothing is faked in the *code path* — only the *backends* are stand-ins:

| Source in demo | What it really is | Findings you'll see |
|---|---|---|
| `softhsm` | A real PKCS#11 token (SoftHSM) inside the container, seeded with 8 keys | 3DES key, RSA-1024, an extractable KEK, quantum-vulnerable RSA/EC |
| `vault` | A **real HashiCorp Vault** dev server with Transit keys + a PKI mount | exportable key, rotation off, short-lived cert, AES-128 |
| `fake-aws` | moto — an AWS API mock so faithful that real `boto3` doesn't notice | rotation disabled, disabled key, quantum-vulnerable signing keys |
| `voltage` | A mock inventory export in the canonical Voltage shape | rotation overdue (800 days), 3DES, software-only keys |
| `app-certs` | A folder of deliberately imperfect PEM files | expired cert, expiring-in-10-days, RSA-1024, orphan private key |
| `edges` | The mock's HTTPS port, scanned like any TLS endpoint | self-signed, expiring cert |

### What the output looks like

```
$ docker compose exec keycensus keycensus scan -c /config/keycensus.yml -o /out

assets:   45  (key=36, certificate=8, protocol=1)
sources:  6/6 ok
  - softhsm (pkcs11): 12 assets
  - vault (vault): 10 assets
  - fake-aws (aws-kms): 7 assets
  - voltage (voltage): 7 assets
  - app-certs (pem): 8 assets
  - edges (tls): 2 assets
findings: critical=1, high=5, medium=14, low=25, info=19

  [critical] legacy.batch — Certificate has EXPIRED
  [high    ] old.reporting — RSA-1024 is below the strong-cryptography minimum
  [high    ] legacy-pin-3des — 3DES is a broken or deprecated algorithm
  [high    ] batch-3des — 3DES is a broken or deprecated algorithm
  [medium  ] pan-fpe-legacy — Key is 800 days old, cryptoperiod is 365 days
  [medium  ] gateway.payments — Certificate expires in 10 days
  ...
```

Every finding says **what**, **why it matters**, **what to do**, and **which control** it maps to
(`PCI-DSS-4.0:3.7.4`, `NIST-IR-8547`, ...).

---

## Point it at your real estate

```bash
cp config/keycensus.example.yml config/keycensus.yml     # describe your sources
cp .env.example .env                                     # secrets go here, never in YAML
pip install "keycensus[all]"                             # or use the container
keycensus scan -c config/keycensus.yml -o ./out
```

```yaml
# config/keycensus.yml
policy: default
sources:
  - name: luna-payments
    type: pkcs11
    module: /usr/safenet/lunaclient/lib/libCryptoki2_64.so
    token_label: payments-partition
    pin_env: LUNA_PIN_PAYMENTS
    hardware_backed: true
    fips_validated: true
  - name: vault-prod
    type: vault
    url: https://vault.example.com:8200
    token_env: VAULT_TOKEN
  - name: aws-prod
    type: aws-kms
    region: us-east-1
  - name: kv-payments
    type: azure-keyvault
    vault_url: https://payments-kv.vault.azure.net
  - name: gcp-payments
    type: gcp-kms
    project: acme-payments-prod
  - name: ctm-prod
    type: ciphertrust
    url: https://ctm.example.com
    username: keycensus
    password_env: CTM_PASSWORD
  - name: voltage
    type: voltage
    file: /exports/voltage-keys.csv
  - name: app-certs
    type: pem
    paths: [/etc/ssl/app]
  - name: edges
    type: tls
    endpoints: ["api.example.com:443"]
```

Then either run it on a schedule (`keycensus scan ... --fail-on high` in CI / cron) or leave it
running (`keycensus serve -c ... --interval 6h`) and point Prometheus at `:9742/metrics`.

**Read-only, always.** Every collector uses list/describe/read calls only. The PKCS#11 collector
never reads key values, only public attributes. See [SECURITY.md](SECURITY.md).

---

## What it checks

| Rule | Default | Control |
|---|---|---|
| Broken / deprecated algorithm (DES, 3DES, RC4) | high | PCI 3.5.1, 3.7.5; NIST 800-131A |
| Key size below "strong cryptography" (RSA<2048, ECC<224, AES<128) | high | PCI 3.7.1 |
| Certificate signed with SHA-1 / MD5 | high | PCI 4.2.1 |
| Key older than its cryptoperiod | medium | PCI 3.7.4; NIST 800-57 |
| Automatic rotation available but off | low | PCI 3.7.4 |
| Certificate expired / expiring (7d, 30d) | critical / high / medium | PCI 4.2.1 |
| Key exportable / extractable | medium | PCI 3.7.3, 3.6.1 |
| Key in software, not an HSM | low | PCI 3.6.1; FIPS 140-3 |
| Quantum-vulnerable **encryption** key (harvest-now-decrypt-later) | medium | NIST IR 8547; PCI 12.3.3 |
| Quantum-vulnerable signing key | low | NIST IR 8547; PCI 12.3.3 |
| AES-128 (reduced quantum margin) | info | NIST IR 8547 |
| TLS < 1.2 accepted, weak cipher suite, no forward secrecy | high / high / low | PCI 4.2.1, 12.3.3 |
| No creation date (cryptoperiod unknowable) | info | PCI 12.3.3, 3.6.1.1 |

All thresholds and severities live in one YAML: [`keycensus/data/default-policy.yml`](keycensus/data/default-policy.yml).
Copy it, change the numbers, pass `--policy`. Full list: [docs/POLICY.md](docs/POLICY.md).

---

## Outputs

| Format | For | Notes |
|---|---|---|
| `cbom.json` | Auditors, Dependency-Track, PQC migration tools | CycloneDX 1.6, `cryptographic-asset` components; findings as `vulnerabilities`; **schema-validated in CI** |
| `report.html` | Humans | Self-contained, printable, filterable |
| `inventory.json` | Scripts | Everything, including raw source fields |
| `inventory.csv` | Spreadsheets, GRC uploads | One row per asset with findings column |
| `/metrics` | Prometheus | Findings by severity/rule/source, key age, cert expiry, quantum class |
| `diff.json` / `diff.md` | Change review, CI gates | With `--baseline previous/inventory.json`: assets added / removed / changed, findings new / resolved, sources broken |

```bash
keycensus scan -c keycensus.yml -o out --baseline last/inventory.json --fail-on-new high   # exit 3 on new high+ findings
keycensus diff last/inventory.json out/inventory.json -f markdown                           # or text / json
keycensus upload dtrack --url https://dtrack.corp --project hsm-estate --version 2026-09-02 --cbom out/cbom.json
helm install keycensus ./helm/keycensus -f my-values.yaml                                    # Deployment and/or CronJob
```

---

## Add a source

A collector is one Python class:

```python
class MyKmsCollector(Collector):
    type_name = "my-kms"
    def collect(self) -> list[CryptoAsset]:
        return [self.asset(kind="key", name="...", native_id="...", algorithm="AES", key_size=256, ...)]
```

Register it in `keycensus/collectors/__init__.py`, done. Entrust nShield, Utimaco, YubiHSM and
CloudHSM already work through the PKCS#11 collector. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
has the walkthrough.

---

## Documentation

- [docs/COLLECTORS.md](docs/COLLECTORS.md) — every source type, its options, and the permissions it needs
- [docs/DIFF.md](docs/DIFF.md) — diff mode: what changed since the last scan, and how to gate CI on it
- [docs/DEPENDENCY-TRACK.md](docs/DEPENDENCY-TRACK.md) — pushing the CBOM into OWASP Dependency-Track
- [helm/keycensus/README.md](helm/keycensus/README.md) — the Helm chart (serve Deployment and/or scan CronJob)
- [docs/POLICY.md](docs/POLICY.md) — every rule, how it decides, how to tune it
- [docs/CBOM.md](docs/CBOM.md) — how assets map to CycloneDX, and how to load the CBOM elsewhere
- [docs/COMPLIANCE.md](docs/COMPLIANCE.md) — the PCI DSS / NIST controls and what evidence keycensus gives you
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — design, data model, adding collectors and rules
- [docs/FAQ.md](docs/FAQ.md)
- [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CHANGELOG.md](CHANGELOG.md)

## Status & honesty

- The PKCS#11, Vault, AWS KMS, PEM and TLS collectors run **real code paths** in the demo and tests
  (SoftHSM, a real Vault, moto's AWS API, generated certs, a live TLS handshake).
- The Azure Key Vault / Managed HSM and Google Cloud KMS collectors speak the documented REST APIs and are
  tested against recorded responses; they have not yet run against a live subscription/project in CI.
- The CipherTrust Manager and KeySafe 5 collectors were written from the vendors' REST API references and
  tested against mocks. Field names are matched tolerantly and can be remapped; a redacted real response is
  the most useful issue you can open.
- **Voltage SecureData has no public inventory API.** The `voltage` collector consumes an export
  (JSON or CSV, from the Management Console or an internal adapter) with a configurable field map.
  If you run Voltage and can share a redacted export, that is the most useful issue you can open.
- Control text is paraphrased. keycensus is evidence for *your* assessment, not a QSA.
- Cryptoperiod defaults are opinions (365 d symmetric, 730 d asymmetric). Change them.

## Roadmap

- [x] Azure Key Vault / Managed HSM and Google Cloud KMS collectors *(0.2.0)*
- [x] Entrust KeySafe 5 and Thales CipherTrust Manager REST collectors (beyond PKCS#11) *(0.2.0, mock-verified)*
- [x] Diff mode: what changed since the last scan *(0.2.0)*
- [x] Dependency-Track upload helper *(0.2.0)*
- [x] Helm chart *(0.2.0)*
- [ ] Integration tests against real Azure / GCP accounts (needs credentials in CI)
- [ ] Real-appliance validation of the CipherTrust and KeySafe 5 field mappings
- [ ] SBOM ↔ CBOM linking: which application uses which key

Sister project: [luna-exporter](https://github.com/FlavioImbertDomingos/luna-exporter) — Prometheus
monitoring for Thales Luna appliances.

## License

Apache-2.0. Not affiliated with Thales, OpenText, HashiCorp or AWS.
