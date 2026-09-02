# Compliance mapping

keycensus produces **evidence**, not a verdict. Control text below is paraphrased; read the
standard. Not QSA or legal advice.

## PCI DSS v4.0.1

| Requirement | What it asks (paraphrased) | keycensus evidence |
|---|---|---|
| **3.5.1** | Stored PAN rendered unreadable with strong cryptography | `weak-algorithm`, `weak-key-size` findings on keys tagged for PAN protection |
| **3.6.1** | Procedures protect keys used to protect stored account data | `key-exportable`, `key-software-backed`; `hardwareBacked` / `securedBy` per key in the CBOM |
| **3.6.1.1** *(service providers)* | Documented cryptographic architecture: algorithms, protocols, keys, expiry, HSM usage | The CBOM **is** this document; `no-creation-date` flags the gaps |
| **3.7.1** | Strong key generation | `weak-key-size` |
| **3.7.3** | Secure key storage | `key-exportable`, `key-software-backed` |
| **3.7.4** | Key changes at the end of the cryptoperiod | `rotation-overdue`, `rotation-disabled`; the policy file documents the cryptoperiods |
| **3.7.5** | Retire/replace weakened or compromised keys | `weak-algorithm`, `deprecated-signature-hash`, `key-not-active` |
| **4.2.1** | Strong cryptography for PAN in transit; only trusted keys/certs | `tls-*` findings, `cert-expired`, `cert-expiring-*`, `cert-self-signed` |
| **12.3.3** | Inventory of cipher suites and protocols in use, reviewed ≥ annually, with a plan for deprecated ones | The CBOM + `quantum-*` and `tls-*` findings; run it on a schedule and keep the outputs |

**How to present it to an assessor:** a dated `cbom.json` + `report.html` from a scheduled scan,
the policy YAML (your cryptoperiods and thresholds), and the ticket trail for the findings.
`keycensus scan --fail-on high` in a pipeline gives you the "we would have caught it" evidence.

## NIST

| Document | Relevance | keycensus |
|---|---|---|
| SP 800-57 Part 1 Rev. 5 | Security strengths (Table 2) and cryptoperiod guidance (Table 1) | `classicalSecurityLevel` in the CBOM; default cryptoperiods |
| SP 800-131A Rev. 2 | Algorithm/key-length transitions: 3DES disallowed after 2023, SHA-1 signatures disallowed, < 112-bit keys disallowed | `weak-algorithm`, `weak-key-size`, `deprecated-signature-hash` |
| IR 8547 (2024) | PQC transition: quantum-vulnerable algorithms deprecated 2030, disallowed 2035 | `quantum-vulnerable(-encryption)`, `quantum-reduced`; `nistQuantumSecurityLevel` in the CBOM; the PQC readiness bar in the report |
| FIPS 140-3 | Validated modules | `fipsValidated` / `certificationLevel` where the source tells us (AWS KMS, or your `fips_validated: true` on a PKCS#11 source) |
| FIPS 203 / 204 / 205 | ML-KEM, ML-DSA, SLH-DSA | Recognised as `quantum-safe`; Vault `ml-dsa-*` and KMS `ML_DSA_*` specs are mapped |

## What keycensus does *not* do

- Prove keys are *used* for PAN — tag them (`tags: {pci: "true"}`) and filter.
- Check key custodian procedures, split knowledge, dual control (3.7.6–3.7.8) — process controls.
- Assess whether a cipher suite is acceptable *for your risk* — it flags the widely-deprecated ones.
- Replace a QSA.
