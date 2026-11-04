# Post-quantum transition timeline

The dates that drive the `quantum-*` rules, and what keycensus gives you for each. Every entry links
to its source. Last checked: 4 November 2026.

| Date | What happened | Binding? | What keycensus gives you |
|---|---|---|---|
| Aug 2024 | NIST publishes FIPS 203 (ML-KEM, key establishment), FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA, signatures) | Standard | ML-KEM, ML-DSA and SLH-DSA assets are recognised as `quantum-safe` with their NIST security category in the CBOM |
| 31 Mar 2025 | PCI DSS requirement 12.3.3 takes effect: an inventory of cipher suites and protocols in use, a plan for weakened algorithms, reviewed at least annually | Yes, for PCI scope | The CBOM is the inventory; `quantum-*`, `weak-*` and `tls-*` findings are the input to the plan; a scheduled scan is the annual review |
| Jan 2026 | G7 Cyber Expert Group roadmap for the financial sector: critical systems in 2030 to 2032, 2035 as a general target for the rest | No, it states it sets no regulatory expectations | Its first phase is "discovery and inventory" of cryptographic assets, protocols and third-party dependencies; `used_by` and SBOM linking cover the dependency part |
| 22 Jun 2026 | US Executive Order 14412: federal high value assets and high-impact systems move to post-quantum key establishment by 31 Dec 2030 and post-quantum signatures by 31 Dec 2031. It also directs NIST and CISA to write guidance for a cryptographic bill of materials | Yes, for federal agencies; contractors through FAR rules to follow | `quantum-vulnerable-encryption` maps to the 2030 key-establishment deadline, `quantum-vulnerable` to the 2031 signature deadline; both cite `US-EO-14412` |
| Jul 2026 | DigiCert survey of 1,001 IT and security decision makers (US, UK, Australia): 87% are planning, testing or implementing PQC; 7% have quantum-safe or hybrid cryptography across most of their certificates | Data | The gap between those two numbers is mostly inventory: you cannot replace certificates you have not found. The `pem`, `tls`, `vault` and `adcs` collectors find them |
| 27 Oct 2026 | NIST IR 8547, final. RSA, ECDSA, EdDSA, DH and ECDH are deprecated after 2030 and disallowed after 2035, at every security strength. ML-KEM-768 is the recommended default. Hybrids stay allowed, but NIST calls them temporary and expects a second move to PQC only | NIST guidance; binding where FIPS or federal policy applies | `quantum-vulnerable` findings fire for every RSA and ECC key regardless of size; TLS and SSH endpoints are classified as classical, `hybrid` (allowed, temporary) or ML-KEM by their negotiated key exchange; findings cite `NIST-IR-8547`; the report's executive summary and PQC readiness bar show the share left to migrate |

## The executive summary

`report.html` opens with a summary built from these dates. The same numbers are in `inventory.json`
under `executive`, in the console output of `keycensus scan`, and in Prometheus. It counts keys and
certificates (the public half of a key pair is folded into its private key) and probed endpoints, as
of the scan date.

| Row | Date | Counts | Basis |
|---|---|---|---|
| Now | in force since 31 Mar 2025 | Assets with a `weak-algorithm`, `weak-key-size`, `deprecated-signature-hash`, `adcs-template-weak-key-size`, `tls-weak-protocol`, `tls-weak-cipher` or `ssh-weak-algorithm` finding | PCI DSS 12.3.3, SP 800-131A |
| Key establishment | 31 Dec 2030 | Quantum-vulnerable keys used to encrypt, decrypt, wrap, unwrap or derive, DH and X25519 keys, and endpoints with classical key exchange | EO 14412; IR 8547 deprecation |
| Signatures | 31 Dec 2031 | Quantum-vulnerable signing keys and every quantum-vulnerable certificate | EO 14412; IR 8547 deprecation |
| Disallowed | 31 Dec 2035 | Everything still quantum-vulnerable, plus classical endpoints | IR 8547; G7 general target |

Choices worth knowing:

- A key that both signs and decrypts falls due at the earlier date (2030).
- A quantum-vulnerable key with no recorded purpose appears only in the 2035 row, and the report says
  how many there are. If it could be used to encrypt, plan it for 2030.
- "Still valid on the date" counts keys and certificates whose expiry falls after the deadline. Those
  will still be in service when the date passes, so waiting for normal renewal is too late.
- Hybrid endpoints meet the 2030 date and are not counted as due; the summary reminds you that
  IR 8547 expects a second move to pure ML-KEM.
- EO 14412 binds federal high-value assets and high-impact systems only. The rows count the whole
  scan; scan federal-scope sources separately if you need the federal figure.

Metrics: `keycensus_quantum_vulnerable_ratio`, `keycensus_pqc_milestone_assets{milestone,date,kind}`
(`kind` is `asset` or `endpoint`) and `keycensus_pqc_milestone_days_left{milestone,date}`. For example,
to alert when anything is still waiting on the 2030 key-establishment date with a year to go:

```promql
keycensus_pqc_milestone_assets{milestone="key-establishment-2030"} > 0
  and on(milestone) keycensus_pqc_milestone_days_left < 365
```

## What changed from the 2024 draft of IR 8547

The November 2024 draft deprecated only the 112-bit algorithms (RSA-2048, P-224) in 2030 and left
128-bit ones such as RSA-3072 and P-256 until 2035. The final report deprecates all of them in 2030.
A plan that kept RSA-3072 until 2035 now runs five years past the deprecation date. keycensus
already treated every RSA and ECC key as quantum-vulnerable, so no rule changed; the control text
did.

The final report also says NIST does not expect to move off AES-128, AES-192, AES-256 or SHA-2 as
part of this transition. keycensus still flags AES-128 and AES-192 as `quantum-reduced` (info), but
the finding no longer cites IR 8547, because IR 8547 does not ask for that change. Turn it off if
your programme agrees with NIST:

```yaml
rules:
  quantum-reduced: {enabled: false}
```

SHA-1 is disallowed in FIPS 140 validated modules after 2030; `deprecated-signature-hash` now cites
IR 8547 as well as SP 800-131A.

## Hybrid key exchange

The `tls`, `ssh` and `network` collectors report the key exchange each endpoint negotiates. TLS 1.3
groups are read from the server's first reply to a ClientHello that offers X25519MLKEM768 the way
browsers do; SSH key exchange algorithms from the server's KEXINIT. Hybrids (X25519MLKEM768,
SecP256r1MLKEM768, SecP384r1MLKEM1024, mlkem768x25519-sha256, sntrup761x25519-sha512) are classified
`hybrid`: allowed by IR 8547 but temporary, reported as an info finding so the second transition stays
on the plan. Classical key exchange is `quantum-vulnerable-key-exchange` (medium). Details in
[COLLECTORS.md](COLLECTORS.md#key-exchange-classical-hybrid-or-ml-kem).

## What keycensus does not cover yet

- The NIST and CISA CBOM guidance called for by EO 14412 is not published yet. The CBOM is
  CycloneDX 1.6; once the minimum elements are out, docs/CBOM.md will map each one to a field.

## Sources

- NIST IR 8547, *Transition to Post-Quantum Cryptography Standards*, final, 27 October 2026:
  https://csrc.nist.gov/pubs/ir/8547/final (https://doi.org/10.6028/NIST.IR.8547)
- NIST FIPS 203, 204 and 205, August 2024: https://csrc.nist.gov/projects/post-quantum-cryptography
- PCI DSS v4.0.1, requirement 12.3.3: https://www.pcisecuritystandards.org/
- G7 Cyber Expert Group, *Advancing a coordinated roadmap for the transition to post-quantum
  cryptography in the financial sector*, January 2026:
  https://home.treasury.gov/system/files/136/G7-CEG-Quantum-Roadmap.pdf
- Executive Order 14412, *Securing the Nation Against Advanced Cryptographic Attacks*, 22 June 2026
  (summary with section references: https://blog.cloudflare.com/post-quantum-eo-2026)
- DigiCert, *Quantum Readiness Outlook*, 23 July 2026:
  https://www.digicert.com/news/quantum-security-deployment-remains-stuck

Dates and requirements are paraphrased. Read the source before you rely on one.
