# Policy & rules

A policy is a versioned **pack**: a YAML file with cryptoperiods (how long a key may live), certificate
thresholds, and settings per rule, plus a version, an effective date, a review date and references.
keycensus ships two packs, `default`
([`keycensus/data/default-policy.yml`](../keycensus/data/default-policy.yml)) and `nist-pqc`
([`keycensus/data/policies/nist-pqc.yml`](../keycensus/data/policies/nist-pqc.yml)), and you can write your
own.

```bash
keycensus policy show default                     # version, dates, references, every rule
keycensus policy show nist-pqc --as-of 2031-06-01 # severities on a future date
keycensus policy validate my-policy.yml           # unknown rules, bad severities and dates
keycensus policy diff default my-policy.yml       # what your pack changes, for review
keycensus scan -c config.yml --policy my-policy.yml   # or `policy: my-policy.yml` in the config
```

## Packs

A pack lists only what it changes. It is merged over the pack it `extends` (the built-in `default` unless
it says otherwise): `rules:` merges per rule, while `cryptoperiod_days:` and `certificate:` are replaced
wholesale when present (your numbers are the numbers).

```yaml
name: acme-crypto
version: "2027.1"            # bump on every change
effective: 2027-01-15        # the date this version applies from
review_by: 2027-07-15        # keycensus warns after this date
owner: crypto-governance@acme.example
extends: default             # or nist-pqc
references:
  - id: ACME-STD-12
    title: ACME Cryptographic Standard, section 12
    url: https://wiki.acme.example/crypto-standard
applies_to:                  # the whole pack; every key is optional
  exclude_source_types: [code]
rules:
  rotation-overdue:
    severity: high
    rationale: Keys protecting card data rotate yearly under ACME-STD-12.
  quantum-vulnerable-encryption:
    effective: 2027-04-01    # no findings before this date
    schedule:                # severity steps on dates
      - {from: 2028-01-01, severity: high}
    applies_to: {source_types: [pkcs11, aws-kms]}
    controls: [ACME-STD-12.4]          # replaces the rule's built-in controls
    references: [ACME-STD-12]          # added to the finding's references
  weak-hash: {enabled: false}
```

| Rule setting | Meaning |
|---|---|
| `enabled` | `false` switches the rule off. |
| `severity` | `critical`, `high`, `medium`, `low` or `info`. |
| `effective` | The rule raises nothing before this date. |
| `schedule` | Severity steps: from each `from:` date the rule uses that step's severity. |
| `applies_to` | `kinds`, `sources`, `source_types`, `exclude_sources`, `exclude_source_types`. A pack-level `applies_to` limits every rule. |
| `controls` | The control ids the finding cites, replacing the built-in ones. |
| `references` | Extra reference ids added to the finding. |
| `rationale` | Why the setting is what it is. Shown by `policy show --json`, kept for reviewers. |

keycensus refuses a pack with an unknown rule id, an unknown setting, a severity that is not one of the
five, or a date it cannot read, and suggests the closest rule name. A typo in a rule name used to switch
nothing off without anyone noticing. A pack without a version still loads, with a warning: scans then
record only its digest.

### What a scan records

Every scan records the pack it used, in `inventory.json` under `policy_pack`: name, version, the
`name@version` reference, a SHA-256 digest of the merged pack, where it came from, the effective and
review dates, whether the review is overdue, the date the rules were evaluated on, and any dated changes
still to come. Every finding records `policy: name@version`. The CBOM carries `keycensus:policy` and
`keycensus:policyDigest`, the audit log records the pack with each `scan.start`, and `serve` exports
`keycensus_policy_info` and `keycensus_policy_review_overdue`.

The digest changes with any edit, so a pack changed without a version bump still shows up in
`keycensus diff` as a policy change.

Rules are evaluated on the scan's date: re-running an old pack on today's date can grade findings
differently if it has a `schedule:`. `policy show --as-of` shows what a pack does on any date.

### Built-in packs

| Pack | What it is |
|---|---|
| `default` | Conservative readings of PCI DSS v4.0.1, NIST SP 800-57, SP 800-131A and IR 8547. Severities do not change with the date. |
| `nist-pqc` | `default`, with the quantum findings graded up on NIST IR 8547's dates: from 2031-01-01 (deprecated after 2030) quantum-vulnerable encryption and key exchange are high and signatures medium; from 2036-01-01 (disallowed after 2035) they are critical and high. |

## Cryptoperiods

```yaml
cryptoperiod_days:
  default: 365
  by_algorithm: {AES: 365, ChaCha20: 365, HMAC: 365, RSA: 730, EC: 730, Ed25519: 730}
  by_purpose:  {wrap: 1095, sign: 730}     # purpose wins over algorithm
```

The rule compares `now - (last_rotated or created)` with the limit. NIST SP 800-57 Part 1 Rev. 5
Table 1 suggests ≤ 2 years for symmetric data-encryption keys and 1–3 years for signature keys;
many PCI programmes standardise on 1 year. Pick yours and write it down — the policy file *is*
the documented cryptoperiod PCI DSS 3.7.4 asks for.

## Rules

| Rule id | Triggers when | Default | Controls |
|---|---|---|---|
| `weak-algorithm` | algorithm ∈ {DES, 3DES, RC4, RC2, Blowfish, IDEA, CAST5} (keys, certificates, code) | high | 3.5.1, 3.7.5, SP 800-131A |
| `weak-key-size` | RSA/DSA/DH < 2048, ECC < 224, AES/HMAC < 128 (keys, certificates, key generation in code) | high | 3.7.1, 3.5.1 |
| `deprecated-signature-hash` | certificate signed with MD5/SHA-1 | high | 4.2.1, 3.7.5, SP 800-131A, IR 8547 |
| `rotation-overdue` | active key older than its cryptoperiod | medium | 3.7.4, SP 800-57 |
| `rotation-disabled` | source supports auto-rotation and it's off | low | 3.7.4 |
| `no-creation-date` | key has no created/rotated timestamp | info | 12.3.3, 3.6.1.1 |
| `cert-expired` | notAfter in the past | critical | 4.2.1 |
| `cert-expiring-critical` | < `expiring_critical_days` (7) | high | 4.2.1 |
| `cert-expiring-soon` | < `expiring_soon_days` (30) | medium | 4.2.1 |
| `cert-self-signed` | subject == issuer (not Vault PKI roots) | info | 4.2.1 |
| `cert-long-validity` | end-entity validity > `max_validity_days` (398); CA certificates are exempt | info | 3.7.4 |
| `key-exportable` | extractable / exportable / imported material | medium | 3.7.3, 3.6.1 |
| `key-software-backed` | `hardware_backed: false` with a protective purpose | low | 3.6.1, FIPS 140-3 |
| `key-not-active` | state is disabled / pending deletion / destroyed | info | 3.7.5 |
| `quantum-vulnerable-encryption` | RSA/EC/DH **key** used to encrypt/wrap/derive | medium | IR 8547, EO 14412, 12.3.3 |
| `quantum-vulnerable` | RSA/EC/DH/Ed used for signatures, or any certificate | low | IR 8547, EO 14412, 12.3.3 |
| `quantum-reduced` | AES-128/192, short HMAC (margin note; NIST keeps AES-128/192) | info | none |
| `tls-weak-protocol` | negotiates or accepts SSLv3/TLS 1.0/1.1 | high | 4.2.1, 12.3.3 |
| `tls-weak-cipher` | RC4, 3DES, NULL, EXPORT, anon, MD5, RC2, IDEA | high | 4.2.1, 12.3.3 |
| `tls-no-forward-secrecy` | non-(EC)DHE suite | low | 4.2.1 |
| `quantum-vulnerable-key-exchange` | TLS 1.3 group or SSH kex is classical (x25519, P-256, curve25519-sha256 …) | medium | IR 8547, EO 14412, 12.3.3 |
| `hybrid-key-exchange` | TLS 1.3 group or SSH kex is hybrid (X25519MLKEM768, mlkem768x25519-sha256, sntrup761x25519 …): allowed, but temporary | info | IR 8547 |
| `ssh-weak-algorithm` | SSH server offers SHA-1 kex or `ssh-rsa`, DSA, CBC/RC4/3DES, MD5 or truncated SHA-1 MACs | high | SP 800-131A, 12.3.3 |
| `unknown-algorithm` | collector could not identify the algorithm | info | 12.3.3 |
| `adcs-template-weak-key-size` | an AD CS CA publishes a template whose minimum key size is weak by the `weak-key-size` test | medium | 3.7.1, SP 800-131A |
| `hardcoded-private-key` | `code` collector: a private key or keystore in the source tree (keys under test paths are flagged in the detail). For these keys `key-exportable`, `key-software-backed` and `no-creation-date` are not raised: this finding covers them | critical | 3.6.1, 3.7.3 |
| `weak-hash` | `code` collector: MD5 or SHA-1 calls | medium | SP 800-131A, 3.5.1, 12.3.3 |
| `weak-cipher-mode` | `code` collector: ECB mode, including Java's `Cipher.getInstance("AES")` | high | 3.5.1, SP 800-131A |
| `keystore-weak-protection` | JKS or JCEKS; PKCS#12 with RC2, RC4, DES or 3DES, a SHA-1/MD5 MAC or under 1000 MAC iterations; or a keystore that opens with no password or a well-known one | medium | 3.6.1, 3.7.3 |
| `ct-unexpected-issuer` | `ct` collector: a public certificate from a CA not in `expected_issuers` | high | 4.2.1 |
| `ldap-cleartext` | `network` collector: an LDAP server on 389 that refuses StartTLS | medium | 4.2.1, 12.3.3 |
| `key-reuse-on-renewal` | `kubernetes` collector: a cert-manager Certificate with `privateKey.rotationPolicy: Never` | low | 3.7.4, SP 800-57 |

(`3.x` / `4.x` / `12.x` = PCI DSS v4.0.1 requirements.)

### Why these severities

- **critical** — something is failing *now* (expired cert).
- **high** — a control is failed outright (broken algorithm, weak key, SHA-1); an assessor will write it up.
- **medium** — a control is at risk or a real security gap (overdue rotation, exportable key,
  quantum-vulnerable *encryption* — the harvest-now-decrypt-later case).
- **low** — hygiene; fix on the next change window.
- **info** — inventory facts an assessor wants to see you *know* (PCI 12.3.3).

### The quantum rules, briefly

NIST IR 8547 (final, 27 October 2026): RSA, ECDSA, ECDH, DH, DSA and EdDSA are **deprecated after
2030 and disallowed after 2035**, at every security strength. The 2024 draft deprecated only the
112-bit sizes in 2030; RSA-3072 and P-256 now get the same date as RSA-2048. Executive Order 14412
puts federal high-impact systems on post-quantum key establishment by the end of 2030 and signatures
by the end of 2031.

Keys that *encrypt* are worse than keys that *sign*: ciphertext captured today can be decrypted
later, signatures cannot be forged retroactively. That is why `quantum-vulnerable-encryption` is
medium and `quantum-vulnerable` is low.

NIST does not expect to move off AES-128/192/256 or SHA-2. keycensus still flags AES-128 and AES-192
as `quantum-reduced` (info) as a margin note for data that must stay secret for decades, and the
finding cites no control. Disable it if you follow NIST's reading. Dates and sources:
[PQC-TIMELINE.md](PQC-TIMELINE.md).

Endpoints get the same treatment for key exchange. A TLS 1.3 or SSH endpoint whose negotiated key
exchange is classical gets `quantum-vulnerable-key-exchange` (medium): recorded traffic is the
harvest-now-decrypt-later case. A hybrid gets `hybrid-key-exchange` (info), because NIST IR 8547 allows
hybrids but calls them temporary and expects a second move to ML-KEM only. A pure ML-KEM group gets
nothing. The `tls-*` rules run only on TLS endpoints, never on SSH.

## Examples

**Strict PCI programme, 180-day symmetric rotation, page on overdue keys:**

```yaml
name: pci-strict
version: "1"
effective: 2026-12-01
review_by: 2027-06-01
cryptoperiod_days:
  default: 180
  by_algorithm: {RSA: 365, EC: 365}
  by_purpose: {wrap: 730}
rules:
  rotation-overdue: {severity: high}
  key-software-backed: {severity: medium}
```

**PQC discovery only (turn everything else off):**

```yaml
name: pqc-discovery
version: "1"
extends: nist-pqc
rules:
  weak-algorithm: {enabled: false}
  weak-key-size: {enabled: false}
  rotation-overdue: {enabled: false}
  rotation-disabled: {enabled: false}
  cert-expiring-soon: {enabled: false}
  key-exportable: {enabled: false}
  key-software-backed: {enabled: false}
```

## CI gate

```bash
keycensus scan -c config.yml --fail-on high     # exit 1 if any high/critical finding
```
