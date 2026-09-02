# Policy & rules

A policy is a YAML file with three parts: **cryptoperiods** (how long a key may live),
**certificate thresholds**, and per-rule **enabled / severity** overrides. The built-in default
is [`keycensus/data/default-policy.yml`](../keycensus/data/default-policy.yml).

```bash
keycensus rules                                   # list rules and default severities
cp keycensus/data/default-policy.yml my-policy.yml
keycensus scan -c config.yml --policy my-policy.yml
```

Merging: `rules:` merges per rule (list only what you change); `cryptoperiod_days:` and
`certificate:` are replaced wholesale when present (your numbers are the numbers).

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
| `weak-algorithm` | algorithm ∈ {DES, 3DES, RC4} | high | 3.5.1, 3.7.5, SP 800-131A |
| `weak-key-size` | RSA/DSA/DH < 2048, ECC < 224, AES/HMAC < 128 | high | 3.7.1, 3.5.1 |
| `deprecated-signature-hash` | certificate signed with MD5/SHA-1 | high | 4.2.1, 3.7.5 |
| `rotation-overdue` | active key older than its cryptoperiod | medium | 3.7.4, SP 800-57 |
| `rotation-disabled` | source supports auto-rotation and it's off | low | 3.7.4 |
| `no-creation-date` | key has no created/rotated timestamp | info | 12.3.3, 3.6.1.1 |
| `cert-expired` | notAfter in the past | critical | 4.2.1 |
| `cert-expiring-critical` | < `expiring_critical_days` (7) | high | 4.2.1 |
| `cert-expiring-soon` | < `expiring_soon_days` (30) | medium | 4.2.1 |
| `cert-self-signed` | subject == issuer (not Vault PKI roots) | info | 4.2.1 |
| `cert-long-validity` | validity > `max_validity_days` (398) | info | 3.7.4 |
| `key-exportable` | extractable / exportable / imported material | medium | 3.7.3, 3.6.1 |
| `key-software-backed` | `hardware_backed: false` with a protective purpose | low | 3.6.1, FIPS 140-3 |
| `key-not-active` | state is disabled / pending deletion / destroyed | info | 3.7.5 |
| `quantum-vulnerable-encryption` | RSA/EC/DH **key** used to encrypt/wrap/derive | medium | IR 8547, 12.3.3 |
| `quantum-vulnerable` | RSA/EC/DH/Ed used for signatures, or any certificate | low | IR 8547, 12.3.3 |
| `quantum-reduced` | AES-128/192, short HMAC | info | IR 8547 |
| `tls-weak-protocol` | negotiates or accepts SSLv3/TLS 1.0/1.1 | high | 4.2.1, 12.3.3 |
| `tls-weak-cipher` | RC4, 3DES, NULL, EXPORT, anon, MD5, RC2, IDEA | high | 4.2.1, 12.3.3 |
| `tls-no-forward-secrecy` | non-(EC)DHE suite | low | 4.2.1 |
| `unknown-algorithm` | collector could not identify the algorithm | info | 12.3.3 |

(`3.x` / `4.x` / `12.x` = PCI DSS v4.0.1 requirements.)

### Why these severities

- **critical** — something is failing *now* (expired cert).
- **high** — a control is failed outright (broken algorithm, weak key, SHA-1); an assessor will write it up.
- **medium** — a control is at risk or a real security gap (overdue rotation, exportable key,
  quantum-vulnerable *encryption* — the harvest-now-decrypt-later case).
- **low** — hygiene; fix on the next change window.
- **info** — inventory facts an assessor wants to see you *know* (PCI 12.3.3).

### The quantum rules, briefly

NIST IR 8547 (2024): RSA, ECDSA, ECDH, DH, DSA and EdDSA are **deprecated after 2030 and
disallowed after 2035**. Keys that *encrypt* are worse than keys that *sign*: ciphertext captured
today can be decrypted later, signatures cannot be forged retroactively. That is why
`quantum-vulnerable-encryption` is medium and `quantum-vulnerable` is low. Symmetric keys and
hashes only lose ~half their strength (Grover), so AES-256 / SHA-256 are fine; AES-128 is flagged
info as "plan to move".

## Examples

**Strict PCI programme, 180-day symmetric rotation, page on overdue keys:**

```yaml
name: pci-strict
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
