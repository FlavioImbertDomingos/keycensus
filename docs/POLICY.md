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
