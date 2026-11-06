# Qualification

How far each part of keycensus has been tested, against what, and what it is known not to do. Stages are
defined in [ROADMAP.md](ROADMAP.md#stages). Nothing here is field-validated yet: if you run keycensus
against a real estate, an issue saying which collectors worked is the most useful report you can send.

Last updated for 0.14.0. Every row runs in CI on every push unless it says otherwise.

## Collectors

| Collector | Tested against | Stage | Coverage reported | Known limits |
|---|---|---|---|---|
| `pkcs11` | SoftHSM2 (a real PKCS#11 library), in the tests and in the docker compose smoke test | integration-tested | tokens, objects | Not yet run on Luna, nShield or CloudHSM. Vendor-specific attributes are not read. |
| `vault` | Mocked HTTP in the unit tests; a real Vault 1.18 (Transit, PKI) in the docker compose smoke test | integration-tested | mounts, items; denied ACL policy reads | Coverage is mock-tested; the compose test checks a denied PKI mount with a narrowed policy. |
| `aws-kms` | moto, the AWS emulator: KMS, STS, Organizations | integration-tested (emulator) | accounts, regions, keys; denied optional permissions | Never run against a real organization. |
| `azure-keyvault` | Recorded REST and ARM responses | implemented | subscriptions, vaults; denied optional permissions | A live OIDC harness exists ([INTEGRATION-TESTS.md](INTEGRATION-TESTS.md)) and has not run yet. RBAC consumers are mock-tested only. |
| `gcp-kms` | Recorded REST responses | implemented | projects, locations; denied getIamPolicy | Same live harness, not run yet. |
| `ciphertrust` | A mock written from Thales' API reference | implemented | keys (listing) | Field names unconfirmed on a real appliance; remappable. |
| `keysafe5` | The bundled mock | implemented | keys (listing) | Same as CipherTrust. |
| `voltage` | JSON and CSV exports | implemented | complete or failed | Voltage has no public inventory API. |
| `adcs` | An in-memory LDAP directory with real attribute names and encodings; CSVs shaped like `certutil -view` | implemented | directory, exports | Not run against a live forest or CA. `certutil` headers are localised. |
| `files` / `pem` | Files made by `openssl`, `keytool` (JKS, JCEKS, PKCS#12) and `ssh-keygen`; SSH fingerprints compared with `ssh-keygen -l` | integration-tested | paths, files | PKCS#12 contents need the password. |
| `tls` | OpenSSL 3.5 and Go 1.24 TLS servers; OpenLDAP `slapd` for StartTLS | integration-tested | complete or failed | Live internet endpoints are not part of CI (the CI network intercepts TLS). |
| `ssh` | OpenSSH 9.6 | integration-tested | complete or failed | |
| `network` | Local TLS, SSH and LDAP servers | integration-tested | complete or failed | A host that does not answer is not a gap: discovery cannot know it should have answered. |
| `ct` | Cert Spotter live (once, by hand; CI replays the real response); crt.sh from recorded shapes | integration-tested (Cert Spotter), implemented (crt.sh) | domains | crt.sh is often slow or erroring. |
| `kubernetes` | The official Python client against a local server answering in the API's shapes | implemented | namespaces, cert-manager; denied pods and ingresses | Not run against a real cluster yet. |
| `code` | A sample repository that compiles with javac, go, node, gcc and python; two open-source JWT libraries (node-jsonwebtoken, jjwt) | integration-tested | complete or failed | Pattern-based: does not follow variables or wrappers; reads the working tree, not git history. |

"Complete or failed" means the collector does not break its scope down. Its assets are still carried
forward if it fails, because a failed source never removes anything.

## Server features

| Feature | Tested against | Stage |
|---|---|---|
| OIDC sign-in and machine JWTs | CI: an in-process identity provider that signs real JWTs and tampers with nonce and userinfo. Once by hand during 0.9.0: `oidc-provider` (a certified OpenID provider) for browser login, userinfo, logout, a refused user and client credentials | integration-tested (by hand) |
| RFC 3161 timestamps | CI: `openssl ts -reply` as the TSA and `openssl ts -verify` as an independent check. Once by hand: FreeTSA and DigiCert's public TSAs | integration-tested |
| Signed scan manifests | Unit tests: tampered files, wrong keys, moved timestamps | implemented |
| Hash-chained audit log | Unit tests: edited and deleted lines, HMAC, continuation after rotation | implemented |
| Change alerts and webhooks | Unit tests; the Prometheus alert rules are checked with `promtool` in CI | implemented |
| CycloneDX 1.6 and 1.7 output | CI: both versions validated against the official schemas; every 1.7 `algorithmFamily` checked against the Cryptography Registry and every name against its family's patterns; RSA padding read from code that compiles with javac, go and node, and from AWS KMS under moto | implemented |
| `keycensus doctor` | Unit tests for every collector's scopes and optional permissions; the shipped AWS policy run under moto's IAM evaluation, whole and with permissions removed; a test that every grant a remedy names appears in the `deploy/` file it points to. CI: doctor against the compose demo, and against a narrowed Vault policy | implemented |
| `serve` end to end | The docker compose smoke test in CI: SoftHSM, Vault, the demo sources, `/inventory.json`, `/cbom.json`, `/metrics` | integration-tested |

## FIPS 140

keycensus does not decide whether a module is validated. A collector sets `fips_validated` when the vendor
documents the key store as FIPS-validated, and records `fips_evidence: {basis: vendor-documentation}`. A
FIPS standard and level appear in the CBOM only when you add the CMVP certificate to the source:

```yaml
- name: prod-hsm
  type: pkcs11
  module: /usr/lib/libCryptoki2_64.so
  fips_validated: true
  fips_evidence:
    standard: FIPS 140-3
    level: 3
    certificate: 4884                 # CMVP certificate number; the URL is filled in
    module: Example HSM model 7
    version: firmware 7.8.4
    status: active
```

Without a certificate number, `certificationLevel` is `unknown`, and a shared algorithm component used by
assets with different evidence gets no level at all.
