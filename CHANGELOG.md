# Changelog

## 0.12.0 — 2026-11-05

**Trustworthy results: what was inspected, what was missed, and what backs each finding.**

**A scan that could not look never closes anything**

- Before this release, a source that failed or lost a permission made its assets look "removed" and their
  findings "resolved" in diffs and change alerts. Now an asset missing from a failed source, or from the
  part of a partial source that was not scanned, is *unverified*: `diff` lists it under
  `assets_unverified` and its findings under `findings_unverified`, and change alerts say
  `asset-unverified` (digest) and `finding-unverified` (ignore) instead of `asset-removed` (page) and
  `finding-resolved`.
- `scan --baseline` and `serve` carry those assets forward into the new inventory with `observed: false`
  and `last_observed`, so the report and CBOM still show them, and their findings stay open with
  `verified: false` ("not re-verified" in the report). `--no-carry-forward` turns it off.
- A real deletion in a scope that was fully scanned is still `asset-removed`.

**Complete, partial and failed sources, with coverage**

- Every source reports `status` (complete, partial, failed) and `coverage`: per scope, how many items were
  expected, scanned, denied, unavailable or failed, plus optional permissions that were denied. When the
  total cannot be discovered, it says so.
- Instrumented: AWS (accounts, regions, keys, and denied optional reads such as `kms:ListGrants`), Azure
  (subscriptions, vaults), GCP (projects, locations, now scanned one by one), Kubernetes (namespaces,
  cert-manager), files (paths, files) and Certificate Transparency (domains). Other collectors are
  complete or failed.
- `scan --require-complete` exits 6 unless every source scanned its whole scope.
- New change kind `source-partial` (page): a source that was complete now misses part of its scope.
- The report opens its executive summary with what the scan covered; the sources table shows status and
  coverage; unobserved assets and unverified findings are marked.
- Metrics: `keycensus_source_complete`, `keycensus_source_coverage`, `keycensus_source_assets_not_observed`,
  and a `KeycensusSourcePartial` alert rule. The compose smoke test now requires every demo source to be
  complete.

**FIPS claims backed by evidence**

- The CBOM used to say `certificationLevel: fips140-3-l3` for any asset with `fips_validated: true`. It now
  states a standard and level only from a CMVP certificate recorded in the source's new `fips_evidence`
  block (standard, level, certificate, module, version, status ...). A vendor claim alone is `unknown`;
  assets that disagree get no level on their shared algorithm component.
- Each asset carries `fips_evidence` (`basis`: cmvp-certificate, configured or vendor-documentation), also
  in the CBOM properties and the CSV.
- Collector comments that stated vendor FIPS levels as fact were reworded.

**Roadmap and qualification**

- New [docs/ROADMAP.md](docs/ROADMAP.md): stages (planned, implemented, integration-tested,
  field-validated) and an acceptance criterion for every item. The README's tick list is gone; history
  stays in this changelog.
- New [docs/QUALIFICATION.md](docs/QUALIFICATION.md): what each collector was tested against, its stage
  and known limits. Corrects the README, which had ticked live Azure/GCP integration tests that have not
  run yet.
- CONTRIBUTING asks for qualification runs instead of collectors that now exist.
- Helm chart 0.5.1, `appVersion` 0.12.0.

## 0.11.0 — 2026-11-04

**Discovery: what nobody listed.**

**LDAP StartTLS** (`network`, `tls`)

- Port 389 is now in network discovery's default ports as `ldap-starttls`: keycensus sends the LDAP StartTLS
  extended request (no bind, no credentials) and runs the TLS, legacy-version and key exchange probes over
  the upgraded connection. The `tls` collector takes `ldap://host[:port]` and `ldaps://host[:port]` endpoints.
- An LDAP server that refuses StartTLS is reported as `protocol: LDAP` with an `ldap-cleartext` finding
  (medium). Tested against OpenLDAP slapd.

**Certificate Transparency** (`ct`, new)

- Every public certificate issued for your domains and subdomains, from Cert Spotter (default, returns the
  certificates) or crt.sh, as `certificate` assets with key algorithm, issuer, SANs and expiry.
- `expected_issuers`: a certificate from any other CA gets `ct-unexpected-issuer` (high).
- Pagination, `Retry-After` on 429, retries on 5xx, API key through any secret reference.

**Keystores and SSH keys** (`files`, the `pem` collector under a clearer name)

- New shared parser (`keycensus/collectors/keyfiles.py`) for PEM, DER, PKCS#12, JKS, JCEKS and OpenSSH.
- PKCS#12: protection read without a password; contents with `keystore_passwords` or a well-known password.
  JKS/JCEKS: every entry and certificate chain without a password, JCEKS secret keys included; the
  password only checks the integrity digest.
- SSH: private keys (algorithm, cipher, passphrase or not), `*.pub`, `authorized_keys` (with options),
  `known_hosts` (hashed hosts, `@cert-authority`), host keys and OpenSSH certificates, each with its role and
  an `ssh-keygen -l` fingerprint.
- `keystore-weak-protection` (medium): JKS/JCEKS, legacy PKCS#12 (RC2, 3DES, SHA-1 MAC), no password or
  `changeit` and friends. A PKCS#12 with an unknown password is reported as locked.
- Plain PEM keys keep their asset ids, so diffs against older scans do not churn.

**Kubernetes** (`kubernetes`, new, `pip install "keycensus[kubernetes]"`)

- TLS secrets (leaf certificate, whether `tls.key` matches `tls.crt`), Opaque secrets (any key, certificate
  or keystore in a value), cert-manager Certificates matched to their secret (issuer type, key algorithm,
  rotationPolicy, Ready), and `used_by` from the pods and ingresses that use each secret.
- `key-reuse-on-renewal` (low) for `rotationPolicy: Never`.
- RBAC kit in `deploy/kubernetes/`; Helm chart 0.5.0 adds `rbac.kubernetesSource` (off by default, and the
  service account token stays unmounted unless it is on). Mock-verified with the official client.

**Code scanning** (`code`, new)

- Hard-coded private keys in any file, including ones pasted into string literals with escaped newlines,
  concatenation or YAML blocks, OpenSSH keys and committed keystores: `hardcoded-private-key` (critical).
  Placeholders are ignored, test paths are flagged, and the key itself is never stored.
- Crypto API calls in Python, Java/Kotlin/Scala/Groovy, Go, JavaScript/TypeScript, C# and C/C++ (OpenSSL),
  grouped per algorithm, size, curve and mode, with every call site. New `algorithm` asset kind; in the CBOM
  these are algorithm components with CycloneDX `evidence.occurrences`.
- `weak-hash` (MD5, SHA-1), `weak-cipher-mode` (ECB, including Java's bare `Cipher.getInstance("AES")`),
  plus `weak-algorithm`, `weak-key-size` and the quantum rules on code. `keycensus:ignore` skips a line.

**Also**

- `weak-algorithm` covers RC2, Blowfish, IDEA and CAST5. SHA-2 and SHA-3 are classified as quantum-safe,
  MD5 and SHA-1 as broken.
- For hard-coded keys, `key-exportable`, `key-software-backed` and `no-creation-date` are not raised.
- The executive summary and the report's PQC bar count keys and certificates only, not code call sites.
- Change alerts: a certificate that disappears after its expiry date, and a code call site that disappears,
  are `asset-retired` (digest), not `asset-removed` (page). An SSH `.pub` file next to its private key is
  folded into it, like other key pairs.
- CI installs slapd for the StartTLS tests and renders the chart with `rbac.kubernetesSource=true`.

## 0.10.0 — 2026-11-04

**An executive summary at the top of the report.**

- `report.html` now opens with the share of keys and certificates that are quantum-vulnerable, split
  by use (encrypt and key agreement, the harvest-now-decrypt-later exposure; signing and certificates;
  purpose unknown), and a table of what must move before each date in docs/PQC-TIMELINE.md: broken
  crypto now (PCI DSS 12.3.3), key establishment by 31 Dec 2030 and signatures by 31 Dec 2031 (EO 14412,
  IR 8547 deprecation), and everything by 31 Dec 2035 (IR 8547 disallowed). Each row gives the keys and
  certificates, the endpoints, the days left, who the date binds, and how many assets are still valid on
  the date. Probed endpoints are split into classical, hybrid and pure ML-KEM.
- A key that both signs and decrypts falls due at the earlier date. Keys with no recorded purpose
  appear only in the 2035 row and are called out. Hybrid endpoints meet the 2030 date and are not
  counted as due.
- The same summary is in `inventory.json` (`executive`), in the `keycensus scan` console output, and in
  Prometheus: `keycensus_quantum_vulnerable_ratio`, `keycensus_pqc_milestone_assets{milestone,date,kind}`,
  `keycensus_pqc_milestone_days_left{milestone,date}`.
- Helm chart 0.4.1, `appVersion` 0.10.0.

## 0.9.0 — 2026-11-04

**Sign in with your identity provider, and timestamps a third party vouches for.**

**OIDC for `serve`** (`serve.auth.oidc`)

- Browsers: authorization code flow with PKCE (S256), `state` bound to a short-lived signed cookie,
  `nonce` checked in the ID token, then keycensus's own HMAC-signed session cookie (HttpOnly,
  SameSite=Lax, Secure on https). The provider's tokens are never stored. `/login`, `/logout`, and an
  unauthenticated browser request is redirected to sign in.
- Machines: `Authorization: Bearer <JWT>` from the provider (client credentials, workload identity),
  checked for issuer, audience, expiry and signature.
- JWTs are verified against the provider's JWKS (RS/PS/ES 256-512 and EdDSA; never `none` or HMAC), with
  a JWKS refetch when a new key id appears (key rotation). The discovery issuer must match exactly.
- Who may in: `allowed_emails`, `allowed_domains`, `allowed_groups`, `allowed_subjects`; at least one is
  required. Claims missing from the ID token come from userinfo, only for the same subject. Only the
  `email` claim is used for email and domain rules, never `preferred_username`.
- Works alongside static tokens; OIDC alone satisfies the "no unauthenticated non-loopback serve" rule.
- Audit events: `serve.login`, `serve.login_failed`, `serve.logout`; reads are recorded as
  `oidc:<email>` or `jwt:<subject>`.
- Tested end to end against `oidc-provider`, a certified OpenID provider, and in CI against a scripted
  provider.

**RFC 3161 timestamps** (`signing.timestamp`)

- After signing, keycensus sends the SHA-256 of the signature to a TSA (several `urls`, tried in order) and
  stores the reply as `manifest.json.tsr`; `serve` serves `/manifest.json.tsr`.
- Checked on arrival and by `keycensus verify`: status, message imprint, nonce, the CMS signature, the
  timeStamping EKU, validity at the stamped time, and the chain to `ca_file` / `--tsa-ca-file`.
  `--require-timestamp` fails a folder without a trusted timestamp. `required: true` fails a scan whose
  timestamp could not be obtained.
- The `.tsr` is standard: `openssl ts -verify` accepts it. Verified against FreeTSA and DigiCert.
- New core dependency: `asn1crypto` (pure Python), for the RFC 3161 and CMS structures.

## 0.8.0 — 2026-11-04

**Safe to leave running.** Stage 1 of the roadmap: the report and CBOM need a token, every scan can be
signed and audited, credentials can come from a secret store, and the image itself is signed.

**`serve` needs a token**

- Listens on 127.0.0.1 by default. On any other address it refuses to start without a token, unless
  `serve.allow_unauthenticated` (or `--insecure-no-auth`) says a proxy in front authenticates.
- Named tokens under `serve.auth.tokens` (any secret reference), plus `$KEYCENSUS_SERVE_TOKEN` as a
  token named "default". `Authorization: Bearer`, or Basic in a browser with the token as the password.
  Tokens are kept only as SHA-256 digests and compared in constant time; 16 characters minimum.
- `/metrics`, `/healthz` and the new `/livez` stay public (configurable with `public_paths`); everything
  else needs a token.
- HTTPS with `serve.tls` or `--tls-cert/--tls-key`. Security headers on every response.
- `serve.listen` and `serve.port` in the config; `--listen` and `--port` still override.
- **Upgrade note:** the image sets `KEYCENSUS_LISTEN=0.0.0.0`, so a container now needs
  `KEYCENSUS_SERVE_TOKEN` (or `allow_unauthenticated`) to start. The Helm chart creates a token Secret;
  the demo compose file allows unauthenticated access and publishes the port on 127.0.0.1 only.

**Secrets from a secret store**

- Every `<key>_env` option also accepts `<key>_vault` (HashiCorp Vault KV v1/v2; token or Kubernetes
  auth), `<key>_aws_secret` (AWS Secrets Manager), `<key>_azure_secret` (Azure Key Vault) and
  `<key>_gcp_secret` (GCP Secret Manager), with `#field` for JSON secrets. Backends are configured in a
  top-level `secrets:` block and only contacted when used; values are cached for 5 minutes.

**Audit log**

- `audit: {path, hmac_key_env}` appends one JSON object per line, each carrying the previous entry's
  hash (HMAC-SHA-256 when a key is set): `scan.start` (config and policy hashes, each source's credential
  references), `scan.end` (results and output hashes), `config.changed`, `serve.read` (path, token name,
  client), `serve.denied`, `webhook.sent` (endpoint host only) and `scan.signed`. A `.head` file keeps the
  chain going across log rotation.
- `keycensus audit verify FILE` checks every link and reports the first edited or missing entry.

**Signed scan records**

- `signing: {private_key_file}` writes `manifest.json` (SHA-256 of every output, version, config and
  policy hashes, key fingerprint) and an Ed25519 signature next to the outputs. `serve` signs each rescan
  and serves `/manifest.json` and `/manifest.json.sig`.
- `keycensus keygen` creates the key pair (never overwrites); `keycensus verify OUT --public-key ...`
  checks the signature and every file, and exits 1 on any difference.

**Least-privilege kits** in `deploy/`: an AWS member role (CloudFormation, for a StackSet) and scanner
policy, an Azure custom role, a GCP custom role, a Vault policy and an AD account checklist; summarized
in the new [docs/PERMISSIONS.md](docs/PERMISSIONS.md).

**Signed releases**: the publish job signs the GHCR image with Sigstore (keyless), attaches an SPDX SBOM
attestation and SLSA build provenance. SECURITY.md has the `cosign verify` and `gh attestation verify`
commands.

**Helm**: a generated serve token Secret, liveness on `/livez`, every `config` block now reaches the
config file (it used to pass only `policy` and `sources`), and `appVersion` corrected to 0.8.0.

## 0.7.0 — 2026-11-03

**Hybrid key exchange, network discovery and cloud-wide discovery.** Three roadmap items.

**Key exchange: classical, hybrid or ML-KEM**

- The `tls` collector now reports the TLS 1.3 key exchange group each endpoint negotiates
  (`key_exchange` on the asset, `probe_pqc: true` by default). keycensus writes its own ClientHello,
  offering X25519MLKEM768 the way browsers do, and reads the group from the server's first reply, which
  TLS 1.3 sends unencrypted. A second probe offers only post-quantum groups and lists every one the server
  accepts, so "supports the hybrid but prefers X25519" is visible. The handshake is never finished and no
  OpenSSL 3.5 is needed. Tested against OpenSSL 3.5 and Go 1.24 servers.
- New quantum class `hybrid`. X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024,
  mlkem768x25519-sha256 and sntrup761x25519-sha512 are hybrid; MLKEM512/768/1024 are quantum-safe; x25519,
  the NIST curves and finite-field DH are quantum-vulnerable. The pre-FIPS 203 X25519Kyber768Draft00 and
  NTRU Prime hybrids are noted as not NIST algorithms.
- New rules: `quantum-vulnerable-key-exchange` (medium; NIST IR 8547, EO 14412, PCI 12.3.3), whose
  remediation says when the server already accepts a hybrid and only its preference order is wrong, and
  `hybrid-key-exchange` (info): allowed by NIST IR 8547 but temporary.
- New change kind `pq-key-exchange-lost` (pages by default; also in the `KeycensusCryptoWeakened` alert)
  for an endpoint that falls back from hybrid or ML-KEM to classical; `pq-key-exchange-gained` is ignored.
- `key_exchange` is in the CBOM (`keycensus:keyExchange`, `keycensus:pqKeyExchangeSupported`), the CSV,
  diff mode and the HTML report, which counts endpoints by key exchange class.

**SSH**

- New `ssh` collector. Reads the banner and the server's KEXINIT, which SSH sends before any login, and
  records the offered key exchange, host key, cipher and MAC algorithms. `key_exchange` is what a current
  OpenSSH client would negotiate. Tested against OpenSSH 9.6.
- New rule `ssh-weak-algorithm` (high): SHA-1 key exchange or `ssh-rsa`, DSA, CBC/RC4/3DES/Blowfish, MD5
  or truncated SHA-1 MACs. The `tls-*` rules no longer run on non-TLS endpoints.

**Network discovery**

- New `network` collector: TCP connect to every host and port in CIDR ranges (default ports 443, 8443,
  636, 3269 and 22), then the TLS, LDAPS or SSH probe on each open port. Refuses public ranges and ranges
  over 4096 addresses unless told otherwise; `exclude` ranges are never touched.

**Cloud auto-discovery**

- `aws-kms`: `organization: true` scans every ACTIVE account in the AWS Organization by assuming
  `member_role` in each; `regions: all` scans every enabled region. Assets carry `account_id` and `region`.
- `azure-keyvault`: `discover: true` scans every Key Vault and Managed HSM in every enabled subscription
  (or the listed `subscriptions`). Assets carry `subscription_id`, `resource_group` and `vault`.
- `gcp-kms`: `discover: true` scans every ACTIVE project from Cloud Resource Manager (narrowed by
  `project_query`, or an explicit `projects` list). Projects without the Cloud KMS API are skipped quietly.
- In all three, one account, subscription, vault, project or region that fails is logged and skipped; the
  source fails only when every target fails. Mock-tested (moto, recorded responses), not yet run against a
  real organization.

Docs: COLLECTORS (key exchange, `ssh`, `network`, discovery sections), POLICY, CBOM, ALERTING,
COMPLIANCE, PQC-TIMELINE, ARCHITECTURE, FAQ, SECURITY, README and the example config.

## 0.6.1 — 2026-11-03

**NIST IR 8547 is final.** NIST published the final *Transition to Post-Quantum Cryptography
Standards* on 27 October 2026. This release brings the control text, finding text and docs in line
with it and with Executive Order 14412. No rule fires differently; findings cite different controls.

- `NIST-IR-8547` now describes the final report: RSA, ECDSA, EdDSA, DH and ECDH deprecated after
  2030 and disallowed after 2035 at every security strength (the 2024 draft deprecated only the
  112-bit sizes in 2030), and SHA-1 disallowed in FIPS 140 modules after 2030.
- New control `US-EO-14412`: federal high value assets and high-impact systems move to post-quantum
  key establishment by 31 Dec 2030 and signatures by 31 Dec 2031. `quantum-vulnerable-encryption`
  and `quantum-vulnerable` cite it.
- `quantum-reduced` (AES-128/192, short HMAC) no longer cites IR 8547, because the final report keeps
  AES-128/192/256 and SHA-2. The finding stays as an info-level margin note with no control; turn it
  off with `quantum-reduced: {enabled: false}` if you follow NIST's reading.
- `deprecated-signature-hash` also cites IR 8547.
- `quantum-vulnerable-encryption` remediation names ML-KEM-768, NIST's recommended default, and
  calls hybrids a bridge rather than the end state. ML-KEM-512 assets note the 768 default.
- New [docs/PQC-TIMELINE.md](docs/PQC-TIMELINE.md): FIPS 203/204/205 (Aug 2024), PCI DSS 12.3.3
  (Mar 2025), the G7 Cyber Expert Group roadmap (Jan 2026), EO 14412 (Jun 2026), the DigiCert
  Quantum Readiness Outlook (Jul 2026) and IR 8547 final (Oct 2026), each with its source and what
  keycensus gives you for it. COMPLIANCE.md gains US federal and financial-sector sections; POLICY.md,
  CBOM.md and the README are updated.
- Roadmap: hybrid key exchange in the `tls` collector, and a mapping to the NIST / CISA CBOM minimum
  elements once EO 14412's guidance is published.

## 0.6.0 — 2026-10-16

**Microsoft AD CS.** Most Windows estates run their internal PKI on Active Directory Certificate
Services, and until now keycensus only saw its certificates after they landed on a disk or a port.
The new `adcs` collector reads the PKI at the source.

- **From Active Directory (LDAP):** every enterprise CA certificate, the trusted roots, the
  NTAuth and AIA stores, and the templates each CA publishes with their crypto settings (minimum
  key size, key algorithm for v3+ templates, validity, hash, exportable private key, key archival,
  enrollee-supplied subject). A certificate that sits in several stores is one asset with all its
  stores listed. Any domain account can read this; nothing on the CA servers is touched.
- **From the CA database:** issued certificates, read from a `certutil -view ... csv` export run on
  each CA, since the database has no remote interface outside DCOM. Handles UTF-16 output, PEM in
  quoted cells, `EMPTY` nulls and English display-name or schema-name headers; `field_map` covers
  localised ones. Expired and revoked certificates are skipped by default (`include_expired`,
  `include_revoked`). A file with no certificate column, or none that parse, fails the source
  rather than reporting an empty CA.
- With both configured, template OIDs in the export resolve to template names.
- The requester of each issued certificate is recorded in `used_by` (`via: enrollment`), so
  `principal:` selectors in `applications:` can link certificates to the machine or service
  account that holds the key.
- A simple bind over plain `ldap://` is refused; use `ldaps://`, `start_tls: true` or
  `auth: kerberos`.
- New extras: `keycensus[adcs]` (ldap3) and `keycensus[adcs-kerberos]` (ldap3 + gssapi). `all`
  includes ldap3.

**Policy**

- New rule `adcs-template-weak-key-size` (medium, PCI DSS 3.7.1, SP 800-131A): a CA publishes a
  template whose minimum key size fails the `weak-key-size` test, so it will keep issuing weak
  certificates until the template changes.
- `cert-long-validity` no longer fires on CA certificates. The 398-day limit is for end-entity
  certificates, and a 10-year issuing CA is normal. This also removes the finding from CA
  certificates found by the `pem` collector.

Tested against ldap3's in-memory directory and `certutil`-shaped exports; not yet against a live
forest. Docs: [docs/COLLECTORS.md](docs/COLLECTORS.md), plus updates to the README, POLICY,
LINKING, COMPLIANCE, ARCHITECTURE, FAQ, SECURITY and CONTRIBUTING pages.

## 0.5.0 — 2026-09-03

**Who uses this key — the last two gaps.** AWS grants, GCP IAM bindings and CipherTrust owners have
fed `used_by` since 0.3.0; Azure was the one cloud that could not answer, and SPDX users could not
declare an application at all.

**Azure RBAC consumers** (`include_rbac`, on by default)

- Azure authorizes three different ways and the collector reads whichever the vault uses: ARM role
  assignments at the vault scope for RBAC vaults, `properties.accessPolicies` for the older model,
  and the HSM's own data-plane local RBAC for Managed HSM — which needs no ARM call and no extra
  permission at all.
- Roles that only *list* (Key Vault Reader, Managed HSM Crypto Auditor) are deliberately not
  consumers: they can see that a key exists, not use it. Same for `get`+`list` access policies.
- The management plane is a different endpoint and a different token audience, so `auth: token` now
  takes `arm_token_env` alongside `token_env`. With `auth: default` the credential chain handles it.
- `used_by` is filled at the **vault** scope, because that is where Azure authorizes. AWS and GCP are
  per key; pretending Azure is too would invent precision the platform does not have.
- Optional Microsoft Graph name resolution (`resolve_principal_names`), off by default because
  `Directory.Read.All` is a much larger permission than reading an inventory. Without it, principals
  are reported as object ids.
- A 403 anywhere in this path is logged and tolerated — no consumer information is worse than no
  inventory.

**SPDX SBOMs for linking**

- `applications: - sbom: foo.spdx.json` now works for SPDX 2.2 and 2.3 JSON alongside CycloneDX.
  Identity comes from the package the document **DESCRIBES** — not the document name (usually the
  file) and not the first package (usually a dependency). Falls back to the 2.2 `documentDescribes`
  shorthand, then to the single package when there is exactly one.
- purl from the `externalRefs` entry with `referenceType: purl`; owner from `supplier`, else
  `originator`, unwrapping `"Organization: ACME (a@b)"` to `ACME` and ignoring `NOASSERTION`.
- `Application.sbom_format` records which reader ran. A test pins that both formats link an
  application to exactly the same assets — the format must never change the answer.
- Unreadable SBOMs now say what to do: XML and SPDX tag-value point at `syft convert`.
- The demo's third application ships an SPDX SBOM, so `make demo` exercises both readers.

## 0.4.0 — 2026-09-03

**Alerting on change, not just on state.** The diff existed as a CLI command and an exit code and
exported no metrics, so "a key became exportable an hour ago" could not fire anything. Suggested by
[Jitendra Bhargude](https://www.linkedin.com/in/jitendrabhargude/), who pointed out that diff mode without alerts is half a
feature.

- `keycensus/changes.py` — every raw field change is classified into a **kind** with an **urgency**
  (`page` / `digest` / `ignore`). 30 kinds; 12 page by default. Weakening is judged with the same
  strength model the findings use, so RSA-3072 → RSA-2048 pages and RSA-2048 → RSA-4096 does not, and
  a key that was already `destroyed` disappearing is a digest rather than a page.
- `keycensus changes` — `--kinds` prints the vocabulary and its default urgency; two inventory files
  print the classified diff, with the *reason* each page-worthy change matters.
- **Metrics**: `keycensus_change_total{kind,urgency,source}`, `keycensus_changes_last_scan{kind,urgency}`,
  `keycensus_last_change_timestamp_seconds`, `keycensus_diffs_total`. `serve` diffs every rescan
  against the previous one and publishes `/diff.json` and `/changes.json` beside the report.
- **Alert rules**: six new rules in `prometheus/alerts/keycensus.rules.yml` — a catch-all on
  `urgency="page"`, dedicated pages for a vanished key / a key that became exportable / crypto that
  weakened / rotation being switched off, a digest rule that never pages, and
  `KeycensusNoChangeDetectionRunning` for when the diff itself stops running.
- **Webhooks** (`keycensus/notify.py`) for teams without Prometheus: `generic`, `slack` and `teams`
  payloads, `on: page|any|never`. The URL comes from the environment and an inline `webhook_url:` is
  rejected — a webhook URL is a credential. A delivery failure never changes the exit code.
- `changes.urgency` in the config re-maps any kind; an unknown kind is a config error, not a silent
  no-op, so a typo cannot quietly disable an alert.
- `--fail-on-page` on `scan` and `diff`: **exit 5** when the estate got worse. Ignores the churn of
  new keys and rotations that `--fail-on-change` (exit 4) catches.
- Docs: [docs/ALERTING.md](docs/ALERTING.md), with a short opinion on what should page and what
  should not.


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
