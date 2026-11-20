# Roadmap

What comes next, in order, and what each item has to prove before it is done. What already shipped is in
[CHANGELOG.md](../CHANGELOG.md); how far each collector has been tested is in
[QUALIFICATION.md](QUALIFICATION.md).

## Stages

Every item moves through four stages. The roadmap names the stage an item has reached, never more.

| Stage | Means |
|---|---|
| planned | Agreed and scoped. No code yet. |
| implemented | Merged, with tests against mocks or recorded responses. |
| integration-tested | Tested against a real implementation of the system it talks to: a real Vault, SoftHSM, OpenLDAP, files made by `keytool` or `ssh-keygen`, a certified OIDC provider, or a vendor emulator where the table says so. |
| field-validated | Run against a real production estate by someone other than the author, with the result reported back. |

## Now: 0.21.0, init and packaging

| Item | Stage | Acceptance criterion |
|---|---|---|
| `keycensus init` | implemented | Asks which sources you run (marking the ones the machine looks set up for), asks only the settings a first scan needs, writes the config with secrets as environment variable references, tests every source with `doctor`, names the extra a missing library needs, and runs the first scan. See [INSTALL.md](INSTALL.md). |
| `pipx install keycensus`, Homebrew, single-file binaries | implemented | A `v*` tag builds the wheel, the sdist and single-file binaries for Linux x86_64 and macOS arm64, installs each on a clean machine with no Python on the path and runs `init` and a scan with it, publishes to PyPI by trusted publishing and attaches the binaries, checksums, provenance and a Homebrew formula to the release. Integration-tested once the first tagged release has run it end to end. |

## Shipped in 0.20.0, SARIF and observed use against a real Vault

| Item | Stage | Acceptance criterion |
|---|---|---|
| SARIF output | implemented | `-f sarif` and `/findings.sarif` validate against the OASIS SARIF 2.1.0 schema; code findings point at file and line, relative to the scan directory; key store findings carry a logical location; fingerprints are stable across runs; severities map to GitHub's `security-severity` bands. See [SARIF.md](SARIF.md). |
| Observed use against a real Vault | integration-tested (Vault) | The compose smoke test turns on Vault 1.18's file audit device, makes Transit calls with two tokens (one of them refused), and checks that `keycensus usage` attributes each call to the right token, policy and key, lists the authorised policy that made no call, and raises `key-not-used` for an idle key. CloudTrail, Key Vault and Cloud Audit Logs stay tested on recorded samples. |

## Shipped in 0.19.0, observed use

| Item | Stage | Acceptance criterion |
|---|---|---|
| Observed use from audit logs | implemented | CloudTrail, Vault audit device, Azure Key Vault `AuditEvent` and Google Cloud Audit Logs are read from files and matched to keys; each key reports who called it, which operations, how many calls, refused calls, first and last call, and the window, apart from "allowed to use" (`used_by`) and "declared" (`applications`). Each caller is compared with the authorised consumers, and authorised consumers that made no call are listed. A key no log covers is reported as unknown, not unused. Tested with recorded log samples. See [OBSERVED-USE.md](OBSERVED-USE.md). |

## Shipped in 0.18.0, asset identity and relationships

| Item | Stage | Acceptance criterion |
|---|---|---|
| Asset identity and relationships | implemented | The same certificate seen in a file, a Kubernetes secret and on a TLS endpoint is one asset with three observations: certificates by fingerprint, keys by public key, AWS multi-region keys by key id. Certificate-to-key (`certifies`), certificate-to-issuer (`issued-by`) and Azure certificate-to-key (`backed-by`) relationships, and key versions per identity. The CBOM has one component per identity with each place as an evidence occurrence; the report, the executive summary and the metrics count distinct assets; a copy going away is not a deletion. Wrapping-key links are not covered: no collector reports them yet. See [IDENTITY.md](IDENTITY.md). |

## Shipped in 0.17.0, versioned policy packs

| Item | Stage | Acceptance criterion |
|---|---|---|
| Versioned policy packs | implemented | Each pack has a version, an effective date, references, applicability and a review date, and every scan records the exact pack version and digest; every finding records the pack that produced it. Rules can take effect on a date and change severity on a schedule (the `nist-pqc` pack uses NIST IR 8547's dates). `keycensus diff` says whether a finding changed because of the asset, the policy or time. See [POLICY.md](POLICY.md). |

## Shipped in 0.16.0, Kubernetes in CI

| Item | Stage | Acceptance criterion |
|---|---|---|
| Kubernetes against a real cluster | integration-tested | The collector runs in CI against kind with cert-manager: a TLS secret mounted by a Deployment, an Opaque secret with a key, a Certificate with `rotationPolicy: Never`, and a namespace the service account may not read. RBAC is `deploy/kubernetes/keycensus-reader.yaml` narrowed to RoleBindings. The scan must find each asset and nothing from the forbidden namespace, and `doctor` must name that namespace and the file. |
| CBOM components that Dependency-Track does not merge | integration-tested | Asset components carry their source as `group`; the Dependency-Track job fails if any asset component is merged on import. |

## Shipped in 0.15.0, Dependency-Track round-trip

| Item | Stage | Acceptance criterion |
|---|---|---|
| Downstream ingestion tests | integration-tested | A CBOM with applications, relationships and findings is uploaded into Dependency-Track 5.1 in CI, exported back and compared; the job records what survives (components, properties, dependency edges) and what does not (`cryptoProperties`, findings), and checks that 4.14 refuses the import instead of half doing it. |

The job has passed on GitHub Actions since 0.16.0, against Dependency-Track 5.1.2 and 4.14.6, which also
makes CycloneDX 1.7 below integration-tested: a real tool reads keycensus's 1.7 output.

## Shipped in 0.14.0, doctor

| Item | Stage | Acceptance criterion |
|---|---|---|
| `keycensus doctor` | integration-tested | For each source: what it reached, which scopes were partial and why, which permission is missing and the file that grants it. Runs the sources or reads an existing inventory.json. CI runs it against the compose demo (a real Vault and SoftHSM), and with a Vault token whose policy lacks one PKI path. See [DOCTOR.md](DOCTOR.md). |
| Coverage for Vault, PKCS#11, AD CS, CipherTrust, KeySafe 5 | implemented (Vault, AD CS, CipherTrust, KeySafe 5), integration-tested (PKCS#11, SoftHSM) | Vault mounts and items, PKCS#11 tokens and objects, AD CS directory and exports, CipherTrust and KeySafe 5 listings report what they scanned and what they could not, so a denied mount or a missing export makes the source partial instead of failed or silently short. |

## Shipped in 0.12.0, trustworthy results

The question each release should answer better: what did we inspect, what did we miss, and what evidence
supports each finding.

| Item | Stage | Acceptance criterion |
|---|---|---|
| Scan states (complete, partial, failed) per source and per scan | integration-tested (files), implemented (cloud, Kubernetes) | `inventory.json`, the report, the console and `/metrics` show the state of every source. |
| Finding lifecycle that cannot be closed by an outage | integration-tested | An outage, a lost permission or a partial scan never makes an asset "removed" or a finding "resolved". Missing assets from a failed or unscanned scope are carried forward as not observed, with their last observation time, and their findings stay open as "not re-verified". A real deletion in a fully scanned scope still counts. |
| Coverage within a source | implemented | AWS (accounts, regions, keys), Azure (subscriptions, vaults), GCP (projects, locations), Kubernetes (namespaces, cert-manager), files (paths, files) and CT (domains) report expected, scanned, denied, unavailable and failed counts, and denied optional permissions. When the total cannot be discovered, it says so instead of showing a percentage. |
| `--require-complete` CI gate | integration-tested | `keycensus scan --require-complete` exits 6 unless every source scanned its whole scope. |
| FIPS claims backed by evidence | implemented | keycensus never states a FIPS 140 standard or level without a CMVP certificate number in the source's `fips_evidence`. A vendor claim alone is `certificationLevel: unknown`. |

Voltage reads export files and stays complete-or-failed.

## Next

### Collector qualification

| Item | Stage | Acceptance criterion |
|---|---|---|
| Live Azure Key Vault and GCP KMS runs in CI | implemented (harness only) | The OIDC harness in [INTEGRATION-TESTS.md](INTEGRATION-TESTS.md) runs on a schedule against real accounts, and its last result is published. Until then both collectors stay "implemented". |
| Cloud organization discovery live | planned | One real AWS organization, Azure tenant and GCP folder, with the coverage counts checked by hand. |
| CipherTrust and KeySafe 5 field mappings | planned | A redacted response from a real appliance, checked into the test fixtures. |
| AD CS against a live forest and CA export | planned | A run against a lab forest, with a real `certutil -view` export. |

### Standards and interoperability

| Item | Stage | Acceptance criterion |
|---|---|---|
| CycloneDX 1.7, keeping 1.6 | integration-tested (0.13.0; read back by Dependency-Track 5.1.2 in CI) | `--cbom-version 1.7` output validates against the 1.7 schema; algorithm names are normalised with the CycloneDX Cryptography Registry. |
| NIST / CISA minimum elements | planned | A mapping table from the CBOM to the minimum elements, once the guidance under EO 14412 is published. |

## Then: teams and scale

Built on the 0.12.0 lifecycle, so an outage can never close a ticket or drop a finding out of the plan.

| Item | Stage | Acceptance criterion |
|---|---|---|
| Agent and server | planned | One agent per network zone sends Ed25519-signed results to a central server, which accepts only registered agent keys. |
| Web UI with roles | planned | Findings with owners and due dates, risk exceptions that expire, approvals with separation of duties: PCI DSS 12.3.3's plan for weakened algorithms as a workflow. |
| Jira and ServiceNow tickets; GRC export | planned | One ticket per finding with no duplicates, closed only when the finding is resolved in a complete scan; a CSV and an OSCAL POA&M export. |
| Operational requirements | planned | Written and tested before release: agent enrollment and revocation, replay protection, offline buffering and retry, retention, backup and restore, and a tested scale limit. |

## Later

| Item | Stage | Acceptance criterion |
|---|---|---|
| Risk-based PQC migration plan | planned | Per application: data sensitivity, how long it must stay confidential, exposure, owner, replacement support and effort, and why it ranks where it does. Absorbs the earlier "migration plan per quantum-vulnerable key" item. |
| Deeper code analysis | planned | Language-aware analysis of variables and wrappers, a confidence per result, and accuracy measured on a labelled sample corpus. (SARIF output shipped in 0.20.0.) |

## Language

keycensus stays in Python. It spends its time waiting on HSMs, APIs and networks, so a rewrite would cost
months of features for little speed. If the agent needs a small static binary, that one component may be
written in Go.
