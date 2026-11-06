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

## Now: 0.12.0, trustworthy results

The question each release should answer better: what did we inspect, what did we miss, and what evidence
supports each finding.

| Item | Stage | Acceptance criterion |
|---|---|---|
| Scan states (complete, partial, failed) per source and per scan | integration-tested (files), implemented (cloud, Kubernetes) | `inventory.json`, the report, the console and `/metrics` show the state of every source. |
| Finding lifecycle that cannot be closed by an outage | integration-tested | An outage, a lost permission or a partial scan never makes an asset "removed" or a finding "resolved". Missing assets from a failed or unscanned scope are carried forward as not observed, with their last observation time, and their findings stay open as "not re-verified". A real deletion in a fully scanned scope still counts. |
| Coverage within a source | implemented | AWS (accounts, regions, keys), Azure (subscriptions, vaults), GCP (projects, locations), Kubernetes (namespaces, cert-manager), files (paths, files) and CT (domains) report expected, scanned, denied, unavailable and failed counts, and denied optional permissions. When the total cannot be discovered, it says so instead of showing a percentage. |
| `--require-complete` CI gate | integration-tested | `keycensus scan --require-complete` exits 6 unless every source scanned its whole scope. |
| FIPS claims backed by evidence | implemented | keycensus never states a FIPS 140 standard or level without a CMVP certificate number in the source's `fips_evidence`. A vendor claim alone is `certificationLevel: unknown`. |

Coverage for Vault, PKCS#11, CipherTrust, KeySafe 5, AD CS and Voltage is still complete-or-failed;
breaking those down (mounts, slots, CAs, pages) comes with `keycensus doctor`.

## Next

### Easy to start

| Item | Stage | Acceptance criterion |
|---|---|---|
| `pipx install keycensus`, Homebrew, single-file binaries | planned | A clean machine goes from install to first report with no Python setup. |
| `keycensus init` | planned | Asks which sources you run, tests each credential, writes the config and runs the first scan. |
| `keycensus doctor` | planned | For each source: what it reached, which scopes were partial and why, which permission is missing and the policy file that grants it. Built on the coverage records from 0.12.0. |

### Collector qualification

| Item | Stage | Acceptance criterion |
|---|---|---|
| Live Azure Key Vault and GCP KMS runs in CI | implemented (harness only) | The OIDC harness in [INTEGRATION-TESTS.md](INTEGRATION-TESTS.md) runs on a schedule against real accounts, and its last result is published. Until then both collectors stay "implemented". |
| Kubernetes against a real cluster | planned | The collector runs in CI against kind with cert-manager installed: TLS and Opaque secrets, a Certificate, a forbidden namespace. |
| Cloud organization discovery live | planned | One real AWS organization, Azure tenant and GCP folder, with the coverage counts checked by hand. |
| CipherTrust and KeySafe 5 field mappings | planned | A redacted response from a real appliance, checked into the test fixtures. |
| AD CS against a live forest and CA export | planned | A run against a lab forest, with a real `certutil -view` export. |

### Standards and interoperability

| Item | Stage | Acceptance criterion |
|---|---|---|
| CycloneDX 1.7, keeping 1.6 | planned | `--cbom-version 1.7` output validates against the 1.7 schema; algorithm names are normalised with the CycloneDX Cryptography Registry. |
| Downstream ingestion tests | planned | A CBOM, with relationships and findings, round-trips through Dependency-Track in CI. |
| Versioned policy packs | planned | Each policy has a version, an effective date, references, applicability and a review date, and every scan records the exact policy version. |
| NIST / CISA minimum elements | planned | A mapping table from the CBOM to the minimum elements, once the guidance under EO 14412 is published. |

## Then: 0.13.0, teams and scale

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
| Asset identity and relationships | planned | The same certificate seen in a file, a Kubernetes secret and on a TLS endpoint is one asset with three observations; key versions, certificate-to-key and wrapping-key links. |
| Observed usage | planned | Optional CloudTrail, Vault audit and cloud audit-log imports, reported apart from "allowed to use" and "declared dependency", with the observation window. |
| Risk-based PQC migration plan | planned | Per application: data sensitivity, how long it must stay confidential, exposure, owner, replacement support and effort, and why it ranks where it does. Absorbs the earlier "migration plan per quantum-vulnerable key" item. |
| Deeper code analysis | planned | Language-aware analysis of variables and wrappers, a confidence per result, SARIF output, and accuracy measured on a labelled sample corpus. |

## Language

keycensus stays in Python. It spends its time waiting on HSMs, APIs and networks, so a rewrite would cost
months of features for little speed. If the agent needs a small static binary, that one component may be
written in Go.
