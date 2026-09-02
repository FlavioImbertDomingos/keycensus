# FAQ

**Is it safe to run against production HSMs and KMSs?**
Yes — it only reads. PKCS#11: `C_FindObjects` + `C_GetAttributeValue` on public attributes.
Vault: `list` + `read` on key metadata. AWS: `List*`/`Describe*`/`Get*RotationStatus`. Use
read-only roles/policies (examples in [COLLECTORS.md](COLLECTORS.md)) and it *cannot* change anything.

**Does it ever see key material?**
No. It never reads `CKA_VALUE`, never exports, never calls `GetPublicKey` on KMS, never reads Vault
`export/` endpoints. Private keys found in PEM files are parsed only to learn their algorithm and
size.

**Why is my HSM key's age "unknown"?**
PKCS#11 has no mandatory creation timestamp. If the HSM sets `CKA_START_DATE` you get it;
otherwise keycensus says so (`no-creation-date`, info) rather than guessing. Fix it at the
source or maintain a key register and feed it via the `voltage`-style export collector.

**Is the PKCS#11 collector really Luna / nShield / CloudHSM compatible?**
It uses only baseline PKCS#11 v2.x calls and attributes, tested against SoftHSM. Vendor
libraries occasionally refuse certain attribute reads for certain objects; those objects are
logged and skipped rather than failing the scan. Please open an issue with vendor + firmware if
you hit one.

**Where should keycensus run?**
Wherever it can reach the sources. For PKCS#11 that means a host with the vendor client — usually
the crypto-ops jump host or the app server. For Vault/KMS/TLS anywhere with network access. Running
one instance per network zone with a merged view is a reasonable pattern (the JSON outputs
concatenate trivially).

**Why isn't there a real Voltage integration?**
Voltage SecureData has no public inventory API. The collector reads an export and the docs say so
plainly. If you have a Voltage estate, export from the Management Console (or write a 20-line
adapter that emits the canonical JSON), point `file:` or `url:` at it, and it just works.

**Can I use it without Docker?**
`pip install "keycensus[all]"` and `keycensus scan -c config.yml`. Docker is only for the demo
stack and the container image. The PKCS#11 extra needs the vendor library on the host.

**How do I gate a pipeline?**
`keycensus scan -c config.yml --fail-on high` → exit code 1 on high/critical findings, 2 if any
source failed, 0 otherwise.

**What's the difference between `scan` and `serve`?**
`scan` runs once and writes files. `serve` rescans on an interval and exposes `/metrics`,
`/report.html`, `/cbom.json` over HTTP — for Prometheus and for a bookmarkable live report.

**The CBOM validates, but Dependency-Track shows nothing.**
Make sure you're on a Dependency-Track version with CycloneDX 1.6 support (≥ 4.11) and upload
with `Content-Type: application/vnd.cyclonedx+json`.

**Severities feel wrong for my environment.**
They're meant to be changed. Copy the default policy, edit `rules:`, pass `--policy`. See
[POLICY.md](POLICY.md).

**Is this a substitute for a commercial crypto-inventory / CBOM product?**
For discovery across the common sources and a standards-based output, it's a solid start. The
commercial tools add network-wide passive discovery, code scanning, agent-based endpoint
inventory, and workflow. keycensus is the open, scriptable, inspectable core you can run today.

**License / trademarks?**
Apache-2.0. Thales, Luna, Entrust, nShield, OpenText, Voltage, HashiCorp, Vault and AWS are
trademarks of their owners; no affiliation.
