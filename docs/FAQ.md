# FAQ

**Is it safe to run against production HSMs and KMSs?**
Yes — it only reads. PKCS#11: `C_FindObjects` + `C_GetAttributeValue` on public attributes.
Vault: `list` + `read` on key metadata. AWS: `List*`/`Describe*`/`Get*RotationStatus`. Use
read-only roles/policies (examples in [COLLECTORS.md](COLLECTORS.md)) and it *cannot* change anything.
Endpoints are probed, not logged into: a TLS handshake plus one unfinished ClientHello per probe, and
for SSH the banner and algorithm list the server sends before authentication.

**Does it ever see key material?**
No. It never reads `CKA_VALUE`, never exports, never calls `GetPublicKey` on KMS, never reads Vault
`export/` endpoints, never reads AD CS archived keys. Private keys found in PEM files are parsed only
to learn their algorithm and size.

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

**Does the AD CS collector find ESC1-style misconfigurations?**
No, and it does not try to. It inventories the CAs, their templates' crypto settings (minimum key
size, validity, exportable private keys) and the certificates the CAs issued, and grades them like
any other certificate. Whether a template is *exploitable* depends on enrollment ACLs and CA flags
that keycensus does not read. Run Locksmith, PSPKIAudit or Certipy for that; the two answer
different questions and work well side by side.

**Why does AD CS need a `certutil` export instead of an API?**
The CA database is only reachable remotely over DCOM (ICertView), which does not work from a Linux
container. The CA certificates and templates come straight from LDAP; for the issued certificates,
a scheduled `certutil -view ... csv` on each CA is the dependable path. The exact command is in
[COLLECTORS.md](COLLECTORS.md#adcs--microsoft-active-directory-certificate-services).

**Is the network scan safe to run?**
It is a TCP connect to each address and port in range, then a TLS handshake or an SSH banner read on the
ports that answered. No exploits, no logins, no raw packets, no root. It still looks like a scan to an IDS,
so tell your network team first, and only scan ranges you are authorized to scan. By default it refuses
public addresses and ranges over 4096 addresses.

**How does keycensus see X25519MLKEM768 when my OpenSSL is 3.0?**
It does not use OpenSSL for that part. It writes the TLS 1.3 ClientHello itself, offering the hybrid
groups, and reads which group the server picks from the reply, which is unencrypted in TLS 1.3. The
handshake is never finished. See [COLLECTORS.md](COLLECTORS.md#key-exchange-classical-hybrid-or-ml-kem).
If a TLS-inspecting proxy sits between keycensus and the server, the proxy answers instead, so run it from
inside the network you are measuring.

**How do Grafana, auditors or a dashboard get at the report now that it needs a token?**
Give each its own named token under `serve.auth.tokens`, and send it as `Authorization: Bearer ...`.
A browser asks for a user name and password: any user name, the token as the password. `/metrics`
stays public, so Prometheus needs nothing. The audit log records which token read what.

**How does an assessor check that a CBOM was not edited after the scan?**
Turn on `signing:`. Each scan writes `manifest.json` (a SHA-256 per output file) and
`manifest.json.sig`. The assessor runs `keycensus verify <folder> --public-key keycensus-signing.pub.pem`;
any changed byte, missing file or other key fails it.

**Which timestamp authority should I use?**
Any RFC 3161 TSA. DigiCert (`http://timestamp.digicert.com`) and Sectigo run free public ones whose roots
are in the usual system bundles, so `ca_file: /etc/ssl/certs/ca-certificates.crt` works for them.
FreeTSA (`https://freetsa.org/tsr`) publishes its root at freetsa.org. List two in `urls` so one outage
does not leave a scan unstamped, and set `required: true` if an unstamped scan should fail. Only the hash
of the signature leaves your network.

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
with `Content-Type: application/vnd.cyclonedx+json`. Keep the default 1.6 output for Dependency-Track
unless your release states that it reads CycloneDX 1.7; `--cbom-version 1.7` is for tools that do.

**Severities feel wrong for my environment.**
They're meant to be changed. Copy the default policy, edit `rules:`, pass `--policy`. See
[POLICY.md](POLICY.md).

**Is this a substitute for a commercial crypto-inventory / CBOM product?**
For discovery across the common sources and a standards-based output, it's a solid start. The
commercial tools add network-wide passive discovery, code scanning, agent-based endpoint
inventory, and workflow. keycensus is the open, scriptable, inspectable core you can run today.

**License / trademarks?**
Apache-2.0. Thales, Luna, Entrust, nShield, OpenText, Voltage, HashiCorp, Vault, AWS, Microsoft and
Active Directory are trademarks of their owners; no affiliation.
