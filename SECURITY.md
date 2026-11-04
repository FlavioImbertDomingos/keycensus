# Security

## Reporting

Email the maintainer (address on the GitHub profile). Please don't open public issues for
vulnerabilities.

## What keycensus touches

It holds credentials for several sensitive systems at once (an HSM partition PIN, a Vault token,
AWS credentials) and produces an output that is itself sensitive: a map of every key you own,
with names, locations and weaknesses. Treat both the config and the outputs accordingly.

## What the project does

- **Read-only everywhere.** No collector has a write path. PKCS#11 reads attributes, never values.
- **Secrets never in YAML.** `*_env`, `*_file`, or a secret store (`*_vault`, `*_aws_secret`,
  `*_azure_secret`, `*_gcp_secret`); `config/keycensus.yml` and `.env` are git-ignored. Values are never
  logged; the audit log records references only.
- **The report and CBOM need a token.** `keycensus serve` listens on 127.0.0.1 by default and refuses to
  start on any other address without a token, unless `allow_unauthenticated` says a proxy authenticates.
  Tokens are compared as SHA-256 digests in constant time; HTTPS with `serve.tls`. Or sign in with
  your identity provider (`serve.auth.oidc`): authorization code with PKCE, `state` and `nonce` checks,
  ID tokens and machine JWTs verified against the provider's JWKS, allow-lists required. Responses carry
  `nosniff`, `no-store`, `X-Frame-Options: DENY` and a restrictive Content-Security-Policy.
- **Audit log.** With `audit:` set, every scan (sources and credential references), config or policy
  change, report or CBOM read (with the token's name), refused request and webhook is appended to a
  hash-chained JSON lines file, optionally HMAC-keyed. `keycensus audit verify` checks the chain.
- **Signed scan records.** With `signing:` set, every scan writes `manifest.json` (SHA-256 of each
  output) and an Ed25519 signature over it. With `signing.timestamp`, an RFC 3161 Time Stamping
  Authority countersigns that signature, so the signing time does not rest on the scanner's clock.
  `keycensus verify OUT --public-key ... --tsa-ca-file ...` checks all of it.
- **No key material in outputs.** Assets carry metadata only; certificate public keys are summarised
  (algorithm, size, fingerprint), not embedded.
- **TLS verification on by default** for Vault, Voltage and AD CS LDAPS URLs; the `tls` collector disables
  verification *only* for the endpoint it's inventorying (it reports the cert; it doesn't trust it).
- **Probes, not attacks.** The TLS key exchange probe sends a ClientHello and reads one reply, never
  finishing the handshake; the SSH probe reads the banner and algorithm list, never logging in. The
  `network` collector refuses public ranges and ranges over 4096 addresses unless told otherwise.
- **No clear-text LDAP passwords.** The AD CS collector refuses a simple bind over plain `ldap://`;
  it needs `ldaps://`, StartTLS or Kerberos.
- **Minimal privileges documented** per collector in `docs/PERMISSIONS.md`, with deployable IAM, Azure,
  GCP and Vault policies in `deploy/`.
- **Unprivileged container**, non-root UID, no capabilities.
- **Signed releases.** Every image CI publishes to GHCR is signed with Sigstore (keyless, logged in Rekor),
  with an SPDX SBOM attestation and SLSA build provenance bound to its digest. Verify before you run it:

  ```bash
  cosign verify ghcr.io/flavioimbertdomingos/keycensus:main \
    --certificate-identity-regexp '^https://github.com/FlavioImbertDomingos/keycensus/\.github/workflows/ci\.yml@' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  gh attestation verify oci://ghcr.io/flavioimbertdomingos/keycensus:main --repo FlavioImbertDomingos/keycensus
  ```
- Dependencies: `click`, `PyYAML`, `cryptography`, `jinja2`, `requests`, `prometheus-client`,
  plus optional `python-pkcs11`, `hvac`, `boto3`, `azure-identity`, `google-auth`, `ldap3` (and
  `gssapi` for AD CS Kerberos). The TLS 1.3 and SSH probes are written against the RFCs with the
  standard library and `cryptography`; no extra dependency.

## What you should do

- Restrict who can read `out/` and who holds a `serve` token — the outputs are a target list. Give each
  reader its own named token so the audit log can tell them apart.
- Put `keycensus serve` behind your monitoring network, not on a public interface, and turn on
  `serve.tls` or terminate TLS in front of it.
- Turn on `audit:` with an HMAC key kept away from the people who can read the log, and `signing:` with
  a private key only the scanner can read. Ship the audit log somewhere append-only.
- Use the kits in `deploy/`: a Crypto User (not Crypto Officer) role for PKCS#11, the read-only Vault
  policy, the AWS member role and scanner policy, the Azure and GCP custom roles, and a dedicated AD
  account with no rights beyond Domain Users for the AD CS LDAP bind.
- Keep keycensus's own credentials in a secret store (`*_vault`, `*_aws_secret`, ...) rather than
  environment variables, and rotate them like any other service credential.
- For cloud discovery, give keycensus a read-only role (an AWS member role with only KMS read actions,
  Azure *Reader* plus the Key Vault read roles, GCP `roles/browser` and `roles/cloudkms.viewer`), never an
  administrator role such as `OrganizationAccountAccessRole`.
- Get written approval before pointing the `network` collector at a range, and tell whoever watches the IDS.

## Out of scope

`mock-voltage/` and the demo seeds are demo tooling with fixed passwords; never expose them.
