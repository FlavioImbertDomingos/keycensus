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
- **Secrets never in YAML.** `*_env` / `*_file` only; `config/keycensus.yml` and `.env` are git-ignored.
- **No key material in outputs.** Assets carry metadata only; certificate public keys are summarised
  (algorithm, size, fingerprint), not embedded.
- **TLS verification on by default** for Vault, Voltage and AD CS LDAPS URLs; the `tls` collector disables
  verification *only* for the endpoint it's inventorying (it reports the cert; it doesn't trust it).
- **Probes, not attacks.** The TLS key exchange probe sends a ClientHello and reads one reply, never
  finishing the handshake; the SSH probe reads the banner and algorithm list, never logging in. The
  `network` collector refuses public ranges and ranges over 4096 addresses unless told otherwise.
- **No clear-text LDAP passwords.** The AD CS collector refuses a simple bind over plain `ldap://`;
  it needs `ldaps://`, StartTLS or Kerberos.
- **Minimal privileges documented** per collector in `docs/COLLECTORS.md`.
- **Unprivileged container**, non-root UID, no capabilities.
- Dependencies: `click`, `PyYAML`, `cryptography`, `jinja2`, `requests`, `prometheus-client`,
  plus optional `python-pkcs11`, `hvac`, `boto3`, `azure-identity`, `google-auth`, `ldap3` (and
  `gssapi` for AD CS Kerberos). The TLS 1.3 and SSH probes are written against the RFCs with the
  standard library and `cryptography`; no extra dependency.

## What you should do

- Restrict who can read `out/`, the `/report.html` port, and the CBOM — they are a target list.
- Put `keycensus serve` behind your monitoring network, not on a public interface. Today it listens on
  all interfaces with no authentication; use `--listen 127.0.0.1` or a reverse proxy with auth until the
  roadmap's `serve` hardening ships.
- Use a Crypto User (not Crypto Officer) role for PKCS#11; a read-only Vault policy; an IAM role
  with only the five `kms:*` read actions; a dedicated AD account with no rights beyond domain user
  for the AD CS LDAP bind.
- Rotate the credentials keycensus uses like any other service credential.
- For cloud discovery, give keycensus a read-only role (an AWS member role with only KMS read actions,
  Azure *Reader* plus the Key Vault read roles, GCP `roles/browser` and `roles/cloudkms.viewer`), never an
  administrator role such as `OrganizationAccountAccessRole`.
- Get written approval before pointing the `network` collector at a range, and tell whoever watches the IDS.

## Out of scope

`mock-voltage/` and the demo seeds are demo tooling with fixed passwords; never expose them.
