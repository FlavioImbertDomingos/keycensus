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
- **TLS verification on by default** for Vault and Voltage URLs; the `tls` collector disables
  verification *only* for the endpoint it's inventorying (it reports the cert; it doesn't trust it).
- **Minimal privileges documented** per collector in `docs/COLLECTORS.md`.
- **Unprivileged container**, non-root UID, no capabilities.
- Dependencies: `click`, `PyYAML`, `cryptography`, `jinja2`, `requests`, `prometheus-client`,
  plus optional `python-pkcs11`, `boto3`.

## What you should do

- Restrict who can read `out/`, the `/report.html` port, and the CBOM — they are a target list.
- Put `keycensus serve` behind your monitoring network, not on a public interface.
- Use a Crypto User (not Crypto Officer) role for PKCS#11; a read-only Vault policy; an IAM role
  with only the five `kms:*` read actions.
- Rotate the credentials keycensus uses like any other service credential.

## Out of scope

`mock-voltage/` and the demo seeds are demo tooling with fixed passwords; never expose them.
