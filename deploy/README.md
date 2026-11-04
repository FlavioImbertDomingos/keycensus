# Least-privilege kits

Ready-to-deploy permissions for every source keycensus reads. Each grants listing and metadata reads
only: no key use, no export, no secret values (except the credentials keycensus itself needs).

| Path | For | What it is |
|---|---|---|
| `aws/keycensus-member-role.yaml` | `aws-kms` with `organization: true` | CloudFormation role for every member account; deploy with a StackSet |
| `aws/keycensus-scanner-policy.json` | `aws-kms` | IAM policy for the identity keycensus runs as: list accounts, assume the member role, read KMS in its own account |
| `azure/keycensus-reader-role.json` | `azure-keyvault` | Custom role: list subscriptions and vaults, read key/certificate metadata, rotation policies and role assignments |
| `azure/README.md` | `azure-keyvault` | Access-policy vaults, Managed HSM local RBAC, the built-in alternative |
| `gcp/keycensus-kms-viewer-role.yaml` | `gcp-kms` | Custom role: seven read permissions, bound at the organization or a folder |
| `vault/keycensus-policy.hcl` | `vault`, and `*_vault` secret references | Vault policy and a Kubernetes auth role example |
| `ad/README.md` | `adcs` | Checklist for the LDAP account and the CA export task |

PKCS#11 needs a Crypto User (read) role on the partition or slot, never Crypto Officer; the
CipherTrust and KeySafe 5 collectors need a read-only API user. Details per source:
[docs/COLLECTORS.md](../docs/COLLECTORS.md) and [docs/PERMISSIONS.md](../docs/PERMISSIONS.md).
