# Permissions

What each source needs, at the least. Every grant below is a list or metadata read: keycensus never
uses a key, exports one, or reads a secret value other than its own credentials. Ready-to-deploy files
are in [`deploy/`](../deploy/README.md).

| Source | Grant | File |
|---|---|---|
| `pkcs11` | A Crypto User (read) role on the partition or slot. Never Crypto Officer or SO. | |
| `vault` | `read` on `sys/mounts`, `list`/`read` on Transit keys and PKI certs, `list`/`read` on `sys/policies/acl` for consumers | [`deploy/vault/keycensus-policy.hcl`](../deploy/vault/keycensus-policy.hcl) |
| `aws-kms`, one account | `kms:ListKeys`, `ListAliases`, `DescribeKey`, `GetKeyRotationStatus`, `ListResourceTags`, `ListGrants`, `GetKeyPolicy`; `ec2:DescribeRegions` for `regions: all` | [`deploy/aws/keycensus-scanner-policy.json`](../deploy/aws/keycensus-scanner-policy.json) |
| `aws-kms`, `organization: true` | The above plus `organizations:ListAccounts` and `sts:AssumeRole` on the member role; the member role in every account | [`deploy/aws/keycensus-member-role.yaml`](../deploy/aws/keycensus-member-role.yaml) (StackSet) |
| `azure-keyvault` | Subscription and vault reads, `keys/read`, `certificates/read`, `keyrotationpolicies/read`, role assignment reads; *Managed HSM Crypto Auditor* on Managed HSMs | [`deploy/azure/keycensus-reader-role.json`](../deploy/azure/keycensus-reader-role.json), [`deploy/azure/README.md`](../deploy/azure/README.md) |
| `gcp-kms` | `resourcemanager.projects.get` and six `cloudkms.*` list/get permissions, at the organization or folder | [`deploy/gcp/keycensus-kms-viewer-role.yaml`](../deploy/gcp/keycensus-kms-viewer-role.yaml) |
| `ciphertrust` | A read-only API user | |
| `keysafe5` | A bearer token or client certificate with read access to keys | |
| `adcs` | A Domain Users account for LDAP; CA *Read* for the account that runs the `certutil` export on each CA | [`deploy/ad/README.md`](../deploy/ad/README.md) |
| `voltage`, `pem` | Read access to the export or the folder | |
| `tls`, `ssh`, `network` | Network reach to the endpoints. No credentials. Written approval for the ranges you scan. | |

## keycensus's own credentials

The credentials above should not sit in environment variables if you can avoid it. Every `*_env`
option has store-backed siblings, configured once in a top-level `secrets:` block:

```yaml
secrets:
  vault: {url: https://vault.example.com:8200, auth: kubernetes, role: keycensus}
  aws: {region: us-east-1}

sources:
  - name: ctm-prod
    type: ciphertrust
    url: https://ctm.example.com
    username: keycensus
    password_vault: secret/data/keycensus#ctm_password       # HashiCorp Vault KV v1 or v2
  - name: corp-pki
    type: adcs
    ldap_url: ldaps://dc01.corp.example.com
    username: svc-keycensus@corp.example.com
    password_aws_secret: arn:aws:secretsmanager:us-east-1:111111111111:secret:keycensus/adcs#password
  - name: nshield
    type: keysafe5
    url: https://keysafe5.example.com
    token_azure_secret: https://kc-kv.vault.azure.net/secrets/ks5-token
```

`_gcp_secret` (Secret Manager) works the same way. Fetched values are cached for `cache_seconds`
(default 300). The audit log records which reference each source used, never the value.

## Who can read what keycensus produces

The outputs are a map of every key you own and what is wrong with it. `keycensus serve` therefore
requires a token for `/report.html`, `/cbom.json`, `/inventory.json`, `/findings.json`, the diffs and
the signed manifest. `/metrics`, `/healthz` and `/livez` stay public by default so Prometheus and
Kubernetes probes need nothing.

```yaml
serve:
  listen: 0.0.0.0
  auth:
    tokens:
      - {name: grafana, token_vault: secret/data/keycensus#grafana_token}
      - {name: auditor, token_file: /run/secrets/kc-auditor}
    # public_paths: []        # protect /metrics too
  tls: {cert_file: /etc/keycensus/tls.crt, key_file: /etc/keycensus/tls.key}
```

Give each reader its own named token: the audit log records which token read which file, so you can
answer "who downloaded the CBOM last week". `serve` refuses to start on a non-loopback address with
no token at all, unless `allow_unauthenticated: true` says something in front of it authenticates.
