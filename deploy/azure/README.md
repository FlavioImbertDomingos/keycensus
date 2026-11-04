# Azure: least privilege for keycensus

`keycensus-reader-role.json` is a custom role with exactly what the `azure-keyvault` collector reads:
the subscription and vault listing for `discover: true`, key and certificate metadata (public keys
only), key rotation policies, and role assignments for consumers. It has no `secrets/getSecret`, no
key operations, and no write action.

```bash
# 1. Create the role at the management group that holds your subscriptions
#    (edit AssignableScopes first)
az role definition create --role-definition keycensus-reader-role.json

# 2. Assign it to the identity keycensus runs as (managed identity, workload identity or SP)
az role assignment create --assignee <object-id> --role "keycensus inventory reader" \
  --scope /providers/Microsoft.Management/managementGroups/<mg>
```

Vaults that use **access policies** instead of RBAC ignore role assignments for data access. Give the
identity a `get` + `list` policy on keys and certificates there:

```bash
az keyvault set-policy -n <vault> --object-id <object-id> --key-permissions get list getrotationpolicy \
  --certificate-permissions get list
```

**Managed HSM** has its own local RBAC. Assign the built-in *Managed HSM Crypto Auditor* role on the HSM:

```bash
az keyvault role assignment create --hsm-name <hsm> --role "Managed HSM Crypto Auditor" \
  --assignee <object-id> --scope /
```

If you would rather use built-in roles: *Reader* on the subscriptions plus *Key Vault Reader* on the
vaults covers the same ground, and *Key Vault Reader* can also see secret metadata (names, not values).
