# Vault policy for the `vault` collector, plus reading keycensus's own credentials from KV.
#
#   vault policy write keycensus keycensus-policy.hcl
#   vault write auth/kubernetes/role/keycensus bound_service_account_names=keycensus \
#     bound_service_account_namespaces=keycensus policies=keycensus ttl=1h
#
# Mount names below are the defaults; repeat the blocks for every Transit and PKI mount you scan.

# Find the Transit and PKI mounts (skip if you list transit_mounts / pki_mounts explicitly)
path "sys/mounts" { capabilities = ["read"] }

# Transit: key names and metadata (versions, type, exportable, auto-rotate). Never encrypt/decrypt/export.
path "transit/keys"   { capabilities = ["list"] }
path "transit/keys/*" { capabilities = ["read"] }

# PKI: issued certificates (public)
path "pki/certs"  { capabilities = ["list"] }
path "pki/cert/*" { capabilities = ["read"] }

# Consumers: which policies grant use of each Transit key (include_policies)
path "sys/policies/acl"   { capabilities = ["list"] }
path "sys/policies/acl/*" { capabilities = ["read"] }

# keycensus's own secrets, if you use *_vault references (secrets: vault: ...)
path "secret/data/keycensus" { capabilities = ["read"] }
