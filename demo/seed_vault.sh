#!/bin/sh
# Seed a Vault dev server with Transit keys and a PKI mount.
# Runs inside the hashicorp/vault image (vault CLI available). Idempotent.
set -eu
export VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
export VAULT_TOKEN="${VAULT_TOKEN:-root}"

for i in $(seq 1 30); do
  if vault status >/dev/null 2>&1; then break; fi
  echo "waiting for vault..."; sleep 1
done

if vault read -field=type transit/keys/payments-dek >/dev/null 2>&1; then
  echo "vault already seeded"; exit 0
fi

vault secrets enable transit >/dev/null 2>&1 || true
vault write -f transit/keys/payments-dek type=aes256-gcm96 auto_rotate_period=720h
vault write -f transit/keys/session-aes128 type=aes128-gcm96
vault write -f transit/keys/legacy-rsa type=rsa-2048 exportable=true
vault write -f transit/keys/jwt-ecdsa type=ecdsa-p256
vault write -f transit/keys/stream-chacha type=chacha20-poly1305 auto_rotate_period=720h
vault write -f transit/keys/audit-hmac type=hmac key_size=32
vault write -f transit/keys/ssh-ed25519 type=ed25519

vault secrets enable pki >/dev/null 2>&1 || true
vault secrets tune -max-lease-ttl=87600h pki >/dev/null
vault write -f pki/root/generate/internal common_name="Demo Bank Vault Root CA" ttl=87600h key_type=rsa key_bits=4096 >/dev/null
vault write pki/roles/internal allowed_domains=demo.bank allow_subdomains=true max_ttl=720h >/dev/null
vault write pki/issue/internal common_name=vault-app.demo.bank ttl=240h >/dev/null
vault write pki/issue/internal common_name=vault-batch.demo.bank ttl=24h >/dev/null
# who uses which key: ACL policies (keycensus reads sys/policies/acl and maps transit paths to keys)
vault policy write payments-api - <<'POL' >/dev/null
path "transit/encrypt/payments-dek" { capabilities = ["update"] }
path "transit/decrypt/payments-dek" { capabilities = ["update"] }
path "transit/encrypt/session-*"    { capabilities = ["update"] }
POL
vault policy write auth-service - <<'POL' >/dev/null
path "transit/sign/jwt-ecdsa"   { capabilities = ["update"] }
path "transit/verify/jwt-ecdsa" { capabilities = ["update"] }
POL
vault policy write batch-reporting - <<'POL' >/dev/null
path "transit/decrypt/payments-dek" { capabilities = ["update"] }
path "transit/keys/legacy-rsa"      { capabilities = ["read"] }
POL
echo "seeded vault: 7 transit keys, 1 root CA, 2 leaf certs, 3 policies"
