#!/usr/bin/env bash
# Create the Azure Key Vault fixtures the live tests expect (idempotent). Costs: a standard Key Vault is
# free apart from per-operation pennies; the optional premium tier (for the RSA-HSM key) is a few dollars/month.
#
#   az login
#   ./tests/integration/bootstrap-azure.sh                 # standard tier
#   AZ_SKU=premium ./tests/integration/bootstrap-azure.sh  # also creates kcit-rsa-hsm
#
# Then grant the CI identity read access (see docs/INTEGRATION-TESTS.md) and set the repository variable
# KEYCENSUS_IT_AZURE_VAULT_URL=https://<vault>.vault.azure.net
set -euo pipefail
RG="${AZ_RG:-keycensus-it}"
LOC="${AZ_LOCATION:-eastus}"
VAULT="${AZ_VAULT:-keycensus-it-$RANDOM}"
SKU="${AZ_SKU:-standard}"

if az keyvault list -g "$RG" --query "[?starts_with(name,'keycensus-it')].name" -o tsv 2>/dev/null | grep -q .; then
  VAULT=$(az keyvault list -g "$RG" --query "[?starts_with(name,'keycensus-it')].name" -o tsv | head -1)
  echo "using existing vault $VAULT"
else
  az group create -n "$RG" -l "$LOC" -o none
  az keyvault create -n "$VAULT" -g "$RG" -l "$LOC" --sku "$SKU" --enable-rbac-authorization true -o none
  echo "created vault $VAULT ($SKU)"
  ME=$(az ad signed-in-user show --query id -o tsv)
  SCOPE=$(az keyvault show -n "$VAULT" --query id -o tsv)
  az role assignment create --assignee "$ME" --role "Key Vault Administrator" --scope "$SCOPE" -o none
  echo "waiting for RBAC propagation..."; sleep 30
fi
URL="https://$VAULT.vault.azure.net"

key() { az keyvault key show --vault-name "$VAULT" -n "$1" -o none 2>/dev/null || az keyvault key create --vault-name "$VAULT" -n "$1" "${@:2}" -o none; }
key kcit-rsa-rotating --kty RSA --size 2048
key kcit-ec-p384 --kty EC --curve P-384
key kcit-rsa-disabled --kty RSA --size 3072
az keyvault key set-attributes --vault-name "$VAULT" -n kcit-rsa-disabled --enabled false -o none
if [ "$SKU" = "premium" ]; then key kcit-rsa-hsm --kty RSA-HSM --size 2048; fi

# rotation policy on the rotating key only
az keyvault key rotation-policy update --vault-name "$VAULT" -n kcit-rsa-rotating --value '{
  "lifetimeActions": [{"trigger": {"timeBeforeExpiry": "P30D"}, "action": {"type": "Rotate"}}],
  "attributes": {"expiryTime": "P1Y"}}' -o none

# a self-signed certificate (Key Vault issues it with its own RSA-2048 key)
az keyvault certificate show --vault-name "$VAULT" -n kcit-selfsigned -o none 2>/dev/null || \
  az keyvault certificate create --vault-name "$VAULT" -n kcit-selfsigned \
    -p "$(az keyvault certificate get-default-policy | sed 's/CN=CLIGetDefaultPolicy/CN=kcit-selfsigned/')" -o none

echo
echo "KEYCENSUS_IT_AZURE_VAULT_URL=$URL"
echo "vault resource id: $(az keyvault show -n "$VAULT" --query id -o tsv)"
