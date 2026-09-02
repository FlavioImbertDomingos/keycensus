#!/usr/bin/env bash
# Delete everything bootstrap-azure.sh created (the whole resource group).
set -euo pipefail
RG="${AZ_RG:-keycensus-it}"
for v in $(az keyvault list -g "$RG" --query "[].name" -o tsv); do
  az keyvault delete -n "$v" -g "$RG" -o none && az keyvault purge -n "$v" -o none || true
done
az group delete -n "$RG" --yes --no-wait
echo "resource group $RG deletion requested"
