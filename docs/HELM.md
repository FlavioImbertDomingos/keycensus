# Helm

See [helm/keycensus/README.md](../helm/keycensus/README.md). Quick start:

```bash
kubectl -n crypto create secret generic keycensus-secrets --from-literal=VAULT_TOKEN=... --from-literal=HSM_PIN=...
helm install keycensus ./helm/keycensus -n crypto -f my-values.yaml --set existingSecret=keycensus-secrets
```
