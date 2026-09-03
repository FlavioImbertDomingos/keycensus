# Helm

See [helm/keycensus/README.md](../helm/keycensus/README.md). Quick start:

```bash
kubectl -n crypto create secret generic keycensus-secrets --from-literal=VAULT_TOKEN=... --from-literal=HSM_PIN=...
helm install keycensus ./helm/keycensus -n crypto -f my-values.yaml --set existingSecret=keycensus-secrets
```

## Alerting on change

The chart's CronJob keeps `/out/latest` on a PVC and passes it as `--baseline`, so every run produces
a classified change set (`changes.json`) as well as a diff. Two ways to act on it:

```yaml
# 1. Prometheus: the Deployment's /metrics carries keycensus_change_total{kind,urgency,source}.
#    Load prometheus/alerts/keycensus.rules.yml into your Prometheus and you are done.

# 2. Webhook, for clusters without Prometheus. The URL is a credential, so it lives in the Secret:
#    kubectl create secret generic keycensus-secrets \
#      --from-literal=KEYCENSUS_WEBHOOK_URL='https://hooks.slack.com/services/...'
existingSecret: keycensus-secrets
config:
  notifications:
    webhook_url_env: KEYCENSUS_WEBHOOK_URL
    format: slack
    on: page
```

Add `--fail-on-page` to the CronJob args to make a run that finds a page-worthy change exit 5, which
Kubernetes records as a failed Job. Details: [ALERTING.md](ALERTING.md).
