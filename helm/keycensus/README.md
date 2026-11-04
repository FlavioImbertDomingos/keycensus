# keycensus Helm chart

Runs [keycensus](https://github.com/FlavioImbertDomingos/keycensus) in Kubernetes, two ways:

| `mode.serve` (default) | `mode.scan` |
|---|---|
| Deployment that rescans every `interval` and serves `/report.html`, `/cbom.json`, `/inventory.json`, `/metrics` | CronJob that scans on a schedule, keeps the previous `inventory.json` as a **baseline** on a PVC, writes `diff.json` / `diff.md`, fails the Job on `failOn` / `failOnNew`, and can upload the CBOM to **Dependency-Track** |

```bash
kubectl create ns crypto
kubectl -n crypto create secret generic keycensus-secrets \
  --from-literal=VAULT_TOKEN=... --from-literal=HSM_PIN=... --from-literal=AZURE_TOKEN=...
helm install keycensus ./helm/keycensus -n crypto \
  -f my-values.yaml --set existingSecret=keycensus-secrets
```

`my-values.yaml` holds your sources (exactly the `sources:` list from `keycensus.yml`):

```yaml
config:
  policy: default
  sources:
    - name: vault-prod
      type: vault
      url: https://vault.corp:8200
      token_env: VAULT_TOKEN
    - name: kv-payments
      type: azure-keyvault
      vault_url: https://payments-kv.vault.azure.net
      auth: default          # workload identity -> see serviceAccount.annotations
    - name: gcp-payments
      type: gcp-kms
      project: acme-payments-prod
mode:
  serve: { enabled: true, interval: 30m }
  scan:
    enabled: true
    schedule: "0 2 * * *"
    failOnNew: high
    dependencyTrack:
      enabled: true
      url: https://dtrack.corp
      apiKeySecret: keycensus-dtrack   # key DTRACK_API_KEY
      project: hsm-estate
serviceMonitor: { enabled: true }
serviceAccount:
  annotations:
    azure.workload.identity/client-id: 00000000-0000-0000-0000-000000000000
```

## Things to know

* **PKCS#11 sources need the vendor client library in the pod.** Build an image `FROM ghcr.io/flavioimbertdomingos/keycensus`
  that adds it (and its config files), set `image.repository`, and mount HSM client certs via `extraVolumes` /
  `extraVolumeMounts`. Network HSMs must be reachable from the cluster (NTLS 1792 for Luna, 9004 for nShield).
* **Cloud collectors** use workload identity when `auth: default`: annotate the service account for AKS / GKE / EKS
  and grant the read-only roles listed in `docs/COLLECTORS.md`.
* **`network` sources scan from the pod.** The pod needs egress to the ranges and ports you list; a
  NetworkPolicy that only allows the sources' APIs will make every port look closed. Tell whoever watches
  your IDS before the CronJob's first run.
* **Cloud discovery** (`organization: true`, `discover: true`) runs with the same workload identity; give it
  the organization-wide read roles listed in `docs/COLLECTORS.md`, not an administrator role.
* **The report and CBOM need a token.** The chart creates `<release>-serve-token` with a random token
  (kept across upgrades) and passes it as `$KEYCENSUS_SERVE_TOKEN`; `NOTES.txt` prints how to read it.
  Bring your own with `mode.serve.auth.existingTokenSecret`, or add named tokens under `config.serve.auth`.
  `/metrics`, `/healthz` and `/livez` stay public, so probes and the ServiceMonitor need nothing.
* **OIDC**: set `config.serve.auth.oidc` (see `docs/PERMISSIONS.md`). `redirect_url` must be the address
  your Ingress serves, and with more than one replica every pod needs the same `session_key` (put it in
  `existingSecret` and reference it with `session_key_env`).
* **Scanning this cluster** (`type: kubernetes` with no kubeconfig): set `rbac.kubernetesSource: true`. The
  chart then creates a ClusterRole to read secrets, pods, ingresses and cert-manager resources, binds it to
  the service account and mounts its token (otherwise the token is not mounted). Reading secrets means
  reading their values; leave it off unless you use that source.
* **Audit and signing**: set `config.audit` and `config.signing` (they pass through to the config file).
  Put the audit log on the scan PVC or ship it off the pod, and mount the signing key from a Secret
  with `extraVolumes`.
* **Secrets** never go in values. `existingSecret` is mounted with `envFrom`; the keys are the env var names your
  sources reference (`token_env`, `pin_env`, ...). Dependency-Track's key goes in its own Secret (`DTRACK_API_KEY`).
* The container runs as UID 10001 with a read-only root filesystem; `/out` and `/tmp` are writable volumes.
* `prometheus/alerts/keycensus.rules.yml` in the repo has alert rules you can load as a PrometheusRule.

## Values

See [`values.yaml`](values.yaml) — every key is commented.

## Lint / render

```bash
helm lint helm/keycensus
helm template t helm/keycensus --kube-version 1.29.0 -f helm/keycensus/ci/scan-values.yaml
```
