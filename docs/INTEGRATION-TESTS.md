# Live integration tests (Azure Key Vault, Google Cloud KMS)

The unit tests run the cloud collectors against recorded API responses. The live tests in
`tests/integration/` run them against a **real** vault and a **real** project, so a change in the
cloud API or in the collector's assumptions shows up as a red build, not as a surprise on someone's
estate. They are skipped whenever the environment does not point at an account, so `pytest`
stays green on laptops, forks and pull requests from strangers.

```
KEYCENSUS_IT_AZURE_VAULT_URL=https://keycensus-it-1234.vault.azure.net
KEYCENSUS_IT_GCP_PROJECT=keycensus-it        KEYCENSUS_IT_GCP_LOCATION=us-east1
```

Credentials come from the normal chains — `az login` / `gcloud auth application-default login` on a
laptop, **OIDC workload identity federation in CI** (no secret is stored in GitHub at all).

## 1. Create the fixtures (once, ~5 minutes, a few dollars a month)

```bash
az login                          # an account that can create a resource group
./tests/integration/bootstrap-azure.sh              # standard tier; AZ_SKU=premium adds an RSA-HSM key
gcloud auth login && gcloud config set project keycensus-it
./tests/integration/bootstrap-gcp.sh
```

`tests/integration/fixtures.yml` lists what gets created and what the tests assert (four keys and a
self-signed certificate in Azure; five keys on a ring plus a service account with an IAM binding in
GCP). Everything is prefixed `kcit-`; `teardown-*.sh` removes it again.

To run against something that is *not* the fixtures (your own vault, say), set `KEYCENSUS_IT_FIXTURES=0`
and only the structural assertions run.

## 2. Let GitHub Actions log in without a secret

### Azure — federated credential on an app registration

```bash
APP=$(az ad app create --display-name keycensus-ci --query appId -o tsv)
az ad sp create --id "$APP" -o none
az ad app federated-credential create --id "$APP" --parameters '{
  "name": "github-main", "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:FlavioImbertDomingos/keycensus:ref:refs/heads/main",
  "audiences": ["api://AzureADTokenExchange"]}'
# read-only on the fixture vault (RBAC vault): keys + certificates
SCOPE=$(az keyvault show -n <vault> --query id -o tsv)
az role assignment create --assignee "$APP" --role "Key Vault Crypto User" --scope "$SCOPE"
az role assignment create --assignee "$APP" --role "Key Vault Certificate User" --scope "$SCOPE"
az role assignment create --assignee "$APP" --role "Key Vault Reader" --scope "$SCOPE"
```

Repository **variables** (Settings → Secrets and variables → Actions → Variables):
`AZURE_CLIENT_ID` = `$APP`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `KEYCENSUS_IT_AZURE_VAULT_URL`.
Add a second federated credential with subject `repo:...:environment:...` or `...:ref:refs/tags/*` if you
want tags or environments to run it too. The rotation-policy read needs `keys/getrotationpolicy`, which
*Key Vault Crypto User* includes.

### GCP — workload identity pool

```bash
PROJECT=keycensus-it; PN=$(gcloud projects describe $PROJECT --format 'value(projectNumber)')
gcloud iam workload-identity-pools create github --location global --project $PROJECT
gcloud iam workload-identity-pools providers create-oidc github --location global --workload-identity-pool github \
  --issuer-uri https://token.actions.githubusercontent.com \
  --attribute-mapping "google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition "assertion.repository=='FlavioImbertDomingos/keycensus'" --project $PROJECT
gcloud iam service-accounts create keycensus-ci --project $PROJECT
gcloud projects add-iam-policy-binding $PROJECT \
  --member "serviceAccount:keycensus-ci@$PROJECT.iam.gserviceaccount.com" --role roles/cloudkms.viewer
gcloud iam service-accounts add-iam-policy-binding keycensus-ci@$PROJECT.iam.gserviceaccount.com --project $PROJECT \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/$PN/locations/global/workloadIdentityPools/github/attribute.repository/FlavioImbertDomingos/keycensus"
```

Variables: `GCP_WORKLOAD_IDENTITY_PROVIDER` =
`projects/$PN/locations/global/workloadIdentityPools/github/providers/github`,
`GCP_SERVICE_ACCOUNT` = `keycensus-ci@$PROJECT.iam.gserviceaccount.com`, `KEYCENSUS_IT_GCP_PROJECT`,
`KEYCENSUS_IT_GCP_LOCATION`. `roles/cloudkms.viewer` includes `getIamPolicy`, so the consumer test works.

## 3. Run it

`.github/workflows/integration.yml` runs on demand (Actions → *Live integration* → Run workflow),
every Monday, and on pushes to `main` that touch the two collectors or the tests. Each job is
skipped while its variables are unset. Besides the pytest run it uploads a full `keycensus scan`
of the fixture vault/project (report, CBOM, inventory) as a workflow artifact, which is also a
handy way to see what the collectors produce on a real account.

Locally:

```bash
az login   # or: export KEYCENSUS_IT_AZURE_TOKEN=$(az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)
KEYCENSUS_IT_AZURE_VAULT_URL=https://<vault>.vault.azure.net pytest tests/integration/test_azure_live.py -rs
gcloud auth application-default login
KEYCENSUS_IT_GCP_PROJECT=keycensus-it pytest tests/integration/test_gcp_live.py -rs
```

## What is (and is not) covered

Covered: listing, paging, key/certificate mapping, rotation policy, disabled keys, protection levels
(HSM when the premium tier / HSM key is present), IAM consumers on GCP. Not covered: Azure Managed
HSM (a dedicated pool costs real money — the collector treats it as a Key Vault with a different host
and scope, which the unit tests exercise), and RBAC consumers on Azure (needs the ARM API; on the
roadmap).

The status of this harness in the upstream repository: the code and workflow are in place; the
fixtures and federated identities exist only in the maintainer's accounts once he sets them up, and
the workflow's job summary shows whether they ran or were skipped.
