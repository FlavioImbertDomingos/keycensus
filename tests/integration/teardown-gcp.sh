#!/usr/bin/env bash
# KMS key rings cannot be deleted; destroying every version stops the billing and the tests' fixtures.
set -euo pipefail
PROJECT="${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
LOC="${GCP_LOCATION:-us-east1}"
for k in $(gcloud kms keys list --keyring kcit-ring --location "$LOC" --project "$PROJECT" --format 'value(name.basename())'); do
  for v in $(gcloud kms keys versions list --key "$k" --keyring kcit-ring --location "$LOC" --project "$PROJECT" --filter 'state!=DESTROYED AND state!=DESTROY_SCHEDULED' --format 'value(name.basename())'); do
    gcloud kms keys versions destroy "$v" --key "$k" --keyring kcit-ring --location "$LOC" --project "$PROJECT" --quiet
  done
done
gcloud iam service-accounts delete "kcit-app@$PROJECT.iam.gserviceaccount.com" --project "$PROJECT" --quiet || true
echo "all kcit-ring key versions scheduled for destruction"
