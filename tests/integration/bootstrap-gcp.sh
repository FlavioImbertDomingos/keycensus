#!/usr/bin/env bash
# Create the Cloud KMS fixtures the live tests expect (idempotent). Key versions cost ~$0.06/month each;
# the HSM key ~$1/month. Destroyed/disabled versions are free.
#
#   gcloud auth login && gcloud config set project <project>
#   ./tests/integration/bootstrap-gcp.sh
#
# Then set the repository variable KEYCENSUS_IT_GCP_PROJECT=<project> (and KEYCENSUS_IT_GCP_LOCATION=us-east1).
set -euo pipefail
PROJECT="${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
LOC="${GCP_LOCATION:-us-east1}"
RING="kcit-ring"
SA="kcit-app"
gcloud services enable cloudkms.googleapis.com --project "$PROJECT"
gcloud kms keyrings describe "$RING" --location "$LOC" --project "$PROJECT" >/dev/null 2>&1 || \
  gcloud kms keyrings create "$RING" --location "$LOC" --project "$PROJECT"

key() { gcloud kms keys describe "$1" --keyring "$RING" --location "$LOC" --project "$PROJECT" >/dev/null 2>&1 || \
        gcloud kms keys create "$1" --keyring "$RING" --location "$LOC" --project "$PROJECT" "${@:2}"; }
key kcit-sym-rotating --purpose encryption --rotation-period 90d --next-rotation-time "$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+30d +%Y-%m-%dT%H:%M:%SZ)"
key kcit-ec-sign --purpose asymmetric-signing --default-algorithm ec-sign-p256-sha256
key kcit-hmac --purpose mac --default-algorithm hmac-sha256
key kcit-hsm-sym --purpose encryption --protection-level hsm
key kcit-disabled --purpose encryption
gcloud kms keys versions disable 1 --key kcit-disabled --keyring "$RING" --location "$LOC" --project "$PROJECT" 2>/dev/null || true

# a service account that "uses" the rotating key -> the collector reports it as a consumer
gcloud iam service-accounts describe "$SA@$PROJECT.iam.gserviceaccount.com" --project "$PROJECT" >/dev/null 2>&1 || \
  gcloud iam service-accounts create "$SA" --display-name "keycensus IT consumer" --project "$PROJECT"
gcloud kms keys add-iam-policy-binding kcit-sym-rotating --keyring "$RING" --location "$LOC" --project "$PROJECT" \
  --member "serviceAccount:$SA@$PROJECT.iam.gserviceaccount.com" --role roles/cloudkms.cryptoKeyEncrypterDecrypter >/dev/null

echo
echo "KEYCENSUS_IT_GCP_PROJECT=$PROJECT"
echo "KEYCENSUS_IT_GCP_LOCATION=$LOC"
