#!/usr/bin/env bash
# Seed a kind cluster (cert-manager already installed) for the `kubernetes` CI job, and write a
# kubeconfig for the keycensus service account to $1.
#
#   apps     a TLS secret mounted by a Deployment, and an Opaque secret holding an EC private key
#   certs    a cert-manager Certificate from a self-signed Issuer, with rotationPolicy: Never
#   locked   a TLS secret the service account may not read
#
# RBAC is deploy/kubernetes/keycensus-reader.yaml narrowed the way its header describes: the
# ClusterRoleBinding replaced by RoleBindings in apps and certs only.
set -euo pipefail
out=${1:?usage: kind_seed.sh <kubeconfig to write>}
here=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)

for ns in apps certs locked; do kubectl create namespace "$ns"; done
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/web.key" -out "$work/web.crt" -days 30 \
  -subj "/CN=web.apps.example.com" 2>/dev/null
kubectl -n apps create secret tls web-tls --cert="$work/web.crt" --key="$work/web.key"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/signer.pem"
kubectl -n apps create secret generic signer --from-file=signing.key="$work/signer.pem" --from-literal=note=not-a-key
kubectl -n locked create secret tls hidden-tls --cert="$work/web.crt" --key="$work/web.key"

# The cert-manager webhook can take a few seconds after its rollout to accept requests.
for i in $(seq 1 30); do
  kubectl apply -f "$here/tests/fixtures/kind/resources.yaml" && break
  [ "$i" = 30 ] && exit 1
  sleep 5
done
kubectl -n certs wait certificate/internal --for=condition=Ready --timeout=180s
kubectl -n apps rollout status deploy/web --timeout=180s

kubectl apply -f "$here/deploy/kubernetes/keycensus-reader.yaml"
kubectl delete clusterrolebinding keycensus-reader
for ns in apps certs; do
  kubectl -n "$ns" create rolebinding keycensus-reader --clusterrole=keycensus-reader \
    --serviceaccount=keycensus:keycensus
done

token=$(kubectl -n keycensus create token keycensus --duration=1h)
kubectl config view --raw --minify > "$out"
kubectl --kubeconfig "$out" config set-credentials keycensus --token="$token" >/dev/null
kubectl --kubeconfig "$out" config set-context --current --user=keycensus >/dev/null
test "$(kubectl --kubeconfig "$out" auth can-i list secrets -n apps)" = yes
test "$(kubectl --kubeconfig "$out" auth can-i list secrets -n locked || true)" = no
echo "seeded; keycensus kubeconfig at $out"
