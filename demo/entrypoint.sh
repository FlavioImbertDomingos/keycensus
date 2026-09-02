#!/bin/sh
# Container entrypoint.
#
#   entrypoint.sh serve        -> (demo) seed SoftHSM/KMS/certs if KEYCENSUS_DEMO=1, then `keycensus serve`
#   entrypoint.sh scan         -> one-shot scan into /out, then exit
#   entrypoint.sh <anything>   -> passed straight to the keycensus CLI
set -eu

CONFIG="${KEYCENSUS_CONFIG:-/config/keycensus.yml}"
INTERVAL="${KEYCENSUS_INTERVAL:-15m}"

if [ "${KEYCENSUS_DEMO:-0}" = "1" ]; then
  echo "[demo] preparing demo data..."
  python /app/demo/make_demo_certs.py /app/demo/certs >/dev/null 2>&1 || true
  python /app/demo/seed_softhsm.py --label demo --pin "${HSM_PIN:-1234}" || echo "[demo] softhsm seed skipped"
  if [ -n "${KMS_ENDPOINT:-}" ]; then
    for i in $(seq 1 30); do
      if python /app/demo/seed_kms.py --endpoint "$KMS_ENDPOINT" 2>/dev/null; then break; fi
      echo "[demo] waiting for fake KMS at $KMS_ENDPOINT..."; sleep 2
    done
  fi
fi

case "${1:-serve}" in
  serve)
    shift || true
    exec keycensus serve -c "$CONFIG" --interval "$INTERVAL" --port "${KEYCENSUS_PORT:-9742}" "$@"
    ;;
  scan)
    shift || true
    exec keycensus scan -c "$CONFIG" -o "${KEYCENSUS_OUT:-/out}" "$@"
    ;;
  *)
    exec keycensus "$@"
    ;;
esac
