#!/bin/sh
# First-run check for an installed keycensus (wheel or binary): version, init, scan, every report.
#   sh packaging/smoke.sh /path/to/keycensus
set -eu
KC="$1"
"$KC" --version
work=$(mktemp -d)
cd "$work"
mkdir certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/web.key -out certs/web.crt -days 30 -subj /CN=smoke 2>/dev/null
"$KC" init -s pem -y --no-scan
"$KC" scan -c keycensus.yml -o out -f json -f cbom -f csv -f html -f sarif
for f in inventory.json cbom.json inventory.csv report.html keycensus.sarif; do test -s "out/$f"; done
grep -q '"assets": 2' out/inventory.json
echo "smoke test passed in $work"
