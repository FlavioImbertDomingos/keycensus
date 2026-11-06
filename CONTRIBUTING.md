# Contributing

Most valuable contributions, in order:

1. **Redacted real-world samples**: a `/partitions` attribute dump from a Luna or nShield, a
   Voltage Management Console export, a KMS `DescribeKey` from a CloudHSM key store, the header
   row and one redacted row of a `certutil -view ... csv` export from an AD CS CA (especially a
   non-English one). These let us lock down field mappings against reality.
   Also useful: the `keycensus scan` output for a TLS endpoint behind your load balancer or CDN that
   negotiates X25519MLKEM768, and for an SSH server offering `mlkem768x25519-sha256`.
2. **Qualification runs** (see [docs/QUALIFICATION.md](docs/QUALIFICATION.md)): run a mock-tested
   collector (Azure, GCP, Kubernetes, CipherTrust, KeySafe 5, AD CS) against your real system and report
   what worked, what failed, and the coverage line it printed. That moves it from "implemented" to
   "integration-tested" or "field-validated".
3. Rules you wish existed, with the control they map to.

## Dev setup

```bash
git clone https://github.com/FlavioImbertDomingos/keycensus.git && cd keycensus
python -m venv .venv && source .venv/bin/activate
pip install -e ".[test]" ruff
sudo apt-get install softhsm2        # for the PKCS#11 tests (they skip if absent)
make test lint
```

Run the demo without Docker:

```bash
python demo/make_demo_certs.py demo/certs
export SOFTHSM2_CONF=demo/softhsm2.conf   # edit tokendir to somewhere writable
python demo/seed_softhsm.py
moto_server -p 5050 &  python demo/seed_kms.py --endpoint http://localhost:5050   # 5000 is AirPlay on macOS
python mock-voltage/app.py &
HSM_PIN=1234 VOLTAGE_PASSWORD=changeme AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  keycensus scan -c config/keycensus.demo.yml -o out   # adjust hostnames to localhost
```

## Rules of the road

- Every collector: a test with the backend mocked (or SoftHSM / moto where a real one is cheap), and a row
  in `docs/QUALIFICATION.md` that says honestly what it was tested against.
- A collector that walks several scopes (accounts, regions, namespaces) reports them with
  `self.coverage` and tags each asset's `extra.coverage_scope`, so a partial scan is never read as a
  complete one (see `keycensus/collectors/base.py`).
- Every rule: a test in `tests/test_policy.py`, an entry in the default policy, a row in `docs/POLICY.md`.
- Every CBOM change: `tests/test_exporters.py::test_cbom_is_schema_valid` must still pass.
- No secrets in YAML, ever. `*_env` / `*_file` only.
- ruff (line length 120) for lint and format.
- Conventional-ish commits: `feat:`, `fix:`, `docs:`, `test:`, `ci:`.

Security issues: see [SECURITY.md](SECURITY.md), not public issues.
