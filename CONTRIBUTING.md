# Contributing

Most valuable contributions, in order:

1. **Redacted real-world samples**: a `/partitions` attribute dump from a Luna or nShield, a
   Voltage Management Console export, a KMS `DescribeKey` from a CloudHSM key store. These let
   us lock down field mappings against reality.
2. **New collectors**: Azure Key Vault / Managed HSM, Google Cloud KMS, CipherTrust Manager,
   KeySafe 5, Kubernetes secrets, JKS/PKCS#12 files.
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

- Every collector: a test with the backend mocked (or SoftHSM / moto where a real one is cheap).
- Every rule: a test in `tests/test_policy.py`, an entry in the default policy, a row in `docs/POLICY.md`.
- Every CBOM change: `tests/test_exporters.py::test_cbom_is_schema_valid` must still pass.
- No secrets in YAML, ever. `*_env` / `*_file` only.
- ruff (line length 120) for lint and format.
- Conventional-ish commits: `feat:`, `fix:`, `docs:`, `test:`, `ci:`.

Security issues: see [SECURITY.md](SECURITY.md), not public issues.
