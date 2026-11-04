# The CBOM output

`cbom.json` is a **CycloneDX 1.6** document. CycloneDX is the OWASP bill-of-materials standard;
version 1.6 added *cryptographic assets* — the format is what Dependency-Track, IBM's CBOM tooling,
and most PQC-migration products ingest. keycensus validates its output against the official
JSON schema in CI (`tests/test_exporters.py`).

## Mapping

| keycensus | CycloneDX component (`type: cryptographic-asset`) |
|---|---|
| key | `cryptoProperties.assetType: related-crypto-material` — `type` (secret-key / private-key / public-key), `id`, `state`, `creationDate`, `updateDate` (last rotation), `expirationDate`, `size`, `securedBy.mechanism` (HSM / Software), `algorithmRef` → algorithm component |
| certificate | `assetType: certificate` — `subjectName`, `issuerName`, `notValidBefore/After`, `certificateFormat`, `signatureAlgorithmRef`, `subjectPublicKeyRef` |
| TLS / SSH endpoint | `assetType: protocol` — `type: tls` or `ssh`, `version`, `cipherSuites[]`; as `properties`: legacy versions accepted, `keycensus:keyExchange` (the negotiated TLS 1.3 group or SSH kex), `keycensus:pqKeyExchangeSupported` (each post-quantum group the server accepts) and `keycensus:quantumClass` (`quantum-vulnerable`, `hybrid` or `quantum-safe`) |
| algorithm (derived, de-duplicated) | `assetType: algorithm` — `primitive`, `parameterSetIdentifier` (key size), `curve`, `executionEnvironment` (hardware / software-plain-ram), `cryptoFunctions`, `classicalSecurityLevel`, `nistQuantumSecurityLevel`, `certificationLevel` (fips140-3-l3 when known) |
| finding | `vulnerabilities[]` — `id: KEYCENSUS-<RULE>`, `ratings[].severity`, `recommendation`, `affects[].ref`, control ids as `properties` |
| source | `metadata.properties` `keycensus:source:<name>` = ok / error |

Every key or certificate `dependsOn` its algorithm component, so "show me everything using
RSA-2048" is a graph query.

`bom-ref`s are stable across scans (`kc-<sha256(source|kind|native_id)[:12]>`), so two CBOMs
can be diffed.

## Extra properties

Anything CycloneDX has no field for is carried as `properties` with a `keycensus:` prefix:
`source`, `sourceType`, `quantumClass` (quantum-vulnerable / quantum-reduced / hybrid / quantum-safe),
`rotationEnabled`, `exportable`, `hardwareBacked`, `fipsValidated`, `signatureHash`,
`selfSigned`, `weakVersionsAccepted`; and your `tags:` as `tag:<key>`.

## Using it

**Dependency-Track:** upload as a project BOM (`POST /api/v1/bom`). Crypto assets appear in the
components view; vulnerabilities appear in the findings view with keycensus as the source.

**Diff two scans:**

```bash
jq -r '.components[] | select(.cryptoProperties.assetType!="algorithm") | ."bom-ref"' cbom-old.json | sort > a
jq -r '.components[] | select(.cryptoProperties.assetType!="algorithm") | ."bom-ref"' cbom-new.json | sort > b
comm -13 a b   # new assets
comm -23 a b   # gone
```

**Everything quantum-vulnerable that encrypts:**

```bash
jq '.vulnerabilities[] | select(.id=="KEYCENSUS-QUANTUM-VULNERABLE-ENCRYPTION") | .affects[].ref' cbom.json
```

**Which controls have findings:**

```bash
jq -r '.vulnerabilities[].properties[] | select(.name=="control") | .value' cbom.json | sort | uniq -c
```

## Validate it yourself

```bash
pip install jsonschema
python - <<'EOF'
import json
from jsonschema import Draft7Validator
from referencing import Registry, Resource
S = "tests/fixtures/"
schema = json.load(open(S + "bom-1.6.schema.json"))
reg = Registry().with_resources([
    ("jsf-0.82.SNAPSHOT.schema.json", Resource.from_contents(json.load(open(S + "jsf-0.82.schema.json")))),
    ("spdx.SNAPSHOT.schema.json", Resource.from_contents(json.load(open(S + "spdx.schema.json")))),
])
errors = list(Draft7Validator(schema, registry=reg).iter_errors(json.load(open("out/cbom.json"))))
print("schema errors:", len(errors))
EOF
```

The schema files under `tests/fixtures/` are copies of the official CycloneDX schemas
(Apache-2.0).

## Federal CBOM guidance

US Executive Order 14412 (June 2026) directs NIST and CISA to write guidance for a cryptographic bill
of materials. It is not published yet. keycensus emits CycloneDX 1.6 `cryptographic-asset`
components, the format most CBOM tooling reads today; when the minimum elements are out, this page
will map each one to a field and list any gaps. See [PQC-TIMELINE.md](PQC-TIMELINE.md).
