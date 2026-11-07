# The CBOM output

`cbom.json` is a CycloneDX document, 1.6 by default and 1.7 on request. CycloneDX is the OWASP
bill-of-materials standard; version 1.6 added cryptographic assets, and it is the version
Dependency-Track, IBM's CBOM tooling and most PQC-migration products read today. CI validates both
versions against the official JSON schemas (`tests/test_exporters.py`, `tests/test_cyclonedx17.py`).

```bash
keycensus scan -c keycensus.yml --cbom-version 1.7     # or in the config:  cbom: {version: "1.7"}
```

`serve` uses the config setting for `/cbom.json` and says the version in the content type.

## CycloneDX 1.7 and the Cryptography Registry

CycloneDX 1.7 names algorithms with the [Cryptography Registry](https://cyclonedx.org/registry/cryptography/):
a list of algorithm families (`RSAES-OAEP`, `ECDSA`, `AES`, `ML-KEM` ...), each with name patterns such as
`RSA-OAEP[-{hashAlgorithm}][-{keyLength}]`, and a list of elliptic curves (`nist/P-256`,
`brainpool/brainpoolP256r1`). keycensus ships a copy of the registry (`keycensus/data/cyclonedx/`, from
spec release 1.7.2) and normalises every algorithm with it (`keycensus/registry.py`).

What changes in 1.7 output:

| 1.6 | 1.7 |
|---|---|
| name `RSA-2048`, `AES-256`, `EC-P-256` | name from the registry pattern: `RSA-OAEP-SHA-256-3072`, `AES-256-GCM`, `ECDSA-P-256` |
| no family | `algorithmProperties.algorithmFamily`, a value of the registry's family enum |
| `curve: P-256` | `ellipticCurve: nist/P-256` |
| `algorithmRef`, `subjectPublicKeyRef`, `signatureAlgorithmRef` | `relatedCryptographicAssets: [{type, ref}]` with types `algorithm`, `publicKeyAlgorithm`, `signatureAlgorithm` |
| no `$schema` | `$schema` set to the 1.7 schema URL |

A family is only set when the source says enough to choose it. An RSA key is RSAES-OAEP, RSAES-PKCS1,
RSASSA-PKCS1 or RSASSA-PSS depending on the padding it is used with, which a key store does not record.
keycensus knows the scheme when code calls it (`RSA/ECB/OAEPWithSHA-256AndMGF1Padding`, `SHA256withRSA`,
Go's `rsa.SignPSS`, Python's `padding.OAEP`, .NET's `RSAEncryptionPadding`, WebCrypto's `RSA-OAEP`) and
for AWS KMS keys with `KeyUsage: ENCRYPT_DECRYPT`, which KMS only uses with OAEP. An EC key used for both
signing and key agreement, or with no recorded purpose, is likewise ECDSA or ECDH. In those cases the
component has no `algorithmFamily`, keeps the plain name (`RSA-2048`), and carries a
`keycensus:registryNote` property saying what was missing. Guessing would put a wrong family in a
document auditors rely on.

Every key, certificate, endpoint and code component has `group` set to the name of the source it came
from (from 0.16.0), so tools that identify components by group, name and version, Dependency-Track among
them, do not merge a key with an algorithm of the same name.

The 1.6 output is unchanged apart from three added properties, `keycensus:registryName`,
`keycensus:registryFamily` and `keycensus:registryNote`, so names and `bom-ref`s stay the same for anyone
already diffing 1.6 CBOMs.

## Mapping

| keycensus | CycloneDX component (`type: cryptographic-asset`) |
|---|---|
| key | `cryptoProperties.assetType: related-crypto-material` — `type` (secret-key / private-key / public-key), `id`, `state`, `creationDate`, `updateDate` (last rotation), `expirationDate`, `size`, `securedBy.mechanism` (HSM / Software), `algorithmRef` → algorithm component (1.7: `relatedCryptographicAssets`) |
| certificate | `assetType: certificate` — `subjectName`, `issuerName`, `notValidBefore/After`, `certificateFormat`, `signatureAlgorithmRef`, `subjectPublicKeyRef` (1.7: `relatedCryptographicAssets`) |
| TLS / SSH endpoint | `assetType: protocol` — `type: tls` or `ssh`, `version`, `cipherSuites[]`; as `properties`: legacy versions accepted, `keycensus:keyExchange` (the negotiated TLS 1.3 group or SSH kex), `keycensus:pqKeyExchangeSupported` (each post-quantum group the server accepts) and `keycensus:quantumClass` (`quantum-vulnerable`, `hybrid` or `quantum-safe`) |
| algorithm called by code (`code` collector) | `assetType: algorithm` with `mode` (ecb, cbc, gcm ...) and every call site as `evidence.occurrences[]`: `location` (file), `line`, `additionalContext` (the API and language). Properties `keycensus:occurrences`, `keycensus:repository`, `keycensus:onlyInTests` |
| hard-coded private key | as a key, plus `evidence.occurrences[]` with the file and line and `keycensus:hardcoded: true` |
| algorithm (derived, de-duplicated) | `assetType: algorithm` — `primitive`, `parameterSetIdentifier` (key size), `curve` (1.7: `algorithmFamily`, `ellipticCurve`), `executionEnvironment` (hardware / software-plain-ram), `cryptoFunctions`, `classicalSecurityLevel`, `nistQuantumSecurityLevel`, `certificationLevel` (fips140-3-l3 when known) |
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

**Dependency-Track:** `keycensus upload dtrack` (see [DEPENDENCY-TRACK.md](DEPENDENCY-TRACK.md)). Use
5.1 or later. Components, their `keycensus:*` properties and the dependency graph are kept;
`cryptoProperties` and the findings are not.

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

For a 1.7 file, load `tests/fixtures/cdx-1.7/bom-1.7.schema.json` and register
`cryptography-defs.schema.json`, `jsf-0.82.schema.json` and `spdx.schema.json` from the same folder under
both their bare names and `http://cyclonedx.org/schema/<name>`; `tests/test_cyclonedx17.py` does exactly
that.

The schema files under `tests/fixtures/` and the registry under `keycensus/data/cyclonedx/` are copies
of the official CycloneDX files (Apache-2.0).

## Federal CBOM guidance

US Executive Order 14412 (June 2026) directs NIST and CISA to write guidance for a cryptographic bill
of materials. It is not published yet. keycensus emits CycloneDX 1.6 or 1.7 `cryptographic-asset`
components, the format most CBOM tooling reads today; when the minimum elements are out, this page
will map each one to a field and list any gaps. See [PQC-TIMELINE.md](PQC-TIMELINE.md).
