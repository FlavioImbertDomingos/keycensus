# Dependency-Track

[OWASP Dependency-Track](https://dependencytrack.org) can hold the CBOM next to your software BOMs: one
project per estate or environment, a version per scan. It keeps less of a CBOM than the CycloneDX file
does, and which version you run matters. The section below says what survives.

```bash
export DTRACK_API_KEY=...          # Team > API keys; needs BOM_UPLOAD (+ PROJECT_CREATION_UPLOAD to auto-create, VIEW_PORTFOLIO for the readback)
keycensus scan -c keycensus.yml -o out
keycensus upload dtrack --url https://dtrack.corp --project hsm-estate --version "$(date -u +%F)" --cbom out/cbom.json
```

Output:

```
uploaded out/cbom.json (token 3c1b…)
processed
https://dtrack.corp/projects/6f3a…
```

`--wait` (the default) fails when Dependency-Track reports that it could not process the BOM.

## What Dependency-Track keeps

The `dependency-track` CI job uploads a linked CBOM (certificates, keys, algorithms, two applications and
their findings) into a fresh Dependency-Track with `keycensus upload dtrack`, exports the project back as
CycloneDX and compares the two (`tests/integration/dtrack_roundtrip.py`). Each run writes the comparison
to the job summary.

| | Dependency-Track 5.1 | Dependency-Track 4.14 |
|---|---|---|
| `cryptographic-asset` components | kept, as type `cryptographic-asset` | not supported: 4.x has no component type for them, so the CBOM is not imported |
| Applications and `dependsOn` edges (application to key, certificate to algorithm) | kept | |
| `keycensus:*` properties (source, location, registry name ...) | kept | |
| `cryptoProperties` (algorithm, key size, curve, certificate dates, certification level) | not stored | |
| Findings (the CBOM's `vulnerabilities`) | not imported | |
| CycloneDX 1.7 | accepted (5.1.0 and later; also 4.14.4 and later, for the BOM format only) | |

The table comes from Dependency-Track's source code (5.1.2 and 4.14.6), and the CI job checks the 5.1
column on every push. Use Dependency-Track 5.1 or later for a CBOM.

Two consequences for how you use it:

* Dependency-Track identifies a component by group, name, version and package URL, and merges components
  that share them. keycensus sets `group` to the source name on every key, certificate, endpoint and code
  component, so a key named after its algorithm, or two keys with the same name in different sources,
  stay apart. Two keys with the same name in the same source are still merged. The shared algorithm
  components have no group; the only ones that can coincide are an EdDSA public-key algorithm and the same
  algorithm used to sign a certificate, which describe the same thing. The CI job fails if any asset
  component is merged.
* Dependency-Track computes findings from package URLs and its vulnerability feeds; it does not import
  findings embedded in a BOM. keycensus findings stay in the report, `inventory.json`, the CBOM file and
  `/metrics`.

## Options

| Flag | Default | Notes |
|---|---|---|
| `--url` | — | Dependency-Track API base (the UI URL works; `/api/v1/bom` is appended) |
| `--api-key-env` / `--api-key-file` | `DTRACK_API_KEY` | never on the command line |
| `--project` / `--version` | — | project name + version; `--auto-create` (default on) creates missing ones |
| `--project-uuid` | — | upload into an existing project by UUID instead |
| `--parent` / `--parent-version` | — | portfolio grouping, e.g. parent `crypto` |
| `--latest/--no-latest` | unset | mark this version as the project's latest |
| `--wait/--no-wait`, `--timeout` | wait, 120 s | poll `/api/v1/bom/token/<token>` until processed |
| `--insecure` | off | skip TLS verification (lab only) |

## In the Helm chart

```yaml
mode:
  scan:
    enabled: true
    dependencyTrack:
      enabled: true
      url: https://dtrack.corp
      apiKeySecret: keycensus-dtrack     # Secret with key DTRACK_API_KEY
      project: hsm-estate
      parent: crypto
      versionFromDate: true              # version = scan date
```
