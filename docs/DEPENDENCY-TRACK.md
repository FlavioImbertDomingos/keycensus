# Dependency-Track

[OWASP Dependency-Track](https://dependencytrack.org) ingests CycloneDX BOMs — since 4.11 including
the cryptographic assets keycensus emits. Uploading the CBOM there puts your HSM/KMS estate next to your
software BOMs: one project per estate or environment, a version per scan, Dependency-Track's own policy
engine, notifications and audit trail on top.

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

## What Dependency-Track shows

Each `cryptographic-asset` component appears with its algorithm properties (primitive, key size, curve,
mode, certification level, execution environment) exactly as in `cbom.json`; keycensus findings are
attached as `vulnerabilities` with the `keycensus` source, severity and the PCI DSS / NIST control ids
as references. Dependency-Track policies can then trigger on e.g. "any component with
`crypto:algorithm:primitive` = `block-cipher` and key size < 128".

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
