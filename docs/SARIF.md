# SARIF output

`-f sarif` writes `keycensus.sarif`, the findings in SARIF 2.1.0, the format GitHub code scanning, GitLab, Azure
DevOps, DefectDojo and the VS Code SARIF viewer read. `keycensus serve` also serves it at `/findings.sarif`
(token required, like the other reports).

```
keycensus scan -c keycensus.yml -o out -f json -f sarif
keycensus link -c keycensus.yml -i out/inventory.json -o out -f sarif
```

## What is in it

* One rule per finding type (`weak-hash`, `hardcoded-private-key`, `cert-expired`, ...), with the finding's title,
  its remediation as help text, and the controls it maps to as tags.
* One result per finding. The message is the finding's title and detail; `properties` carry the severity, the
  asset id, the source, whether the finding was re-verified in this scan, and the policy pack that produced it.
* Levels: critical and high are `error`, medium is `warning`, low and info are `note`. Rules also carry
  `security-severity` (critical 9.5, high 8.0, medium 5.5, low 2.0; info has none), which GitHub uses to label
  alerts critical, high, medium or low.
* `precision` is `medium` for rules whose findings all come from the `code` collector, which matches patterns
  and does not follow variables, and `high` otherwise.
* A partial fingerprint per result, from the rule and the asset id, so GitHub keeps one alert per finding from
  scan to scan instead of opening a new one each time.
* `automationDetails.id` is `keycensus/` for every scan, so a new policy pack version updates the same set of
  alerts rather than opening a second set.

## Locations

| Finding on | Location |
|---|---|
| A hard-coded key found by `code` | the file and line |
| An algorithm call found by `code` (`weak-hash`, `weak-cipher-mode`, ...) | every call site, file and line (up to 200 per algorithm, as the collector keeps them) |
| A key or certificate file found by `pem` or `files` | the file |
| A key in an HSM, a KMS, Vault, a TLS endpoint, Kubernetes, AD CS ... | a logical location: the asset name and `<source>/<native id>` |

Paths under the directory keycensus runs in are written relative to it; anything else is an absolute
`file://` URI. GitHub code scanning matches relative paths against the repository, so run the scan from the
repository root.

## GitHub code scanning

```yaml
name: crypto inventory
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  keycensus:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pipx install git+https://github.com/FlavioImbertDomingos/keycensus@v0.20.0
      - run: keycensus scan -c .keycensus.yml -o out -f sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: out/keycensus.sarif
          category: keycensus
```

With a config such as:

```yaml
sources:
  - name: repo
    type: code
    paths: ["."]
```

Code findings then show on the pull request diff and in the repository's Security tab. Pin the actions to a
commit in your own workflows, as keycensus's CI does.

## Limits

* GitHub shows an alert against a file. Findings with only a logical location (keys in an HSM or a KMS) are
  valid SARIF and other viewers list them, but GitHub code scanning is the wrong place for an estate-wide
  scan: use the HTML report, the CBOM or the ticket integrations for those, and SARIF for repositories.
* GitHub keeps the top 5,000 results per run. A large estate scan can exceed that; a repository scan will not.
* SARIF carries findings, not the inventory. Assets without findings are not in it.
