# SBOM ↔ CBOM linking — which application uses which key

A CBOM lists your cryptography. An SBOM lists your software. Neither answers the question that
matters at 2 a.m.: *this key is weak / expiring / compromised — which applications break?*
keycensus builds that edge and puts it in every output.

## Two kinds of evidence

**1. What the key store already knows (inferred, automatic).** Collectors record who is allowed to
use each key on `asset.used_by`:

| Source | Evidence | `via` |
|---|---|---|
| AWS KMS | grants (`GranteePrincipal`) and key-policy `Allow` principals (root and `*` excluded; `Service` principals kept) | `grant:<name>`, `key-policy:<sid>` |
| Google Cloud KMS | IAM bindings on the CryptoKey for crypto roles (`cryptoKeyEncrypterDecrypter`, `signerVerifier`, …) | `iam:<role>` |
| HashiCorp Vault | ACL policies granting `transit/<encrypt\|decrypt\|sign\|verify\|hmac\|keys\|…>/<key>` (exact or glob) | `vault-policy:<op>` |
| CipherTrust Manager | `application` and `owner` on the key | `ctm-application`, `ctm-owner` |

Each needs one extra read permission (`kms:ListGrants` + `kms:GetKeyPolicy`, `getIamPolicy`,
`sys/policies/acl`); when denied the collector carries on with an empty list. Turn off with
`include_consumers: false` / `include_iam: false` / `include_policies: false`.

**2. What you declare (config, optionally backed by SBOMs).**

```yaml
applications:
  - sbom: sboms/payments-api.cdx.json     # CycloneDX JSON; name/version/purl/bom-ref from metadata.component
    owner: payments-team                  # else metadata.component.supplier.name
  - sbom: sboms/batch-reporting.spdx.json # SPDX 2.2/2.3 JSON works too; identity from the DESCRIBES package
    uses:                                 # selectors: keys AND-ed inside one entry, entries OR-ed
      - {source: luna-payments, name: "pan-*"}
      - {source: aws-prod, tag: {app: payments}}
      - {principal: "arn:aws:iam::*:role/payments-api*"}     # glob over inferred used_by ids
      - {kind: certificate, name: "*.payments.example.com"}
  - name: auth-service                    # no SBOM yet: still worth declaring
    uses: [{source: vault-prod, name: "jwt-*"}]
  - name: batch-reporting                 # no selectors: relies on automatic matching
linking:
  auto_match: true                        # default
```

Selector keys: `source`, `source_type`, `name`, `native_id`, `id`, `kind`, `algorithm`, `tag`
(mapping, every pair must match), `principal` / `used_by` (glob over inferred consumer ids). Globs
are case-insensitive `fnmatch`.

**Automatic matching** links an asset to an application when an inferred consumer id contains the
application's name as a whole token — `arn:aws:iam::123:role/payments-api` ↔ `payments-api`, Vault
policy `batch_reporting` ↔ `batch-reporting`. It is how an application with an SBOM but no selectors
still gets its keys; disable it with `linking.auto_match: false` if your naming is not that tidy.

## What you get

* `inventory.json`: an `applications` list (name, version, purl, owner, SBOM serial, matched asset ids
  and *why* each matched) and `applications` / `used_by` on every asset; summary gains `applications`,
  `assets_linked`, `assets_unlinked`.
* `cbom.json`: one `application` component per application (bom-ref/purl from its SBOM, the SBOM
  referenced under `externalReferences[type=bom]`) with `dependencies[].dependsOn` → its crypto assets.
  Dependency-Track and any CycloneDX tool then show the graph; keys carry
  `keycensus:application` and `keycensus:usedBy:*` properties.
* `report.html`: an **Applications** table (linked assets, findings, worst severity — the blast
  radius) and a *Used by* column on every asset.
* `inventory.csv`: `applications` and `used_by` columns.
* Prometheus: `keycensus_application_assets{application,owner}`,
  `keycensus_application_worst_finding` (0 none … 5 critical), `keycensus_assets_unlinked`.
* Diff mode watches `applications` and `used_by`, so "this key gained a consumer" is a reported change.
* A finding, `unlinked-asset` (info by default), for every key/certificate no declared application
  claims — the orphan-key list an audit asks for. Only evaluated when `applications:` exist.

## Commands

```bash
keycensus scan -c keycensus.yml -o out                          # links during the scan
keycensus link -c keycensus.yml -i out/inventory.json -o out2   # re-link a saved scan (new SBOMs, no rescan)
keycensus link -c keycensus.yml -i out/inventory.json --sbom sboms/new-service.cdx.json -o out2
```

`link` is for the common case where SBOMs change every build and HSM scans happen nightly.

## SBOM formats

Both major formats are read, and the format never changes which keys an application links to — only
where the identity comes from.

| | CycloneDX JSON | SPDX 2.2 / 2.3 JSON |
|---|---|---|
| Application identity | `metadata.component` | the package the document **DESCRIBES** |
| name / version | `name`, `version` | `name`, `versionInfo` |
| purl | `purl` | `externalRefs` entry with `referenceType: purl` |
| owner | `supplier.name` | `supplier`, else `originator` — `"Organization: ACME (a@b)"` is unwrapped to `ACME` |
| ref | `bom-ref` | `SPDXID` |
| serial | `serialNumber` | `documentNamespace` |

The DESCRIBES relationship matters: an SPDX document's `name` is usually the *file*
(`payments-api-sbom`), and its first package is often a dependency. keycensus reads
`relationships` for `DESCRIBES`, falls back to the SPDX 2.2 `documentDescribes` shorthand, then to
the single package when a document has exactly one — and only then to the document name.

Anything you set explicitly in `applications:` still wins over the document, in both formats.

## Limits, honestly

* CycloneDX **JSON** and SPDX 2.2/2.3 **JSON** are read; XML and SPDX tag-value are not (convert with
  `syft convert` or `cyclonedx-cli`). Only the root component/package is used for identity; the rest
  are counted, not matched.
* Inferred consumers are *authorisations*, not observed use: a role that may use a key is listed
  whether or not it ever did. That is still what an auditor wants (least privilege), but it is not
  telemetry.
* PKCS#11 has no notion of a consumer; declare those keys explicitly.
