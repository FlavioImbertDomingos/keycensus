# Observed use

The collectors report who is allowed to use a key: KMS grants and key policies, IAM bindings, Vault
policies, Key Vault RBAC (`used_by`, see [LINKING.md](LINKING.md)). You declare which application uses it
(`applications`). Neither says whether anyone did. The key stores log every cryptographic call, and keycensus
reads those logs and puts the answer on each key as `observed_use`, next to the other two and never mixed with
them.

| Evidence | Field | Answers |
|---|---|---|
| Authorisation, from the key store | `used_by` | Who may use the key |
| Declaration, from your config and SBOMs | `applications` | Which application says it uses the key |
| Audit log, from the key store | `observed_use` | Who called the key, how often, and when, in the window the log covers |

## Logs it reads

| Log | Calls counted | Matched to | Caller |
|---|---|---|---|
| AWS CloudTrail (the trail's S3 objects, gzipped or not) | KMS `Encrypt`, `Decrypt`, `ReEncrypt`, `GenerateDataKey*`, `Sign`, `Verify`, `GenerateMac`, `VerifyMac`, `DeriveSharedSecret` | `aws-kms` keys, by key ARN | the IAM role (not the session), user or AWS service; `via` when a service such as S3 called on the role's behalf |
| HashiCorp Vault file audit device | Transit `encrypt`, `decrypt`, `rewrap`, `sign`, `verify`, `hmac`, `datakey` responses | `vault` keys, by mount and key name | the token's display name, and its policies |
| Azure Key Vault `AuditEvent` diagnostic logs | `KeyEncrypt`, `KeyDecrypt`, `KeySign`, `KeyVerify`, `KeyWrap`, `KeyUnwrap` | `azure-keyvault` keys, by key id without version | the object id, with the UPN or app id next to it |
| Google Cloud Audit Logs, Data Access, `cloudkms.googleapis.com` | `Encrypt`, `Decrypt`, `AsymmetricSign`, `AsymmetricDecrypt`, `MacSign`, `MacVerify`, `RawEncrypt`, `RawDecrypt` | `gcp-kms` keys, by key name (any version) | the principal email |

Management calls (`DescribeKey`, `GetCryptoKey`, `KeyGet`, reading `transit/keys/...`) are not use and are
skipped. A refused call is counted apart, as `denied`.

## Configuration

```yaml
usage:
  window_days: 30                 # optional: only calls in the 30 days before the scan; default: the whole log
  logs:
    - type: cloudtrail
      path: logs/cloudtrail/      # a file, a directory (read recursively) or a glob
    - type: vault-audit
      path: /var/log/vault/audit.log
      sources: [vault-prod]       # optional: which sources this log belongs to; default: every source of its type
    - type: azure-keyvault
      path: logs/kv-prod/         # the PT1H.json files a diagnostic setting writes to a storage account
    - type: gcp-audit
      path: logs/gcp-kms.json     # gcloud logging read 'protoPayload.serviceName="cloudkms.googleapis.com"' --format=json
```

JSON, JSON lines and gzip all work. Relative paths resolve against the config file. `keycensus scan` reads
the logs after linking; a log that cannot be read is reported in the inventory and the report, and does not
stop the scan.

To read logs against a scan you already have, without rescanning:

```
keycensus usage -i out/inventory.json --log cloudtrail:logs/cloudtrail/ --log vault-audit:audit.log \
  --log azure-keyvault:logs/kv-prod/ --log gcp-audit:logs/gcp-kms.json -o out
keycensus usage -c keycensus.yml -i out/inventory.json --window-days 90 -o out
```

```
  AWS CloudTrail                    6 calls       5 matched  2026-11-01 to 2026-11-18
                               1 key(s) used but not in the inventory
  Vault audit device                4 calls       4 matched  2026-11-02 to 2026-11-18
  Azure Key Vault AuditEvent        3 calls       3 matched  2026-11-14 to 2026-11-18
  Google Cloud Audit Logs           3 calls       3 matched  2026-11-13 to 2026-11-18

7 key(s) covered by a log: 4 used, 3 not used in the window
```

## What a key gets

```json
"observed_use": {
  "logs": ["cloudtrail"],
  "window": {"from": "2026-11-01T08:00:00Z", "to": "2026-11-18T08:00:00Z"},
  "events": 5, "succeeded": 4, "denied": 1,
  "principals": [
    {"id": "arn:aws:iam::111122223333:role/payments-api", "log": "cloudtrail",
     "operations": {"Decrypt": 3, "GenerateDataKey": 1}, "events": 4, "denied": 0,
     "first_seen": "2026-11-01T08:00:00Z", "last_seen": "2026-11-18T08:00:00Z",
     "authorized": true, "via": ["s3.amazonaws.com"]},
    {"id": "arn:aws:iam::111122223333:user/jdoe", "log": "cloudtrail", "operations": {},
     "events": 1, "denied": 1, "authorized": false, "first_seen": "...", "last_seen": "..."}
  ],
  "authorized_not_seen": [{"id": "arn:aws:iam::111122223333:role/old-batch", "via": "key-policy:Allow"}]
}
```

That is from the recorded samples in `tests/fixtures/usage/`.

* `observed_use` is `null` when no log covers the key: its use is unknown, which is not the same as unused.
* A log covers a key when it holds calls from the key's scope: the AWS account and region, the Vault mount,
  the Key Vault, the GCP project. A covered key with no calls has an empty `principals` list.
* `authorized` compares the caller with `used_by`: the role or user ARN for AWS, the token's policies for
  Vault (a call is authorised when one of its policies is a policy that grants the key), the object id for
  Azure, the member for GCP. `null` means the collector recorded no consumers for that key, so there is
  nothing to compare with.
* `authorized_not_seen` lists the consumers `used_by` names that made no successful call in the window.

## Where it shows up

* `inventory.json`: `observed_use` on each key; a top-level `usage` block with each log's path, record and
  call counts, window, the scopes it covers, and the keys it saw used that are not in the inventory; the
  summary adds `assets_usage_covered`, `assets_used` and `assets_not_used` (all `null` when no log was read).
* The HTML report: "Observed use" with the logs and their windows, one row per key and caller with
  operations, refused calls, last call and whether the caller is authorised; "Authorised, not seen"; and
  "Covered, not used".
* A finding, `key-not-used` (info by default): an active key a log covers with no successful call in the
  window. Change its severity or turn it off in the policy like any other rule.
* The CBOM: properties `keycensus:observedUseWindow`, `keycensus:observedUseEvents`, one
  `keycensus:observedUse` per caller and one `keycensus:authorizedNotSeen` per unused consumer; the metadata
  names each log as `keycensus:auditLog:<type>`.
* `inventory.csv`: an `observed_use` column. Empty when no log covers the key, `none` when it is covered and
  unused, otherwise each caller with its number of calls.
* Prometheus: `keycensus_assets_usage_covered`, `keycensus_assets_not_used` and
  `keycensus_audit_log_calls{log,matched}`.

## Getting the logs

keycensus reads files and needs no extra permission on the key store. Someone has to produce the files:

| Log | What has to be on | What keycensus needs |
|---|---|---|
| CloudTrail | A trail in the account and region, with KMS events not excluded (trails log them unless "Exclude AWS KMS events" is set) | Read access to the trail's objects, copied down with `aws s3 sync` |
| Vault | A file audit device: `vault audit enable file file_path=/var/log/vault/audit.log` | Read access to the file. The audit device hashes tokens and request data; the path, display name and policies it records are plain |
| Azure Key Vault | A diagnostic setting sending the `AuditEvent` category to a storage account or Log Analytics | The exported JSON |
| Google Cloud | Data Access audit logs turned on for Cloud KMS (the cryptographic calls are `DATA_READ` entries) | `gcloud logging read` output, or a log sink to Cloud Storage |

## Limits

* The window is what the logs hold. A key used once a year (annual re-encryption, a disaster-recovery role)
  looks unused in a 30-day window. Judge `key-not-used` and `authorized_not_seen` against a window long enough
  for the key's job.
* AWS keys used through an IAM identity policy rather than the key policy or a grant show their callers as
  `authorized: false`: the collector reads key policies and grants, not every identity policy in the account.
* CloudTrail data events for other services are not needed and not read. Calls that KMS makes for itself
  (automatic rotation) are not use.
* Keys in other stores (PKCS#11, CipherTrust, KeySafe 5, files, certificates on TLS endpoints) have no log
  reader yet; their `observed_use` stays `null`.
* `keycensus diff` does not compare observed use between scans: call counts change every window. The current
  numbers are in every scan.
