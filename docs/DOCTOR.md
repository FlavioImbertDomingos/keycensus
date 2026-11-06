# keycensus doctor

`keycensus doctor` explains a scan. For each source it says what the source reached, what it could not
reach and why, and what to change: the permission that is missing, the file in [`deploy/`](../deploy/README.md)
that grants it, or the option to fix.

```bash
keycensus doctor -c keycensus.yml                 # run the sources now, without writing reports
keycensus doctor -c keycensus.yml -s vault-prod   # one source (repeatable)
keycensus doctor -i out/inventory.json            # explain a scan that already ran, without scanning
keycensus doctor -c keycensus.yml --json          # for scripts
```

It exits 2 when a source failed and 6 when one was partial, the same codes as
`keycensus scan --require-complete`, so it can gate a pipeline as well as explain it.

## Example

Four sources, each with a different problem. This is the command's real output for that setup (a Vault
whose token cannot list one Transit mount or the ACL policies, an AWS account whose role lacks
`kms:ListGrants`, a certificate folder that is missing on the host, and an HSM client that is not
installed):

```text
4 source(s): 1 complete, 2 partial, 1 failed

vault-prod (vault): partial, 1 asset(s), 0.01s
  reached     mounts: 3 expected, 2 scanned, 1 denied
              items: 1 expected, 1 scanned
  denied      mounts: transit-payments
              GET transit-payments/keys -> 403: {"errors": ["1 error occurred: * permission denied
              "]}
              Assets in this part were not inventoried; ones seen before are carried forward as not
              observed and their findings stay open.
              fix: add list on <mount>/keys (Transit) or <mount>/certs (PKI), and read below it, for
              each mount listed
              file: deploy/vault/keycensus-policy.hcl
  optional    list sys/policies/acl
              denied 1 time(s)
              Policy consumers are missing from used_by.
              fix: add path "sys/policies/acl" { capabilities = ["list"] } to the keycensus policy
              file: deploy/vault/keycensus-policy.hcl

aws-prod (aws-kms): complete, 1 asset(s), 0.08s
  reached     accounts: 1 expected, 1 scanned
              keys: 1 expected, 1 scanned
              regions: 1 expected, 1 scanned
  optional    kms:ListGrants
              denied 1 time(s)
              Grants are missing from used_by.
              fix: grant kms:ListGrants to the scanner role (and in the member role for
              organization: true)
              file: deploy/aws/keycensus-scanner-policy.json

app-certs (pem): partial, 0 asset(s), 0s
  reached     paths: 2 expected, 1 scanned, 1 unavailable
  unavailable paths: /etc/pki/app
              does not exist
              Assets in this part were not inventoried; ones seen before are carried forward as not
              observed and their findings stay open.
              fix: the path does not exist on this host; fix it in paths:, or mount it into the
              container

luna-payments (pkcs11): failed, 0 asset(s), 0.01s
  failed      source
              PKCS11Error: OS exception while loading
              /usr/safenet/lunaclient/lib/libCryptoki2_64.so:
              /usr/safenet/lunaclient/lib/libCryptoki2_64.so: cannot open shared object file: No
              such file or directory
              The source produced nothing; its assets from earlier scans are carried forward as not
              observed and their findings stay open.
              fix: the PKCS#11 library in module: is not on this host; install the vendor client
              (Luna, nShield, CloudHSM) or fix the path

Files named above are in the keycensus repository: https://github.com/FlavioImbertDomingos/keycensus/tree/main/deploy

```

## What it reports

Every problem has one of three levels.

| Level | Means | Effect on the inventory |
|---|---|---|
| failed | The source produced nothing: bad credentials, no network path, a missing library or option. | Its assets from earlier scans are carried forward as not observed, and their findings stay open. |
| gap | Part of the source's scope was not scanned: a denied account, a missing export, a mount the token cannot list. The source is partial. | Assets that lived in that part are carried forward; assets in parts that were scanned are not. |
| optional | An optional read was denied. The scan is complete. | Some fields are missing, usually consumers (`used_by`) or rotation status. |

Remedies are kept honest by tests: every optional permission a collector records must have a remedy, the
text that remedy asks you to grant must appear in the `deploy/` file it names, and the shipped AWS policy
is run against moto's IAM evaluation to check that it leaves nothing to fix. CI also runs `doctor`
against the docker compose demo (a real Vault and SoftHSM), once with the demo token and once with a token
whose policy lacks one PKI path, and checks that it names that mount and the Vault policy file.

## What each source breaks down

| Source | Scopes |
|---|---|
| `aws-kms` | accounts, regions, keys; optional `kms:ListGrants`, `kms:GetKeyPolicy`, `kms:GetKeyRotationStatus`, `kms:ListResourceTags`, `ec2:DescribeRegions` |
| `azure-keyvault` | subscriptions, vaults; optional vault properties, role assignments, rotation policies |
| `gcp-kms` | projects, locations; optional `cloudkms.cryptoKeys.getIamPolicy` |
| `kubernetes` | namespaces (TLS and Opaque secrets), cert-manager; optional pods and ingresses |
| `vault` | mounts (each Transit and PKI mount), items (each key or certificate); optional ACL policy reads |
| `pkcs11` | tokens, objects (an object whose attributes cannot be read) |
| `adcs` | directory (the LDAP read), exports (each `certutil` export, and rows without a readable certificate) |
| `ciphertrust`, `keysafe5` | keys (the listing, including a page that fails part way or a listing cut off) |
| `files`, `pem` | paths, files |
| `ct` | domains |

The other sources (`tls`, `ssh`, `network`, `code`, `voltage`) are complete or failed. A failure still
gets a remedy.

## What it does not do

`doctor` does not change anything: it never edits a policy or applies a role. It cannot see a scope that
the source never learned about. A cloud account outside the organization, or a host that discovery did
not find, is not a gap. And it reads only what the collectors report, so a key that a permission hides
without an error (some HSMs return fewer objects instead of refusing) does not show up.
