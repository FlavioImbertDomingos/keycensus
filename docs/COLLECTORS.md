# Collectors

Each entry under `sources:` in the config has a `name` (your label, becomes the `source`
field on every asset), a `type` (one of the below), and type-specific options.
Secrets are always `*_env` (environment variable), `*_file` (path) or a secret store reference
(`*_vault`, `*_aws_secret`, `*_azure_secret`, `*_gcp_secret`; see [PERMISSIONS.md](PERMISSIONS.md)),
never inline. The permissions each source needs are in [PERMISSIONS.md](PERMISSIONS.md) and `deploy/`.

Every collector runs inside a try/except: one broken source is reported as `error`
in the output and the others still scan. `keycensus scan` exits `2` if any source failed.

## `pkcs11` — HSMs

Thales Luna, Entrust nShield, AWS CloudHSM (client SDK), Utimaco, Securosys, YubiHSM,
SoftHSM ... anything with a PKCS#11 library.

```yaml
- name: luna-payments
  type: pkcs11
  module: /usr/safenet/lunaclient/lib/libCryptoki2_64.so
  token_label: payments-partition   # or: slot: 0
  pin_env: LUNA_PIN_PAYMENTS        # or pin_file: /run/secrets/pin
  hardware_backed: true             # default true
  fips_validated: true              # optional, adds certificationLevel to the CBOM
  tags: {site: phx-dc1}
```

| Vendor | `module` (typical) |
|---|---|
| Thales Luna | `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` |
| Entrust nShield | `/opt/nfast/toolkits/pkcs11/libcknfast.so` |
| AWS CloudHSM | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` |
| Utimaco | `/opt/utimaco/lib/libcs_pkcs11_R3.so` |
| SoftHSM | `/usr/lib/softhsm/libsofthsm2.so` |

**Where to run it:** PKCS#11 is an in-process API, so keycensus must run on a host with the vendor
client installed and registered with the HSM — usually the same box that runs your application, or
a dedicated "crypto ops" host. Needs a Crypto User (read) role, not a Crypto Officer.

**What it reads:** `C_FindObjects` for secret/private/public keys and `C_GetAttributeValue` for
label, id, key type, size/modulus/curve, usage flags, extractable/sensitive, start/end dates.
It never calls `C_GetAttributeValue(CKA_VALUE)`, wrap, or export.

**Caveat:** PKCS#11 has no mandatory creation date. Unless your HSM sets `CKA_START_DATE`,
keys come back with `created: null` and a `no-creation-date` info finding. That is a real
inventory gap and worth fixing at the source (Luna: `partition showinfo`, nShield: `nfkminfo`
have dates the collector could be taught to merge — PRs welcome).

Requires `pip install "keycensus[pkcs11]"`.

## `vault` — HashiCorp Vault

Transit keys and PKI-issued certificates.

```yaml
- name: vault-prod
  type: vault
  url: https://vault.example.com:8200
  token_env: VAULT_TOKEN
  namespace: payments                 # Enterprise, optional
  transit_mounts: [transit]           # default: discover via sys/mounts
  pki_mounts: [pki_int]               # default: discover
  verify_tls: /config/corp-ca.pem     # true | false | CA path
  hardware_backed: false              # true if Transit uses Managed Keys / HSM seal
```

Token policy needed:

```hcl
path "sys/mounts"             { capabilities = ["read"] }
path "transit/keys"           { capabilities = ["list"] }
path "transit/keys/*"         { capabilities = ["read"] }
path "pki/certs"              { capabilities = ["list"] }
path "pki/cert/*"             { capabilities = ["read"] }
```

Reads: key type, every version's creation time (oldest = `created`, newest = `last_rotated`),
`auto_rotate_period` (→ `rotation_enabled`), `exportable`, supported operations.

## `aws-kms` — AWS KMS

```yaml
- name: aws-prod
  type: aws-kms
  region: us-east-1
  profile: prod                   # optional; default boto3 credential chain
  endpoint_url: http://kms:5000   # only for moto / LocalStack
  include_aws_managed: false      # aws/* keys
  include_pending_deletion: true
```

IAM: `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyRotationStatus`, `kms:ListAliases`,
`kms:ListResourceTags`. Reads spec, usage, state, origin (→ `exportable` for EXTERNAL,
`hardware_backed` for CloudHSM key stores), creation date, rotation status, tags.
AWS-managed KMS is FIPS 140-3 L3 validated, so `fips_validated: true` is set automatically.

Requires `pip install "keycensus[aws]"`.

### Every account and region

```yaml
- name: aws-org
  type: aws-kms
  regions: all                      # or [us-east-1, eu-west-1]; "all" = every region enabled in the account
  organization: true                # every ACTIVE account in the AWS Organization
  member_role: KeycensusReadOnly    # assumed in each member account
  # accounts: [111111111111]        # only these
  # exclude_accounts: [222222222222]
  # external_id_env: KC_EXTERNAL_ID # if the member role requires sts:ExternalId
```

Run it from the management account or a delegated administrator. It calls `organizations:ListAccounts`,
then `sts:AssumeRole` into `arn:aws:iam::<account>:role/<member_role>` in each member account; its own
account is scanned with its own credentials. Deploy the member role everywhere with a CloudFormation
StackSet, granting only the KMS read actions above. `regions: all` uses `ec2:DescribeRegions` to list
the regions enabled in each account and falls back to botocore's KMS region list if that is denied.

Every asset gets `extra.account_id` and `extra.region`. An account whose role is missing, or a region
that is disabled, is logged and skipped; the source is marked failed only when every account and
region failed, so one forgotten account does not hide the other forty.

## `voltage` — OpenText Voltage SecureData

Voltage does not expose a public inventory API; feed keycensus an **export**.

```yaml
- name: voltage
  type: voltage
  file: /exports/voltage-keys.csv          # or url: https://...  (+ username / password_env)
  hardware_backed: true
  field_map:                               # rename your columns → ours
    name: KeyName
    identity: Identity
    district: District
    algorithm: Algorithm
    purpose: Usage
    created: CreatedDate
    rotated: LastRotation
    state: Status
    exportable: Exportable
```

Canonical fields: `key_id, name, identity, district, algorithm, purpose, created, rotated,
expires, state, exportable, auto_rotate, hsm_backed`. Algorithm strings such as
`FF1-AES-256`, `AES256`, `3DES`, `RSA-2048`, `SHA-256 HMAC` are normalised (FPE mode is kept
in `extra.fpe_mode`). States `active|enabled|current` → active; `retired|disabled|inactive|deprecated`
→ deactivated.

The demo's `mock-voltage/` serves this shape over HTTP and CSV.

## `azure-keyvault` — Azure Key Vault and Managed HSM

```yaml
- name: kv-payments
  type: azure-keyvault
  vault_url: https://payments-kv.vault.azure.net        # or https://<name>.managedhsm.azure.net
  auth: default                                         # DefaultAzureCredential: managed/workload identity, az login, SP env vars
  # auth: token + token_env: AZURE_TOKEN                # a raw bearer token (CI: az account get-access-token --resource https://vault.azure.net)
  include_certificates: true
  include_disabled: true

  # Consumers -- see "Azure RBAC consumers" below
  include_rbac: true
  subscription_id: 00000000-0000-0000-0000-000000000000   # or resource_id, to skip the lookup
  # arm_token_env: AZURE_ARM_TOKEN                        # only with auth: token
  resolve_principal_names: false
```

**Permissions:** `keys/list`, `keys/get`, `keys/getrotationpolicy`, `certificates/list`,
`certificates/get` (Key Vault "Reader"-style access policy or the *Key Vault Crypto User* + *Key Vault
Certificate User* RBAC roles); on Managed HSM the *Managed HSM Crypto Auditor* role. Requires
`pip install "keycensus[azure]"` for `auth: default`; `auth: token` needs nothing extra.

**What maps:** `kty` (`RSA`, `RSA-HSM`, `EC`, `EC-HSM`, `oct`, `oct-HSM`) → algorithm and `hardware_backed`
(everything on a Managed HSM is hardware-backed and FIPS 140-3 L3); `crv` → curve; the RSA modulus length →
`key_size`; `key_ops` → purposes; `attributes.exp/nbf/enabled/created/exportable/recoveryLevel`; the rotation
policy (`lifetimeActions` with a `Rotate` action) → `rotation_enabled`. Certificates are parsed from `cer`
(the public part) and carry the issuer provider and the backing key's `kty`. Asset ids are version-less, so a
rotation shows up as `last_rotated` changing in diff mode rather than as a new asset.

### Every subscription

```yaml
- name: azure-all
  type: azure-keyvault
  discover: true                      # instead of vault_url
  # subscriptions: [00000000-...]     # only these; default: every Enabled subscription you can see
  # exclude_vaults: [sandbox-kv]
  # vault_dns_suffix: vault.azure.net             # sovereign clouds: vault.usgovcloudapi.net, vault.azure.cn
  # managed_hsm_dns_suffix: managedhsm.azure.net
```

Lists subscriptions (`GET /subscriptions`), then every `Microsoft.KeyVault/vaults` and
`Microsoft.KeyVault/managedHSMs` resource in each, and scans each vault as if it had its own entry, with
its ARM id already known (so RBAC consumers need no extra lookup). The identity needs *Reader* on the
subscriptions, simplest at a management group, plus the data-plane roles above on each vault. Assets get
`extra.subscription_id`, `extra.resource_group` and `extra.vault`. A vault it cannot read is logged and
skipped; the source fails only if every vault fails. Use `auth: default`: `auth: token` carries one
data-plane token, and Key Vault and Managed HSM need different audiences.

### Azure RBAC consumers

`include_rbac` (default on) fills in `used_by` — who is authorised to *use* these keys. Azure has three
authorization models and the collector reads whichever the vault actually uses:

| Vault | Where the answer lives | Extra permission | Extra token |
|---|---|---|---|
| RBAC vault (`enableRbacAuthorization: true`) | ARM role assignments at the vault scope | `Microsoft.Authorization/roleAssignments/read` + `Microsoft.KeyVault/vaults/read` (built-in **Reader** covers both) | management plane |
| Access-policy vault (the older model) | `properties.accessPolicies` on the vault resource | `Microsoft.KeyVault/vaults/read` | management plane |
| Managed HSM | the HSM's own data plane, local RBAC | none beyond listing keys | none |

Two things to know before you turn it on:

- **The management plane is a different endpoint and a different token audience.** With
  `auth: default` the credential chain handles it. With `auth: token` you must supply
  `arm_token_env` as well — one bearer token is never valid for two audiences:
  ```bash
  export AZURE_TOKEN=$(az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)
  export AZURE_ARM_TOKEN=$(az account get-access-token --resource https://management.azure.com --query accessToken -o tsv)
  ```
- **Azure authorizes at the vault scope, not per key.** So every asset in a vault carries the same
  `used_by` list. AWS grants and GCP IAM bindings are per key; pretending Azure is too would invent
  precision the platform does not have.

Roles that only *list* — *Key Vault Reader*, *Managed HSM Crypto Auditor* — are deliberately not
consumers: they can see that a key exists, not use it.

Principals come back as object ids (GUIDs); ARM does not resolve names. `resolve_principal_names: true`
looks them up in Microsoft Graph, which needs `Directory.Read.All` — a much larger permission than
reading an inventory, so it is off by default. GUIDs still link through an explicit
`{principal: "..."}` selector; automatic name matching needs the names.

A 403 anywhere in this path is logged and tolerated. No consumer information is worse than no inventory.

## `gcp-kms` — Google Cloud KMS

```yaml
- name: gcp-payments
  type: gcp-kms
  project: acme-payments-prod
  locations: [global, us-east1]        # default: every location in the project
  auth: default                        # Application Default Credentials (workload identity, SA JSON, gcloud)
  # auth: token + token_env: GCP_TOKEN # gcloud auth print-access-token
  include_destroyed: false
```

**Permissions:** `roles/cloudkms.viewer` on the project. Requires `pip install "keycensus[gcp]"` for
`auth: default`.

**What maps:** one asset per **CryptoKey**, described by its primary version: `algorithm`
(`GOOGLE_SYMMETRIC_ENCRYPTION`, `RSA_SIGN_PSS_3072_SHA256`, `EC_SIGN_P256_SHA256`, `HMAC_SHA256`,
`PQ_SIGN_ML_DSA_65` …) → algorithm/size/curve/hash; `protectionLevel` `HSM` → `hardware_backed` +
`fips_validated`, `EXTERNAL*` → `exportable` (the material lives outside Google); `rotationPeriod` →
`rotation_enabled` (symmetric keys only — GCP has no auto-rotation for asymmetric keys, so those are `null`);
`primary.createTime` → `last_rotated`; version counts and states, `nextRotationTime`, import jobs and the
external key URI go to `extra`. Keys whose versions are all destroyed are skipped unless `include_destroyed`.

### Every project

```yaml
- name: gcp-all
  type: gcp-kms
  discover: true                                 # instead of project
  # project_query: "parent:folders/123456789"    # Cloud Resource Manager search filter
  # projects: [acme-payments-prod, acme-core]    # or an explicit list
  # exclude_projects: [acme-sandbox]
```

Calls Cloud Resource Manager `projects:search` for every ACTIVE project the identity can see, narrowed by
`project_query` if set, and scans each. Grant `roles/browser` and `roles/cloudkms.viewer` at the
organization or folder. Projects where the Cloud KMS API was never enabled hold no keys and are skipped
quietly; any other failure is logged and skipped, and the source fails only if every project fails.
Assets get `extra.project`.

## `ciphertrust` — Thales CipherTrust Manager

Beyond PKCS#11: the CM key vault as CM itself sees it — every key, its state, usage mask and lifecycle
dates — over the REST API, without a KMIP/PKCS#11 client.

```yaml
- name: ctm-prod
  type: ciphertrust
  url: https://ctm.corp
  username: keycensus
  password_env: CTM_PASSWORD
  domain: payments                     # optional CM domain
  # jwt_env: CTM_JWT                   # or a pre-issued JWT / API token
  verify_tls: /etc/ssl/certs/corp-ca.pem
  hardware_backed: true                # the domain is HSM-anchored (Luna / nShield root of trust)
  include_public_keys: false
  include_destroyed: false
```

**Permissions:** a user in a group with read access to keys (the built-in *Key Users* / *Key Admins* or a
custom group with `ReadKey`). Only `GET /api/v1/vault/keys2` metadata is read; nothing is exported.

**What maps:** `algorithm` + `size` + `curveid` → algorithm/size/curve (AES, TDES → 3DES, RSA, EC with
prime256v1 / secp384r1 / brainpool / ed25519, HMAC-SHA*, ML-DSA/ML-KEM); `usageMask` bits → purposes;
`state` → `Pre-Active` / `Active` / `Deactivated` / `Compromised` / `Destroyed`; `createdAt`,
`deactivationDate` → created / expires; `unexportable` → `exportable`; `objectType` → key vs certificate;
`labels` → tags; `meta` → extra (a `rotation*` key there sets `rotation_enabled`).

## `keysafe5` — Entrust KeySafe 5 (nShield)

Beyond PKCS#11: the whole nShield estate from KeySafe 5's management API — every application key in the
Security World, how it is protected (module / softcard / OCS card set), and which HSMs (ESNs) hold it.

```yaml
- name: nshield-estate
  type: keysafe5
  url: https://keysafe5.corp
  auth: bearer                         # OIDC / API token
  token_env: KS5_TOKEN
  # auth: basic + username + password_env
  verify_tls: /etc/ssl/certs/corp-ca.pem
  keys_path: /km/v1/keys               # default; /mgmt/v1/keys is tried on 404
  hsms_path: /mgmt/v1/hsms             # optional HSM inventory (model, firmware) merged into extra
  field_map: {}                        # rename fields if your KeySafe 5 version differs
```

**What maps:** nShield key types (`RSAPrivate`, `ECDSAPrivate`, `ECDHPublic`, `Rijndael` = AES, `DES3`,
`HMACSHA256`, `Ed25519`, `MLDSA65`, `Wrapped` …) → algorithm/size/curve/key type; `protection` and the
cardset / softcard name → `extra.protection` / `extra.protector`; `hsmESNs` → `extra.hsm_esns` (+ model and
firmware when `hsms_path` answers). Every Security World key is `hardware_backed` and `fips_validated`
by default (nShield modules are FIPS 140-3 validated) — set the options to false for softcard keys if your
auditor disagrees.

**Honesty:** the collector was written from the KeySafe 5 REST API reference and tested against a mock. Field
names are matched tolerantly (see the module docstring for the accepted names) and `field_map` covers the
rest; a redacted real `GET keys` response in an issue is the fastest way to make the defaults right.

## `adcs` — Microsoft Active Directory Certificate Services

AD CS keeps its inventory in two places, and the collector reads either or both.

**Active Directory, over LDAP.** The forest's configuration partition holds the Public Key
Services container: every enterprise CA's certificate (`Enrollment Services`), the trusted roots
(`Certification Authorities`), the `NTAuthCertificates` store, the `AIA` store, and every
certificate template with its key-size, validity and private-key settings. Any authenticated
domain account can read it. Nothing on the CA servers is touched.

**The CA database, from an export.** The certificates a CA has issued live in its own database.
The only remote interface to it is DCOM (ICertView), which does not work from Linux, so the CA
exports it with `certutil` and keycensus reads the CSV, the same pattern as the `voltage` collector.

```yaml
- name: corp-pki
  type: adcs

  # Active Directory
  ldap_url: ldaps://dc01.corp.example.com        # ldaps://, or ldap:// with start_tls: true
  auth: simple                                   # simple | kerberos
  username: svc-keycensus@corp.example.com       # UPN or bind DN
  password_env: ADCS_LDAP_PASSWORD               # or password_file
  verify_tls: /config/corp-root-ca.pem           # true | false | CA bundle path
  # config_dn: CN=Configuration,DC=corp,DC=example,DC=com   # default: read from the rootDSE
  include_templates: true

  # CA database exports, one per CA
  exports:
    - /exports/corp-issuing-ca1.csv              # CA name defaults to the file name
    - {file: /exports/ca2.csv, ca: CORP-ISSUING-CA2}
  include_expired: false
  include_revoked: false
  # field_map: {certificate: "Binary Certificate"}   # only if your header is not recognised
  ca_hardware_backed: true                       # optional, see below
```

Run on each CA to produce the export (read-only; needs *Read* on the CA, which CA administrators
and local administrators have):

```bat
certutil -view -restrict "Disposition=20" ^
  -out "RequestID,RequesterName,CertificateTemplate,SerialNumber,NotAfter,RawCertificate" ^
  csv > corp-issuing-ca1.csv
```

To include revoked certificates, use `-restrict "Disposition>=20,Disposition<=21"`, add
`Disposition,RevokedWhen` to `-out`, and set `include_revoked: true`. Schedule it with Task
Scheduler and copy the file to wherever keycensus runs.

**Permissions.** LDAP: any domain user; give keycensus its own account with no other rights.
Simple binds are refused over plain `ldap://` because the password would cross the network in
clear text; use `ldaps://`, `start_tls: true`, or `auth: kerberos` (run `kinit` first and install
`keycensus[adcs-kerberos]`). The export: CA *Read*, on the CA, by whoever runs `certutil`.

**What maps to what.**

* CA certificates from LDAP become `certificate` assets. The same certificate usually appears in
  several stores (a root is in `Certification Authorities` and `AIA`, an issuing CA in
  `Enrollment Services` and `NTAuthCertificates`); it is one asset with `extra.stores` listing
  all of them. An enterprise CA's asset is named after the CA and carries `extra.ca_host` and
  `extra.templates`.
* `extra.templates` has one entry per template the CA publishes: `key_algorithm` (RSA, or EC
  from a v3+ template's CNG settings), `min_key_size` (`msPKI-Minimal-Key-Size`), `validity_days`
  (`pKIExpirationPeriod`), `hash_algorithm`, `exportable_key` (`CT_FLAG_EXPORTABLE_KEY`),
  `key_archival`, `enrollee_supplies_subject`, EKUs and the template OID.
* Issued certificates from an export become `certificate` assets. Everything cryptographic
  (algorithm, size, expiry, signature hash) comes from the certificate itself, never from the
  other columns. `extra` keeps `ca`, `request_id`, `requester`, `template` and `revoked`.
  When LDAP is configured too, template OIDs in the export are resolved to template names.
* The requester (the account that enrolled and holds the private key) goes into `used_by` with
  `via: enrollment`, so `principal:` selectors in `applications:` can match `CORP\web01$`.
* Revoked certificates (with `include_revoked`) get state `deactivated`.

**Findings this source adds.** Issued and CA certificates go through the same rules as any other
certificate (`weak-key-size`, `deprecated-signature-hash`, expiry, `quantum-vulnerable`). One rule
is specific to AD CS: `adcs-template-weak-key-size` fires on a CA that publishes a template whose
minimum key size is below the strong-cryptography floor, because that CA will keep issuing weak
certificates until the template changes. CA certificates are exempt from `cert-long-validity`,
since a CA is meant to outlive what it issues.

**What it does not read.**

* The CA's own configuration in the registry (CA signing hash, CSP/KSP, whether the CA key is
  in an HSM). LDAP cannot see it, so `hardware_backed` is unknown unless you set
  `ca_hardware_backed`. If the CA keys are in a Luna or nShield, the `pkcs11` collector on the
  CA's HSM partition gives you the key side.
* Archived private keys. The export command above does not ask for them and the collector would
  ignore them.
* Certificates published to user or computer objects (`userCertificate`), and certificates in
  endpoint certificate stores. Use the `pem` and `tls` collectors for what is deployed.
* AD CS attack paths (the "ESC" family: enrollment rights, `EDITF_ATTRIBUTESUBJECTALTNAME2`,
  web enrollment relays, ACLs on templates). The template flags above are recorded because they
  are crypto settings, but deciding exploitability needs enrollment ACLs and CA flags keycensus
  does not read. Use a tool built for it, such as Locksmith, PSPKIAudit or Certipy.

**Honesty.** The LDAP side is tested against ldap3's in-memory directory with the real attribute
names and encodings (`cACertificate`, `pKIExpirationPeriod`, `msPKI-*`); the export side against
CSVs shaped like `certutil -view ... csv` output (UTF-16, PEM in quoted cells, `EMPTY` for nulls,
English display-name headers). Neither has run against a live forest or CA yet. Headers are
localised on non-English Windows; schema names and English display names are recognised, and
`field_map` covers the rest. A redacted export header from a real CA in an issue is the fastest
way to widen the defaults.

Requires `pip install "keycensus[adcs]"` (ldap3) for the LDAP side. Exports need no extra.

## `files` (or `pem`) — certificates, keys, keystores and SSH keys on disk

```yaml
- name: app-certs
  type: files                      # `pem` is the same collector
  paths: [/etc/ssl/app, /opt/kafka/config, /etc/ssh, /home]
  recursive: true
  # patterns: [...]                # default: PEM/DER extensions, *.p12 *.pfx *.jks *.jceks *.keystore
  #                                # *.truststore, id_*, *-cert.pub, authorized_keys, known_hosts, ssh_host_*_key
  keystore_passwords:              # tried on PKCS#12, JKS/JCEKS and encrypted PEM keys, then the well-known ones
    - password_env: KAFKA_KEYSTORE_PASSWORD
    - password_vault: secret/data/keystores#payments
  max_file_bytes: 10000000
```

| Format | What is read | Needs the password? |
|---|---|---|
| PEM, DER | Certificates (expiry, signature hash, SANs, CA flag), private keys, public keys. Encrypted PEM keys are opened with the configured passwords, else reported with the algorithm from the PEM label | Only for encrypted keys |
| PKCS#12 (.p12, .pfx) | The protection (cipher, MAC, iterations) without a password; the key and certificates with one | For the contents |
| JKS, JCEKS | Every entry: private keys with their certificate chains (stored unencrypted), trusted certificates, JCEKS secret keys (algorithm hidden), entry dates, key protection algorithm | No. The password is only used to check the integrity digest |
| OpenSSH private key | Algorithm, size, cipher and bcrypt rounds, whether a passphrase protects it | No |
| `*.pub`, `authorized_keys`, `known_hosts` | Every key, with options, host patterns (hashed ones as `(hashed)`) and `@cert-authority` markers | No |
| OpenSSH certificates (`*-cert.pub`) | Principals, user or host, validity, the signing CA's fingerprint | No |

Private keys become `key` assets marked `exportable: true`, `hardware_backed: false`, `created: null`:
a private key in a file with no register entry is what an inventory should surface. JKS records when each
entry was added, so those keys have a creation date. SSH keys carry `extra.ssh_role` (`host-key`,
`user-key`, `authorized-key`, `known-host`) and `extra.ssh_fingerprint` in `ssh-keygen -l` form; FIDO keys
(`sk-*`) are `hardware_backed: true`.

`keystore-weak-protection` (medium) fires for a keystore that is JKS or JCEKS (proprietary, SHA-1 based key
protection), legacy PKCS#12 (RC2-40, 3DES, SHA-1 MAC), opens with an empty password, or opens with a
well-known one (`changeit`, `changeme`, `password`, `secret`, `123456`). A PKCS#12 file whose password is
not configured is still reported, as a locked keystore, with its protection. Key material is never stored.

## `tls` — live endpoints

```yaml
- name: edges
  type: tls
  endpoints:
    - api.example.com:443
    - 10.0.0.5:8443
    - ldap://dc01.corp.example.com       # LDAP StartTLS, port 389 unless given
    - ldaps://dc01.corp.example.com      # LDAP over TLS, port 636 unless given
  timeout: 5
  probe_legacy: true      # also attempt TLS 1.0 / 1.1 handshakes
  probe_pqc: true         # TLS 1.3 key exchange group: classical, hybrid or ML-KEM
```

One `protocol` asset per endpoint (negotiated version, cipher suite, legacy versions the server
*also* accepts, key exchange group) plus one `certificate` asset for the leaf. Verification is disabled
on purpose — we inventory, we don't trust. `probe_legacy` needs an OpenSSL that can still speak TLS 1.0
(`@SECLEVEL=0`); if it can't, legacy versions are reported as not accepted.

For `ldap://` endpoints every connection first sends the LDAP StartTLS extended request (RFC 4511, OID
1.3.6.1.4.1.1466.20037), before any bind and with no credentials, then runs the same handshake, legacy and
key exchange probes over the upgraded connection. The asset is still `protocol: TLS`, with
`extra.starttls: ldap`. Tested against OpenLDAP `slapd`.

### Key exchange: classical, hybrid or ML-KEM

Python's `ssl` module cannot report the negotiated TLS group on most installed OpenSSL versions, and
cannot offer ML-KEM before OpenSSL 3.5. So for TLS 1.3 endpoints keycensus sends its own ClientHello and
reads the server's first reply, which in TLS 1.3 is unencrypted and names the chosen group. It never
finishes the handshake. The ML-KEM keys it offers are well-formed but random, so no keys are shared and
nothing is decrypted. Two probes:

* **preference**: offers what browsers offer (X25519MLKEM768, then X25519, P-256, P-384). The group the
  server picks becomes `key_exchange` on the asset: what real clients get today.
* **support**: offers only post-quantum groups (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024,
  MLKEM512/768/1024, and the obsolete X25519Kyber768Draft00), removing each one the server picks, until
  it refuses. The list goes to `extra.key_exchange.pq_supported`.

| `key_exchange` | Class | Finding |
|---|---|---|
| x25519, secp256r1, secp384r1, ffdhe… | `quantum-vulnerable` | `quantum-vulnerable-key-exchange` (medium). If `pq_supported` is not empty, the remediation says so: the fix is the server's preference order, not an upgrade |
| X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 | `hybrid` | `hybrid-key-exchange` (info): allowed by NIST IR 8547, but temporary |
| X25519Kyber768Draft00 | `hybrid` | `hybrid-key-exchange`, noting the post-quantum half is pre-FIPS 203 Kyber |
| MLKEM512, MLKEM768, MLKEM1024 | `quantum-safe` | none |

TLS 1.2-only endpoints are not probed (TLS 1.2 has no hybrid groups); `key_exchange` stays empty. An
endpoint that moves from hybrid back to classical between scans raises the `pq-key-exchange-lost` change,
which pages by default. Tested against OpenSSL 3.5 (Node 22) and Go 1.24 TLS servers. A TLS-intercepting
proxy between keycensus and the endpoint answers for it, so scan from inside the network you are measuring.

## `ssh` — SSH servers

```yaml
- name: bastions
  type: ssh
  endpoints: ["bastion.example.com", "10.0.0.7:2222"]   # port defaults to 22
  timeout: 5
```

An SSH server sends its banner and its list of algorithms (KEXINIT) in the clear before any login. The
collector reads exactly that and disconnects: no authentication, no key exchange. One `protocol` asset
per endpoint, with `extra.ssh` holding the offered key exchange, host key, cipher and MAC algorithms.
`key_exchange` is what a current OpenSSH client would negotiate (the first algorithm in OpenSSH 10's
default order that the server offers), so a server offering `mlkem768x25519-sha256` (OpenSSH 9.9+) or
`sntrup761x25519-sha512` (OpenSSH 9.0+) is `hybrid`; NTRU Prime is noted as not a NIST algorithm.

Findings: `quantum-vulnerable-key-exchange` / `hybrid-key-exchange` as for TLS, and `ssh-weak-algorithm`
(high) when the server offers SHA-1 key exchange or `ssh-rsa` signatures, DSA, CBC/RC4/3DES/Blowfish
ciphers, or MD5 / truncated SHA-1 MACs. The host key itself is not read (that needs a completed key
exchange), only the host key algorithms offered.

## `network` — discovery

```yaml
- name: dc-east
  type: network
  cidrs: [10.20.0.0/22, 10.20.8.15]
  exclude: [10.20.1.0/28]          # never touched, not even a TCP connect
  ports: {443: tls, 8443: tls, 389: ldap-starttls, 636: ldaps, 3269: ldaps, 22: ssh}   # the default
  connect_timeout: 1.0
  timeout: 5
  concurrency: 64
  max_hosts: 4096                  # larger ranges are refused unless you raise this
  allow_public: false              # public addresses are refused unless you set this
  probe_legacy: false
  probe_pqc: true
  resolve_names: false             # reverse DNS for each endpoint found
```

Finds endpoints nobody listed. First a plain TCP connect to every host and port in range (no raw packets,
no root, no SYN scan), then a probe on each open port: `tls` and `ldaps` get the `tls` collector's
handshake and key exchange probe (a `protocol` asset and the leaf `certificate`), `ssh` gets the `ssh`
collector's KEXINIT read. `ldap-starttls` (389) sends the LDAP StartTLS request first, then runs the TLS
probes. Every asset carries `extra.service` and `extra.discovered_by: network`. A port that is open but does
not speak the expected protocol is logged and skipped.

An LDAP server that answers but refuses StartTLS (no certificate configured) is reported as a `protocol`
asset with `protocol: LDAP` and `extra.starttls_error`, and gets an `ldap-cleartext` finding (medium): simple
binds to it send passwords in the clear. Domain controllers answer StartTLS on 389 once they have an LDAPS
certificate.

**Only scan networks you are authorized to scan.** The defaults are deliberately small: private,
loopback and link-local ranges only, at most 4096 addresses, six ports. Raising `max_hosts` or setting
`allow_public` should be a written decision. A /22 with the default ports is about 6,000 connects; if every
port is filtered (each connect waits out `connect_timeout`) that is roughly 100 seconds at the defaults.

## `kubernetes` — secrets and cert-manager

```yaml
- name: prod-cluster
  type: kubernetes
  # kubeconfig: ~/.kube/config     # default: the in-cluster service account, else $KUBECONFIG
  # context: prod
  namespaces: []                   # default: every namespace
  tls_secrets: true                # kubernetes.io/tls: the leaf certificate in tls.crt
  opaque_secrets: true             # Opaque: any value that is a key, certificate or keystore
  include_chain: false             # also intermediates in tls.crt and ca.crt
  cert_manager: true               # Certificate, Issuer, ClusterIssuer
  find_consumers: true             # pods and ingresses that use each secret
  keystore_passwords: [{password_env: KEYSTORE_PASSWORD}]
```

Needs `pip install "keycensus[kubernetes]"`. For each TLS secret, a `certificate` asset for the leaf with
`extra.key_algorithm` and `extra.key_matches_certificate` (a `tls.key` that does not match `tls.crt` breaks
the workload at its next restart). Opaque secret values go through the same reader as the `files`
collector, so a JKS or PKCS#12 keystore a Kafka broker or Java service keeps in a secret is read entry by
entry, with the same `keystore-weak-protection` finding. Values that are not key material are not decoded.

cert-manager Certificates are matched to their secret: the asset gets `extra.cert_manager` (issuer, issuer
type such as `acme (https://acme-v02...)`, `ca`, `vault`; private key algorithm and size; rotationPolicy;
renewBefore; Ready) and `rotation_enabled: true`. A Certificate whose secret is not readable or not issued
yet is reported from its spec. `rotationPolicy: Never`, the default before cert-manager 1.18, reuses the
private key at every renewal and gets `key-reuse-on-renewal` (low).

`used_by` lists the pods (by owner, such as `payments/ReplicaSet/api-7d9f`) that mount the secret as a
volume or read it into env vars, and the ingresses that terminate TLS with it.

Kubernetes RBAC cannot grant read access to TLS secrets only: `get`/`list` on secrets returns every value.
keycensus keeps only descriptions, but scope the grant with namespaced RoleBindings if that matters to you.
[`deploy/kubernetes/keycensus-reader.yaml`](../deploy/kubernetes/keycensus-reader.yaml) has the ClusterRole;
the Helm chart creates the same with `rbac.kubernetesSource: true`. Tested with the official client against
a local server that answers in the API's shapes; not yet run against a live cluster.

## `ct` — Certificate Transparency

```yaml
- name: public-certs
  type: ct
  domains: [example.com, example.org]
  include_subdomains: true           # default
  provider: certspotter              # or crtsh
  api_key_env: CERTSPOTTER_API_KEY   # optional; raises Cert Spotter's free allowance
  include_expired: false
  expected_issuers: ["Let's Encrypt", "DigiCert"]
  max_certificates: 5000
```

Publicly trusted CAs log every certificate they issue, so CT shows certificates that never made it into a
register: a vendor-built marketing site, a forgotten test host, or a certificate someone obtained for your
name. Each becomes a `certificate` asset with key algorithm and size, issuer, SANs and expiry, so the expiry,
weak-key and quantum rules apply to it. `extra.precertificate` marks entries where only the precertificate
was logged; `extra.revoked` comes from Cert Spotter.

With `expected_issuers`, a certificate from any other CA gets `ct-unexpected-issuer` (high). Matching is a
case-insensitive substring of the issuer DN or Cert Spotter's friendly name. CAA records are the matching
control on the CA side.

Cert Spotter (SSLMate) returns the certificates themselves, one entry per issuance. Without an API key its
free allowance is a few queries an hour; with one it covers large estates. crt.sh needs no key, lists
entries and is then asked for each certificate (`max_certificates` caps that); it is often slow or
returning errors, which keycensus retries. Both honour `Retry-After` on HTTP 429.

## `code` — source code

```yaml
- name: payments-repo
  type: code
  paths: [/src/payments-api, /src/batch-jobs]
  exclude: ["docs/**"]               # added to .git, node_modules, vendor, build, target, venv ...
  hardcoded_keys: true
  api_usage: true
  skip_tests: false
  max_file_bytes: 1000000
```

**Hard-coded keys.** Every file is checked for private keys: PEM blocks, including ones pasted into string
literals with escaped newlines, Java or JavaScript string concatenation, Python implicit concatenation and
YAML block scalars; OpenSSH private keys; committed keystores (.p12, .pfx, .jks ...). Each key becomes a `key`
asset with `extra.hardcoded`, the file and the line, and gets `hardcoded-private-key` (critical). Text that
looks like a key but does not parse (`REPLACE_ME` placeholders) is ignored, and so are certificates and
public keys. Keys under a test path (`tests/`, `fixtures/`, `testdata/`, `*_test.go` ...) are reported
with `extra.test_path` and the finding says so, because test keys sometimes are production keys. The
inventory holds the algorithm, size and fingerprint, never the key.

**API usage.** One `algorithm` asset per algorithm, size, curve and mode per repository, with every call
site in `extra.occurrences` (file, line, API, language) and in the CBOM as CycloneDX `evidence.occurrences`.

| Language | Recognised |
|---|---|
| Python | `hashlib`, `cryptography` (hashes, ciphers and modes, RSA/EC/DSA/Ed25519/X25519 key generation), pycryptodome (`AES.new` with its mode, DES, DES3, ARC4, RSA, ECC) |
| Java, Kotlin, Scala, Groovy | `Cipher.getInstance` (a bare `"AES"` is AES/ECB in SunJCE, and reported so), `MessageDigest`, `KeyPairGenerator` with the `initialize` size or curve, `KeyGenerator`, `Signature` (SHA1withRSA reports SHA-1 too), `KeyAgreement`, `KEM` (ML-KEM) |
| Go | `crypto/md5`, `sha1`, `sha256`, `sha512`, `des`, `rc4`, `rsa.GenerateKey` size, `ecdsa`/`ecdh` curves, `ed25519`, `crypto/mlkem` |
| JavaScript, TypeScript | Node `createHash`, `createCipheriv`/`createCipher` cipher strings, `generateKeyPair(Sync)` with modulus or curve; WebCrypto algorithm objects |
| C# | `MD5`/`SHA1`/... `.Create()` and `*CryptoServiceProvider`, `DES`, `TripleDES`, `RC2`, `Aes`, `CipherMode.ECB` set on a cipher created just above, `RSA.Create(size)`, `ECDsa` curves |
| C, C++ | OpenSSL `EVP_*` digests and ciphers (`EVP_aes_128_ecb` gives AES-128/ECB), `MD5`/`SHA1` calls, RSA key generation sizes, `NID_*` curves, `EVP_PKEY_CTX_new_from_name` |

Findings: `weak-hash` (MD5, SHA-1), `weak-cipher-mode` (ECB), `weak-algorithm` (DES, 3DES, RC4, RC2,
Blowfish), `weak-key-size`, and the quantum rules, so RSA and ECDH call sites land in the migration plan
with their locations. ML-KEM call sites are inventoried as quantum-safe. A line with `keycensus:ignore` (or
the line after it) is skipped; use it for the MD5 that computes a cache key.

Detection reads each language's standard APIs line by line. It does not follow variables
(`Cipher.getInstance(name)` with `name` from config is not seen), wrappers or third-party crypto libraries
beyond those listed, and it reads the working tree, not git history: pair it with gitleaks or trufflehog for
secrets that were committed and removed. Scanning two open-source JWT libraries (node-jsonwebtoken, jjwt)
took 0.2 and 1.1 seconds; every key found was a test key, correctly flagged as such.

## Writing your own

```python
from keycensus.collectors.base import Collector
from keycensus.model import KIND_KEY, STATE_ACTIVE

class AzureKeyVaultCollector(Collector):
    type_name = "azure-kv"
    requires_extra = "azure"          # for the friendly ImportError message

    def collect(self):
        client = ...                   # whatever SDK
        out = []
        for k in client.list_keys():
            out.append(self.asset(
                kind=KIND_KEY, name=k.name, native_id=k.id,
                algorithm="RSA", key_size=k.key_size, key_type="private-key",
                purposes=["sign", "verify"], created=k.created_on, state=STATE_ACTIVE,
                hardware_backed=k.key_type.endswith("-HSM"), location=client.vault_url,
            ))
        return out
```

Add it to `REGISTRY` in `keycensus/collectors/__init__.py`, add a test with the SDK mocked,
document it here. `self.asset()` fills in `source`/`source_type`/`tags` for you.
