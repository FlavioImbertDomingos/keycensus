# Collectors

Each entry under `sources:` in the config has a `name` (your label, becomes the `source`
field on every asset), a `type` (one of the below), and type-specific options.
Secrets are always `*_env` (environment variable) or `*_file` (path), never inline.

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

## `pem` — files on disk

```yaml
- name: app-certs
  type: pem
  paths: [/etc/ssl/app, /opt/payments/keys, /etc/nginx/cert.pem]
  patterns: ["*.pem", "*.crt", "*.cer", "*.key", "*.der", "*.pub"]   # default
  recursive: true
```

Parses every PEM block (bundles yield several assets) and bare DER. Certificates become
`certificate` assets with expiry, signature hash, SANs, CA flag. Private keys become `key` assets
marked `exportable: true`, `hardware_backed: false`, `created: null` — a private key sitting in
a file with no register entry is precisely what an inventory should surface. Encrypted PEM keys
are recorded as opaque private keys.

## `tls` — live endpoints

```yaml
- name: edges
  type: tls
  endpoints: ["api.example.com:443", "10.0.0.5:8443"]
  timeout: 5
  probe_legacy: true      # also attempt TLS 1.0 / 1.1 handshakes
```

One `protocol` asset per endpoint (negotiated version, cipher suite, legacy versions the server
*also* accepts) plus one `certificate` asset for the leaf. Verification is disabled on purpose —
we inventory, we don't trust. `probe_legacy` needs an OpenSSL that can still speak TLS 1.0
(`@SECLEVEL=0`); if it can't, legacy versions are reported as not accepted.

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
