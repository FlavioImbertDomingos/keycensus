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
