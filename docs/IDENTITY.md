# Asset identity

The same certificate is often in several places: a PEM file on a host, a Kubernetes secret, a TLS endpoint,
a Certificate Transparency log. A key pair can be a private key file, its `.pub`, an entry in a keystore and
a Vault Transit key. keycensus keeps one record per place, because each place has its own location, coverage
and findings: an expired certificate has to be replaced everywhere it is deployed. On top of those records it
works out which ones are the same asset, and how assets relate to each other.

## How records are matched

| Matched by | Applies to | Where the value comes from |
|---|---|---|
| Certificate fingerprint (SHA-256 of the DER) | every certificate | files, keystores, Kubernetes, TLS, LDAPS/StartTLS, CT, AD CS, Vault PKI, Azure |
| Public key (SHA-256 of the SubjectPublicKeyInfo) | keys whose public half the collector can see | PEM and DER keys, JKS/PKCS#12 keystores, OpenSSH keys, hard-coded keys found by the `code` collector, Vault Transit asymmetric keys (latest version), Azure Key Vault RSA and EC keys |
| Multi-region key id (`mrk-...`) | AWS KMS multi-region keys and their replicas | `aws-kms` |
| Nothing: its own identity | everything else | a secret key in an HSM, a KMS key whose public part is not read |

Names never match anything. Two keys called `payments` in two places stay two identities unless their
public keys or fingerprints are the same.

A private key and its public key are one key pair, so they share an identity. A certificate and its key do
not: they are two identities, linked by a relationship.

## Relationships

| Relationship | Means | Evidence |
|---|---|---|
| `certifies` | A certificate for a key the inventory also holds | the same public key |
| `issued-by` | A certificate and the CA certificate that issued it | the certificate's authority key identifier equals the CA's subject key identifier; when two CA certificates share one key identifier, nothing is recorded |
| `backed-by` | An Azure Key Vault certificate and the key Key Vault keeps for it | the certificate's `kid` |

Key versions are reported per identity as `versions` (current version, how many, and the oldest version
that can still decrypt, where the key store says so: Vault Transit, GCP KMS, Azure Key Vault).

Not covered yet: which key wraps which (for example a KEK protecting data keys). No collector reports it
today; it will come with the collectors that can see it.

## Where it shows up

```json
"summary": {"assets": 5, "assets_distinct": 3, "assets_in_several_places": 2, "relationships": 2}
```

That is from the test estate in `tests/test_identity.py`: a leaf certificate in two folders, its private
key and public key, and the CA certificate that issued it.

* `inventory.json`: every asset carries `identity`; `identities` lists the identities with more than one
  record, each with its observations; `relationships` lists the edges. For example:

  ```json
  {
    "id": "ki-19a6156a8087",
    "basis": "certificate fingerprint",
    "kind": "certificate",
    "name": "web.example.com",
    "observations": [
      {"source": "app", "source_type": "pem", "location": "/etc/ssl/app/web.crt", "observed": true},
      {"source": "ingress", "source_type": "pem", "location": "/etc/ssl/ingress/tls.crt", "observed": true}
    ],
    "places": 2
  }
  ```

* The CBOM has one component per identity. A component seen in several places has `bom-ref` set to the
  identity id (`ki-...`), `group` set to its sources, and one `evidence.occurrences` entry per place (the
  file and line for code). A certificate also `dependsOn` the key it certifies and the CA certificate that
  issued it. A record seen in one place keeps its asset id as `bom-ref`, so CBOMs of estates without
  copies do not change.
* The HTML report counts distinct assets in its headline (with the number of records next to it), and lists
  "Seen in more than one place" and "Relationships".
* The executive summary counts each certificate and key pair once.
* `keycensus diff` marks a removed record whose certificate or key pair is still seen elsewhere with
  `elsewhere` (the other places), and change alerting reports it as `asset-copy-removed`, a digest, instead
  of `asset-removed`, which pages. The last copy going away still pages.
* Prometheus: `keycensus_assets_distinct` and `keycensus_assets_in_several_places`. `keycensus_assets`
  still counts records.

## Limits

* A key is matched only when its public half is visible. Secret keys, and keys in stores that do not return
  a public key to keycensus (PKCS#11 private objects, AWS and GCP KMS keys, CipherTrust), are their own
  identity even when the same material lives somewhere else.
* Findings stay per record: a certificate in three places with an expiry finding has three findings, one per
  place to fix.
