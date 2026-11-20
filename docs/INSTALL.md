# Installing keycensus

Four ways, from no Python at all to a full development checkout. All of them give you the same `keycensus`
command.

| Way | Needs | Gets you |
|---|---|---|
| Single-file binary | nothing | every collector, on Linux x86_64 (glibc 2.36 or later: Debian 12, Ubuntu 24.04, RHEL 10 and newer) and macOS on Apple silicon |
| Homebrew | Homebrew | the same binary, kept up to date by `brew upgrade` |
| pipx | Python 3.11+ | the Python package, with the extras you choose |
| Container | Docker or Kubernetes | `ghcr.io/flavioimbertdomingos/keycensus`, also used by the Helm chart ([HELM.md](HELM.md)) |

## Single-file binary

Download it from the [releases page](https://github.com/FlavioImbertDomingos/keycensus/releases):

```
curl -LO https://github.com/FlavioImbertDomingos/keycensus/releases/latest/download/SHA256SUMS
curl -LO https://github.com/FlavioImbertDomingos/keycensus/releases/download/v0.21.0/keycensus-0.21.0-linux-x86_64
sha256sum -c --ignore-missing SHA256SUMS
chmod +x keycensus-0.21.0-linux-x86_64 && sudo mv keycensus-0.21.0-linux-x86_64 /usr/local/bin/keycensus
```

Each binary carries a build provenance attestation; `gh attestation verify keycensus-0.21.0-linux-x86_64
--repo FlavioImbertDomingos/keycensus` checks that it was built by the release workflow from this repository.

On macOS, a binary downloaded with a browser is quarantined by Gatekeeper because it is not notarised. Remove
the flag with `xattr -d com.apple.quarantine keycensus-0.21.0-macos-arm64`, or install with Homebrew, which
does not set it.

The PKCS#11 collector still needs your HSM vendor's client library on the machine, whichever way keycensus is
installed.

## Homebrew

```
brew install flavioimbertdomingos/keycensus/keycensus
```

The formula installs the single-file binary, so Homebrew pulls in no Python.

## pipx

```
pipx install "keycensus[all]"
```

The base package reads files, endpoints, code, Certificate Transparency, Vault, CipherTrust, KeySafe 5 and
Voltage. Cloud and HSM sources need an extra:

| Extra | For |
|---|---|
| `aws` | `aws-kms` (boto3) |
| `azure` | `azure-keyvault` with `auth: default` (azure-identity) |
| `gcp` | `gcp-kms` with `auth: default` (google-auth) |
| `kubernetes` | `kubernetes` |
| `pkcs11` | `pkcs11` (python-pkcs11) |
| `adcs` | `adcs` (ldap3); `adcs-kerberos` adds gssapi |
| `all` | all of the above except Kerberos |

`keycensus init` tells you which extra a source needs if it is missing. `pip install "keycensus[aws]"` works
too, in a virtual environment.

## First run

```
keycensus init
```

`init` lists the source types (marking the ones this machine looks set up for: `VAULT_ADDR`, AWS credentials,
a kubeconfig, Google application default credentials, an Azure profile, a PKCS#11 library), asks the few
settings each one needs, and writes `keycensus.yml`. It never asks for a secret: for a token, PIN or password
it asks for the name of the environment variable that holds it and checks that the variable is set. Then it
runs `keycensus doctor` on every source, so a missing permission shows up with the grant that fixes it, and
runs the first scan into `./out`.

```
keycensus init -s pem -s vault -y          # no questions: the defaults, and VAULT_ADDR if it is set
keycensus init --no-scan -o prod.yml       # write and test the config, scan later
```

The config `init` writes holds only the settings a first scan needs. Every other setting of every source
type is in [config/keycensus.example.yml](../config/keycensus.example.yml).

## How releases are built

A `v*` tag runs `.github/workflows/release.yml`: it builds the wheel, the sdist and both binaries, installs
each on a clean machine and runs a first scan with it (`packaging/smoke.sh`), publishes to PyPI by trusted
publishing (no API token is stored anywhere), and attaches the binaries, `SHA256SUMS` and the Homebrew
formula to the GitHub release. The Linux binary is built on Debian 12. On older distributions (Ubuntu 22.04,
RHEL 9, Amazon Linux 2023) use pipx or the container. A pull request that changes packaging runs the same
builds and tests, without publishing.
