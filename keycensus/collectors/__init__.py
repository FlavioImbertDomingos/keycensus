"""Collector registry. Add a line here to plug in a new source type."""

from __future__ import annotations

from ..config import SourceConfig
from .adcs import AdcsCollector
from .aws_kms import AwsKmsCollector
from .azure_keyvault import AzureKeyVaultCollector
from .base import Collector, CollectorError
from .ciphertrust import CipherTrustCollector
from .code import CodeCollector
from .ct import CtCollector
from .gcp_kms import GcpKmsCollector
from .keysafe5 import KeySafe5Collector
from .kubernetes import KubernetesCollector
from .network import NetworkCollector
from .pem_files import FilesCollector, PemCollector
from .pkcs11 import Pkcs11Collector
from .ssh_endpoint import SshCollector
from .tls_endpoint import TlsCollector
from .vault import VaultCollector
from .voltage import VoltageCollector

REGISTRY: dict[str, type[Collector]] = {
    c.type_name: c
    for c in (
        Pkcs11Collector,
        VaultCollector,
        AwsKmsCollector,
        AzureKeyVaultCollector,
        GcpKmsCollector,
        CipherTrustCollector,
        KeySafe5Collector,
        VoltageCollector,
        PemCollector,
        FilesCollector,
        TlsCollector,
        AdcsCollector,
        SshCollector,
        NetworkCollector,
        CtCollector,
        KubernetesCollector,
        CodeCollector,
    )
}

DESCRIPTIONS = {
    "pkcs11": "Any PKCS#11 HSM: Thales Luna, Entrust nShield, CloudHSM, Utimaco, SoftHSM",
    "vault": "HashiCorp Vault Transit keys and PKI certificates",
    "aws-kms": "AWS KMS keys (incl. CloudHSM key stores); one account or every account and region in an Organization",
    "azure-keyvault": "Azure Key Vault and Managed HSM; one vault or every vault in every subscription",
    "gcp-kms": "Google Cloud KMS keys (software, HSM, external); one project or every project you can see",
    "ciphertrust": "Thales CipherTrust Manager key vault (REST, beyond PKCS#11)",
    "keysafe5": "Entrust KeySafe 5 / nShield Security World keys (REST, beyond PKCS#11)",
    "voltage": "OpenText Voltage SecureData key inventory export (JSON/CSV, file or URL)",
    "pem": "Files on disk: PEM/DER certificates and keys, PKCS#12 and Java keystores, SSH keys and certificates",
    "files": "Same as pem",
    "kubernetes": "Kubernetes TLS and Opaque secrets (certificates, keys, keystores) and cert-manager Certificates",
    "code": "Source code: hard-coded private keys and keystores, crypto API calls in Python, Java, Go, JS/TS, C#, C",
    "tls": "Live TLS endpoints: protocol, cipher suite, key exchange (classical / hybrid / ML-KEM), leaf certificate",
    "ssh": "SSH servers: offered key exchange (incl. post-quantum hybrids), host key, cipher and MAC algorithms",
    "network": "Discovery: scan CIDR ranges for TLS, LDAP (StartTLS and LDAPS) and SSH endpoints, then probe each one",
    "ct": "Certificate Transparency logs: every public certificate issued for your domains (Cert Spotter or crt.sh)",
    "adcs": "Microsoft AD CS: CA certificates and templates from AD (LDAP), issued certificates from certutil",
}


def build(cfg: SourceConfig) -> Collector:
    cls = REGISTRY.get(cfg.type)
    if cls is None:
        raise CollectorError(f"[{cfg.name}] unknown source type {cfg.type!r}; known: {', '.join(sorted(REGISTRY))}")
    return cls(cfg)


__all__ = ["REGISTRY", "DESCRIPTIONS", "build", "Collector", "CollectorError"]
