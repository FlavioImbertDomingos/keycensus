"""Collector registry. Add a line here to plug in a new source type."""

from __future__ import annotations

from ..config import SourceConfig
from .aws_kms import AwsKmsCollector
from .azure_keyvault import AzureKeyVaultCollector
from .base import Collector, CollectorError
from .ciphertrust import CipherTrustCollector
from .gcp_kms import GcpKmsCollector
from .keysafe5 import KeySafe5Collector
from .pem_files import PemCollector
from .pkcs11 import Pkcs11Collector
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
        TlsCollector,
    )
}

DESCRIPTIONS = {
    "pkcs11": "Any PKCS#11 HSM: Thales Luna, Entrust nShield, CloudHSM, Utimaco, SoftHSM",
    "vault": "HashiCorp Vault Transit keys and PKI certificates",
    "aws-kms": "AWS KMS keys (incl. CloudHSM custom key stores)",
    "azure-keyvault": "Azure Key Vault keys + certificates, and Azure Managed HSM",
    "gcp-kms": "Google Cloud KMS keys (software, HSM, external protection levels)",
    "ciphertrust": "Thales CipherTrust Manager key vault (REST, beyond PKCS#11)",
    "keysafe5": "Entrust KeySafe 5 / nShield Security World keys (REST, beyond PKCS#11)",
    "voltage": "OpenText Voltage SecureData key inventory export (JSON/CSV, file or URL)",
    "pem": "Certificates and keys in PEM/DER files on disk",
    "tls": "Live TLS endpoints: negotiated protocol, cipher suite, leaf certificate",
}


def build(cfg: SourceConfig) -> Collector:
    cls = REGISTRY.get(cfg.type)
    if cls is None:
        raise CollectorError(f"[{cfg.name}] unknown source type {cfg.type!r}; known: {', '.join(sorted(REGISTRY))}")
    return cls(cfg)


__all__ = ["REGISTRY", "DESCRIPTIONS", "build", "Collector", "CollectorError"]
