"""The compliance controls that findings map to.

Kept deliberately short and quotable. Text is paraphrased, not the standard's
wording -- always check the standard itself.
"""

from __future__ import annotations

CONTROLS: dict[str, dict[str, str]] = {
    # ---- PCI DSS v4.0.1 ------------------------------------------------
    "PCI-DSS-4.0:3.5.1": {
        "framework": "PCI DSS v4.0.1",
        "title": "PAN is rendered unreadable using strong cryptography",
        "why": "Weak algorithms or key sizes mean stored account data is not actually protected.",
    },
    "PCI-DSS-4.0:3.6.1": {
        "framework": "PCI DSS v4.0.1",
        "title": "Procedures protect cryptographic keys used to protect stored account data",
        "why": "Keys must be stored in an HSM / key-encrypting key structure with restricted access.",
    },
    "PCI-DSS-4.0:3.6.1.1": {
        "framework": "PCI DSS v4.0.1",
        "title": "Documented description of the cryptographic architecture (service providers)",
        "why": "Requires an inventory of all keys, algorithms, protocols and their expiry -- exactly what a CBOM is.",
    },
    "PCI-DSS-4.0:3.7.1": {
        "framework": "PCI DSS v4.0.1",
        "title": "Generation of strong cryptographic keys",
        "why": "Key sizes below the 'strong cryptography' definition fail this control.",
    },
    "PCI-DSS-4.0:3.7.3": {
        "framework": "PCI DSS v4.0.1",
        "title": "Secure storage of cryptographic keys",
        "why": "Exportable or software-only keys weaken storage protections.",
    },
    "PCI-DSS-4.0:3.7.4": {
        "framework": "PCI DSS v4.0.1",
        "title": "Key changes at the end of the defined cryptoperiod",
        "why": "Keys older than their cryptoperiod, or with rotation disabled, fail this control.",
    },
    "PCI-DSS-4.0:3.7.5": {
        "framework": "PCI DSS v4.0.1",
        "title": "Retirement or replacement of weakened or compromised keys",
        "why": "Deprecated algorithms (3DES, SHA-1, RSA-1024) must be retired.",
    },
    "PCI-DSS-4.0:4.2.1": {
        "framework": "PCI DSS v4.0.1",
        "title": "Strong cryptography and protocols protect PAN in transit",
        "why": "TLS < 1.2, weak cipher suites, expired or weakly-signed certificates fail this control.",
    },
    "PCI-DSS-4.0:12.3.3": {
        "framework": "PCI DSS v4.0.1",
        "title": "Inventory of cryptographic cipher suites and protocols, reviewed at least annually",
        "why": "Mandatory from 31 March 2025. Must identify deprecated algorithms and include a migration plan.",
    },
    # ---- NIST ----------------------------------------------------------
    "NIST-SP-800-57": {
        "framework": "NIST SP 800-57 Part 1 Rev. 5",
        "title": "Recommendation for Key Management -- cryptoperiods and security strengths",
        "why": "Defines how long keys should live and how strong they must be.",
    },
    "NIST-SP-800-131A": {
        "framework": "NIST SP 800-131A Rev. 2",
        "title": "Transitioning the use of cryptographic algorithms and key lengths",
        "why": "3DES disallowed after 2023; SHA-1 signatures disallowed; RSA/DSA/DH < 2048 disallowed.",
    },
    "NIST-IR-8547": {
        "framework": "NIST IR 8547",
        "title": "Transition to Post-Quantum Cryptography Standards",
        "why": "Quantum-vulnerable algorithms deprecated after 2030 and disallowed after 2035.",
    },
    "NIST-FIPS-140-3": {
        "framework": "FIPS 140-3",
        "title": "Security requirements for cryptographic modules",
        "why": "Keys for regulated data should be generated and stored in validated modules.",
    },
}


def describe(control_id: str) -> dict[str, str]:
    return CONTROLS.get(control_id, {"framework": "?", "title": control_id, "why": ""})
