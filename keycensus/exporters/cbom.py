"""CycloneDX 1.6 Cryptography Bill of Materials (CBOM).

A CBOM is a standard, machine-readable list of every cryptographic asset --
the format auditors, PQC-migration tools and Dependency-Track understand.

Mapping:

    keycensus asset          CycloneDX component (type: cryptographic-asset)
    ----------------------   -------------------------------------------------
    key                      cryptoProperties.assetType = related-crypto-material
                             (+ algorithmRef -> a shared algorithm component)
    certificate              cryptoProperties.assetType = certificate
                             (+ signatureAlgorithmRef, subjectPublicKeyRef)
    protocol (TLS endpoint)  cryptoProperties.assetType = protocol
                             (+ cipherSuites)
    finding                  vulnerabilities[] entry with `affects` -> the component

Algorithm components are de-duplicated: every RSA-2048 key points at the one
`alg:RSA-2048` component, which carries the classical / quantum security levels.
"""

from __future__ import annotations

import json
import uuid

from .. import __version__
from ..analysis import strength
from ..analysis.controls import describe
from ..model import KIND_CERTIFICATE, KIND_KEY, KIND_PROTOCOL, CryptoAsset, Inventory, iso

_CDX_STATES = {"pre-activation", "active", "suspended", "deactivated", "compromised", "destroyed"}
SEVERITY_TO_CDX = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


def _alg_ref(asset: CryptoAsset) -> str:
    return f"alg:{asset.display_algorithm}"


def _algorithm_component(asset: CryptoAsset) -> dict:
    s = strength.assess(asset)
    props: dict = {
        "primitive": strength.primitive_for(asset),
        "executionEnvironment": "hardware"
        if asset.hardware_backed
        else "software-plain-ram"
        if asset.hardware_backed is False
        else "unknown",
        "cryptoFunctions": sorted({_fn(p) for p in asset.purposes} - {None}) or ["unknown"],
    }
    if asset.key_size:
        props["parameterSetIdentifier"] = str(asset.key_size)
    if asset.curve:
        props["curve"] = asset.curve
    if s.classical_bits is not None:
        props["classicalSecurityLevel"] = s.classical_bits
    if s.nist_quantum_level is not None:
        props["nistQuantumSecurityLevel"] = s.nist_quantum_level
    if asset.fips_validated:
        props["certificationLevel"] = ["fips140-3-l3"]
    return {
        "type": "cryptographic-asset",
        "bom-ref": _alg_ref(asset),
        "name": asset.display_algorithm,
        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": props},
        "properties": [{"name": "keycensus:quantumClass", "value": s.quantum_class}],
    }


def _fn(purpose: str) -> str | None:
    return {
        "encrypt": "encrypt", "decrypt": "decrypt", "sign": "sign", "verify": "verify",
        "wrap": "encrypt", "unwrap": "decrypt", "derive": "keyderive", "mac": "tag",
    }.get(purpose)  # fmt: skip


def _key_component(asset: CryptoAsset) -> dict:
    rcm: dict = {
        "type": asset.key_type if asset.key_type in ("private-key", "public-key", "secret-key", "key") else "key",
        "id": asset.native_id,
        "state": asset.state if asset.state in _CDX_STATES else "active",
        "algorithmRef": _alg_ref(asset),
    }  # fmt: skip
    if asset.created:
        rcm["creationDate"] = iso(asset.created)
        rcm["activationDate"] = iso(asset.created)
    if asset.last_rotated:
        rcm["updateDate"] = iso(asset.last_rotated)
    if asset.expires:
        rcm["expirationDate"] = iso(asset.expires)
    if asset.key_size:
        rcm["size"] = asset.key_size
    if asset.hardware_backed is not None:
        rcm["securedBy"] = {"mechanism": "HSM" if asset.hardware_backed else "Software"}
    return {
        "type": "cryptographic-asset",
        "bom-ref": asset.id,
        "name": asset.name,
        "description": asset.location or None,
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": rcm,
        },
        "properties": _props(asset),
    }


def _cert_component(asset: CryptoAsset, sig_ref: str | None) -> dict:
    cp: dict = {
        "subjectName": asset.subject or asset.name,
        "issuerName": asset.issuer or "",
        "certificateFormat": "X.509",
        "subjectPublicKeyRef": _alg_ref(asset),
    }
    if asset.created:
        cp["notValidBefore"] = iso(asset.created)
    if asset.expires:
        cp["notValidAfter"] = iso(asset.expires)
    if sig_ref:
        cp["signatureAlgorithmRef"] = sig_ref
    return {
        "type": "cryptographic-asset",
        "bom-ref": asset.id,
        "name": asset.name,
        "description": asset.location or None,
        "cryptoProperties": {"assetType": "certificate", "certificateProperties": cp},
        "properties": _props(asset),
    }


def _protocol_component(asset: CryptoAsset) -> dict:
    pp: dict = {"type": "tls"}
    if asset.protocol_version:
        pp["version"] = asset.protocol_version.replace("TLSv", "")
    if asset.cipher_suites:
        pp["cipherSuites"] = [{"name": c} for c in asset.cipher_suites]
    return {
        "type": "cryptographic-asset",
        "bom-ref": asset.id,
        "name": asset.name,
        "cryptoProperties": {"assetType": "protocol", "protocolProperties": pp},
        "properties": _props(asset)
        + [{"name": "keycensus:weakVersionsAccepted", "value": v} for v in asset.weak_versions_accepted],
    }


def _props(asset: CryptoAsset) -> list[dict]:
    s = strength.assess(asset)
    out = [
        {"name": "keycensus:source", "value": asset.source},
        {"name": "keycensus:sourceType", "value": asset.source_type},
        {"name": "keycensus:quantumClass", "value": s.quantum_class},
    ]
    for k, v in (
        ("rotationEnabled", asset.rotation_enabled),
        ("exportable", asset.exportable),
        ("hardwareBacked", asset.hardware_backed),
        ("fipsValidated", asset.fips_validated),
        ("signatureHash", asset.signature_hash),
        ("selfSigned", asset.self_signed),
    ):
        if v is not None:
            out.append(
                {
                    "name": f"keycensus:{k}",
                    "value": str(v).lower() if isinstance(v, bool) else str(v),
                }
            )
    for k, v in asset.tags.items():
        out.append({"name": f"tag:{k}", "value": str(v)})
    return out


def _signature_alg_component(asset: CryptoAsset) -> dict | None:
    if not asset.signature_algorithm:
        return None
    ref = f"alg:sig:{asset.signature_algorithm}"
    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": asset.signature_algorithm,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "signature",
                "cryptoFunctions": ["sign", "verify"],
            },
        },
    }


def build(inv: Inventory) -> dict:
    components: dict[str, dict] = {}
    for a in inv.assets:
        if a.kind in (KIND_KEY, KIND_CERTIFICATE):
            components.setdefault(_alg_ref(a), _algorithm_component(a))
        if a.kind == KIND_KEY:
            components[a.id] = _key_component(a)
        elif a.kind == KIND_CERTIFICATE:
            sig = _signature_alg_component(a)
            if sig:
                components.setdefault(sig["bom-ref"], sig)
            components[a.id] = _cert_component(a, sig["bom-ref"] if sig else None)
        elif a.kind == KIND_PROTOCOL:
            components[a.id] = _protocol_component(a)

    # strip None descriptions (schema disallows null)
    comp_list = []
    for c in components.values():
        comp_list.append({k: v for k, v in c.items() if v is not None})

    vulns = []
    for i, f in enumerate(inv.findings):
        vulns.append(
            {
                "bom-ref": f"finding-{i}",
                "id": f"KEYCENSUS-{f.rule_id.upper()}",
                "source": {"name": "keycensus"},
                "description": f.title,
                "detail": f.detail,
                "recommendation": f.remediation,
                "ratings": [{"severity": SEVERITY_TO_CDX[f.severity], "method": "other"}],
                "properties": [{"name": "control", "value": c} for c in f.controls]
                + [{"name": "controlTitle", "value": f"{c}: {describe(c)['title']}"} for c in f.controls],
                "affects": [{"ref": f.asset_id}],
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": iso(inv.generated_at),
            "tools": {"components": [{"type": "application", "name": "keycensus", "version": __version__}]},
            "properties": [
                {"name": "keycensus:policy", "value": inv.policy_name},
                {"name": "keycensus:sources", "value": str(len(inv.sources))},
            ]
            + [
                {
                    "name": f"keycensus:source:{s.name}",
                    "value": s.error or f"ok ({len(s.assets)} assets)",
                }
                for s in inv.sources
            ],
        },
        "components": comp_list,
        "dependencies": [
            {"ref": a.id, "dependsOn": [_alg_ref(a)]} for a in inv.assets if a.kind in (KIND_KEY, KIND_CERTIFICATE)
        ],
        "vulnerabilities": vulns,
    }


def render(inv: Inventory) -> str:
    return json.dumps(build(inv), indent=2) + "\n"
