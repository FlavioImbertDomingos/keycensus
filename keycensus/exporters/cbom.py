"""CycloneDX Cryptography Bill of Materials (CBOM), version 1.6 (default) or 1.7.

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
    algorithm (code scan)    cryptoProperties.assetType = algorithm, with every call site as
                             evidence.occurrences (location = file, line, additionalContext = API)
    hard-coded key           related-crypto-material, with the file and line as evidence.occurrences
    finding                  vulnerabilities[] entry with `affects` -> the component
    application (linked)     component type: application (name, version, purl, bom-ref from its
                             SBOM) + dependencies[].dependsOn -> the crypto assets it uses; the
                             SBOM itself is referenced via externalReferences[type=bom]

Algorithm components are de-duplicated: every RSA-2048 key points at the one
`alg:RSA-2048` component, which carries the classical / quantum security levels.

CycloneDX 1.7 (`version="1.7"`, `--cbom-version 1.7`) differs in three ways:

* Algorithm components are named with the CycloneDX Cryptography Registry (keycensus.registry):
  `name` follows the family's pattern (AES-256-GCM, RSA-OAEP-SHA-256-2048, ECDSA-P-256) and
  `algorithmFamily` names the family, when the source establishes it. Curves use `ellipticCurve` with
  registry identifiers (nist/P-256) instead of the deprecated `curve`.
* Links use `relatedCryptographicAssets` instead of the deprecated `algorithmRef`, `subjectPublicKeyRef`
  and `signatureAlgorithmRef`.
* `specVersion` is 1.7 and `$schema` points at the 1.7 schema.

1.6 output keeps its component names, so existing consumers see no change; the registry family and name
are added there as `keycensus:registryFamily` and `keycensus:registryName` properties.
"""

from __future__ import annotations

import json
import uuid

from .. import __version__, identity, registry
from ..analysis import strength
from ..analysis.controls import describe
from ..model import (
    KIND_ALGORITHM,
    KIND_CERTIFICATE,
    KIND_KEY,
    KIND_PROTOCOL,
    CryptoAsset,
    Inventory,
    fips_level,
    iso,
)

VERSIONS = ("1.6", "1.7")
DEFAULT_VERSION = "1.6"
_CDX_STATES = {"pre-activation", "active", "suspended", "deactivated", "compromised", "destroyed"}
SEVERITY_TO_CDX = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


def _alg_ref(asset: CryptoAsset, v17: bool = False) -> str:
    if v17:
        norm = registry.normalise(asset)
        if norm.resolved:
            return f"alg:{norm.name}"
    return f"alg:{asset.display_algorithm}"


def _registry_props(norm: registry.RegistryName) -> list[dict]:
    out = [{"name": "keycensus:registryName", "value": norm.name}]
    if norm.family:
        out.append({"name": "keycensus:registryFamily", "value": norm.family})
    if norm.note:
        out.append({"name": "keycensus:registryNote", "value": norm.note})
    return out


def _algorithm_component(asset: CryptoAsset, v17: bool = False) -> dict:
    s = strength.assess(asset)
    norm = registry.normalise(asset)
    props: dict = {
        "primitive": (norm.primitive if v17 and norm.primitive else None) or strength.primitive_for(asset),
        "executionEnvironment": "hardware"
        if asset.hardware_backed
        else "software-plain-ram"
        if asset.hardware_backed is False
        else "unknown",
        "cryptoFunctions": sorted({_fn(p) for p in asset.purposes} - {None}) or ["unknown"],
    }
    if asset.key_size:
        props["parameterSetIdentifier"] = str(asset.key_size)
    if v17:
        if norm.family:
            props["algorithmFamily"] = norm.family
        if norm.curve:
            props["ellipticCurve"] = norm.curve
    elif asset.curve:
        props["curve"] = asset.curve
    if s.classical_bits is not None:
        props["classicalSecurityLevel"] = s.classical_bits
    if s.nist_quantum_level is not None:
        props["nistQuantumSecurityLevel"] = s.nist_quantum_level
    return {
        "type": "cryptographic-asset",
        "bom-ref": _alg_ref(asset, v17),
        "name": norm.name if v17 and norm.resolved else asset.display_algorithm,
        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": props},
        "properties": [{"name": "keycensus:quantumClass", "value": s.quantum_class}]
        + ([] if v17 and norm.resolved and not norm.note else _registry_props(norm)),
    }


def _fn(purpose: str) -> str | None:
    return {
        "encrypt": "encrypt", "decrypt": "decrypt", "sign": "sign", "verify": "verify",
        "wrap": "encrypt", "unwrap": "decrypt", "derive": "keyderive", "mac": "tag", "digest": "digest",
    }.get(purpose)  # fmt: skip


def _key_component(asset: CryptoAsset, v17: bool = False) -> dict:
    rcm: dict = {
        "type": asset.key_type if asset.key_type in ("private-key", "public-key", "secret-key", "key") else "key",
        "id": asset.native_id,
        "state": asset.state if asset.state in _CDX_STATES else "active",
    }  # fmt: skip
    if v17:
        rcm["relatedCryptographicAssets"] = [{"type": "algorithm", "ref": _alg_ref(asset, v17)}]
    else:
        rcm["algorithmRef"] = _alg_ref(asset)
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
    comp = {
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
    ex = asset.extra or {}
    if ex.get("hardcoded"):
        occ = {"location": ex.get("file") or asset.location, "line": int(ex.get("line") or 1),
               "additionalContext": "hard-coded private key"}  # fmt: skip
        comp["evidence"] = {"occurrences": [occ]}
        comp["properties"].append({"name": "keycensus:hardcoded", "value": "true"})
    return comp


_CDX_MODES = {"CBC", "ECB", "CCM", "GCM", "CFB", "OFB", "CTR"}


def _code_algorithm_component(asset: CryptoAsset, v17: bool = False) -> dict:
    """An algorithm the code calls, with its call sites as CycloneDX evidence."""
    comp = _algorithm_component(asset, v17)
    ex = asset.extra or {}
    mode = ex.get("mode")
    if mode:
        comp["cryptoProperties"]["algorithmProperties"]["mode"] = mode.lower() if mode in _CDX_MODES else "other"
    norm = registry.normalise(asset)
    comp.update({
        "bom-ref": asset.id,
        "name": norm.name if v17 and norm.resolved else asset.display_algorithm + (f"/{mode}" if mode else ""),
        "description": asset.name,
        "evidence": {"occurrences": [
            {"location": o["file"], "line": int(o["line"]), "additionalContext": f"{o['api']} ({o['language']})"}
            for o in ex.get("occurrences") or []]},
    })  # fmt: skip
    comp["properties"] = _props(asset) + [
        {"name": "keycensus:occurrences", "value": str(ex.get("occurrence_count", 0))},
        {"name": "keycensus:repository", "value": str(ex.get("repository") or asset.location)},
    ] + ([{"name": "keycensus:onlyInTests", "value": "true"}] if ex.get("only_in_tests") else [])  # fmt: skip
    return comp


def _cert_component(asset: CryptoAsset, sig_ref: str | None, v17: bool = False) -> dict:
    cp: dict = {
        "subjectName": asset.subject or asset.name,
        "issuerName": asset.issuer or "",
        "certificateFormat": "X.509",
    }
    if asset.created:
        cp["notValidBefore"] = iso(asset.created)
    if asset.expires:
        cp["notValidAfter"] = iso(asset.expires)
    if v17:
        related = [{"type": "publicKeyAlgorithm", "ref": _alg_ref(asset, v17)}]
        if sig_ref:
            related.append({"type": "signatureAlgorithm", "ref": sig_ref})
        cp["relatedCryptographicAssets"] = related
    else:
        cp["subjectPublicKeyRef"] = _alg_ref(asset)
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
    pp: dict = {"type": "ssh" if (asset.protocol or "").upper() == "SSH" else "tls"}
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
        + [{"name": "keycensus:weakVersionsAccepted", "value": v} for v in asset.weak_versions_accepted]
        + ([{"name": "keycensus:keyExchange", "value": asset.key_exchange}] if asset.key_exchange else [])
        + [
            {"name": "keycensus:pqKeyExchangeSupported", "value": g}
            for g in ((asset.extra or {}).get("key_exchange") or {}).get("pq_supported") or []
        ],  # fmt: skip
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
        ("fipsEvidence", (asset.fips_evidence or {}).get("basis")),
        ("fipsStandard", (asset.fips_evidence or {}).get("standard")),
        ("fipsLevel", (asset.fips_evidence or {}).get("level")),
        ("fipsCertificate", (asset.fips_evidence or {}).get("certificate")),
        ("fipsModule", (asset.fips_evidence or {}).get("module")),
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
    for u in asset.used_by:
        out.append(
            {"name": f"keycensus:usedBy:{u.get('type', 'principal')}", "value": f"{u.get('id')} ({u.get('via')})"}
        )
    for app in asset.applications:
        out.append({"name": "keycensus:application", "value": app})
    use = asset.observed_use
    if use is not None:
        w = use.get("window") or {}
        out.append({"name": "keycensus:observedUseWindow", "value": f"{w.get('from') or ''}/{w.get('to') or ''}"})
        out.append({"name": "keycensus:observedUseEvents", "value": str(use.get("succeeded", 0))})
        for p in use.get("principals") or []:
            ops = ",".join(f"{k}={v}" for k, v in sorted(p["operations"].items()))
            auth = {True: "authorized", False: "not in used_by", None: "no consumers recorded"}[p.get("authorized")]
            out.append({"name": "keycensus:observedUse",
                        "value": f"{p['id']} {ops or 'refused'} last={p['last_seen']} ({auth})"})  # fmt: skip
        for u in use.get("authorized_not_seen") or []:
            out.append({"name": "keycensus:authorizedNotSeen", "value": f"{u['id']} ({u.get('via')})"})
    return out


def _application_component(app) -> dict:
    c: dict = {"type": "application", "bom-ref": app.ref, "name": app.name}
    if app.version:
        c["version"] = app.version
    if app.purl:
        c["purl"] = app.purl
    if app.description:
        c["description"] = app.description
    if app.owner:
        c["supplier"] = {"name": app.owner}
    refs = []
    if app.sbom_serial:
        refs.append({"type": "bom", "url": app.sbom_serial, "comment": f"SBOM of {app.name}"})
    if refs:
        c["externalReferences"] = refs
    props = [{"name": "keycensus:linkedAssets", "value": str(len(app.asset_ids))}]
    if app.sbom_path:
        props.append({"name": "keycensus:sbomPath", "value": app.sbom_path})
    c["properties"] = props
    return c


def _signature_alg_component(asset: CryptoAsset, v17: bool = False) -> dict | None:
    if not asset.signature_algorithm:
        return None
    norm = registry.signature_algorithm(asset.signature_algorithm)
    named = v17 and norm is not None and norm.resolved
    props: dict = {"primitive": "signature", "cryptoFunctions": ["sign", "verify"]}
    if named:
        props["algorithmFamily"] = norm.family
    comp = {
        "type": "cryptographic-asset",
        "bom-ref": f"alg:sig:{norm.name if named else asset.signature_algorithm}",
        "name": norm.name if named else asset.signature_algorithm,
        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": props},
    }
    if norm is not None and not named:
        comp["properties"] = _registry_props(norm)
    return comp


def _certification_levels(inv: Inventory, v17: bool = False) -> dict[str, list[str]]:
    """certificationLevel per shared algorithm component. A level appears only when every key and certificate
    using that algorithm has certificate-backed FIPS evidence for that same level; a FIPS claim without a
    certificate is "unknown". Mixed modules get no level at all rather than a misleading one."""
    seen: dict[str, set] = {}
    for a in inv.assets:
        if a.kind in (KIND_KEY, KIND_CERTIFICATE):
            level = fips_level(a.fips_evidence) or ("unknown" if a.fips_validated else None)
            seen.setdefault(_alg_ref(a, v17), set()).add(level)
    out = {}
    for ref, levels in seen.items():
        if len(levels) == 1 and None not in levels:
            out[ref] = [next(iter(levels))]
    return out


def build(inv: Inventory, version: str = DEFAULT_VERSION) -> dict:
    if version not in VERSIONS:
        raise ValueError(f"CycloneDX version {version!r} is not supported; use one of {', '.join(VERSIONS)}")
    v17 = version == "1.7"
    components: dict[str, dict] = {}
    levels = _certification_levels(inv, v17)
    # One component per identity: the same certificate or key pair seen in several places is one component,
    # with a CycloneDX evidence occurrence for each place (keycensus.identity). A single record keeps its asset
    # id as bom-ref, so CBOMs of estates without duplicates are unchanged.
    idents = identity.group(inv.assets)
    ref_of: dict[str, str] = {}
    ident_ref: dict[str, str] = {}
    for ident in idents:
        merged = len(ident.asset_ids) > 1 and ident.basis != identity.BASIS_SINGLE
        ident_ref[ident.id] = ident.id if merged else ident.asset_ids[0]
        for aid in ident.asset_ids:
            ref_of[aid] = ident_ref[ident.id]
    sources_of = {ident.id: sorted({o["source"] for o in ident.observations}) for ident in idents}
    ident_of = identity.index(idents)
    for a in inv.assets:
        cref = ref_of.get(a.id, a.id)
        if a.kind in (KIND_KEY, KIND_CERTIFICATE):
            ref = _alg_ref(a, v17)
            if ref not in components:
                comp = _algorithm_component(a, v17)
                if ref in levels:
                    comp["cryptoProperties"]["algorithmProperties"]["certificationLevel"] = levels[ref]
                components[ref] = comp
        if a.kind == KIND_KEY:
            components[a.id] = _key_component(a, v17)
        elif a.kind == KIND_CERTIFICATE:
            sig = _signature_alg_component(a, v17)
            if sig:
                components.setdefault(sig["bom-ref"], sig)
            components[a.id] = _cert_component(a, sig["bom-ref"] if sig else None, v17)
        elif a.kind == KIND_PROTOCOL:
            components[a.id] = _protocol_component(a)
        elif a.kind == KIND_ALGORITHM:
            components[a.id] = _code_algorithm_component(a, v17)
        if a.id in components and a.source:
            # Tools such as Dependency-Track identify a component by group, name and version. Without a group,
            # a key named "Ed25519" and the shared Ed25519 algorithm component are merged into one, and so are
            # two keys with the same name in different sources.
            components[a.id]["group"] = a.source
        if cref != a.id and a.id in components:
            comp = components.pop(a.id)
            occ = _occurrences(comp, a)
            if cref in components:  # another record of this identity was emitted first: add this place to it
                have = components[cref].setdefault("evidence", {}).setdefault("occurrences", [])
                have += [o for o in occ if o not in have]
                continue
            comp["bom-ref"] = cref
            comp["group"] = ",".join(sources_of[ident_of[a.id]])
            comp["evidence"] = {**(comp.get("evidence") or {}), "occurrences": occ}
            components[cref] = comp
    for ident in idents:
        comp = components.get(ident.id)
        if comp is not None:
            comp.setdefault("properties", []).append({"name": "keycensus:places", "value": str(ident.places)})

    for app in inv.applications:
        components[app.ref] = _application_component(app)

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
                "affects": [{"ref": ref_of.get(f.asset_id, f.asset_id)}],
            }
        )

    head = {"$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json"} if v17 else {}
    return {
        **head,
        "bomFormat": "CycloneDX",
        "specVersion": version,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": iso(inv.generated_at),
            "tools": {"components": [{"type": "application", "name": "keycensus", "version": __version__}]},
            "properties": [
                {"name": "keycensus:policy", "value": (inv.policy_pack or {}).get("ref") or inv.policy_name},
                {"name": "keycensus:policyDigest", "value": (inv.policy_pack or {}).get("digest") or ""},
                {"name": "keycensus:sources", "value": str(len(inv.sources))},
                {"name": "keycensus:applications", "value": str(len(inv.applications))},
            ]
            + [
                {
                    "name": f"keycensus:auditLog:{lg['type']}",
                    "value": f"{lg['path']} {lg['from'] or ''}/{lg['to'] or ''}",
                }
                for lg in (inv.usage or {}).get("logs") or []
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
        "dependencies": _dependencies(inv, v17, ref_of, ident_ref),
        "vulnerabilities": vulns,
    }


def _occurrences(comp: dict, a) -> list[dict]:
    """Where this record was seen: the collector's own occurrences (file and line for code), else its location."""
    own = (comp.get("evidence") or {}).get("occurrences")
    return list(own) if own else [{"location": f"{a.source}: {a.location or a.native_id}"}]


def _dependencies(inv: Inventory, v17: bool, ref_of: dict[str, str], ident_ref: dict[str, str]) -> list[dict]:
    """Each key or certificate depends on its algorithm; a certificate also depends on the key it certifies, the
    CA certificate that issued it and the Key Vault key behind it; an application depends on its assets."""
    deps: dict[str, list[str]] = {}

    def add(ref: str, target: str) -> None:
        lst = deps.setdefault(ref, [])
        if target != ref and target not in lst:
            lst.append(target)

    for a in inv.assets:
        if a.kind in (KIND_KEY, KIND_CERTIFICATE):
            add(ref_of.get(a.id, a.id), _alg_ref(a, v17))
    for rel in identity.relationships(inv.assets, identity.group(inv.assets)):
        add(ident_ref[rel["from"]], ident_ref[rel["to"]])
    for app in inv.applications:
        deps.setdefault(app.ref, [])
        for aid in app.asset_ids:
            add(app.ref, ref_of.get(aid, aid))
    return [{"ref": r, "dependsOn": d} for r, d in deps.items()]


def render(inv: Inventory, version: str = DEFAULT_VERSION) -> str:
    return json.dumps(build(inv, version), indent=2) + "\n"
