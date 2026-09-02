"""Collector: AWS KMS (including keys backed by CloudHSM custom key stores).

    - name: aws-prod
      type: aws-kms
      region: us-east-1
      profile: prod                    # optional; otherwise the default boto3 credential chain
      endpoint_url: http://moto:5000   # demo / LocalStack only
      include_aws_managed: false       # aws/* keys are AWS's problem, not yours
      include_pending_deletion: true
      include_consumers: true          # who uses the key: grants + key policy principals -> used_by

Needs `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyRotationStatus`, `kms:ListAliases`,
`kms:ListResourceTags`, and for `include_consumers` also `kms:ListGrants` and `kms:GetKeyPolicy`
(both tolerated when denied). Requires `pip install 'keycensus[aws]'`.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC

from ..model import (
    ALG_EC,
    ALG_HMAC,
    ALG_ML_DSA,
    ALG_RSA,
    ALG_UNKNOWN,
    KIND_KEY,
    STATE_ACTIVE,
    STATE_DEACTIVATED,
    STATE_DESTROYED,
    STATE_PRE_ACTIVATION,
    STATE_UNKNOWN,
    CryptoAsset,
)
from .base import Collector

log = logging.getLogger(__name__)

# KeySpec -> (algorithm, key_size, curve)
KEY_SPECS = {
    "SYMMETRIC_DEFAULT": ("AES", 256, None),
    "RSA_2048": (ALG_RSA, 2048, None),
    "RSA_3072": (ALG_RSA, 3072, None),
    "RSA_4096": (ALG_RSA, 4096, None),
    "ECC_NIST_P256": (ALG_EC, 256, "P-256"),
    "ECC_NIST_P384": (ALG_EC, 384, "P-384"),
    "ECC_NIST_P521": (ALG_EC, 521, "P-521"),
    "ECC_SECG_P256K1": (ALG_EC, 256, "secp256k1"),
    "HMAC_224": (ALG_HMAC, 224, None),
    "HMAC_256": (ALG_HMAC, 256, None),
    "HMAC_384": (ALG_HMAC, 384, None),
    "HMAC_512": (ALG_HMAC, 512, None),
    "ML_DSA_44": (ALG_ML_DSA, 44, None),
    "ML_DSA_65": (ALG_ML_DSA, 65, None),
    "ML_DSA_87": (ALG_ML_DSA, 87, None),
    "SM2": ("SM2", 256, "sm2p256v1"),
}

KEY_STATES = {
    "Enabled": STATE_ACTIVE,
    "Disabled": STATE_DEACTIVATED,
    "PendingDeletion": STATE_DESTROYED,
    "PendingReplicaDeletion": STATE_DESTROYED,
    "PendingImport": STATE_PRE_ACTIVATION,
    "Creating": STATE_PRE_ACTIVATION,
    "Unavailable": STATE_UNKNOWN,
    "Updating": STATE_ACTIVE,
}

USAGE_PURPOSES = {
    "ENCRYPT_DECRYPT": ["encrypt", "decrypt"],
    "SIGN_VERIFY": ["sign", "verify"],
    "GENERATE_VERIFY_MAC": ["mac"],
    "KEY_AGREEMENT": ["derive"],
}


class AwsKmsCollector(Collector):
    type_name = "aws-kms"
    requires_extra = "aws"

    def collect(self) -> list[CryptoAsset]:
        import boto3

        session_kwargs = {}
        if self.opt.get("profile"):
            session_kwargs["profile_name"] = self.opt["profile"]
        session = boto3.session.Session(**session_kwargs)
        client_kwargs = {"region_name": self.opt.get("region")}
        if self.opt.get("endpoint_url"):
            client_kwargs["endpoint_url"] = self.opt["endpoint_url"]
        kms = session.client("kms", **client_kwargs)

        aliases: dict[str, list[str]] = {}
        for page in kms.get_paginator("list_aliases").paginate():
            for a in page.get("Aliases", []):
                if a.get("TargetKeyId"):
                    aliases.setdefault(a["TargetKeyId"], []).append(a["AliasName"])

        include_aws = bool(self.opt.get("include_aws_managed", False))
        include_pending = bool(self.opt.get("include_pending_deletion", True))
        self.include_consumers = bool(self.opt.get("include_consumers", True))
        assets: list[CryptoAsset] = []
        for page in kms.get_paginator("list_keys").paginate():
            for entry in page.get("Keys", []):
                md = kms.describe_key(KeyId=entry["KeyId"])["KeyMetadata"]
                if md.get("KeyManager") == "AWS" and not include_aws:
                    continue
                if md.get("KeyState") == "PendingDeletion" and not include_pending:
                    continue
                assets.append(self._asset(kms, md, aliases.get(md["KeyId"], [])))
        return assets

    def _consumers(self, kms, key_id: str) -> list[dict]:
        """Grants (the mechanism AWS services and apps use) plus non-root principals in the key policy."""
        out: list[dict] = []
        seen: set[tuple[str, str]] = set()

        def add(kind: str, ident: str, via: str):
            if ident and (kind, ident) not in seen:
                seen.add((kind, ident))
                out.append({"type": kind, "id": ident, "via": via})

        try:
            for page in kms.get_paginator("list_grants").paginate(KeyId=key_id):
                for g in page.get("Grants", []):
                    add("principal", g.get("GranteePrincipal", ""), "grant:" + (g.get("Name") or "unnamed"))
        except Exception as exc:  # noqa: BLE001 - kms:ListGrants denied
            log.debug("[%s] list_grants %s: %s", self.name, key_id, exc)
        try:
            policy = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default").get("Policy") or "{}")
            for st in policy.get("Statement") or []:
                if st.get("Effect") != "Allow":
                    continue
                principal = st.get("Principal") or {}
                arns = principal.get("AWS") if isinstance(principal, dict) else principal
                for arn in [arns] if isinstance(arns, str) else (arns or []):
                    if isinstance(arn, str) and not arn.endswith(":root") and arn != "*":
                        add("principal", arn, "key-policy:" + str(st.get("Sid") or "unnamed"))
                services = principal.get("Service") if isinstance(principal, dict) else None
                for svc in [services] if isinstance(services, str) else (services or []):
                    add("service", svc, "key-policy:" + str(st.get("Sid") or "unnamed"))
        except Exception as exc:  # noqa: BLE001 - kms:GetKeyPolicy denied
            log.debug("[%s] get_key_policy %s: %s", self.name, key_id, exc)
        return out

    def _asset(self, kms, md: dict, names: list[str]) -> CryptoAsset:
        spec = md.get("KeySpec") or md.get("CustomerMasterKeySpec") or "SYMMETRIC_DEFAULT"
        alg, size, curve = KEY_SPECS.get(spec, (ALG_UNKNOWN, None, None))
        usage = md.get("KeyUsage", "ENCRYPT_DECRYPT")
        purposes = list(USAGE_PURPOSES.get(usage, []))

        rotation = None
        rotation_period = None
        if spec == "SYMMETRIC_DEFAULT" and md.get("Origin") == "AWS_KMS":
            try:
                r = kms.get_key_rotation_status(KeyId=md["KeyId"])
                rotation = bool(r.get("KeyRotationEnabled"))
                rotation_period = r.get("RotationPeriodInDays")
            except Exception as exc:  # noqa: BLE001 - permission or unsupported key store
                log.debug("[%s] rotation status for %s: %s", self.name, md["KeyId"], exc)

        tags = {}
        try:
            for t in kms.list_resource_tags(KeyId=md["KeyId"]).get("Tags", []):
                tags[t["TagKey"]] = t["TagValue"]
        except Exception:  # noqa: BLE001
            pass

        origin = md.get("Origin", "AWS_KMS")
        hardware = origin in ("AWS_CLOUDHSM",) or bool(md.get("CustomKeyStoreId"))
        # AWS KMS itself runs on FIPS 140-3 L3 validated HSMs; treat as hardware-backed unless external.
        if origin == "AWS_KMS":
            hardware = True
        created = md.get("CreationDate")
        if created and created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        expires = md.get("ValidTo") or md.get("DeletionDate")
        if expires and expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)

        name = names[0].removeprefix("alias/") if names else md["KeyId"]
        used_by = self._consumers(kms, md["KeyId"]) if self.include_consumers else []
        return self.asset(
            used_by=used_by,
            kind=KIND_KEY,
            name=name,
            native_id=md["Arn"],
            algorithm=alg,
            key_size=size,
            curve=curve,
            key_type="secret-key" if spec.startswith(("SYMMETRIC", "HMAC")) else "private-key",
            purposes=purposes,
            created=created,
            expires=expires,
            state=KEY_STATES.get(md.get("KeyState", ""), STATE_UNKNOWN),
            rotation_enabled=rotation,
            exportable=origin == "EXTERNAL",  # imported material exists outside KMS by definition
            hardware_backed=hardware,
            fips_validated=origin == "AWS_KMS" or hardware,
            location=f"{md.get('Arn', '').split(':')[3] if md.get('Arn') else ''} {origin}",
            tags=tags,
            extra={
                "key_id": md["KeyId"],
                "aliases": names,
                "key_spec": spec,
                "key_usage": usage,
                "origin": origin,
                "key_manager": md.get("KeyManager"),
                "multi_region": md.get("MultiRegion"),
                "custom_key_store_id": md.get("CustomKeyStoreId"),
                "rotation_period_days": rotation_period,
                "description": md.get("Description"),
            },
        )
