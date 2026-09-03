"""Collector: Azure Key Vault and Azure Managed HSM (keys + certificates).

    - name: kv-payments
      type: azure-keyvault
      vault_url: https://payments-kv.vault.azure.net          # Key Vault
      # vault_url: https://payments-hsm.managedhsm.azure.net  # Managed HSM (FIPS 140-3 L3, single-tenant)
      auth: default            # default (DefaultAzureCredential) | token (a bearer token from token_env/_file)
      token_env: AZURE_TOKEN   # only with auth: token -- CI, tests, `az account get-access-token`
      include_certificates: true
      include_disabled: true
      api_version: "7.5"

      # Who can use these keys -> asset.used_by (docs/COLLECTORS.md#azure-rbac-consumers)
      include_rbac: true
      subscription_id: 00000000-0000-0000-0000-000000000000   # or $AZURE_SUBSCRIPTION_ID
      # resource_id: /subscriptions/.../resourceGroups/rg/providers/Microsoft.KeyVault/vaults/payments-kv
      resolve_principal_names: false   # needs Microsoft Graph Directory.Read.All; off by default

Talks to the data-plane REST API directly with `requests` (no SDK needed at runtime);
`pip install 'keycensus[azure]'` adds `azure-identity` for `auth: default` (managed
identity, workload identity, `az login`, service principal env vars -- the usual chain).

Needs the *Key Vault Reader* / *Key Vault Crypto User*-style permissions (`keys/list`,
`keys/get`, `keys/getrotationpolicy`, `certificates/list`, `certificates/get`) on the
vault, or the `Managed HSM Crypto Auditor` role on a Managed HSM. It never reads key
material or secrets.

What maps to what:

* `kty` RSA / RSA-HSM / EC / EC-HSM / oct / oct-HSM -> algorithm, `hardware_backed` for
  the `-HSM` kinds (and everything on a Managed HSM), `crv` -> curve, `n` length -> RSA size.
* `attributes.enabled/created/updated/exp/nbf/exportable/recoveryLevel/hsmPlatform`.
* the rotation policy (`lifetimeActions` with a `Rotate` action) -> `rotation_enabled`.
* certificates: the public `cer` is parsed like any other certificate; the backing key is
  also listed as a key, so both appear.

**Consumers (`include_rbac`).** Azure has three separate authorization models for this, and the
collector reads whichever one the vault actually uses:

* **RBAC vaults** (`enableRbacAuthorization: true`) -- ARM role assignments at the vault scope.
  Needs `Microsoft.Authorization/roleAssignments/read` and `Microsoft.KeyVault/vaults/read`
  (the built-in *Reader* role covers both) on the **management** plane, which is a different
  endpoint and a different token audience from everything else in this collector.
* **Access-policy vaults** (the older model) -- `properties.accessPolicies` on the vault resource,
  read from the same ARM call.
* **Managed HSM** -- local RBAC, served by the HSM's own data plane, so no ARM and no extra
  permission beyond what listing keys already needs.

A 403 on any of it is tolerated: no consumer information is worse than no inventory.

Principals come back as object ids (GUIDs), because ARM does not resolve names. Set
`resolve_principal_names: true` to look them up in Microsoft Graph -- that needs
`Directory.Read.All`, which is a large permission, so it is off by default and the GUIDs are
reported as-is. GUIDs still link fine through an explicit `principal:` selector in
`applications:`; automatic name matching needs the names.
"""

from __future__ import annotations

import base64
import logging
from datetime import UTC, datetime
from urllib.parse import urlparse

import requests
from cryptography import x509

from ..model import (
    ALG_AES,
    ALG_EC,
    ALG_RSA,
    ALG_UNKNOWN,
    KIND_KEY,
    STATE_ACTIVE,
    STATE_DEACTIVATED,
    STATE_PRE_ACTIVATION,
    CryptoAsset,
)
from .base import Collector
from .x509util import certificate_fields

log = logging.getLogger(__name__)

CURVES = {"P-256": ("P-256", 256), "P-384": ("P-384", 384), "P-521": ("P-521", 521), "P-256K": ("secp256k1", 256)}
OPS = {
    "encrypt": "encrypt",
    "decrypt": "decrypt",
    "sign": "sign",
    "verify": "verify",
    "wrapKey": "wrap",
    "unwrapKey": "unwrap",
    "import": "import",
    "export": "export",
}


class AzureKeyVaultCollector(Collector):
    type_name = "azure-keyvault"
    requires_extra = "azure"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.url = str(self.opt.get("vault_url", "")).rstrip("/")
        if not self.url:
            raise ValueError(f"[{self.name}] vault_url is required")
        host = urlparse(self.url).hostname or ""
        self.managed_hsm = "managedhsm" in host
        self.api_version = str(self.opt.get("api_version", "7.5"))
        self.timeout = float(self.opt.get("timeout", 15))
        self.session = requests.Session()
        self.session.headers["Accept"] = "application/json"

        # Consumers. The management plane is a different endpoint, a different
        # token audience and a different set of permissions from the data plane,
        # so it gets its own everything.
        self.include_rbac = bool(self.opt.get("include_rbac", True))
        self.arm_endpoint = str(self.opt.get("arm_endpoint", "https://management.azure.com")).rstrip("/")
        self.arm_api_version = str(self.opt.get("arm_api_version", "2023-07-01"))
        self.rbac_api_version = str(self.opt.get("rbac_api_version", "2022-04-01"))
        self.graph_endpoint = str(self.opt.get("graph_endpoint", "https://graph.microsoft.com")).rstrip("/")
        self.resolve_names = bool(self.opt.get("resolve_principal_names", False))
        self.vault_name = host.split(".", 1)[0]
        self._role_names: dict[str, str] = {}  # roleDefinitionId -> display name, cached per run
        self._principals: dict[str, str] = {}  # objectId -> display name

    # ------------------------------------------------------------ auth
    def _token(self, audience: str | None = None) -> str:
        """Bearer token for one audience. `auth: token` supplies the data-plane one
        directly; a management-plane call then needs `arm_token_env` as well, because
        one token is never valid for two audiences."""
        if str(self.opt.get("auth", "default")) == "token":
            if audience == "arm":
                return self.cfg.secret("arm_token", required=True)
            if audience == "graph":
                return self.cfg.secret("graph_token", required=True)
            return self.cfg.secret("token", required=True)
        from azure.identity import DefaultAzureCredential  # noqa: PLC0415 - optional dependency

        scope = {
            "arm": f"{self.arm_endpoint}/.default",
            "graph": f"{self.graph_endpoint}/.default",
        }.get(audience or "", "https://managedhsm.azure.net/.default" if self.managed_hsm
              else "https://vault.azure.net/.default")  # fmt: skip
        cred_kwargs = {}
        if self.opt.get("authority"):
            cred_kwargs["authority"] = self.opt["authority"]
        return DefaultAzureCredential(**cred_kwargs).get_token(scope).token

    # ------------------------------------------------------------ http
    def _get(self, path_or_url: str, params: dict | None = None):
        url = path_or_url if path_or_url.startswith("http") else f"{self.url}/{path_or_url.lstrip('/')}"
        p = {} if "api-version=" in url else {"api-version": self.api_version}  # nextLink already carries it
        p.update(params or {})
        r = self.session.get(url, params=p, timeout=self.timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"GET {url} -> {r.status_code}: {r.text[:200]}")
        return r.json()

    def _paged(self, path: str) -> list[dict]:
        out: list[dict] = []
        nxt: str | None = path
        params = {"maxresults": 25}
        while nxt:
            page = self._get(nxt, params if nxt == path else None)
            out.extend(page.get("value") or [])
            nxt = page.get("nextLink")
        return out

    # ------------------------------------------------------------ consumers
    # Roles that let the holder USE a key, as opposed to seeing that it exists.
    # Matched on the role definition's display name, because the built-in role
    # GUIDs are stable but unreadable and custom roles have neither.
    _USE_ROLES = (
        "Key Vault Crypto User",
        "Key Vault Crypto Officer",
        "Key Vault Crypto Service Encryption User",
        "Key Vault Crypto Service Release User",
        "Key Vault Certificates Officer",
        "Key Vault Certificate User",
        "Key Vault Secrets User",
        "Key Vault Secrets Officer",
        "Key Vault Administrator",
        "Managed HSM Crypto User",
        "Managed HSM Crypto Officer",
        "Managed HSM Administrator",
        "Owner",
        "Contributor",
    )
    # Key Vault Reader / Managed HSM Crypto Auditor can list but not use, so they
    # are consumers of the inventory, not of the keys. Left out on purpose.

    _PRINCIPAL_KINDS = {
        "ServicePrincipal": "service",
        "User": "user",
        "Group": "group",
        "ForeignGroup": "group",
        "Device": "device",
    }

    def _arm_get(self, url: str, params: dict | None = None) -> dict:
        r = self.session.get(
            url,
            params=params,
            timeout=self.timeout,
            headers={"Authorization": f"Bearer {self._token('arm')}"},
        )
        if r.status_code >= 400:
            raise RuntimeError(f"GET {url} -> {r.status_code}: {r.text[:200]}")
        return r.json()

    def _resource_id(self) -> str | None:
        """The vault's ARM id. Given explicitly, or found by name in a subscription."""
        rid = self.opt.get("resource_id")
        if rid:
            return str(rid)
        sub = self.opt.get("subscription_id") or self.cfg.secret("subscription_id", required=False)
        if not sub:
            log.info(
                "[%s] include_rbac is on but neither resource_id nor subscription_id is set, and the vault URL "
                "does not carry either -- skipping consumers. Set subscription_id (or $AZURE_SUBSCRIPTION_ID).",
                self.name,
            )
            return None
        url = f"{self.arm_endpoint}/subscriptions/{sub}/resources"
        page = self._arm_get(url, {
            "api-version": "2021-04-01",
            "$filter": f"resourceType eq 'Microsoft.KeyVault/vaults' and name eq '{self.vault_name}'",
        })  # fmt: skip
        for item in page.get("value") or []:
            return str(item.get("id"))
        log.info("[%s] vault %s not found in subscription %s", self.name, self.vault_name, sub)
        return None

    def _role_name(self, role_definition_id: str) -> str:
        if role_definition_id not in self._role_names:
            try:
                doc = self._arm_get(f"{self.arm_endpoint}{role_definition_id}", {"api-version": self.rbac_api_version})
                self._role_names[role_definition_id] = str(
                    (doc.get("properties") or {}).get("roleName") or role_definition_id.rsplit("/", 1)[-1]
                )
            except RuntimeError as exc:
                log.debug("[%s] role definition %s: %s", self.name, role_definition_id, exc)
                self._role_names[role_definition_id] = role_definition_id.rsplit("/", 1)[-1]
        return self._role_names[role_definition_id]

    def _principal_name(self, object_id: str) -> str | None:
        """Microsoft Graph lookup. Off unless resolve_principal_names is set, because
        Directory.Read.All is a much larger permission than reading an inventory."""
        if not self.resolve_names or not object_id:
            return None
        if object_id in self._principals:
            return self._principals[object_id]
        try:
            r = self.session.get(
                f"{self.graph_endpoint}/v1.0/directoryObjects/{object_id}",
                timeout=self.timeout,
                headers={"Authorization": f"Bearer {self._token('graph')}"},
            )
            name = r.json().get("displayName") if r.status_code < 400 else None
        except Exception as exc:  # noqa: BLE001 - a name is a nicety, never a failure
            log.debug("[%s] graph lookup %s: %s", self.name, object_id, exc)
            name = None
        self._principals[object_id] = name
        return name

    def _rbac_consumers(self) -> list[dict]:
        """ARM role assignments at the vault scope, plus legacy access policies."""
        rid = self._resource_id()
        if not rid:
            return []
        out: list[dict] = []
        try:
            vault = self._arm_get(f"{self.arm_endpoint}{rid}", {"api-version": self.arm_api_version})
        except RuntimeError as exc:
            log.info("[%s] cannot read the vault resource (%s); no consumers reported", self.name, exc)
            return []

        props = vault.get("properties") or {}
        if props.get("enableRbacAuthorization"):
            try:
                page = self._arm_get(
                    f"{self.arm_endpoint}{rid}/providers/Microsoft.Authorization/roleAssignments",
                    {"api-version": self.rbac_api_version, "$filter": "atScope()"},
                )
            except RuntimeError as exc:
                log.info("[%s] role assignments unreadable (%s); no consumers reported", self.name, exc)
                return []
            out.extend(self._from_role_assignments(page.get("value") or []))
        else:
            out.extend(self._from_access_policies(props.get("accessPolicies") or []))
        return out

    def _from_role_assignments(self, assignments: list[dict]) -> list[dict]:
        out, seen = [], set()
        for a in assignments:
            p = a.get("properties") or {}
            role = self._role_name(str(p.get("roleDefinitionId", "")))
            if not any(r.lower() in role.lower() for r in self._USE_ROLES):
                continue
            oid = str(p.get("principalId", ""))
            if not oid or (oid, role) in seen:
                continue
            seen.add((oid, role))
            entry = {
                "type": self._PRINCIPAL_KINDS.get(str(p.get("principalType", "")), "principal"),
                "id": self._principal_name(oid) or oid,
                "via": f"rbac:{role}",
            }
            if entry["id"] != oid:
                entry["object_id"] = oid  # keep the GUID when a name was resolved
            out.append(entry)
        return out

    def _from_access_policies(self, policies: list[dict]) -> list[dict]:
        """The pre-RBAC model: permissions are attached to the vault, not to a role."""
        out, seen = [], set()
        for pol in policies:
            perms = pol.get("permissions") or {}
            keys = [str(x).lower() for x in (perms.get("keys") or [])]
            certs = [str(x).lower() for x in (perms.get("certificates") or [])]
            # "list" and "get" are inventory rights; anything else is use.
            using = sorted(set(keys + certs) - {"list", "get", "getrotationpolicy", "listissuers", "getissuers"})
            if not using:
                continue
            oid = str(pol.get("objectId", ""))
            if not oid or oid in seen:
                continue
            seen.add(oid)
            entry = {
                "type": "principal",
                "id": self._principal_name(oid) or oid,
                "via": "access-policy:" + ",".join(using[:6]),
            }
            if entry["id"] != oid:
                entry["object_id"] = oid
            out.append(entry)
        return out

    def _managed_hsm_consumers(self) -> list[dict]:
        """Managed HSM keeps its RBAC in its own data plane -- same token, no ARM."""
        try:
            page = self._get("providers/Microsoft.Authorization/roleAssignments", {"$filter": "atScope()"})
        except RuntimeError as exc:
            log.info("[%s] local RBAC unreadable (%s); no consumers reported", self.name, exc)
            return []
        out, seen = [], set()
        for a in page.get("value") or []:
            p = a.get("properties") or {}
            role = str(p.get("roleDefinitionId", "")).rsplit("/", 1)[-1]
            oid = str(p.get("principalId", ""))
            if not oid or oid in seen:
                continue
            seen.add(oid)
            out.append({
                "type": self._PRINCIPAL_KINDS.get(str(p.get("principalType", "")), "principal"),
                "id": self._principal_name(oid) or oid,
                "via": f"local-rbac:{role}",
            })  # fmt: skip
        return out

    # ------------------------------------------------------------ collect
    def collect(self) -> list[CryptoAsset]:
        self.session.headers["Authorization"] = f"Bearer {self._token()}"
        include_disabled = bool(self.opt.get("include_disabled", True))
        assets: list[CryptoAsset] = []
        for item in self._paged("keys"):
            kid = item.get("kid") or ""
            attrs = item.get("attributes") or {}
            if attrs.get("enabled") is False and not include_disabled:
                continue
            key = self._get(kid)  # current version, full JWK (public part only)
            assets.append(self._key_asset(key, attrs))
        if bool(self.opt.get("include_certificates", True)):
            for item in self._paged("certificates"):
                cid = item.get("id") or ""
                cert = self._get(cid)
                asset = self._cert_asset(cert)
                if asset:
                    assets.append(asset)

        # Consumers are a property of the vault, not of one key: Azure authorizes
        # at the vault scope (role assignments and access policies both), so every
        # asset in this vault carries the same list. Where AWS grants and GCP IAM
        # bindings are per key, this is not, and pretending otherwise would invent
        # precision the platform does not have.
        if self.include_rbac and assets:
            consumers = self._managed_hsm_consumers() if self.managed_hsm else self._rbac_consumers()
            if consumers:
                log.info("[%s] %d consumer(s) at the vault scope", self.name, len(consumers))
                for a in assets:
                    a.used_by = list(consumers)
        return assets

    # ------------------------------------------------------------ mapping
    def _key_asset(self, data: dict, list_attrs: dict) -> CryptoAsset:
        jwk = data.get("key") or {}
        attrs = data.get("attributes") or list_attrs or {}
        kid = jwk.get("kid") or data.get("kid") or ""
        name, version = _split_kid(kid)
        kty = str(jwk.get("kty", ""))
        hsm = kty.endswith("-HSM") or self.managed_hsm or bool(attrs.get("hsmPlatform"))
        base = kty.replace("-HSM", "")
        alg, size, curve = ALG_UNKNOWN, None, None
        if base == "RSA":
            alg, size = ALG_RSA, _b64_bits(jwk.get("n"))
        elif base == "EC":
            alg = ALG_EC
            curve, size = CURVES.get(jwk.get("crv", ""), (jwk.get("crv"), None))
        elif base == "oct":
            alg, size = ALG_AES, _b64_bits(jwk.get("k")) or attrs.get("key_size") or None
        purposes = [OPS[o] for o in jwk.get("key_ops") or [] if o in OPS]
        rotation = self._rotation(name) if base != "oct" or self.managed_hsm else None
        enabled = attrs.get("enabled", True)
        nbf = _ts(attrs.get("nbf"))
        state = STATE_ACTIVE if enabled else STATE_DEACTIVATED
        if enabled and nbf and nbf > datetime.now(UTC):
            state = STATE_PRE_ACTIVATION
        return self.asset(
            kind=KIND_KEY,
            name=name,
            native_id=kid.rsplit("/", 1)[0] if version else kid,  # version-less id: stable across rotations
            algorithm=alg,
            key_size=size,
            curve=curve,
            key_type="secret-key" if base == "oct" else "private-key",
            purposes=purposes,
            created=_ts(attrs.get("created")),
            last_rotated=_ts(attrs.get("created")),  # the current version's creation is the last rotation
            expires=_ts(attrs.get("exp")),
            state=state,
            rotation_enabled=rotation,
            exportable=bool(attrs.get("exportable", False)),
            hardware_backed=hsm,
            fips_validated=hsm,  # Key Vault HSM pool and Managed HSM are FIPS 140-3 Level 3 validated
            location=f"{'Managed HSM' if self.managed_hsm else 'Key Vault'} {urlparse(self.url).hostname}",
            tags={k: str(v) for k, v in (data.get("tags") or {}).items()},
            extra={
                "kty": kty,
                "version": version,
                "key_ops": jwk.get("key_ops"),
                "recovery_level": attrs.get("recoveryLevel"),
                "hsm_platform": attrs.get("hsmPlatform"),
                "updated": attrs.get("updated"),
                "managed": data.get("managed"),
                "release_policy": bool(data.get("release_policy")),
            },
        )

    def _rotation(self, name: str) -> bool | None:
        try:
            pol = self._get(f"keys/{name}/rotationpolicy")
        except RuntimeError as exc:  # 404 = no policy on this vault/key, 403 = not permitted
            log.debug("[%s] rotation policy for %s: %s", self.name, name, exc)
            return None
        for la in pol.get("lifetimeActions") or []:
            if str((la.get("action") or {}).get("type", "")).lower() == "rotate":
                return True
        return False

    def _cert_asset(self, data: dict) -> CryptoAsset | None:
        cer = data.get("cer")
        if not cer:
            return None
        try:
            cert = x509.load_der_x509_certificate(base64.b64decode(cer))
        except ValueError:
            log.warning("[%s] certificate %s: cannot parse 'cer'", self.name, data.get("id"))
            return None
        cid = data.get("id") or ""
        name, version = _split_kid(cid)
        attrs = data.get("attributes") or {}
        fields = certificate_fields(cert)
        policy = data.get("policy") or {}
        key_props = policy.get("key_props") or {}
        hsm = str(key_props.get("kty", "")).endswith("-HSM") or self.managed_hsm
        state = fields.get("state")
        if attrs.get("enabled") is False:
            state = STATE_DEACTIVATED
        return self.asset(
            source_type="azure-keyvault-cert",
            native_id=cid.rsplit("/", 1)[0] if version else cid,
            location=f"Key Vault {urlparse(self.url).hostname} certificates/{name}",
            hardware_backed=hsm,
            rotation_enabled=bool(policy.get("lifetime_actions")) or None,
            exportable=bool(key_props.get("exportable", True)),
            tags={k: str(v) for k, v in (data.get("tags") or {}).items()},
            extra={
                **fields.pop("extra"),
                "version": version,
                "issuer_provider": (policy.get("issuer") or {}).get("name"),
                "kid": data.get("kid"),
                "sid": data.get("sid"),
            },
            **{**fields, "name": name or fields["name"], "state": state},
        )


def _split_kid(kid: str) -> tuple[str, str | None]:
    """https://v.vault.azure.net/keys/<name>/<version> -> (name, version)."""
    parts = [p for p in urlparse(kid).path.split("/") if p]
    if len(parts) >= 3:
        return parts[1], parts[2]
    if len(parts) == 2:
        return parts[1], None
    return kid, None


def _b64_bits(value: str | None) -> int | None:
    if not value:
        return None
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    return len(raw) * 8


def _ts(value) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value), UTC)
    except (TypeError, ValueError, OSError):
        return None
