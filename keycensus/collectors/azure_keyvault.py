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

    # ------------------------------------------------------------ auth
    def _token(self) -> str:
        if str(self.opt.get("auth", "default")) == "token":
            return self.cfg.secret("token", required=True)
        from azure.identity import DefaultAzureCredential  # noqa: PLC0415 - optional dependency

        scope = "https://managedhsm.azure.net/.default" if self.managed_hsm else "https://vault.azure.net/.default"
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
