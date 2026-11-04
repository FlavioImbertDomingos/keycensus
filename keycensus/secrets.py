"""Where a secret comes from. Every `<key>` option that holds a credential can be given as:

    password_env: CTM_PASSWORD                                   # environment variable
    password_file: /run/secrets/ctm                              # file (trailing newline stripped)
    password_vault: secret/data/keycensus#ctm_password           # HashiCorp Vault KV (v1 or v2), field after #
    password_aws_secret: arn:aws:secretsmanager:...:secret:kc#ctm  # AWS Secrets Manager; #field reads JSON
    password_azure_secret: https://kc-kv.vault.azure.net/secrets/ctm-password   # Azure Key Vault secret
    password_gcp_secret: projects/acme/secrets/ctm-password      # GCP Secret Manager (latest version)
    password: inline-value                                       # last resort, and only where allowed

Checked in that order; the first one present wins. The backends are configured once, at the top
of the config file, and only the ones you use are ever contacted:

    secrets:
      vault:
        url: https://vault.example.com:8200        # else $VAULT_ADDR
        auth: token                                 # token | kubernetes
        token_env: VAULT_TOKEN                      # auth: token (default $VAULT_TOKEN)
        role: keycensus                             # auth: kubernetes
        mount: kubernetes                           # auth: kubernetes, the auth mount path
        namespace: ops                              # Vault Enterprise, optional
        verify_tls: true                            # true | false | CA bundle path
      aws: {region: us-east-1, profile: secrets}    # optional; else the default boto3 chain
      azure: {}                                      # DefaultAzureCredential
      cache_seconds: 300                             # how long a fetched secret is reused

Values are never logged. `describe()` returns the reference (env var name, Vault path, ARN), which
is what the audit log records as the credential identity of a scan.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

import requests

log = logging.getLogger(__name__)

BACKENDS = ("file", "env", "vault", "aws_secret", "azure_secret", "gcp_secret")


class SecretError(Exception):
    pass


_settings: dict[str, Any] = {}
_cache: dict[str, tuple[float, str]] = {}
_lock = threading.Lock()
_vault_token: str | None = None


def configure(settings: dict[str, Any] | None) -> None:
    global _settings, _vault_token
    with _lock:
        _settings = dict(settings or {})
        _cache.clear()
        _vault_token = None


def references(options: dict[str, Any], key: str) -> dict[str, str]:
    """{backend: reference} for every way `key` is configured in these options."""
    return {b: str(options[f"{key}_{b}"]) for b in BACKENDS if options.get(f"{key}_{b}")}


def describe(options: dict[str, Any]) -> list[str]:
    """Every credential reference in a block of options, for the audit log: never values."""
    out = []
    for k, v in sorted(options.items()):
        for b in BACKENDS:
            if k.endswith(f"_{b}") and v:
                out.append(f"{k}={v}")
    return out


def resolve(options: dict[str, Any], key: str, owner: str = "", required: bool = False,
            allow_inline: bool = True) -> str | None:  # fmt: skip
    """The secret `key` from these options, via whichever backend is configured."""
    refs = references(options, key)
    where = f"[{owner}] " if owner else ""
    for backend in BACKENDS:
        if backend not in refs:
            continue
        ref = refs[backend]
        if backend == "env":
            val = os.environ.get(ref)
            if not val and required:
                raise SecretError(f"{where}env var {ref} is not set")
            return val
        if backend == "file":
            p = Path(ref)
            if not p.exists():
                raise SecretError(f"{where}{key}_file {p} does not exist")
            return p.read_text().strip()
        try:
            return _cached(f"{backend}:{ref}", lambda b=backend, r=ref: _FETCH[b](r))
        except SecretError:
            raise
        except Exception as exc:  # noqa: BLE001 - name the reference, never the value
            raise SecretError(f"{where}{key}_{backend} {ref}: {type(exc).__name__}: {exc}") from exc
    val = options.get(key)
    if val is not None and allow_inline:
        return str(val)
    if required:
        hint = ", ".join(f"{key}_{b}" for b in BACKENDS)
        raise SecretError(f"{where}needs {key} as one of: {hint}")
    return None


def _cached(cache_key: str, fetch) -> str:
    ttl = float(_settings.get("cache_seconds", 300))
    now = time.monotonic()
    with _lock:
        hit = _cache.get(cache_key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    value = fetch()
    with _lock:
        _cache[cache_key] = (now, value)
    return value


def _field(text: str, field: str | None, ref: str) -> str:
    if not field:
        return text
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise SecretError(f"{ref}: #{field} given but the secret is not JSON") from exc
    if field not in data:
        raise SecretError(f"{ref}: no field {field!r} in the secret")
    return str(data[field])


# ---------------------------------------------------------------- HashiCorp Vault
def _vault_cfg() -> dict[str, Any]:
    return dict(_settings.get("vault") or {})


def _vault_session() -> tuple[requests.Session, str]:
    global _vault_token
    cfg = _vault_cfg()
    url = str(cfg.get("url") or os.environ.get("VAULT_ADDR") or "").rstrip("/")
    if not url:
        raise SecretError("a *_vault secret needs secrets.vault.url or $VAULT_ADDR")
    s = requests.Session()
    verify = cfg.get("verify_tls", True)
    s.verify = verify if isinstance(verify, str) else bool(verify)
    if cfg.get("namespace"):
        s.headers["X-Vault-Namespace"] = str(cfg["namespace"])
    if _vault_token is None:
        auth = str(cfg.get("auth", "token"))
        if auth == "token":
            token = os.environ.get(str(cfg.get("token_env", "VAULT_TOKEN")))
            if not token and cfg.get("token_file"):
                token = Path(str(cfg["token_file"])).read_text().strip()
            if not token:
                raise SecretError("Vault auth: token, but no token in token_env / token_file / $VAULT_TOKEN")
            _vault_token = token
        elif auth == "kubernetes":
            jwt_path = str(cfg.get("jwt_file", "/var/run/secrets/kubernetes.io/serviceaccount/token"))
            mount = str(cfg.get("mount", "kubernetes")).strip("/")
            r = s.post(
                f"{url}/v1/auth/{mount}/login",
                timeout=10,
                json={"role": cfg.get("role", "keycensus"), "jwt": Path(jwt_path).read_text().strip()},
            )
            if r.status_code >= 400:
                raise SecretError(f"Vault kubernetes login -> {r.status_code}")
            _vault_token = r.json()["auth"]["client_token"]
        else:
            raise SecretError(f"secrets.vault.auth must be token or kubernetes, not {auth!r}")
    s.headers["X-Vault-Token"] = _vault_token
    return s, url


def _fetch_vault(ref: str) -> str:
    path, _, field = ref.partition("#")
    s, url = _vault_session()
    r = s.get(f"{url}/v1/{path.strip('/')}", timeout=10)
    if r.status_code >= 400:
        raise SecretError(f"Vault GET {path} -> {r.status_code}")
    data = r.json().get("data") or {}
    if isinstance(data.get("data"), dict) and "metadata" in data:  # KV v2 wraps the payload
        data = data["data"]
    if not field:
        if len(data) != 1:
            raise SecretError(f"Vault {path} holds {len(data)} fields; name one with #field")
        return str(next(iter(data.values())))
    if field not in data:
        raise SecretError(f"Vault {path}: no field {field!r}")
    return str(data[field])


# ---------------------------------------------------------------- AWS Secrets Manager
def _fetch_aws(ref: str) -> str:
    import boto3  # noqa: PLC0415 - optional extra

    secret_id, _, field = ref.partition("#")
    cfg = dict(_settings.get("aws") or {})
    region = cfg.get("region")
    if not region and secret_id.startswith("arn:"):
        region = secret_id.split(":")[3]
    session = boto3.session.Session(profile_name=cfg["profile"]) if cfg.get("profile") else boto3.session.Session()
    kwargs = {"region_name": region}
    if cfg.get("endpoint_url"):
        kwargs["endpoint_url"] = cfg["endpoint_url"]
    resp = session.client("secretsmanager", **kwargs).get_secret_value(SecretId=secret_id)
    text = resp.get("SecretString")
    if text is None:
        text = base64.b64decode(resp["SecretBinary"]).decode() if isinstance(resp["SecretBinary"], str) \
            else resp["SecretBinary"].decode()  # fmt: skip
    return _field(text, field or None, secret_id)


# ---------------------------------------------------------------- Azure Key Vault
def _fetch_azure(ref: str) -> str:
    url, _, field = ref.partition("#")
    cfg = dict(_settings.get("azure") or {})
    token = os.environ.get(str(cfg["token_env"])) if cfg.get("token_env") else None
    if not token:
        from azure.identity import DefaultAzureCredential  # noqa: PLC0415 - optional extra

        host = url.split("/")[2]
        scope = "https://managedhsm.azure.net/.default" if "managedhsm" in host else "https://vault.azure.net/.default"
        token = DefaultAzureCredential().get_token(scope).token
    r = requests.get(url, params={"api-version": "7.4"}, headers={"Authorization": f"Bearer {token}"}, timeout=10)
    if r.status_code >= 400:
        raise SecretError(f"Azure Key Vault GET {url} -> {r.status_code}")
    return _field(str(r.json()["value"]), field or None, url)


# ---------------------------------------------------------------- GCP Secret Manager
def _fetch_gcp(ref: str) -> str:
    name, _, field = ref.partition("#")
    if "/versions/" not in name:
        name = f"{name}/versions/latest"
    cfg = dict(_settings.get("gcp") or {})
    endpoint = str(cfg.get("endpoint", "https://secretmanager.googleapis.com")).rstrip("/")
    token = os.environ.get(str(cfg["token_env"])) if cfg.get("token_env") else None
    if token:
        session = requests.Session()
        session.headers["Authorization"] = f"Bearer {token}"
    else:
        import google.auth  # noqa: PLC0415 - optional extra
        from google.auth.transport.requests import AuthorizedSession  # noqa: PLC0415

        creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        session = AuthorizedSession(creds)
    r = session.get(f"{endpoint}/v1/{name}:access", timeout=10)
    if r.status_code >= 400:
        raise SecretError(f"GCP Secret Manager {name} -> {r.status_code}")
    text = base64.b64decode(r.json()["payload"]["data"]).decode()
    return _field(text, field or None, name)


_FETCH = {"vault": _fetch_vault, "aws_secret": _fetch_aws, "azure_secret": _fetch_azure, "gcp_secret": _fetch_gcp}
