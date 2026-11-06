"""Configuration: a YAML file listing sources, plus which policy to apply.

    policy: default                # or a path to your own policy YAML
    sources:
      - name: prod-hsm
        type: pkcs11
        module: /usr/lib/libCryptoki2_64.so
        token_label: payments
        pin_env: HSM_PIN
      - name: vault
        type: vault
        url: https://vault.example.com:8200
        token_env: VAULT_TOKEN

Optionally, `applications:` declares which application uses which key (see
keycensus.linking) and `linking: {auto_match: true}` tunes the automatic matching.

Secrets are referenced by environment variable (`*_env`), file (`*_file`), or a secret
store (`*_vault`, `*_aws_secret`, `*_azure_secret`, `*_gcp_secret`; see keycensus.secrets),
never written into the YAML. Optional top-level blocks: `secrets:` (secret store settings),
`serve:` (listen address, auth, TLS), `audit:` (hash-chained audit log), `signing:` (signed
scan records).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import secrets


class ConfigError(Exception):
    pass


@dataclass
class SourceConfig:
    name: str
    type: str
    options: dict[str, Any] = field(default_factory=dict)

    def secret(self, key: str, required: bool = False) -> str | None:
        """Resolve `<key>_file`, `<key>_env`, a secret store reference, then plain `<key>`."""
        try:
            return secrets.resolve(self.options, key, owner=self.name, required=required)
        except secrets.SecretError as exc:
            raise ConfigError(str(exc)) from exc


@dataclass
class Config:
    sources: list[SourceConfig]
    policy: str = "default"
    serve: dict[str, Any] = field(default_factory=dict)
    applications: list[dict[str, Any]] = field(default_factory=list)  # see keycensus.linking
    auto_match: bool = True
    notifications: dict[str, Any] | None = None  # see keycensus.notify; None = no block, {} = defaults
    change_urgency: dict[str, str] = field(default_factory=dict)  # see keycensus.changes
    base_dir: str | None = None  # directory of the config file; relative SBOM paths resolve against it
    audit: dict[str, Any] | None = None  # see keycensus.audit
    signing: dict[str, Any] | None = None  # see keycensus.signing
    config_sha256: str | None = None  # of the config file as loaded, for the audit log and signed manifests
    cbom_version: str = "1.6"  # `cbom: {version: "1.7"}`; see keycensus.exporters.cbom


def load(path: str | Path) -> Config:
    data = Path(path).read_bytes()
    raw = yaml.safe_load(data) or {}
    secrets.configure(raw.get("secrets") or {})
    sources_raw = raw.get("sources") or []
    if not sources_raw:
        raise ConfigError(f"{path}: 'sources' list is empty")
    sources = []
    seen = set()
    for entry in sources_raw:
        if not isinstance(entry, dict) or not entry.get("name") or not entry.get("type"):
            raise ConfigError(f"{path}: every source needs 'name' and 'type': {entry!r}")
        if entry["name"] in seen:
            raise ConfigError(f"{path}: duplicate source name {entry['name']!r}")
        seen.add(entry["name"])
        opts = {k: v for k, v in entry.items() if k not in ("name", "type")}
        sources.append(SourceConfig(name=str(entry["name"]), type=str(entry["type"]), options=opts))
    apps = raw.get("applications") or []
    if not isinstance(apps, list):
        raise ConfigError(f"{path}: 'applications' must be a list")
    linking = raw.get("linking") or {}
    changes = raw.get("changes") or {}
    if not isinstance(changes, dict):
        raise ConfigError(f"{path}: 'changes' must be a mapping")
    cbom_block = raw.get("cbom") or {}
    if not isinstance(cbom_block, dict):
        raise ConfigError(f"{path}: 'cbom' must be a mapping")
    cbom_version = str(cbom_block.get("version", "1.6"))
    if cbom_version not in ("1.6", "1.7"):
        raise ConfigError(f"{path}: cbom.version is {cbom_version!r}; expected 1.6 or 1.7")
    for block in ("serve", "audit", "signing", "secrets"):
        if raw.get(block) is not None and not isinstance(raw.get(block), dict):
            raise ConfigError(f"{path}: '{block}' must be a mapping")
    urgency = changes.get("urgency") or {}
    if not isinstance(urgency, dict):
        raise ConfigError(f"{path}: 'changes.urgency' must be a mapping of change kind -> page|digest|ignore")
    from .changes import DEFAULT_URGENCY, URGENCIES  # noqa: PLC0415 - avoids a config <-> changes import cycle

    for kind, level in urgency.items():
        if level not in URGENCIES:
            raise ConfigError(f"{path}: changes.urgency[{kind}] is {level!r}; expected one of {', '.join(URGENCIES)}")
        if kind not in DEFAULT_URGENCY:
            raise ConfigError(
                f"{path}: changes.urgency[{kind}] is not a change kind keycensus emits. "
                "Run `keycensus changes --kinds` for the list."
            )
    return Config(
        sources=sources,
        policy=str(raw.get("policy", "default")),
        serve=raw.get("serve") or {},
        applications=apps,
        auto_match=bool(linking.get("auto_match", True)),
        notifications=raw.get("notifications"),
        change_urgency={str(k): str(v) for k, v in urgency.items()},
        base_dir=str(Path(path).resolve().parent),
        audit=raw.get("audit"),
        signing=raw.get("signing"),
        config_sha256=hashlib.sha256(data).hexdigest(),
        cbom_version=cbom_version,
    )
