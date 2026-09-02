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

Secrets are referenced by environment variable (`*_env`) or file (`*_file`),
never written into the YAML.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    pass


@dataclass
class SourceConfig:
    name: str
    type: str
    options: dict[str, Any] = field(default_factory=dict)

    def secret(self, key: str, required: bool = False) -> str | None:
        """Resolve `<key>_file`, then `<key>_env`, then plain `<key>`."""
        if self.options.get(f"{key}_file"):
            p = Path(self.options[f"{key}_file"])
            if not p.exists():
                raise ConfigError(f"[{self.name}] {key}_file {p} does not exist")
            return p.read_text().strip()
        if self.options.get(f"{key}_env"):
            val = os.environ.get(self.options[f"{key}_env"])
            if not val and required:
                raise ConfigError(f"[{self.name}] env var {self.options[f'{key}_env']} is not set")
            return val
        val = self.options.get(key)
        if val is None and required:
            raise ConfigError(f"[{self.name}] needs {key}, {key}_env or {key}_file")
        return str(val) if val is not None else None


@dataclass
class Config:
    sources: list[SourceConfig]
    policy: str = "default"
    serve: dict[str, Any] = field(default_factory=dict)
    applications: list[dict[str, Any]] = field(default_factory=list)  # see keycensus.linking
    auto_match: bool = True
    base_dir: str | None = None  # directory of the config file; relative SBOM paths resolve against it


def load(path: str | Path) -> Config:
    with open(path) as fh:
        raw = yaml.safe_load(fh) or {}
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
    return Config(
        sources=sources,
        policy=str(raw.get("policy", "default")),
        serve=raw.get("serve") or {},
        applications=apps,
        auto_match=bool(linking.get("auto_match", True)),
        base_dir=str(Path(path).resolve().parent),
    )
