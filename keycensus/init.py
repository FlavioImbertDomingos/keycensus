"""`keycensus init`: ask which sources you run, write the config, test each source, run the first scan.

Secrets are never asked for and never written: init asks for the name of the environment variable that holds
each one (`VAULT_TOKEN`, `HSM_PIN` ...) and checks that it is set. The config it writes uses `*_env`
references, like every keycensus config.

What init knows about each source type is in QUESTIONS: the few settings a first scan needs. Everything else
keeps its default and can be added to the file later (config/keycensus.example.yml lists them all).
"""

from __future__ import annotations

import importlib.util
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

TEXT, LIST, ENV, BOOL = "text", "list", "env", "bool"


@dataclass
class Question:
    key: str
    prompt: str
    kind: str = TEXT
    default: Any = None
    required: bool = False
    env_default: tuple[str, ...] = ()  # environment variables whose value is a better default


@dataclass
class SourceType:
    type: str
    name: str  # default source name
    questions: list[Question] = field(default_factory=list)
    module: str | None = None  # optional dependency the collector imports
    extra: str | None = None  # the pip extra that installs it
    fixed: dict[str, Any] = field(default_factory=dict)  # written as is
    note: str | None = None


QUESTIONS: dict[str, SourceType] = {
    t.type: t
    for t in (
        SourceType(
            "pem",
            "files",
            [Question("paths", "Folders or files with certificates and keys", LIST, ["."], required=True)],
        ),  # fmt: skip
        SourceType("code", "repo", [Question("paths", "Source code folders to scan", LIST, ["."], required=True)]),
        SourceType(
            "tls",
            "tls-endpoints",
            [Question("endpoints", "TLS endpoints (host:port, comma separated)", LIST, required=True)],
            fixed={"probe_pqc": True},
        ),  # fmt: skip
        SourceType(
            "ssh", "ssh-endpoints", [Question("endpoints", "SSH servers (host or host:port)", LIST, required=True)]
        ),  # fmt: skip
        SourceType(
            "network",
            "network",
            [Question("cidrs", "CIDR ranges to discover (only ranges you may scan)", LIST, required=True)],
        ),  # fmt: skip
        SourceType("ct", "public-certs", [Question("domains", "Your public domains", LIST, required=True)]),
        SourceType(
            "vault",
            "vault",
            [
                Question("url", "Vault address", TEXT, "https://vault.example.com:8200", True, ("VAULT_ADDR",)),
                Question("token", "Environment variable that holds the Vault token", ENV, "VAULT_TOKEN"),
                Question("namespace", "Vault namespace (blank for none)", TEXT, None, False, ("VAULT_NAMESPACE",)),
            ],
            note="Policy to grant: deploy/vault/keycensus-policy.hcl",
        ),
        SourceType(
            "aws-kms",
            "aws",
            [
                Question("region", "AWS region", TEXT, "us-east-1", True, ("AWS_REGION", "AWS_DEFAULT_REGION")),
                Question(
                    "profile", "AWS profile (blank for the default credentials)", TEXT, None, False, ("AWS_PROFILE",)
                ),
                Question("organization", "Scan every account in the AWS Organization?", BOOL, False),
            ],
            module="boto3",
            extra="aws",
            note="Policy to grant: deploy/aws/keycensus-scanner-policy.json",
        ),
        SourceType(
            "azure-keyvault",
            "azure",
            [
                Question("vault_url", "Key Vault URL (blank to discover every vault you can see)", TEXT),
            ],
            module="azure.identity",
            extra="azure",
            fixed={"auth": "default"},
            note="Role to grant: deploy/azure/keycensus-reader-role.json",
        ),
        SourceType(
            "gcp-kms",
            "gcp",
            [
                Question(
                    "project",
                    "GCP project (blank to discover every project you can see)",
                    TEXT,
                    None,
                    False,
                    ("GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT"),
                ),
            ],
            module="google.auth",
            extra="gcp",
            fixed={"auth": "default"},
            note="Role to grant: deploy/gcp/keycensus-kms-viewer-role.yaml",
        ),
        SourceType(
            "kubernetes",
            "cluster",
            [
                Question("context", "kubeconfig context (blank for the current one, or in-cluster)", TEXT),
                Question("namespaces", "Namespaces (blank for all)", LIST),
            ],
            module="kubernetes",
            extra="kubernetes",
            note="RBAC to apply: deploy/kubernetes/keycensus-reader.yaml",
        ),
        SourceType(
            "pkcs11",
            "hsm",
            [
                Question("module", "Path to the PKCS#11 library", TEXT, None, True),
                Question("token_label", "Token (partition) label", TEXT, None, True),
                Question("pin", "Environment variable that holds the PIN", ENV, "HSM_PIN"),
                Question("hardware_backed", "Is this a hardware HSM (not SoftHSM)?", BOOL, True),
            ],
            module="pkcs11",
            extra="pkcs11",
        ),
        SourceType(
            "adcs",
            "corp-pki",
            [
                Question("ldap_url", "Domain controller (ldaps://dc01.corp.example.com)", TEXT, None, True),
                Question("username", "Bind user (user@corp.example.com)", TEXT, None, True),
                Question("password", "Environment variable that holds the bind password", ENV, "ADCS_LDAP_PASSWORD"),
                Question("exports", "certutil -view CSV exports, one per CA (blank for none)", LIST),
            ],
            module="ldap3",
            extra="adcs",
        ),
        SourceType(
            "ciphertrust",
            "ciphertrust",
            [
                Question("url", "CipherTrust Manager URL", TEXT, None, True),
                Question("username", "User", TEXT, "keycensus"),
                Question("password", "Environment variable that holds the password", ENV, "CTM_PASSWORD"),
            ],
        ),
        SourceType(
            "keysafe5",
            "keysafe5",
            [
                Question("url", "KeySafe 5 URL", TEXT, None, True),
                Question("token", "Environment variable that holds the bearer token", ENV, "KS5_TOKEN"),
            ],
            fixed={"auth": "bearer"},
        ),
        SourceType(
            "voltage", "voltage", [Question("file", "Path to the Voltage key export (JSON or CSV)", TEXT, None, True)]
        ),  # fmt: skip
    )
}
ALIASES = {"files": "pem"}

_PKCS11_LIBS = (
    "/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/opt/homebrew/lib/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so",
    "/usr/safenet/lunaclient/lib/libCryptoki2_64.so", "/opt/nfast/toolkits/pkcs11/libcknfast.so",
)  # fmt: skip


def detect(env: dict[str, str] | None = None, home: Path | None = None) -> dict[str, str]:
    """Source types this machine looks set up for, with the reason: shown as hints, never acted on alone."""
    env = dict(os.environ if env is None else env)
    home = home or Path.home()
    found: dict[str, str] = {}
    if env.get("VAULT_ADDR"):
        found["vault"] = f"VAULT_ADDR is {env['VAULT_ADDR']}"
    if env.get("AWS_PROFILE") or env.get("AWS_ACCESS_KEY_ID") or (home / ".aws" / "credentials").exists():
        found["aws-kms"] = "AWS credentials are configured"
    if env.get("AZURE_CLIENT_ID") or (home / ".azure" / "azureProfile.json").exists():
        found["azure-keyvault"] = "Azure credentials are configured"
    if (
        env.get("GOOGLE_APPLICATION_CREDENTIALS")
        or (home / ".config" / "gcloud" / "application_default_credentials.json").exists()
    ):
        found["gcp-kms"] = "Google application default credentials exist"
    if env.get("KUBERNETES_SERVICE_HOST") or env.get("KUBECONFIG") or (home / ".kube" / "config").exists():
        found["kubernetes"] = "a kubeconfig or in-cluster service account exists"
    lib = next((p for p in _PKCS11_LIBS if Path(p).exists()), None)
    if lib:
        found["pkcs11"] = f"a PKCS#11 library is at {lib}"
    return found


def default_for(q: Question, stype: str, env: dict[str, str] | None = None) -> Any:
    env = dict(os.environ if env is None else env)
    for var in q.env_default:
        if env.get(var):
            return env[var]
    if stype == "pkcs11" and q.key == "module":
        return next((p for p in _PKCS11_LIBS if Path(p).exists()), None)
    if stype == "pkcs11" and q.key == "hardware_backed":
        mod = default_for(QUESTIONS["pkcs11"].questions[0], stype, env) or ""
        return "softhsm" not in str(mod).lower()
    return q.default


def parse_answer(q: Question, raw: Any) -> Any:
    """A typed answer from what was typed (or the default). None means: leave it out of the config."""
    if q.kind == BOOL:
        return raw if isinstance(raw, bool) else str(raw).strip().lower() in ("y", "yes", "true", "1")
    if q.kind == LIST:
        if isinstance(raw, list):
            return [str(x) for x in raw if str(x).strip()] or None
        items = [x.strip() for x in str(raw or "").split(",") if x.strip()]
        return items or None
    text = str(raw).strip() if raw is not None else ""
    return text or None


def source_block(stype: str, name: str, answers: dict[str, Any]) -> dict[str, Any]:
    st = QUESTIONS[stype]
    block: dict[str, Any] = {"name": name, "type": stype}
    for q in st.questions:
        v = answers.get(q.key)
        if v is None or (q.kind == BOOL and v is False and q.key == "organization"):
            continue
        block[f"{q.key}_env" if q.kind == ENV else q.key] = v
    if stype == "azure-keyvault" and "vault_url" not in block:
        block["discover"] = True
    if stype == "gcp-kms" and "project" not in block:
        block["discover"] = True
    if stype == "aws-kms" and block.get("organization"):
        block["regions"] = "all"
    block.update(st.fixed)
    return block


def render_config(blocks: list[dict[str, Any]]) -> str:
    from .collectors import DESCRIPTIONS  # noqa: PLC0415

    out = [
        "# keycensus configuration, written by `keycensus init`.",
        "# Secrets are referenced by environment variable (*_env); they are never written here.",
        "# Every setting of every source type: config/keycensus.example.yml in the keycensus repository.",
        "",
        "policy: default",
        "",
        "sources:",
    ]
    for b in blocks:
        out.append(f"  # {DESCRIPTIONS.get(b['type'], b['type'])}")
        for i, (k, v) in enumerate(b.items()):
            out.append(("  - " if i == 0 else "    ") + f"{k}: {_flow(v)}")
        note = QUESTIONS[b["type"]].note
        if note:
            out.append(f"  #   {note}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def _flow(value: Any) -> str:
    """One YAML value on one line: scalars plain or quoted as needed, lists inline."""
    return yaml.safe_dump(value, default_flow_style=True, width=10_000).split("\n...")[0].strip()


def missing_module(stype: str) -> str | None:
    """The pip extra a source type needs, when its library is not installed."""
    st = QUESTIONS.get(stype)
    if not st or not st.module:
        return None
    try:
        found = importlib.util.find_spec(st.module) is not None
    except (ImportError, ValueError):
        found = False
    return None if found else st.extra


def install_hint(extras: list[str]) -> str:
    spec = f"keycensus[{','.join(sorted(set(extras)))}]"
    if shutil.which("pipx"):
        return f'pipx install --force "{spec}"'
    return f'pip install "{spec}"'


def unset_secrets(blocks: list[dict[str, Any]], env: dict[str, str] | None = None) -> list[tuple[str, str]]:
    env = dict(os.environ if env is None else env)
    return [(b["name"], v) for b in blocks for k, v in b.items() if k.endswith("_env") and not env.get(str(v))]
