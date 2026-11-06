"""`keycensus doctor`: for each source, what it reached, what it could not, why, and what to change.

It reads the same records a scan writes (status, coverage, error) and adds a remedy to every problem: the
permission that is missing, the file in `deploy/` that grants it, or the option to change. It can run the
sources itself or read the `sources` block of an existing inventory.json, so a scan that already ran in CI
can be explained without scanning again.

Problems come in three levels:

* failed: the source produced nothing. Its assets from earlier scans are carried forward as not observed.
* gap: part of the source's scope was not scanned (a denied account, a missing export). The source is
  partial, and assets that lived in that part are carried forward.
* optional: an optional read was denied. The scan is complete, but some fields are missing (consumers,
  rotation status).
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Any

from .model import GAP_DENIED, GAP_ERROR, GAP_UNAVAILABLE, SCAN_COMPLETE, SCAN_FAILED, SCAN_PARTIAL, Coverage

DEPLOY_URL = "https://github.com/FlavioImbertDomingos/keycensus/tree/main/deploy"

FAILED, GAP, OPTIONAL = "failed", "gap", "optional"

# Where the least-privilege grant for each source type lives in the repository.
FILES = {
    "vault": "deploy/vault/keycensus-policy.hcl",
    "aws-kms": "deploy/aws/keycensus-scanner-policy.json",
    "azure-keyvault": "deploy/azure/keycensus-reader-role.json",
    "gcp-kms": "deploy/gcp/keycensus-kms-viewer-role.yaml",
    "kubernetes": "deploy/kubernetes/keycensus-reader.yaml",
    "adcs": "deploy/ad/README.md",
}
AWS_MEMBER_ROLE = "deploy/aws/keycensus-member-role.yaml"
AZURE_README = "deploy/azure/README.md"

# What a source type needs when it is denied outright (401/403 on its first call).
CREDENTIALS = {
    "vault": "a token whose policy is keycensus-policy.hcl: read on sys/mounts, list and read on the Transit "
             "and PKI mounts",
    "pkcs11": "the Crypto User PIN of the partition or slot (pin_env, pin_file or a secret reference); never "
              "the Crypto Officer or SO PIN",
    "aws-kms": "credentials for a role with keycensus-scanner-policy.json (kms:ListKeys, kms:ListAliases, "
               "kms:DescribeKey and the optional reads)",
    "azure-keyvault": "an identity with the keycensus inventory reader role on the subscription or management "
                      "group, plus keys and certificates get/list on vaults that use access policies",
    "gcp-kms": "a service account bound to the keycensusKmsViewer role at the organization, folder or project",
    "kubernetes": "a service account bound to the keycensus-reader ClusterRole, or a RoleBinding per namespace",
    "ciphertrust": "a read-only CipherTrust API user (username and password, or a prebuilt JWT)",
    "keysafe5": "a bearer token or client certificate with read access to keys",
    "adcs": "a Domain Users account that can bind over LDAPS (or auth: kerberos with a keytab)",
    "ct": "a valid Cert Spotter API key, or no key at all (the free tier is rate limited)",
}  # fmt: skip

CARRIED = ("Assets in this part were not inventoried; ones seen before are carried forward as not observed "
           "and their findings stay open.")  # fmt: skip
NOTHING = ("The source produced nothing; its assets from earlier scans are carried forward as not observed "
           "and their findings stay open.")  # fmt: skip


@dataclass
class Fix:
    action: str
    file: str | None = None


@dataclass
class Problem:
    level: str  # failed | gap | optional
    kind: str  # denied | unavailable | error | auth | network | tls | config | dependency
    scope: str  # "source", a scope name such as "mounts", or an optional permission
    detail: str  # the reason the collector recorded
    effect: str
    items: list[str] = field(default_factory=list)  # gap ids, or how many times an optional read was denied
    fix: Fix | None = None


@dataclass
class Diagnosis:
    name: str
    type: str
    status: str
    assets: int
    duration_seconds: float
    reached: list[str]
    problems: list[Problem]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------------------------- failures
_DEPENDENCY = re.compile(r"missing dependency.*?\(pip install '([^']+)'\)", re.S)
_PATTERNS = [
    ("dependency", r"missing dependency|No module named"),
    ("config", r"unknown source type|is required|needs '|needs a|must be|not set|no such option|ConfigError|"
               r"does not exist|no token present|NoSuchToken|No token matching|slot \S+ not found|"
               r"cannot open shared object file|OS exception while loading|image not found"),
    ("tls", r"CERTIFICATE_VERIFY_FAILED|certificate verify failed|SSLError|self.signed certificate|"
            r"unable to get local issuer"),
    ("auth", r"\b401\b|unauthori[sz]ed|login failed|bind failed|invalidCredentials|invalid credentials|"
             r"ExpiredToken|InvalidClientTokenId|UnrecognizedClient|AADSTS\d+|CKR_PIN_INCORRECT|PIN_INCORRECT|"
             r"invalid_grant|token.*expired"),
    ("denied", r"\b403\b|forbidden|AccessDenied|access denied|permission denied|AuthorizationFailed|"
               r"not authorized|PERMISSION_DENIED"),
    ("network", r"Connection refused|ConnectionError|Max retries|NewConnectionError|Name or service not known|"
                r"nodename nor servname|Temporary failure in name resolution|timed out|Timeout|could not connect|"
                r"No route to host|Network is unreachable|EndpointConnectionError|getaddrinfo"),
]  # fmt: skip


def classify_error(text: str) -> str:
    for kind, pattern in _PATTERNS:
        if re.search(pattern, text, re.I):
            return kind
    return GAP_ERROR


def failure_fix(stype: str, kind: str, text: str) -> Fix | None:
    if kind == "dependency":
        m = _DEPENDENCY.search(text)
        return Fix(f"pip install '{m.group(1)}'" if m else "install the Python package the error names")
    if kind == "config":
        if "unknown source type" in text:
            return Fix("fix the source's type; `keycensus collectors` lists the known ones")
        if stype == "pkcs11" and re.search(r"shared object|OS exception while loading|image not found", text):
            return Fix("the PKCS#11 library in module: is not on this host; install the vendor client (Luna, "
                       "nShield, CloudHSM) or fix the path")  # fmt: skip
        if stype == "pkcs11" and ("token" in text or "slot" in text):
            return Fix("check token_label or slot against `pkcs11-tool --list-slots` for the same module")
        return Fix("set the option the error names in the source's config block, or the environment variable "
                   "or secret reference it points to; `keycensus validate` checks the file")  # fmt: skip
    if kind == "tls":
        return Fix("set verify_tls to the path of the CA bundle that issued the server's certificate")
    if kind == "network":
        return Fix("keycensus could not reach the service: check the URL, port, DNS, firewall and proxy from the "
                   "host that runs keycensus")  # fmt: skip
    if kind in ("auth", "denied"):
        if stype == "vault" and "sys/mounts" in text:
            return Fix("grant read on sys/mounts, or list the mounts in transit_mounts and pki_mounts",
                       FILES["vault"])  # fmt: skip
        if stype == "aws-kms" and ("organizations" in text.lower() or "ListAccounts" in text):
            return Fix("run from the management account or a delegated administrator, with "
                       "organizations:ListAccounts", FILES["aws-kms"])  # fmt: skip
        need = CREDENTIALS.get(stype)
        if need:
            prefix = "the credentials were refused; use " if kind == "auth" else "the identity lacks access; give it "
            return Fix(prefix + need, FILES.get(stype))
        return Fix("check the credentials and the account's read access in the source system")
    return Fix("run `keycensus scan -v` for the full error, and open an issue if it is a keycensus bug")


# ---------------------------------------------------------------------------------------------- gaps
def gap_fix(stype: str, scope: str, kind: str) -> Fix | None:  # noqa: C901, PLR0911, PLR0912 - one table
    denied, unavailable = kind == GAP_DENIED, kind == GAP_UNAVAILABLE
    if stype == "aws-kms":
        if scope == "accounts":
            if denied:
                return Fix("deploy the KeycensusReadOnly role in these accounts (CloudFormation StackSet) and let "
                           "the scanner assume it (sts:AssumeRole)", AWS_MEMBER_ROLE)  # fmt: skip
            return Fix("check that the accounts are ACTIVE and the role name matches member_role")
        if scope == "regions":
            if denied:
                return Fix("kms:ListKeys was denied in these regions; look for a service control policy or "
                           "permission boundary that blocks them, or drop them from regions:",
                           FILES["aws-kms"])  # fmt: skip
            return Fix("the regions are not enabled for the account (opt-in regions) or KMS was unreachable; "
                       "enable them or leave them out of regions:")  # fmt: skip
        if scope == "keys":
            return Fix("kms:DescribeKey was refused for these keys; a key policy can deny even when IAM allows, "
                       "so add the scanner role to the key policies", FILES["aws-kms"])  # fmt: skip
    if stype == "azure-keyvault":
        if scope == "subscriptions":
            return Fix("assign the keycensus inventory reader role at the management group that holds these "
                       "subscriptions", FILES["azure-keyvault"])  # fmt: skip
        if scope == "vaults":
            if denied:
                return Fix("give the identity keys and certificates get/list on these vaults: the reader role's "
                           "DataActions for RBAC vaults, an access policy for the others, Managed HSM Crypto "
                           "Auditor for Managed HSMs", AZURE_README)  # fmt: skip
            return Fix("the vault did not answer; check its network rules (firewall, private endpoint) allow the "
                       "host that runs keycensus")  # fmt: skip
    if stype == "gcp-kms":
        if scope == "projects":
            return Fix("bind the keycensusKmsViewer role at the organization or folder above these projects",
                       FILES["gcp-kms"])  # fmt: skip
        if scope == "locations":
            return Fix("cloudkms.keyRings.list was refused in these locations; check organization policies "
                       "that restrict resource locations", FILES["gcp-kms"])  # fmt: skip
    if stype == "kubernetes":
        if scope == "cert-manager" and unavailable:
            return Fix("cert-manager's CRDs are not installed in this cluster; set cert_manager: false to stop "
                       "looking")  # fmt: skip
        if scope == "cert-manager":
            return Fix("grant get/list on certificates, issuers and clusterissuers in cert-manager.io",
                       FILES["kubernetes"])  # fmt: skip
        if denied:
            return Fix("bind the keycensus-reader role in these namespaces (get/list on secrets)",
                       FILES["kubernetes"])  # fmt: skip
        return Fix("the namespaces were listed but could not be read; check that they still exist")
    if stype == "vault":
        if scope == "mounts":
            if denied:
                return Fix("add list on <mount>/keys (Transit) or <mount>/certs (PKI), and read below it, for each "
                           "mount listed", FILES["vault"])  # fmt: skip
            return Fix("the mounts did not answer; check they still exist, or remove them from transit_mounts and "
                       "pki_mounts")  # fmt: skip
        if scope == "items":
            if denied:
                return Fix("add read on <mount>/keys/* or <mount>/cert/* for these paths", FILES["vault"])
            return Fix("Vault returned an error for these keys or certificates; check the server log")
    if stype == "adcs":
        if scope == "directory":
            return Fix("the domain controller could not be read; check ldap_url, the account and LDAPS "
                       "trust, then rerun", FILES["adcs"])  # fmt: skip
        if scope == "exports":
            if unavailable:
                return Fix("the export file is missing; check the scheduled certutil -view task on that CA and "
                           "where it writes", FILES["adcs"])  # fmt: skip
            return Fix("rows without a readable certificate usually mean a localised certutil header; map the "
                       "column with field_map: {certificate: <your header>}")  # fmt: skip
    if stype in ("files", "pem", "keyfiles"):
        if unavailable:
            return Fix("the path does not exist on this host; fix it in paths:, or mount it into the container")
        return Fix("grant the account that runs keycensus read access to these paths (and execute on their "
                   "directories)")  # fmt: skip
    if stype == "ct":
        return Fix("the CT service did not answer for these domains; rerun later, or switch provider (Cert "
                   "Spotter is more reliable than crt.sh) and add an API key for higher limits")  # fmt: skip
    if stype == "pkcs11":
        return Fix("some objects refused attribute reads; vendor HSMs often hide attributes from a Crypto User. "
                   "Run with -v to see which, and report the vendor and model in an issue")  # fmt: skip
    if stype in ("ciphertrust", "keysafe5"):
        return Fix("the key listing stopped part way; raise timeout or lower page_size and rerun")
    return None


# ---------------------------------------------------------------------------------------------- optional
_OPTIONAL = {
    "aws-kms": {
        "kms:ListGrants": "grants are missing from used_by",
        "kms:GetKeyPolicy": "key-policy principals are missing from used_by",
        "kms:GetKeyRotationStatus": "rotation status is unknown",
        "kms:ListResourceTags": "tags are missing",
        "ec2:DescribeRegions": "regions: all fell back to the session's region list",
    },
    "azure-keyvault": {
        "Microsoft.KeyVault/vaults/read": (
            "vault properties (soft delete, purge protection) are missing",
            "Microsoft.KeyVault/vaults/read",
        ),
        "Microsoft.Authorization/roleAssignments/read": (
            "RBAC consumers are missing from used_by",
            "Microsoft.Authorization/roleAssignments/read",
        ),
        "keys/rotationpolicy/read": (
            "rotation policies are unknown",
            "Microsoft.KeyVault/vaults/keyrotationpolicies/read",
        ),
    },
    "gcp-kms": {"cloudkms.cryptoKeys.getIamPolicy": "IAM consumers are missing from used_by"},
    "kubernetes": {
        "pods/list": ("workloads that mount each secret are missing from used_by", 'resources: ["pods"]'),
        "ingresses/list": ("ingresses that terminate TLS with each secret are missing", 'resources: ["ingresses"]'),
    },
    "vault": {
        "list sys/policies/acl": ("policy consumers are missing from used_by", 'path "sys/policies/acl"'),
        "read sys/policies/acl/*": ("some policies could not be read for consumers", 'path "sys/policies/acl/*"'),
    },
}


def optional_fix(stype: str, permission: str) -> tuple[str, Fix]:
    entry = _OPTIONAL.get(stype, {}).get(permission)
    if isinstance(entry, tuple):
        effect, grant = entry
    else:
        effect, grant = entry or "some fields are missing", permission
    file = FILES.get(stype)
    if stype == "aws-kms":
        action = f"grant {grant} to the scanner role (and in the member role for organization: true)"
    elif stype == "vault":
        action = f'add {grant} {{ capabilities = ["{permission.split()[0]}"] }} to the keycensus policy'
    elif stype == "kubernetes":
        action = f"grant list on {permission.split('/')[0]} to the keycensus-reader role"
    else:
        action = f"grant {grant}"
    return effect, Fix(action, file)


def optional_grant(stype: str, permission: str) -> str:
    """The exact text the deploy file must contain for this optional permission (used by the tests)."""
    entry = _OPTIONAL.get(stype, {}).get(permission)
    return entry[1] if isinstance(entry, tuple) else permission


# ---------------------------------------------------------------------------------------------- diagnose
def _clean(text: str) -> str:
    """One line: drops the escaped newlines and tabs that JSON error bodies carry."""
    return re.sub(r"\s+", " ", re.sub(r"(\\[nt])+", " ", str(text))).strip()


def diagnose(record: dict[str, Any]) -> Diagnosis:
    """One source, from a SourceResult or an inventory.json `sources` entry."""
    stype = str(record.get("type") or "")
    cov = record.get("coverage")
    cov = cov if isinstance(cov, Coverage) else Coverage.from_dict(cov)
    error = record.get("error")
    status = record.get("status") or (SCAN_FAILED if error else SCAN_PARTIAL if cov.gap_ids else SCAN_COMPLETE)
    problems: list[Problem] = []
    if error:
        kind = classify_error(error)
        problems.append(Problem(FAILED, kind, "source", _clean(error), NOTHING,
                                fix=failure_fix(stype, kind, str(error))))  # fmt: skip
    for scope_name, scope in cov.scopes.items():
        by_kind: dict[str, list[dict]] = {}
        for g in scope.gaps:
            by_kind.setdefault(g["kind"], []).append(g)
        for kind, gaps in by_kind.items():
            reasons = sorted({_clean(g["reason"]) for g in gaps})
            detail = reasons[0] + (f" (and {len(reasons) - 1} other reason(s))" if len(reasons) > 1 else "")
            problems.append(Problem(GAP, kind, scope_name, detail, CARRIED,
                                    items=[g["id"].split(":", 1)[-1] for g in gaps],
                                    fix=gap_fix(stype, scope_name, kind)))  # fmt: skip
    for perm, n in sorted(cov.optional_denied.items()):
        effect, fix = optional_fix(stype, perm)
        problems.append(Problem(OPTIONAL, GAP_DENIED, perm, f"denied {n} time(s)", effect.capitalize() + ".",
                                fix=fix))  # fmt: skip
    reached = [line for line in cov.describe().split("; ") if line]
    assets = record.get("assets")
    return Diagnosis(
        name=str(record.get("name")),
        type=stype,
        status=status,
        assets=len(assets) if isinstance(assets, list) else int(assets or 0),
        duration_seconds=round(float(record.get("duration_seconds") or 0), 2),
        reached=reached,
        problems=problems,
    )


def run_sources(config, names: list[str] | None = None, max_workers: int = 8) -> list[dict[str, Any]]:
    """Run the configured collectors (no policy, no reports) and return their source records."""
    from .collectors import build
    from .model import SourceResult

    wanted = [s for s in config.sources if not names or s.name in names]
    missing = sorted(set(names or []) - {s.name for s in config.sources})
    if missing:
        raise ValueError(f"no source named {', '.join(missing)} in the config")
    collectors, results = [], []
    for src in wanted:
        try:
            collectors.append(build(src))
        except Exception as exc:  # noqa: BLE001 - a bad config block is itself a diagnosis
            results.append(SourceResult(name=src.name, type=src.type, error=f"{type(exc).__name__}: {exc}"))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results += list(pool.map(lambda c: c.run(), collectors))
    order = {s.name: i for i, s in enumerate(config.sources)}
    results.sort(key=lambda r: order.get(r.name, 999))
    return [{"name": r.name, "type": r.type, "assets": len(r.assets), "error": r.error, "status": r.status,
             "coverage": r.coverage, "duration_seconds": r.duration_seconds} for r in results]  # fmt: skip


def exit_code(diagnoses: list[Diagnosis]) -> int:
    """2 when a source failed, 6 when one was partial (the same codes as `scan`), else 0."""
    statuses = {d.status for d in diagnoses}
    return 2 if SCAN_FAILED in statuses else 6 if SCAN_PARTIAL in statuses else 0


# ---------------------------------------------------------------------------------------------- output
def _wrap(text: str, indent: int, width: int = 100) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width - indent:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}" if cur else w
    if cur:
        lines.append(cur)
    return [" " * indent + line for line in lines]


def render_text(diagnoses: list[Diagnosis], max_items: int = 5) -> str:
    counts = {s: sum(1 for d in diagnoses if d.status == s) for s in (SCAN_COMPLETE, SCAN_PARTIAL, SCAN_FAILED)}
    out = [f"{len(diagnoses)} source(s): {counts[SCAN_COMPLETE]} complete, {counts[SCAN_PARTIAL]} partial, "
           f"{counts[SCAN_FAILED]} failed", ""]  # fmt: skip
    files = False
    for d in diagnoses:
        out.append(f"{d.name} ({d.type}): {d.status}, {d.assets} asset(s), {d.duration_seconds:g}s")
        if d.reached:
            out.append("  reached     " + d.reached[0])
            out += [" " * 14 + r for r in d.reached[1:]]
        elif d.status != SCAN_FAILED:
            out.append("  reached     everything it was configured to read (this source type reports no breakdown)")
        if not d.problems:
            out.append("  ok          nothing to change")
        for p in d.problems:
            label = {FAILED: "failed", GAP: p.kind, OPTIONAL: "optional"}[p.level]
            head = "source" if p.level == FAILED else p.scope
            if p.items:
                shown = ", ".join(p.items[:max_items]) + (f" and {len(p.items) - max_items} more"
                                                          if len(p.items) > max_items else "")  # fmt: skip
                head = f"{p.scope}: {shown}"
            out.append(f"  {label:<11} {head}")
            out += _wrap(p.detail, 14)
            out += _wrap(p.effect, 14)
            if p.fix:
                out += _wrap("fix: " + p.fix.action, 14)
                if p.fix.file:
                    out.append(f"              file: {p.fix.file}")
                    files = True
        out.append("")
    if files:
        out.append(f"Files named above are in the keycensus repository: {DEPLOY_URL}")
    return "\n".join(out).rstrip() + "\n"


def render_json(diagnoses: list[Diagnosis]) -> dict[str, Any]:
    return {"status": {0: SCAN_COMPLETE, 6: SCAN_PARTIAL, 2: SCAN_FAILED}[exit_code(diagnoses)],
            "sources": [d.to_dict() for d in diagnoses]}  # fmt: skip


__all__ = ["Diagnosis", "Fix", "Problem", "classify_error", "diagnose", "exit_code", "gap_fix", "optional_fix",
           "render_json", "render_text", "run_sources", "GAP_DENIED", "GAP_UNAVAILABLE"]  # fmt: skip
