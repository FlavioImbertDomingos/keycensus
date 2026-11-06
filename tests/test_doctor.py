"""keycensus doctor: diagnoses, remedies, the deploy files they point to, and the command."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from keycensus import doctor
from keycensus.cli import main
from keycensus.collectors import REGISTRY, build
from keycensus.model import Coverage

from .conftest import source

REPO = Path(__file__).resolve().parent.parent
COLLECTORS = REPO / "keycensus" / "collectors"


def _record(r):
    return {"name": r.name, "type": r.type, "assets": len(r.assets), "error": r.error, "status": r.status,
            "coverage": r.coverage, "duration_seconds": r.duration_seconds}  # fmt: skip


# ----------------------------------------------------------------------------- the remedies stay true
def _types_by_module():
    out = {}
    for name, cls in REGISTRY.items():
        out.setdefault(Path(cls.__module__.replace(".", "/")).name, []).append(name)
    return out


def test_every_file_a_remedy_names_exists():
    files = {*doctor.FILES.values(), doctor.AWS_MEMBER_ROLE, doctor.AZURE_README}
    for f in files:
        assert (REPO / f).is_file(), f


def test_every_optional_permission_a_collector_records_has_a_remedy_its_file_grants():
    by_module = _types_by_module()
    seen = 0
    for path in COLLECTORS.glob("*.py"):
        for perm in re.findall(r'coverage\.optional\("([^"]+)"\)', path.read_text()):
            for stype in by_module[path.stem]:
                assert perm in doctor._OPTIONAL.get(stype, {}), (stype, perm)
                grant = doctor.optional_grant(stype, perm)
                assert grant in (REPO / doctor.FILES[stype]).read_text(), (stype, grant)
                if stype == "aws-kms":
                    assert grant in (REPO / doctor.AWS_MEMBER_ROLE).read_text(), grant
                seen += 1
    assert seen >= 12


def test_every_scope_a_collector_reports_has_a_remedy():
    by_module = _types_by_module()
    for path in COLLECTORS.glob("*.py"):
        text = path.read_text()
        scopes = set(re.findall(r'coverage\.(?:gap|expect|ok)\("([\w-]+)"', text))
        scopes |= set(re.findall(r'scope = "([\w-]+)"', text))
        for stype in by_module.get(path.stem, []):
            for scope in scopes:
                for kind in ("denied", "unavailable", "error"):
                    assert doctor.gap_fix(stype, scope, kind) is not None, (stype, scope, kind)


@pytest.mark.parametrize(
    "text,kind",
    [
        ("missing dependency: No module named 'boto3' (pip install 'keycensus[aws]')", "dependency"),
        ("ConfigError: [v] env var VT is not set", "config"),
        ("NoSuchToken: No token matching {'token_label': 'x'}", "config"),
        ("SSLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed", "tls"),
        ("RuntimeError: login failed: 401 bad password", "auth"),
        ("ClientError: An error occurred (AccessDeniedException) when calling ListKeys", "denied"),
        ("RuntimeError: GET sys/mounts -> 403: permission denied", "denied"),
        ("ConnectionError: Max retries exceeded (Connection refused)", "network"),
        ("ValueError: something new", "error"),
    ],
)
def test_classify_error(text, kind):
    assert doctor.classify_error(text) == kind


def test_failure_fixes_are_specific():
    dep = doctor.failure_fix("aws-kms", "dependency", "missing dependency: x (pip install 'keycensus[aws]')")
    assert dep.action == "pip install 'keycensus[aws]'"
    mounts = doctor.failure_fix("vault", "denied", "GET sys/mounts -> 403: permission denied")
    assert "sys/mounts" in mounts.action and mounts.file == "deploy/vault/keycensus-policy.hcl"
    assert doctor.failure_fix("gcp-kms", "auth", "401").file == "deploy/gcp/keycensus-kms-viewer-role.yaml"


# ----------------------------------------------------------------------------- real sources
def test_files_source_with_missing_paths(tmp_path, cert_dir):
    r = build(source("certs", "pem", paths=[str(cert_dir), str(tmp_path / "nope")])).run()
    d = doctor.diagnose(_record(r))
    assert d.status == "partial" and d.reached == ["paths: 2 expected, 1 scanned, 1 unavailable"]
    (p,) = d.problems
    assert (p.level, p.kind, p.scope, p.items) == ("gap", "unavailable", "paths", [str(tmp_path / "nope")])
    assert "does not exist" in p.fix.action
    text = doctor.render_text([d])
    assert "unavailable paths:" in text and "carried forward" in text


def _aws_with_policy(monkeypatch, drop=()):
    """Run aws-kms as an IAM user holding deploy/aws/keycensus-scanner-policy.json, minus `drop`, with moto
    evaluating the policy for every call."""
    boto3 = pytest.importorskip("boto3")
    from moto import mock_aws
    from moto.core.authorization import ActionAuthenticatorMixin

    for k, v in {"AWS_ACCESS_KEY_ID": "t", "AWS_SECRET_ACCESS_KEY": "t", "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    policy = json.loads((REPO / "deploy/aws/keycensus-scanner-policy.json").read_text())
    stmt = next(s for s in policy["Statement"] if s["Sid"] == "KmsInventoryInThisAccount")
    stmt["Action"] = [a for a in stmt["Action"] if a not in drop]

    @ActionAuthenticatorMixin.set_initial_no_auth_action_count(4)
    def scan():
        iam = boto3.client("iam")
        iam.create_user(UserName="keycensus")
        iam.put_user_policy(UserName="keycensus", PolicyName="scanner", PolicyDocument=json.dumps(policy))
        key = iam.create_access_key(UserName="keycensus")["AccessKey"]
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", key["AccessKeyId"])
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", key["SecretAccessKey"])
        return build(source("aws", "aws-kms", regions=["us-east-1"])).run()

    with mock_aws():
        boto3.client("kms").create_key(Description="k")
        return scan()


def test_the_shipped_aws_policy_leaves_nothing_to_fix(monkeypatch):
    d = doctor.diagnose(_record(_aws_with_policy(monkeypatch)))
    assert d.status == "complete" and d.assets == 1 and d.problems == []


def test_doctor_names_the_missing_aws_permission_and_the_file(monkeypatch):
    d = doctor.diagnose(_record(_aws_with_policy(monkeypatch, drop=("kms:ListGrants", "kms:GetKeyRotationStatus"))))
    assert d.status == "complete"
    probs = {p.scope: p for p in d.problems}
    assert set(probs) == {"kms:ListGrants", "kms:GetKeyRotationStatus"}
    assert probs["kms:ListGrants"].level == "optional" and "used_by" in probs["kms:ListGrants"].effect
    assert probs["kms:ListGrants"].fix.file == "deploy/aws/keycensus-scanner-policy.json"
    assert "kms:ListGrants" in probs["kms:ListGrants"].fix.action


def test_doctor_explains_a_denied_aws_listing(monkeypatch):
    r = _aws_with_policy(monkeypatch, drop=("kms:ListKeys",))
    d = doctor.diagnose(_record(r))
    assert d.status == "failed"
    (p,) = [p for p in d.problems if p.level == "failed"]
    assert p.kind == "denied" and p.fix.file == "deploy/aws/keycensus-scanner-policy.json"


def test_gaps_are_grouped_and_listed():
    cov = Coverage()
    cov.expect("regions", 8)
    for i in range(7):
        cov.gap("regions", f"111/r{i}", "AccessDeniedException", "denied")
    cov.ok("regions")
    d = doctor.diagnose({"name": "a", "type": "aws-kms", "assets": 3, "coverage": cov.to_dict()})
    (p,) = d.problems
    assert len(p.items) == 7 and "service control policy" in p.fix.action
    assert "and 2 more" in doctor.render_text([d])


# ----------------------------------------------------------------------------- the command
def test_cli_runs_sources_and_exits_like_require_complete(tmp_path, cert_dir):
    cfg = tmp_path / "c.yml"
    cfg.write_text(f"sources:\n  - name: certs\n    type: pem\n    paths: ['{cert_dir}']\n"
                   f"  - name: gone\n    type: pem\n    paths: ['{tmp_path / 'nope'}']\n"
                   "  - name: v\n    type: vault\n    url: http://127.0.0.1:1\n"
                   "    token_env: KC_UNSET_TOKEN\n")  # fmt: skip
    r = CliRunner().invoke(main, ["doctor", "-c", str(cfg)])
    assert r.exit_code == 2, r.output
    assert "3 source(s): 1 complete, 1 partial, 1 failed" in r.output
    assert "KC_UNSET_TOKEN" in r.output and "fix:" in r.output

    r = CliRunner().invoke(main, ["doctor", "-c", str(cfg), "-s", "certs"])
    assert r.exit_code == 0 and "nothing to change" in r.output

    r = CliRunner().invoke(main, ["doctor", "-c", str(cfg), "-s", "nope"])
    assert r.exit_code != 0 and "no source named nope" in r.output


def test_cli_explains_an_earlier_scan_without_scanning(tmp_path, cert_dir):
    cfg = tmp_path / "c.yml"
    cfg.write_text(f"sources:\n  - name: certs\n    type: pem\n    paths: ['{cert_dir}', '{tmp_path / 'x'}']\n")
    out = tmp_path / "out"
    assert CliRunner().invoke(main, ["scan", "-c", str(cfg), "-o", str(out), "-f", "json"]).exit_code == 0
    r = CliRunner().invoke(main, ["doctor", "-i", str(out / "inventory.json"), "--json"])
    assert r.exit_code == 6, r.output
    body = json.loads(r.output)
    assert body["status"] == "partial"
    (src,) = body["sources"]
    assert src["problems"][0]["items"] == [str(tmp_path / "x")]


def test_cli_needs_exactly_one_input(tmp_path):
    assert CliRunner().invoke(main, ["doctor"]).exit_code == 2
