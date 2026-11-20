"""`keycensus init`: questions, the config it writes, secrets by reference only, the doctor run and the first scan."""

from __future__ import annotations

import pytest
import yaml
from click.testing import CliRunner

from keycensus import init as setup
from keycensus.cli import main
from keycensus.collectors import DESCRIPTIONS, REGISTRY
from keycensus.config import load

from .conftest import make_cert, pem


@pytest.fixture
def certs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "certs").mkdir()
    _, cert = make_cert("init-test")
    (tmp_path / "certs" / "web.pem").write_bytes(pem(cert))
    return tmp_path


def test_every_source_type_has_questions_and_a_description():
    assert set(setup.QUESTIONS) | set(setup.ALIASES) == set(REGISTRY)
    assert all(t in DESCRIPTIONS for t in setup.QUESTIONS)


def test_interactive_init_writes_config_tests_it_and_scans(certs):
    res = CliRunner().invoke(main, ["init"], input="pem\n\ncerts\n")
    assert res.exit_code == 0, res.output
    cfg = load(certs / "keycensus.yml")
    assert [(s.name, s.type, s.options) for s in cfg.sources] == [("files", "pem", {"paths": ["certs"]})]
    assert "1 source(s): 1 complete" in res.output and "First scan" in res.output
    assert (certs / "out" / "report.html").exists() and (certs / "out" / "inventory.json").exists()


def test_secrets_are_written_as_env_references_only(certs, monkeypatch):
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:9")
    res = CliRunner().invoke(main, ["init", "-s", "vault", "-y", "--no-scan"])
    assert res.exit_code == 0, res.output
    text = (certs / "keycensus.yml").read_text()
    block = yaml.safe_load(text)["sources"][0]
    assert block == {"name": "vault", "type": "vault", "url": "http://127.0.0.1:9", "token_env": "VAULT_TOKEN"}
    assert "reads its secret from $VAULT_TOKEN, which is not set" in res.output
    assert "failed" in res.output and "next: keycensus scan" in res.output


def test_yes_fails_when_a_required_setting_has_no_default(certs):
    res = CliRunner().invoke(main, ["init", "-s", "tls", "-y"])
    assert res.exit_code != 0 and "required" in res.output
    assert not (certs / "keycensus.yml").exists()


def test_existing_config_is_kept_without_force(certs):
    (certs / "keycensus.yml").write_text("sources: []\n")
    res = CliRunner().invoke(main, ["init", "-s", "pem", "-y"])
    assert res.exit_code != 0 and "--force" in res.output
    assert (certs / "keycensus.yml").read_text() == "sources: []\n"
    res = CliRunner().invoke(main, ["init", "-s", "files", "-y", "--force", "--no-scan"])
    assert res.exit_code == 0, res.output
    assert load(certs / "keycensus.yml").sources[0].type == "pem"


def test_unknown_type_is_refused(certs):
    res = CliRunner().invoke(main, ["init", "-s", "oracle-tde", "-y"])
    assert res.exit_code != 0 and "unknown source type" in res.output


def test_detect_reads_environment_and_home(tmp_path):
    (tmp_path / ".kube").mkdir()
    (tmp_path / ".kube" / "config").write_text("")
    found = setup.detect({"VAULT_ADDR": "https://v:8200", "AWS_PROFILE": "prod"}, home=tmp_path)
    assert set(found) >= {"vault", "aws-kms", "kubernetes"} and "gcp-kms" not in found
    assert setup.detect({}, home=tmp_path).keys() >= {"kubernetes"}


def test_defaults_come_from_the_environment():
    q = next(q for q in setup.QUESTIONS["aws-kms"].questions if q.key == "region")
    assert setup.default_for(q, "aws-kms", {"AWS_REGION": "eu-west-1"}) == "eu-west-1"
    assert setup.default_for(q, "aws-kms", {}) == "us-east-1"


def test_discovery_when_no_vault_or_project_is_given():
    az = setup.source_block("azure-keyvault", "azure", {"vault_url": None})
    assert az == {"name": "azure", "type": "azure-keyvault", "discover": True, "auth": "default"}
    gcp = setup.source_block("gcp-kms", "gcp", {"project": "acme"})
    assert gcp == {"name": "gcp", "type": "gcp-kms", "project": "acme", "auth": "default"}
    org = setup.source_block("aws-kms", "aws", {"region": "us-east-1", "profile": None, "organization": True})
    assert org["organization"] is True and org["regions"] == "all"


def test_every_generated_block_loads(tmp_path):
    blocks = []
    for t, st in setup.QUESTIONS.items():
        answers = {q.key: setup.parse_answer(q, q.default if q.default is not None else ("x" if q.kind != "list"
                                                                                          else ["x"]))
                   for q in st.questions}  # fmt: skip
        blocks.append(setup.source_block(t, f"s-{t}", answers))
    p = tmp_path / "all.yml"
    p.write_text(setup.render_config(blocks))
    cfg = load(p)
    assert [s.type for s in cfg.sources] == list(setup.QUESTIONS)
    assert "password" not in {k for s in cfg.sources for k in s.options}  # only password_env


def test_missing_library_is_named_with_the_install_command(monkeypatch):
    monkeypatch.setattr(setup.importlib.util, "find_spec", lambda name: None)
    assert setup.missing_module("aws-kms") == "aws" and setup.missing_module("pem") is None
    monkeypatch.setattr(setup.shutil, "which", lambda name: None)
    assert setup.install_hint(["aws", "gcp"]) == 'pip install "keycensus[aws,gcp]"'


def test_parse_answer():
    lst = setup.Question("p", "", setup.LIST)
    assert setup.parse_answer(lst, "a, b,,c") == ["a", "b", "c"] and setup.parse_answer(lst, "") is None
    assert setup.parse_answer(setup.Question("b", "", setup.BOOL), "y") is True
    assert setup.parse_answer(setup.Question("t", ""), "  ") is None
