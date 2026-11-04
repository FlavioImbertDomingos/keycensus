"""Secret references: env, file, Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager."""

from __future__ import annotations

import base64
import json

import pytest
import responses

from keycensus import secrets
from keycensus.config import ConfigError, load

from .conftest import source

VAULT = "https://vault.example.com:8200"


@pytest.fixture(autouse=True)
def fresh():
    secrets.configure({})
    yield
    secrets.configure({})


def test_env_file_inline_order(tmp_path, monkeypatch):
    monkeypatch.setenv("P", "from-env")
    (tmp_path / "p").write_text("from-file\n")
    assert source("s", "x", password_file=str(tmp_path / "p"), password_env="P").secret("password") == "from-file"
    assert source("s", "x", password_env="P", password="inline").secret("password") == "from-env"
    assert source("s", "x", password="inline").secret("password") == "inline"
    with pytest.raises(ConfigError, match="password_vault"):
        source("s", "x").secret("password", required=True)


@responses.activate
def test_vault_kv2_token(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "hvs.x")
    secrets.configure({"vault": {"url": VAULT}})
    responses.add(responses.GET, f"{VAULT}/v1/secret/data/keycensus",
                  match=[responses.matchers.header_matcher({"X-Vault-Token": "hvs.x"})],
                  json={"data": {"data": {"ctm": "s3cret", "ks5": "t0ken"}, "metadata": {"version": 3}}})  # fmt: skip
    cfg = source("ctm", "ciphertrust", password_vault="secret/data/keycensus#ctm")
    assert cfg.secret("password") == "s3cret"
    assert cfg.secret("password") == "s3cret"
    assert len(responses.calls) == 1  # cached
    with pytest.raises(ConfigError, match="holds 2 fields"):
        secrets.configure({"vault": {"url": VAULT}})
        source("x", "x", password_vault="secret/data/keycensus").secret("password")


@responses.activate
def test_vault_kv1_and_kubernetes_auth(tmp_path):
    jwt = tmp_path / "jwt"
    jwt.write_text("eyJ.sa\n")
    secrets.configure({"vault": {"url": VAULT, "auth": "kubernetes", "role": "kc", "jwt_file": str(jwt),
                                 "namespace": "ops"}})  # fmt: skip
    responses.add(responses.POST, f"{VAULT}/v1/auth/kubernetes/login",
                  match=[responses.matchers.json_params_matcher({"role": "kc", "jwt": "eyJ.sa"})],
                  json={"auth": {"client_token": "hvs.k8s"}})  # fmt: skip
    responses.add(responses.GET, f"{VAULT}/v1/kv/hsm",
                  match=[responses.matchers.header_matcher({"X-Vault-Token": "hvs.k8s", "X-Vault-Namespace": "ops"})],
                  json={"data": {"pin": "1234"}})  # fmt: skip
    assert source("hsm", "pkcs11", pin_vault="kv/hsm").secret("pin") == "1234"


@responses.activate
def test_vault_errors_name_the_reference_not_the_value(monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", "hvs.x")
    secrets.configure({"vault": {"url": VAULT}})
    responses.add(responses.GET, f"{VAULT}/v1/secret/data/kc", json={"data": {"data": {"other": "TOPSECRET"},
                                                                             "metadata": {}}})  # fmt: skip
    with pytest.raises(ConfigError) as exc:
        source("x", "x", password_vault="secret/data/kc#ctm").secret("password")
    assert "secret/data/kc" in str(exc.value) and "TOPSECRET" not in str(exc.value)


def test_vault_needs_an_address(monkeypatch):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    with pytest.raises(ConfigError, match="VAULT_ADDR"):
        source("x", "x", token_vault="secret/data/kc#t").secret("token")


def test_aws_secrets_manager(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from moto import mock_aws

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "t")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "t")
    with mock_aws():
        sm = boto3.client("secretsmanager", region_name="eu-west-1")
        arn = sm.create_secret(Name="kc/ctm", SecretString=json.dumps({"password": "pw1", "user": "kc"}))["ARN"]
        sm.create_secret(Name="kc/plain", SecretString="just-a-string")
        assert source("x", "x", password_aws_secret=f"{arn}#password").secret("password") == "pw1"
        secrets.configure({"aws": {"region": "eu-west-1"}})
        assert source("x", "x", password_aws_secret="kc/plain").secret("password") == "just-a-string"
        with pytest.raises(ConfigError, match="not JSON"):
            source("x", "x", password_aws_secret="kc/plain#password").secret("password")


@responses.activate
def test_azure_key_vault_secret(monkeypatch):
    monkeypatch.setenv("AZT", "eyJ.kv")
    secrets.configure({"azure": {"token_env": "AZT"}})
    url = "https://kc-kv.vault.azure.net/secrets/ctm-password"
    responses.add(responses.GET, url, match=[responses.matchers.header_matcher({"Authorization": "Bearer eyJ.kv"})],
                  json={"value": "azpw", "id": f"{url}/abc"})  # fmt: skip
    assert source("x", "x", password_azure_secret=url).secret("password") == "azpw"


@responses.activate
def test_gcp_secret_manager(monkeypatch):
    monkeypatch.setenv("GT", "ya29.x")
    secrets.configure({"gcp": {"token_env": "GT"}})
    responses.add(responses.GET,
                  "https://secretmanager.googleapis.com/v1/projects/acme/secrets/ctm/versions/latest:access",
                  json={"payload": {"data": base64.b64encode(b'{"password": "gpw"}').decode()}})  # fmt: skip
    assert source("x", "x", password_gcp_secret="projects/acme/secrets/ctm#password").secret("password") == "gpw"


def test_describe_lists_references_only():
    opts = {"password_vault": "secret/data/kc#ctm", "token_env": "T", "url": "https://x", "password": "inline"}
    assert secrets.describe(opts) == ["password_vault=secret/data/kc#ctm", "token_env=T"]


def test_config_load_configures_backends(tmp_path, monkeypatch):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    (tmp_path / "k.yml").write_text(
        "secrets:\n  vault: {url: https://vault.internal:8200}\nsources:\n  - {name: a, type: pem, paths: [/tmp]}\n"
    )
    cfg = load(tmp_path / "k.yml")
    assert secrets._vault_cfg()["url"] == "https://vault.internal:8200"
    assert len(cfg.config_sha256) == 64
