"""Live integration tests against real cloud accounts.

They are skipped unless the environment says where to look:

    KEYCENSUS_IT_AZURE_VAULT_URL=https://keycensus-it.vault.azure.net   (+ Azure credentials in the environment)
    KEYCENSUS_IT_GCP_PROJECT=keycensus-it                                (+ Google credentials in the environment)

Credentials come from the usual chains (DefaultAzureCredential / Application Default Credentials) --
in CI through OIDC (see .github/workflows/integration.yml), locally through `az login` / `gcloud auth
application-default login`. A raw bearer token also works: KEYCENSUS_IT_AZURE_TOKEN / KEYCENSUS_IT_GCP_TOKEN.

The fixtures the assertions expect are created by tests/integration/bootstrap-*.sh (see docs/INTEGRATION-TESTS.md).
Set KEYCENSUS_IT_FIXTURES=0 to run against an arbitrary vault/project with only structural assertions.
"""

from __future__ import annotations

import os

import pytest
import yaml

from keycensus.config import SourceConfig

HERE = os.path.dirname(__file__)


def pytest_configure(config):
    config.addinivalue_line("markers", "live: talks to a real cloud account (skipped without credentials)")


@pytest.fixture(scope="session")
def fixtures() -> dict:
    with open(os.path.join(HERE, "fixtures.yml")) as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="session")
def expect_fixtures() -> bool:
    return os.environ.get("KEYCENSUS_IT_FIXTURES", "1") != "0"


@pytest.fixture(scope="session")
def azure_source() -> SourceConfig:
    url = os.environ.get("KEYCENSUS_IT_AZURE_VAULT_URL")
    if not url:
        pytest.skip("KEYCENSUS_IT_AZURE_VAULT_URL not set")
    opts = {"vault_url": url, "include_certificates": True}
    if os.environ.get("KEYCENSUS_IT_AZURE_TOKEN"):
        opts.update(auth="token", token_env="KEYCENSUS_IT_AZURE_TOKEN")
    else:
        pytest.importorskip("azure.identity", reason="pip install 'keycensus[azure]' for DefaultAzureCredential")
        opts["auth"] = "default"
    return SourceConfig(name="azure-it", type="azure-keyvault", options=opts)


@pytest.fixture(scope="session")
def gcp_source() -> SourceConfig:
    project = os.environ.get("KEYCENSUS_IT_GCP_PROJECT")
    if not project:
        pytest.skip("KEYCENSUS_IT_GCP_PROJECT not set")
    opts = {"project": project, "include_destroyed": True}
    loc = os.environ.get("KEYCENSUS_IT_GCP_LOCATION")
    if loc:
        opts["locations"] = [loc]
    if os.environ.get("KEYCENSUS_IT_GCP_TOKEN"):
        opts.update(auth="token", token_env="KEYCENSUS_IT_GCP_TOKEN")
    else:
        pytest.importorskip("google.auth", reason="pip install 'keycensus[gcp]' for Application Default Credentials")
        opts["auth"] = "default"
    return SourceConfig(name="gcp-it", type="gcp-kms", options=opts)
