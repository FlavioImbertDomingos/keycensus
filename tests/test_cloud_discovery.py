"""Cloud auto-discovery: every account (AWS), subscription (Azure) and project (GCP)."""

from __future__ import annotations

import pytest
import responses
from responses import matchers

from keycensus.collectors import build

from .conftest import source


# ===================================================================== AWS Organizations (moto)
def test_aws_organization_all_accounts_and_regions(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from moto import mock_aws

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "t")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "t")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with mock_aws():
        org = boto3.client("organizations", region_name="us-east-1")
        org.create_organization(FeatureSet="ALL")
        member = org.create_account(Email="pay@example.com", AccountName="payments")["CreateAccountStatus"]["AccountId"]
        me = boto3.client("sts").get_caller_identity()["Account"]

        boto3.client("kms", region_name="us-east-1").create_key(Description="mgmt-east")
        boto3.client("kms", region_name="eu-west-1").create_key(Description="mgmt-eu")
        creds = boto3.client("sts").assume_role(RoleArn=f"arn:aws:iam::{member}:role/KeycensusReadOnly",
                                                RoleSessionName="seed")["Credentials"]  # fmt: skip
        member_kms = boto3.client("kms", region_name="eu-west-1", aws_access_key_id=creds["AccessKeyId"],
                                  aws_secret_access_key=creds["SecretAccessKey"],
                                  aws_session_token=creds["SessionToken"])  # fmt: skip
        member_kms.create_key(Description="member-eu", KeySpec="RSA_3072", KeyUsage="SIGN_VERIFY")

        res = build(source("aws-org", "aws-kms", organization=True, regions=["us-east-1", "eu-west-1"])).run()
        only = build(source("aws-org", "aws-kms", organization=True, regions=["eu-west-1"], accounts=[member])).run()
    assert res.error is None, res.error
    seen = {(a.extra["account_id"], a.extra["region"]) for a in res.assets}
    assert seen == {(me, "us-east-1"), (me, "eu-west-1"), (member, "eu-west-1")}
    member_key = next(a for a in res.assets if a.extra["account_id"] == member)
    assert member_key.algorithm == "RSA" and member_key.key_size == 3072 and f":{member}:" in member_key.native_id
    assert {a.extra["account_id"] for a in only.assets} == {member}


def test_aws_all_regions_falls_back_and_tolerates_failures(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from moto import mock_aws

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "t")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "t")
    with mock_aws():
        boto3.client("kms", region_name="ap-southeast-2").create_key(Description="sydney")
        res = build(source("aws", "aws-kms", regions="all")).run()
    assert res.error is None
    assert [a.extra["region"] for a in res.assets] == ["ap-southeast-2"]


def test_aws_every_target_failing_is_a_source_error(monkeypatch):
    pytest.importorskip("boto3")
    from moto import mock_aws

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "t")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "t")
    with mock_aws():
        res = build(source("aws", "aws-kms", regions=["no-such-region-1"])).run()
    assert res.error and "every account / region failed" in res.error


# ===================================================================== Azure: every subscription
ARM = "https://management.azure.com"


def _azure_vault(url: str, key: str):
    responses.add(responses.GET, f"{url}/keys", json={"value": [{"kid": f"{url}/keys/{key}",
                                                                  "attributes": {"enabled": True}}]})  # fmt: skip
    responses.add(responses.GET, f"{url}/keys/{key}", json={
        "key": {"kid": f"{url}/keys/{key}/v1", "kty": "RSA-HSM", "n": "AQAB" * 86, "key_ops": ["sign"]},
        "attributes": {"enabled": True},
    })  # fmt: skip
    responses.add(responses.GET, f"{url}/keys/{key}/rotationpolicy", status=404, json={})
    responses.add(responses.GET, f"{url}/certificates", json={"value": []})


@responses.activate
def test_azure_discovers_every_subscription_and_vault(monkeypatch):
    monkeypatch.setenv("AZT", "eyJ.data")
    monkeypatch.setenv("ARMT", "eyJ.arm")
    responses.add(responses.GET, f"{ARM}/subscriptions", json={
        "value": [{"subscriptionId": "sub-a", "state": "Enabled"}, {"subscriptionId": "sub-old", "state": "Disabled"}],
        "nextLink": f"{ARM}/subscriptions?api-version=2022-12-01&$skiptoken=2",
    })  # fmt: skip
    responses.add(responses.GET, f"{ARM}/subscriptions",
                  match=[matchers.query_param_matcher({"api-version": "2022-12-01", "$skiptoken": "2"})],
                  json={"value": [{"subscriptionId": "sub-b", "state": "Enabled"}]})  # fmt: skip
    rid = "/subscriptions/sub-a/resourceGroups/rg-pay/providers/Microsoft.KeyVault/vaults/pay-kv"
    responses.add(responses.GET, f"{ARM}/subscriptions/sub-a/resources", json={"value": [
        {"id": rid, "name": "pay-kv", "type": "Microsoft.KeyVault/vaults"},
        {"id": rid.replace("pay-kv", "sandbox-kv"), "name": "sandbox-kv", "type": "Microsoft.KeyVault/vaults"},
    ]})  # fmt: skip
    responses.add(responses.GET, f"{ARM}/subscriptions/sub-b/resources", json={"value": [
        {"id": "/subscriptions/sub-b/resourceGroups/rg/providers/Microsoft.KeyVault/managedHSMs/core-hsm",
         "name": "core-hsm", "type": "Microsoft.KeyVault/managedHSMs"},
        {"id": "/subscriptions/sub-b/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/locked-kv",
         "name": "locked-kv", "type": "Microsoft.KeyVault/vaults"},
    ]})  # fmt: skip
    _azure_vault("https://pay-kv.vault.azure.net", "tde")
    _azure_vault("https://core-hsm.managedhsm.azure.net", "kek")
    responses.add(responses.GET, "https://locked-kv.vault.azure.net/keys", status=403, json={"error": "Forbidden"})

    res = build(source("azure-all", "azure-keyvault", discover=True, auth="token", token_env="AZT",
                       arm_token_env="ARMT", include_rbac=False, exclude_vaults=["sandbox-kv"])).run()  # fmt: skip
    assert res.error is None, res.error
    by = {a.extra["vault"]: a for a in res.assets}
    assert set(by) == {"pay-kv", "core-hsm"}  # sandbox excluded, locked one skipped, disabled sub ignored
    assert by["pay-kv"].extra["subscription_id"] == "sub-a" and by["pay-kv"].extra["resource_group"] == "rg-pay"
    assert by["core-hsm"].hardware_backed is True and "Managed HSM" in by["core-hsm"].location
    assert not any("sandbox-kv" in c.request.url for c in responses.calls)


@responses.activate
def test_azure_discovery_all_failing_is_an_error(monkeypatch):
    monkeypatch.setenv("ARMT", "eyJ.arm")
    monkeypatch.setenv("AZT", "eyJ.data")
    responses.add(responses.GET, f"{ARM}/subscriptions/sub-x/resources", status=403, json={})
    res = build(source("a", "azure-keyvault", discover=True, subscriptions=["sub-x"], auth="token",
                       token_env="AZT", arm_token_env="ARMT")).run()  # fmt: skip
    assert res.error and "every subscription / vault failed" in res.error


def test_azure_needs_a_vault_or_discover():
    with pytest.raises(ValueError, match="discover"):
        build(source("a", "azure-keyvault"))


# ===================================================================== GCP: every project
GCP = "https://cloudkms.googleapis.com"
CRM = "https://cloudresourcemanager.googleapis.com"


def _gcp_project(project: str, key: str):
    ring = f"projects/{project}/locations/global/keyRings/r"
    responses.add(responses.GET, f"{GCP}/v1/projects/{project}/locations/global/keyRings",
                  json={"keyRings": [{"name": ring}]})  # fmt: skip
    responses.add(responses.GET, f"{GCP}/v1/{ring}/cryptoKeys", json={"cryptoKeys": [{
        "name": f"{ring}/cryptoKeys/{key}", "purpose": "ASYMMETRIC_SIGN", "createTime": "2025-01-01T00:00:00Z",
        "versionTemplate": {"protectionLevel": "HSM", "algorithm": "EC_SIGN_P384_SHA384"}}]})  # fmt: skip
    responses.add(responses.GET, f"{GCP}/v1/{ring}/cryptoKeys/{key}/cryptoKeyVersions", json={})


@responses.activate
def test_gcp_discovers_every_project(monkeypatch):
    monkeypatch.setenv("GT", "ya29.token")
    responses.add(
        responses.GET,
        f"{CRM}/v3/projects:search",
        match=[matchers.query_param_matcher({"query": "state:ACTIVE parent:folders/9", "pageSize": "500"})],
        json={"projects": [{"projectId": "pay"}, {"projectId": "sandbox"}], "nextPageToken": "p2"},
    )
    responses.add(responses.GET, f"{CRM}/v3/projects:search",
                  match=[matchers.query_param_matcher({"query": "state:ACTIVE parent:folders/9", "pageSize": "500",
                                                       "pageToken": "p2"})],
                  json={"projects": [{"projectId": "core"}, {"projectId": "no-kms"}]})  # fmt: skip
    _gcp_project("pay", "signer")
    _gcp_project("core", "root-ca")
    responses.add(
        responses.GET,
        f"{GCP}/v1/projects/no-kms/locations/global/keyRings",
        status=403,
        json={"error": {"status": "PERMISSION_DENIED", "details": [{"reason": "SERVICE_DISABLED"}]}},
    )
    res = build(
        source(
            "gcp-all",
            "gcp-kms",
            discover=True,
            auth="token",
            token_env="GT",
            locations=["global"],
            include_iam=False,
            project_query="parent:folders/9",
            exclude_projects=["sandbox"],
        )
    ).run()
    assert res.error is None, res.error
    assert {a.extra["project"]: a.algorithm for a in res.assets} == {"pay": "EC", "core": "EC"}
    assert not any("sandbox" in c.request.url for c in responses.calls)


@responses.activate
def test_gcp_explicit_project_list_and_all_failing(monkeypatch):
    monkeypatch.setenv("GT", "ya29.token")
    responses.add(
        responses.GET,
        f"{GCP}/v1/projects/a/locations/global/keyRings",
        status=403,
        json={"error": {"status": "PERMISSION_DENIED"}},
    )
    res = build(source("g", "gcp-kms", projects=["a"], auth="token", token_env="GT", locations=["global"])).run()
    assert res.error and "every project failed" in res.error
