"""Google Cloud KMS, for real. Skipped without KEYCENSUS_IT_GCP_PROJECT."""

from __future__ import annotations

import pytest

from keycensus.collectors.gcp_kms import GcpKmsCollector
from keycensus.model import KIND_KEY

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def result(gcp_source):
    res = GcpKmsCollector(gcp_source).run()
    assert res.error is None, f"collector failed: {res.error}"
    return res


def test_scan_succeeds_and_looks_sane(result):
    assert result.assets, "project has no keys -- run bootstrap-gcp.sh"
    for a in result.assets:
        assert a.kind == KIND_KEY
        assert a.native_id.startswith("projects/") and "/cryptoKeys/" in a.native_id
        assert a.algorithm != "unknown", f"{a.name}: could not map {a.extra.get('gcp_algorithm')}"
        assert a.created is not None and a.extra["versions"] >= 1
        assert a.extra["protection_level"] in ("SOFTWARE", "HSM", "EXTERNAL", "EXTERNAL_VPC")
        assert a.hardware_backed == (a.extra["protection_level"] == "HSM")


def test_expected_fixtures(result, fixtures, expect_fixtures):
    if not expect_fixtures:
        pytest.skip("KEYCENSUS_IT_FIXTURES=0")
    by = {a.name: a for a in result.assets if a.extra.get("key_ring") == fixtures["gcp"]["key_ring"]}
    for name, want in fixtures["gcp"]["keys"].items():
        assert name in by, f"expected key {name} not found in ring {fixtures['gcp']['key_ring']} (have: {sorted(by)})"
        a = by[name]
        for field, value in want.items():
            got = getattr(a, field)
            if isinstance(value, list):
                assert sorted(got) == sorted(value), f"{name}.{field}: got {got!r}, want {value!r}"
            else:
                assert got == value, f"{name}.{field}: got {got!r}, want {value!r}"


def test_iam_consumers_are_read(result, expect_fixtures):
    if not expect_fixtures:
        pytest.skip("KEYCENSUS_IT_FIXTURES=0")
    by = {a.name: a for a in result.assets}
    users = by["kcit-sym-rotating"].used_by
    assert any(u["id"].startswith("serviceAccount:kcit-app@") for u in users), users
    assert users[0]["via"].startswith("iam:")
