"""Azure Key Vault, for real. Skipped without KEYCENSUS_IT_AZURE_VAULT_URL."""

from __future__ import annotations

import pytest

from keycensus.collectors.azure_keyvault import AzureKeyVaultCollector
from keycensus.model import KIND_CERTIFICATE, KIND_KEY

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def result(azure_source):
    res = AzureKeyVaultCollector(azure_source).run()
    assert res.error is None, f"collector failed: {res.error}"
    return res


def test_scan_succeeds_and_looks_sane(result):
    assert result.assets, "vault has no keys/certificates -- run bootstrap-azure.sh"
    for a in result.assets:
        assert a.kind in (KIND_KEY, KIND_CERTIFICATE)
        assert a.native_id.startswith("https://") and ("/keys/" in a.native_id or "/certificates/" in a.native_id)
        assert a.algorithm != "unknown", f"{a.name}: could not map kty {a.extra.get('kty')}"
        assert a.created is not None
        assert a.hardware_backed is not None and a.exportable is not None
        assert "Key Vault" in a.location or "Managed HSM" in a.location


def test_versionless_ids_are_stable(result):
    ids = [a.native_id for a in result.assets]
    assert len(ids) == len(set(ids)), "asset ids must be unique (version-less kid/id)"
    # https://<vault>/keys/<name> -- exactly four path-ish segments, no version suffix
    assert all(len(i.split("/")) == 5 for i in ids), ids


def test_expected_fixtures(result, fixtures, expect_fixtures):
    if not expect_fixtures:
        pytest.skip("KEYCENSUS_IT_FIXTURES=0")
    by = {a.name: a for a in result.assets}
    for name, want in fixtures["azure"]["keys"].items():
        if name not in by:
            if want.get("optional"):
                continue
            pytest.fail(f"expected key {name} not found (have: {sorted(by)})")
        a = by[name]
        assert a.kind == KIND_KEY
        for field, value in want.items():
            if field == "optional":
                continue
            assert getattr(a, field) == value, f"{name}.{field}: got {getattr(a, field)!r}, want {value!r}"
    for name, want in fixtures["azure"]["certificates"].items():
        a = by.get(name)
        assert a is not None, f"expected certificate {name} not found"
        assert a.kind == KIND_CERTIFICATE and a.source_type == "azure-keyvault-cert"
        for field, value in want.items():
            assert getattr(a, field) == value, f"{name}.{field}: got {getattr(a, field)!r}, want {value!r}"
        assert a.fingerprint_sha256 and a.expires is not None


def test_rotation_policy_is_read(result, expect_fixtures):
    if not expect_fixtures:
        pytest.skip("KEYCENSUS_IT_FIXTURES=0")
    by = {a.name: a for a in result.assets}
    assert by["kcit-rsa-rotating"].rotation_enabled is True
    assert by["kcit-ec-p384"].rotation_enabled is False


def test_rbac_consumers_when_the_identity_can_read_them(result):
    """`include_rbac` needs Reader on the management plane, which the bootstrap grants
    but somebody else's account may not. Absent consumers are a skip, not a failure:
    the collector is required to degrade quietly, and that is what is asserted here."""
    used = [u for a in result.assets for u in a.used_by]
    if not used:
        pytest.skip(
            "no consumers reported -- expected when the identity lacks Reader on the vault, "
            "or when include_rbac/subscription_id are unset. The scan itself still succeeded, "
            "which is the property that matters."
        )
    for u in used:
        assert set(u) >= {"type", "id", "via"}
        assert u["via"].startswith(("rbac:", "access-policy:", "local-rbac:"))
        assert u["id"], "a consumer with no principal is not a consumer"
    # Azure authorizes at the vault scope, so every asset carries the same list.
    lists = {tuple(sorted(u["id"] for u in a.used_by)) for a in result.assets}
    assert len(lists) == 1, "consumers should be identical across a vault's assets"
