"""Coverage inside sources that used to be complete-or-failed: Vault mounts and items, AD CS directory and
exports, CipherTrust and KeySafe 5 listings. PKCS#11 tokens and objects are checked in the SoftHSM test."""

import responses

from keycensus.collectors import build
from keycensus.collectors.ciphertrust import CipherTrustCollector
from keycensus.collectors.keysafe5 import KeySafe5Collector
from keycensus.collectors.vault import VaultCollector
from keycensus.model import SCAN_COMPLETE, SCAN_FAILED, SCAN_PARTIAL

from .conftest import make_cert, pem, source
from .test_adcs import cell, certutil_csv

VAULT = "http://vault.test:8200"
CTM = "https://ctm.test"
KS5 = "https://ks5.test"


@responses.activate
def test_vault_denied_mount_is_a_gap_not_a_failure(monkeypatch):
    monkeypatch.setenv("VT", "t")
    responses.add(responses.GET, f"{VAULT}/v1/sys/mounts", json={"data": {
        "transit/": {"type": "transit"}, "transit-pay/": {"type": "transit"}, "pki/": {"type": "pki"}}})  # fmt: skip
    responses.add(responses.GET, f"{VAULT}/v1/sys/policies/acl", status=403, json={"errors": ["permission denied"]})
    responses.add(responses.GET, f"{VAULT}/v1/transit/keys", json={"data": {"keys": ["dek", "gone"]}})
    responses.add(responses.GET, f"{VAULT}/v1/transit/keys/dek", json={"data": {"type": "aes256-gcm96", "keys": {}}})
    responses.add(responses.GET, f"{VAULT}/v1/transit/keys/gone", status=500, json={"errors": ["boom"]})
    responses.add(responses.GET, f"{VAULT}/v1/transit-pay/keys", status=403, json={"errors": ["permission denied"]})
    _, cert = make_cert("a.example")
    responses.add(responses.GET, f"{VAULT}/v1/pki/certs", json={"data": {"keys": ["01"]}})
    responses.add(responses.GET, f"{VAULT}/v1/pki/cert/01", json={"data": {"certificate": pem(cert).decode()}})

    res = VaultCollector(source("v", "vault", url=VAULT, token_env="VT")).run()
    assert res.error is None and res.status == SCAN_PARTIAL
    mounts = res.coverage.scopes["mounts"]
    assert (mounts.expected, mounts.scanned) == (3, 2)
    assert mounts.gaps == [{"id": "mounts:transit-pay", "kind": "denied", "reason": mounts.gaps[0]["reason"]}]
    items = res.coverage.scopes["items"]
    assert (items.expected, items.scanned) == (3, 2)
    assert items.gaps[0]["id"] == "items:transit/keys/gone" and items.gaps[0]["kind"] == "error"
    assert res.coverage.optional_denied == {"list sys/policies/acl": 1}
    dek = next(a for a in res.assets if a.name == "dek")
    assert dek.extra["coverage_scope"] == ["mounts:transit", "items:transit/keys/dek"]
    # a key that was in the denied mount last time is unverified, not removed; one in a scanned mount is removed
    assert res.unverified({"extra": {"coverage_scope": ["mounts:transit-pay", "items:transit-pay/keys/k"]}})
    assert not res.unverified({"extra": {"coverage_scope": ["mounts:transit", "items:transit/keys/old"]}})


@responses.activate
def test_vault_without_sys_mounts_still_fails(monkeypatch):
    monkeypatch.setenv("VT", "t")
    responses.add(responses.GET, f"{VAULT}/v1/sys/mounts", status=403, json={"errors": ["permission denied"]})
    res = VaultCollector(source("v", "vault", url=VAULT, token_env="VT", include_policies=False)).run()
    assert res.status == SCAN_FAILED and "sys/mounts" in res.error


def test_adcs_one_missing_export_makes_the_source_partial(tmp_path):
    _, c = make_cert("web.corp.example.com")
    good = tmp_path / "CA1.csv"
    good.write_text(certutil_csv([["1", "CORP\\w", "Web", "01", "20 -- Issued", "EMPTY", cell(c)]]))
    res = build(source("pki", "adcs", exports=[str(good), {"file": str(tmp_path / "CA2.csv"), "ca": "CA2"}])).run()
    assert res.error is None and res.status == SCAN_PARTIAL
    ex = res.coverage.scopes["exports"]
    assert (ex.expected, ex.scanned) == (2, 1)
    assert ex.gaps[0]["id"] == "exports:CA2" and ex.gaps[0]["kind"] == "unavailable"
    assert res.assets[0].extra["coverage_scope"] == ["exports:CA1", "exports:CA1/rows"]


def test_adcs_unparseable_rows_are_a_gap(tmp_path):
    _, c = make_cert("web.corp.example.com")
    p = tmp_path / "CA1.csv"
    p.write_text(certutil_csv([["1", "CORP\\w", "Web", "01", "20 -- Issued", "EMPTY", cell(c)],
                               ["2", "CORP\\x", "Web", "02", "20 -- Issued", "EMPTY", "garbage !!"]]))  # fmt: skip
    res = build(source("pki", "adcs", exports=[str(p)])).run()
    assert res.status == SCAN_PARTIAL
    gaps = res.coverage.scopes["exports"].gaps
    assert gaps[0]["id"] == "exports:CA1/rows" and "1 row(s)" in gaps[0]["reason"]


def test_adcs_directory_down_with_exports_is_partial(monkeypatch, tmp_path):
    _, c = make_cert("web.corp.example.com")
    p = tmp_path / "CA1.csv"
    p.write_text(certutil_csv([["1", "CORP\\w", "Web", "01", "20 -- Issued", "EMPTY", cell(c)]]))
    col = build(source("pki", "adcs", ldap_url="ldaps://dc01.corp.example.com", exports=[str(p)]))

    def down():
        raise ConnectionError("could not connect to dc01.corp.example.com:636")

    monkeypatch.setattr(col, "_connect", down)
    res = col.run()
    assert res.status == SCAN_PARTIAL and len(res.assets) == 1
    assert res.coverage.scopes["directory"].gaps[0]["id"] == "directory:dc01.corp.example.com"
    assert res.coverage.scopes["directory"].gaps[0]["kind"] == "unavailable"


def test_adcs_nothing_readable_is_still_failed(tmp_path):
    res = build(source("pki", "adcs", exports=[str(tmp_path / "a.csv"), str(tmp_path / "b.csv")])).run()
    assert res.status == SCAN_FAILED and "does not exist" in res.error


def _ctm_key(i):
    return {"id": str(i), "name": f"k{i}", "algorithm": "AES", "size": 256, "objectType": "Symmetric Key",
            "state": "Active", "usageMask": 12}  # fmt: skip


@responses.activate
def test_ciphertrust_later_page_failure_is_partial(monkeypatch):
    monkeypatch.setenv("CTJ", "jwt")
    url = f"{CTM}/api/v1/vault/keys2"
    responses.add(responses.GET, url, json={"total": 3, "resources": [_ctm_key(1), _ctm_key(2)]})
    responses.add(responses.GET, url, status=503, json={"error": "busy"})
    res = CipherTrustCollector(source("c", "ciphertrust", url=CTM, jwt_env="CTJ", page_size=2)).run()
    assert res.error is None and res.status == SCAN_PARTIAL and len(res.assets) == 2
    keys = res.coverage.scopes["keys"]
    assert (keys.expected, keys.scanned) == (3, 2)
    assert keys.gaps[0]["id"] == "keys:listing" and keys.gaps[0]["kind"] == "unavailable"
    assert all(a.extra["coverage_scope"] == ["keys:listing"] for a in res.assets)


@responses.activate
def test_ciphertrust_complete_listing(monkeypatch):
    monkeypatch.setenv("CTJ", "jwt")
    responses.add(responses.GET, f"{CTM}/api/v1/vault/keys2", json={"total": 1, "resources": [_ctm_key(1)]})
    res = CipherTrustCollector(source("c", "ciphertrust", url=CTM, jwt_env="CTJ")).run()
    assert res.status == SCAN_COMPLETE
    assert res.coverage.scopes["keys"].expected == 1 and res.coverage.scopes["keys"].scanned == 1


@responses.activate
def test_keysafe5_listing_cut_off_is_a_gap(monkeypatch):
    monkeypatch.setenv("KT", "t")
    monkeypatch.setattr(KeySafe5Collector, "MAX_PAGES", 2)
    key = {"name": "k", "type": "Rijndael", "size": 256, "id": "1"}
    for _ in range(3):
        responses.add(responses.GET, f"{KS5}/mgmt/v1/keys", json={"keys": [key], "next": "p"})
    res = KeySafe5Collector(source("k", "keysafe5", url=KS5, token_env="KT", keys_path="/mgmt/v1/keys",
                                   hsms_path=None)).run()  # fmt: skip
    assert res.error is None and res.status == SCAN_PARTIAL
    keys = res.coverage.scopes["keys"]
    assert keys.scanned == 2 and keys.gaps[0]["reason"] == "stopped after 2 pages"
