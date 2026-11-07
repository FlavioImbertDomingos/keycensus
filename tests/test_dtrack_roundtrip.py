"""The comparison the Dependency-Track CI job runs, checked offline against a simulated export.

The real round trip runs in CI against Dependency-Track containers (the `dependency-track` job); these
tests make sure the comparison itself would notice a lost component, property or dependency edge.
"""

import uuid

import pytest
import responses

from keycensus.dtrack import DependencyTrack, DependencyTrackError
from keycensus.exporters import cbom

from .integration.dtrack_roundtrip import compare, identity, roundtrip_ok, summary_markdown

DT = "http://dt.test"


def simulated_export(sent: dict, drop_crypto=True) -> dict:
    """What Dependency-Track 5.1 does to a BOM, as read from its source: new bom-refs, components with the
    same identity merged, cryptoProperties and embedded vulnerabilities not stored."""
    seen, comps, ref_map = {}, [], {}
    for c in sent["components"]:
        k = identity(c)
        if k not in seen:
            seen[k] = str(uuid.uuid4())
            keep = {kk: v for kk, v in c.items() if kk != "bom-ref" and not (drop_crypto and kk == "cryptoProperties")}
            comps.append(keep | {"bom-ref": seen[k]})
        ref_map[c["bom-ref"]] = seen[k]
    deps: dict[str, set] = {}
    for d in sent.get("dependencies") or []:
        if d["ref"] in ref_map:
            deps.setdefault(ref_map[d["ref"]], set()).update(
                ref_map[t] for t in d.get("dependsOn") or [] if t in ref_map
            )
    return {"components": comps, "dependencies": [{"ref": r, "dependsOn": sorted(v)} for r, v in deps.items()]}


@pytest.fixture(params=["1.6", "1.7"])
def sent(request, sample_inventory):
    return cbom.build(sample_inventory, request.param)


def test_a_faithful_import_passes(sent):
    r = compare(sent, simulated_export(sent))
    assert roundtrip_ok(r) == []
    assert r["components_back"] == r["distinct_identities_sent"] > 0
    assert r["crypto_properties_back"] == 0 < r["crypto_properties_sent"]
    assert r["vulnerabilities_back"] == 0 < r["vulnerabilities_sent"]
    assert r["dependency_edges_sent"] > 0 and r["dependency_edges_missing"] == []
    assert "round-trip holds" in summary_markdown("5.1.2", sent["specVersion"], r, [])


def test_lost_components_properties_and_edges_are_caught(sent):
    back = simulated_export(sent)
    gone = back["components"].pop()
    for c in back["components"]:
        c["properties"] = [p for p in c.get("properties") or [] if p["name"] != "keycensus:source"]
    back["dependencies"] = back["dependencies"][1:]
    r = compare(sent, back)
    problems = roundtrip_ok(r)
    assert any("components differ" in p and gone["name"] in p for p in problems)
    assert any("properties lost" in p for p in problems)
    assert any("dependency edges lost" in p for p in problems)


def test_a_changed_type_is_caught(sent):
    back = simulated_export(sent)
    back["components"][0]["type"] = "library"  # what Dependency-Track 4 would do if it fell back to LIBRARY
    assert any("types changed" in p for p in roundtrip_ok(compare(sent, back)))


def test_same_name_components_are_reported_as_merged():
    sent = {"components": [
        {"bom-ref": "a", "type": "cryptographic-asset", "name": "Ed25519"},
        {"bom-ref": "b", "type": "cryptographic-asset", "name": "Ed25519"},
        {"bom-ref": "c", "type": "cryptographic-asset", "name": "RSA-2048"}],
        "dependencies": [{"ref": "a", "dependsOn": ["b"]}, {"ref": "c", "dependsOn": ["b"]}]}  # fmt: skip
    r = compare(sent, simulated_export(sent))
    assert r["merged_by_identity"] == {"Ed25519": 2} and roundtrip_ok(r) == []
    assert r["dependency_edges_sent"] == 1  # a -> b collapses onto itself once merged


@responses.activate
def test_upload_wait_reports_failed_processing():
    responses.add(responses.GET, f"{DT}/api/v1/bom/token/t", json={"processing": False, "status": "FAILED"})
    with pytest.raises(DependencyTrackError, match="FAILED"):
        DependencyTrack(DT, "k").wait("t", timeout=5, interval=0)


@responses.activate
def test_upload_wait_still_works_without_status():
    responses.add(responses.GET, f"{DT}/api/v1/bom/token/t", json={"processing": False})
    assert DependencyTrack(DT, "k").wait("t", timeout=5, interval=0)


@pytest.mark.parametrize("version", ["1.6", "1.7"])
def test_keys_and_algorithms_no_longer_share_an_identity(sample_inventory, version):
    """Each asset's component carries its source as `group`, so Dependency-Track cannot merge a key named
    after its algorithm with the algorithm, or same-named keys from two sources."""
    bom = cbom.build(sample_inventory, version)
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    for a in sample_inventory.assets:
        if a.id in by_ref:
            assert by_ref[a.id]["group"] == a.source
    algorithm_names = {c["name"] for c in bom["components"] if "group" not in c and c["type"] != "application"}
    for c in bom["components"]:
        if "group" in c:
            assert identity(c) not in {("", n, "", "") for n in algorithm_names}


def test_merged_asset_components_fail_the_roundtrip():
    sent = {"components": [
        {"bom-ref": "a", "type": "cryptographic-asset", "group": "vault", "name": "dek"},
        {"bom-ref": "b", "type": "cryptographic-asset", "group": "vault", "name": "dek"}]}  # fmt: skip
    r = compare(sent, simulated_export(sent))
    assert r["assets_merged"] == ["vault/dek"]
    assert any("were merged" in p for p in roundtrip_ok(r))
