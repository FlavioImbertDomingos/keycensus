"""The checks the kind CI job runs, against hand-written results shaped like a real run."""

import copy

from .integration.kind_check import check


def _asset(id_, ns, secret, kind="certificate", **kw):
    a = {"id": id_, "kind": kind, "algorithm": "RSA", "key_size": 2048, "curve": None, "used_by": [],
         "extra": {"namespace": ns, "secret": secret}}  # fmt: skip
    a.update({k: v for k, v in kw.items() if k != "extra"})
    a["extra"].update(kw.get("extra", {}))
    return a


GOOD_INV = {
    "assets": [
        _asset("w", "apps", "web-tls", extra={"key_matches_certificate": True},
               used_by=[{"type": "workload", "id": "apps/ReplicaSet/web-5d8f", "via": "k8s-volume"}]),
        _asset("s", "apps", "signer", kind="key", algorithm="EC", key_size=256, curve="P-256"),
        _asset("c", "certs", "internal-tls", algorithm="EC", key_size=256, curve="P-256",
               extra={"cert_manager": {"certificate": "certs/internal", "issuer": "Issuer/selfsigned",
                                       "rotation_policy": "Never", "ready": True}}),
    ],  # fmt: skip
    "findings": [{"asset_id": "c", "rule_id": "key-reuse-on-renewal"}],
    "sources": [{"status": "partial", "coverage": {"scopes": {
        "namespaces": {"gaps": [{"id": "namespaces:locked", "kind": "denied"}]},
        "namespaces-opaque": {"gaps": [{"id": "namespaces-opaque:locked", "kind": "denied"}]}}}}],
}  # fmt: skip
GOOD_DOC = {"status": "partial", "sources": [{"problems": [
    {"level": "gap", "scope": "namespaces", "items": ["locked"],
     "fix": {"file": "deploy/kubernetes/keycensus-reader.yaml"}},
    {"level": "optional", "scope": "clusterissuers/list"}]}]}  # fmt: skip


def test_a_correct_run_passes():
    assert check(GOOD_INV, GOOD_DOC) == []


def test_leaks_and_misses_fail():
    inv = copy.deepcopy(GOOD_INV)
    inv["assets"].append(_asset("x", "locked", "hidden-tls"))
    inv["assets"][0]["used_by"] = []
    inv["findings"] = []
    fails = check(inv, GOOD_DOC)
    assert any("locked namespace" in f for f in fails)
    assert any("used_by" in f for f in fails)
    assert any("key-reuse-on-renewal" in f for f in fails)


def test_doctor_must_name_the_namespace_and_file():
    doc = copy.deepcopy(GOOD_DOC)
    doc["sources"][0]["problems"][0]["fix"]["file"] = None
    assert any("keycensus-reader.yaml" in f for f in check(GOOD_INV, doc))
