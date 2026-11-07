"""Kubernetes collector: the official client against a local API server that answers like kube-apiserver."""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from keycensus.analysis.policy import Policy, evaluate
from keycensus.collectors import build
from keycensus.model import KIND_CERTIFICATE, KIND_KEY

from .conftest import make_cert, pem, source
from .keymaterial import need

pytest.importorskip("kubernetes")


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def key_pem(k) -> bytes:
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def secret(ns, name, type_, data, annotations=None):
    return {"metadata": {"name": name, "namespace": ns, "annotations": annotations or {}}, "type": type_,
            "data": {k: b64(v) for k, v in data.items()}}  # fmt: skip


def lst(kind, items, cont=None):
    return {"kind": kind, "apiVersion": "v1", "metadata": {"continue": cont} if cont else {}, "items": items}


class FakeKube:
    def __init__(self, keystore: bytes | None, cert_manager: bool = True):
        k1 = ec.generate_private_key(ec.SECP256R1())
        ca_key, ca = make_cert("Intermediate CA", ca=True)
        _, leaf = make_cert("api.payments.example.com", key=k1, issuer="Intermediate CA", issuer_key=ca_key)
        _, other = make_cert("old.example.com")
        stray = ec.generate_private_key(ec.SECP384R1())
        self.tls = [
            secret("payments", "api-tls", "kubernetes.io/tls", {"tls.crt": pem(leaf) + pem(ca), "tls.key": key_pem(k1),
                                                                "ca.crt": pem(ca)},
                   {"cert-manager.io/certificate-name": "api"}),
            secret("legacy", "old-tls", "kubernetes.io/tls", {"tls.crt": pem(other), "tls.key": key_pem(stray)}),
        ]  # fmt: skip
        opaque = {"password": b"not a key", "README": b"hello"}
        if keystore:
            opaque["broker.keystore.jks"] = keystore
        self.opaque = [secret("kafka", "broker-keystore", "Opaque", opaque)]
        self.cert_manager = cert_manager
        self.requests: list[str] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):  # noqa: N802
                outer.requests.append(self.path)
                assert self.headers.get("Authorization") == "Bearer test-token"
                code, body = outer.route(self.path)
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def route(self, path):
        u = urlparse(path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        p = u.path
        if p.endswith("/secrets"):
            ns = p.split("/")[4] if "/namespaces/" in p else None
            items = self.tls if q.get("fieldSelector") == "type=kubernetes.io/tls" else self.opaque
            items = [s for s in items if ns in (None, s["metadata"]["namespace"])]
            if not q.get("continue") and len(items) > 1:  # two pages: exercises `continue`
                return 200, lst("SecretList", items[:1], cont="page2")
            return 200, lst("SecretList", items[1:] if q.get("continue") else items)
        if p.endswith("/pods"):
            pod = {"metadata": {"name": "api-7d9f-x2", "namespace": "payments",
                                "ownerReferences": [{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "api-7d9f",
                                                     "uid": "u1"}]},
                   "spec": {"containers": [{"name": "api", "env": [{"name": "K", "valueFrom": {"secretKeyRef": {
                       "name": "api-tls", "key": "tls.key"}}}]}],
                            "volumes": [{"name": "tls", "secret": {"secretName": "api-tls"}}]}}  # fmt: skip
            return 200, lst("PodList", [pod])
        if p.endswith("/ingresses"):
            ing = {"metadata": {"name": "api", "namespace": "payments"},
                   "spec": {"tls": [{"hosts": ["api.payments.example.com"], "secretName": "api-tls"}]}}  # fmt: skip
            return 200, lst("IngressList", [ing])
        if p.startswith("/apis/cert-manager.io/"):
            if not self.cert_manager:
                return 404, {"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound",
                             "code": 404}  # fmt: skip
            if p.endswith("/clusterissuers"):
                acme = {"server": "https://acme-v02.api.letsencrypt.org/directory"}
                return 200, lst("ClusterIssuerList", [{"metadata": {"name": "letsencrypt"}, "spec": {"acme": acme}}])
            if p.endswith("/issuers"):
                return 200, lst("IssuerList", [])
            if p.endswith("/certificates"):
                return 200, lst("CertificateList", [
                    {"metadata": {"name": "api", "namespace": "payments"},
                     "spec": {"secretName": "api-tls", "dnsNames": ["api.payments.example.com"],
                              "issuerRef": {"name": "letsencrypt", "kind": "ClusterIssuer"},
                              "privateKey": {"algorithm": "ECDSA", "size": 256, "rotationPolicy": "Never"}},
                     "status": {"conditions": [{"type": "Ready", "status": "True"}],
                                "notAfter": "2027-01-01T00:00:00Z"}},
                    {"metadata": {"name": "pending", "namespace": "payments"},
                     "spec": {"secretName": "pending-tls", "commonName": "pending.example.com",
                              "issuerRef": {"name": "letsencrypt", "kind": "ClusterIssuer"},
                              "privateKey": {"algorithm": "ECDSA", "size": 384}},
                     "status": {"conditions": [{"type": "Ready", "status": "False"}]}},
                ])  # fmt: skip
        return 404, {"kind": "Status", "code": 404}

    def kubeconfig(self, tmp_path):
        cfg = {"apiVersion": "v1", "kind": "Config", "current-context": "test",
               "clusters": [{"name": "c", "cluster": {"server": self.url}}],
               "users": [{"name": "u", "user": {"token": "test-token"}}],
               "contexts": [{"name": "test", "context": {"cluster": "c", "user": "u"}}]}  # fmt: skip
        p = tmp_path / "kubeconfig"
        p.write_text(json.dumps(cfg))
        return str(p)

    def close(self):
        self.srv.shutdown()


@need("keytool")
def test_collects_secrets_cert_manager_and_consumers(tmp_path, keymaterial):
    kube = FakeKube((keymaterial / "app.jks").read_bytes())
    try:
        r = build(source("prod", "kubernetes", kubeconfig=kube.kubeconfig(tmp_path), cluster_name="prod")).run()
    finally:
        kube.close()
    assert r.error is None, r.error
    by = {a.native_id: a for a in r.assets}

    api = by["k8s:prod/payments/api-tls#leaf"]
    assert api.kind == KIND_CERTIFICATE and api.subject == "CN=api.payments.example.com"
    assert api.extra["key_matches_certificate"] is True and api.extra["key_algorithm"] == "EC-P-256"
    assert api.extra["cert_manager"]["issuer_type"].startswith("acme (https://acme-v02")
    assert api.extra["cert_manager"]["rotation_policy"] == "Never" and api.rotation_enabled is True
    assert {(u["id"], u["via"]) for u in api.used_by} == {("payments/ReplicaSet/api-7d9f", "k8s-volume"),
                                                          ("payments/ReplicaSet/api-7d9f", "k8s-env"),
                                                          ("payments/Ingress/api", "k8s-ingress")}  # fmt: skip
    assert "k8s:prod/payments/api-tls#1" not in by  # intermediates only with include_chain

    old = by["k8s:prod/legacy/old-tls#leaf"]
    assert old.extra["key_matches_certificate"] is False

    pending = by["k8s:prod/payments/certificate/pending"]
    assert (pending.algorithm, pending.curve, pending.extra["from_cert_manager_spec"]) == ("EC", "P-384", True)

    jks = [a for a in r.assets if a.extra.get("secret_key") == "broker.keystore.jks"]
    assert {a.kind for a in jks} == {KIND_KEY, KIND_CERTIFICATE} and len(jks) == 4
    assert all(a.name.startswith("kafka/broker-keystore:") for a in jks)
    assert not any(a.extra.get("secret_key") in ("password", "README") for a in r.assets)

    assert any("continue=page2" in p for p in kube.requests)  # followed pagination
    rules = {(f.rule_id, f.asset_name) for f in evaluate(r.assets, Policy.default())}
    assert ("key-reuse-on-renewal", api.name) in rules
    assert any(rid == "keystore-weak-protection" and n.startswith("kafka/") for rid, n in rules)


def test_namespaces_chain_and_no_cert_manager(tmp_path):
    kube = FakeKube(None, cert_manager=False)
    try:
        r = build(source("prod", "kubernetes", kubeconfig=kube.kubeconfig(tmp_path), namespaces=["payments"],
                         include_chain=True, find_consumers=False)).run()  # fmt: skip
    finally:
        kube.close()
    assert r.error is None, r.error
    assert {a.extra["namespace"] for a in r.assets} == {"payments"}
    assert any(a.native_id.endswith("#1") for a in r.assets) and any("#ca" in a.native_id for a in r.assets)
    assert all("/namespaces/payments/" in p for p in kube.requests if "/secrets" in p)
    assert not any("/pods" in p for p in kube.requests)


def test_no_credentials(tmp_path, monkeypatch):
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    r = build(source("x", "kubernetes", kubeconfig=str(tmp_path / "missing"))).run()
    assert "no Kubernetes credentials" in r.error


class NamespacedKube(FakeKube):
    """RBAC as deploy/kubernetes/keycensus-reader.yaml describes when narrowed: RoleBindings in some
    namespaces, no ClusterRoleBinding. Everything in `locked`, and every cluster-scoped list, is forbidden."""

    def route(self, path):
        p = urlparse(path).path
        if "/namespaces/locked/" in p or "/namespaces/" not in p:
            return 403, {"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "Forbidden",
                         "code": 403}  # fmt: skip
        return super().route(path)


def test_rolebindings_per_namespace_give_a_gap_only_for_the_unbound_one(tmp_path):
    from keycensus.doctor import diagnose

    kube = NamespacedKube(None)
    try:
        r = build(source("prod", "kubernetes", kubeconfig=kube.kubeconfig(tmp_path),
                         namespaces=["payments", "locked", "legacy"])).run()  # fmt: skip
    finally:
        kube.close()
    assert r.error is None, r.error
    assert r.status == "partial"
    assert {a.extra.get("namespace") for a in r.assets if a.extra.get("namespace")} == {"payments", "legacy"}
    gaps = {g["id"]: g["kind"] for s in r.coverage.scopes.values() for g in s.gaps}
    assert gaps == {"namespaces:locked": "denied", "namespaces-opaque:locked": "denied",
                    "cert-manager:issuers/locked": "denied", "cert-manager:certificates/locked": "denied"}  # fmt: skip
    # pods and ingresses in the other namespaces were still read; ClusterIssuers are an optional read
    assert set(r.coverage.optional_denied) == {"pods/list", "ingresses/list", "clusterissuers/list"}
    api = next(a for a in r.assets if a.extra.get("secret") == "api-tls")
    assert any(u["id"].startswith("payments/") for u in api.used_by)
    d = diagnose({"name": r.name, "type": r.type, "assets": len(r.assets), "coverage": r.coverage})
    ns_gap = next(p for p in d.problems if p.scope == "namespaces")
    assert ns_gap.items == ["locked"] and ns_gap.fix.file == "deploy/kubernetes/keycensus-reader.yaml"
