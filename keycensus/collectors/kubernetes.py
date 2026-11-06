"""Collector: certificates and keys in Kubernetes secrets, and what cert-manager is managing.

    - name: prod-cluster
      type: kubernetes
      # kubeconfig: ~/.kube/config         # default: the in-cluster service account, else $KUBECONFIG
      # context: prod
      namespaces: []                       # default: every namespace
      tls_secrets: true                    # kubernetes.io/tls secrets: the certificate in tls.crt
      opaque_secrets: true                 # Opaque secrets: any value that is a key, certificate or keystore
      include_chain: false                 # also report intermediates in tls.crt and ca.crt
      cert_manager: true                   # Certificate, Issuer and ClusterIssuer resources
      find_consumers: true                 # pods and ingresses that mount or reference each secret
      keystore_passwords: [{password_env: KEYSTORE_PASSWORD}]
      max_value_bytes: 1000000

What comes back:

* For each TLS secret, a `certificate` asset for the leaf in `tls.crt`, with
  `extra.key_matches_certificate` (a tls.key that does not match tls.crt breaks the workload at
  the next restart) and the key's algorithm.
* For Opaque secrets, everything keycensus.collectors.keyfiles recognises in each value: PEM keys
  and certificates, PKCS#12, JKS and JCEKS keystores (Kafka, Hadoop and Java apps keep them here),
  SSH keys. Values that are not key material are not decoded beyond the first bytes.
* cert-manager: each Certificate is matched to its secret, and the asset gets `extra.cert_manager`
  (issuer and issuer type, private key algorithm, rotationPolicy, renewBefore, Ready). A Certificate
  whose secret is not readable or not issued yet is reported from its spec. `rotationPolicy: Never`
  (the default before cert-manager 1.18) reuses the private key at every renewal and gets a
  `key-reuse-on-renewal` finding.
* `used_by`: the pods (by owner) that mount the secret or read it into env vars, and the ingresses
  that terminate TLS with it.

Reading secrets means reading their values: the `get`/`list` grant on secrets cannot be narrowed to
TLS secrets by Kubernetes RBAC. keycensus decodes values in memory and keeps only descriptions. The
ClusterRole is in deploy/kubernetes/keycensus-reader.yaml.
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..model import KIND_CERTIFICATE, STATE_ACTIVE, STATE_DEACTIVATED, CryptoAsset, utcnow
from . import keyfiles
from .base import Collector, CollectorError, gap_kind
from .pem_files import entries_to_assets, keystore_passwords
from .x509util import certificate_fields, describe_public_key

log = logging.getLogger(__name__)

CM_GROUP, CM_VERSION = "cert-manager.io", "v1"
_CM_CURVES = {256: "P-256", 384: "P-384", 521: "P-521"}


def _parse_time(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def _owner(meta) -> str:
    refs = getattr(meta, "owner_references", None) or []
    if refs:
        r = refs[0]
        return f"{r.kind}/{r.name}"
    return f"Pod/{meta.name}"


class KubernetesCollector(Collector):
    type_name = "kubernetes"
    requires_extra = "kubernetes"

    def collect(self) -> list[CryptoAsset]:
        from kubernetes import client  # noqa: PLC0415

        api = self._api_client()
        self.core = client.CoreV1Api(api)
        self.custom = client.CustomObjectsApi(api)
        self.net = client.NetworkingV1Api(api)
        self.namespaces = [str(n) for n in self.opt.get("namespaces") or []]
        self.passwords = keystore_passwords(self.opt, self.name)
        self.max_bytes = int(self.opt.get("max_value_bytes", 1_000_000))
        self.cluster = str(self.opt.get("cluster_name") or self.opt.get("context") or self.name)

        consumers = self._consumers() if self.opt.get("find_consumers", True) else {}
        assets: list[CryptoAsset] = []
        by_secret: dict[tuple[str, str], list[CryptoAsset]] = {}
        if self.opt.get("tls_secrets", True):
            for s in self._secrets("type=kubernetes.io/tls"):
                found = self._tls_secret(s)
                by_secret.setdefault((s.metadata.namespace, s.metadata.name), []).extend(found)
                assets += found
        if self.opt.get("opaque_secrets", True):
            for s in self._secrets("type=Opaque"):
                found = self._opaque_secret(s)
                by_secret.setdefault((s.metadata.namespace, s.metadata.name), []).extend(found)
                assets += found
        if self.opt.get("cert_manager", True):
            assets += self._cert_manager(by_secret)
        for key, found in by_secret.items():
            for a in found:
                a.used_by.extend(consumers.get(key, []))
        return assets

    # --------------------------------------------------------------- client
    def _api_client(self):
        from kubernetes import client, config  # noqa: PLC0415

        kubeconfig, context = self.opt.get("kubeconfig"), self.opt.get("context")
        if not kubeconfig and not context:
            try:
                config.load_incluster_config()
                return client.ApiClient()
            except config.ConfigException:
                pass
        try:
            return config.new_client_from_config(config_file=kubeconfig, context=context)
        except (config.ConfigException, FileNotFoundError) as exc:
            raise CollectorError(f"[{self.name}] no Kubernetes credentials: {exc}") from exc

    def _list(self, all_ns, per_ns, scope: str | None = None, **kw):
        """Every item, across the configured namespaces, following `continue` tokens. With `scope`, a namespace
        that cannot be listed is recorded as a coverage gap and skipped; the cluster-wide list failing fails
        the source."""
        from kubernetes.client.exceptions import ApiException  # noqa: PLC0415

        targets = [(per_ns, {"namespace": ns}) for ns in self.namespaces] or [(all_ns, {})]
        for fn, args in targets:
            cont = None
            items: list = []
            try:
                while True:
                    page = fn(limit=500, _continue=cont, **args, **kw)
                    items += page.items
                    cont = page.metadata._continue
                    if not cont:
                        break
            except ApiException as exc:
                if not (scope and args):
                    raise
                self.coverage.gap(scope, args["namespace"], f"HTTP {exc.status}: {exc.reason}", gap_kind(exc))
                log.warning("[%s] %s in namespace %s: HTTP %s", self.name, scope, args["namespace"], exc.status)
                continue
            if scope and args:
                self.coverage.ok(scope)
            yield from items

    def _secrets(self, field_selector: str):
        scope = "namespaces" if field_selector == "type=kubernetes.io/tls" else "namespaces-opaque"
        if self.namespaces:
            self.coverage.expect(scope, len(self.namespaces))
        return self._list(self.core.list_secret_for_all_namespaces, self.core.list_namespaced_secret,
                          scope=scope, field_selector=field_selector)  # fmt: skip

    # -------------------------------------------------------------- secrets
    def _value(self, s, key: str) -> bytes | None:
        raw = (s.data or {}).get(key)
        if raw is None or len(raw) > self.max_bytes * 4 // 3 + 4:
            return None
        try:
            return base64.b64decode(raw)
        except (ValueError, TypeError):
            return None

    def _base(self, s) -> tuple[str, str, dict[str, Any]]:
        ns, name = s.metadata.namespace, s.metadata.name
        ann = s.metadata.annotations or {}
        extra: dict[str, Any] = {"namespace": ns, "secret": name, "secret_type": s.type, "cluster": self.cluster,
                                 "coverage_scope": [f"namespaces:{ns}", f"namespaces-opaque:{ns}"]}  # fmt: skip
        if ann.get("cert-manager.io/certificate-name"):
            extra["cert_manager_certificate"] = ann["cert-manager.io/certificate-name"]
        return f"k8s:{self.cluster}/{ns}/{name}", f"k8s:{ns}/secret/{name}", extra

    def _tls_secret(self, s) -> list[CryptoAsset]:
        native, location, extra = self._base(s)
        crt = self._value(s, "tls.crt") or b""
        try:
            chain = x509.load_pem_x509_certificates(crt)
        except ValueError as exc:
            log.info("[%s] %s: tls.crt unreadable: %s", self.name, location, exc)
            return []
        if not chain:
            return []
        key_info: dict[str, Any] = {}
        key_pem = self._value(s, "tls.key")
        if key_pem:
            try:
                key = serialization.load_pem_private_key(key_pem, password=None)
                alg, size, curve = describe_public_key(key)
                spki = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                pub = key.public_key().public_bytes(*spki)
                leaf_pub = chain[0].public_key().public_bytes(*spki)
                key_info = {"key_algorithm": f"{alg}-{curve or size}", "key_matches_certificate": pub == leaf_pub}
            except (ValueError, TypeError) as exc:
                key_info = {"key_unreadable": str(exc)[:200]}
        certs = list(enumerate(chain if self.opt.get("include_chain") else chain[:1]))
        if self.opt.get("include_chain"):
            ca = self._value(s, "ca.crt")
            if ca:
                try:
                    certs += [(f"ca{i}", c) for i, c in enumerate(x509.load_pem_x509_certificates(ca))]
                except ValueError:
                    pass
        out = []
        for idx, cert in certs:
            f = certificate_fields(cert)
            f["extra"].update(extra, **(key_info if idx == 0 else {}), chain_position=idx)
            out.append(self.asset(native_id=f"{native}#{'leaf' if idx == 0 else idx}", location=location,
                                  hardware_backed=False if idx == 0 else None, **f))  # fmt: skip
        return out

    def _opaque_secret(self, s) -> list[CryptoAsset]:
        native, location, extra = self._base(s)
        out: list[CryptoAsset] = []
        for key in sorted(s.data or {}):
            data = self._value(s, key)
            if not data or not keyfiles.looks_like_key_material(data):
                continue
            try:
                entries = keyfiles.parse(data, key, self.passwords)
            except (keyfiles.KeyfileError, ValueError) as exc:
                log.info("[%s] %s/%s: %s", self.name, location, key, exc)
                continue
            for e in entries:
                e.fields["name"] = f"{s.metadata.namespace}/{s.metadata.name}:{e.fields.get('name') or key}"
            out += entries_to_assets(self, entries, f"{native}:{key}", f"{location}:{key}",
                                     extra={**extra, "secret_key": key}, compat_single_key_id=False)  # fmt: skip
        return out

    # ---------------------------------------------------------- consumers
    def _consumers(self) -> dict[tuple[str, str], list[dict[str, str]]]:
        from kubernetes.client.exceptions import ApiException  # noqa: PLC0415

        out: dict[tuple[str, str], list[dict[str, str]]] = {}

        def add(ns, secret, who, via):
            lst = out.setdefault((ns, secret), [])
            entry = {"type": "workload", "id": f"{ns}/{who}", "via": via}
            if entry not in lst:
                lst.append(entry)

        try:
            for pod in self._list(self.core.list_pod_for_all_namespaces, self.core.list_namespaced_pod):
                ns, who, spec = pod.metadata.namespace, _owner(pod.metadata), pod.spec
                for v in spec.volumes or []:
                    if v.secret and v.secret.secret_name:
                        add(ns, v.secret.secret_name, who, "k8s-volume")
                    for src in (v.projected.sources or []) if v.projected else []:
                        if src.secret and src.secret.name:
                            add(ns, src.secret.name, who, "k8s-volume")
                for c in list(spec.containers or []) + list(spec.init_containers or []):
                    for e in c.env or []:
                        ref = e.value_from.secret_key_ref if e.value_from else None
                        if ref and ref.name:
                            add(ns, ref.name, who, "k8s-env")
                    for ef in c.env_from or []:
                        if ef.secret_ref and ef.secret_ref.name:
                            add(ns, ef.secret_ref.name, who, "k8s-env")
        except ApiException as exc:
            self.coverage.optional("pods/list")
            log.info("[%s] pods not listed (%s): used_by will be empty", self.name, exc.status)
        try:
            for ing in self._list(self.net.list_ingress_for_all_namespaces, self.net.list_namespaced_ingress):
                for t in ing.spec.tls or []:
                    if t.secret_name:
                        add(ing.metadata.namespace, t.secret_name, f"Ingress/{ing.metadata.name}", "k8s-ingress")
        except ApiException as exc:
            self.coverage.optional("ingresses/list")
            log.info("[%s] ingresses not listed (%s)", self.name, exc.status)
        return out

    # -------------------------------------------------------- cert-manager
    def _custom(self, plural: str, cluster_scoped: bool = False) -> list[dict]:
        from kubernetes.client.exceptions import ApiException  # noqa: PLC0415

        items: list[dict] = []
        try:
            if cluster_scoped or not self.namespaces:
                targets = [lambda **kw: self.custom.list_cluster_custom_object(CM_GROUP, CM_VERSION, plural, **kw)]
            else:
                targets = [lambda ns=ns, **kw: self.custom.list_namespaced_custom_object(CM_GROUP, CM_VERSION, ns,
                                                                                         plural, **kw)
                           for ns in self.namespaces]  # fmt: skip
            for fn in targets:
                cont = None
                while True:
                    page = fn(limit=500, _continue=cont) if cont else fn(limit=500)
                    items += page.get("items") or []
                    cont = (page.get("metadata") or {}).get("continue")
                    if not cont:
                        break
        except ApiException as exc:
            if exc.status == 404:
                log.info("[%s] cert-manager is not installed (no %s.%s)", self.name, plural, CM_GROUP)
            else:
                self.coverage.gap("cert-manager", plural, f"HTTP {exc.status}: {exc.reason}", gap_kind(exc))
                log.warning("[%s] cert-manager %s not listed: HTTP %s", self.name, plural, exc.status)
        return items

    @staticmethod
    def _issuer_type(spec: dict) -> str:
        for k in ("acme", "ca", "vault", "selfSigned", "venafi"):
            if k in (spec or {}):
                if k == "acme":
                    return f"acme ({spec['acme'].get('server', '')})"
                return k
        return "external"

    def _cert_manager(self, by_secret: dict[tuple[str, str], list[CryptoAsset]]) -> list[CryptoAsset]:
        issuers: dict[tuple[str, str, str], str] = {}
        for it in self._custom("issuers"):
            m = it["metadata"]
            issuers[("Issuer", m.get("namespace", ""), m["name"])] = self._issuer_type(it.get("spec"))
        for it in self._custom("clusterissuers", cluster_scoped=True):
            issuers[("ClusterIssuer", "", it["metadata"]["name"])] = self._issuer_type(it.get("spec"))
        out: list[CryptoAsset] = []
        for c in self._custom("certificates"):
            meta, spec, status = c["metadata"], c.get("spec") or {}, c.get("status") or {}
            ns = meta.get("namespace", "")
            ref = spec.get("issuerRef") or {}
            ikind = ref.get("kind", "Issuer")
            itype = issuers.get((ikind, ns if ikind == "Issuer" else "", ref.get("name", "")), "unknown")
            pk = spec.get("privateKey") or {}
            conditions = status.get("conditions") or []
            ready = next((x.get("status") == "True" for x in conditions if x.get("type") == "Ready"), None)
            info = {
                "certificate": f"{ns}/{meta['name']}",
                "issuer": f"{ikind}/{ref.get('name')}",
                "issuer_type": itype,
                "private_key_algorithm": pk.get("algorithm", "RSA"),
                "private_key_size": pk.get("size"),
                "rotation_policy": pk.get("rotationPolicy") or "unset (Never before cert-manager 1.18, then Always)",
                "renew_before": spec.get("renewBefore"),
                "duration": spec.get("duration"),
                "ready": ready,
                "renewal_time": status.get("renewalTime"),
            }
            matched = [a for a in by_secret.get((ns, spec.get("secretName", "")), []) if a.kind == KIND_CERTIFICATE]
            for a in matched:
                a.extra["cert_manager"] = info
                a.rotation_enabled = True
            if not matched:
                out.append(self._from_spec(ns, meta, spec, status, info))
        return out

    def _from_spec(self, ns: str, meta: dict, spec: dict, status: dict, info: dict) -> CryptoAsset:
        alg = {"RSA": "RSA", "ECDSA": "EC", "Ed25519": "Ed25519"}.get(info["private_key_algorithm"], "unknown")
        size = info["private_key_size"] or {"RSA": 2048, "EC": 256, "Ed25519": 256}.get(alg)
        curve = _CM_CURVES.get(size) if alg == "EC" else ("Ed25519" if alg == "Ed25519" else None)
        not_after = _parse_time(status.get("notAfter"))
        names = spec.get("dnsNames") or []
        return self.asset(
            kind=KIND_CERTIFICATE, name=spec.get("commonName") or (names[0] if names else meta["name"]),
            native_id=f"k8s:{self.cluster}/{ns}/certificate/{meta['name']}", algorithm=alg, key_size=size,
            curve=curve, key_type="public-key", purposes=["sign"], issuer=info["issuer"],
            created=_parse_time(status.get("notBefore")), expires=not_after, rotation_enabled=True,
            state=STATE_ACTIVE if not_after and not_after > utcnow() else STATE_DEACTIVATED,
            location=f"k8s:{ns}/certificate/{meta['name']}",
            extra={"namespace": ns, "cluster": self.cluster, "cert_manager": info, "sans": names,
                   "coverage_scope": ["cert-manager:certificates", f"namespaces:{ns}"],
                   "from_cert_manager_spec": True, "secret": spec.get("secretName")},
        )  # fmt: skip
