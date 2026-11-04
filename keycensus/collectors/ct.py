"""Collector: every public certificate issued for your domains, from Certificate Transparency logs.

    - name: public-certs
      type: ct
      domains: [example.com, example.org]
      include_subdomains: true              # default
      provider: certspotter                 # or crtsh
      api_key_env: CERTSPOTTER_API_KEY      # optional; _file, _vault, _aws_secret ... work too
      include_expired: false                # default: only certificates still valid
      expected_issuers: ["Let's Encrypt", "DigiCert"]   # optional: anything else is a finding
      max_certificates: 5000
      timeout: 30

Every publicly trusted CA must log each certificate it issues, so CT shows certificates nobody put
in a register: the marketing site a vendor set up, the test host someone forgot, a certificate a CA
issued that you did not ask for. Each one becomes a `certificate` asset with its key algorithm and
size, issuer, SANs and expiry, so the same expiry, weak-key and quantum rules apply.

Providers:

* `certspotter` (SSLMate Cert Spotter API, default): returns the certificate itself, deduplicated
  per issuance (a precertificate and its final certificate are one entry). Without an API key the
  free allowance is small (a few queries an hour); with a key it covers large estates.
* `crtsh` (crt.sh, Sectigo): no key, but often slow or returning errors under load. The JSON search
  lists entries; each certificate is then downloaded once (`max_certificates` caps that), and a
  precertificate and its final certificate are folded together by issuer and serial.

`expected_issuers` matches case-insensitively against the issuer name and Cert Spotter's
friendly name. A certificate from any other CA gets a `ct-unexpected-issuer` finding: either a
team bought one outside the approved process, or someone obtained a certificate for your name.
"""

from __future__ import annotations

import base64
import logging
import time
from datetime import UTC, datetime
from typing import Any

import requests
from cryptography import x509

from .. import secrets
from ..model import CryptoAsset, utcnow
from .base import Collector, CollectorError
from .x509util import certificate_fields

log = logging.getLogger(__name__)

CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
CRTSH_URL = "https://crt.sh/"
PRECERT_POISON = "1.3.6.1.4.1.11129.2.4.3"
PROVIDERS = {"certspotter", "crtsh"}


def _parse_time(s: str | None) -> datetime | None:
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class CtCollector(Collector):
    type_name = "ct"

    def collect(self) -> list[CryptoAsset]:
        domains = self.opt.get("domains") or []
        if isinstance(domains, str):
            domains = [domains]
        if not domains:
            raise CollectorError(f"[{self.name}] ct collector needs 'domains'")
        provider = str(self.opt.get("provider", "certspotter")).lower()
        if provider not in PROVIDERS:
            raise CollectorError(f"[{self.name}] unknown provider {provider!r}; use {sorted(PROVIDERS)}")
        self.timeout = float(self.opt.get("timeout", 30))
        self.max_certs = int(self.opt.get("max_certificates", 5000))
        self.include_expired = bool(self.opt.get("include_expired", False))
        self.subdomains = bool(self.opt.get("include_subdomains", True))
        self.expected = [str(i).lower() for i in self.opt.get("expected_issuers") or []]
        self.http = requests.Session()
        self.http.headers["User-Agent"] = "keycensus (cryptographic inventory)"
        seen: set[str] = set()
        assets: list[CryptoAsset] = []
        fetch = self._certspotter if provider == "certspotter" else self._crtsh
        for domain in domains:
            domain = str(domain).strip().lstrip("*.").lower()
            for asset in fetch(domain):
                if asset.native_id in seen:
                    continue  # a SAN covers two configured domains
                seen.add(asset.native_id)
                assets.append(asset)
                if len(assets) >= self.max_certs:
                    log.warning("[%s] stopped at max_certificates=%d", self.name, self.max_certs)
                    return assets
        return assets

    # ------------------------------------------------------------------ HTTP
    def _get(self, url: str, params: Any = None, headers: dict | None = None) -> requests.Response:
        """GET with retries on 429 (honouring Retry-After, up to 60 s) and 5xx."""
        last = ""
        for attempt in range(4):
            try:
                r = self.http.get(url, params=params, headers=headers, timeout=self.timeout)
            except requests.RequestException as exc:
                last = f"{type(exc).__name__}: {exc}"
                time.sleep(min(2**attempt, 8))
                continue
            if r.status_code == 429 or r.status_code >= 500:
                last = f"HTTP {r.status_code}"
                wait = r.headers.get("Retry-After", "")
                time.sleep(min(float(wait) if wait.replace(".", "", 1).isdigit() else 2**attempt, 60))
                continue
            if r.status_code in (401, 403):
                raise CollectorError(f"[{self.name}] {url}: HTTP {r.status_code} (check the API key)")
            r.raise_for_status()
            return r
        raise CollectorError(f"[{self.name}] {url}: gave up after retries ({last})")

    # ------------------------------------------------------------- providers
    def _certspotter(self, domain: str):
        key = secrets.resolve(self.opt, "api_key", owner=self.name)
        headers = {"Authorization": f"Bearer {key}"} if key else None
        url = str(self.opt.get("url", CERTSPOTTER_URL))
        after: str | None = None
        while True:
            params = [("domain", domain), ("include_subdomains", "true" if self.subdomains else "false"),
                      ("expand", "dns_names"), ("expand", "issuer"), ("expand", "cert_der")]  # fmt: skip
            if after:
                params.append(("after", after))
            page = self._get(url, params, headers).json()
            if not page:
                return
            for item in page:
                asset = self._from_certspotter(domain, item)
                if asset is not None:
                    yield asset
            after = str(page[-1]["id"])

    def _from_certspotter(self, domain: str, item: dict) -> CryptoAsset | None:
        not_after = _parse_time(item.get("not_after"))
        if not self.include_expired and not_after and not_after < utcnow():
            return None
        issuer = item.get("issuer") or {}
        extra = {"ct_provider": "certspotter", "ct_id": str(item.get("id")), "ct_domain": domain,
                 "revoked": bool(item.get("revoked")), "issuer_friendly_name": issuer.get("friendly_name"),
                 "dns_names": item.get("dns_names") or []}  # fmt: skip
        der = item.get("cert_der")
        if not der:
            return None
        cert = x509.load_der_x509_certificate(base64.b64decode(der))
        return self._asset(cert, item.get("tbs_sha256") or item.get("cert_sha256"), extra,
                           [issuer.get("name") or "", issuer.get("friendly_name") or ""])  # fmt: skip

    def _crtsh(self, domain: str):
        url = str(self.opt.get("url", CRTSH_URL))
        q = f"%.{domain}" if self.subdomains else domain
        params = {"q": q, "output": "json"}
        if not self.include_expired:
            params["exclude"] = "expired"
        rows = self._get(url, params).json()
        if self.subdomains:  # %.example.com does not match example.com itself
            params["q"] = domain
            rows += self._get(url, params).json()
        groups: dict[tuple, dict] = {}
        for row in rows:
            groups.setdefault((row.get("issuer_ca_id"), row.get("serial_number")), row)
        for (_ca, serial), row in groups.items():
            extra = {"ct_provider": "crtsh", "ct_id": str(row.get("id")), "ct_domain": domain,
                     "dns_names": sorted(set(str(row.get("name_value", "")).split()))}  # fmt: skip
            try:
                pem = self._get(url, {"d": row["id"]}).content
                cert = x509.load_pem_x509_certificate(pem)
            except (CollectorError, ValueError, requests.RequestException) as exc:
                log.info("[%s] crt.sh %s: certificate not downloaded: %s", self.name, row.get("id"), exc)
                yield self._row_only(row, serial, extra)
                continue
            yield self._asset(cert, f"{row.get('issuer_ca_id')}:{serial}", extra, [row.get("issuer_name") or ""])

    # ---------------------------------------------------------------- assets
    def _unexpected(self, issuer_names: list[str]) -> bool:
        if not self.expected:
            return False
        names = " | ".join(issuer_names).lower()
        return not any(e in names for e in self.expected)

    def _asset(self, cert: x509.Certificate, uid: str | None, extra: dict, issuer_names: list[str]) -> CryptoAsset:
        fields = certificate_fields(cert)
        precert = any(e.oid.dotted_string == PRECERT_POISON for e in cert.extensions)
        fields["extra"].update(extra, precertificate=precert,
                               unexpected_issuer=self._unexpected(issuer_names + [fields["issuer"] or ""]))  # fmt: skip
        if self.expected:
            fields["extra"]["expected_issuers"] = self.opt.get("expected_issuers")
        return self.asset(native_id=f"ct:{uid or fields['fingerprint_sha256']}", location=f"ct:{extra['ct_domain']}",
                          hardware_backed=None, **fields)  # fmt: skip

    def _row_only(self, row: dict, serial: str | None, extra: dict) -> CryptoAsset:
        """crt.sh listed it but the download failed: keep what the search result says."""
        not_after = _parse_time(row.get("not_after"))
        extra.update(serial=serial, unexpected_issuer=self._unexpected([row.get("issuer_name") or ""]),
                     certificate_not_downloaded=True)  # fmt: skip
        name = row.get("common_name") or (extra["dns_names"][0] if extra["dns_names"] else "certificate")
        return self.asset(kind="certificate", name=name, native_id=f"ct:{row.get('issuer_ca_id')}:{serial}",
                          issuer=row.get("issuer_name"), created=_parse_time(row.get("not_before")),
                          expires=not_after, key_type="public-key", location=f"ct:{extra['ct_domain']}",
                          state="active" if not_after and not_after > utcnow() else "deactivated",
                          extra=extra)  # fmt: skip
