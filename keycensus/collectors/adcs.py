"""Collector: Microsoft Active Directory Certificate Services (AD CS).

AD CS keeps its inventory in two places, and this collector reads either or both:

1. **Active Directory (LDAP)** -- the Public Key Services container in the forest's
   configuration partition. It holds every enterprise CA's certificate (Enrollment Services),
   the trusted roots (Certification Authorities), the NTAuth store, the AIA store, and the
   certificate templates with their key-size, validity and private-key settings. Any domain
   user can read it; no access to the CA servers is needed.
2. **The CA database** -- every certificate a CA has issued. There is no remote API for it that
   works from Linux (ICertView is DCOM), so the CA exports it with `certutil -view` and this
   collector reads the CSV, the same way the Voltage collector reads an export.

    - name: corp-pki
      type: adcs

      # 1. Active Directory
      ldap_url: ldaps://dc01.corp.example.com      # ldaps://, or ldap:// with start_tls: true
      auth: simple                                 # simple (bind DN or UPN + password) | kerberos (kinit first)
      username: svc-keycensus@corp.example.com
      password_env: ADCS_LDAP_PASSWORD
      verify_tls: /config/corp-root-ca.pem         # true | false | CA bundle path
      # config_dn: CN=Configuration,DC=corp,DC=example,DC=com   # default: read from the rootDSE
      include_templates: true                      # read published templates' crypto settings

      # 2. CA database exports (one per CA)
      exports:
        - /exports/corp-issuing-ca1.csv
        - {file: /exports/ca2.csv, ca: CORP-ISSUING-CA2}
      include_expired: false     # the CA database keeps every certificate ever issued
      include_revoked: false
      ca_hardware_backed: true   # optional: CA private keys are in an HSM (LDAP cannot tell)

Export command, run on each CA (read-only; needs CA *Read* permission, which local
administrators and CA administrators have):

    certutil -view -restrict "Disposition=20" ^
      -out "RequestID,RequesterName,CertificateTemplate,SerialNumber,NotAfter,RawCertificate" ^
      csv > issued.csv

Add `Disposition=21` (or drop `-restrict`) and the `Disposition,RevokedWhen` columns to see
revoked certificates too. Column headers are localised display names, so they are matched
tolerantly (schema names and English display names both work) and `field_map` covers anything
else. Only the certificate column is required: everything cryptographic is read from the
certificate itself, never from the other columns.

What maps to what:

* CA certificates found in LDAP -> `certificate` assets, deduplicated by fingerprint across the
  stores they appear in (`extra.stores`: enrollment, root, ntauth, aia). An enterprise CA's asset
  also carries `extra.ca_name`, `extra.ca_host` and `extra.templates`: one entry per template the
  CA publishes, with key algorithm, minimum key size, validity, whether the private key is
  exportable, whether the enrollee supplies the subject, and the template OID.
* Issued certificates -> `certificate` assets with `extra.template` (OID resolved to the template
  name when LDAP is also configured), `extra.request_id`, `extra.requester`, `extra.ca`,
  `extra.revoked`. Revoked certificates get state `deactivated`. The requester (the account that
  enrolled, and so holds the private key) goes into `used_by` with `via: enrollment`, which is
  what SBOM linking matches `principal:` selectors against.

Never requests, revokes or approves anything, and never reads archived private keys.
"""

from __future__ import annotations

import base64
import binascii
import csv
import io
import logging
import re
from pathlib import Path
from typing import Any

from cryptography import x509

from ..model import STATE_DEACTIVATED, CryptoAsset
from .base import Collector, CollectorError
from .x509util import certificate_fields

log = logging.getLogger(__name__)

PKS = "CN=Public Key Services,CN=Services,{config}"
STORES = {
    "enrollment": ("CN=Enrollment Services," + PKS, "(objectClass=pKIEnrollmentService)"),
    "root": ("CN=Certification Authorities," + PKS, "(objectClass=certificationAuthority)"),
    "aia": ("CN=AIA," + PKS, "(objectClass=certificationAuthority)"),
    "ntauth": ("CN=NTAuthCertificates," + PKS, "(objectClass=*)"),
}
TEMPLATES = ("CN=Certificate Templates," + PKS, "(objectClass=pKICertificateTemplate)")
TEMPLATE_ATTRS = [
    "cn",
    "displayName",
    "msPKI-Cert-Template-OID",
    "msPKI-Minimal-Key-Size",
    "pKIExpirationPeriod",
    "msPKI-Template-Schema-Version",
    "msPKI-RA-Application-Policies",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Private-Key-Flag",
    "pKIExtendedKeyUsage",
]

# msPKI-Certificate-Name-Flag / msPKI-Private-Key-Flag bits (MS-CRTD 2.28, 2.27)
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001
CT_FLAG_EXPORTABLE_KEY = 0x00000010

# v3+ templates name their CNG algorithm in msPKI-RA-Application-Policies, e.g.
# "msPKI-Asymmetric-Algorithm`PZPWSTR`ECDSA_P256`msPKI-Hash-Algorithm`PZPWSTR`SHA256`..."
_RA_FIELD = re.compile(r"msPKI-(Asymmetric-Algorithm|Hash-Algorithm)`PZPWSTR`([^`]+)`", re.I)
_CNG_ALG = re.compile(r"^(RSA|ECDSA|ECDH|DSA)(?:_P(\d+))?$", re.I)

# Canonical export fields -> accepted header spellings (compared lower-case, alphanumerics only).
# Schema names first (what -out takes), then English display names (what the header shows).
EXPORT_COLUMNS = {
    "certificate": ["rawcertificate", "binarycertificate", "certificate"],
    "request_id": ["requestid", "issuedrequestid", "requestrequestid"],
    "requester": ["requestername", "requestrequestername", "issuedrequestername"],
    "template": ["certificatetemplate", "template"],
    "serial": ["serialnumber", "serial"],
    "disposition": ["disposition", "requestdisposition", "requestdispositionmessage"],
    "revoked_when": ["revokedwhen", "revocationdate", "requestrevokedwhen"],
}
DISPOSITION_ISSUED = 20
DISPOSITION_REVOKED = 21


class AdcsCollector(Collector):
    type_name = "adcs"
    requires_extra = "adcs"

    def collect(self) -> list[CryptoAsset]:
        if not self.opt.get("ldap_url") and not self.opt.get("exports"):
            raise CollectorError(f"[{self.name}] adcs needs 'ldap_url', 'exports', or both")
        assets: list[CryptoAsset] = []
        template_names: dict[str, str] = {}
        if self.opt.get("ldap_url"):
            ca_assets, template_names = self._collect_ldap()
            assets.extend(ca_assets)
        for spec in self.opt.get("exports") or []:
            assets.extend(self._collect_export(spec, template_names))
        return assets

    # ------------------------------------------------------------------ LDAP
    def _collect_ldap(self) -> tuple[list[CryptoAsset], dict[str, str]]:
        conn = self._connect()
        try:
            config_dn = self.opt.get("config_dn") or self._config_dn(conn)
            templates: dict[str, dict[str, Any]] = {}
            if self.opt.get("include_templates", True):
                templates = {t["name"]: t for t in self._read_templates(conn, config_dn)}
            by_fp: dict[str, CryptoAsset] = {}
            for store, (base_tpl, flt) in STORES.items():
                attrs = ["cn", "cACertificate"]
                if store == "enrollment":
                    attrs += ["dNSHostName", "certificateTemplates"]
                for entry in self._search(conn, base_tpl.format(config=config_dn), flt, attrs):
                    for der in _values(entry, "cACertificate"):
                        self._add_ca_cert(by_fp, store, entry, der, templates)
        finally:
            try:
                conn.unbind()
            except Exception:  # noqa: BLE001 - nothing useful to do on a failed unbind
                pass
        oid_to_name = {t["oid"]: name for name, t in templates.items() if t.get("oid")}
        return list(by_fp.values()), oid_to_name

    def _connect(self):
        import ssl  # noqa: PLC0415

        import ldap3  # noqa: PLC0415 - optional extra
        from ldap3 import Tls  # noqa: PLC0415

        url = str(self.opt["ldap_url"])
        use_ssl = url.lower().startswith("ldaps://")
        start_tls = bool(self.opt.get("start_tls", False))
        verify = self.opt.get("verify_tls", True)
        tls = None
        if use_ssl or start_tls:
            if verify is False:
                tls = Tls(validate=ssl.CERT_NONE)
            elif isinstance(verify, str):
                tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=verify)
            else:
                tls = Tls(validate=ssl.CERT_REQUIRED)
        server = ldap3.Server(url, use_ssl=use_ssl, tls=tls, get_info=ldap3.NONE,
                              connect_timeout=float(self.opt.get("timeout", 10)))  # fmt: skip
        auth = str(self.opt.get("auth", "simple")).lower()
        if auth == "kerberos":
            conn = ldap3.Connection(server, authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS,
                                    read_only=True, auto_bind=False)  # fmt: skip
        elif auth == "simple":
            if not (use_ssl or start_tls) and not self.opt.get("allow_plaintext_bind", False):
                raise CollectorError(
                    f"[{self.name}] refusing a simple bind over plain LDAP: the password would cross the "
                    "network in clear text. Use ldaps://, start_tls: true, or auth: kerberos."
                )
            conn = ldap3.Connection(server, user=self.cfg.secret("username", required=True),
                                    password=self.cfg.secret("password", required=True),
                                    authentication=ldap3.SIMPLE, read_only=True, auto_bind=False)  # fmt: skip
        else:
            raise CollectorError(f"[{self.name}] auth must be 'simple' or 'kerberos', not {auth!r}")
        conn.open()
        if start_tls and not use_ssl:
            conn.start_tls()
        if not conn.bind():
            raise CollectorError(f"[{self.name}] LDAP bind failed: {conn.result.get('description')}")
        return conn

    def _config_dn(self, conn) -> str:
        entries = self._search(conn, "", "(objectClass=*)", ["configurationNamingContext"], scope="BASE")
        for e in entries:
            vals = _values(e, "configurationNamingContext")
            if vals:
                return _text(vals[0])
        raise CollectorError(f"[{self.name}] rootDSE has no configurationNamingContext; set config_dn")

    def _search(self, conn, base: str, flt: str, attrs: list[str], scope: str = "LEVEL") -> list[dict[str, Any]]:
        """Paged search returning [{"dn": ..., "attributes": {name: [values]}}]."""
        import ldap3  # noqa: PLC0415

        scopes = {"BASE": ldap3.BASE, "LEVEL": ldap3.LEVEL, "SUBTREE": ldap3.SUBTREE}
        if scope == "BASE" and base == "":
            # rootDSE: a plain base search, paging is not allowed on it
            conn.search("", flt, search_scope=ldap3.BASE, attributes=attrs)
            return [{"dn": e["dn"], "attributes": e.get("raw_attributes") or {}} for e in conn.response or []
                    if e.get("type") == "searchResEntry"]  # fmt: skip
        if scope == "BASE" or base.startswith("CN=NTAuthCertificates"):
            ok = conn.search(base, flt, search_scope=ldap3.BASE, attributes=attrs)
            if not ok and conn.result.get("result") == 32:  # noSuchObject: store not present
                return []
            return [{"dn": e["dn"], "attributes": e.get("raw_attributes") or {}} for e in conn.response or []
                    if e.get("type") == "searchResEntry"]  # fmt: skip
        out = []
        try:
            gen = conn.extend.standard.paged_search(base, flt, search_scope=scopes[scope], attributes=attrs,
                                                    paged_size=500, generator=True)  # fmt: skip
            for e in gen:
                if e.get("type") == "searchResEntry":
                    out.append({"dn": e["dn"], "attributes": e.get("raw_attributes") or {}})
        except ldap3.core.exceptions.LDAPNoSuchObjectResult:
            return []
        if conn.result and conn.result.get("result") == 32:
            return []
        return out

    def _read_templates(self, conn, config_dn: str) -> list[dict[str, Any]]:
        base, flt = TEMPLATES
        out = []
        for e in self._search(conn, base.format(config=config_dn), flt, TEMPLATE_ATTRS):
            out.append(parse_template(e.get("attributes") or {}))
        return [t for t in out if t.get("name")]

    def _add_ca_cert(self, by_fp: dict[str, CryptoAsset], store: str, entry: dict, der: bytes,
                     templates: dict[str, dict[str, Any]]) -> None:  # fmt: skip
        try:
            cert = x509.load_der_x509_certificate(bytes(der))
        except ValueError as exc:
            log.warning("[%s] unparseable cACertificate on %s: %s", self.name, entry.get("dn"), exc)
            return
        fields = certificate_fields(cert)
        fp = fields["fingerprint_sha256"]
        asset = by_fp.get(fp)
        if asset is None:
            fields["extra"].update({"stores": [], "dn": entry.get("dn")})
            asset = self.asset(native_id=f"ldap:{fp}", location=str(self.opt.get("ldap_url")), **fields)
            hw = self.opt.get("ca_hardware_backed")
            if hw is not None:
                asset.hardware_backed = bool(hw)
            by_fp[fp] = asset
        if store not in asset.extra["stores"]:
            asset.extra["stores"].append(store)
        if store == "enrollment":
            attrs = entry.get("attributes") or {}
            ca_name = _first_text(attrs, "cn")
            asset.extra["ca_name"] = ca_name
            asset.extra["ca_host"] = _first_text(attrs, "dNSHostName")
            asset.extra["dn"] = entry.get("dn")
            published = [_text(v) for v in _values(entry, "certificateTemplates")]
            asset.extra["templates"] = [templates.get(n, {"name": n}) for n in sorted(published)]
            if ca_name:
                asset.name = ca_name

    # ------------------------------------------------------------------ CA database export
    def _collect_export(self, spec, template_names: dict[str, str]) -> list[CryptoAsset]:
        if isinstance(spec, dict):
            path = Path(str(spec.get("file") or ""))
            ca = spec.get("ca") or path.stem
        else:
            path = Path(str(spec))
            ca = path.stem
        if not path.is_file():
            raise CollectorError(f"[{self.name}] export {path} does not exist")
        rows = list(csv.reader(io.StringIO(_decode(path.read_bytes()))))
        rows = [r for r in rows if any(c.strip() for c in r)]
        if not rows:
            return []
        cols = _map_columns(rows[0], self.opt.get("field_map") or {})
        if "certificate" not in cols:
            raise CollectorError(
                f"[{self.name}] {path}: no certificate column (looked for RawCertificate / "
                f"'Binary Certificate'). Header was: {rows[0]}. Re-export with RawCertificate in -out, "
                "or set field_map: {certificate: <your column>}."
            )
        include_expired = bool(self.opt.get("include_expired", False))
        include_revoked = bool(self.opt.get("include_revoked", False))
        assets: list[CryptoAsset] = []
        bad = 0
        skipped = 0
        for row in rows[1:]:

            def g(key, row=row):
                i = cols.get(key)
                v = row[i].strip() if i is not None and i < len(row) else ""
                return "" if v.upper() == "EMPTY" else v  # certutil writes EMPTY for a null column

            disposition = _leading_int(g("disposition"))
            if disposition is not None and disposition not in (DISPOSITION_ISSUED, DISPOSITION_REVOKED):
                skipped += 1  # pending, denied, failed ... carry no certificate worth inventorying
                continue
            revoked = disposition == DISPOSITION_REVOKED or bool(g("revoked_when"))
            der = _cert_bytes(g("certificate"))
            if der is None:
                bad += 1
                continue
            try:
                cert = x509.load_der_x509_certificate(der)
            except ValueError:
                bad += 1
                continue
            fields = certificate_fields(cert)
            if revoked and not include_revoked:
                skipped += 1
                continue
            if not include_expired and fields["expires"] and fields["state"] == STATE_DEACTIVATED and not revoked:
                skipped += 1
                continue
            template_raw = g("template")
            template_oid = template_raw.split()[0] if re.match(r"^\d+(\.\d+)+", template_raw) else None
            template = template_names.get(template_oid, template_raw) if template_oid else template_raw
            serial = g("serial").replace(" ", "").lower() or fields["extra"]["serial"]
            fields["extra"].update({
                "ca": ca,
                "request_id": g("request_id") or None,
                "requester": g("requester") or None,
                "template": template or None,
                "template_oid": template_oid,
                "revoked": revoked,
                "revoked_when": g("revoked_when") or None,
                "export": str(path),
            })  # fmt: skip
            if revoked:
                fields["state"] = STATE_DEACTIVATED
            asset = self.asset(native_id=f"{ca}:{serial}", location=f"{ca} (CA database)", **fields)
            if fields["extra"]["requester"]:
                # The account that enrolled holds the private key: the closest thing AD CS has to a consumer.
                asset.used_by = [{"type": "principal", "id": fields["extra"]["requester"], "via": "enrollment"}]
            assets.append(asset)
        if bad:
            log.warning("[%s] %s: %d row(s) had no parseable certificate", self.name, path, bad)
            if not assets and not skipped:
                raise CollectorError(f"[{self.name}] {path}: none of {bad} row(s) had a parseable certificate")
        log.info("[%s] %s: %d certificate(s), %d skipped (expired/revoked/not issued)", self.name, path,
                 len(assets), skipped)  # fmt: skip
        return assets


# ---------------------------------------------------------------------- helpers
def parse_template(attrs: dict[str, Any]) -> dict[str, Any]:
    """Crypto-relevant settings of one pKICertificateTemplate (raw LDAP attributes)."""
    a = {k.lower(): v for k, v in attrs.items()}

    def first(name):
        v = a.get(name.lower())
        if isinstance(v, list | tuple):
            v = v[0] if v else None
        return v

    def as_int(name):
        v = first(name)
        try:
            return int(_text(v)) if v is not None else None
        except ValueError:
            return None

    ra = " ".join(_text(v) for v in (a.get("mspki-ra-application-policies") or []))
    cng = {m.group(1).lower(): m.group(2) for m in _RA_FIELD.finditer(ra)}
    algorithm, curve_bits = "RSA", None
    if cng.get("asymmetric-algorithm"):
        m = _CNG_ALG.match(cng["asymmetric-algorithm"])
        if m:
            fam = m.group(1).upper()
            algorithm = "EC" if fam in ("ECDSA", "ECDH") else fam
            curve_bits = int(m.group(2)) if m.group(2) else None
    min_size = as_int("msPKI-Minimal-Key-Size")
    if algorithm == "EC" and curve_bits:
        min_size = curve_bits
    name_flag = as_int("msPKI-Certificate-Name-Flag") or 0
    pk_flag = as_int("msPKI-Private-Key-Flag") or 0
    return {
        "name": _text(first("cn")) if first("cn") is not None else None,
        "display_name": _text(first("displayName")) if first("displayName") is not None else None,
        "oid": _text(first("msPKI-Cert-Template-OID")) if first("msPKI-Cert-Template-OID") is not None else None,
        "schema_version": as_int("msPKI-Template-Schema-Version"),
        "key_algorithm": algorithm,
        "min_key_size": min_size,
        "curve": f"P-{curve_bits}" if algorithm == "EC" and curve_bits else None,
        "hash_algorithm": cng.get("hash-algorithm"),
        "validity_days": _interval_days(first("pKIExpirationPeriod")),
        "exportable_key": bool(pk_flag & CT_FLAG_EXPORTABLE_KEY),
        "key_archival": bool(pk_flag & CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL),
        "enrollee_supplies_subject": bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT),
        "ekus": [_text(v) for v in (a.get("pkiextendedkeyusage") or [])],
    }


def _interval_days(raw) -> int | None:
    """pKIExpirationPeriod: 8 bytes, little-endian, negative count of 100 ns intervals."""
    if raw is None:
        return None
    b = bytes(raw) if not isinstance(raw, str) else raw.encode("latin-1")
    if len(b) != 8:
        return None
    ticks = -int.from_bytes(b, "little", signed=True)
    return round(ticks / 10_000_000 / 86_400) if ticks > 0 else None


def _values(entry: dict[str, Any], name: str) -> list:
    attrs = entry.get("attributes") or {}
    for k, v in attrs.items():
        if k.lower() == name.lower():
            return list(v) if isinstance(v, list | tuple) else [v]
    return []


def _first_text(attrs: dict[str, Any], name: str) -> str | None:
    vals = _values({"attributes": attrs}, name)
    return _text(vals[0]) if vals else None


def _text(v) -> str:
    if isinstance(v, bytes | bytearray):
        return bytes(v).decode("utf-8", "replace")
    return str(v)


def _decode(data: bytes) -> str:
    """certutil output redirected to a file may be UTF-16 (with BOM), UTF-8, or the console code page."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", "replace")


def _norm(header: str) -> str:
    return re.sub(r"[^a-z0-9]", "", header.lower())


def _map_columns(header: list[str], field_map: dict[str, str]) -> dict[str, int]:
    normed = [_norm(h) for h in header]
    cols: dict[str, int] = {}
    for key, aliases in EXPORT_COLUMNS.items():
        wanted = [_norm(str(field_map[key]))] if key in field_map else aliases
        for alias in wanted:
            if alias in normed:
                cols[key] = normed.index(alias)
                break
    return cols


def _cert_bytes(text: str) -> bytes | None:
    """A certificate cell: PEM (what certutil writes), bare base64, or hex."""
    if not text or text.upper() == "EMPTY":
        return None
    body = re.sub(r"-----(BEGIN|END) [A-Z ]+-----", "", text)
    compact = re.sub(r"\s+", "", body)
    if not compact:
        return None
    if re.fullmatch(r"[0-9a-fA-F]+", compact) and compact.startswith("30"):
        try:
            return binascii.unhexlify(compact)
        except binascii.Error:
            return None
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None


def _leading_int(text: str) -> int | None:
    m = re.match(r"\s*(\d+)", text or "")
    return int(m.group(1)) if m else None
