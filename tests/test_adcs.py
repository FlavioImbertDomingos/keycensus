"""AD CS collector: LDAP side against ldap3's in-memory mock, export side against certutil-shaped CSVs."""

from __future__ import annotations

import csv
import io

import ldap3
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding

from keycensus.analysis.policy import Policy, evaluate
from keycensus.collectors import build
from keycensus.collectors.adcs import AdcsCollector, CollectorError, _cert_bytes, _interval_days, parse_template
from keycensus.model import KIND_CERTIFICATE, STATE_ACTIVE, STATE_DEACTIVATED

from .conftest import make_cert, pem, source

CONFIG = "CN=Configuration,DC=corp,DC=example,DC=com"
PKS = f"CN=Public Key Services,CN=Services,{CONFIG}"
WEB_OID = "1.3.6.1.4.1.311.21.8.1111.2222.3333.4444.5555.6666.101.7"


def period(days: int) -> bytes:
    """pKIExpirationPeriod encoding: negative 100 ns ticks, little-endian, 8 bytes."""
    return (-days * 86_400 * 10_000_000).to_bytes(8, "little", signed=True)


@pytest.fixture
def pki():
    root_key, root = make_cert("Corp Root CA", days_ago=1000, days_valid=7300, ca=True)
    _, issuing = make_cert("CORP-ISSUING-CA1", days_ago=500, days_valid=3650, issuer="Corp Root CA",
                           issuer_key=root_key, ca=True)  # fmt: skip
    return root, issuing


@pytest.fixture
def ldap_conn(pki):
    root, issuing = pki
    server = ldap3.Server("dc01.corp.example.com")
    conn = ldap3.Connection(server, user="CN=svc,DC=corp", password="pw", client_strategy=ldap3.MOCK_SYNC)
    conn.strategy.add_entry("CN=svc,DC=corp", {"userPassword": "pw", "objectClass": "person"})
    der = lambda c: c.public_bytes(Encoding.DER)  # noqa: E731
    add = conn.strategy.add_entry
    add(f"CN=CORP-ISSUING-CA1,CN=Enrollment Services,{PKS}", {
        "objectClass": ["top", "pKIEnrollmentService"], "cn": "CORP-ISSUING-CA1",
        "dNSHostName": "ca1.corp.example.com", "cACertificate": [der(issuing)],
        "certificateTemplates": ["WebServerV2", "LegacyUser", "ECDSAWeb"],
    })  # fmt: skip
    add(f"CN=Corp Root CA,CN=Certification Authorities,{PKS}", {
        "objectClass": ["top", "certificationAuthority"], "cn": "Corp Root CA", "cACertificate": [der(root)],
    })  # fmt: skip
    add(f"CN=Corp Root CA,CN=AIA,{PKS}", {
        "objectClass": ["top", "certificationAuthority"], "cn": "Corp Root CA", "cACertificate": [der(root)],
    })  # fmt: skip
    add(f"CN=NTAuthCertificates,{PKS}", {
        "objectClass": ["top", "certificationAuthority"], "cn": "NTAuthCertificates",
        "cACertificate": [der(issuing)],
    })  # fmt: skip
    templates = {
        "WebServerV2": {"msPKI-Minimal-Key-Size": "2048", "pKIExpirationPeriod": period(365),
                        "msPKI-Cert-Template-OID": WEB_OID, "msPKI-Template-Schema-Version": "2",
                        "msPKI-Certificate-Name-Flag": "1", "msPKI-Private-Key-Flag": "16"},
        "LegacyUser": {"msPKI-Minimal-Key-Size": "1024", "pKIExpirationPeriod": period(730),
                       "msPKI-Template-Schema-Version": "1"},
        "ECDSAWeb": {"msPKI-Minimal-Key-Size": "256", "pKIExpirationPeriod": period(365),
                     "msPKI-Template-Schema-Version": "4",
                     "msPKI-RA-Application-Policies":
                         "msPKI-Asymmetric-Algorithm`PZPWSTR`ECDSA_P384`msPKI-Hash-Algorithm`PZPWSTR`SHA384`"},
        "NotPublished": {"msPKI-Minimal-Key-Size": "512"},
    }  # fmt: skip
    for name, attrs in templates.items():
        add(f"CN={name},CN=Certificate Templates,{PKS}",
            {"objectClass": ["top", "pKICertificateTemplate"], "cn": name, **attrs})  # fmt: skip
    conn.bind()
    return conn


def collector(monkeypatch, conn, **opts) -> AdcsCollector:
    opts.setdefault("ldap_url", "ldaps://dc01.corp.example.com")
    opts.setdefault("config_dn", CONFIG)
    c = build(source("corp-pki", "adcs", **opts))
    monkeypatch.setattr(c, "_connect", lambda: conn)
    return c


# ------------------------------------------------------------------ LDAP
def test_ldap_inventories_ca_certificates_once_per_key(monkeypatch, ldap_conn):
    assets = collector(monkeypatch, ldap_conn).collect()
    assert {a.name for a in assets} == {"CORP-ISSUING-CA1", "Corp Root CA"}
    by = {a.name: a for a in assets}
    assert sorted(by["Corp Root CA"].extra["stores"]) == ["aia", "root"]
    assert sorted(by["CORP-ISSUING-CA1"].extra["stores"]) == ["enrollment", "ntauth"]
    ca = by["CORP-ISSUING-CA1"]
    assert ca.kind == KIND_CERTIFICATE and ca.state == STATE_ACTIVE
    assert ca.extra["ca_host"] == "ca1.corp.example.com"
    assert ca.extra["is_ca"] is True
    assert ca.native_id == f"ldap:{ca.fingerprint_sha256}"
    assert ca.hardware_backed is None  # LDAP cannot tell; only the option sets it


def test_ldap_reads_published_templates(monkeypatch, ldap_conn):
    ca = next(a for a in collector(monkeypatch, ldap_conn).collect() if a.name == "CORP-ISSUING-CA1")
    t = {x["name"]: x for x in ca.extra["templates"]}
    assert set(t) == {"WebServerV2", "LegacyUser", "ECDSAWeb"}  # NotPublished is not on this CA
    assert t["WebServerV2"]["min_key_size"] == 2048
    assert t["WebServerV2"]["validity_days"] == 365
    assert t["WebServerV2"]["enrollee_supplies_subject"] is True
    assert t["WebServerV2"]["exportable_key"] is True
    assert t["WebServerV2"]["oid"] == WEB_OID
    assert t["ECDSAWeb"]["key_algorithm"] == "EC" and t["ECDSAWeb"]["min_key_size"] == 384
    assert t["ECDSAWeb"]["curve"] == "P-384" and t["ECDSAWeb"]["hash_algorithm"] == "SHA384"
    assert t["LegacyUser"]["key_algorithm"] == "RSA" and t["LegacyUser"]["min_key_size"] == 1024


def test_templates_can_be_skipped(monkeypatch, ldap_conn):
    ca = next(a for a in collector(monkeypatch, ldap_conn, include_templates=False).collect()
              if a.name == "CORP-ISSUING-CA1")  # fmt: skip
    assert [t["name"] for t in ca.extra["templates"]] == ["ECDSAWeb", "LegacyUser", "WebServerV2"]
    assert "min_key_size" not in ca.extra["templates"][0]


def test_ca_hardware_backed_option(monkeypatch, ldap_conn):
    assets = collector(monkeypatch, ldap_conn, ca_hardware_backed=True).collect()
    assert all(a.hardware_backed is True for a in assets)


def test_missing_store_is_not_an_error(monkeypatch, pki):
    server = ldap3.Server("dc")
    conn = ldap3.Connection(server, client_strategy=ldap3.MOCK_SYNC)
    conn.bind()
    assert collector(monkeypatch, conn).collect() == []


def test_policy_flags_weak_template_but_not_ca_lifetime(monkeypatch, ldap_conn):
    assets = collector(monkeypatch, ldap_conn).collect()
    findings = evaluate(assets, Policy.default())
    rules = [(f.rule_id, f.asset_name) for f in findings]
    assert ("adcs-template-weak-key-size", "CORP-ISSUING-CA1") in rules
    weak = [f for f in findings if f.rule_id == "adcs-template-weak-key-size"]
    assert len(weak) == 1 and "LegacyUser" in weak[0].title
    # A 10-year issuing CA is normal; the 398-day limit is for end-entity certificates.
    assert not any(r == "cert-long-validity" for r, _ in rules)


def test_simple_bind_over_plain_ldap_is_refused():
    c = build(source("x", "adcs", ldap_url="ldap://dc01", username="u", password="p"))
    with pytest.raises(CollectorError, match="clear text"):
        c._connect()


def test_needs_ldap_or_exports():
    result = build(source("x", "adcs")).run()
    assert result.error and "ldap_url" in result.error


def test_parse_template_helpers():
    assert _interval_days(period(730)) == 730
    assert _interval_days(b"\x00" * 8) is None
    assert _interval_days(None) is None
    t = parse_template({"cn": [b"X"], "msPKI-Minimal-Key-Size": [b"4096"]})
    assert t["name"] == "X" and t["min_key_size"] == 4096 and t["key_algorithm"] == "RSA"


# ------------------------------------------------------------------ certutil export
def certutil_csv(rows, header=None) -> str:
    """Shape of `certutil -view ... csv`: English display-name header, PEM with CRLF in quoted cells."""
    header = header or ["Issued Request ID", "Requester Name", "Certificate Template", "Serial Number",
                        "Request Disposition", "Revocation Date", "Binary Certificate"]  # fmt: skip
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    w.writerow(header)
    for r in rows:
        w.writerow(r)
    return buf.getvalue()


def cell(cert) -> str:
    return pem(cert).decode().replace("\n", "\r\n")


@pytest.fixture
def export(tmp_path):
    _, web = make_cert("web01.corp.example.com", days_ago=30, days_valid=365)
    _, weak = make_cert("legacy-user", key=rsa.generate_private_key(65537, 1024), days_ago=30, days_valid=730)
    _, old = make_cert("old.corp.example.com", days_ago=800, days_valid=365)
    _, revoked = make_cert("stolen-laptop", key=ec.generate_private_key(ec.SECP256R1()), days_ago=10)
    text = certutil_csv([
        ["101", "CORP\\web01$", f"{WEB_OID} WebServerV2", "61 00 00 00 65 aa", "20 -- Issued", "EMPTY", cell(web)],
        ["102", "CORP\\jdoe", "LegacyUser", "6100000066", "20 -- Issued", "EMPTY", cell(weak)],
        ["103", "CORP\\old$", "WebServer", "6100000067", "20 -- Issued", "EMPTY", cell(old)],
        ["104", "CORP\\lap$", "Machine", "6100000068", "21 -- Revoked", "9/1/2026 10:00 AM", cell(revoked)],
        ["105", "CORP\\x", "User", "", "31 -- Denied", "EMPTY", "EMPTY"],
    ])  # fmt: skip
    path = tmp_path / "CORP-ISSUING-CA1.csv"
    path.write_bytes(b"\xff\xfe" + text.encode("utf-16-le"))  # certutil > file on Windows: UTF-16 LE
    return path


def test_export_reads_issued_certificates(export):
    assets = build(source("corp-pki", "adcs", exports=[str(export)])).collect()
    names = {a.name: a for a in assets}
    assert set(names) == {"web01.corp.example.com", "legacy-user"}  # expired, revoked, denied skipped
    web = names["web01.corp.example.com"]
    assert web.native_id == "CORP-ISSUING-CA1:61000000" + "65aa"
    assert web.extra["template"] == f"{WEB_OID} WebServerV2"  # no LDAP: kept as exported
    assert web.extra["template_oid"] == WEB_OID
    assert web.extra["request_id"] == "101" and web.extra["requester"] == "CORP\\web01$"
    assert web.extra["ca"] == "CORP-ISSUING-CA1" and web.extra["revoked"] is False
    assert web.used_by == [{"type": "principal", "id": "CORP\\web01$", "via": "enrollment"}]
    assert names["legacy-user"].key_size == 1024


def test_export_include_expired_and_revoked(export):
    assets = build(source("p", "adcs", exports=[{"file": str(export), "ca": "CA1"}],
                          include_expired=True, include_revoked=True)).collect()  # fmt: skip
    by = {a.name: a for a in assets}
    assert set(by) == {"web01.corp.example.com", "legacy-user", "old.corp.example.com", "stolen-laptop"}
    assert by["stolen-laptop"].state == STATE_DEACTIVATED and by["stolen-laptop"].extra["revoked"] is True
    assert by["stolen-laptop"].extra["revoked_when"] == "9/1/2026 10:00 AM"
    assert all(a.native_id.startswith("CA1:") for a in assets)


def test_export_findings(export):
    assets = build(source("p", "adcs", exports=[str(export)])).collect()
    rules = {(f.rule_id, f.asset_name) for f in evaluate(assets, Policy.default())}
    assert ("weak-key-size", "legacy-user") in rules


def test_export_template_oid_resolved_through_ldap(monkeypatch, ldap_conn, export):
    assets = collector(monkeypatch, ldap_conn, exports=[str(export)]).collect()
    web = next(a for a in assets if a.name == "web01.corp.example.com")
    assert web.extra["template"] == "WebServerV2"


def test_export_schema_name_header_and_field_map(tmp_path):
    _, c = make_cert("a.example.com")
    p = tmp_path / "ca.csv"
    p.write_text(certutil_csv([["7", base64_der(c)]], header=["RequestID", "RawCertificate"]))
    a = build(source("p", "adcs", exports=[str(p)])).collect()
    assert len(a) == 1 and a[0].extra["request_id"] == "7"
    p.write_text(certutil_csv([["7", cell(c)]], header=["Nº", "Certificado binario"]))
    a = build(source("p", "adcs", exports=[str(p)], field_map={"certificate": "Certificado binario"})).collect()
    assert len(a) == 1


def test_export_without_certificate_column_fails_loudly(tmp_path):
    p = tmp_path / "ca.csv"
    p.write_text(certutil_csv([["7", "x"]], header=["RequestID", "SerialNumber"]))
    result = build(source("p", "adcs", exports=[str(p)])).run()
    assert result.error and "RawCertificate" in result.error


def test_export_with_no_parseable_certificates_fails_loudly(tmp_path):
    p = tmp_path / "ca.csv"
    p.write_text(certutil_csv([["7", "not base64 !!"]], header=["RequestID", "RawCertificate"]))
    result = build(source("p", "adcs", exports=[str(p)])).run()
    assert result.error and "parseable" in result.error


def test_missing_export_file_is_an_error(tmp_path):
    result = build(source("p", "adcs", exports=[str(tmp_path / "nope.csv")])).run()
    assert result.error and "does not exist" in result.error


def test_cert_cell_formats():
    _, c = make_cert("x")
    der = c.public_bytes(Encoding.DER)
    assert _cert_bytes(pem(c).decode()) == der
    assert _cert_bytes(base64_der(c)) == der
    assert _cert_bytes(der.hex()) == der
    assert _cert_bytes("EMPTY") is None and _cert_bytes("") is None


def base64_der(c) -> str:
    import base64

    return base64.b64encode(c.public_bytes(Encoding.DER)).decode()
