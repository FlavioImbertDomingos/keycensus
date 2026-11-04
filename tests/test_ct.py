"""Certificate Transparency collector. The Cert Spotter fixture is a real API response."""

from __future__ import annotations

import base64
import datetime as dt
import json
import re

import pytest
import responses
from cryptography.hazmat.primitives import serialization

from keycensus.analysis.policy import Policy, evaluate
from keycensus.collectors import build
from keycensus.collectors.ct import CERTSPOTTER_URL, CRTSH_URL

from .conftest import FIXTURES, make_cert, pem, source

ISSUANCES = json.loads((FIXTURES / "certspotter-issuances.json").read_text())


def _run(**opts):
    return build(source("pub", "ct", **opts)).run()


@responses.activate
def test_certspotter_pages_and_parses():
    responses.get(CERTSPOTTER_URL, json=ISSUANCES[:1])
    responses.get(CERTSPOTTER_URL, json=ISSUANCES[1:])
    responses.get(CERTSPOTTER_URL, json=[])
    r = _run(domains=["pulseai.systems"], include_expired=True)
    assert r.error is None, r.error
    assert len(r.assets) == 2
    rsa, ec = sorted(r.assets, key=lambda a: a.algorithm, reverse=True)
    assert (rsa.algorithm, rsa.key_size) == ("RSA", 4096) and "Let's Encrypt" in rsa.issuer
    assert (ec.algorithm, ec.curve) == ("EC", "P-256") and ec.extra["precertificate"] is True
    assert ec.extra["dns_names"] == ["*.pulseai.systems", "pulseai.systems"]
    calls = responses.calls
    assert "include_subdomains=true" in calls[0].request.url and "expand=cert_der" in calls[0].request.url
    assert f"after={ISSUANCES[0]['id']}" in calls[1].request.url
    assert "Authorization" not in calls[0].request.headers


@responses.activate
def test_unexpected_issuer_is_a_finding(monkeypatch):
    monkeypatch.setenv("CS_KEY", "k-123")
    responses.get(CERTSPOTTER_URL, json=ISSUANCES)
    responses.get(CERTSPOTTER_URL, json=[])
    r = _run(domains=["pulseai.systems"], include_expired=True, expected_issuers=["let's encrypt"],
             api_key_env="CS_KEY")  # fmt: skip
    assert responses.calls[0].request.headers["Authorization"] == "Bearer k-123"
    flagged = [a for a in r.assets if a.extra["unexpected_issuer"]]
    assert [a.issuer for a in flagged] == ["CN=WE1,O=Google Trust Services,C=US"]
    findings = [f for f in evaluate(r.assets, Policy.default()) if f.rule_id == "ct-unexpected-issuer"]
    assert len(findings) == 1 and "Google Trust Services" in findings[0].detail


@responses.activate
def test_expired_are_skipped_by_default(monkeypatch):
    old = dict(ISSUANCES[0], id="1", not_after="2020-01-01T00:00:00Z")
    responses.get(CERTSPOTTER_URL, json=[old])
    responses.get(CERTSPOTTER_URL, json=[])
    assert _run(domains=["pulseai.systems"]).assets == []


@responses.activate
def test_rate_limit_is_retried(monkeypatch):
    monkeypatch.setattr("keycensus.collectors.ct.time.sleep", lambda s: None)
    responses.get(CERTSPOTTER_URL, status=429, headers={"Retry-After": "1"})
    responses.get(CERTSPOTTER_URL, json=ISSUANCES[:1])
    responses.get(CERTSPOTTER_URL, json=[])
    r = _run(domains=["pulseai.systems"], include_expired=True)
    assert r.error is None and len(r.assets) == 1


@responses.activate
def test_bad_key_is_reported():
    responses.get(CERTSPOTTER_URL, status=401)
    r = _run(domains=["example.com"], api_key="wrong")
    assert "HTTP 401" in r.error


@responses.activate
def test_crtsh_folds_precert_and_downloads_once():
    _, cert = make_cert("www.example.com", days_valid=90)
    row = {"issuer_ca_id": 7, "issuer_name": "C=US, O=Example CA", "common_name": "www.example.com",
           "name_value": "www.example.com\nexample.com", "id": 111, "serial_number": "0abc",
           "not_before": "2026-10-01T00:00:00", "not_after": "2027-01-01T00:00:00"}  # fmt: skip
    precert = dict(row, id=110)  # same issuer and serial: the precertificate entry
    other = dict(row, id=222, serial_number="0def", common_name="old.example.com", name_value="old.example.com")

    def search(request):
        q = re.search(r"q=([^&]+)", request.url).group(1)
        return (200, {}, json.dumps([row, precert, other] if q.startswith("%25") else []))

    responses.add_callback(responses.GET, re.compile(re.escape(CRTSH_URL) + r"\?q="), callback=search)
    responses.get(re.compile(re.escape(CRTSH_URL) + r"\?d=111"), body=pem(cert))
    responses.get(re.compile(re.escape(CRTSH_URL) + r"\?d=222"), status=404)
    r = _run(domains=["example.com"], provider="crtsh")
    assert r.error is None, r.error
    by = {a.name: a for a in r.assets}
    assert set(by) == {"www.example.com", "old.example.com"}
    assert by["www.example.com"].algorithm == "RSA" and by["www.example.com"].extra["ct_provider"] == "crtsh"
    assert by["old.example.com"].extra["certificate_not_downloaded"] is True
    assert sum(1 for c in responses.calls if "d=111" in c.request.url) == 1
    assert "exclude=expired" in responses.calls[0].request.url


def test_config_errors():
    assert "needs 'domains'" in _run().error
    assert "unknown provider" in _run(domains=["a.com"], provider="google").error


def test_der_round_trip_matches_fixture():
    der = base64.b64decode(ISSUANCES[0]["cert_der"])
    from cryptography import x509

    cert = x509.load_der_x509_certificate(der)
    assert cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert cert.not_valid_after_utc == dt.datetime(2026, 12, 6, 4, 30, 52, tzinfo=dt.UTC)


pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")
