"""OIDC for serve: browser login (code + PKCE), session cookies, bearer JWTs, and the checks around them."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from keycensus.audit import AuditLog
from keycensus.config import ConfigError
from keycensus.oidc import Oidc, OidcError, safe_next
from keycensus.serve import ServeSettings, State, make_handler

SECRET = "client-secret-0123456789abcdef"


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _int(n: int) -> str:
    return b64(n.to_bytes((n.bit_length() + 7) // 8, "big"))


class FakeIdp:
    """Just enough of an OpenID provider: discovery, JWKS, authorize, token (with PKCE), userinfo."""

    def __init__(self):
        self.rsa = rsa.generate_private_key(65537, 2048)
        self.ec = ec.generate_private_key(ec.SECP256R1())
        self.kids = {"r1": self.rsa, "e1": self.ec}
        self.users = {"alice": {"email": "alice@example.com", "groups": ["crypto-team"]},
                      "bob": {"email": "bob@other.org", "groups": []}}  # fmt: skip
        self.login_as, self.codes, self.tamper = "alice", {}, {}
        self.id_token_claims_only_sub = False
        idp = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, obj, code=200):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802
                u = urlparse(self.path)
                if u.path == "/.well-known/openid-configuration":
                    return self._json({"issuer": idp.issuer, "authorization_endpoint": f"{idp.issuer}/authorize",
                                       "token_endpoint": f"{idp.issuer}/token", "jwks_uri": f"{idp.issuer}/jwks",
                                       "userinfo_endpoint": f"{idp.issuer}/userinfo"})  # fmt: skip
                if u.path == "/jwks":
                    return self._json({"keys": idp.jwks()})
                if u.path == "/authorize":
                    q = {k: v[0] for k, v in parse_qs(u.query).items()}
                    assert q["code_challenge_method"] == "S256" and q["response_type"] == "code"
                    code = os.urandom(8).hex()
                    idp.codes[code] = {**q, "user": idp.login_as}
                    self.send_response(302)
                    query = urlencode({"code": code, "state": q["state"]})
                    self.send_header("Location", f"{q['redirect_uri']}?{query}")
                    self.end_headers()
                    return None
                if u.path == "/userinfo":
                    user = self.headers["Authorization"].split()[1].split(":")[0]
                    return self._json({"sub": idp.tamper.get("userinfo_sub", user), **idp.users[user]})
                return self._json({}, 404)

            def do_POST(self):  # noqa: N802
                raw = self.rfile.read(int(self.headers["Content-Length"])).decode()
                form = {k: v[0] for k, v in parse_qs(raw).items()}
                auth = base64.b64decode(self.headers.get("Authorization", "Basic Og==").split()[1]).decode()
                if auth != f"keycensus:{SECRET}":
                    return self._json({"error": "invalid_client"}, 401)
                if form.get("grant_type") == "client_credentials":
                    at = idp.token({"sub": "ci-pipeline", "aud": "api://keycensus"}, "e1")
                    return self._json({"access_token": at})
                pending = idp.codes.pop(form["code"])
                want = b64(hashlib.sha256(form["code_verifier"].encode()).digest())
                if want != pending["code_challenge"]:
                    return self._json({"error": "invalid_grant", "error_description": "PKCE"}, 400)
                user = pending["user"]
                claims = {"sub": user, "aud": "keycensus", "nonce": idp.tamper.get("nonce", pending["nonce"])}
                if not idp.id_token_claims_only_sub:
                    claims.update(idp.users[user])
                return self._json({"id_token": idp.token(claims, "r1"), "access_token": f"{user}:at"})

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.issuer = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def jwks(self):
        out = []
        for kid, k in self.kids.items():
            pub = k.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                n = pub.public_numbers()
                out.append({"kty": "RSA", "kid": kid, "use": "sig", "n": _int(n.n), "e": _int(n.e)})
            else:
                n = pub.public_numbers()
                out.append({"kty": "EC", "kid": kid, "crv": "P-256", "x": b64(n.x.to_bytes(32, "big")),
                            "y": b64(n.y.to_bytes(32, "big"))})  # fmt: skip
        return out

    def token(self, claims, kid, alg=None, **override):
        now = int(time.time())
        body = {"iss": self.issuer, "iat": now, "exp": now + 300, **claims, **override}
        key = self.kids[kid]
        alg = alg or ("RS256" if isinstance(key, rsa.RSAPrivateKey) else "ES256")
        h = b64(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
        p = b64(json.dumps(body).encode())
        data = f"{h}.{p}".encode()
        if alg == "RS256":
            sig = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        elif alg == "ES256":
            r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
            sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        else:
            sig = b""
        return f"{h}.{p}.{b64(sig)}"

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def idp():
    i = FakeIdp()
    yield i
    i.close()


def _serve(idp, tmp_path, **oidc_extra):
    port_sock = __import__("socket").socket()
    port_sock.bind(("127.0.0.1", 0))
    port = port_sock.getsockname()[1]
    port_sock.close()
    cfg = {"issuer": idp.issuer, "client_id": "keycensus", "client_secret_env": "KC_OIDC",
           "redirect_url": f"http://127.0.0.1:{port}/oauth2/callback", "allowed_domains": ["example.com"],
           "session_key_env": "KC_SESSION", **oidc_extra}  # fmt: skip
    settings = ServeSettings.from_config({"listen": "0.0.0.0", "auth": {"oidc": cfg}})
    state = State()
    state.ready = True
    state.outputs = {"/report.html": ("text/html", "<html>report</html>"), "/cbom.json": ("application/json", "{}")}
    audit = AuditLog(tmp_path / "audit.jsonl")
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state, settings, audit))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{port}", settings


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("KC_OIDC", SECRET)
    monkeypatch.setenv("KC_SESSION", "session-key-for-tests")
    monkeypatch.delenv("KEYCENSUS_SERVE_TOKEN", raising=False)


def _events(tmp_path):
    return [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]


# ===================================================================== browser login
def test_browser_login_session_and_logout(idp, tmp_path):
    srv, base, _ = _serve(idp, tmp_path)
    try:
        s = requests.Session()
        r = s.get(f"{base}/report.html", headers={"Accept": "text/html"})
        assert r.status_code == 200 and r.text == "<html>report</html>" and r.url == f"{base}/report.html"
        assert s.get(f"{base}/cbom.json").status_code == 200
        cookie = next(c for c in s.cookies if c.name == "kc_session")
        assert cookie.has_nonstandard_attr("HttpOnly")
        assert s.get(f"{base}/logout").status_code == 200
        assert s.get(f"{base}/cbom.json").status_code == 401
        assert requests.get(f"{base}/cbom.json").headers["WWW-Authenticate"].startswith("Bearer")
    finally:
        srv.shutdown()
    ev = [e["event"] for e in _events(tmp_path)]
    assert ev[:4] == ["serve.denied", "serve.login", "serve.read", "serve.read"] and "serve.logout" in ev
    assert _events(tmp_path)[1]["identity"] == "oidc:alice@example.com"


def test_claims_from_userinfo_when_the_id_token_has_only_sub(idp, tmp_path):
    idp.id_token_claims_only_sub = True
    srv, base, _ = _serve(idp, tmp_path, allowed_domains=[], allowed_groups=["crypto-team"])
    try:
        assert requests.Session().get(f"{base}/report.html", headers={"Accept": "text/html"}).status_code == 200
        idp.tamper["userinfo_sub"] = "someone-else"
        r = requests.Session().get(f"{base}/report.html", headers={"Accept": "text/html"})
        assert r.status_code == 403 and "different subject" in r.text
    finally:
        srv.shutdown()


def test_user_outside_the_allow_list_is_refused(idp, tmp_path):
    idp.login_as = "bob"
    srv, base, _ = _serve(idp, tmp_path)
    try:
        r = requests.Session().get(f"{base}/report.html", headers={"Accept": "text/html"})
        assert r.status_code == 403 and "bob@other.org is not allowed" in r.text
    finally:
        srv.shutdown()
    assert _events(tmp_path)[-1]["event"] == "serve.login_failed"


def test_nonce_and_state_are_enforced(idp, tmp_path):
    srv, base, _ = _serve(idp, tmp_path)
    try:
        idp.tamper["nonce"] = "replayed"
        r = requests.Session().get(f"{base}/report.html", headers={"Accept": "text/html"})
        assert r.status_code == 403 and "nonce" in r.text
        idp.tamper.clear()
        r = requests.get(f"{base}/oauth2/callback?code=x&state=forged")
        assert r.status_code == 403 and "state" in r.text
        r = requests.get(f"{base}/oauth2/callback?error=access_denied&error_description=user+cancelled")
        assert r.status_code == 403 and "access_denied" in r.text
    finally:
        srv.shutdown()


def test_forged_session_cookie_is_ignored(idp, tmp_path):
    srv, base, _ = _serve(idp, tmp_path)
    try:
        s = requests.Session()
        s.get(f"{base}/report.html", headers={"Accept": "text/html"})
        good = s.cookies.get("kc_session")
        body, mac = good.rsplit(".", 1)
        forged = base64.urlsafe_b64encode(json.dumps({"id": "admin@example.com", "exp": 9999999999}).encode()).decode()
        forged_cookie = {"kc_session": f"{forged.rstrip('=')}.{mac}"}
        assert requests.get(f"{base}/cbom.json", cookies=forged_cookie).status_code == 401
        assert requests.get(f"{base}/cbom.json", cookies={"kc_session": good}).status_code == 200
    finally:
        srv.shutdown()


# ===================================================================== machine tokens
def test_bearer_jwt_for_machines(idp, tmp_path):
    srv, base, _ = _serve(idp, tmp_path, accept_bearer_jwt=True, audience="api://keycensus",
                          allowed_subjects=["ci-pipeline"])  # fmt: skip
    try:
        at = requests.post(f"{idp.issuer}/token", data={"grant_type": "client_credentials"},
                           auth=("keycensus", SECRET)).json()["access_token"]  # fmt: skip
        assert requests.get(f"{base}/cbom.json", headers={"Authorization": f"Bearer {at}"}).status_code == 200
        bad = [
            idp.token({"sub": "ci-pipeline", "aud": "api://other"}, "e1"),                 # wrong audience
            idp.token({"sub": "ci-pipeline", "aud": "api://keycensus"}, "e1", exp=1000),   # expired
            idp.token({"sub": "ci-pipeline", "aud": "api://keycensus"}, "e1", iss="https://evil"),
            idp.token({"sub": "intruder", "aud": "api://keycensus"}, "e1"),                # not allowed
            idp.token({"sub": "ci-pipeline", "aud": "api://keycensus"}, "e1", alg="none"),
        ]  # fmt: skip
        for t in bad:
            assert requests.get(f"{base}/cbom.json", headers={"Authorization": f"Bearer {t}"}).status_code == 401
    finally:
        srv.shutdown()
    reasons = [e.get("reason", "") for e in _events(tmp_path) if e["event"] == "serve.denied"]
    assert any("audience" in r for r in reasons) and any("expired" in r for r in reasons)
    assert any("issuer" in r for r in reasons) and any("not accepted" in r for r in reasons)


def test_key_rotation_refetches_jwks(idp, monkeypatch):
    o = Oidc({"issuer": idp.issuer, "client_id": "keycensus", "allowed_subjects": ["svc"], "accept_bearer_jwt": True})
    assert o.bearer(idp.token({"sub": "svc", "aud": "keycensus"}, "e1"))[0] == "jwt:svc"
    idp.kids["e2"] = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(o, "_jwks_at", time.monotonic() - 120)  # cache is old enough to refresh
    assert o.bearer(idp.token({"sub": "svc", "aud": "keycensus"}, "e2"))[0] == "jwt:svc"


# ===================================================================== configuration
def test_config_rules(idp):
    with pytest.raises(OidcError, match="at least one of"):
        Oidc({"issuer": idp.issuer, "client_id": "x"})
    with pytest.raises(OidcError, match="issuer and client_id"):
        Oidc({"client_id": "x", "allowed_domains": ["a"]})
    o = Oidc({"issuer": idp.issuer + "/", "client_id": "x", "allowed_domains": ["a"],
              "discovery_url": f"{idp.issuer}/.well-known/openid-configuration"})  # fmt: skip
    o.issuer = "https://pretend.example"
    with pytest.raises(OidcError, match="not the configured"):
        o.metadata()
    # OIDC alone satisfies the "no unauthenticated non-loopback serving" rule
    s = ServeSettings.from_config({"listen": "0.0.0.0", "auth": {"oidc": {"issuer": idp.issuer, "client_id": "x",
                                                                          "allowed_domains": ["a"]}}})  # fmt: skip
    assert s.oidc is not None
    with pytest.raises(ConfigError, match="at least one of"):
        ServeSettings.from_config({"auth": {"oidc": {"issuer": idp.issuer, "client_id": "x"}}})


def test_safe_next():
    assert safe_next("/cbom.json") == "/cbom.json"
    for evil in ("//evil.example", "https://evil.example", "/\\evil.example", "/x\r\nSet-Cookie: a=b", None):
        assert safe_next(evil) == "/"
