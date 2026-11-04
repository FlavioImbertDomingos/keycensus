"""OpenID Connect for `keycensus serve`: people sign in through your identity provider, machines send
tokens it issued. Works with any standard provider (Entra ID, Okta, Google, Keycloak, Auth0, Dex ...).

    serve:
      auth:
        oidc:
          issuer: https://login.microsoftonline.com/<tenant>/v2.0
          client_id: 00000000-0000-0000-0000-000000000000
          client_secret_env: KC_OIDC_SECRET      # any secret reference; leave out for a public client (PKCE only)
          redirect_url: https://keycensus.example.com/oauth2/callback
          scopes: [openid, email, profile]
          # who may in -- at least one rule is required, so "anyone with a Google account" cannot happen
          allowed_domains: [example.com]
          allowed_emails: [auditor@partner.com]
          allowed_groups: [crypto-team]          # matched against the groups_claim
          groups_claim: groups
          allowed_subjects: []                   # sub / client ids, for machine tokens
          session_hours: 8
          session_key_env: KC_SESSION_KEY        # shared by every replica; random per process if unset
          accept_bearer_jwt: true                # machines: Authorization: Bearer <access token from the IdP>
          audience: api://keycensus              # expected `aud` of those tokens (default: client_id)

**Browsers** get the authorization code flow with PKCE (S256), a `state` bound to a short-lived signed
cookie and a `nonce` checked in the ID token. After login keycensus sets its own session cookie
(HMAC-signed, HttpOnly, SameSite=Lax, Secure when the redirect URL is https) and never stores the
provider's tokens. `/logout` clears it.

**Machines** send an access token the provider issued (client credentials, workload identity
federation). It must be a JWT signed by a key in the provider's JWKS, with the expected issuer and
audience, unexpired, and allowed by the same rules.

ID tokens and JWT access tokens are checked against the provider's published keys (RS256/384/512,
PS256/384/512, ES256/384/512, EdDSA; never `none` or HMAC), with 60 seconds of clock leeway. The
discovery document's issuer must equal `issuer` exactly.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets as pysecrets
import threading
import time
from typing import Any
from urllib.parse import urlencode, urlparse

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from . import secrets

log = logging.getLogger(__name__)

SESSION_COOKIE = "kc_session"
STATE_COOKIE = "kc_oidc"
LEEWAY = 60
_ALGS = {
    "RS256": ("rsa", hashes.SHA256), "RS384": ("rsa", hashes.SHA384), "RS512": ("rsa", hashes.SHA512),
    "PS256": ("pss", hashes.SHA256), "PS384": ("pss", hashes.SHA384), "PS512": ("pss", hashes.SHA512),
    "ES256": ("ec", hashes.SHA256), "ES384": ("ec", hashes.SHA384), "ES512": ("ec", hashes.SHA512),
    "EdDSA": ("okp", None),
}  # fmt: skip
_CURVES = {"P-256": (ec.SECP256R1, 32), "P-384": (ec.SECP384R1, 48), "P-521": (ec.SECP521R1, 66)}


class OidcError(Exception):
    pass


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _int(s: str) -> int:
    return int.from_bytes(_b64d(s), "big")


def jwk_to_key(jwk: dict[str, Any]):
    kty = jwk.get("kty")
    if kty == "RSA":
        return rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
    if kty == "EC":
        curve, _ = _CURVES[jwk["crv"]]
        return ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), curve()).public_key()
    if kty == "OKP" and jwk.get("crv") == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(_b64d(jwk["x"]))
    raise OidcError(f"unsupported JWK kty={kty} crv={jwk.get('crv')}")


class Oidc:
    def __init__(self, cfg: dict[str, Any], owner: str = "serve.auth.oidc"):
        self.cfg = dict(cfg)
        self.issuer = str(cfg.get("issuer") or "").rstrip("/")
        self.client_id = str(cfg.get("client_id") or "")
        if not self.issuer or not self.client_id:
            raise OidcError(f"{owner} needs issuer and client_id")
        self.client_secret = secrets.resolve(cfg, "client_secret", owner=owner, allow_inline=False)
        self.redirect_url = str(cfg.get("redirect_url") or "")
        self.callback_path = urlparse(self.redirect_url).path or "/oauth2/callback"
        self.scopes = [str(s) for s in cfg.get("scopes") or ["openid", "email", "profile"]]
        if "openid" not in self.scopes:
            self.scopes.insert(0, "openid")
        self.allowed_emails = {str(e).lower() for e in cfg.get("allowed_emails") or []}
        self.allowed_domains = {str(d).lower().lstrip("@") for d in cfg.get("allowed_domains") or []}
        self.allowed_groups = {str(g) for g in cfg.get("allowed_groups") or []}
        self.allowed_subjects = {str(s) for s in cfg.get("allowed_subjects") or []}
        if not (self.allowed_emails or self.allowed_domains or self.allowed_groups or self.allowed_subjects):
            raise OidcError(
                f"{owner} needs at least one of allowed_emails, allowed_domains, allowed_groups or "
                "allowed_subjects; otherwise every account at the provider could read the inventory"
            )
        self.groups_claim = str(cfg.get("groups_claim", "groups"))
        self.session_seconds = int(float(cfg.get("session_hours", 8)) * 3600)
        self.accept_bearer = bool(cfg.get("accept_bearer_jwt", False))
        self.audience = str(cfg.get("audience") or self.client_id)
        key = secrets.resolve(cfg, "session_key", owner=owner, allow_inline=False)
        if key:
            self.session_key = hashlib.sha256(key.encode()).digest()
        else:
            self.session_key = os.urandom(32)
            log.warning("%s: no session_key set; sessions end on restart and do not work across replicas", owner)
        self.secure = self.redirect_url.startswith("https://")
        self.timeout = float(cfg.get("timeout", 10))
        self._meta: dict[str, Any] | None = None
        self._jwks: dict[str, Any] = {}
        self._jwks_at = 0.0
        self._lock = threading.Lock()

    # ------------------------------------------------------------ provider metadata and keys
    def metadata(self) -> dict[str, Any]:
        if self._meta is None:
            url = str(self.cfg.get("discovery_url") or f"{self.issuer}/.well-known/openid-configuration")
            r = requests.get(url, timeout=self.timeout)
            if r.status_code != 200:
                raise OidcError(f"OIDC discovery {url} -> {r.status_code}")
            meta = r.json()
            if str(meta.get("issuer", "")).rstrip("/") != self.issuer:
                raise OidcError(f"discovery issuer {meta.get('issuer')!r} is not the configured {self.issuer!r}")
            for k in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                if not meta.get(k):
                    raise OidcError(f"discovery document has no {k}")
            self._meta = meta
        return self._meta

    def _key(self, kid: str | None):
        with self._lock:
            for attempt in range(2):
                if not self._jwks or (attempt == 1 and time.monotonic() - self._jwks_at > 60):
                    r = requests.get(self.metadata()["jwks_uri"], timeout=self.timeout)
                    if r.status_code != 200:
                        raise OidcError(f"JWKS -> {r.status_code}")
                    self._jwks = {k.get("kid", ""): k for k in r.json().get("keys", []) if k.get("use", "sig") == "sig"}
                    self._jwks_at = time.monotonic()
                if kid in self._jwks:
                    return jwk_to_key(self._jwks[kid])
                if not kid and len(self._jwks) == 1:
                    return jwk_to_key(next(iter(self._jwks.values())))
        raise OidcError(f"no key {kid!r} in the provider's JWKS")

    # ------------------------------------------------------------ JWT
    def verify_jwt(self, token: str, audience: str, nonce: str | None = None) -> dict[str, Any]:
        try:
            h64, p64, s64 = token.split(".")
            header, claims, sig = json.loads(_b64d(h64)), json.loads(_b64d(p64)), _b64d(s64)
        except (ValueError, json.JSONDecodeError) as exc:
            raise OidcError("not a JWT") from exc
        alg = header.get("alg")
        if alg not in _ALGS:
            raise OidcError(f"JWT alg {alg!r} is not accepted")
        kind, hash_cls = _ALGS[alg]
        key = self._key(header.get("kid"))
        signed = f"{h64}.{p64}".encode()
        try:
            if kind == "rsa" and isinstance(key, rsa.RSAPublicKey):
                key.verify(sig, signed, padding.PKCS1v15(), hash_cls())
            elif kind == "pss" and isinstance(key, rsa.RSAPublicKey):
                key.verify(sig, signed, padding.PSS(padding.MGF1(hash_cls()), hash_cls.digest_size), hash_cls())
            elif kind == "ec" and isinstance(key, ec.EllipticCurvePublicKey):
                n = len(sig) // 2
                key.verify(encode_dss_signature(int.from_bytes(sig[:n], "big"), int.from_bytes(sig[n:], "big")),
                           signed, ec.ECDSA(hash_cls()))  # fmt: skip
            elif kind == "okp" and isinstance(key, ed25519.Ed25519PublicKey):
                key.verify(sig, signed)
            else:
                raise OidcError(f"key type does not match alg {alg}")
        except InvalidSignature as exc:
            raise OidcError("JWT signature is invalid") from exc
        now = time.time()
        if str(claims.get("iss", "")).rstrip("/") != self.issuer:
            raise OidcError("JWT issuer does not match")
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if audience not in auds:
            raise OidcError("JWT audience does not match")
        if not isinstance(claims.get("exp"), int | float) or claims["exp"] < now - LEEWAY:
            raise OidcError("JWT expired")
        if isinstance(claims.get("nbf"), int | float) and claims["nbf"] > now + LEEWAY:
            raise OidcError("JWT not valid yet")
        if nonce is not None and claims.get("nonce") != nonce:
            raise OidcError("ID token nonce does not match this login")
        return claims

    # ------------------------------------------------------------ authorization
    def allowed(self, claims: dict[str, Any]) -> tuple[bool, str]:
        # Only the `email` claim, never preferred_username: some providers let users change the latter.
        email = str(claims.get("email") or "").lower()
        if email and claims.get("email_verified") is not False:
            if email in self.allowed_emails:
                return True, f"email {email}"
            if "@" in email and email.rsplit("@", 1)[1] in self.allowed_domains:
                return True, f"domain {email.rsplit('@', 1)[1]}"
        groups = claims.get(self.groups_claim) or []
        groups = [groups] if isinstance(groups, str) else groups
        hit = self.allowed_groups.intersection(str(g) for g in groups)
        if hit:
            return True, f"group {sorted(hit)[0]}"
        for s in (claims.get("sub"), claims.get("azp"), claims.get("client_id"), claims.get("appid")):
            if s and str(s) in self.allowed_subjects:
                return True, f"subject {s}"
        return False, "not in allowed_emails / allowed_domains / allowed_groups / allowed_subjects"

    @staticmethod
    def identity(claims: dict[str, Any]) -> str:
        return str(claims.get("email") or claims.get("preferred_username") or claims.get("azp")
                   or claims.get("client_id") or claims.get("sub") or "unknown")  # fmt: skip

    def bearer(self, token: str) -> tuple[str | None, str]:
        """(identity or None, reason) for a machine's `Authorization: Bearer <jwt>`."""
        if not self.accept_bearer or token.count(".") != 2:
            return None, "not a JWT"
        try:
            claims = self.verify_jwt(token, self.audience)
        except OidcError as exc:
            return None, str(exc)
        ok, why = self.allowed(claims)
        return (f"jwt:{self.identity(claims)}", why) if ok else (None, why)

    # ------------------------------------------------------------ signed cookies
    def _seal(self, payload: dict[str, Any]) -> str:
        body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
        mac = _b64e(hmac.new(self.session_key, body.encode(), hashlib.sha256).digest())
        return f"{body}.{mac}"

    def _open(self, value: str | None) -> dict[str, Any] | None:
        if not value or "." not in value:
            return None
        body, mac = value.rsplit(".", 1)
        want = _b64e(hmac.new(self.session_key, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(mac, want):
            return None
        try:
            payload = json.loads(_b64d(body))
        except (ValueError, json.JSONDecodeError):
            return None
        return payload if payload.get("exp", 0) > time.time() else None

    def _cookie(self, name: str, value: str, max_age: int) -> str:
        attrs = f"{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"
        return attrs + ("; Secure" if self.secure else "")

    def session(self, cookies: dict[str, str]) -> str | None:
        s = self._open(cookies.get(SESSION_COOKIE))
        return f"oidc:{s['id']}" if s and s.get("id") else None

    # ------------------------------------------------------------ browser flow
    def login(self, next_path: str) -> tuple[str, str]:
        """(location, Set-Cookie) that starts a login."""
        if not self.redirect_url:
            raise OidcError("browser login needs serve.auth.oidc.redirect_url")
        state, nonce, verifier = pysecrets.token_urlsafe(24), pysecrets.token_urlsafe(24), pysecrets.token_urlsafe(48)
        challenge = _b64e(hashlib.sha256(verifier.encode()).digest())
        cookie = self._seal({"s": state, "n": nonce, "v": verifier, "next": safe_next(next_path),
                             "exp": int(time.time()) + 600})  # fmt: skip
        query = urlencode({
            "response_type": "code", "client_id": self.client_id, "redirect_uri": self.redirect_url,
            "scope": " ".join(self.scopes), "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256",
        })  # fmt: skip
        endpoint = self.metadata()["authorization_endpoint"]
        sep = "&" if "?" in endpoint else "?"
        return f"{endpoint}{sep}{query}", self._cookie(STATE_COOKIE, cookie, 600)

    def callback(self, params: dict[str, str], cookies: dict[str, str]) -> tuple[str, str, list[str]]:
        """Finish a login. Returns (identity, redirect path, Set-Cookie headers); raises OidcError."""
        if params.get("error"):
            raise OidcError(f"provider returned {params['error']}: {params.get('error_description', '')}".strip())
        pending = self._open(cookies.get(STATE_COOKIE))
        if not pending or not hmac.compare_digest(str(params.get("state", "")), pending["s"]):
            raise OidcError("login state missing or does not match (expired, or started in another browser)")
        data = {"grant_type": "authorization_code", "code": params.get("code", ""),
                "redirect_uri": self.redirect_url, "code_verifier": pending["v"]}  # fmt: skip
        auth = None
        if self.client_secret:
            auth = (self.client_id, self.client_secret)
        else:
            data["client_id"] = self.client_id
        r = requests.post(self.metadata()["token_endpoint"], data=data, auth=auth, timeout=self.timeout,
                          headers={"Accept": "application/json"})  # fmt: skip
        if r.status_code != 200:
            raise OidcError(f"token endpoint -> {r.status_code}")
        tokens = r.json()
        id_token = tokens.get("id_token")
        if not id_token:
            raise OidcError("token response has no id_token")
        claims = self.verify_jwt(id_token, self.client_id, nonce=pending["n"])
        claims = self._with_userinfo(claims, tokens.get("access_token"))
        ok, why = self.allowed(claims)
        if not ok:
            raise OidcError(f"{self.identity(claims)} is not allowed: {why}")
        who = self.identity(claims)
        session = self._seal({"id": who, "sub": claims.get("sub"), "exp": int(time.time()) + self.session_seconds})
        return (
            f"oidc:{who}",
            pending["next"],
            [
                self._cookie(SESSION_COOKIE, session, self.session_seconds),
                self._cookie(STATE_COOKIE, "", 0),
            ],
        )

    def _with_userinfo(self, claims: dict[str, Any], access_token: str | None) -> dict[str, Any]:
        """Many providers put email and groups only in userinfo, not in the ID token. Merge them in,
        but only when userinfo is about the same subject the signed ID token named."""
        endpoint = self.metadata().get("userinfo_endpoint")
        if not endpoint or not access_token or self.cfg.get("use_userinfo") is False:
            return claims
        try:
            r = requests.get(endpoint, headers={"Authorization": f"Bearer {access_token}"}, timeout=self.timeout)
        except requests.RequestException as exc:
            log.info("OIDC userinfo failed (%s); using the ID token's claims only", exc)
            return claims
        if r.status_code != 200 or "json" not in r.headers.get("Content-Type", ""):
            return claims
        info = r.json()
        if info.get("sub") != claims.get("sub"):
            raise OidcError("userinfo is about a different subject than the ID token")
        return {**info, **claims}  # the signed ID token wins on any claim both carry

    def logout_cookie(self) -> str:
        return self._cookie(SESSION_COOKIE, "", 0)


def safe_next(path: str | None) -> str:
    """Only local paths, so the login cannot be used as an open redirect."""
    p = str(path or "/")
    if not p.startswith("/") or p.startswith("//") or p.startswith("/\\") or "\r" in p or "\n" in p:
        return "/"
    return p


def parse_cookies(header: str | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (header or "").split(";"):
        k, sep, v = part.strip().partition("=")
        if sep:
            out[k] = v
    return out
