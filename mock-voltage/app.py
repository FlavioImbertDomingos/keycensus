"""A pretend Voltage SecureData key-inventory export.

Serves the canonical export shape the `voltage` collector consumes, with a
realistic spread of key ages so the demo has rotation findings. Also listens
on HTTPS (port 8443) with a short-lived self-signed cert so the `tls`
collector has something to scan.

Not a Voltage emulator. Just enough for `docker compose up`.
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Flask, Response, jsonify, request

log = logging.getLogger("mock-voltage")
app = Flask(__name__)
USERNAME = os.environ.get("MOCK_USERNAME", "monitor")
PASSWORD = os.environ.get("MOCK_PASSWORD", "changeme")


def days_ago(n: int) -> str:
    return (dt.datetime.now(dt.UTC) - dt.timedelta(days=n)).strftime("%Y-%m-%d")


KEYS = [
    {"key_id": "vk-0001", "name": "pan-fpe-prod", "identity": "payments@demo.bank", "district": "prod",
     "algorithm": "FF1-AES-256", "purpose": "fpe", "created": days_ago(700), "rotated": days_ago(120),
     "state": "active", "exportable": False, "hsm_backed": True},
    {"key_id": "vk-0002", "name": "pan-fpe-legacy", "identity": "payments@demo.bank", "district": "prod",
     "algorithm": "FF1-AES-256", "purpose": "fpe", "created": days_ago(1500), "rotated": days_ago(800),
     "state": "active", "exportable": False, "hsm_backed": True},
    {"key_id": "vk-0003", "name": "pii-tokenize", "identity": "crm@demo.bank", "district": "prod",
     "algorithm": "AES-256", "purpose": "tokenize", "created": days_ago(400), "rotated": None,
     "state": "active", "exportable": False, "hsm_backed": True},
    {"key_id": "vk-0004", "name": "batch-3des", "identity": "mainframe@demo.bank", "district": "legacy",
     "algorithm": "3DES", "purpose": "encrypt", "created": days_ago(3000), "rotated": days_ago(2000),
     "state": "active", "exportable": True, "hsm_backed": False},
    {"key_id": "vk-0005", "name": "report-signing", "identity": "reports@demo.bank", "district": "prod",
     "algorithm": "RSA-2048", "purpose": "sign", "created": days_ago(200), "rotated": None,
     "state": "active", "exportable": False, "hsm_backed": True},
    {"key_id": "vk-0006", "name": "pan-fpe-2019", "identity": "payments@demo.bank", "district": "prod",
     "algorithm": "FF1-AES-256", "purpose": "fpe", "created": days_ago(2500), "rotated": days_ago(2500),
     "state": "retired", "exportable": False, "hsm_backed": True},
    {"key_id": "vk-0007", "name": "test-district-key", "identity": "qa@demo.bank", "district": "test",
     "algorithm": "AES-128", "purpose": "encrypt", "created": days_ago(30), "rotated": None,
     "state": "active", "exportable": True, "hsm_backed": False},
]  # fmt: skip


@app.before_request
def auth():
    if request.path == "/health":
        return None
    a = request.authorization
    if not a or (a.username, a.password) != (USERNAME, PASSWORD):
        return Response("auth required\n", 401, {"WWW-Authenticate": 'Basic realm="voltage"'})
    return None


@app.get("/health")
def health():
    return "ok\n"


@app.get("/inventory.json")
def inventory_json():
    return jsonify(
        {
            "server": "mock-voltage-kms",
            "exported_at": dt.datetime.now(dt.UTC).isoformat(),
            "keys": KEYS,
        }
    )


@app.get("/inventory.csv")
def inventory_csv():
    cols = list(KEYS[0].keys())
    lines = [",".join(cols)] + [",".join("" if k[c] is None else str(k[c]) for c in cols) for k in KEYS]
    return Response("\n".join(lines) + "\n", mimetype="text/csv")


def _self_signed(days: int) -> tuple[str, str]:
    key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mock-voltage")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )  # fmt: skip
    d = tempfile.mkdtemp()
    cp, kp = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cp, kp


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    http_port = int(os.environ.get("MOCK_PORT", "8800"))
    https_port = int(os.environ.get("MOCK_TLS_PORT", "8443"))
    cert, key = _self_signed(int(os.environ.get("MOCK_TLS_CERT_DAYS", "20")))
    threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=https_port, ssl_context=(cert, key), threaded=True),  # noqa: S104
        daemon=True,
    ).start()
    log.info("mock Voltage export on :%d (http) and :%d (https)", http_port, https_port)
    app.run(host="0.0.0.0", port=http_port, threaded=True)  # noqa: S104


if __name__ == "__main__":
    main()
