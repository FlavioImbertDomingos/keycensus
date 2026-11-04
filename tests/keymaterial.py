"""Real keystores and SSH keys, made by keytool, openssl and ssh-keygen at test time (never committed)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

TOOLS = {t: shutil.which(t) for t in ("keytool", "openssl", "ssh-keygen")}


def _run(*cmd, **kw):
    env = {**os.environ, "JAVA_TOOL_OPTIONS": ""}
    return subprocess.run(list(cmd), check=True, capture_output=True, env=env, **kw)


def make_java(d: Path) -> None:
    kt = TOOLS["keytool"]
    _run(kt, "-genkeypair", "-alias", "web", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=web.example.com",
         "-validity", "365", "-storetype", "JKS", "-keystore", str(d / "app.jks"), "-storepass", "changeit",
         "-keypass", "changeit")  # fmt: skip
    _run(kt, "-genkeypair", "-alias", "sign", "-keyalg", "EC", "-groupname", "secp384r1", "-dname", "CN=signer",
         "-validity", "365", "-storetype", "JKS", "-keystore", str(d / "app.jks"), "-storepass", "changeit",
         "-keypass", "changeit")  # fmt: skip
    _run(kt, "-exportcert", "-alias", "web", "-keystore", str(d / "app.jks"), "-storepass", "changeit",
         "-file", str(d / "web.der"))  # fmt: skip
    _run(kt, "-importcert", "-noprompt", "-alias", "ca", "-file", str(d / "web.der"), "-storetype", "JKS",
         "-keystore", str(d / "trust.jks"), "-storepass", "s3cr3t-Pw")  # fmt: skip
    _run(kt, "-genseckey", "-alias", "db", "-keyalg", "AES", "-keysize", "256", "-storetype", "JCEKS",
         "-keystore", str(d / "hadoop.jceks"), "-storepass", "changeit", "-keypass", "changeit")  # fmt: skip
    _run(kt, "-genkeypair", "-alias", "api", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=api",
         "-validity", "365", "-storetype", "JCEKS", "-keystore", str(d / "hadoop.jceks"), "-storepass", "changeit",
         "-keypass", "changeit")  # fmt: skip
    _run(kt, "-genkeypair", "-alias", "tls", "-keyalg", "RSA", "-keysize", "3072", "-dname", "CN=tls.example.com",
         "-validity", "365", "-storetype", "PKCS12", "-keystore", str(d / "modern.p12"), "-storepass",
         "Str0ng-pass")  # fmt: skip


def make_openssl(d: Path) -> None:
    o = TOOLS["openssl"]
    _run(o, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj", "/CN=legacy",
         "-keyout", str(d / "l.key"), "-out", str(d / "l.crt"))  # fmt: skip
    legacy = ["-legacy"] if b"-legacy" in subprocess.run([o, "pkcs12", "-help"], capture_output=True).stderr else []
    _run(o, "pkcs12", "-export", *legacy, "-in", str(d / "l.crt"), "-inkey", str(d / "l.key"),
         "-out", str(d / "legacy.p12"), "-passout", "pass:changeit", "-certpbe", "PBE-SHA1-RC2-40",
         "-keypbe", "PBE-SHA1-3DES", "-macalg", "sha1")  # fmt: skip
    _run(o, "pkcs12", "-export", "-in", str(d / "l.crt"), "-inkey", str(d / "l.key"), "-out", str(d / "locked.p12"),
         "-passout", "pass:N0t-a-default!")  # fmt: skip


def make_ssh(d: Path) -> None:
    sk = TOOLS["ssh-keygen"]
    _run(sk, "-q", "-t", "ed25519", "-N", "", "-C", "alice@laptop", "-f", str(d / "id_ed25519"))
    _run(sk, "-q", "-t", "rsa", "-b", "3072", "-N", "pass phrase", "-C", "bob", "-f", str(d / "id_rsa"))
    _run(sk, "-q", "-t", "ecdsa", "-b", "384", "-N", "", "-f", str(d / "ssh_host_ecdsa_key"))
    _run(sk, "-q", "-t", "rsa", "-b", "1024", "-N", "", "-f", str(d / "ssh_host_rsa_key"))
    _run(sk, "-q", "-t", "ed25519", "-N", "", "-C", "ca", "-f", str(d / "user_ca"))
    _run(sk, "-q", "-s", str(d / "user_ca"), "-I", "alice-cert", "-n", "alice,root", "-V", "+52w",
         str(d / "id_ed25519.pub"))  # fmt: skip
    pub = lambda n: " ".join((d / n).read_text().split()[:2])  # noqa: E731
    (d / "authorized_keys").write_text(f'command="/bin/true",no-pty {(d / "id_ed25519.pub").read_text().strip()}\n'
                                       f"{(d / 'id_rsa.pub').read_text().strip()}\n")  # fmt: skip
    (d / "known_hosts").write_text(f"github.com {pub('ssh_host_ecdsa_key.pub')}\n"
                                   f"|1|abc=|def= {pub('ssh_host_rsa_key.pub')}\n"
                                   f"@cert-authority *.example.com {pub('user_ca.pub')}\n")  # fmt: skip


@pytest.fixture(scope="session")
def keymaterial(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("keymaterial")
    if TOOLS["keytool"]:
        make_java(d)
    if TOOLS["openssl"]:
        make_openssl(d)
    if TOOLS["ssh-keygen"]:
        make_ssh(d)
    return d


def need(*tools):
    missing = [t for t in tools if not TOOLS[t]]
    return pytest.mark.skipif(bool(missing), reason=f"needs {', '.join(missing)}")
