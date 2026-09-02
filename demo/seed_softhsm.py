#!/usr/bin/env python3
"""Create a SoftHSM token with a realistic mix of keys (good and bad).

    export SOFTHSM2_CONF=/path/to/softhsm2.conf   # optional
    python demo/seed_softhsm.py [--module /usr/lib/softhsm/libsofthsm2.so] [--label demo] [--pin 1234]

Keys created:
  payments-dek-aes256   AES-256, encrypt/decrypt       (fine)
  session-aes128        AES-128                        (quantum-reduced)
  legacy-pin-3des       3DES                           (weak-algorithm)
  hmac-256              generic secret 256-bit         (fine)
  legacy-rsa1024        RSA-1024                       (weak-key-size)
  signing-rsa2048       RSA-2048, sign/verify          (quantum-vulnerable)
  kek-rsa4096           RSA-4096 wrap/unwrap, extractable (exportable + quantum-vulnerable-encryption)
  ecdsa-p256            EC P-256 sign/verify           (quantum-vulnerable)
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys

import pkcs11
from pkcs11 import Attribute, KeyType, ObjectClass

ENC_ONLY = {Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.EXTRACTABLE: False}


def ensure_token(label: str, pin: str, so_pin: str):
    util = shutil.which("softhsm2-util")
    if not util:
        sys.exit("softhsm2-util not found; apt-get install softhsm2")
    listing = subprocess.run([util, "--show-slots"], capture_output=True, text=True, check=False).stdout
    if f"Label:            {label}" in listing:
        return
    subprocess.run(
        [util, "--init-token", "--free", "--label", label, "--pin", pin, "--so-pin", so_pin],
        check=True,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", default="/usr/lib/softhsm/libsofthsm2.so")
    ap.add_argument("--label", default="demo")
    ap.add_argument("--pin", default="1234")
    ap.add_argument("--so-pin", default="12345678")
    args = ap.parse_args()

    ensure_token(args.label, args.pin, args.so_pin)
    lib = pkcs11.lib(args.module)
    token = lib.get_token(token_label=args.label)
    with token.open(rw=True, user_pin=args.pin) as s:
        existing = {o[Attribute.LABEL] for o in s.get_objects({Attribute.CLASS: ObjectClass.SECRET_KEY})}
        if "payments-dek-aes256" in existing:
            print("token already seeded")
            return

        s.generate_key(KeyType.AES, 256, label="payments-dek-aes256", store=True,
                       template=ENC_ONLY)  # fmt: skip
        s.generate_key(KeyType.AES, 128, label="session-aes128", store=True,
                       template=ENC_ONLY)  # fmt: skip
        s.generate_key(KeyType.DES3, label="legacy-pin-3des", store=True,
                       template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True})  # fmt: skip
        s.generate_key(KeyType.GENERIC_SECRET, 256, label="hmac-256", store=True,
                       template={Attribute.SIGN: True, Attribute.VERIFY: True})  # fmt: skip

        s.generate_keypair(KeyType.RSA, 1024, label="legacy-rsa1024", store=True,
                           private_template={Attribute.SIGN: True, Attribute.DECRYPT: True})  # fmt: skip
        s.generate_keypair(KeyType.RSA, 2048, label="signing-rsa2048", store=True,
                           private_template={Attribute.SIGN: True, Attribute.DECRYPT: False,
                                             Attribute.UNWRAP: False, Attribute.EXTRACTABLE: False})  # fmt: skip
        s.generate_keypair(KeyType.RSA, 4096, label="kek-rsa4096", store=True,
                           private_template={Attribute.UNWRAP: True, Attribute.DECRYPT: True,
                                             Attribute.SIGN: False, Attribute.EXTRACTABLE: True})  # fmt: skip
        params = s.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        params.generate_keypair(label="ecdsa-p256", store=True,
                                private_template={Attribute.SIGN: True, Attribute.EXTRACTABLE: False})  # fmt: skip
    print(f"seeded SoftHSM token '{args.label}' with 8 key objects")


if __name__ == "__main__":
    main()
