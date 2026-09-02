#!/usr/bin/env python3
"""Seed a moto (fake AWS) KMS with a realistic mix of keys.

    python demo/seed_kms.py --endpoint http://localhost:5000

Real boto3 code; only the endpoint is fake. Keys:
  alias/payments-cmk        SYMMETRIC_DEFAULT, rotation ON        (fine)
  alias/legacy-cmk          SYMMETRIC_DEFAULT, rotation OFF       (rotation-disabled)
  alias/jwt-signing         RSA_2048 SIGN_VERIFY                  (quantum-vulnerable)
  alias/envelope-rsa4096    RSA_4096 ENCRYPT_DECRYPT              (quantum-vulnerable-encryption)
  alias/webhook-ecdsa       ECC_NIST_P256 SIGN_VERIFY             (quantum-vulnerable)
  alias/api-hmac            HMAC_256 GENERATE_VERIFY_MAC          (fine)
  alias/retired-cmk         SYMMETRIC_DEFAULT, disabled           (key-not-active)
"""

from __future__ import annotations

import argparse
import os

import boto3


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", default=os.environ.get("KMS_ENDPOINT", "http://localhost:5000"))
    ap.add_argument("--region", default="us-east-1")
    args = ap.parse_args()

    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
    kms = boto3.client("kms", region_name=args.region, endpoint_url=args.endpoint)

    existing = {a["AliasName"] for a in kms.list_aliases()["Aliases"]}
    if "alias/payments-cmk" in existing:
        print("KMS already seeded")
        return

    def make(
        alias,
        spec="SYMMETRIC_DEFAULT",
        usage="ENCRYPT_DECRYPT",
        rotate=None,
        enabled=True,
        tags=None,
    ):
        md = kms.create_key(
            KeySpec=spec, KeyUsage=usage, Description=f"demo {alias}",
            Tags=[{"TagKey": k, "TagValue": v} for k, v in (tags or {}).items()],
        )["KeyMetadata"]  # fmt: skip
        kms.create_alias(AliasName=f"alias/{alias}", TargetKeyId=md["KeyId"])
        if rotate:
            kms.enable_key_rotation(KeyId=md["KeyId"])
        if not enabled:
            kms.disable_key(KeyId=md["KeyId"])
        return md["KeyId"]

    make("payments-cmk", rotate=True, tags={"app": "payments", "pci": "true"})
    make("legacy-cmk", rotate=False, tags={"app": "reporting"})
    make("jwt-signing", "RSA_2048", "SIGN_VERIFY", tags={"app": "auth"})
    make("envelope-rsa4096", "RSA_4096", "ENCRYPT_DECRYPT", tags={"app": "archive"})
    make("webhook-ecdsa", "ECC_NIST_P256", "SIGN_VERIFY")
    make("api-hmac", "HMAC_256", "GENERATE_VERIFY_MAC")
    make("retired-cmk", enabled=False)
    print("seeded fake KMS with 7 keys")


if __name__ == "__main__":
    main()
