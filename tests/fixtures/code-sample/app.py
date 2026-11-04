"""Sample service code for keycensus's code scanner tests."""

import hashlib

from Crypto.Cipher import DES3  # pycryptodome
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def cache_key(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()  # keycensus:ignore  (not security-relevant)


def keys():
    signing = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    agreement = ec.generate_private_key(ec.SECP384R1())
    return signing, agreement


def legacy_encrypt(key: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


def triple(key: bytes, data: bytes) -> bytes:
    # hashlib.md5() in a comment is not a call
    return DES3.new(key, DES3.MODE_CBC, iv=b"\0" * 8).encrypt(data)


DIGEST = hashes.SHA256()
