import hashlib


def test_digest():
    assert hashlib.md5(b"x").hexdigest()
