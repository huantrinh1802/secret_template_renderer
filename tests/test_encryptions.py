import base64
import hashlib
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from src.plugins.encryptions.basic import (
    _GCM_PREFIX,
    _PBKDF2_ITERATIONS,
    decrypt,
    encrypt,
)


def _make_cbc_value(plaintext: str, password: str) -> str:
    """Produce an old-format AES-256-CBC ciphertext (no v2: prefix)."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000, dklen=32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = enc.update(padded) + enc.finalize()
    return base64.b64encode(salt + iv + ciphertext).decode()


class TestEncrypt:
    def test_produces_gcm_prefix(self):
        assert encrypt("hello", "pw").startswith(_GCM_PREFIX)

    def test_each_call_produces_different_ciphertext(self):
        a = encrypt("hello", "pw")
        b = encrypt("hello", "pw")
        assert a != b  # random salt + nonce

    def test_pbkdf2_iterations_at_minimum(self):
        assert _PBKDF2_ITERATIONS >= 600_000


class TestDecrypt:
    def test_gcm_roundtrip(self):
        enc = encrypt("my secret", "correct-horse")
        assert decrypt(enc, "correct-horse") == "my secret"

    def test_wrong_password_returns_none(self):
        enc = encrypt("secret", "correct")
        assert decrypt(enc, "wrong") is None

    def test_tampered_ciphertext_returns_none(self):
        enc = encrypt("secret", "pw")
        chars = list(enc)
        mid = len(chars) // 2
        chars[mid] = "A" if chars[mid] != "A" else "B"
        assert decrypt("".join(chars), "pw") is None

    def test_cbc_backward_compat(self):
        old = _make_cbc_value("legacy-value", "old-pw")
        assert not old.startswith(_GCM_PREFIX)
        assert decrypt(old, "old-pw") == "legacy-value"

    def test_cbc_wrong_password_returns_none(self):
        old = _make_cbc_value("value", "correct")
        assert decrypt(old, "wrong") is None

    def test_unicode_roundtrip(self):
        enc = encrypt("café ☕", "pw")
        assert decrypt(enc, "pw") == "café ☕"
