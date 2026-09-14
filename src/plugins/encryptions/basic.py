import base64
import hashlib
import logging
import os
from getpass import getpass
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Legacy CBC imports kept only for decrypting old v1 values
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

logger = logging.getLogger(__name__)

_GCM_PREFIX = "v2:"
_PBKDF2_ITERATIONS = 600_000


def derive_key(password: str, salt: bytes, iterations: int = _PBKDF2_ITERATIONS) -> bytes:
    """Derives a 32-byte key from the password using PBKDF2."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=32)


def encrypt(plaintext: str, password: str | None) -> str:
    """Encrypts plaintext using AES-256-GCM (authenticated)."""
    if password is None:
        password = os.getenv("TEMV_BASIC_PASSWORD")
    if password is None:
        password = getpass()
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt appends the 16-byte auth tag to the ciphertext
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode(), None)
    payload = base64.b64encode(salt + nonce + ciphertext_with_tag).decode()
    return _GCM_PREFIX + payload


def _decrypt_gcm(encrypted_bytes: bytes, password: str) -> bytes:
    salt = encrypted_bytes[:16]
    nonce = encrypted_bytes[16:28]
    ciphertext_with_tag = encrypted_bytes[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)


def _decrypt_cbc_legacy(encrypted_bytes: bytes, password: str) -> bytes:
    """Decrypt values produced by the old AES-256-CBC path (100k PBKDF2 iterations)."""
    salt = encrypted_bytes[:16]
    key = derive_key(password, salt, iterations=100_000)
    iv = encrypted_bytes[16:32]
    ciphertext = encrypted_bytes[32:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _try_decrypt(encrypted: str, password: str) -> bytes | None:
    try:
        is_gcm = encrypted.startswith(_GCM_PREFIX)
        raw = base64.b64decode(encrypted[len(_GCM_PREFIX):] if is_gcm else encrypted)
        return _decrypt_gcm(raw, password) if is_gcm else _decrypt_cbc_legacy(raw, password)
    except Exception:
        return None


def decrypt(encrypted: str, password: str | None) -> str | None:
    """Decrypts AES-256-GCM encrypted text; falls back to legacy CBC for old values."""
    if password is None:
        password = os.getenv("TEMV_BASIC_PASSWORD")

    if password is not None:
        result = _try_decrypt(encrypted, password)
        if result is None:
            logger.warning("Failed to decrypt the secret")
            return None
        return result.decode()

    for attempt in range(3):
        pwd = getpass()
        result = _try_decrypt(encrypted, pwd)
        if result is not None:
            return result.decode()
        if attempt < 2:
            logger.warning("Incorrect password. Try again!")
        else:
            logger.warning("Failed to decrypt the secret after 3 attempts")
    return None


def register(registry: dict[str, dict[str, Callable[[str, str | None], str | None]]]):
    """Register the basic encryption provider."""
    registry["basic"] = {"encrypt": encrypt, "decrypt": decrypt}
