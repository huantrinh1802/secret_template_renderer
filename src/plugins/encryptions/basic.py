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


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte key from the password using PBKDF2."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)


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
    """Decrypt values produced by the old AES-256-CBC path."""
    salt = encrypted_bytes[:16]
    key = derive_key(password, salt)
    iv = encrypted_bytes[16:32]
    ciphertext = encrypted_bytes[32:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def decrypt(encrypted: str, password: str | None) -> str | None:
    """Decrypts AES-256-GCM encrypted text; falls back to legacy CBC for old values."""
    attempts = 0
    if password is None:
        password = os.getenv("TEMV_BASIC_PASSWORD", None)
    if password is not None:
        attempts = 2
    plaintext = None
    while attempts < 3 and plaintext is None:
        if password is None:
            password = getpass()
        try:
            is_gcm = encrypted.startswith(_GCM_PREFIX)
            raw = base64.b64decode(encrypted[len(_GCM_PREFIX):] if is_gcm else encrypted)
            plaintext = (
                _decrypt_gcm(raw, password)
                if is_gcm
                else _decrypt_cbc_legacy(raw, password)
            )
        except Exception:
            if attempts < 2:
                logger.warning("Cannot decrypt the secret. Try again!")
            else:
                logger.warning("Failed to decrypt the secret")
            attempts += 1
            plaintext = None
            password = None
    if plaintext is None:
        return None
    return plaintext.decode()


def register(registry: dict[str, dict[str, Callable[[str, str | None], str | None]]]):
    """Register the basic encryption provider."""
    registry["basic"] = {"encrypt": encrypt, "decrypt": decrypt}
