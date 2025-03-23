import base64
import hashlib
import logging
import os
from getpass import getpass
from typing import Callable

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

logger = logging.getLogger(__name__)


def derive_key(password: str) -> bytes:
    """Derives a 32-byte key from the password using SHA-256."""
    return hashlib.sha256(password.encode()).digest()


def encrypt(plaintext: str, password: str | None) -> str:
    """Encrypts plaintext using AES-256-CBC."""
    if password is None:
        password = os.getenv("TEMV_BASIC_PASSWORD")
    if password is None:
        password = getpass()
    key = derive_key(password)
    iv = os.urandom(16)  # AES block size is 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Apply PKCS7 padding
    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Encode IV + ciphertext in Base64
    return base64.b64encode(iv + ciphertext).decode()


def decrypt(encrypted: str, password: str | None) -> str | None:
    """Decrypts AES-256-CBC encrypted text."""
    time = 0
    if password is None:
        password = os.getenv("TEMV_BASIC_PASSWORD", None)
    if password is not None:
        time = 2
    plaintext = None
    while time < 3 and plaintext is None:
        if password is None:
            password = getpass()
        try:
            key = derive_key(password)
            encrypted_bytes = base64.b64decode(encrypted)
            iv = encrypted_bytes[:16]  # First 16 bytes are the IV
            ciphertext = encrypted_bytes[16:]

            cipher = Cipher(
                algorithms.AES(key), modes.CBC(iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()

            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove padding
            unpadder = PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        except:
            if time < 2:
                logger.warning("Cannot decrypt the secret. Try again!")
            else:
                logger.warning("Failed to decrypt the secret")
            time = time + 1
            plaintext = None
            password = None
    if time == 3 or plaintext is None:
        return None
    return plaintext.decode()


def register(registry: dict[str, dict[str, Callable[[str, str | None], str | None]]]):
    """Register the pass secret provider."""
    registry["basic"] = {"encrypt": encrypt, "decrypt": decrypt}
