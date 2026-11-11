import base64
import logging
import os
import pathlib
import re
import shutil
import subprocess
from collections.abc import Callable

logger = logging.getLogger(__name__)

_PREFIX = "age:"
_ARMOR_HEADER = "-----BEGIN AGE ENCRYPTED FILE-----"
_IDENTITY_ENV = "TEMV_AGE_IDENTITY"
_RECIPIENT_ENV = "TEMV_AGE_RECIPIENT"


def _binary(name: str) -> str | None:
    path = shutil.which(name)
    if path is None:
        logger.error(f"'{name}' binary not found in PATH (install from https://age-encryption.org)")
    return path


def _identity_path() -> str | None:
    identity = os.getenv(_IDENTITY_ENV)
    if not identity:
        logger.error(f"No age identity configured (set {_IDENTITY_ENV} or pass --identity)")
        return None
    return str(pathlib.Path(identity).expanduser())


def _recipients() -> list[str]:
    """Recipients from TEMV_AGE_RECIPIENT, falling back to the one derived from the identity."""
    configured = re.split(r"[\s,]+", os.getenv(_RECIPIENT_ENV, "").strip())
    recipients = [r for r in configured if r]
    if recipients:
        return recipients

    identity = _identity_path()
    keygen = _binary("age-keygen")
    if identity is None or keygen is None:
        return []
    result = subprocess.run([keygen, "-y", identity], capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"Could not derive recipient from identity: {result.stderr.strip()}")
        return []
    return [line for line in result.stdout.splitlines() if line]


def encrypt(plaintext: str, password: str | None = None) -> str | None:
    """Encrypts plaintext to the configured age recipient(s); `password` is unused."""
    age = _binary("age")
    recipients = _recipients()
    if age is None or not recipients:
        if age is not None:
            logger.error(f"No age recipient configured (set {_RECIPIENT_ENV} or pass --recipient)")
        return None
    cmd = [age, "-e"]
    for recipient in recipients:
        cmd += ["-r", recipient]
    result = subprocess.run(cmd, input=plaintext.encode(), capture_output=True)
    if result.returncode != 0:
        logger.error(f"age encryption failed: {result.stderr.decode().strip()}")
        return None
    return _PREFIX + base64.b64encode(result.stdout).decode()


def decrypt(encrypted: str, password: str | None = None) -> str | None:
    """Decrypts an `age:` value (or an armored age file) with the configured identity."""
    age = _binary("age")
    identity = _identity_path()
    if age is None or identity is None:
        return None
    encrypted = encrypted.strip()
    try:
        if encrypted.startswith(_PREFIX):
            data = base64.b64decode(encrypted[len(_PREFIX):], validate=True)
        elif encrypted.startswith(_ARMOR_HEADER):
            data = encrypted.encode()
        else:
            logger.warning("Failed to decrypt the secret: not an age value")
            return None
    except ValueError:
        logger.warning("Failed to decrypt the secret: malformed age value")
        return None
    result = subprocess.run([age, "-d", "-i", identity], input=data, capture_output=True)
    if result.returncode != 0:
        logger.warning(f"Failed to decrypt the secret: {result.stderr.decode().strip()}")
        return None
    return result.stdout.decode()


def register(registry: dict[str, dict[str, Callable[..., str | None]]]):
    """Register the age encryption provider."""
    registry["age"] = {"encrypt": encrypt, "decrypt": decrypt}
