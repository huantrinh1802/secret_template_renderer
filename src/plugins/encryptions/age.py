import base64
import logging
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from getpass import getpass

logger = logging.getLogger(__name__)

_PREFIX = "age:"
_ARMOR_HEADER = "-----BEGIN AGE ENCRYPTED FILE-----"
_SCRYPT_STANZA = b"-> scrypt "
_IDENTITY_ENV = "STR_AGE_IDENTITY"
_IDENTITY_SECRET_ENV = "STR_AGE_IDENTITY_SECRET"
_RECIPIENT_ENV = "STR_AGE_RECIPIENT"
_SSH_AGENT_ENV = "STR_AGE_SSH_AGENT"
_PASSPHRASE_ENV = "STR_AGE_PASSPHRASE"
_MODE_ENV = "STR_AGE_MODE"
_SSH_KEY_TYPES = ("ssh-ed25519", "ssh-rsa")


def _binary(name: str) -> str | None:
    path = shutil.which(name)
    if path is None:
        logger.error(f"'{name}' binary not found in PATH (install from https://age-encryption.org)")
    return path


def _pyrage():
    try:
        import pyrage
    except ImportError:
        logger.error("Passphrase mode needs pyrage (pip install 'secret_template_renderer[age]')")
        return None
    return pyrage


def _passphrase(password: str | None) -> str:
    return password or os.getenv(_PASSPHRASE_ENV) or getpass("age passphrase: ")


def _fetch_identity_secret() -> bytes | None:
    """Read the private key via a secrets provider: ``provider:key[:path]``."""
    spec = os.getenv(_IDENTITY_SECRET_ENV, "")
    provider, _, rest = spec.partition(":")
    key, _, path = rest.partition(":")
    if not provider or not key:
        logger.error(f"{_IDENTITY_SECRET_ENV} must look like provider:key[:path]")
        return None
    # Imported lazily: this plugin is loaded by src.app itself.
    from src import app

    app.load_plugins("secrets")
    secret = app.get_secret(provider, key, path)
    if not secret:
        logger.error(f"Could not read the age identity from '{provider}'")
        return None
    return (secret.rstrip("\n") + "\n").encode()


def _identity() -> tuple[list[str], bytes | None] | None:
    """Return (age args, stdin data) to supply the identity, or None if unconfigured."""
    if os.getenv(_IDENTITY_SECRET_ENV):
        key = _fetch_identity_secret()
        return (["-i", "-"], key) if key else None
    identity = os.getenv(_IDENTITY_ENV)
    if identity:
        return ["-i", str(pathlib.Path(identity).expanduser())], None
    logger.error(f"No age identity configured (set {_IDENTITY_ENV} or {_IDENTITY_SECRET_ENV})")
    return None


def _ssh_agent_recipients() -> list[str]:
    """Public keys held by the SSH agent (e.g. 1Password, Bitwarden)."""
    setting = os.getenv(_SSH_AGENT_ENV, "").strip()
    if not setting:
        return []
    ssh_add = shutil.which("ssh-add")
    if ssh_add is None:
        logger.error("'ssh-add' not found in PATH")
        return []
    result = subprocess.run([ssh_add, "-L"], capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"ssh-add -L failed: {result.stderr.strip() or result.stdout.strip()}")
        return []
    keys = [k for k in result.stdout.splitlines() if k.startswith(_SSH_KEY_TYPES)]
    if setting.lower() not in ("1", "true", "yes", "all"):
        keys = [k for k in keys if setting in k]
    if not keys:
        logger.error("No matching age-compatible (ed25519/rsa) key in the SSH agent")
    return keys


def _recipients() -> list[str]:
    """Explicit recipients, plus SSH-agent keys; else derived from the identity."""
    configured = re.split(r"[,\n]", os.getenv(_RECIPIENT_ENV, ""))
    recipients = [r.strip() for r in configured if r.strip()] + _ssh_agent_recipients()
    if recipients:
        return recipients

    identity = _identity()
    keygen = _binary("age-keygen")
    if identity is None or keygen is None:
        return []
    args, stdin = identity
    result = subprocess.run([keygen, "-y", args[1]], input=stdin, capture_output=True)
    if result.returncode != 0:
        logger.error(f"Could not derive recipient from identity: {result.stderr.decode().strip()}")
        return []
    return [line for line in result.stdout.decode().splitlines() if line]


def _use_passphrase(password: str | None) -> bool:
    return bool(password) or os.getenv(_MODE_ENV) == "passphrase" or bool(os.getenv(_PASSPHRASE_ENV))


def encrypt(plaintext: str, password: str | None = None) -> str | None:
    """Encrypts to age recipients, or with a passphrase when one/``STR_AGE_MODE=passphrase`` is given."""
    if _use_passphrase(password):
        pyrage = _pyrage()
        if pyrage is None:
            return None
        data = pyrage.passphrase.encrypt(plaintext.encode(), _passphrase(password))
        return _PREFIX + base64.b64encode(data).decode()

    age = _binary("age")
    if age is None:
        return None
    recipients = _recipients()
    if not recipients:
        logger.error(f"No age recipient configured (set {_RECIPIENT_ENV} or {_SSH_AGENT_ENV})")
        return None
    cmd = [age, "-e"]
    for recipient in recipients:
        cmd += ["-r", recipient]
    result = subprocess.run(cmd, input=plaintext.encode(), capture_output=True)
    if result.returncode != 0:
        logger.error(f"age encryption failed: {result.stderr.decode().strip()}")
        return None
    return _PREFIX + base64.b64encode(result.stdout).decode()


def _decrypt_passphrase(data: bytes, password: str | None) -> str | None:
    pyrage = _pyrage()
    if pyrage is None:
        return None
    interactive = not (password or os.getenv(_PASSPHRASE_ENV))
    for attempt in range(3 if interactive else 1):
        try:
            return pyrage.passphrase.decrypt(data, _passphrase(password)).decode()
        except pyrage.DecryptError:
            if interactive and attempt < 2:
                logger.warning("Incorrect passphrase. Try again!")
    logger.warning("Failed to decrypt the secret")
    return None


def _decrypt_identity(data: bytes) -> str | None:
    age = _binary("age")
    identity = _identity()
    if age is None or identity is None:
        return None
    args, stdin = identity
    if stdin is None:
        result = subprocess.run([age, "-d", *args], input=data, capture_output=True)
    else:
        # The identity occupies stdin, so the ciphertext goes via a file.
        with tempfile.TemporaryDirectory(prefix="str-age-") as tmp:
            path = pathlib.Path(tmp) / "value.age"
            path.write_bytes(data)
            result = subprocess.run([age, "-d", *args, str(path)], input=stdin, capture_output=True)
    if result.returncode != 0:
        logger.warning(f"Failed to decrypt the secret: {result.stderr.decode().strip()}")
        return None
    return result.stdout.decode()


def decrypt(encrypted: str, password: str | None = None) -> str | None:
    """Decrypts an `age:` value (or armored age file), by passphrase or identity per its header."""
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
    # Binary header lists recipient stanzas; armored files are left to the age binary.
    if _SCRYPT_STANZA in data.split(b"\n---", 1)[0]:
        return _decrypt_passphrase(data, password)
    return _decrypt_identity(data)


def register(registry: dict[str, dict[str, Callable[..., str | None]]]):
    """Register the age encryption provider."""
    registry["age"] = {"encrypt": encrypt, "decrypt": decrypt}
