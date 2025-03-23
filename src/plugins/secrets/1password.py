import subprocess
from collections.abc import Callable


def get_1password_secret(item_name: str, *_) -> str | None:
    result = subprocess.run(
        ["op", "read", f"op://{item_name}"], capture_output=True, text=True
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def register(secrets_providers: dict[str, Callable[[str, str], str | None]]):
    """Register the 1Password secret provider."""
    secrets_providers["1password"] = get_1password_secret
