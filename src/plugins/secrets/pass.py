import subprocess
from collections.abc import Callable


def get_pass_secret(item_name: str, *_) -> str | None:
    result = subprocess.run(["pass", item_name], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ""


def register(secrets_providers: dict[str, Callable[[str, str], str | None]]):
    """Register the pass secret provider."""
    secrets_providers["pass"] = get_pass_secret
