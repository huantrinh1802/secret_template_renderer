import subprocess
from collections.abc import Callable


def get_bitwarden_secret(item_name: str, path: str) -> str | None:
    command = f'bw get item "{item_name}"'
    if path and len(path) > 0:
        type, value = path.split(".")
        match type:
            case "field":
                command += (
                    f" | jq -r '.fields[] | select(.name == \"{value}\") | .value'"
                )
            case "login":
                command += f" | jq -r '.login.{value}"
            case _:
                return None
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result.stdout.strip()


def register(secrets_providers: dict[str, Callable[[str, str], str | None]]):
    """Register the Bitwarden secret provider."""
    secrets_providers["bitwarden"] = get_bitwarden_secret
