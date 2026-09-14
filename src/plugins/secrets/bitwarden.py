import json
import subprocess
from collections.abc import Callable


def get_bitwarden_secret(item_name: str, path: str) -> str | None:
    result = subprocess.run(
        ["bw", "get", "item", item_name],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    try:
        item = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None

    if not path:
        return result.stdout.strip()

    type_, value = path.split(".", 1)
    match type_:
        case "field":
            for field in item.get("fields", []):
                if field.get("name") == value:
                    return field.get("value")
            return None
        case "login":
            return item.get("login", {}).get(value)
        case _:
            return None


def register(secrets_providers: dict[str, Callable[[str, str], str | None]]):
    """Register the Bitwarden secret provider."""
    secrets_providers["bitwarden"] = get_bitwarden_secret
