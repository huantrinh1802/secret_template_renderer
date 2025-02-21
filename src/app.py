import argparse
import importlib
import importlib.machinery
import importlib.util
import pathlib
import types
from collections.abc import Callable
from typing import Any

from jinja2 import Environment, FileSystemLoader

# Registry for secret providers
secrets_providers: dict[str, Callable[[str, str], str | None]] = {}


def register_provider(name: str, provider_func: Callable[[str, str], str | None]):
    """Register a secret provider.
    
    :param name: The name of the provider to register.
    :type name: str
    :param provider_func: A callable function that takes two string arguments and 
                          returns a string or None. This function represents the 
                          secret provider logic.
    :type provider_func: Callable[[str, str], str | None]
    """
    secrets_providers[name] = provider_func
    print(f"Registered provider: {name}")


def load_plugins():
    """Load built-in and user plugins."""
    # Load built-in plugins
    _load_plugins_from_dir(pathlib.Path(__file__).parent / "plugins")

    # Load user plugins from ~/.config/jinja_secret_renderer/plugins/
    config_plugins_dir = (
        pathlib.Path.home() / ".config" / "temv" / "plugins"
    )
    if config_plugins_dir.exists():
        _load_plugins_from_dir(config_plugins_dir)


def _load_plugins_from_dir(directory: pathlib.Path):
    """Helper to load plugins from a directory."""
    for file in directory.glob("*.py"):
        if file.name == "__init__.py":
            continue  # Skip __init__.py

        spec: importlib.machinery.ModuleSpec | None = (
            importlib.util.spec_from_file_location(file.stem, file)
        )
        if spec and spec.loader:
            module: types.ModuleType = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Look for a 'register' function in the plugin
            if hasattr(module, "register"):
                register_func: Callable[..., Any] | None = getattr(module, "register")
                if callable(register_func):
                    register_func(secrets_providers)


# Jinja custom function
def get_secret(source: str, key: str, path: str = "") -> str | None:
    if source in secrets_providers:
        return secrets_providers[source](key, path)
    else:
        return None


# Main rendering function
def render_template(template_path: str, output_path: str):
    env: Environment = Environment(loader=FileSystemLoader("."))
    env.globals["get_secret"] = get_secret  # pyright: ignore [reportArgumentType]

    template = env.get_template(template_path)
    rendered_content = template.render()

    with open(output_path, "w") as f:
        _ = f.write(rendered_content)


def main():
    parser = argparse.ArgumentParser(description="Render Jinja template with secrets.")
    _ = parser.add_argument(
        "-t", "--template", required=True, help="Path to the Jinja template."
    )
    _ = parser.add_argument(
        "-o", "--output", required=True, help="Path to the output file."
    )
    args = parser.parse_args()
    load_plugins()
    render_template(args.template, args.output)  # pyright: ignore [reportAny]


if __name__ == "__main__":
    main()
