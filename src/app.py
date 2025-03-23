import argparse
import importlib
import importlib.machinery
import importlib.util
import logging
import os
import pathlib
import secrets
import string
import subprocess
import sys
import types
from collections.abc import Callable
from functools import partial
from typing import Any, Literal, TypedDict

from jinja2 import Environment, FileSystemLoader

from src.logger import Logging

# Registry for secret providers
providers: dict[str, dict[str, Any]] = {"secrets": {}, "encryptions": {}}
logger = Logging(__name__)


type plugins_type = Literal["secrets", "encryptions"]


def load_plugins(type: plugins_type):
    """Load built-in and user plugins."""
    # Load built-in plugins
    _load_plugins_from_dir(pathlib.Path(__file__).parent / "plugins" / type, type)
    cwd_config_plugins = pathlib.Path.cwd() / ".temv" / "plugins" / type
    if cwd_config_plugins.exists():
        _load_plugins_from_dir(cwd_config_plugins, type)
    # Load plugins from TEMV_PLUGIN_DIR
    env_var_plugin_dir = os.getenv("TEMV_PLUGIN_DIR", None)
    if env_var_plugin_dir is None:
        env_var_plugin_dir = os.getenv("XDG_CONFIG_DIR")
    if env_var_plugin_dir:
        env_var_path = pathlib.Path(env_var_plugin_dir) / type
        if env_var_plugin_dir != "" and env_var_path.exists():
            _load_plugins_from_dir(env_var_path, "encryptions")
    logger.debug(
        "Loaded plugins",
        data={
            f"{type}_providers": list(providers[type].keys()),
        },
    )


def _load_plugins_from_dir(directory: pathlib.Path, type: plugins_type = "secrets"):
    """Helper to load plugins from a directory."""
    for file in directory.glob("*.py"):
        if file.name == "__init__.py":
            continue  # Skip __init__.py
        if type == "encryptions" and file.name == "basic.py":
            pkg = importlib.util.find_spec("cryptography")
            if pkg is None:
                continue
        spec: importlib.machinery.ModuleSpec | None = (
            importlib.util.spec_from_file_location(file.stem, file)
        )
        if spec and spec.loader:
            module: types.ModuleType = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if hasattr(module, "register"):
                register_func: Callable[..., Any] | None = getattr(module, "register")
                if callable(register_func):
                    register_func(providers[type])


def get_secret(source: str, key: str, path: str = "") -> str | None:
    if source in providers["secrets"]:
        return providers["secrets"][source](key, path)
    else:
        return None


def import_env(source: str) -> str:
    with open(source, "r") as env_file:
        env = env_file.readlines()
    return "\n".join(env).rstrip("\n")


type StringType = Literal["string", "password"]


def generate_random_string(
    length: int = 16,
    type: StringType = "string",
    lower_case: bool = True,
    numbers: bool = True,
    has_special_chars: bool = False,
    must_has_special_chars: bool = False,
    exclude_characters: str = "",
):
    characters = ""
    if not has_special_chars and must_has_special_chars:
        raise ValueError(
            "must_has_special_chars is True cannot use with has_special_chars is False"
        )
    if lower_case:
        characters += string.ascii_lowercase
    if numbers:
        characters += string.digits
    if type == "password" or has_special_chars:
        characters += string.punctuation

    # Remove excluded characters
    characters = "".join(c for c in characters if c not in exclude_characters)

    if not characters:
        raise ValueError("No valid characters left to generate a string.")
    output: str | None = None
    while (
        output is None
        or (output and len(output) < length)
        or (must_has_special_chars and all(c not in characters for c in output))
    ):
        try:
            # Try using OpenSSL for better randomness
            result = subprocess.run(
                [
                    "openssl",
                    "rand",
                    "-base64",
                    str(length * 2),  # Generate more bytes to filter properly
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            random_bytes = result.stdout

            # Filter to allowed characters
            output = "".join(c for c in random_bytes if c in characters)[:length]
        except (FileNotFoundError, subprocess.CalledProcessError):
            logger.exception("openssl not found")
            # Fallback to Python's secrets module
            output = "".join(secrets.choice(characters) for _ in range(length))
    return output


def decrypt(
    encrypted_value: str, module: str = "basic", password: str | None = None
) -> str | None:
    return providers["encryptions"][module]["decrypt"](encrypted_value, password)


def encrypt(
    value: str, module: str = "basic", password: str | None = None
) -> str | None:
    return providers["encryptions"][module]["encrypt"](value, password)


def shell(command: str) -> str | None:
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.rstrip("\n")


# Main rendering function
def render_template(template_path: str, password: str | None):
    env: Environment = Environment(loader=FileSystemLoader("."))
    env.globals["get_secret"] = get_secret  # pyright: ignore [reportArgumentType]
    env.globals["import_env"] = import_env  # pyright:ignore [reportArgumentType]
    env.globals["random"] = generate_random_string  # pyright:ignore [reportArgumentType]
    decrypt_func = partial(decrypt, password=password)
    env.globals["decrypt"] = decrypt_func  # pyright:ignore [reportArgumentType]
    encrypt_func = partial(encrypt, password=password)
    env.globals["encrypt"] = encrypt_func  # pyright:ignore [reportArgumentType]
    env.globals["shell"] = shell  # pyright:ignore [reportArgumentType]

    template = env.from_string(template_path)
    return template.render()


def read_input(file_path: str):
    """Reads input from a file."""
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def read_stdin():
    """Reads input from stdin if data is available."""
    if not sys.stdin.isatty():  # Check if stdin is piped
        return sys.stdin.read()
    return None


class Args(TypedDict):
    subcommand: str
    password: str | None
    input: str | None
    file: str | None
    output: str | None
    debug: bool


def main():
    parser = argparse.ArgumentParser(description="Render Jinja template with secrets.")
    _ = parser.add_argument("-d", "--debug", help="Debug mode", action="store_true")
    subparsers = parser.add_subparsers(help="subcommand help", dest="subcommand")
    generate_cmd = subparsers.add_parser("generate", help="Generate file from template")
    _ = generate_cmd.add_argument(
        "-f", "--file", required=True, help="Path to the Jinja template."
    )
    _ = generate_cmd.add_argument(
        "-o", "--output", help="Path to the output file.", default=None
    )
    _ = generate_cmd.add_argument(
        "-p", "--password", help="Password for decrypt", default=None
    )
    encrypt_cmd = subparsers.add_parser("encrypt", help="Encrypt input file or text")
    _ = encrypt_cmd.add_argument("-p", "--password", help="Password", default=None)
    _ = encrypt_cmd.add_argument("-i", "--input", help="Input")
    _ = encrypt_cmd.add_argument("-f", "--file", help="File")
    _ = encrypt_cmd.add_argument("-o", "--output", help="Directory")

    decrypt_cmd = subparsers.add_parser("decrypt", help="Decrypt input file or text")
    _ = decrypt_cmd.add_argument("-p", "--password", help="Pass", default=None)
    _ = decrypt_cmd.add_argument("-i", "--input", help="Input")
    _ = decrypt_cmd.add_argument("-f", "--file", help="File")
    _ = decrypt_cmd.add_argument("-o", "--output", help="Directory")
    args: Args = vars(parser.parse_args())  #pyright: ignore[reportAssignmentType]
    input_content: str | None = None
    if "input" in args and args['input'] is not None:
        input_content = args['input']
    elif args['file'] is not None:
        try:
            with open(args['file'], "r") as f:
                input_content = "".join(f.readlines())
        except:
            input_content = None
    else:
        input_content = read_stdin()
    if args['debug']:
        logger.logger.setLevel(logging.DEBUG)
    content: str | None = None
    match args.get('subcommand', None):
        case "generate":
            load_plugins("secrets")
            load_plugins("encryptions")
            if input_content:
                content = render_template(input_content, args.get("password", None))
        case "encrypt":
            load_plugins("encryptions")
            if input_content:
                content = providers["encryptions"]["basic"]["encrypt"](
                    input_content, args.get('password', None)
                )
        case "decrypt":
            load_plugins("encryptions")
            if input_content:
                content = providers["encryptions"]["basic"]["decrypt"](
                    input_content, args.get('password', None)
                )
        case _:
            pass
    if content:
        if (output := args.get('output', None)):
            with open(output, "w") as f:
                _ = f.write(content)
        else:
            print(content)


if __name__ == "__main__":
    main()
