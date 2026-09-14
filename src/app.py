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

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from src.logger import Logging

# Registry for secret providers
providers: dict[str, dict[str, Any]] = {"secrets": {}, "encryptions": {}}
logger = Logging(__name__)


type plugins_type = Literal["secrets", "encryptions"]


class SafeFileSystemLoader(FileSystemLoader):
    """Restrict {% include %} / {% extends %} to files under the working directory."""

    def get_source(self, environment, template):
        resolved = (pathlib.Path(".") / template).resolve()
        if not resolved.is_relative_to(pathlib.Path.cwd().resolve()):
            raise TemplateNotFound(template)
        return super().get_source(environment, template)


def load_plugins(plugin_type: plugins_type):
    """Load built-in and user plugins."""
    _load_plugins_from_dir(
        pathlib.Path(__file__).parent / "plugins" / plugin_type, plugin_type
    )
    cwd_config_plugins = pathlib.Path.cwd() / ".temv" / "plugins" / plugin_type
    if cwd_config_plugins.exists():
        _load_plugins_from_dir(cwd_config_plugins, plugin_type)
    env_var_plugin_dir = os.getenv("TEMV_PLUGIN_DIR", None)
    if env_var_plugin_dir is None:
        env_var_plugin_dir = os.getenv("XDG_CONFIG_DIR")
    if env_var_plugin_dir:
        env_var_path = pathlib.Path(env_var_plugin_dir) / plugin_type
        if env_var_path.exists():
            _load_plugins_from_dir(env_var_path, plugin_type)
    logger.debug(
        "Loaded plugins",
        data={
            f"{plugin_type}_providers": list(providers[plugin_type].keys()),
        },
    )


def _load_plugins_from_dir(directory: pathlib.Path, plugin_type: plugins_type = "secrets"):
    """Helper to load plugins from a directory."""
    for file in directory.glob("*.py"):
        if file.name == "__init__.py":
            continue
        if plugin_type == "encryptions" and file.name == "basic.py":
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
                    register_func(providers[plugin_type])


def get_secret(source: str, key: str, path: str = "") -> str | None:
    if source in providers["secrets"]:
        return providers["secrets"][source](key, path)
    else:
        return None


def import_env(source: str) -> str:
    resolved = pathlib.Path(source).resolve()
    if not resolved.is_relative_to(pathlib.Path.cwd().resolve()):
        raise ValueError(
            f"import_env: path outside working directory is not allowed: {source}"
        )
    with open(resolved, "r", encoding="utf-8") as env_file:
        return env_file.read().rstrip("\n")


type StringType = Literal["string", "password"]


def generate_random_string(
    length: int = 16,
    type: StringType = "string",  # noqa: A002
    lower_case: bool = True,
    numbers: bool = True,
    has_special_chars: bool = False,
    must_has_special_chars: bool = False,
    exclude_characters: str = "",
):
    if not isinstance(length, int) or length < 1 or length > 4096:
        raise ValueError(f"length must be a positive integer <= 4096, got {length!r}")
    if not has_special_chars and must_has_special_chars:
        raise ValueError(
            "must_has_special_chars is True cannot use with has_special_chars is False"
        )
    characters = ""
    if lower_case:
        characters += string.ascii_lowercase
    if numbers:
        characters += string.digits
    if type == "password" or has_special_chars:  # noqa: A002
        characters += string.punctuation

    characters = "".join(c for c in characters if c not in exclude_characters)

    if not characters:
        raise ValueError("No valid characters left to generate a string.")

    special_chars = set(string.punctuation) - set(exclude_characters)
    output: str | None = None
    while (
        output is None
        or len(output) < length
        or (must_has_special_chars and not any(c in special_chars for c in output))
    ):
        try:
            result = subprocess.run(
                [
                    "openssl",
                    "rand",
                    "-base64",
                    str(length * 2),
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            output = "".join(c for c in result.stdout if c in characters)[:length]
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            logger.warning(
                "openssl unavailable, falling back to secrets module",
                data={"error": str(e)},
            )
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
    """Execute a shell command and return its stdout. Only available with --allow-shell."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.rstrip("\n")
    except subprocess.CalledProcessError as e:
        logger.error(
            "shell() command failed",
            data={"returncode": e.returncode, "stderr": e.stderr},
        )
        return None


def render_template(template_content: str, password: str | None, allow_shell: bool = False):
    env: Environment = Environment(loader=SafeFileSystemLoader("."))
    env.globals["get_secret"] = get_secret  # pyright: ignore [reportArgumentType]
    env.globals["import_env"] = import_env  # pyright:ignore [reportArgumentType]
    env.globals["random"] = generate_random_string  # pyright:ignore [reportArgumentType]
    decrypt_func = partial(decrypt, password=password)
    env.globals["decrypt"] = decrypt_func  # pyright:ignore [reportArgumentType]
    encrypt_func = partial(encrypt, password=password)
    env.globals["encrypt"] = encrypt_func  # pyright:ignore [reportArgumentType]
    if allow_shell:
        env.globals["shell"] = shell  # pyright:ignore [reportArgumentType]

    template = env.from_string(template_content)
    return template.render()


def read_input(file_path: str):
    """Reads input from a file."""
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def read_stdin():
    """Reads input from stdin if data is available."""
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return None


class Args(TypedDict):
    subcommand: str
    password: str | None
    input: str | None
    file: str | None
    output: str | None
    debug: bool
    allow_shell: bool


def generate_commands() -> Args:
    parser = argparse.ArgumentParser(description="Render Jinja template with secrets.")
    _ = parser.add_argument("-d", "--debug", help="Debug mode", action="store_true")
    subparsers = parser.add_subparsers(help="subcommand help", dest="subcommand")
    _ = subparsers.add_parser("version", help="Print version")

    generate_cmd = subparsers.add_parser("generate", help="Generate file from template")
    _ = generate_cmd.add_argument(
        "-f", "--file", help="Path to the Jinja template.", default=None
    )
    _ = generate_cmd.add_argument(
        "-i", "--input", help="Template content string (overrides -f).", default=None
    )
    _ = generate_cmd.add_argument(
        "-o", "--output", help="Path to the output file.", default=None
    )
    _ = generate_cmd.add_argument(
        "-p",
        "--password",
        help="Password for decrypt (insecure: visible in process list; prefer TEMV_BASIC_PASSWORD env var).",
        default=None,
    )
    _ = generate_cmd.add_argument(
        "--allow-shell",
        help=(
            "Enable the shell() template function. "
            "Executes arbitrary OS commands — only use with trusted templates."
        ),
        action="store_true",
        default=False,
    )

    encrypt_cmd = subparsers.add_parser("encrypt", help="Encrypt input file or text")
    _ = encrypt_cmd.add_argument(
        "-p",
        "--password",
        help="Password (insecure: visible in process list; prefer TEMV_BASIC_PASSWORD env var).",
        default=None,
    )
    _ = encrypt_cmd.add_argument("-i", "--input", help="Input")
    _ = encrypt_cmd.add_argument("-f", "--file", help="File")
    _ = encrypt_cmd.add_argument("-o", "--output", help="Directory")

    decrypt_cmd = subparsers.add_parser("decrypt", help="Decrypt input file or text")
    _ = decrypt_cmd.add_argument(
        "-p",
        "--password",
        help="Password (insecure: visible in process list; prefer TEMV_BASIC_PASSWORD env var).",
        default=None,
    )
    _ = decrypt_cmd.add_argument("-i", "--input", help="Input")
    _ = decrypt_cmd.add_argument("-f", "--file", help="File")
    _ = decrypt_cmd.add_argument("-o", "--output", help="Directory")

    args: Args = vars(parser.parse_args())  #pyright: ignore[reportAssignmentType]
    return args


def main():
    args = generate_commands()
    input_content: str | None = None
    if "input" in args and args["input"] is not None:
        input_content = args["input"]
    elif "file" in args and args["file"] is not None:
        try:
            with open(args["file"], "r") as f:
                input_content = "".join(f.readlines())
        except FileNotFoundError:
            logger.error(f"File not found: {args['file']}")
            sys.exit(1)
        except PermissionError:
            logger.error(f"Permission denied reading file: {args['file']}")
            sys.exit(1)
    else:
        input_content = read_stdin()
    if args["debug"]:
        logger.logger.setLevel(logging.DEBUG)
    content: str | None = None
    match args.get("subcommand", None):
        case "version":
            import importlib.metadata

            print(importlib.metadata.version("secret_template_renderer"))
        case "generate":
            load_plugins("secrets")
            load_plugins("encryptions")
            if input_content:
                content = render_template(
                    input_content,
                    args.get("password", None),
                    allow_shell=args.get("allow_shell", False),
                )
        case "encrypt":
            load_plugins("encryptions")
            if input_content:
                content = providers["encryptions"]["basic"]["encrypt"](
                    input_content, args.get("password", None)
                )
        case "decrypt":
            load_plugins("encryptions")
            if input_content:
                content = providers["encryptions"]["basic"]["decrypt"](
                    input_content, args.get("password", None)
                )
        case _:
            pass
    if content is not None:
        if output := args.get("output", None):
            with open(output, "w") as f:
                _ = f.write(content)
        else:
            print(content)


if __name__ == "__main__":
    main()
