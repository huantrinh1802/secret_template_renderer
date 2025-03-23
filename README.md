# Secret Template Renderer

This project is a Jinja template renderer that supports fetching secrets from various providers.

## Features

- Load built-in and user-defined plugins to extend the functionality
- Register multiple secret providers
- Render Jinja templates with secrets

## Installation

### Using pip

1. Clone the repository
2. Install the required dependencies

   ```bash
   pip install -r requirements.txt
   ```

### Using pipx

```bash
pipx install secret_template_renderer

```

## Usage

### Template Utilities

- `import_env`: import dotenv file
- `get_secret`:  retrieve secret via secret providers
- `shell`: execute shell command
- `random`: generate a random string with the following parameters:
  - length: int = 16,
  - type: string | password = 'string',
  - lower_case: bool = True,
  - numbers: bool = True,
  - has_special_chars: bool = False,
  - must_has_special_chars: bool = False,
  - exclude_characters: str = "",

### Command Line Interface

- `-d`, `--debug`: Enable debug mode

#### Generate

```bash
str generate [-f <template_path>] [-o <output_path>] [-i <input_string>] [-p <password>]
```

- `-f`, `--file`: Path to the Jinja template file
- `-o`, `--output`:   Path to the output file
- `-i`, `--input`:   Input string to be rendered
- `-p`, `--password`:   Password to be used for encryption

#### Encryption

```bash
str encrypt|decrypt [-f <template_path>] [-o <output_path>] [-i <input_string>] [-p <password>]
```

- `-f`, `--file`: Path to the Jinja template file
- `-o`, `--output`:   Path to the output file
- `-i`, `--input`:   Input string to be rendered
- `-p`, `--password`:   Password to be used for encryption

### Example

```dotenv

{{ import_env('.default.env') }} # Importing another dotenv file
DATABASE_PWD={{ get_secret('bitwarden', 'database_system_a', 'login.password') }} # Use the bitwarden plugins to load Bitwarden
NAME=app-{{ random(10) }} # Generate the randomised strings
PWD={{ decrypt("SfB505whBisKznrdHKLvQ0hhaESDP0MqvWFsYNkI0to=", "password") }}
UID={{ shell('echo $UID') }}

```

## Custom plugins

To load custom plugins, place your plugin `.py` files in `~/.config/temv/plugins/[plugin_type]/[plugin_name]`. Currently, there are 2 plugins: `secrets` and `encryptions`.

Each plugin must have a `register` function that takes a dictionary of secret providers as an argument.

Secret example:

```python
import subprocess
from collections.abc import Callable


def get_custom_secret(item_name: str, path: str) -> str | None:
    pass


def register(secrets_providers: dict[str, Callable[[str, str], str | None]]):
    """Register secret provider."""
    secrets_providers["custom_provider"] = get_custom_secret
```

Encryption example:

```python
import subprocess
from collections.abc import Callable


def encrypt(value: str, password: str) -> str | None:
    pass


def decrypt(value: str, password: str) -> str | None:
    pass


def register(providers: dict[str, Callable[[str, str], str | None]]):
    """Register encryption provider."""
    providers["custom_provider"] = {"encrypt": encrypt, "decrypt": decrypt}
```

## License

This project is licensed under the MIT License.
