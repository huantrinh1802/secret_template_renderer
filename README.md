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
pipx install temv

```

## Usage

```bash
python app.py -t <template_path> -o <output_path>
```

- `-t`, `--template`: Path to the Jinja template file
- `-o`, `--output`:   Path to the output file

## Custom Plugins

To load custom plugins, place your plugin `.py` files in `~/.config/temv/plugins/`.

Each plugin must have a `register` function that takes a dictionary of secret providers as an argument.

Example:

```python
import subprocess
from collections.abc import Callable


def get_custom_secret(item_name: str, path: str) -> str | None:
    pass


def register(secrets_providers: dict[str, Callable[[str, str], str | None]]):
    """Register the Bitwarden secret provider."""
    secrets_providers["custom_provider"] = get_custom_secret
```

## License

This project is licensed under the MIT License.
