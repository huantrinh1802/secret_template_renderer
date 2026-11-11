# STR - Secret Template Renderer

Render Jinja2 templates with secrets injected from password managers and other providers. Supports encrypting values inline, generating ephemeral credential files, and loading custom plugins.

## Installation

```bash
pipx install secret_template_renderer
```

Or with the optional encryption support (AES-256-GCM):

```bash
pipx install "secret_template_renderer[crypto]"
```

## Quick start

```dotenv
# aws-creds.tmpl
[default]
aws_access_key_id={{ get_secret('bitwarden', 'aws-prod', 'field.access_key_id') }}
aws_secret_access_key={{ get_secret('bitwarden', 'aws-prod', 'field.secret_access_key') }}
```

```bash
str generate -f aws-creds.tmpl -o ~/.aws/credentials
```

## Commands

### `generate` — render a template

```bash
str generate -f <template> [-i <string>] [-o <output>] [-p <password>] [--allow-shell]
```

| Flag | Description |
|------|-------------|
| `-f`, `--file` | Path to the Jinja2 template file |
| `-i`, `--input` | Template content as a string (overrides `-f`) |
| `-o`, `--output` | Output file path (default: stdout) |
| `-p`, `--password` | Password for `decrypt()`/`encrypt()` — prefer `STR_BASIC_PASSWORD` env var; `-p` is visible in `ps aux` |
| `--allow-shell` | Enable the `shell()` template function (see [Security](#security)) |

Template content can also be piped via stdin:

```bash
cat template.tmpl | str generate
```

---

### `session` — ephemeral credential files

Renders a template to a temp file and prints shell code that exports its path as an environment variable and deletes the file on shell exit. No secrets persist after the session ends.

```bash
# fish
eval (str session -f aws-creds.tmpl --env AWS_SHARED_CREDENTIALS_FILE)

# bash / zsh
eval "$(str session -f aws-creds.tmpl --env AWS_SHARED_CREDENTIALS_FILE)"
```

What gets printed (fish):

```fish
set -x AWS_SHARED_CREDENTIALS_FILE /tmp/temv-a3f9c2
function __temv_cleanup_temv_a3f9c2 --on-event fish_exit
    rm -f /tmp/temv-a3f9c2
    set -e AWS_SHARED_CREDENTIALS_FILE
end
```

What gets printed (bash/zsh):

```bash
export AWS_SHARED_CREDENTIALS_FILE=/tmp/temv-a3f9c2
trap 'rm -f /tmp/temv-a3f9c2; unset AWS_SHARED_CREDENTIALS_FILE' EXIT
```

| Flag | Description |
|------|-------------|
| `-f`, `--file` | Path to the Jinja2 template file |
| `-i`, `--input` | Template content as a string (overrides `-f`) |
| `--env` | Environment variable name to point at the rendered temp file **(required)** |
| `--shell` | Shell syntax to emit: `bash`, `zsh`, or `fish` (default: auto-detect from `$SHELL`) |
| `-p`, `--password` | Password for `decrypt()` — prefer `STR_BASIC_PASSWORD` env var |

The temp file is created with `0600` permissions under `/tmp` with a `temv-` prefix.

---

### `encrypt` / `decrypt` — manage inline secrets

```bash
str encrypt [-i <plaintext>] [-f <file>] [-o <output>] [-p <password>]
str decrypt [-i <ciphertext>] [-f <file>] [-o <output>] [-p <password>]
```

Encrypted values use AES-256-GCM (authenticated encryption) and are prefixed with `v2:`. Old AES-256-CBC values (no prefix) are still decryptable for backward compatibility.

The password is read from, in order:
1. `STR_BASIC_PASSWORD` environment variable
2. `-p` / `--password` flag (**avoid** — visible in `ps aux` and shell history)
3. Interactive prompt (up to 3 attempts)

The old `TEMV_BASIC_PASSWORD` and `TEMV_PLUGIN_DIR` names still work but log a deprecation warning.

#### `age` provider (key pairs, passphrase, SSH keys)

Select it with `-e age`. It uses the [`age`](https://age-encryption.org) and `age-keygen` binaries, which must be on `PATH`. Values are single-line `age:<base64>`; armored age files are accepted by `decrypt` too. In templates pass the provider as the second argument: `{{ decrypt("age:YWdl...", "age") }}`.

```bash
age-keygen -o ~/.config/str/key.txt
export STR_AGE_IDENTITY=~/.config/str/key.txt
str encrypt -e age -i "my secret"      # recipient defaults to the key derived from the identity
str decrypt -e age -i "age:<base64>"
```

| Flag | Env var | Purpose |
|------|---------|---------|
| `-e`, `--encryption` | | `basic` (default) or `age` |
| `--identity FILE` | `STR_AGE_IDENTITY` | age/SSH private key file (decrypt) |
| `-r`, `--recipient KEYS` | `STR_AGE_RECIPIENT` | Public key(s), comma-separated (encrypt) |
| `--identity-secret SPEC` | `STR_AGE_IDENTITY_SECRET` | Fetch the private key via a secrets provider, `provider:key[:path]`; kept in memory, never written to disk |
| `--ssh-agent [FILTER]` | `STR_AGE_SSH_AGENT` | Encrypt to the ed25519/rsa public keys held by the SSH agent; optional text filters by key comment |
| `--passphrase` | `STR_AGE_PASSPHRASE` | Passphrase mode (also `-p`); prompts if none given. Needs the optional `pyrage` extra: `pip install 'secret_template_renderer[age]'` |

`decrypt` reads the value's header to choose passphrase or key mode.

An SSH agent (1Password, Bitwarden, `ssh-agent`) never hands out private keys, so age can encrypt to the agent's public keys but cannot decrypt through the agent:

```bash
str encrypt -e age --ssh-agent "my-key-comment" -i "my secret"
str decrypt -e age --identity-secret "1password:Private/my ssh key/private key" -i "age:..."
str decrypt -e age --identity-secret "bitwarden:my ssh key:sshKey.privateKey" -i "age:..."
```

Tested with Ed25519 keys in the Bitwarden and 1Password SSH agents. If age rejects a 1Password key, append `?ssh-format=openssh` to the `op://` reference (not needed for the Ed25519 key tested; RSA untested). `provider:key[:path]` splits on colons, so vault/item names must not contain `:`.

---

## Template functions

### `get_secret(provider, item, path="")`

Fetch a secret from a configured provider.

```jinja
{{ get_secret('bitwarden', 'my-item', 'login.password') }}
{{ get_secret('1password', 'vault/item/field') }}
{{ get_secret('pass', 'email/personal') }}
```

**Bitwarden path format:** `login.<field>`, `field.<custom_field_name>` or `sshKey.privateKey` / `sshKey.publicKey` (SSH key items)

### `import_env(path)`

Read a `.env` file and embed its contents. The path must be within the current working directory.

```jinja
{{ import_env('.default.env') }}
```

### `decrypt(ciphertext, module="basic")` / `encrypt(plaintext, module="basic")`

Decrypt or encrypt a value inline. The password comes from `STR_BASIC_PASSWORD` or the `-p` flag passed to `generate`.

```jinja
DATABASE_PASSWORD={{ decrypt("v2:...") }}
```

### `random(length, type, ...)`

Generate a random string.

```jinja
{{ random(32) }}
{{ random(16, type="password") }}
{{ random(24, has_special_chars=True, must_has_special_chars=True) }}
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `length` | `16` | Length of the output (1–4096) |
| `type` | `"string"` | `"string"` or `"password"` (includes special chars) |
| `lower_case` | `True` | Include lowercase letters |
| `numbers` | `True` | Include digits |
| `has_special_chars` | `False` | Include punctuation |
| `must_has_special_chars` | `False` | Guarantee at least one special char (requires `has_special_chars=True`) |
| `exclude_characters` | `""` | Characters to exclude from the pool |

### `shell(command)` ⚠️

Execute a shell command and return its stdout. **Only available when `--allow-shell` is passed to `generate` or `session`.** See [Security](#security).

```jinja
{{ shell('aws sts get-caller-identity --query Account --output text') }}
```

---

## Security

### `shell()` is opt-in

`shell()` executes arbitrary OS commands and is **not registered by default**. Only enable it with `--allow-shell` when you fully trust the template source. Never use it with templates from untrusted repositories or generated configs.

### `import_env()` is sandboxed

`import_env()` only reads files within the current working directory. Paths outside CWD (including `..` traversals and absolute paths) are rejected.

### Encryption

Values encrypted with `str encrypt` use AES-256-GCM with a PBKDF2-SHA256 key (600,000 iterations). GCM provides authenticated encryption — any tampering causes decryption to fail rather than returning corrupted data.

---

## Custom plugins

Place plugin `.py` files in any of these locations:

| Location | Scope |
|----------|-------|
| `.temv/plugins/<type>/` | Project-local |
| `$STR_PLUGIN_DIR/<type>/` | User-global (env var) |

`<type>` is either `secrets` or `encryptions`.

### Secret plugin

```python
from collections.abc import Callable


def get_custom_secret(item_name: str, path: str) -> str | None:
    # return None on any failure — never return ""
    ...


def register(providers: dict[str, Callable[[str, str], str | None]]):
    providers["my_provider"] = get_custom_secret
```

Call it in templates as `{{ get_secret('my_provider', 'item', 'path') }}`.

### Encryption plugin

```python
from collections.abc import Callable


def encrypt(value: str, password: str | None) -> str | None:
    ...


def decrypt(value: str, password: str | None) -> str | None:
    ...


def register(providers: dict[str, dict[str, Callable]]):
    providers["my_enc"] = {"encrypt": encrypt, "decrypt": decrypt}
```

Call it in templates as `{{ decrypt("...", module="my_enc") }}`.

---

## License

MIT
