import json
from unittest.mock import MagicMock, patch

from src.plugins.secrets.bitwarden import get_bitwarden_secret

ITEM = {
    "id": "abc123",
    "name": "my-item",
    "fields": [
        {"name": "api-key", "value": "s3cr3t"},
        {"name": "other", "value": "other-val"},
    ],
    "login": {
        "username": "admin",
        "password": "hunter2",
    },
}


def _run_ok(data=ITEM):
    m = MagicMock()
    m.stdout = json.dumps(data)
    m.returncode = 0
    return m


def _run_fail():
    m = MagicMock()
    m.stdout = ""
    m.returncode = 1
    return m


@patch("src.plugins.secrets.bitwarden.subprocess.run")
def test_field_path(mock_run):
    mock_run.return_value = _run_ok()
    assert get_bitwarden_secret("my-item", "field.api-key") == "s3cr3t"


@patch("src.plugins.secrets.bitwarden.subprocess.run")
def test_login_username(mock_run):
    mock_run.return_value = _run_ok()
    assert get_bitwarden_secret("my-item", "login.username") == "admin"


@patch("src.plugins.secrets.bitwarden.subprocess.run")
def test_login_password(mock_run):
    mock_run.return_value = _run_ok()
    assert get_bitwarden_secret("my-item", "login.password") == "hunter2"


@patch("src.plugins.secrets.bitwarden.subprocess.run")
def test_no_path_returns_raw_json(mock_run):
    mock_run.return_value = _run_ok()
    result = get_bitwarden_secret("my-item", "")
    assert result == json.dumps(ITEM).strip()


@patch("src.plugins.secrets.bitwarden.subprocess.run")
def test_nonzero_returncode_returns_none(mock_run):
    mock_run.return_value = _run_fail()
    assert get_bitwarden_secret("my-item", "field.api-key") is None


@patch("src.plugins.secrets.bitwarden.subprocess.run")
def test_invalid_json_returns_none(mock_run):
    m = MagicMock()
    m.stdout = "not-json"
    m.returncode = 0
    mock_run.return_value = m
    assert get_bitwarden_secret("my-item", "field.api-key") is None


@patch("src.plugins.secrets.bitwarden.subprocess.run")
def test_dotless_path_returns_none(mock_run):
    mock_run.return_value = _run_ok()
    assert get_bitwarden_secret("my-item", "nodot") is None


@patch("src.plugins.secrets.bitwarden.subprocess.run")
def test_unknown_type_returns_none(mock_run):
    mock_run.return_value = _run_ok()
    assert get_bitwarden_secret("my-item", "notes.something") is None


@patch("src.plugins.secrets.bitwarden.subprocess.run")
def test_field_not_found_returns_none(mock_run):
    mock_run.return_value = _run_ok()
    assert get_bitwarden_secret("my-item", "field.nonexistent") is None


@patch("src.plugins.secrets.bitwarden.subprocess.run")
def test_no_shell_injection(mock_run):
    """Shell metacharacters in item_name must not reach a shell."""
    mock_run.return_value = _run_fail()
    malicious = '"; rm -rf / #'
    get_bitwarden_secret(malicious, "field.x")
    call_args = mock_run.call_args[0][0]
    assert call_args == ["bw", "get", "item", malicious]
    assert mock_run.call_args[1].get("shell", False) is False
