import importlib.util
import pathlib
from unittest.mock import MagicMock, patch


def _load(filename: str):
    p = pathlib.Path(__file__).parent.parent / "src" / "plugins" / "secrets" / filename
    spec = importlib.util.spec_from_file_location(p.stem, p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestPassPlugin:
    def setup_method(self):
        self.mod = _load("pass.py")

    @patch("subprocess.run")
    def test_success_returns_value(self, mock_run):
        mock_run.return_value = MagicMock(stdout="my-secret\n", returncode=0)
        assert self.mod.get_pass_secret("my/item", "") == "my-secret"

    @patch("subprocess.run")
    def test_failure_returns_none(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        assert self.mod.get_pass_secret("no/item", "") is None


class TestOnePasswordPlugin:
    def setup_method(self):
        self.mod = _load("1password.py")

    @patch("subprocess.run")
    def test_success_returns_value(self, mock_run):
        mock_run.return_value = MagicMock(stdout="secret-value\n", returncode=0)
        assert self.mod.get_1password_secret("vault/item/field") == "secret-value"

    @patch("subprocess.run")
    def test_failure_returns_none(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        assert self.mod.get_1password_secret("vault/missing/field") is None
