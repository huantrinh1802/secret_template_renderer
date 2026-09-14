import os
import pathlib
from unittest.mock import patch

import pytest

from src.app import detect_shell, generate_session_code

RENDERED = "[default]\naws_access_key_id = AKIA...\naws_secret_access_key = secret\n"


def _extract_path_bash(code: str) -> str:
    for line in code.splitlines():
        if line.startswith("export "):
            return line.split("=", 1)[1]
    pytest.fail("No export line found")


def _extract_path_fish(code: str) -> str:
    for line in code.splitlines():
        if line.startswith("set -x "):
            # "set -x VAR /path" → 4 tokens
            return line.split(" ", 3)[3]
    pytest.fail("No set -x line found")


class TestDetectShell:
    def test_fish(self, monkeypatch):
        monkeypatch.setenv("SHELL", "/opt/homebrew/bin/fish")
        assert detect_shell() == "fish"

    def test_bash(self, monkeypatch):
        monkeypatch.setenv("SHELL", "/bin/bash")
        assert detect_shell() == "bash"

    def test_zsh(self, monkeypatch):
        monkeypatch.setenv("SHELL", "/bin/zsh")
        assert detect_shell() == "zsh"

    def test_unknown_defaults_to_bash(self, monkeypatch):
        monkeypatch.setenv("SHELL", "/bin/sh")
        assert detect_shell() == "bash"

    def test_missing_defaults_to_bash(self, monkeypatch):
        monkeypatch.delenv("SHELL", raising=False)
        assert detect_shell() == "bash"


class TestGenerateSessionCode:
    @pytest.fixture(autouse=True)
    def patch_render(self):
        with patch("src.app.render_template", return_value=RENDERED):
            yield

    def test_creates_temp_file_with_rendered_content(self):
        code = generate_session_code("tmpl", "MY_VAR", "bash", None)
        tmp_path = _extract_path_bash(code)
        assert pathlib.Path(tmp_path).read_text() == RENDERED
        os.unlink(tmp_path)

    def test_temp_file_permissions_are_600(self):
        code = generate_session_code("tmpl", "MY_VAR", "bash", None)
        tmp_path = _extract_path_bash(code)
        mode = oct(pathlib.Path(tmp_path).stat().st_mode)[-3:]
        assert mode == "600"
        os.unlink(tmp_path)

    def test_temp_file_has_temv_prefix(self):
        code = generate_session_code("tmpl", "MY_VAR", "bash", None)
        tmp_path = _extract_path_bash(code)
        assert pathlib.Path(tmp_path).name.startswith("temv-")
        os.unlink(tmp_path)

    # --- bash ---

    def test_bash_exports_env_var(self):
        code = generate_session_code("tmpl", "AWS_SHARED_CREDENTIALS_FILE", "bash", None)
        tmp_path = _extract_path_bash(code)
        assert f"export AWS_SHARED_CREDENTIALS_FILE={tmp_path}" in code
        os.unlink(tmp_path)

    def test_bash_trap_deletes_file(self):
        code = generate_session_code("tmpl", "MY_VAR", "bash", None)
        tmp_path = _extract_path_bash(code)
        assert f"rm -f {tmp_path}" in code
        assert "unset MY_VAR" in code
        assert "trap" in code
        os.unlink(tmp_path)

    # --- fish ---

    def test_fish_sets_env_var(self):
        code = generate_session_code("tmpl", "AWS_SHARED_CREDENTIALS_FILE", "fish", None)
        tmp_path = _extract_path_fish(code)
        assert f"set -x AWS_SHARED_CREDENTIALS_FILE {tmp_path}" in code
        os.unlink(tmp_path)

    def test_fish_registers_exit_handler(self):
        code = generate_session_code("tmpl", "MY_VAR", "fish", None)
        tmp_path = _extract_path_fish(code)
        assert "--on-event fish_exit" in code
        assert f"rm -f {tmp_path}" in code
        assert "set -e MY_VAR" in code
        os.unlink(tmp_path)

    def test_fish_handler_name_is_unique_per_session(self):
        code1 = generate_session_code("tmpl", "MY_VAR", "fish", None)
        code2 = generate_session_code("tmpl", "MY_VAR", "fish", None)
        p1 = _extract_path_fish(code1)
        p2 = _extract_path_fish(code2)
        # Each session gets a distinct cleanup function derived from its temp path
        func1 = next(line for line in code1.splitlines() if line.startswith("function "))
        func2 = next(line for line in code2.splitlines() if line.startswith("function "))
        assert func1 != func2
        os.unlink(p1)
        os.unlink(p2)

    # --- zsh ---

    def test_zsh_uses_export_and_trap(self):
        code = generate_session_code("tmpl", "MY_VAR", "zsh", None)
        tmp_path = _extract_path_bash(code)  # same format as bash
        assert "export MY_VAR=" in code
        assert "trap" in code
        os.unlink(tmp_path)
