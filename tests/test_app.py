import string

import pytest

from src.app import generate_random_string, import_env


class TestGenerateRandomString:
    def test_default_length(self):
        assert len(generate_random_string()) == 16

    def test_custom_length(self):
        assert len(generate_random_string(length=32)) == 32

    def test_length_zero_raises(self):
        with pytest.raises(ValueError):
            generate_random_string(length=0)

    def test_length_negative_raises(self):
        with pytest.raises(ValueError):
            generate_random_string(length=-1)

    def test_length_too_large_raises(self):
        with pytest.raises(ValueError):
            generate_random_string(length=5000)

    def test_must_has_special_chars_is_enforced(self):
        for _ in range(10):
            result = generate_random_string(
                length=32, has_special_chars=True, must_has_special_chars=True
            )
            assert any(c in string.punctuation for c in result), (
                f"No special char found in: {result!r}"
            )

    def test_must_has_special_chars_without_flag_raises(self):
        with pytest.raises(ValueError):
            generate_random_string(has_special_chars=False, must_has_special_chars=True)

    def test_exclude_characters(self):
        result = generate_random_string(length=64, exclude_characters="0123456789")
        assert not any(c.isdigit() for c in result)

    def test_no_special_chars_by_default(self):
        for _ in range(5):
            result = generate_random_string(length=64)
            assert not any(c in string.punctuation for c in result)

    def test_password_type_allows_special_chars(self):
        allowed = set(string.ascii_lowercase + string.digits + string.punctuation)
        result = generate_random_string(length=64, type="password")
        assert set(result).issubset(allowed)

    def test_no_valid_chars_raises(self):
        with pytest.raises(ValueError, match="No valid characters"):
            generate_random_string(
                length=8,
                lower_case=False,
                numbers=False,
                has_special_chars=False,
            )


class TestImportEnv:
    def test_reads_file_in_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        env_file = tmp_path / ".env"
        env_file.write_text("KEY=VALUE\nFOO=BAR")
        assert import_env(str(env_file)) == "KEY=VALUE\nFOO=BAR"

    def test_strips_trailing_newline(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        env_file = tmp_path / ".env"
        env_file.write_text("KEY=VALUE\n")
        assert import_env(str(env_file)) == "KEY=VALUE"

    def test_rejects_absolute_path_outside_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ValueError, match="outside working directory"):
            import_env("/etc/passwd")

    def test_rejects_path_traversal(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ValueError, match="outside working directory"):
            import_env("../../../etc/passwd")


class TestExitCodes:
    def _run(self, monkeypatch, *argv):
        from src import app

        monkeypatch.setattr("sys.argv", ["str", *argv])
        monkeypatch.setattr("sys.stdin", __import__("io").StringIO(""))
        app.main()

    def test_decrypt_wrong_password_exits_nonzero(self, monkeypatch):
        from src.plugins.encryptions.basic import encrypt

        enc = encrypt("v", "right")
        with pytest.raises(SystemExit) as exc:
            self._run(monkeypatch, "decrypt", "-p", "wrong", "-i", enc)
        assert exc.value.code == 1

    def test_age_encrypt_without_recipient_exits_nonzero(self, monkeypatch):
        for name in ("STR_AGE_IDENTITY", "STR_AGE_IDENTITY_SECRET", "STR_AGE_RECIPIENT", "STR_AGE_SSH_AGENT", "STR_AGE_PASSPHRASE", "STR_AGE_MODE"):
            monkeypatch.delenv(name, raising=False)
        with pytest.raises(SystemExit) as exc:
            self._run(monkeypatch, "encrypt", "-e", "age", "-i", "x")
        assert exc.value.code == 1

    def test_success_does_not_exit(self, monkeypatch, capsys):
        self._run(monkeypatch, "encrypt", "-p", "pw", "-i", "x")
        assert capsys.readouterr().out.startswith("v2:")


class TestFailClosed:
    def _run(self, monkeypatch, *argv, stdin=""):
        import io

        from src import app

        monkeypatch.setattr("sys.argv", ["str", *argv])
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
        app.main()

    def test_failed_decrypt_in_template_exits_nonzero_and_writes_nothing(self, monkeypatch, tmp_path, capsys):
        from src.plugins.encryptions.basic import encrypt

        enc = encrypt("v", "right")
        out = tmp_path / "out.env"
        with pytest.raises(SystemExit) as exc:
            self._run(monkeypatch, "generate", "-p", "wrong", "-o", str(out), "-i", f"DB={{{{ decrypt('{enc}') }}}}")
        assert exc.value.code == 1
        assert not out.exists()
        assert "None" not in capsys.readouterr().out

    def test_failed_decrypt_in_session_exits_nonzero(self, monkeypatch):
        from src.plugins.encryptions.basic import encrypt

        enc = encrypt("v", "right")
        with pytest.raises(SystemExit) as exc:
            self._run(monkeypatch, "session", "--env", "X", "-p", "wrong", "-i", f"{{{{ decrypt('{enc}') }}}}")
        assert exc.value.code == 1

    def test_successful_decrypt_in_template(self, monkeypatch, capsys):
        from src.plugins.encryptions.basic import encrypt

        enc = encrypt("v", "right")
        self._run(monkeypatch, "generate", "-p", "right", "-i", f"DB={{{{ decrypt('{enc}') }}}}")
        assert capsys.readouterr().out.strip() == "DB=v"


class TestPrivateOutput:
    def test_output_is_mode_0600_even_with_open_umask(self, tmp_path):
        import os

        from src.app import write_private

        old = os.umask(0o022)
        try:
            path = tmp_path / "out.env"
            write_private(str(path), "SECRET=1\n")
        finally:
            os.umask(old)
        assert path.read_text() == "SECRET=1\n"
        assert (path.stat().st_mode & 0o777) == 0o600

    def test_existing_permissive_file_is_tightened(self, tmp_path):
        from src.app import write_private

        path = tmp_path / "out.env"
        path.write_text("old")
        path.chmod(0o644)
        write_private(str(path), "new")
        assert path.read_text() == "new"
        assert (path.stat().st_mode & 0o777) == 0o600
