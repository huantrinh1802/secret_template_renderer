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
