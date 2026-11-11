import shutil
import subprocess

import pytest

from src.plugins.encryptions import age

pytestmark = pytest.mark.skipif(
    shutil.which("age") is None or shutil.which("age-keygen") is None,
    reason="age binaries not installed",
)


@pytest.fixture
def keypair(tmp_path):
    identity = tmp_path / "key.txt"
    subprocess.run(["age-keygen", "-o", str(identity)], check=True, capture_output=True)
    public = subprocess.run(
        ["age-keygen", "-y", str(identity)], check=True, capture_output=True, text=True
    ).stdout.strip()
    return identity, public


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (
        "TEMV_AGE_IDENTITY",
        "TEMV_AGE_IDENTITY_SECRET",
        "TEMV_AGE_RECIPIENT",
        "TEMV_AGE_SSH_AGENT",
        "TEMV_AGE_PASSPHRASE",
        "TEMV_AGE_MODE",
    ):
        monkeypatch.delenv(name, raising=False)


class TestRoundtrip:
    def test_explicit_recipient(self, keypair, monkeypatch):
        identity, public = keypair
        monkeypatch.setenv("TEMV_AGE_IDENTITY", str(identity))
        monkeypatch.setenv("TEMV_AGE_RECIPIENT", public)
        enc = age.encrypt("my secret")
        assert enc is not None and enc.startswith("age:")
        assert "\n" not in enc
        assert age.decrypt(enc) == "my secret"

    def test_recipient_derived_from_identity(self, keypair, monkeypatch):
        identity, _ = keypair
        monkeypatch.setenv("TEMV_AGE_IDENTITY", str(identity))
        assert age.decrypt(age.encrypt("café ☕")) == "café ☕"

    def test_multiple_recipients(self, keypair, tmp_path, monkeypatch):
        identity, public = keypair
        other = tmp_path / "other.txt"
        subprocess.run(["age-keygen", "-o", str(other)], check=True, capture_output=True)
        other_pub = subprocess.run(
            ["age-keygen", "-y", str(other)], check=True, capture_output=True, text=True
        ).stdout.strip()
        monkeypatch.setenv("TEMV_AGE_RECIPIENT", f"{public}, {other_pub}")
        enc = age.encrypt("shared")
        for ident in (identity, other):
            monkeypatch.setenv("TEMV_AGE_IDENTITY", str(ident))
            assert age.decrypt(enc) == "shared"

    def test_armored_input(self, keypair, monkeypatch):
        identity, public = keypair
        monkeypatch.setenv("TEMV_AGE_IDENTITY", str(identity))
        armored = subprocess.run(
            ["age", "-a", "-r", public], input=b"armored", capture_output=True, check=True
        ).stdout.decode()
        assert age.decrypt(armored) == "armored"


class TestFailures:
    def test_wrong_identity_returns_none(self, keypair, tmp_path, monkeypatch):
        _, public = keypair
        monkeypatch.setenv("TEMV_AGE_RECIPIENT", public)
        enc = age.encrypt("secret")
        other = tmp_path / "other.txt"
        subprocess.run(["age-keygen", "-o", str(other)], check=True, capture_output=True)
        monkeypatch.setenv("TEMV_AGE_IDENTITY", str(other))
        assert age.decrypt(enc) is None

    def test_no_identity_returns_none(self):
        assert age.decrypt("age:AAAA") is None

    def test_no_recipient_or_identity_returns_none(self):
        assert age.encrypt("x") is None

    def test_malformed_value_returns_none(self, keypair, monkeypatch):
        identity, _ = keypair
        monkeypatch.setenv("TEMV_AGE_IDENTITY", str(identity))
        assert age.decrypt("age:!!!notbase64") is None
        assert age.decrypt("plain text") is None


class TestPassphrase:
    def test_roundtrip_with_password_arg(self):
        enc = age.encrypt("secret", "pw")
        assert enc.startswith("age:")
        assert age.decrypt(enc, "pw") == "secret"

    def test_roundtrip_via_env(self, monkeypatch):
        monkeypatch.setenv("TEMV_AGE_PASSPHRASE", "pw")
        assert age.decrypt(age.encrypt("café ☕")) == "café ☕"

    def test_wrong_passphrase_returns_none(self):
        assert age.decrypt(age.encrypt("secret", "right"), "wrong") is None

    def test_mode_without_passphrase_prompts(self, monkeypatch):
        monkeypatch.setenv("TEMV_AGE_MODE", "passphrase")
        monkeypatch.setattr(age, "getpass", lambda *_: "typed")
        enc = age.encrypt("secret")
        assert age.decrypt(enc, "typed") == "secret"

    def test_decrypt_routes_by_header(self, keypair, monkeypatch):
        identity, public = keypair
        monkeypatch.setenv("TEMV_AGE_IDENTITY", str(identity))
        monkeypatch.setenv("TEMV_AGE_RECIPIENT", public)
        assert age.decrypt(age.encrypt("by-key")) == "by-key"
        assert age.decrypt(age.encrypt("by-pass", "pw"), "pw") == "by-pass"


class TestSshKeys:
    @pytest.fixture
    def ssh_key(self, tmp_path):
        key = tmp_path / "id_ed25519"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "temv-test", "-f", str(key)],
            check=True,
        )
        return key, (tmp_path / "id_ed25519.pub").read_text().strip()

    @pytest.fixture
    def fake_agent(self, ssh_key, tmp_path, monkeypatch):
        """Put an ssh-add on PATH that lists the test key plus an unsupported one."""
        _, public = ssh_key
        script = tmp_path / "bin" / "ssh-add"
        script.parent.mkdir()
        script.write_text(f"#!/bin/sh\necho 'ecdsa-sha2-nistp256 AAAA other'\necho '{public}'\n")
        script.chmod(0o755)
        monkeypatch.setenv("PATH", f"{script.parent}:/usr/bin:/bin:/opt/homebrew/bin")

    def test_encrypt_to_agent_keys(self, ssh_key, fake_agent, monkeypatch):
        key, _ = ssh_key
        monkeypatch.setenv("TEMV_AGE_SSH_AGENT", "1")
        enc = age.encrypt("via-agent")
        monkeypatch.setenv("TEMV_AGE_IDENTITY", str(key))
        assert age.decrypt(enc) == "via-agent"

    def test_agent_filter_no_match(self, fake_agent, monkeypatch):
        monkeypatch.setenv("TEMV_AGE_SSH_AGENT", "nonexistent")
        assert age.encrypt("x") is None

    def test_identity_from_secret_provider(self, ssh_key, fake_agent, monkeypatch):
        from src import app

        key, _ = ssh_key
        monkeypatch.setenv("TEMV_AGE_SSH_AGENT", "temv-test")
        enc = age.encrypt("from-vault")
        calls = []

        def fake_get_secret(source, name, path=""):
            calls.append((source, name, path))
            return key.read_text()

        monkeypatch.setattr(app, "get_secret", fake_get_secret)
        monkeypatch.setattr(app, "load_plugins", lambda *_: None)
        monkeypatch.setenv("TEMV_AGE_IDENTITY_SECRET", "1password:Private/age key/private key")
        assert age.decrypt(enc) == "from-vault"
        assert calls == [("1password", "Private/age key/private key", "")]

    def test_malformed_identity_secret(self, monkeypatch):
        monkeypatch.setenv("TEMV_AGE_IDENTITY_SECRET", "nokey")
        assert age._identity() is None


def test_register():
    registry: dict = {}
    age.register(registry)
    assert set(registry["age"]) == {"encrypt", "decrypt"}
