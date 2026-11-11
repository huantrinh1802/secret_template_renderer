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
    monkeypatch.delenv("TEMV_AGE_IDENTITY", raising=False)
    monkeypatch.delenv("TEMV_AGE_RECIPIENT", raising=False)


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


def test_register():
    registry: dict = {}
    age.register(registry)
    assert set(registry["age"]) == {"encrypt", "decrypt"}
