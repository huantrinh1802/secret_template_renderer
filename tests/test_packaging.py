import pathlib
import shutil
import subprocess
import zipfile

import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("uv") is None or shutil.which("git") is None,
    reason="uv and git required",
)

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGINS = [
    "src/plugins/encryptions/age.py",
    "src/plugins/encryptions/basic.py",
    "src/plugins/secrets/1password.py",
    "src/plugins/secrets/bitwarden.py",
    "src/plugins/secrets/pass.py",
]


def test_wheel_ships_plugins(tmp_path):
    """Plugins are discovered by file glob at runtime, so they must be in the wheel."""
    # Build from tracked files only: stale egg-info/build dirs can mask missing packages.
    src = tmp_path / "src_copy"
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout.decode().split("\0")
    for name in filter(None, tracked):
        if (ROOT / name).is_file():
            (src / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, src / name)
    out = tmp_path / "out"
    subprocess.run(["uv", "build", "--wheel", "-o", str(out)], cwd=src, check=True, capture_output=True)
    names = set(zipfile.ZipFile(next(out.glob("*.whl"))).namelist())
    assert set(PLUGINS) <= names
