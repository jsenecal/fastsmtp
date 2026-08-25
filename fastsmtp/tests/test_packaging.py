"""What the built distributions actually contain.

Two things this repo ships are invisible to every other test: the migration
scripts and the license. Both are decided by ``[tool.hatch.build]`` and by
where a file sits on disk, not by anything Python imports, so a config change
that drops them fails nothing and is noticed by whoever pip-installs next.

Before the migrations moved into the package they were exactly that failure:
``alembic/`` sat beside ``src/``, outside the wheel's ``packages``, so a
pip-installed server had no migrations at all - ``fastsmtp db upgrade head``
could not run and startup could not check the schema.

``uv build`` builds the sdist and then the wheel *from* that sdist, so these
also cover an sdist that omits what the wheel needs.

Marked ``packaging``: each build takes tens of seconds and needs the network
for the build backend. Deselect locally with ``-m "not packaging"``; CI runs
the suite unfiltered.
"""

import subprocess
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.packaging

REPO_ROOT = Path(__file__).resolve().parents[2]


def build(package: str, into: Path) -> zipfile.ZipFile:
    """Build ``package`` and return its wheel, failing with the build output."""
    result = subprocess.run(
        ["uv", "build", "--package", package, "-o", str(into)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"uv build --package {package} exited {result.returncode}\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )
    wheels = sorted(into.glob("*.whl"))
    assert len(wheels) == 1, f"expected one wheel, got {[w.name for w in wheels]}"
    return zipfile.ZipFile(wheels[0])


@pytest.fixture(scope="module")
def server_wheel(tmp_path_factory: pytest.TempPathFactory) -> zipfile.ZipFile:
    return build("fastsmtp", tmp_path_factory.mktemp("server-dist"))


@pytest.fixture(scope="module")
def cli_wheel(tmp_path_factory: pytest.TempPathFactory) -> zipfile.ZipFile:
    return build("fastsmtp-cli", tmp_path_factory.mktemp("cli-dist"))


def test_server_wheel_ships_the_migrations(server_wheel: zipfile.ZipFile) -> None:
    """Every revision on disk has to be in the wheel, not just the directory."""
    from fastsmtp.db.migrations import alembic_script_location

    on_disk = {path.name for path in (alembic_script_location() / "versions").glob("*.py")}
    in_wheel = {
        Path(name).name
        for name in server_wheel.namelist()
        if name.startswith("fastsmtp/alembic/versions/") and name.endswith(".py")
    }

    assert on_disk, "no migration scripts found on disk; the location is wrong"
    assert in_wheel == on_disk


def test_server_wheel_ships_the_alembic_environment(server_wheel: zipfile.ZipFile) -> None:
    """``env.py`` drives every migration and ``script.py.mako`` is what
    ``db revision`` renders; neither is a Python module hatchling would pick up
    on its own."""
    names = set(server_wheel.namelist())
    assert "fastsmtp/alembic/env.py" in names
    assert "fastsmtp/alembic/script.py.mako" in names


def test_the_wheels_carry_the_license(
    server_wheel: zipfile.ZipFile, cli_wheel: zipfile.ZipFile
) -> None:
    """Both wheels shipped with no license at all before #111."""
    for wheel in (server_wheel, cli_wheel):
        licenses = [name for name in wheel.namelist() if "dist-info/licenses/" in name]
        assert licenses, f"{Path(wheel.filename or '?').name} ships no license file"
