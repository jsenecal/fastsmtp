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

import re
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


# --- The image built from ``Dockerfile`` (issue #142) -----------------------
#
# ``fastsmtp-cli`` was built and tested in CI but shipped in no artifact an
# operator running the published container could reach: the builder stage ran
# ``uv sync --frozen --no-dev --package fastsmtp`` (one package), and the
# runtime stage copied only ``fastsmtp/src`` from the builder. The venv never
# had ``fsmtp`` installed in it at all, so the container had no supported path
# to the API and an operator fell back to a hand-written SQL UPDATE.
#
# A full ``docker build`` needs a daemon and is too slow for this suite, so
# these tests parse ``Dockerfile`` itself and check the two properties that
# caused the gap: both workspace packages reach ``uv sync``, and both source
# trees are copied into the runtime stage. That is enough to catch a
# regression - e.g. someone reverting to a single ``--package`` flag, or
# adding a new workspace member and forgetting its runtime ``COPY`` - without
# needing to actually build the image.

_STAGE_HEADER_RE = re.compile(r"^FROM\s+\S+\s+AS\s+(\S+)", re.IGNORECASE)


def parse_dockerfile_stages(text: str) -> dict[str, list[str]]:
    """Split a Dockerfile into named build stages, each a list of its
    logical instruction lines (backslash line-continuations joined, blank
    lines and comments dropped).

    This is intentionally a small parser tailored to this repo's Dockerfile,
    not a general one: it only needs to answer "what RUN and COPY
    instructions does stage X have", which line-based regex handles fine.
    """
    logical_lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if logical_lines and logical_lines[-1].endswith("\\"):
            logical_lines[-1] = logical_lines[-1][:-1].rstrip() + " " + line.strip()
        else:
            logical_lines.append(line)

    stages: dict[str, list[str]] = {}
    current_stage: str | None = None
    for line in logical_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        header = _STAGE_HEADER_RE.match(stripped)
        if header:
            current_stage = header.group(1)
            stages[current_stage] = []
            continue
        if current_stage is not None:
            stages[current_stage].append(stripped)
    return stages


@pytest.fixture(scope="module")
def dockerfile_stages() -> dict[str, list[str]]:
    text = (REPO_ROOT / "Dockerfile").read_text()
    stages = parse_dockerfile_stages(text)
    assert "builder" in stages and "runtime" in stages, (
        f"expected 'builder' and 'runtime' stages in Dockerfile, found {sorted(stages)}\n"
        "the parser looks for lines shaped like 'FROM <image> AS <stage>'"
    )
    return stages


def test_image_builder_installs_both_workspace_packages(
    dockerfile_stages: dict[str, list[str]],
) -> None:
    """The builder stage must sync both ``fastsmtp`` and ``fastsmtp-cli``, or
    the CLI's console script (``fsmtp``) never exists in the venv at all."""
    sync_lines = [
        line
        for line in dockerfile_stages["builder"]
        if line.startswith("RUN") and "uv sync" in line
    ]
    assert sync_lines, "builder stage has no RUN instruction running `uv sync`"
    assert len(sync_lines) == 1, (
        f"expected exactly one `uv sync` instruction in the builder stage, found "
        f"{len(sync_lines)}: {sync_lines}"
    )
    sync_line = sync_lines[0]

    for package in ("fastsmtp", "fastsmtp-cli"):
        assert f"--package {package}" in sync_line, (
            f"builder's `uv sync` does not pass `--package {package}`:\n  {sync_line}\n"
            f"without it, {package}'s console scripts and dependencies are absent from "
            "the venv that ships in the image"
        )


def test_image_runtime_stage_copies_both_source_trees(
    dockerfile_stages: dict[str, list[str]],
) -> None:
    """Both workspace packages are installed editable (workspace members
    under ``uv sync``), so each one's ``src`` tree has to be copied into the
    runtime stage separately from the venv - copying the venv alone leaves an
    editable install pointing at source that was never brought over."""
    copy_lines = [line for line in dockerfile_stages["runtime"] if line.startswith("COPY")]
    assert any(".venv" in line for line in copy_lines), (
        f"runtime stage has no COPY bringing in the built .venv: {copy_lines}"
    )

    for src_tree in ("fastsmtp/src", "fastsmtp-cli/src"):
        assert any(src_tree in line for line in copy_lines), (
            f"runtime stage has no COPY instruction bringing in '{src_tree}'\n"
            f"COPY instructions found: {copy_lines}"
        )
