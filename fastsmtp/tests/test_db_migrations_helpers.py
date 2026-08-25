"""Tests for locating the migrations and comparing the database against the code."""

from pathlib import Path

import pytest
from fastsmtp.db.migrations import (
    SchemaRevisionError,
    alembic_config,
    alembic_script_location,
    current_db_revision,
    expected_head_revision,
    verify_schema_is_current,
)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine


class TestAlembicDiscovery:
    """The migration CLI is the documented upgrade path; it has to find its scripts."""

    def test_script_location_holds_the_versions(self):
        """The script directory must be absolute: a relative ``script_location``
        is resolved by Alembic against the CWD, which is the caller's."""
        location = alembic_script_location()
        assert location.is_absolute()
        assert (location / "versions").is_dir()

    def test_scripts_live_inside_the_package(self):
        """What makes them survive a wheel build, and what lets the path be
        derived from ``__file__`` instead of by walking three directories up -
        a contract that held in a checkout and in the image, and resolved to
        nowhere from site-packages.
        """
        import fastsmtp

        package_root = Path(fastsmtp.__file__).resolve().parent
        assert alembic_script_location().parent == package_root

    def test_the_config_needs_no_ini_file(self):
        """alembic.ini is gone: the config is built in code, so nothing has to
        be located on disk beside the package."""
        assert alembic_config().config_file_name is None
        assert alembic_config().get_main_option("script_location") == str(alembic_script_location())

    def test_expected_head_is_the_newest_migration(self):
        """The head comes from the shipped scripts, not a hardcoded string."""
        assert expected_head_revision() == "008"


class TestSchemaVerification:
    """Startup must refuse a database older than the code that connects to it."""

    async def _engine(self, tmp_path):
        return create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/schema.db")

    @pytest.mark.asyncio
    async def test_unmanaged_database_reports_no_revision(self, tmp_path):
        """A database with no alembic_version table (create_all, or brand new)."""
        engine = await self._engine(tmp_path)
        try:
            assert await current_db_revision(engine) is None
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_matching_revision_passes(self, tmp_path):
        engine = await self._engine(tmp_path)
        try:
            await self._stamp(engine, expected_head_revision())
            await verify_schema_is_current(engine)
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_stale_revision_raises_naming_both_ends(self, tmp_path):
        """The production shape that motivated the check: a database behind the head."""
        engine = await self._engine(tmp_path)
        try:
            await self._stamp(engine, "003")
            with pytest.raises(SchemaRevisionError) as exc_info:
                await verify_schema_is_current(engine)
        finally:
            await engine.dispose()

        message = str(exc_info.value)
        assert "003" in message
        assert expected_head_revision() in message
        assert "fastsmtp db upgrade head" in message

    @pytest.mark.asyncio
    async def test_newer_revision_is_tolerated(self, tmp_path):
        """A rolling deploy migrates before the old pods are gone; that is normal
        and must not take the old pods down."""
        engine = await self._engine(tmp_path)
        try:
            await self._stamp(engine, "999")
            await verify_schema_is_current(engine)
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_unmanaged_database_is_tolerated(self, tmp_path):
        """create_all-built databases (the test suite's own) have no revision."""
        engine = await self._engine(tmp_path)
        try:
            await verify_schema_is_current(engine)
        finally:
            await engine.dispose()

    @staticmethod
    async def _stamp(engine, revision: str) -> None:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32))"))
            await conn.execute(text("INSERT INTO alembic_version VALUES (:r)"), {"r": revision})
