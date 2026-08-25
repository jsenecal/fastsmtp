"""Tests for the startup guard over encrypted rows and the key that can read them.

The asymmetric failure is the one worth catching: encryption is optional, so a
process with no key is perfectly normal - unless the database it connects to
already holds envelopes. In that state every read of the column raises deep
inside a SELECT, which turns a recipient listing into a 500 and leaves the
delivery worker unable to read the webhook auth headers it must send.

Every behavioural test here runs on both dialects. The predicate has to work
against JSONB on PostgreSQL and against JSON-stored-as-text on SQLite, and it
is written at the SQL level precisely so it never loads the ORM attribute; a
test on one dialect would prove neither half.
"""

import json
import logging
import uuid

import pytest
import pytest_asyncio
from fastsmtp.config import clear_settings_cache
from fastsmtp.crypto import ENVELOPE_MARKER
from fastsmtp.db.encryption_guard import (
    EncryptionKeyMissingError,
    verify_encryption_key_is_configured,
)
from fastsmtp.db.models import Base, Domain, Recipient
from fastsmtp.encryption import get_cipher
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

KEY = "operator-key-for-the-guard"

HEADERS = {"Authorization": "Bearer sk-live-0123456789abcdef"}


@pytest.fixture
def use_key(monkeypatch):
    """Return a helper that configures (or removes) the process encryption key.

    Goes through the environment and the settings cache rather than patching
    ``get_cipher``, so both callers of it - this guard and the column type that
    writes the envelopes - see the same key at the same time. That is what lets
    a test write a genuine envelope and then take the key away.
    """

    def _use(key: str | None) -> None:
        if key is None:
            monkeypatch.delenv("FASTSMTP_ENCRYPTION_KEYS", raising=False)
        else:
            monkeypatch.setenv("FASTSMTP_ENCRYPTION_KEYS", json.dumps([key]))
        clear_settings_cache()

    yield _use

    clear_settings_cache()


@pytest_asyncio.fixture
async def sqlite_engine(tmp_path):
    """A SQLite database with the real schema, where the column is JSON text."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/guard.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture(params=["sqlite", "postgresql"])
def guard_engine(request) -> AsyncEngine:
    """The same test body against both dialects.

    ``test_engine`` is the shared PostgreSQL fixture from conftest, where the
    column is JSONB; the SQLite one stores JSON as text. The detection query
    has to hold on both.
    """
    fixture = "sqlite_engine" if request.param == "sqlite" else "test_engine"
    engine = request.getfixturevalue(fixture)
    # Asserted rather than assumed: a parametrisation that quietly handed both
    # cases the same engine would still be green and would still prove nothing
    # about the dialect it claims to cover.
    assert engine.dialect.name == request.param
    return engine


async def _add_recipient(engine: AsyncEngine, headers: dict, local_part: str = "alerts") -> None:
    """Write one recipient through the ORM, so the column type decides the storage.

    Whether the row lands as an envelope or as plaintext is therefore whatever
    the currently configured key makes it - the same decision production makes.
    """
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        domain = Domain(id=uuid.uuid4(), domain_name=f"{uuid.uuid4().hex}.example.com")
        session.add(domain)
        await session.flush()
        session.add(
            Recipient(
                id=uuid.uuid4(),
                domain_id=domain.id,
                local_part=local_part,
                webhook_url="https://hooks.example.com/inbound",
                webhook_headers=headers,
            )
        )
        await session.commit()


async def _stored_headers_text(engine: AsyncEngine) -> str:
    """Every stored ``webhook_headers`` value as raw text, never through the ORM.

    Reading the attribute would run the decorator and decrypt (or raise); this
    asserts on what is actually on disk.
    """
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT CAST(webhook_headers AS TEXT) FROM recipients"))
        return "\n".join(str(row[0]) for row in result)


class TestNoEncryptedRows:
    """A deployment that never enabled encryption must start exactly as before."""

    async def test_empty_database_passes(self, guard_engine, use_key):
        """Test the guard is silent when there is nothing stored at all.

        The default state of a fresh install: no key, no rows, no reason to
        complain.
        """
        use_key(None)
        await verify_encryption_key_is_configured(guard_engine)

    async def test_plaintext_rows_pass(self, guard_engine, use_key):
        """Test rows written without a key do not trip the guard.

        They are readable by any process, with or without a key, so blocking
        startup on them would break every deployment that has not opted in.
        """
        use_key(None)
        await _add_recipient(guard_engine, HEADERS)
        assert ENVELOPE_MARKER not in await _stored_headers_text(guard_engine)

        await verify_encryption_key_is_configured(guard_engine)


class TestEncryptedRowsWithoutKey:
    """The failure the guard exists for: the data is encrypted, the process is not."""

    async def test_raises_naming_the_setting_and_the_table(self, guard_engine, use_key):
        """Test the message names the evidence and the remediation.

        An operator reading it at startup has to learn which table is affected
        and which setting to populate; without both, the next step is a guess.
        """
        use_key(KEY)
        await _add_recipient(guard_engine, HEADERS)
        assert ENVELOPE_MARKER in await _stored_headers_text(guard_engine)

        use_key(None)
        with pytest.raises(EncryptionKeyMissingError) as exc_info:
            await verify_encryption_key_is_configured(guard_engine)

        message = str(exc_info.value)
        assert "FASTSMTP_ENCRYPTION_KEYS" in message
        assert "recipients" in message
        assert "webhook_headers" in message

    async def test_detected_among_plaintext_rows(self, guard_engine, use_key):
        """Test one envelope is found in a table that is mostly plaintext.

        The state a half-finished rollout leaves behind: rows convert as they
        are rewritten, so the encrypted ones are a minority and are not the
        first row the query meets.
        """
        use_key(None)
        for index in range(3):
            await _add_recipient(guard_engine, HEADERS, local_part=f"plain-{index}")

        use_key(KEY)
        await _add_recipient(guard_engine, HEADERS, local_part="encrypted")

        use_key(None)
        with pytest.raises(EncryptionKeyMissingError):
            await verify_encryption_key_is_configured(guard_engine)

    async def test_plaintext_headers_are_not_mistaken_for_an_envelope(self, guard_engine, use_key):
        """Test the marker is matched literally, underscores included.

        The marker is full of underscores, which are single-character
        wildcards in LIKE. Unescaped, a plaintext header value of the right
        shape would be reported as encrypted and would block startup for a
        deployment that has no encrypted rows at all.
        """
        use_key(None)
        near_miss = ENVELOPE_MARKER.replace("_", "X")
        await _add_recipient(guard_engine, {"X-Marker": f"a{near_miss}z"})

        await verify_encryption_key_is_configured(guard_engine)


class TestKeyConfigured:
    """With a key present the guard has nothing to decide."""

    async def test_encrypted_rows_pass(self, guard_engine, use_key):
        """Test a configured key ends the check, right or wrong.

        Whether it is the *correct* key cannot be answered cheaply, and a
        wrong one surfaces as a DecryptionError on the row that needs it.
        This guard only answers "is there a key at all".
        """
        use_key(KEY)
        await _add_recipient(guard_engine, HEADERS)
        assert get_cipher() is not None

        await verify_encryption_key_is_configured(guard_engine)

    async def test_unqueryable_database_is_not_even_touched(self, tmp_path, use_key):
        """Test the key short-circuits before any query runs.

        A database whose ``recipients`` table does not exist would make the
        probe fail; with a key configured there is nothing to probe for, so
        startup must not depend on the query working at all.
        """
        use_key(KEY)
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/empty.db")
        try:
            await verify_encryption_key_is_configured(engine)
        finally:
            await engine.dispose()


class TestUnqueryableDatabase:
    """Cannot compare, do not block - the stance ``current_db_revision`` takes."""

    async def test_missing_table_warns_and_allows(self, tmp_path, use_key, caplog):
        """Test a database without the table is reported, not refused.

        Reachable from a database that has never been migrated, and from any
        process pointed at one - neither is evidence of encrypted rows, and a
        guard that refuses on the absence of evidence is a guard that breaks
        first-run installs.
        """
        use_key(None)
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/empty.db")
        try:
            with caplog.at_level(logging.WARNING):
                await verify_encryption_key_is_configured(engine)
        finally:
            await engine.dispose()

        assert any(record.levelno == logging.WARNING for record in caplog.records)
        assert "recipients" in caplog.text
