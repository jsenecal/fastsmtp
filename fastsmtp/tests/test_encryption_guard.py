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

The two probes are tested separately and are meant to stay separate. The
recipients one is exact; the delivery-log one samples the newest rows, because
that table holds every delivery inside the retention window. What the sample
gives up is pinned down by
``TestDeliveryLogSamplingLimit.test_envelopes_older_than_the_sample_are_missed``
rather than left implied.
"""

import json
import logging
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from fastsmtp.config import clear_settings_cache
from fastsmtp.crypto import ENVELOPE_MARKER, DecryptionError
from fastsmtp.db.encryption_guard import (
    DELIVERY_LOG_SAMPLE_SIZE,
    EncryptionKeyMissingError,
    _encrypted_delivery_log_probe,
    verify_encryption_key_is_configured,
)
from fastsmtp.db.models import Base, DeliveryLog, Domain, Recipient
from fastsmtp.encryption import get_cipher
from sqlalchemy import insert, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

KEY = "operator-key-for-the-guard"

HEADERS = {"Authorization": "Bearer sk-live-0123456789abcdef"}

PAYLOAD = {"subject": "Quarterly numbers", "body_text": "Attached, in confidence."}

#: Base timestamp for rows whose ``created_at`` a test sets by hand. The
#: delivery-log probe orders by that column, so a test about which rows fall
#: inside the sample cannot leave the ordering to ``server_default now()``:
#: PostgreSQL's ``now()`` is transaction-start time, so a batch written in one
#: transaction would tie and the sample would take an arbitrary thousand.
EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


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


async def _stored_column_text(engine: AsyncEngine, table: str, column: str) -> str:
    """Every stored value of one encrypted column as raw text, never through the ORM.

    Reading the attribute would run the decorator and decrypt (or raise); this
    asserts on what is actually on disk. The CAST is what makes it work on both
    dialects, JSONB and JSON-as-text alike - the same reason the probes cast.
    """
    async with engine.connect() as conn:
        result = await conn.execute(text(f"SELECT CAST({column} AS TEXT) FROM {table}"))
        return "\n".join(str(row[0]) for row in result)


async def _stored_headers_text(engine: AsyncEngine) -> str:
    """Every stored ``recipients.webhook_headers`` value as raw text."""
    return await _stored_column_text(engine, "recipients", "webhook_headers")


def _delivery_log_values(payload: dict, created_at: datetime) -> dict:
    """The column values for one delivery log row, minus the payload's storage form.

    ``domain_id`` and ``recipient_id`` are left NULL on purpose. Both are
    nullable and neither is read by the probe, so building a domain and a
    recipient per row would only add rows to the *other* table this guard
    checks, which is precisely what a delivery-log test must not do.
    """
    return {
        "id": uuid.uuid4(),
        "message_id": f"<{uuid.uuid4().hex}@example.com>",
        "webhook_url": "https://hooks.example.com/inbound",
        "payload_hash": uuid.uuid4().hex,
        "status": "delivered",
        "attempts": 1,
        "instance_id": "guard-test",
        "payload": payload,
        "created_at": created_at,
        "updated_at": created_at,
    }


async def _add_delivery_logs(
    engine: AsyncEngine, payload: dict, *, count: int = 1, first_created_at: datetime = EPOCH
) -> None:
    """Write ``count`` delivery log rows, one second apart, through the column type.

    The insert goes through the mapped table, so ``EncryptedJSON`` decides the
    storage form exactly as it does in production: an envelope while a key is
    configured, plaintext while none is. That is what lets a test write real
    envelopes and then take the key away.

    ``created_at`` is set explicitly and increments, because the probe's sample
    is "the newest N by ``created_at``" and a test about that boundary cannot
    depend on rows written in one transaction tying on ``now()``.
    """
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await session.execute(
            insert(DeliveryLog),
            [
                _delivery_log_values(payload, first_created_at + timedelta(seconds=offset))
                for offset in range(count)
            ],
        )
        await session.commit()


async def _stored_payload_text(engine: AsyncEngine) -> str:
    """Every stored ``delivery_log.payload`` value as raw text."""
    return await _stored_column_text(engine, "delivery_log", "payload")


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

    async def test_plaintext_delivery_logs_pass(self, guard_engine, use_key):
        """Test plaintext payloads do not trip the delivery-log probe either.

        The state of every deployment that has never set a key, and the one the
        probe must be silent about: it is checked at every start, so a false
        positive here refuses startup for an installation with nothing to
        protect.
        """
        use_key(None)
        await _add_delivery_logs(guard_engine, PAYLOAD, count=3)
        assert ENVELOPE_MARKER not in await _stored_payload_text(guard_engine)

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
        # The message reports what was actually found. Naming a table that is
        # clean would send an operator looking for rows that are not there.
        assert "delivery_log" not in message

    async def test_encrypted_payload_names_the_delivery_log(self, guard_engine, use_key):
        """Test an encrypted payload is reported as the delivery log, not as recipients.

        "You have encrypted rows and no key" leaves the operator to work out
        which data is affected, and the two answers lead to different places:
        webhook headers are re-enterable credentials, delivery log payloads are
        the only copy of the messages inside the retention window.
        """
        use_key(KEY)
        await _add_delivery_logs(guard_engine, PAYLOAD)
        assert ENVELOPE_MARKER in await _stored_payload_text(guard_engine)

        use_key(None)
        with pytest.raises(EncryptionKeyMissingError) as exc_info:
            await verify_encryption_key_is_configured(guard_engine)

        message = str(exc_info.value)
        assert "FASTSMTP_ENCRYPTION_KEYS" in message
        assert "delivery_log" in message
        assert "payload" in message
        assert "recipients" not in message

    async def test_both_columns_are_named_when_both_are_encrypted(self, guard_engine, use_key):
        """Test the guard keeps probing after the first column answers yes.

        The normal state once the feature has been on for a while: both columns
        convert. Stopping at the first hit would report half the exposure, and
        an operator who restored only what the message named would still be
        one unreadable column short.
        """
        use_key(KEY)
        await _add_recipient(guard_engine, HEADERS)
        await _add_delivery_logs(guard_engine, PAYLOAD)

        use_key(None)
        with pytest.raises(EncryptionKeyMissingError) as exc_info:
            await verify_encryption_key_is_configured(guard_engine)

        message = str(exc_info.value)
        assert "recipients.webhook_headers" in message
        assert "delivery_log.payload" in message

    async def test_probe_reads_no_payload_through_the_orm(self, guard_engine, use_key):
        """Test the probe answers without decrypting, where the ORM cannot.

        This is the trap the whole module is written around. Loading
        ``DeliveryLog.payload`` with no key runs the type decorator and raises
        ``DecryptionError`` from inside the SELECT - the exact failure the
        guard exists to convert into a clean startup refusal. A probe that
        selected the column would raise it while trying to report it.

        Both halves are asserted together on purpose: the ORM load proves the
        rows really are undecryptable in this process, so the probe returning a
        plain scalar is evidence about the probe rather than about the data.
        """
        use_key(KEY)
        await _add_delivery_logs(guard_engine, PAYLOAD)

        use_key(None)
        factory = async_sessionmaker(guard_engine, expire_on_commit=False)
        async with factory() as session:
            with pytest.raises(DecryptionError):
                await session.execute(select(DeliveryLog.payload))

        async with guard_engine.connect() as conn:
            row = (await conn.execute(_encrypted_delivery_log_probe())).first()

        assert row is not None, "the probe should have found the envelope"
        assert row[0] == 1, "the probe should return a literal, never the column"

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


class TestDeliveryLogSamplingLimit:
    """Where the bounded sample sees, and where it deliberately does not.

    ``delivery_log`` holds every delivery inside the retention window, so the
    exact probe used for ``recipients`` would scan the largest table in the
    database at every process start just to answer "no" on a deployment that
    never enabled encryption. The payload probe therefore looks only at the
    newest ``DELIVERY_LOG_SAMPLE_SIZE`` rows. These two tests are the boundary
    of that trade, written so nobody has to infer it from the constant.
    """

    async def test_envelope_inside_the_sample_is_found(self, guard_engine, use_key):
        """Test an envelope that is not the newest row is still detected.

        The shape a rolling deploy leaves: replicas with and without the key
        write interleaved for as long as the roll takes, so the encrypted rows
        are a minority and none of them is the single newest. The sample has to
        cover a run of newer plaintext rows, not just the top of the table.
        """
        use_key(KEY)
        await _add_delivery_logs(guard_engine, PAYLOAD, first_created_at=EPOCH)

        use_key(None)
        await _add_delivery_logs(
            guard_engine, PAYLOAD, count=50, first_created_at=EPOCH + timedelta(hours=1)
        )

        with pytest.raises(EncryptionKeyMissingError) as exc_info:
            await verify_encryption_key_is_configured(guard_engine)
        assert "delivery_log.payload" in str(exc_info.value)

    async def test_envelopes_older_than_the_sample_are_missed(self, guard_engine, use_key):
        """Test the guard passes when every envelope has aged out of the sample.

        This documents the limitation rather than a desired behaviour: the
        database here really does hold an unreadable row, and startup is
        allowed anyway. Pushed past ``DELIVERY_LOG_SAMPLE_SIZE`` newer
        plaintext rows, the envelope is outside what the probe looks at.

        Judged acceptable, for two reasons.

        First, reaching this state takes work. Encryption applies forward from
        the moment a key is configured, so the process that wrote the envelope
        held the key until it stopped; for a thousand plaintext rows to sit on
        top of it, the estate must have run keyless for a thousand deliveries
        *after* that - which means it already started keyless at least once and
        the guard already had its chance to refuse. The miss is a second
        restart of an installation that ignored the first refusal, not a fresh
        deployment walking into it.

        Second, the alternative is worse. Making the answer exact means the
        unbounded scan, paid at every start by every deployment, almost all of
        which have no encrypted payloads at all - a guaranteed cost against a
        low-probability miss. If the exact answer is ever wanted it belongs in
        an explicit operator command over the whole table, not in the startup
        path.

        The recipients probe is exact and stays exact; that table is small
        enough for the complete answer to be free.
        """
        use_key(KEY)
        await _add_delivery_logs(guard_engine, PAYLOAD, first_created_at=EPOCH)
        assert ENVELOPE_MARKER in await _stored_payload_text(guard_engine)

        use_key(None)
        await _add_delivery_logs(
            guard_engine,
            PAYLOAD,
            count=DELIVERY_LOG_SAMPLE_SIZE,
            first_created_at=EPOCH + timedelta(hours=1),
        )

        # No refusal, even though the row below is genuinely unreadable here.
        await verify_encryption_key_is_configured(guard_engine)

        factory = async_sessionmaker(guard_engine, expire_on_commit=False)
        async with factory() as session:
            with pytest.raises(DecryptionError):
                await session.execute(
                    select(DeliveryLog.payload).where(DeliveryLog.created_at <= EPOCH)
                )


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

    async def test_encrypted_delivery_logs_pass(self, guard_engine, use_key):
        """Test a key ends the check for the payload column too.

        The sample is never taken when there is a key, which is also why the
        bound's cost is only paid by deployments that have not enabled the
        feature - the ones for whom the answer is always "no".
        """
        use_key(KEY)
        await _add_delivery_logs(guard_engine, PAYLOAD, count=3)
        assert ENVELOPE_MARKER in await _stored_payload_text(guard_engine)

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

    async def test_missing_tables_warn_and_allow(self, tmp_path, use_key, caplog):
        """Test a database without the tables is reported, not refused.

        Reachable from a database that has never been migrated, and from any
        process pointed at one - neither is evidence of encrypted rows, and a
        guard that refuses on the absence of evidence is a guard that breaks
        first-run installs.

        Both columns are named. One probe failing must not silence the other's
        report, or an operator would be told about half of what could not be
        checked.
        """
        use_key(None)
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/empty.db")
        try:
            with caplog.at_level(logging.WARNING):
                await verify_encryption_key_is_configured(engine)
        finally:
            await engine.dispose()

        assert any(record.levelno == logging.WARNING for record in caplog.records)
        assert "recipients.webhook_headers" in caplog.text
        assert "delivery_log.payload" in caplog.text
