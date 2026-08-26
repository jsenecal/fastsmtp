"""Storage-layer tests for the EncryptedJSON column type.

``recipients.webhook_headers`` holds the customer's own credentials for their
endpoint, so the column is encrypted at rest. The property that matters is not
that a value survives a round trip - a column that never encrypted anything
would pass that - but what is actually *on disk*. Every storage claim below is
checked by reading the cell back with a SQL cast to text, which returns through
``Text``'s result processor and so never touches ``EncryptedJSON``. A test that
only went through the ORM would pass with the decorator deleted.

The contract being protected:

* Above the storage layer nothing changes: the attribute is a plain dict.
* With no key configured, values are stored in clear, exactly as before.
* Reads accept both shapes, so a plaintext row written before the key existed
  keeps working once a key is configured.
* Writes convert: a row rewritten while a key is configured is stored encrypted.
* A value that cannot be decrypted raises. An empty dict would dispatch the
  webhook with no authentication headers, which looks like a success and is not.
* The DDL is unchanged, which is why adopting the type needed no migration.

``get_cipher`` reads the process-wide settings rather than a fixture, so these
tests configure keys through the environment and clear the settings cache; see
the ``configure_keys`` fixture.
"""

import json
import uuid
from collections.abc import Callable

import pytest
from fastsmtp.crypto import (
    ENVELOPE_MARKER,
    DecryptionError,
    decrypt_json,
    encrypt_json,
    is_encrypted,
)
from fastsmtp.db.encrypted_types import EncryptedJSON
from fastsmtp.db.models import Domain, Recipient
from fastsmtp.encryption import get_cipher
from sqlalchemy import Dialect, Text, cast, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.schema import CreateTable

#: Two unrelated operator keys. Deriving one costs 100k PBKDF2 iterations, and
#: ``get_cipher`` memoizes per key tuple, so the file deliberately uses few.
KEY_A = "column-key-alpha"
KEY_B = "column-key-bravo"

#: The kind of thing the column really holds.
SECRET_HEADERS = {
    "Authorization": "Bearer sk-live-9f3a1c0d7e5b",
    "X-Webhook-Signature": "sha256=deadbeefcafe",
}

#: A second, different value. Rewrites must change the content or SQLAlchemy
#: compares the new value equal to the loaded one and emits no UPDATE at all -
#: which is also why the estate needs a backfill and not just traffic.
ROTATED_HEADERS = {"Authorization": "Bearer sk-live-rewritten-0001"}


async def seed_recipient(
    session: AsyncSession,
    headers: dict[str, str] | None = None,
    *,
    local_part: str = "hooks",
) -> uuid.UUID:
    """Insert a domain and one recipient, and return the recipient's id.

    ``headers`` of None leaves the attribute unset, which exercises the
    column's ``default=dict`` rather than an explicit write.
    """
    domain = Domain(domain_name=f"{uuid.uuid4().hex[:12]}.example.com")
    session.add(domain)
    await session.flush()

    recipient = Recipient(
        domain_id=domain.id,
        local_part=local_part,
        webhook_url="https://hooks.example.com/inbound",
    )
    if headers is not None:
        recipient.webhook_headers = headers
    session.add(recipient)
    await session.commit()
    return recipient.id


async def raw_cell(session: AsyncSession, recipient_id: uuid.UUID) -> str:
    """The webhook_headers cell exactly as the database holds it.

    Casting in SQL is the whole point: the value comes back through ``Text``'s
    result processor, so ``EncryptedJSON.process_result_value`` never runs and
    nothing decrypts it on the way out.
    """
    stmt = select(cast(Recipient.webhook_headers, Text)).where(Recipient.id == recipient_id)
    return (await session.execute(stmt)).scalar_one()


async def load_headers(
    factory: async_sessionmaker[AsyncSession], recipient_id: uuid.UUID
) -> dict[str, str]:
    """Read the recipient back through the ORM in a session of its own.

    A fresh session means a real SELECT and a real trip through the type's
    result processing, rather than an identity-map hit on the object the test
    just wrote.
    """
    async with factory() as session:
        recipient = await session.get_one(Recipient, recipient_id)
        return recipient.webhook_headers


def column_ddl(dialect: Dialect) -> str:
    """The webhook_headers line of CREATE TABLE recipients, for one dialect."""
    ddl = str(CreateTable(Recipient.__table__).compile(dialect=dialect))
    lines = [
        line.strip().rstrip(",")
        for line in ddl.splitlines()
        if line.strip().startswith("webhook_headers ")
    ]
    assert len(lines) == 1, f"expected one webhook_headers column, got {lines}"
    return lines[0]


async def test_no_key_stores_plaintext(
    session_factory: async_sessionmaker[AsyncSession],
    configure_keys: Callable[..., None],
) -> None:
    """Test the column is a pass-through until a key is configured.

    This is the default and the state of every deployment that has not opted
    in, so it has to be byte-for-byte the old plain JSON column.
    """
    async with session_factory() as session:
        recipient_id = await seed_recipient(session, SECRET_HEADERS)
        stored = json.loads(await raw_cell(session, recipient_id))

    assert stored == SECRET_HEADERS
    assert not is_encrypted(stored)
    assert ENVELOPE_MARKER not in stored
    assert await load_headers(session_factory, recipient_id) == SECRET_HEADERS


async def test_key_stores_an_envelope(
    session_factory: async_sessionmaker[AsyncSession],
    configure_keys: Callable[..., None],
) -> None:
    """Test a configured key puts an envelope on disk and nothing readable."""
    configure_keys(KEY_A)

    async with session_factory() as session:
        recipient_id = await seed_recipient(session, SECRET_HEADERS)
        raw = await raw_cell(session, recipient_id)

    stored = json.loads(raw)
    assert is_encrypted(stored)
    assert stored[ENVELOPE_MARKER] == 1
    assert isinstance(stored["ciphertext"], str)

    # Neither the header names nor their values survive anywhere in the cell.
    for name, value in SECRET_HEADERS.items():
        assert name not in raw
        assert value not in raw

    # ...and the application above the storage layer sees none of that.
    assert await load_headers(session_factory, recipient_id) == SECRET_HEADERS


async def test_column_default_is_encrypted_too(
    session_factory: async_sessionmaker[AsyncSession],
    configure_keys: Callable[..., None],
) -> None:
    """Test a recipient created without headers still stores an envelope.

    ``default=dict`` is a Python-side default applied at flush, so it goes
    through the same bind processing as an explicit value. If it did not, every
    recipient created through the API without headers would be a plaintext row
    the estate later has to find.
    """
    configure_keys(KEY_A)

    async with session_factory() as session:
        recipient_id = await seed_recipient(session, None)
        stored = json.loads(await raw_cell(session, recipient_id))

    assert is_encrypted(stored)
    assert await load_headers(session_factory, recipient_id) == {}


async def test_legacy_plaintext_row_reads_once_a_key_exists(
    session_factory: async_sessionmaker[AsyncSession],
    configure_keys: Callable[..., None],
) -> None:
    """Test rows written before the key was configured keep reading.

    This is the rollout: the key is turned on for a database that is already
    full of plaintext. If this raised, enabling the feature would be an outage.
    """
    async with session_factory() as session:
        recipient_id = await seed_recipient(session, SECRET_HEADERS)

    configure_keys(KEY_A)

    assert await load_headers(session_factory, recipient_id) == SECRET_HEADERS


async def test_legacy_plaintext_row_converts_when_rewritten(
    session_factory: async_sessionmaker[AsyncSession],
    configure_keys: Callable[..., None],
) -> None:
    """Test rewriting a plaintext row stores it encrypted.

    The lazy half of the conversion, and also a statement-cache test: the
    INSERT above ran with no cipher and the UPDATE below runs with one, so a
    bind processor resolved once at compile time would keep writing plaintext.
    """
    async with session_factory() as session:
        recipient_id = await seed_recipient(session, SECRET_HEADERS)
        plaintext = json.loads(await raw_cell(session, recipient_id))
    assert not is_encrypted(plaintext)

    configure_keys(KEY_A)

    async with session_factory() as session:
        recipient = await session.get_one(Recipient, recipient_id)
        recipient.webhook_headers = ROTATED_HEADERS
        await session.commit()
        stored = json.loads(await raw_cell(session, recipient_id))

    assert is_encrypted(stored)
    assert await load_headers(session_factory, recipient_id) == ROTATED_HEADERS


async def test_api_style_update_stores_encrypted(
    session_factory: async_sessionmaker[AsyncSession],
    configure_keys: Callable[..., None],
) -> None:
    """Test the generic setattr update route is not a hole.

    ``api/recipients.py`` applies an update by looping ``setattr`` over the
    dumped payload and then refreshing the row, so the update path never names
    the column. It has to encrypt anyway, and the refresh has to decrypt.
    """
    configure_keys(KEY_A)

    async with session_factory() as session:
        recipient_id = await seed_recipient(session, SECRET_HEADERS)

    update_data = {
        "webhook_url": "https://hooks.example.com/v2",
        "webhook_headers": ROTATED_HEADERS,
    }

    async with session_factory() as session:
        recipient = await session.get_one(Recipient, recipient_id)
        for field, value in update_data.items():
            setattr(recipient, field, value)
        await session.flush()
        await session.refresh(recipient)

        assert recipient.webhook_headers == ROTATED_HEADERS
        await session.commit()
        raw = await raw_cell(session, recipient_id)

    assert is_encrypted(json.loads(raw))
    assert ROTATED_HEADERS["Authorization"] not in raw


async def test_wrong_key_raises_on_load(
    session_factory: async_sessionmaker[AsyncSession],
    configure_keys: Callable[..., None],
) -> None:
    """Test a row no configured key can read fails loudly, at load time.

    Degrading to ``{}`` here would post the webhook with no authentication
    headers: a request the sender counts as delivered and the receiver rejects,
    or worse accepts anonymously.
    """
    configure_keys(KEY_A)
    async with session_factory() as session:
        recipient_id = await seed_recipient(session, SECRET_HEADERS)

    configure_keys(KEY_B)

    async with session_factory() as session:
        with pytest.raises(DecryptionError):
            await session.get_one(Recipient, recipient_id)


async def test_removing_the_key_raises_on_load(
    session_factory: async_sessionmaker[AsyncSession],
    configure_keys: Callable[..., None],
) -> None:
    """Test an encrypted row read with no key at all raises rather than leaking.

    Unsetting the variable is the likeliest operator mistake, and the stored
    value is not plaintext just because the process forgot the key.
    """
    configure_keys(KEY_A)
    async with session_factory() as session:
        recipient_id = await seed_recipient(session, SECRET_HEADERS)

    configure_keys()
    assert get_cipher() is None

    async with session_factory() as session:
        with pytest.raises(DecryptionError, match="FASTSMTP_ENCRYPTION_KEYS"):
            await session.get_one(Recipient, recipient_id)


async def test_empty_headers_round_trip(
    session_factory: async_sessionmaker[AsyncSession],
    configure_keys: Callable[..., None],
) -> None:
    """Test an explicitly empty dict is stored encrypted and read back empty.

    ``{}`` is falsy, so a truthiness test anywhere on the write path would
    store it in clear; and it must come back as ``{}`` rather than None.
    """
    configure_keys(KEY_A)

    async with session_factory() as session:
        recipient_id = await seed_recipient(session, {})
        stored = json.loads(await raw_cell(session, recipient_id))

    assert is_encrypted(stored)

    loaded = await load_headers(session_factory, recipient_id)
    assert loaded == {}
    assert loaded is not None


async def test_unicode_headers_round_trip(
    session_factory: async_sessionmaker[AsyncSession],
    configure_keys: Callable[..., None],
) -> None:
    """Test non-ASCII names and values survive encryption unchanged.

    The payload is serialized, encrypted, base64'd and stored in a JSON column,
    which is three encodings deep; a mangled one would show up here.
    """
    configure_keys(KEY_A)
    unicode_headers = {
        "X-Kunde": "Grüße aus München",
        "X-テスト": "値-☃",
    }

    async with session_factory() as session:
        recipient_id = await seed_recipient(session, unicode_headers)
        stored = json.loads(await raw_cell(session, recipient_id))

    assert is_encrypted(stored)
    assert await load_headers(session_factory, recipient_id) == unicode_headers


async def test_rotation_reads_the_old_key_and_writes_the_new_one(
    session_factory: async_sessionmaker[AsyncSession],
    configure_keys: Callable[..., None],
) -> None:
    """Test the whole rotation as the storage layer sees it.

    Prepend the new key, keep the old one; existing rows stay readable, and
    anything rewritten is written under the new key - which is what eventually
    lets the old key be dropped.
    """
    configure_keys(KEY_A)
    async with session_factory() as session:
        recipient_id = await seed_recipient(session, SECRET_HEADERS)

    # New key first, superseded key still present.
    configure_keys(KEY_B, KEY_A)
    assert await load_headers(session_factory, recipient_id) == SECRET_HEADERS

    async with session_factory() as session:
        recipient = await session.get_one(Recipient, recipient_id)
        recipient.webhook_headers = ROTATED_HEADERS
        await session.commit()

    # The old key is gone; the rewritten row must have been encrypted under the
    # primary key, not the one that happened to decrypt it.
    configure_keys(KEY_B)
    assert await load_headers(session_factory, recipient_id) == ROTATED_HEADERS


def test_get_cipher_tracks_the_configured_keys(
    configure_keys: Callable[..., None],
) -> None:
    """Test the cipher cache follows the configuration instead of going stale.

    ``_cipher_for`` is memoized on the key tuple, so this asserts both halves:
    a different key set yields a genuinely different cipher, and the same key
    set is not re-derived.
    """
    assert get_cipher() is None

    configure_keys(KEY_A)
    cipher_a = get_cipher()
    assert cipher_a is not None

    configure_keys(KEY_B)
    cipher_b = get_cipher()
    assert cipher_b is not None
    assert cipher_b is not cipher_a

    # Not merely a different object: it cannot read what A wrote.
    with pytest.raises(DecryptionError):
        decrypt_json(encrypt_json(SECRET_HEADERS, cipher_a), cipher_b)

    configure_keys(KEY_A)
    assert get_cipher() is cipher_a


def test_ddl_is_unchanged() -> None:
    """Test the stored type is still JSONB on PostgreSQL and JSON on SQLite.

    This is the claim that let the column adopt encryption with no migration.
    Change ``load_dialect_impl`` and this fails here, rather than as a schema
    drift someone discovers from ``compare_metadata`` or a production deploy.
    """
    assert column_ddl(postgresql.dialect()) == "webhook_headers JSONB NOT NULL"
    assert column_ddl(sqlite.dialect()) == "webhook_headers JSON NOT NULL"


def test_null_is_left_alone() -> None:
    """Test a NULL cell is neither encrypted nor decrypted.

    ``recipients.webhook_headers`` is NOT NULL, so this branch is unreachable
    through that column - but the type is reusable, and a nullable column
    adopting it must not turn None into an envelope or a decryption failure.
    """
    column_type = EncryptedJSON()
    dialect = postgresql.dialect()

    assert column_type.process_bind_param(None, dialect) is None
    assert column_type.process_result_value(None, dialect) is None
