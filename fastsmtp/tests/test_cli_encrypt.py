"""Tests for ``fastsmtp encrypt-existing``, the at-rest encryption backfill.

Harness
-------
Same shape as ``test_cli_admin.py``: every CLI command runs in its own
``asyncio.run`` loop and asyncpg connections belong to the loop that opened
them, so ``fastsmtp.db.session.async_session`` is replaced with a factory that
builds a NullPool engine per session. The same factory backs the ``db`` helper
used to seed rows and read state back.

The ``keys`` fixture is the other half. ``EncryptedJSON`` asks
``encryption.get_cipher()`` on every read and write, and that resolves through
the cached ``Settings``, so setting ``FASTSMTP_ENCRYPTION_KEYS`` and clearing
the cache is what an operator's ``export`` does - the command under test and
the column type then agree by construction, exactly as they do in a real
process.

What is pinned here: the command refuses to run with no key rather than
reporting success over a no-op; a plaintext row really is written back as an
envelope (asserted against the RAW column, read with Core SQL - the ORM
decrypts, so a round trip through it would pass even if no UPDATE were ever
emitted); ``--dry-run`` writes nothing; and a rotation leaves every row
readable by the new key ALONE, which is the whole point of the exercise.
"""

import json
import uuid
from typing import Any

import pytest
from cli_harness import Db
from fastsmtp.config import clear_settings_cache
from fastsmtp.crypto import DecryptionError, build_cipher, decrypt_json, is_encrypted
from fastsmtp.db.models import Domain, Recipient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

KEY_A = "key-alpha-0000000000000000000000"
KEY_B = "key-bravo-0000000000000000000000"

HEADERS = {"Authorization": "Bearer secret-token", "X-Tenant": "acme"}


@pytest.fixture
def keys():
    """Configure ``FASTSMTP_ENCRYPTION_KEYS``, as an operator's environment would.

    Its own MonkeyPatch context, so the settings cache can be cleared *after*
    the variable is restored - a cached Settings carrying a test key would
    otherwise leak into every later test in the session.
    """
    with pytest.MonkeyPatch.context() as mp:

        def apply(*values: str) -> None:
            mp.setenv("FASTSMTP_ENCRYPTION_KEYS", json.dumps(list(values)))
            clear_settings_cache()

        apply()
        yield apply

    clear_settings_cache()


# --- seeding and inspection ---------------------------------------------------


def seed_domain(db: Db, name: str = "example.com") -> uuid.UUID:
    async def go(session: AsyncSession) -> uuid.UUID:
        domain = Domain(domain_name=name)
        session.add(domain)
        await session.flush()
        return domain.id

    return db(go)


def seed_recipient(
    db: Db,
    domain_id: uuid.UUID,
    local_part: str,
    headers: dict[str, Any],
) -> uuid.UUID:
    """Write one recipient through the ORM, so the column type stores it as configured."""

    async def go(session: AsyncSession) -> uuid.UUID:
        recipient = Recipient(
            domain_id=domain_id,
            local_part=local_part,
            webhook_url="https://hooks.example.com/inbound",
            webhook_headers=headers,
        )
        session.add(recipient)
        await session.flush()
        return recipient.id

    return db(go)


def raw_headers(db: Db, recipient_id: uuid.UUID) -> dict[str, Any]:
    """The stored value, straight from the column, with no decryption on the way out.

    Core SQL and an explicit cast rather than the ORM: ``EncryptedJSON``
    decrypts every value it loads, so anything read through the mapped
    attribute looks identical whether or not the row was ever written.
    """

    async def go(session: AsyncSession) -> dict[str, Any]:
        result = await session.execute(
            text("SELECT webhook_headers::text FROM recipients WHERE id = CAST(:id AS uuid)"),
            {"id": str(recipient_id)},
        )
        stored = json.loads(result.scalar_one())
        assert isinstance(stored, dict)
        return stored

    return db(go)


def orm_headers(db: Db, recipient_id: uuid.UUID) -> dict[str, Any]:
    """The headers as the application sees them, decrypted by the column type."""

    async def go(session: AsyncSession) -> dict[str, Any]:
        recipient = await session.get(Recipient, recipient_id)
        assert recipient is not None
        return dict(recipient.webhook_headers)

    return db(go)


# --- tests --------------------------------------------------------------------


def test_refuses_without_a_key(db: Db, keys, run) -> None:
    """No key means no cipher: fail, name the setting, and leave the row alone."""
    domain_id = seed_domain(db)
    recipient_id = seed_recipient(db, domain_id, "alice", HEADERS)

    exit_code, output = run("encrypt-existing")

    assert exit_code == 1
    assert "FASTSMTP_ENCRYPTION_KEYS" in output
    assert raw_headers(db, recipient_id) == HEADERS


def test_plaintext_row_is_written_back_as_an_envelope(db: Db, keys, run) -> None:
    """The raw column must change; the application's view of it must not.

    The raw assertion is the load-bearing one. The ORM hands back plaintext on
    both sides of the column type, so a version of the command that marked
    nothing dirty and emitted no UPDATE would still satisfy the round trip.
    """
    domain_id = seed_domain(db)
    recipient_id = seed_recipient(db, domain_id, "alice", HEADERS)
    assert raw_headers(db, recipient_id) == HEADERS

    keys(KEY_A)
    exit_code, output = run("encrypt-existing")

    assert exit_code == 0, output
    stored = raw_headers(db, recipient_id)
    assert is_encrypted(stored)
    assert "Bearer secret-token" not in json.dumps(stored)
    assert decrypt_json(stored, build_cipher([KEY_A])) == HEADERS
    assert orm_headers(db, recipient_id) == HEADERS


def test_dry_run_writes_nothing(db: Db, keys, run) -> None:
    domain_id = seed_domain(db)
    recipient_id = seed_recipient(db, domain_id, "alice", HEADERS)

    keys(KEY_A)
    exit_code, output = run("encrypt-existing", "--dry-run")

    assert exit_code == 0, output
    assert "Would encrypt 1 recipient(s) stored in clear" in output
    assert raw_headers(db, recipient_id) == HEADERS


def test_rotation_lets_the_old_key_be_dropped(db: Db, keys, run) -> None:
    """Row written under A, run with [B, A]: B alone must read it afterwards."""
    keys(KEY_A)
    domain_id = seed_domain(db)
    recipient_id = seed_recipient(db, domain_id, "alice", HEADERS)

    only_b = build_cipher([KEY_B])
    assert only_b is not None
    with pytest.raises(DecryptionError):
        decrypt_json(raw_headers(db, recipient_id), only_b)

    keys(KEY_B, KEY_A)
    exit_code, output = run("encrypt-existing")

    assert exit_code == 0, output
    stored = raw_headers(db, recipient_id)
    assert is_encrypted(stored)
    assert decrypt_json(stored, only_b) == HEADERS


def test_unreadable_row_fails_without_overwriting(db: Db, keys, run) -> None:
    """A key dropped too early is reported, not written over with a new envelope."""
    keys(KEY_A)
    domain_id = seed_domain(db)
    recipient_id = seed_recipient(db, domain_id, "alice", HEADERS)
    before = raw_headers(db, recipient_id)

    keys(KEY_B)
    exit_code, output = run("encrypt-existing")

    assert exit_code == 1
    assert "FASTSMTP_ENCRYPTION_KEYS" in output
    assert raw_headers(db, recipient_id) == before


def test_empty_headers_are_encrypted_too(db: Db, keys, run) -> None:
    domain_id = seed_domain(db)
    recipient_id = seed_recipient(db, domain_id, "alice", {})

    keys(KEY_A)
    exit_code, output = run("encrypt-existing")

    assert exit_code == 0, output
    assert is_encrypted(raw_headers(db, recipient_id))
    assert orm_headers(db, recipient_id) == {}


def test_summary_counts_split_clear_from_already_encrypted(db: Db, keys, run) -> None:
    domain_id = seed_domain(db)
    seed_recipient(db, domain_id, "alice", HEADERS)
    seed_recipient(db, domain_id, "bob", HEADERS)

    keys(KEY_A)
    already = seed_recipient(db, domain_id, "carol", HEADERS)
    assert is_encrypted(raw_headers(db, already))

    exit_code, output = run("encrypt-existing")

    assert exit_code == 0, output
    assert (
        "Encrypted 2 recipient(s) stored in clear and re-encrypted 1 under the current key "
        "(3 examined)" in output
    )


def test_every_row_is_converted_across_batches(db: Db, keys, run) -> None:
    """Batching is pagination, not a limit: a batch smaller than the table still finishes."""
    domain_id = seed_domain(db)
    recipient_ids = [seed_recipient(db, domain_id, f"user{n}", HEADERS) for n in range(3)]

    keys(KEY_A)
    exit_code, output = run("encrypt-existing", "--batch-size", "1")

    assert exit_code == 0, output
    assert "(3 examined)" in output
    for recipient_id in recipient_ids:
        assert is_encrypted(raw_headers(db, recipient_id))


def test_empty_table_reports_zero(db: Db, keys, run) -> None:
    keys(KEY_A)
    exit_code, output = run("encrypt-existing")

    assert exit_code == 0, output
    assert "(0 examined)" in output
