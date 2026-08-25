"""Checking the database's encrypted rows against the key this process holds.

Encryption is opt-in, so "no key configured" is a legitimate state and rows
written in it are plaintext. Reads tolerate either shape, which makes almost
every combination of key and data safe. One is not: a database holding
envelopes read by a process with no key. There, every affected row raises
``DecryptionError`` from inside a SELECT - a recipient listing answers 500, and
the delivery worker cannot read the webhook authentication headers it is
supposed to send. The credentials are on disk and unreadable, and nothing in
the request path can do anything about it.

That is worth one query at startup, so the process refuses to come up rather
than failing per-request afterwards.
"""

import logging
import uuid

from sqlalchemy import Select, Text, cast, select
from sqlalchemy.exc import DatabaseError
from sqlalchemy.ext.asyncio import AsyncEngine

from fastsmtp.crypto import ENVELOPE_MARKER, KEYS_SETTING
from fastsmtp.db.models import Recipient
from fastsmtp.encryption import get_cipher

logger = logging.getLogger(__name__)


class EncryptionKeyMissingError(RuntimeError):
    """Raised when the database holds encrypted rows this process cannot read."""


def _encrypted_recipient_probe() -> Select[tuple[uuid.UUID]]:
    """A statement answering "is any stored value an envelope" in one row or none.

    Deliberately SQL-level, and deliberately not selecting the column. Loading
    ``Recipient.webhook_headers`` runs the type decorator on the way out, which
    raises ``DecryptionError`` with no key configured - the very failure this
    module exists to report cleanly. Only the id is fetched; the column is
    touched by a CAST inside the predicate and never leaves the database.

    Casting to text and looking for the marker is the one predicate that holds
    on both dialects: the column is ``JSONB`` on PostgreSQL and ``JSON`` stored
    as text on SQLite, so a JSON containment or path operator would have to be
    written twice.

    ``autoescape`` is load-bearing rather than tidy. The marker is full of
    underscores, and an underscore is a single-character wildcard in LIKE; left
    unescaped, an ordinary header value of roughly the right shape would be
    reported as an envelope and would refuse startup for a deployment that has
    no encrypted rows at all.

    Soft-deleted rows are included on purpose. A tombstoned recipient's headers
    are still ciphertext on disk, still readable through the undelete and audit
    paths, and still need the key at rotation time.

    LIMIT 1 stops at the first match, but a table with no encrypted rows is
    scanned end to end. That is fine for ``recipients``, which holds one row per
    address and is probed once per process start. It does **not** transfer to
    ``delivery_log`` when that table's payload is encrypted in a later phase:
    that table is unbounded and grows with traffic, so the check there needs a
    different shape - a bounded sample, an explicit marker column, or an index -
    rather than this predicate pointed at a bigger table.
    """
    return (
        select(Recipient.id)
        .where(cast(Recipient.webhook_headers, Text).contains(ENVELOPE_MARKER, autoescape=True))
        .limit(1)
    )


async def _has_encrypted_recipients(engine: AsyncEngine) -> bool | None:
    """Whether any encrypted row exists, or None if the question cannot be asked.

    None is not an error: the table may not exist yet, which is the case for a
    database that has never been migrated and for any test schema that does not
    build it. ``current_db_revision`` takes the same stance - a check that
    cannot run reports that, rather than deciding.
    """
    try:
        async with engine.connect() as conn:
            result = await conn.execute(_encrypted_recipient_probe())
            return result.first() is not None
    except DatabaseError:
        return None


async def verify_encryption_key_is_configured(engine: AsyncEngine) -> None:
    """Refuse to start with no key against a database that holds encrypted rows.

    Only that combination raises. A configured key is accepted without further
    question: whether it is the *right* key cannot be established cheaply, and a
    wrong one surfaces as a ``DecryptionError`` on the row that needs it. A
    database with no envelopes is the normal state of every deployment that
    never enabled the feature, and one that cannot be queried at all cannot be
    compared, so it is reported and allowed.
    """
    if get_cipher() is not None:
        logger.debug("Encryption key configured; encrypted columns are readable by this process")
        return

    table = Recipient.__tablename__
    has_encrypted = await _has_encrypted_recipients(engine)

    if has_encrypted is None:
        logger.warning(
            "Could not check %s.webhook_headers for encrypted rows; the table could "
            "not be queried, so no encryption key check was made",
            table,
        )
        return

    if not has_encrypted:
        logger.debug("No encrypted rows in %s.webhook_headers; no key needed", table)
        return

    raise EncryptionKeyMissingError(
        f"Rows in {table}.webhook_headers are encrypted but no encryption key is "
        f"configured. Set {KEYS_SETTING} to the key they were written with before "
        f"starting this version -- every read of an affected row would otherwise "
        f"fail, including the webhook worker's, and the authentication headers it "
        f"needs would be unrecoverable."
    )
