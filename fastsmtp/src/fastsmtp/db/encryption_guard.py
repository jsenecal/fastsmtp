"""Checking the database's encrypted rows against the key this process holds.

Encryption is opt-in, so "no key configured" is a legitimate state and rows
written in it are plaintext. Reads tolerate either shape, which makes almost
every combination of key and data safe. One is not: a database holding
envelopes read by a process with no key. There, every affected row raises
``DecryptionError`` from inside a SELECT - a recipient listing answers 500, the
delivery worker cannot read the webhook authentication headers it is supposed
to send, and a delivery log detail read cannot return the payload. The data is
on disk and unreadable, and nothing in the request path can do anything about
it.

That is worth one query per encrypted column at startup, so the process refuses
to come up rather than failing per-request afterwards.

Two columns are probed and the probes deliberately have different shapes,
because the tables do:

* ``recipients.webhook_headers`` is probed exactly. One row per address, so a
  full scan when nothing matches is affordable and the answer is complete.
* ``delivery_log.payload`` is probed over a bounded sample of the newest rows.
  That table holds every delivery inside the retention window and can be
  millions of rows; the exact question is not worth an unbounded scan at every
  start, and the sampled one answers what an operator actually needs to know.

Do not "tidy" the two into one helper. Merging them would either make the
recipients answer approximate for no gain, or put a scan of the largest table
in the process's startup path.
"""

import logging
import uuid
from typing import Any

from sqlalchemy import ColumnElement, Select, Text, cast, literal, select
from sqlalchemy.exc import DatabaseError
from sqlalchemy.ext.asyncio import AsyncEngine

from fastsmtp.crypto import ENVELOPE_MARKER, KEYS_SETTING
from fastsmtp.db.models import DeliveryLog, Recipient
from fastsmtp.encryption import get_cipher

logger = logging.getLogger(__name__)

#: How many of the newest ``delivery_log`` rows the payload probe looks at.
#:
#: Encryption applies forward from the moment a key is configured, so if any
#: payload is an envelope the newest rows are where one appears: the process
#: that held the key wrote encrypted rows right up to the shutdown that
#: preceded this start. A window of one would answer that clean case.
#:
#: The window is 1000 for the untidy cases, which are the real ones. During a
#: rolling deploy or a partial rollback, replicas with and without the key
#: write interleaved for as long as the roll takes, so the newest rows are a
#: mixture rather than uniformly encrypted; 1000 rows detects a minority as
#: thin as one write in several hundred. It is still a fixed cost: the rows are
#: taken in index order (see ``_encrypted_delivery_log_probe``) and the scan
#: stops at the first match, so the worst case is 1000 tuples regardless of
#: whether the table holds a thousand rows or a hundred million.
DELIVERY_LOG_SAMPLE_SIZE = 1000


class EncryptionKeyMissingError(RuntimeError):
    """Raised when the database holds encrypted rows this process cannot read."""


def _carries_the_marker(expression: ColumnElement[str]) -> ColumnElement[bool]:
    """Whether a text expression contains the envelope marker.

    Both probes go through here so the escaping is decided once.
    ``autoescape`` is load-bearing rather than tidy: the marker is full of
    underscores, and an underscore is a single-character wildcard in LIKE. Left
    unescaped, an ordinary stored value of roughly the right shape would be
    reported as an envelope and would refuse startup for a deployment that has
    no encrypted rows at all. A third probe written without it would fail that
    way silently, which is why this is not inlined at the call sites.

    Args:
        expression: A text-typed expression, which is what a CAST of the JSON
            column produces on either dialect

    Returns:
        The predicate to hang on a WHERE clause
    """
    return expression.contains(ENVELOPE_MARKER, autoescape=True)


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

    Soft-deleted rows are included on purpose. A tombstoned recipient's headers
    are still ciphertext on disk, still readable through the undelete and audit
    paths, and still need the key at rotation time.

    LIMIT 1 stops at the first match, but a table with no encrypted rows is
    scanned end to end. That is fine here, and only here: ``recipients`` holds
    one row per address and is probed once per process start. The unbounded
    shape is why ``delivery_log`` gets a different probe rather than this one
    pointed at a bigger table.
    """
    return (
        select(Recipient.id)
        .where(_carries_the_marker(cast(Recipient.webhook_headers, Text)))
        .limit(1)
    )


def _encrypted_delivery_log_probe() -> Select[tuple[int]]:
    """The same question over ``delivery_log``, asked of the newest rows only.

    ``delivery_log`` grows with traffic and is trimmed only by the retention
    window, so the recipients probe's end-to-end scan does not transfer: on a
    busy deployment with no encrypted payloads at all it would read every row
    in the table before answering "no", at every process start. The bounded
    sample answers the question an operator has - "is this process about to
    read rows it cannot decrypt" - at a cost that does not depend on the size
    of the table. See ``DELIVERY_LOG_SAMPLE_SIZE`` for what the bound gives up.

    The nesting is not stylistic. ``LIMIT`` is applied after ``WHERE``, so a
    flat statement carrying both would mean "the newest N *encrypted* rows",
    which is the unbounded scan again: with no encrypted rows anywhere the
    database still has to read the whole table to discover it cannot fill the
    limit. Taking the sample in a subquery and testing the marker outside it is
    what makes the bound real.

    ``ORDER BY created_at DESC LIMIT n`` is served by ``ix_delivery_log_cleanup``
    on ``(created_at, status)`` - leading column ``created_at`` - so no index
    and no migration are added for this. Dropping that index, or narrowing it
    so ``created_at`` is no longer the leading column, turns this probe into a
    sort of the whole table - which is the reason the index matters beyond the
    cleanup job it is named for.

    As with recipients, the column is never fetched. ``cast(..., Text)`` inside
    the subquery discards the ``EncryptedJSON`` type, so what the outer query
    sees is text and there is no decorator left to run even in principle; the
    outer select returns a literal, so no column value crosses into Python.
    """
    sample = (
        select(cast(DeliveryLog.payload, Text).label("payload_text"))
        .order_by(DeliveryLog.created_at.desc())
        .limit(DELIVERY_LOG_SAMPLE_SIZE)
        .subquery()
    )
    return (
        select(literal(1))
        .select_from(sample)
        .where(_carries_the_marker(sample.c.payload_text))
        .limit(1)
    )


async def _has_encrypted_rows(engine: AsyncEngine, probe: Select[Any]) -> bool | None:
    """Whether the probe found an encrypted row, or None if it could not ask.

    None is not an error: the table may not exist yet, which is the case for a
    database that has never been migrated and for any test schema that does not
    build it. ``current_db_revision`` takes the same stance - a check that
    cannot run reports that, rather than deciding.

    Each call takes its own connection, which is what makes that stance work
    for more than one probe. PostgreSQL aborts the whole transaction on a
    failed statement, so a shared connection that hit a missing table would
    answer None for every probe after it as well - reporting the first table as
    unqueryable and then, wrongly, the rest.
    """
    try:
        async with engine.connect() as conn:
            result = await conn.execute(probe)
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

    Every column is probed even once one has already answered yes. The message
    names which of them are affected, and "recipients and delivery logs" is a
    different remediation conversation from either alone - one extra bounded
    query at startup is a cheap price for not making the operator find out by
    elimination.
    """
    if get_cipher() is not None:
        logger.debug("Encryption key configured; encrypted columns are readable by this process")
        return

    probes: tuple[tuple[str, Select[Any]], ...] = (
        (f"{Recipient.__tablename__}.webhook_headers", _encrypted_recipient_probe()),
        (f"{DeliveryLog.__tablename__}.payload", _encrypted_delivery_log_probe()),
    )

    encrypted: list[str] = []
    for column, probe in probes:
        has_encrypted = await _has_encrypted_rows(engine, probe)
        if has_encrypted is None:
            logger.warning(
                "Could not check %s for encrypted rows; it could not be queried, so "
                "no encryption key check was made against it",
                column,
            )
        elif has_encrypted:
            encrypted.append(column)
        else:
            logger.debug("No encrypted rows found in %s; no key needed for it", column)

    if not encrypted:
        return

    columns = " and ".join(encrypted)
    raise EncryptionKeyMissingError(
        f"Rows in {columns} are encrypted but no encryption key is configured. "
        f"Set {KEYS_SETTING} to the key they were written with before starting this "
        f"version -- every read of an affected row would otherwise fail, including "
        f"the webhook worker's, and the values stored in those columns would be "
        f"unrecoverable."
    )
