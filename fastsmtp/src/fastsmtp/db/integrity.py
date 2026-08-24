"""Uniqueness over live rows: the pre-check and the backstop.

Migration 008 made the name indexes (``users.username``, ``domains.domain_name``)
partial over live rows, so a tombstone never blocks its name. Every writer
that creates or restores a named row does the same two things: ask
:func:`live_value_taken` first, for a readable error, and treat a unique
violation on flush or commit, classified by :func:`is_unique_violation`, as
the lost race. The API routers translate that into a 409
(``api.validation.flush_or_http_conflict``) and the server CLI into an exit
message.

This module lives in the database layer so both can share it: the CLI must
stay importable without FastAPI, so it depends on SQLAlchemy and the models
alone.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute

from fastsmtp.db.models import Domain, User


async def live_value_taken[Named: (User, Domain)](
    session: AsyncSession,
    model: type[Named],
    column: InstrumentedAttribute[str],
    value: str,
    *,
    exclude_id: uuid.UUID | None = None,
) -> bool:
    """Duplicate pre-check for a name column that is unique over live rows.

    ``model`` is taken explicitly, bound to the models whose name index is
    partial over live rows (``User.username``, ``Domain.domain_name``), so a
    column from a model without ``live()`` is a type error rather than an
    ``AttributeError`` at request time. Mirrors what the database enforces:
    a tombstone never blocks its name. ``exclude_id`` leaves out the row
    being updated, which holds its own name legitimately. The check is
    check-then-flush; the index is the backstop, translated by
    :func:`is_unique_violation`.

    The user and domain create, update and restore paths in the routers and
    the CLI all share this one predicate, so it cannot drift from the index
    in only one of them. Recipients are the deliberate exception:
    ``api.recipients._local_part_taken`` stays its own query because the
    catch-all is ``local_part IS NULL``, which no ``column == value`` can
    express.
    """
    stmt = select(model.id).where(column == value, model.live())
    if exclude_id is not None:
        stmt = stmt.where(model.id != exclude_id)
    return (await session.execute(stmt)).first() is not None


def is_unique_violation(exc: IntegrityError) -> bool:
    """True when an IntegrityError is a unique-constraint violation.

    Checked structurally, not by matching driver prose: PostgreSQL reports
    SQLSTATE 23505 (asyncpg puts it on the wrapped exception's cause), and
    SQLite has no SQLSTATE but a stable message prefix. Foreign-key failures
    (23503 / "FOREIGN KEY constraint failed") return False.
    """
    orig = exc.orig
    for candidate in (orig, getattr(orig, "__cause__", None)):
        code = getattr(candidate, "sqlstate", None) or getattr(candidate, "pgcode", None)
        if code:
            return code == "23505"
    return "UNIQUE constraint failed" in str(orig)
