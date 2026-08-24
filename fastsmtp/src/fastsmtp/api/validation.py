"""Shared request validation helpers for the API."""

import uuid
from typing import Annotated

from fastapi import HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute

from fastsmtp.config import Settings

# Re-exported: the predicate lives with the database layer so the server CLI
# can use it without loading FastAPI; importers of this module keep the name.
from fastsmtp.db.integrity import is_unique_violation
from fastsmtp.db.models import SoftDeleteMixin
from fastsmtp.rules.conditions import validate_regex_pattern

# Query-parameter aliases shared by every route that exposes soft-delete
# controls. Declare them as ``include_deleted: IncludeDeleted = False`` /
# ``purge: Purge = False`` - the default goes on the parameter, never inside
# ``Annotated``: FastAPI 0.128 asserts on ``Query(False)`` inside ``Annotated``,
# and a real ``False`` default keeps the direct-call tests in test_api_unit.py
# working without a request.
IncludeDeleted = Annotated[
    bool,
    Query(description="Include soft-deleted rows (requires the role that may delete them)."),
]
Purge = Annotated[
    bool,
    Query(
        description="Permanently delete an already soft-deleted row. Superuser only. "
        "Cannot be undone."
    ),
]


def require_tombstoned(obj: SoftDeleteMixin, detail: str) -> None:
    """Reject purge or restore of a row that is not soft-deleted.

    Purge is only reachable on a tombstone so an accidental ``--purge`` on the
    wrong id is never a one-shot, unrecoverable delete; restore of a live row
    is simply a no-op the caller should know about.

    Raises:
        HTTPException: 409 with ``detail``
    """
    if obj.deleted_at is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


async def live_value_taken(
    session: AsyncSession,
    column: InstrumentedAttribute[str],
    value: str,
    *,
    exclude_id: uuid.UUID | None = None,
) -> bool:
    """Duplicate pre-check for a name column that is unique over live rows.

    ``column`` belongs to a ``SoftDeleteMixin`` model (``User.username``,
    ``Domain.domain_name``). Mirrors what the database enforces: the name
    indexes are partial over live rows (migration 008), so a tombstone never
    blocks its name. ``exclude_id`` leaves out the row being updated, which
    holds its own name legitimately. The check is check-then-flush; the index
    is the backstop, translated by :func:`flush_or_http_conflict`, and the
    create, update and restore routes all share this one predicate so it can
    never drift from the index in only one of them.
    """
    model = column.class_
    stmt = select(model.id).where(column == value, model.live())
    if exclude_id is not None:
        stmt = stmt.where(model.id != exclude_id)
    return (await session.execute(stmt)).first() is not None


async def flush_or_http_conflict(session: AsyncSession, conflict: HTTPException) -> None:
    """Flush, translating a lost unique-constraint race into ``conflict``.

    Duplicate pre-checks in the API are check-then-flush, so two concurrent
    writes can both pass and the loser hits a unique index here; the index is
    the deliberate backstop, this keeps the status code honest. The caller
    owns the guarantee that ``conflict`` describes the only unique constraint
    this flush can plausibly violate. Other integrity failures (foreign keys)
    propagate unchanged.
    """
    try:
        await session.flush()
    except IntegrityError as exc:
        if not is_unique_violation(exc):
            raise
        await session.rollback()
        raise conflict from exc


def require_s3_for_preservation(settings: Settings) -> None:
    """Reject enabling raw message preservation when S3 is not configured.

    Domain and rule flags are stored in the database but acted on by the SMTP
    server, so without this check a flag would be accepted and then silently
    do nothing.

    Raises:
        HTTPException: 422 if the S3 settings needed for preservation are missing
    """
    missing = settings.missing_s3_settings()
    if missing:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                "Raw message preservation requires S3 storage to be configured. "
                f"Missing settings: {', '.join(missing)}"
            ),
        )


def require_valid_rule_regex(pattern: str) -> None:
    """Reject a rule regex pattern that RE2 cannot compile.

    The rule schemas already validate payloads that carry both operator and
    value, but rule updates are partial: changing only one of them can make
    the stored counterpart invalid (e.g. switching the operator to regex
    while the stored value uses a backreference). The update endpoint calls
    this on the merged state.

    Raises:
        HTTPException: 422 naming the compile error
    """
    try:
        validate_regex_pattern(pattern)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
