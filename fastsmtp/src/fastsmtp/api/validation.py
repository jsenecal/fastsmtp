"""Shared request validation helpers for the API."""

from typing import Annotated

from fastapi import HTTPException, Query, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.config import Settings
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
