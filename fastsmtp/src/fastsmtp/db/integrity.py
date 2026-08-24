"""Classifying database integrity errors.

Lives in the database layer, not with the HTTP helpers, because every writer
that backs a duplicate pre-check with a unique index needs it: the API routers
translate a lost race into a 409 (``api.validation.flush_or_http_conflict``),
and the server CLI into an exit message. The CLI must stay importable without
FastAPI, so this module depends on SQLAlchemy alone.
"""

from sqlalchemy.exc import IntegrityError


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
