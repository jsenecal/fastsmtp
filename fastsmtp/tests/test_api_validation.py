"""Tests for the shared API validation helpers."""

from fastsmtp.api.validation import is_unique_violation
from sqlalchemy.exc import IntegrityError


def _integrity_error(orig: BaseException) -> IntegrityError:
    return IntegrityError("stmt", None, orig)


class _PgError(Exception):
    """Stub shaped like asyncpg's exceptions: SQLSTATE on the error itself."""

    def __init__(self, sqlstate: str):
        self.sqlstate = sqlstate


class _AdapterError(Exception):
    """Stub shaped like SQLAlchemy's asyncpg adapter: SQLSTATE on __cause__."""

    def __init__(self, sqlstate: str):
        self.__cause__ = _PgError(sqlstate)


class TestIsUniqueViolation:
    """The predicate must be structural, not driver-prose matching.

    SQLite names columns, not indexes, in its messages ("UNIQUE constraint
    failed: recipients.domain_id, recipients.local_part"), so index-name
    matching silently misses there — the shape this predicate replaced.
    """

    def test_postgres_unique_violation_direct(self):
        assert is_unique_violation(_integrity_error(_PgError("23505"))) is True

    def test_postgres_unique_violation_on_cause(self):
        assert is_unique_violation(_integrity_error(_AdapterError("23505"))) is True

    def test_postgres_foreign_key_violation(self):
        assert is_unique_violation(_integrity_error(_PgError("23503"))) is False

    def test_sqlite_unique_violation_names_columns(self):
        orig = Exception("UNIQUE constraint failed: recipients.domain_id, recipients.local_part")
        assert is_unique_violation(_integrity_error(orig)) is True

    def test_sqlite_foreign_key_violation(self):
        orig = Exception("FOREIGN KEY constraint failed")
        assert is_unique_violation(_integrity_error(orig)) is False
