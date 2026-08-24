"""Tests for the shared API validation helpers."""

from datetime import UTC, datetime
from typing import get_args

import pytest
from fastapi import HTTPException
from fastapi.params import Query
from fastsmtp.api import validation
from fastsmtp.api.validation import IncludeDeleted, Purge, require_tombstoned
from fastsmtp.db.integrity import is_unique_violation, live_value_taken
from fastsmtp.db.models import Domain, User
from pydantic_core import PydanticUndefined
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession


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

    def test_api_validation_re_exports_the_db_predicate(self):
        """The predicate is a DBAPI concern and lives with the database layer,
        where the server CLI can import it without loading FastAPI; the API
        module keeps the name for its existing importers."""
        assert validation.is_unique_violation is is_unique_violation


class TestLiveValueTaken:
    """One duplicate pre-check for every partial unique index over live rows.

    Mirrors what migration 008 enforces for ``users.username`` and
    ``domains.domain_name``: a tombstone never blocks its name. The check is
    check-then-flush; the index is the backstop, translated by
    ``flush_or_http_conflict``.
    """

    def test_api_validation_re_exports_the_db_predicate(self):
        """The routers and the server CLI must run the same query, so the
        predicate lives in the database layer and the API module re-exports it."""
        assert validation.live_value_taken is live_value_taken

    @pytest.mark.asyncio
    async def test_live_row_takes_the_name(self, test_session: AsyncSession):
        test_session.add(User(username="taken", is_active=True))
        await test_session.flush()

        assert await live_value_taken(test_session, User, User.username, "taken") is True
        assert await live_value_taken(test_session, User, User.username, "free") is False

    @pytest.mark.asyncio
    async def test_tombstone_does_not_take_the_name(self, test_session: AsyncSession):
        test_session.add(User(username="gone", is_active=True, deleted_at=datetime.now(UTC)))
        await test_session.flush()

        assert await live_value_taken(test_session, User, User.username, "gone") is False

    @pytest.mark.asyncio
    async def test_exclude_id_ignores_the_row_being_updated(self, test_session: AsyncSession):
        me = User(username="myself", is_active=True)
        test_session.add(me)
        await test_session.flush()

        assert await live_value_taken(test_session, User, User.username, "myself") is True
        assert (
            await live_value_taken(test_session, User, User.username, "myself", exclude_id=me.id)
            is False
        )

    @pytest.mark.asyncio
    async def test_works_on_any_soft_deletable_name_column(self, test_session: AsyncSession):
        test_session.add(Domain(domain_name="live.example"))
        test_session.add(Domain(domain_name="dead.example", deleted_at=datetime.now(UTC)))
        await test_session.flush()

        assert (
            await live_value_taken(test_session, Domain, Domain.domain_name, "live.example") is True
        )
        assert (
            await live_value_taken(test_session, Domain, Domain.domain_name, "dead.example")
            is False
        )


class TestRequireTombstoned:
    """Purge and restore only make sense on a row that is already deleted."""

    def test_passes_on_a_tombstone(self):
        domain = Domain(domain_name="gone.example", deleted_at=datetime.now(UTC))
        require_tombstoned(domain, "Domain is not deleted")

    def test_raises_409_with_the_given_detail_on_a_live_row(self):
        domain = Domain(domain_name="live.example")
        with pytest.raises(HTTPException) as exc_info:
            require_tombstoned(domain, "Domain must be deleted before it can be purged")
        assert exc_info.value.status_code == 409
        assert exc_info.value.detail == "Domain must be deleted before it can be purged"


class TestSoftDeleteQueryAliases:
    """The shared ``include_deleted`` / ``purge`` query-parameter aliases.

    The default has to live on the route parameter (``purge: Purge = False``),
    never inside ``Annotated``: FastAPI 0.128 asserts on ``Query(False)`` inside
    ``Annotated``, and a real ``False`` default is what keeps the direct-call
    tests in test_api_unit.py green.
    """

    @pytest.mark.parametrize("alias", [IncludeDeleted, Purge], ids=["include_deleted", "purge"])
    def test_alias_is_a_bool_query_without_a_default(self, alias):
        annotation, param = get_args(alias)
        assert annotation is bool
        assert isinstance(param, Query)
        assert param.default is PydanticUndefined
        assert param.description
