"""The Alembic migration chain, exercised against a throwaway database.

Every other test in this suite gets its schema from ``Base.metadata.create_all``
(see the ``test_engine`` fixture in conftest), so the migrations never run. A
migration can be broken, irreversible, or produce a schema the models do not
describe, and the rest of the suite still passes.

These tests close that gap: they apply the chain to an empty database, roll it
back to base and re-apply it, then diff the result against ``Base.metadata``.

Marked ``migrations`` so it can be deselected locally with ``-m "not
migrations"``. CI runs the suite unfiltered, so it always runs there.
"""

import subprocess
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from email.message import EmailMessage
from functools import partial
from typing import Any

import pytest
import pytest_asyncio
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from anyio import to_thread
from fastsmtp.db.migrations import expected_head_revision
from fastsmtp.db.models import Base, Rule
from fastsmtp.rules.conditions import evaluate_condition
from fastsmtp.rules.engine import evaluate_rule, extract_field_values
from fastsmtp.smtp.validation import EmailAuthResult
from sqlalchemy import Connection, make_url, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, create_async_engine

pytestmark = pytest.mark.migrations

# The session container's default database holds the create_all schema the rest
# of the suite drops and rebuilds per test, so the chain gets its own.
MIGRATION_DATABASE = "fastsmtp_migration_test"


def _run_alembic(
    environ: dict[str, str], database_url: str, *args: str
) -> subprocess.CompletedProcess[str]:
    """Run one ``fastsmtp db`` command against ``database_url`` in a child process.

    ``alembic/env.py`` drives the migrations with ``asyncio.run``, which makes
    it hostile to in-process invocation from an async test; a child process
    also matches how migrations are applied for real.

    The command is the operator's, not Alembic's own CLI: the migrations ship
    inside the package with no ini file, so ``fastsmtp db`` is the only
    supported way to run them, and driving the chain through it means the
    documented upgrade path is what these tests exercise.

    ``environ`` is the ``scrubbed_environ`` fixture: no ``FASTSMTP_*`` variable
    from the session leaks in, so the chain runs the way a migration Job does,
    with the database URL and nothing else.
    """
    return subprocess.run(
        [sys.executable, "-m", "fastsmtp.cli", "db", *args],
        env={**environ, "FASTSMTP_DATABASE_URL": database_url},
        capture_output=True,
        text=True,
    )


async def alembic(
    environ: dict[str, str], database_url: str, *args: str
) -> subprocess.CompletedProcess[str]:
    """Run a migration command off the event loop, failing on a non-zero exit."""
    result = await to_thread.run_sync(partial(_run_alembic, environ, database_url, *args))
    if result.returncode != 0:
        pytest.fail(
            f"`fastsmtp db {' '.join(args)}` exited {result.returncode}\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )
    return result


@asynccontextmanager
async def connected(database_url: str, **engine_kwargs: Any) -> AsyncIterator[AsyncConnection]:
    """Yield a connection to ``database_url``, disposing the engine afterwards."""
    engine = create_async_engine(database_url, **engine_kwargs)
    try:
        async with engine.connect() as connection:
            yield connection
    finally:
        await engine.dispose()


async def run_autocommit(database_url: str, *statements: str) -> None:
    """Run statements that cannot sit in a transaction, such as CREATE DATABASE."""
    async with connected(database_url, isolation_level="AUTOCOMMIT") as connection:
        for statement in statements:
            await connection.execute(text(statement))


async def public_tables(database_url: str) -> set[str]:
    """Return the table names in the public schema."""
    async with connected(database_url) as connection:
        result = await connection.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        )
        return {row[0] for row in result}


def _diff_against_models(sync_connection: Connection) -> list[Any]:
    """Diff the connected database against the models. Runs on a sync connection.

    Server defaults are deliberately left out of the comparison (alembic's
    default): the models set most defaults Python-side while the migrations set
    them in DDL, and that difference is by design rather than drift.
    """
    return compare_metadata(MigrationContext.configure(sync_connection), Base.metadata)


@pytest_asyncio.fixture
async def migration_database_url(postgres_url: str) -> AsyncIterator[str]:
    """Create an empty database for a migration run and drop it afterwards."""
    drop = f'DROP DATABASE IF EXISTS "{MIGRATION_DATABASE}" WITH (FORCE)'
    await run_autocommit(postgres_url, drop, f'CREATE DATABASE "{MIGRATION_DATABASE}"')
    try:
        yield (
            make_url(postgres_url)
            .set(database=MIGRATION_DATABASE)
            .render_as_string(hide_password=False)
        )
    finally:
        await run_autocommit(postgres_url, drop)


async def test_migration_chain_is_reversible(
    scrubbed_environ: dict[str, str], migration_database_url: str
) -> None:
    """upgrade head -> downgrade base -> upgrade head, with nothing left behind.

    A downgrade that leaves a table standing makes the next upgrade fail on an
    already-existing object, which only shows up on a rollback in production.
    """
    await alembic(scrubbed_environ, migration_database_url, "upgrade", "head")
    await alembic(scrubbed_environ, migration_database_url, "downgrade", "base")

    left_behind = await public_tables(migration_database_url) - {"alembic_version"}
    assert not left_behind, f"downgrade base left tables behind: {sorted(left_behind)}"

    await alembic(scrubbed_environ, migration_database_url, "upgrade", "head")


async def test_upgrade_reports_the_revisions_it_applied(
    scrubbed_environ: dict[str, str], migration_database_url: str
) -> None:
    """An operator has to be able to see what ran, not just that it exited 0.

    Alembic announces each revision through its own logger, which the CLI has
    to give a handler now that alembic.ini is gone. It nearly did not: the
    library attaches a NullHandler to that logger at import, so a guard that
    only asked whether the logger had handlers left the output going nowhere
    and the chain applied in complete silence.
    """
    result = await alembic(scrubbed_environ, migration_database_url, "upgrade", "head")

    reported = result.stdout + result.stderr
    assert "Running upgrade" in reported, f"upgrade said nothing:\n{reported!r}"
    assert "008" in reported


async def test_migrated_schema_matches_models(
    scrubbed_environ: dict[str, str], migration_database_url: str
) -> None:
    """`alembic upgrade head` must produce exactly the schema the models declare.

    This is the check that turns "the migration ran" into "the migration built
    what the code expects" - a model change merged without its migration fails
    here instead of on deploy.
    """
    await alembic(scrubbed_environ, migration_database_url, "upgrade", "head")

    async with connected(migration_database_url) as connection:
        differences = await connection.run_sync(_diff_against_models)

    assert not differences, "migrated schema differs from Base.metadata:\n" + "\n".join(
        f"  {difference!r}" for difference in differences
    )


# (table, name column, sample value) for the two name indexes 008 rebuilds as
# partial unique indexes over live rows only.
NAME_INDEX_CASES = [
    pytest.param("users", "username", "alice", id="users"),
    pytest.param("domains", "domain_name", "example.com", id="domains"),
]


def _insert_named_row(table: str, column: str, tombstoned: bool) -> str:
    """Raw INSERT of a live or tombstoned row; every other column has a default."""
    deleted_at = "now()" if tombstoned else "NULL"
    return (
        f"INSERT INTO {table} (id, {column}, deleted_at) "
        f"VALUES (gen_random_uuid(), :name, {deleted_at})"
    )


async def _insert_live_and_tombstone(database_url: str, table: str, column: str, name: str) -> None:
    async with connected(database_url) as connection:
        for tombstoned in (True, False):
            await connection.execute(
                text(_insert_named_row(table, column, tombstoned)), {"name": name}
            )
        await connection.commit()


@pytest.mark.parametrize(("table", "column", "name"), NAME_INDEX_CASES)
async def test_008_allows_live_after_tombstone_names(
    scrubbed_environ: dict[str, str],
    migration_database_url: str,
    table: str,
    column: str,
    name: str,
) -> None:
    """At head, a live row may share its name with a tombstone, but not with a live row.

    This is the property 008 exists for: deleting alice / example.com and
    recreating the name is a routine admin operation, and the database - not
    only the API pre-check - has to allow it while still rejecting duplicates
    among live rows.
    """
    await alembic(scrubbed_environ, migration_database_url, "upgrade", "head")
    await _insert_live_and_tombstone(migration_database_url, table, column, name)

    async with connected(migration_database_url) as connection:
        with pytest.raises(IntegrityError):
            await connection.execute(
                text(_insert_named_row(table, column, tombstoned=False)), {"name": name}
            )
        await connection.rollback()


@pytest.mark.parametrize(("table", "column", "name"), NAME_INDEX_CASES)
async def test_008_downgrade_refuses_live_and_tombstone_pair(
    scrubbed_environ: dict[str, str],
    migration_database_url: str,
    table: str,
    column: str,
    name: str,
) -> None:
    """Downgrading past 008 with a live/tombstone name pair fails loudly.

    The old, unconditional unique index cannot hold both rows. As with
    005-007, the migration refuses rather than deduplicating: silently
    deleting a user or a domain to make an index fit is not a rollback.
    The failure is transactional, so the database is left at 008 and a
    subsequent ``upgrade head`` is a clean no-op.
    """
    await alembic(scrubbed_environ, migration_database_url, "upgrade", "head")
    await _insert_live_and_tombstone(migration_database_url, table, column, name)

    result = await to_thread.run_sync(
        partial(_run_alembic, scrubbed_environ, migration_database_url, "downgrade", "007")
    )
    assert result.returncode != 0, "downgrade 007 succeeded over a live/tombstone name pair"

    # The whole downgrade is one transaction, so a failure in 008 also rolls
    # back any later revision undone before it: the database stays at head.
    async with connected(migration_database_url) as connection:
        version = await connection.execute(text("SELECT version_num FROM alembic_version"))
        assert version.scalar_one() == expected_head_revision()

    await alembic(scrubbed_environ, migration_database_url, "upgrade", "head")


# -- 009: rule conditions -----------------------------------------------------

# Every flat rule shape worth having an opinion about: each field against each
# operator, values that hit one of the messages below and values that miss,
# both case modes. "Property-style": the whole grid, not a hand-picked example,
# has to evaluate the same before and after.
FLAT_RULE_FIELDS = {
    "from": ["Alice@Example.com", "@example.com", r"^alice@"],
    "to": ["inbox@example.org", "nobody"],
    "subject": ["Invoice", "invoice 42", r"\d+$"],
    "body": ["hello", "HELLO WORLD"],
    "has_attachment": ["true", "false"],
    "attachment_names": [".exe", "report.pdf", r"\.(exe|bat)$"],
    "attachment_types": ["application/pdf", "pdf"],
    "dkim_result": ["pass", "fail"],
    "spf_result": ["pass", "softfail"],
    "header:Auto-Submitted": ["auto-generated", "no"],
    "header:X-Absent": ["anything"],
}
FLAT_RULE_OPERATORS = ("equals", "contains", "starts_with", "ends_with", "regex", "exists")


def _auth(dkim: str, spf: str) -> EmailAuthResult:
    return EmailAuthResult(
        dkim_result=dkim,
        dkim_domain=None,
        dkim_selector=None,
        spf_result=spf,
        spf_domain=None,
        client_ip="192.0.2.1",
    )


def _migration_samples() -> list[tuple[EmailMessage, dict[str, Any], EmailAuthResult | None]]:
    """(message, payload, auth_result) triples the flat-rule grid is judged against."""
    automated = EmailMessage()
    automated["From"] = "alice@example.com"
    automated["To"] = "inbox@example.org"
    automated["Subject"] = "Invoice 42"
    automated["Auto-Submitted"] = "auto-generated"
    automated_payload = {
        "from": "alice@example.com",
        "to": "inbox@example.org",
        "subject": "Invoice 42",
        "body_text": "Hello world",
        "has_attachments": True,
        "attachments": [
            {"filename": "report.pdf", "content_type": "application/pdf"},
            {"filename": "run.exe", "content_type": "application/x-msdownload"},
        ],
    }

    plain = EmailMessage()
    plain["From"] = "bob@other.net"
    plain["Subject"] = "lunch?"
    plain_payload = {"from": "bob@other.net", "subject": "lunch?", "body_text": "hi"}

    return [
        (automated, automated_payload, _auth("pass", "softfail")),
        (plain, plain_payload, _auth("fail", "pass")),
        (plain, plain_payload, None),
    ]


def _flat_verdict(
    flat: tuple[str, str, str, bool],
    sample: tuple[EmailMessage, dict[str, Any], EmailAuthResult | None],
) -> bool:
    """How a flat rule evaluated before 009: any extracted value satisfies the condition."""
    field, operator, value, case_sensitive = flat
    values = extract_field_values(field, *sample)
    if values is None:
        return False
    return any(evaluate_condition(operator, v, value, case_sensitive) for v in values)


async def _insert_ruleset(connection: AsyncConnection) -> str:
    domain = await connection.execute(
        text(
            "INSERT INTO domains (id, domain_name) "
            "VALUES (gen_random_uuid(), 'm.test') RETURNING id"
        )
    )
    ruleset = await connection.execute(
        text(
            "INSERT INTO rulesets (id, domain_id, name) "
            "VALUES (gen_random_uuid(), :domain, 'rs') RETURNING id"
        ),
        {"domain": domain.scalar_one()},
    )
    return str(ruleset.scalar_one())


async def _insert_flat_rules(database_url: str) -> dict[str, tuple[str, str, str, bool]]:
    """Insert, at 008, one flat rule per grid point; map each id to its shape."""
    grid = [
        (field, operator, value, case_sensitive)
        for field, values in FLAT_RULE_FIELDS.items()
        for operator in FLAT_RULE_OPERATORS
        for value in values
        for case_sensitive in (False, True)
    ]
    flat_rules = {}
    async with connected(database_url) as connection:
        ruleset_id = await _insert_ruleset(connection)
        for order, (field, operator, value, case_sensitive) in enumerate(grid):
            inserted = await connection.execute(
                text(
                    'INSERT INTO rules (id, ruleset_id, "order", field, operator, value, '
                    "case_sensitive, action, add_tags, preserve_raw) "
                    "VALUES (gen_random_uuid(), :ruleset, :order, :field, :operator, :value, "
                    ":case_sensitive, 'tag', '[]'::jsonb, false) RETURNING id"
                ),
                {
                    "ruleset": ruleset_id,
                    "order": order,
                    "field": field,
                    "operator": operator,
                    "value": value,
                    "case_sensitive": case_sensitive,
                },
            )
            flat_rules[str(inserted.scalar_one())] = (field, operator, value, case_sensitive)
        await connection.commit()
    return flat_rules


async def test_009_every_flat_rule_evaluates_identically(
    scrubbed_environ: dict[str, str], migration_database_url: str
) -> None:
    """Each pre-009 rule becomes one plain condition and keeps its verdict on every sample."""
    await alembic(scrubbed_environ, migration_database_url, "upgrade", "008")
    flat_rules = await _insert_flat_rules(migration_database_url)
    await alembic(scrubbed_environ, migration_database_url, "upgrade", "head")

    engine = create_async_engine(migration_database_url)
    try:
        async with AsyncSession(engine) as session:
            rules = (await session.execute(select(Rule))).scalars().all()
    finally:
        await engine.dispose()

    assert len(rules) == len(flat_rules)
    samples = _migration_samples()
    mismatches = []
    for rule in rules:
        flat = flat_rules[str(rule.id)]
        (condition,) = rule.conditions
        assert rule.match == "all"
        assert (condition.order, condition.negate) == (0, False)
        assert (
            condition.field,
            condition.operator,
            condition.value,
            condition.case_sensitive,
        ) == flat
        for index, sample in enumerate(samples):
            before = _flat_verdict(flat, sample)
            after = evaluate_rule(rule, *sample)
            if before != after:
                mismatches.append((flat, index, before, after))
    assert not mismatches, mismatches


async def _insert_rule_with_conditions(database_url: str, *negations: bool) -> str:
    """Insert, at 009, one rule holding a condition per entry in ``negations``."""
    async with connected(database_url) as connection:
        ruleset_id = await _insert_ruleset(connection)
        inserted = await connection.execute(
            text(
                'INSERT INTO rules (id, ruleset_id, "order", action, add_tags, preserve_raw) '
                "VALUES (gen_random_uuid(), :ruleset, 0, 'drop', '[]'::jsonb, false) "
                "RETURNING id"
            ),
            {"ruleset": ruleset_id},
        )
        rule_id = inserted.scalar_one()
        for order, negate in enumerate(negations):
            await connection.execute(
                text(
                    'INSERT INTO rule_conditions (id, rule_id, "order", field, operator, value, '
                    "case_sensitive, negate) VALUES (gen_random_uuid(), :rule, :order, "
                    "'subject', 'contains', :value, true, :negate)"
                ),
                {"rule": rule_id, "order": order, "value": f"v{order}", "negate": negate},
            )
        await connection.commit()
    return str(rule_id)


async def test_009_downgrade_restores_a_single_condition_rule(
    scrubbed_environ: dict[str, str], migration_database_url: str
) -> None:
    await alembic(scrubbed_environ, migration_database_url, "upgrade", "head")
    rule_id = await _insert_rule_with_conditions(migration_database_url, False)

    await alembic(scrubbed_environ, migration_database_url, "downgrade", "008")

    async with connected(migration_database_url) as connection:
        row = await connection.execute(
            text("SELECT field, operator, value, case_sensitive FROM rules WHERE id = :id"),
            {"id": rule_id},
        )
        assert tuple(row.one()) == ("subject", "contains", "v0", True)

    await alembic(scrubbed_environ, migration_database_url, "upgrade", "head")


@pytest.mark.parametrize(
    "negations",
    [pytest.param((False, False), id="two-conditions"), pytest.param((True,), id="negated")],
)
async def test_009_downgrade_refuses_rules_the_flat_shape_cannot_hold(
    scrubbed_environ: dict[str, str], migration_database_url: str, negations: tuple[bool, ...]
) -> None:
    """Dropping a condition broadens a rule and dropping a negation inverts it: refuse.

    The failure is transactional, so the database is left at 009.
    """
    await alembic(scrubbed_environ, migration_database_url, "upgrade", "head")
    await _insert_rule_with_conditions(migration_database_url, *negations)

    result = await to_thread.run_sync(
        partial(_run_alembic, scrubbed_environ, migration_database_url, "downgrade", "008")
    )
    assert result.returncode != 0, "downgrade 008 succeeded over a rule it cannot represent"
    assert "Cannot downgrade past 009" in result.stdout + result.stderr

    async with connected(migration_database_url) as connection:
        version = await connection.execute(text("SELECT version_num FROM alembic_version"))
        assert version.scalar_one() == "009"
