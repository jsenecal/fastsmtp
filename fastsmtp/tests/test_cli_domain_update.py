"""Tests for ``fastsmtp domain update`` (issue #141).

The five override columns are nullable and NULL means "inherit the server-wide
setting", so the command is tri-state rather than a pair of boolean flags:
``true``, ``false`` and ``inherit`` are three distinct writes, and an option
that is not given must not write at all. Those four cases are what this file
pins, per column.

The other property here is that a local command still refuses
``preserve_raw_message`` when S3 is unconfigured. The API refuses it in
``api/validation.py`` and this command never goes near the API, so without its
own check it would happily write a flag the SMTP server cannot act on. Both
sides now ask ``Settings.raw_preservation_unavailable``.

Harness as in test_cli_admin.py: the ``db`` and ``run`` fixtures come from
conftest, which points the CLI's own session factory at the test database.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from cli_harness import Db
from fastsmtp.config import clear_settings_cache
from fastsmtp.db.models import Domain
from fastsmtp.db.soft_delete import soft_delete_domain
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

DELETED = datetime(2021, 6, 15, 12, 30, 45, tzinfo=UTC)

#: The five nullable override columns, in the order the command applies them.
OVERRIDES = (
    ("--verify-dkim", "verify_dkim"),
    ("--verify-spf", "verify_spf"),
    ("--reject-dkim-fail", "reject_dkim_fail"),
    ("--reject-spf-fail", "reject_spf_fail"),
    ("--preserve-raw-message", "preserve_raw_message"),
)


def seed_domain(
    db: Db, domain_name: str, *, deleted_at: datetime | None = None, **fields: Any
) -> uuid.UUID:
    async def go(session: AsyncSession) -> uuid.UUID:
        domain = Domain(domain_name=domain_name, **fields)
        session.add(domain)
        await session.flush()
        if deleted_at is not None:
            await soft_delete_domain(session, domain, now=deleted_at)
        return domain.id

    result: uuid.UUID = db(go)
    return result


def domains_named(db: Db, domain_name: str) -> list[Domain]:
    """Every row of that name, tombstones included, oldest first."""

    async def go(session: AsyncSession) -> list[Domain]:
        stmt = select(Domain).where(Domain.domain_name == domain_name).order_by(Domain.created_at)
        return list((await session.execute(stmt)).scalars().all())

    result: list[Domain] = db(go)
    return result


def one_domain(db: Db, domain_name: str) -> Domain:
    (domain,) = domains_named(db, domain_name)
    return domain


@pytest.fixture
def s3(monkeypatch):
    """Configure or clear the process S3 settings the preservation check reads.

    Goes through the environment and the settings cache rather than patching
    the check, so the command resolves the same ``Settings`` an operator's
    shell would give it. The cache is cleared on the way out too: it is
    process-wide and would otherwise leak into whatever runs next.
    """
    variables = (
        ("FASTSMTP_S3_BUCKET", "archive"),
        ("FASTSMTP_S3_ACCESS_KEY", "key"),
        ("FASTSMTP_S3_SECRET_KEY", "secret"),
    )

    def configure(configured: bool) -> None:
        for name, value in variables:
            if configured:
                monkeypatch.setenv(name, value)
            else:
                monkeypatch.delenv(name, raising=False)
        clear_settings_cache()

    yield configure

    clear_settings_cache()


class TestTriStateWrites:
    """true, false and inherit are three writes; a missing option is not a write."""

    @pytest.mark.parametrize("option,column", OVERRIDES)
    @pytest.mark.parametrize("word,written", [("true", True), ("false", False)])
    def test_explicit_value_is_written(self, run, db, s3, option, column, word, written):
        s3(True)  # so --preserve-raw-message true is not refused here
        seed_domain(db, "example.com")

        code, out = run("domain", "update", "example.com", option, word)
        assert code == 0, out
        assert getattr(one_domain(db, "example.com"), column) is written
        assert f"{column}={word}" in out

    @pytest.mark.parametrize("option,column", OVERRIDES)
    def test_inherit_clears_the_override_to_null(self, run, db, option, column):
        """inherit is not false: it removes the row's opinion entirely."""
        seed_domain(db, "example.com", **{column: True})

        code, out = run("domain", "update", "example.com", option, "inherit")
        assert code == 0, out
        assert getattr(one_domain(db, "example.com"), column) is None
        assert f"{column}=inherit" in out

    def test_an_option_not_given_leaves_its_column_untouched(self, run, db):
        seeded = {
            "verify_dkim": True,
            "verify_spf": False,
            "reject_dkim_fail": True,
            "reject_spf_fail": None,
            "preserve_raw_message": True,
        }
        seed_domain(db, "example.com", **seeded)

        code, out = run("domain", "update", "example.com", "--verify-spf", "true")
        assert code == 0, out

        domain = one_domain(db, "example.com")
        assert domain.verify_spf is True
        assert domain.verify_dkim is True
        assert domain.reject_dkim_fail is True
        assert domain.reject_spf_fail is None
        assert domain.preserve_raw_message is True
        # The report names only what moved.
        assert "verify_dkim" not in out
        assert "preserve_raw_message" not in out

    def test_several_options_in_one_call(self, run, db):
        seed_domain(db, "example.com", verify_dkim=True)

        code, out = run(
            "domain",
            "update",
            "example.com",
            "--disable",
            "--verify-dkim",
            "inherit",
            "--reject-spf-fail",
            "true",
        )
        assert code == 0, out
        domain = one_domain(db, "example.com")
        assert domain.is_enabled is False
        assert domain.verify_dkim is None
        assert domain.reject_spf_fail is True


class TestEnabledFlag:
    """is_enabled is NOT NULL, so it is a paired flag rather than a tri-state."""

    def test_disable_then_enable(self, run, db):
        seed_domain(db, "example.com")

        code, out = run("domain", "update", "example.com", "--disable")
        assert code == 0, out
        assert one_domain(db, "example.com").is_enabled is False
        assert "is_enabled=false" in out

        code, out = run("domain", "update", "example.com", "--enable")
        assert code == 0, out
        assert one_domain(db, "example.com").is_enabled is True
        assert "is_enabled=true" in out

    def test_not_given_leaves_it_alone(self, run, db):
        seed_domain(db, "example.com", is_enabled=False)

        code, out = run("domain", "update", "example.com", "--verify-dkim", "true")
        assert code == 0, out
        assert one_domain(db, "example.com").is_enabled is False


class TestNoOptions:
    def test_is_an_error_rather_than_a_silent_no_op(self, run, db):
        seed_domain(db, "example.com")

        code, out = run("domain", "update", "example.com")
        assert code == 1
        assert "At least one option must be provided" in out

    def test_the_check_happens_before_the_domain_is_looked_up(self, run, db):
        """Nothing was seeded: a usage error must not depend on the database."""
        code, out = run("domain", "update", "nosuch.example.com")
        assert code == 1
        assert "At least one option must be provided" in out
        assert "not found" not in out


class TestPreserveRawMessageNeedsS3:
    """The SMTP server cannot honour the flag without S3, so it is refused here too."""

    def test_true_is_refused_when_s3_is_unconfigured(self, run, db, s3):
        s3(False)
        seed_domain(db, "example.com")

        code, out = run("domain", "update", "example.com", "--preserve-raw-message", "true")
        assert code == 1
        assert "Raw message preservation requires S3 storage to be configured" in out
        assert "s3_bucket" in out
        # Refused means nothing was written, not written-and-warned.
        assert one_domain(db, "example.com").preserve_raw_message is None

    def test_true_is_accepted_when_s3_is_configured(self, run, db, s3):
        s3(True)
        seed_domain(db, "example.com")

        code, out = run("domain", "update", "example.com", "--preserve-raw-message", "true")
        assert code == 0, out
        assert one_domain(db, "example.com").preserve_raw_message is True

    @pytest.mark.parametrize("word,expected", [("false", False), ("inherit", None)])
    def test_turning_it_off_never_needs_s3(self, run, db, s3, word, expected):
        """Only enabling is refused; a domain must be able to stop preserving."""
        s3(False)
        seed_domain(db, "example.com", preserve_raw_message=True)

        code, out = run("domain", "update", "example.com", "--preserve-raw-message", word)
        assert code == 0, out
        assert one_domain(db, "example.com").preserve_raw_message is expected

    def test_a_refusal_blocks_the_whole_call(self, run, db, s3):
        """The other options in the same call are not applied piecemeal."""
        s3(False)
        seed_domain(db, "example.com")

        code, out = run(
            "domain",
            "update",
            "example.com",
            "--disable",
            "--preserve-raw-message",
            "true",
        )
        assert code == 1
        assert one_domain(db, "example.com").is_enabled is True


class TestNameLookupResolvesTheLiveRow:
    def test_a_deleted_domain_is_not_found(self, run, db):
        seed_domain(db, "example.com", deleted_at=DELETED)

        code, out = run("domain", "update", "example.com", "--disable")
        assert code == 1
        assert "Domain 'example.com' not found" in out
        assert one_domain(db, "example.com").is_enabled is True

    def test_a_tombstone_sharing_the_name_is_never_updated(self, run, db):
        dead = seed_domain(db, "example.com", deleted_at=DELETED)
        live = seed_domain(db, "example.com")

        code, out = run("domain", "update", "example.com", "--verify-dkim", "true")
        assert code == 0, out
        by_id = {domain.id: domain for domain in domains_named(db, "example.com")}
        assert by_id[live].verify_dkim is True
        assert by_id[dead].verify_dkim is None
