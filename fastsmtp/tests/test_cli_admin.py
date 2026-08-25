"""Tests for the server CLI's user and domain administration under soft delete.

Harness
-------
``test_engine`` builds the schema in the pytest-asyncio loop. Every CLI command
then runs in its own ``asyncio.run`` loop, and asyncpg connections are bound to
the loop that opened them, so ``fastsmtp.db.session.async_session`` is replaced
with a factory that builds a NullPool engine per session: the connection is
opened and closed inside whichever loop calls it. The same factory backs the
``db`` helper the tests use to seed rows and read state back.

What is pinned here: every name-addressed command resolves the *live* row when
a tombstone shares the name (before this, ``scalar_one_or_none`` raised
``MultipleResultsFound``), ``delete`` is soft and ``--purge`` only reaches a
tombstone, ``--id`` is refused without ``--purge`` rather than ignored,
``restore`` refuses ambiguity without ``--id``, ``create`` reports a lost race
as the same conflict as its pre-check, ``remove-member`` (an un-grant) reaches
a tombstoned user, ``purge-deleted`` decides the unconfigured case before it
opens a session, and no command writes ``deleted_at`` or calls
``session.delete`` itself.
"""

import inspect
import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cli_harness import Db
from fastsmtp.config import Settings
from fastsmtp.db.enums import DeliveryStatus
from fastsmtp.db.models import (
    APIKey,
    DeliveryLog,
    Domain,
    DomainMember,
    Recipient,
    RuleSet,
    User,
)
from fastsmtp.db.soft_delete import soft_delete_domain, soft_delete_user
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp import cli

OLDER = datetime(2020, 1, 1, tzinfo=UTC)
NEWER = datetime(2021, 6, 15, 12, 30, 45, tzinfo=UTC)
# Tombstone stamps render like the cleanup cutoffs: explicit UTC, everywhere.
NEWER_TEXT = "2021-06-15 12:30:45 UTC"

ID_NEEDS_PURGE = "--id only applies with --purge; delete addresses the live entry"


async def name_is_free(
    session: AsyncSession,
    model: type[User] | type[Domain],
    column: object,
    value: str,
    *,
    exclude_id: uuid.UUID | None = None,
) -> bool:
    """Stand-in for ``live_value_taken`` that sees no conflict: the race's loser.

    The lost-race tests patch this over ``cli.live_value_taken`` so the
    pre-check misses and the partial unique index has to be the backstop.
    Patching anything else leaves the real pre-check in place and the test
    passes without exercising ``_commit_or_conflict`` at all.
    """
    return False


# --- seeding -----------------------------------------------------------------


def seed_user(
    db: Db,
    username: str,
    *,
    deleted_at: datetime | None = None,
    keys: int = 0,
    **fields: Any,
) -> uuid.UUID:
    async def go(session: AsyncSession) -> uuid.UUID:
        user = User(username=username, **fields)
        session.add(user)
        await session.flush()
        for i in range(keys):
            session.add(
                APIKey(
                    user_id=user.id,
                    key_hash=f"hash-{uuid.uuid4()}",
                    key_salt="salt",
                    key_prefix=f"fsk_{i:04d}",
                    name=f"key-{i}",
                    scopes=[],
                )
            )
        await session.flush()
        if deleted_at is not None:
            await soft_delete_user(session, user, now=deleted_at)
        return user.id

    result: uuid.UUID = db(go)
    return result


def seed_domain(
    db: Db,
    domain_name: str,
    *,
    deleted_at: datetime | None = None,
    recipients: tuple[str | None, ...] = (),
    pending_deliveries: int = 0,
    ruleset: bool = False,
    member: uuid.UUID | None = None,
) -> uuid.UUID:
    async def go(session: AsyncSession) -> uuid.UUID:
        domain = Domain(domain_name=domain_name)
        session.add(domain)
        await session.flush()
        for local_part in recipients:
            recipient = Recipient(
                domain_id=domain.id, local_part=local_part, webhook_url="https://example.com/hook"
            )
            session.add(recipient)
            await session.flush()
            for _ in range(pending_deliveries):
                session.add(
                    DeliveryLog(
                        domain_id=domain.id,
                        recipient_id=recipient.id,
                        message_id=f"<{uuid.uuid4()}@example.com>",
                        webhook_url=recipient.webhook_url,
                        payload_hash="abc123",
                        payload={},
                        status=DeliveryStatus.PENDING.value,
                        attempts=0,
                        next_retry_at=datetime.now(UTC),
                        instance_id="test-instance",
                    )
                )
        if ruleset:
            session.add(RuleSet(domain_id=domain.id, name="default"))
        if member is not None:
            session.add(DomainMember(domain_id=domain.id, user_id=member, role="member"))
        await session.flush()
        if deleted_at is not None:
            await soft_delete_domain(session, domain, now=deleted_at)
        return domain.id

    result: uuid.UUID = db(go)
    return result


def fetch(db: Db, model: type[Any], *where: Any) -> list[Any]:
    """All rows of ``model`` matching ``where``, tombstones included, oldest first."""

    async def go(session: AsyncSession) -> list[Any]:
        stmt = select(model).where(*where).order_by(model.created_at)
        return list((await session.execute(stmt)).scalars().all())

    result: list[Any] = db(go)
    return result


def users_named(db: Db, username: str) -> list[User]:
    return fetch(db, User, User.username == username)


def domains_named(db: Db, domain_name: str) -> list[Domain]:
    return fetch(db, Domain, Domain.domain_name == domain_name)


# --- the invariant the whole file exists for ---------------------------------


class TestMutationsGoThroughService:
    def test_cli_never_writes_tombstones_or_hard_deletes_itself(self):
        """Spec section 8: no ``session.delete()`` and no ``deleted_at =`` in cli.py."""
        source = Path(inspect.getsourcefile(cli)).read_text()
        offenders = [
            line.strip()
            for line in source.splitlines()
            if "session.delete" in line or re.search(r"\bdeleted_at\s*=", line)
        ]
        assert offenders == []


# --- users -------------------------------------------------------------------


class TestUserLookupsResolveTheLiveRow:
    """The MultipleResultsFound regression: a tombstone shares the name with a live row."""

    @pytest.fixture
    def alice(self, db: Db) -> tuple[uuid.UUID, uuid.UUID]:
        dead = seed_user(db, "alice", deleted_at=OLDER)
        live = seed_user(db, "alice")
        return dead, live

    def test_create_reports_the_live_duplicate(self, run, db, alice):
        code, out = run("user", "create", "alice")
        assert code == 1
        assert "User 'alice' already exists" in out
        assert len(users_named(db, "alice")) == 2

    def test_create_lost_race_reports_the_same_conflict(self, run, db, monkeypatch):
        """The pre-check misses (patched: the loser's stale read); the index must not leak."""
        seed_user(db, "alice")

        monkeypatch.setattr(cli, "live_value_taken", name_is_free)
        code, out = run("user", "create", "alice")
        assert code == 1
        assert "User 'alice' already exists" in out
        assert "Traceback" not in out
        assert len(users_named(db, "alice")) == 1

    def test_set_superuser_targets_the_live_row(self, run, db, alice):
        dead, live = alice
        code, out = run("user", "set-superuser", "alice", "--enable")
        assert code == 0, out
        by_id = {u.id: u for u in users_named(db, "alice")}
        assert by_id[live].is_superuser is True
        assert by_id[dead].is_superuser is False

    def test_generate_key_targets_the_live_row(self, run, db, alice):
        dead, live = alice
        code, out = run("user", "generate-key", "alice", "--name", "ci")
        assert code == 0, out
        assert "Generated API key for 'alice'" in out
        keys = fetch(db, APIKey, APIKey.name == "ci")
        assert [k.user_id for k in keys] == [live]

    def test_add_and_remove_member_target_the_live_row(self, run, db, alice):
        dead, live = alice
        seed_domain(db, "example.com")
        code, out = run("domain", "add-member", "example.com", "alice", "--role", "admin")
        assert code == 0, out
        members = fetch(db, DomainMember)
        assert [(m.user_id, m.role) for m in members] == [(live, "admin")]

        code, out = run("domain", "remove-member", "example.com", "alice")
        assert code == 0, out
        assert fetch(db, DomainMember) == []

    def test_delete_targets_the_live_row(self, run, db, alice):
        code, out = run("user", "delete", "alice", "--force")
        assert code == 0, out
        assert all(u.deleted_at is not None for u in users_named(db, "alice"))

    def test_list_shows_the_live_row_only(self, run, alice):
        code, out = run("user", "list")
        assert code == 0
        assert out.count("alice") == 1
        assert "Deleted" not in out


class TestUserList:
    def test_include_deleted_adds_the_column(self, run, db):
        seed_user(db, "alice", deleted_at=NEWER)
        seed_user(db, "bob")

        code, out = run("user", "list", "--include-deleted")
        assert code == 0
        assert "Deleted" in out
        assert "alice" in out and "bob" in out
        assert NEWER_TEXT in out

    def test_default_hides_tombstones(self, run, db):
        seed_user(db, "alice", deleted_at=NEWER)
        seed_user(db, "bob")

        code, out = run("user", "list")
        assert code == 0
        assert "alice" not in out
        assert "Deleted" not in out

    def test_flags_render_as_ascii_words(self, run, db):
        """Active/Superuser show Yes/No like fsmtp does, never check marks.

        Each row is matched cell by cell (``\\S`` is the frame between cells,
        the email cell is empty) so a swapped or hard-coded column cannot pass.
        """
        seed_user(db, "alice")
        seed_user(db, "bob", is_active=False, is_superuser=True)

        code, out = run("user", "list")
        assert code == 0
        assert re.search(r"alice\s+\S\s+\S\s+Yes\s+\S\s+No\b", out), out
        assert re.search(r"bob\s+\S\s+\S\s+No\s+\S\s+Yes\b", out), out
        assert "\u2713" not in out and "\u2717" not in out


class TestUserDelete:
    def test_soft_deletes_and_revokes_keys(self, run, db):
        seed_user(db, "alice", keys=2)

        code, out = run("user", "delete", "alice", "--force")
        assert code == 0, out
        assert (
            "Deleted user 'alice' (2 API key(s) revoked; restore with: fastsmtp user restore alice)"
            in out
        )
        (alice,) = users_named(db, "alice")
        assert alice.deleted_at is not None
        keys = fetch(db, APIKey, APIKey.user_id == alice.id)
        assert len(keys) == 2
        assert all(k.deleted_at == alice.deleted_at and k.is_active is False for k in keys)

    def test_prompt_warns_about_keys_names_restore_and_declining_aborts(self, run, db):
        """Restore does not bring the keys back, so the prompt has to say they go for good."""
        seed_user(db, "alice")

        code, out = run("user", "delete", "alice", input="n\n")
        assert code == 1
        assert (
            "Delete user 'alice'? Their API keys are revoked for good; the user is "
            "restorable with: fastsmtp user restore alice" in out
        )
        (alice,) = users_named(db, "alice")
        assert alice.deleted_at is None

    def test_id_without_purge_is_refused(self, run, db):
        """``--id`` names a tombstone; without ``--purge`` it must not soft-delete the live row."""
        dead = seed_user(db, "alice", deleted_at=OLDER)
        live = seed_user(db, "alice", keys=1)

        code, out = run("user", "delete", "alice", "--id", str(dead), "--force")
        assert code == 1
        assert ID_NEEDS_PURGE in out
        by_id = {u.id: u for u in users_named(db, "alice")}
        assert by_id[live].deleted_at is None
        (key,) = fetch(db, APIKey, APIKey.user_id == live)
        assert key.is_active is True and key.deleted_at is None

    def test_confirming_deletes(self, run, db):
        seed_user(db, "alice")
        code, out = run("user", "delete", "alice", input="y\n")
        assert code == 0, out
        (alice,) = users_named(db, "alice")
        assert alice.deleted_at is not None

    def test_unknown_user(self, run):
        code, out = run("user", "delete", "alice", "--force")
        assert code == 1
        assert "User 'alice' not found" in out

    def test_tombstone_is_not_found_without_purge(self, run, db):
        seed_user(db, "alice", deleted_at=OLDER)
        code, out = run("user", "delete", "alice", "--force")
        assert code == 1
        assert "User 'alice' not found" in out

    def test_name_is_reusable_after_delete(self, run, db):
        seed_user(db, "alice")
        assert run("user", "delete", "alice", "--force")[0] == 0

        code, out = run("user", "create", "alice", "--email", "alice@example.com")
        assert code == 0, out
        assert "Created user 'alice'" in out
        rows = users_named(db, "alice")
        assert [r.deleted_at is None for r in rows] == [False, True]


class TestUserPurge:
    def test_live_only_name_is_refused(self, run, db):
        seed_user(db, "alice")
        code, out = run("user", "delete", "alice", "--purge", "--force")
        assert code == 1
        assert "User 'alice' is not deleted; delete it first, then --purge" in out
        assert len(users_named(db, "alice")) == 1

    def test_unknown_name(self, run):
        code, out = run("user", "delete", "alice", "--purge", "--force")
        assert code == 1
        assert "No deleted user 'alice'" in out

    def test_prompts_then_purges_with_cascades(self, run, db):
        alice = seed_user(db, "alice", deleted_at=NEWER, keys=1)
        seed_domain(db, "example.com", member=alice)

        code, out = run("user", "delete", "alice", "--purge", input="y\n")
        assert code == 0, out
        assert (
            f"Permanently delete user 'alice' (deleted {NEWER_TEXT}) and all their API keys "
            "and memberships? This cannot be undone." in out
        )
        assert "Purged user 'alice'" in out
        assert users_named(db, "alice") == []
        assert fetch(db, APIKey, APIKey.user_id == alice) == []
        assert fetch(db, DomainMember, DomainMember.user_id == alice) == []

    def test_declining_keeps_the_tombstone(self, run, db):
        seed_user(db, "alice", deleted_at=NEWER)
        code, out = run("user", "delete", "alice", "--purge", input="n\n")
        assert code == 1
        assert len(users_named(db, "alice")) == 1

    def test_targets_the_tombstone_not_the_live_namesake(self, run, db):
        dead = seed_user(db, "alice", deleted_at=OLDER)
        live = seed_user(db, "alice")

        code, out = run("user", "delete", "alice", "--purge", "--force")
        assert code == 0, out
        assert [u.id for u in users_named(db, "alice")] == [live]
        assert dead != live

    def test_ambiguity_requires_id(self, run, db):
        older = seed_user(db, "alice", deleted_at=OLDER)
        newer = seed_user(db, "alice", deleted_at=NEWER)

        code, out = run("user", "delete", "alice", "--purge", "--force")
        assert code == 1
        assert "--id" in out
        assert str(older) in out and str(newer) in out
        assert len(users_named(db, "alice")) == 2

        code, out = run("user", "delete", "alice", "--purge", "--force", "--id", str(older))
        assert code == 0, out
        assert [u.id for u in users_named(db, "alice")] == [newer]


class TestUserRestore:
    def test_restores_and_leaves_keys_revoked(self, run, db):
        alice = seed_user(db, "alice", deleted_at=NEWER, keys=1)

        code, out = run("user", "restore", "alice")
        assert code == 0, out
        assert f"Restored user 'alice' (ID: {alice})" in out
        assert (
            "API keys revoked at deletion are not restored; generate new ones with: "
            "fastsmtp user generate-key alice" in out
        )
        (row,) = users_named(db, "alice")
        assert row.deleted_at is None
        (key,) = fetch(db, APIKey, APIKey.user_id == alice)
        assert key.is_active is False and key.deleted_at is not None

    def test_nothing_to_restore(self, run, db):
        seed_user(db, "alice")
        code, out = run("user", "restore", "alice")
        assert code == 1
        assert "No deleted user 'alice'" in out

    def test_ambiguity_lists_tombstones_and_id_disambiguates(self, run, db):
        older = seed_user(db, "alice", deleted_at=OLDER)
        newer = seed_user(db, "alice", deleted_at=NEWER)

        code, out = run("user", "restore", "alice")
        assert code == 1
        assert "pass --id" in out
        assert str(older) in out and str(newer) in out
        assert NEWER_TEXT in out
        # Newest tombstone listed first
        assert out.index(str(newer)) < out.index(str(older))
        assert all(u.deleted_at is not None for u in users_named(db, "alice"))

        code, out = run("user", "restore", "alice", "--id", str(older))
        assert code == 0, out
        by_id = {u.id: u for u in users_named(db, "alice")}
        assert by_id[older].deleted_at is None
        assert by_id[newer].deleted_at is not None

    def test_id_that_matches_no_tombstone(self, run, db):
        seed_user(db, "alice", deleted_at=OLDER)
        stray = uuid.uuid4()
        code, out = run("user", "restore", "alice", "--id", str(stray))
        assert code == 1
        assert f"No deleted user 'alice' with ID {stray}" in out

    def test_live_namesake_blocks_restore(self, run, db):
        seed_user(db, "alice", deleted_at=OLDER)
        seed_user(db, "alice")

        code, out = run("user", "restore", "alice")
        assert code == 1
        assert "User 'alice' already exists; rename or purge it first" in out
        assert [u.deleted_at is None for u in users_named(db, "alice")] == [False, True]

    def test_lost_race_hits_the_index_and_reports_the_same_conflict(self, run, db, monkeypatch):
        """Pre-check misses (patched), so the partial unique index is the backstop."""
        seed_user(db, "alice", deleted_at=OLDER)
        seed_user(db, "alice")

        monkeypatch.setattr(cli, "live_value_taken", name_is_free)
        code, out = run("user", "restore", "alice")
        assert code == 1
        assert "User 'alice' already exists; rename or purge it first" in out
        assert [u.deleted_at is None for u in users_named(db, "alice")] == [False, True]


class TestUserCommandsRefuseTombstones:
    def test_generate_key_refuses_a_tombstoned_user(self, run, db):
        alice = seed_user(db, "alice", deleted_at=OLDER)
        code, out = run("user", "generate-key", "alice")
        assert code == 1
        assert "User 'alice' not found" in out
        assert fetch(db, APIKey, APIKey.user_id == alice) == []

    def test_set_superuser_refuses_a_tombstoned_user(self, run, db):
        seed_user(db, "alice", deleted_at=OLDER)
        code, out = run("user", "set-superuser", "alice", "--enable")
        assert code == 1
        assert "User 'alice' not found" in out

    def test_add_member_refuses_a_tombstoned_user(self, run, db):
        seed_user(db, "alice", deleted_at=OLDER)
        seed_domain(db, "example.com")
        code, out = run("domain", "add-member", "example.com", "alice")
        assert code == 1
        assert "User 'alice' not found" in out
        assert fetch(db, DomainMember) == []


class TestRemoveMemberReachesTombstonedUsers:
    """Removing a membership is an un-grant, so a deleted user's edge is detachable
    from the CLI just as it is through the REST API."""

    def test_detaches_a_tombstoned_users_membership(self, run, db):
        alice = seed_user(db, "alice", deleted_at=OLDER)
        seed_domain(db, "example.com", member=alice)

        code, out = run("domain", "remove-member", "example.com", "alice")
        assert code == 0, out
        assert "Removed 'alice' from 'example.com'" in out
        assert fetch(db, DomainMember) == []

    def test_live_namesake_wins_and_keeps_the_tombstones_edge(self, run, db):
        dead = seed_user(db, "alice", deleted_at=OLDER)
        live = seed_user(db, "alice")
        domain_id = seed_domain(db, "example.com", member=live)

        async def add_dead_edge(session: AsyncSession) -> None:
            session.add(DomainMember(domain_id=domain_id, user_id=dead, role="member"))

        db(add_dead_edge)

        code, out = run("domain", "remove-member", "example.com", "alice")
        assert code == 0, out
        assert [m.user_id for m in fetch(db, DomainMember)] == [dead]

    def test_unknown_user(self, run, db):
        seed_domain(db, "example.com")
        code, out = run("domain", "remove-member", "example.com", "alice")
        assert code == 1
        assert "User 'alice' not found" in out


# --- domains -----------------------------------------------------------------


class TestDomainLookupsResolveTheLiveRow:
    @pytest.fixture
    def example(self, db: Db) -> tuple[uuid.UUID, uuid.UUID]:
        dead = seed_domain(db, "example.com", deleted_at=OLDER)
        live = seed_domain(db, "example.com")
        return dead, live

    def test_create_reports_the_live_duplicate(self, run, db, example):
        code, out = run("domain", "create", "example.com")
        assert code == 1
        assert "Domain 'example.com' already exists" in out
        assert len(domains_named(db, "example.com")) == 2

    def test_create_lost_race_reports_the_same_conflict(self, run, db, monkeypatch):
        seed_domain(db, "example.com")

        monkeypatch.setattr(cli, "live_value_taken", name_is_free)
        code, out = run("domain", "create", "example.com")
        assert code == 1
        assert "Domain 'example.com' already exists" in out
        assert "Traceback" not in out
        assert len(domains_named(db, "example.com")) == 1

    def test_add_and_remove_member_target_the_live_row(self, run, db, example):
        dead, live = example
        seed_user(db, "alice")
        code, out = run("domain", "add-member", "example.com", "alice", "--role", "owner")
        assert code == 0, out
        assert [(m.domain_id, m.role) for m in fetch(db, DomainMember)] == [(live, "owner")]

        code, out = run("domain", "remove-member", "example.com", "alice")
        assert code == 0, out
        assert fetch(db, DomainMember) == []

    def test_delete_targets_the_live_row(self, run, db, example):
        code, out = run("domain", "delete", "example.com", "--force")
        assert code == 0, out
        assert all(d.deleted_at is not None for d in domains_named(db, "example.com"))

    def test_list_shows_the_live_row_only(self, run, example):
        code, out = run("domain", "list")
        assert code == 0
        assert out.count("example.com") == 1
        assert "Deleted" not in out


class TestDomainList:
    def test_include_deleted_adds_the_column(self, run, db):
        seed_domain(db, "old.example", deleted_at=NEWER)
        seed_domain(db, "live.example")

        code, out = run("domain", "list", "--include-deleted")
        assert code == 0
        assert "Deleted" in out
        assert "old.example" in out and "live.example" in out
        assert NEWER_TEXT in out

    def test_default_hides_tombstones(self, run, db):
        seed_domain(db, "old.example", deleted_at=NEWER)
        seed_domain(db, "live.example")

        code, out = run("domain", "list")
        assert code == 0
        assert "old.example" not in out

    def test_flags_render_as_ascii_words(self, run, db):
        """Enabled shows Yes/No like fsmtp does, never check marks (see the user test)."""
        seed_domain(db, "live.example")

        code, out = run("domain", "list")
        assert code == 0
        assert re.search(r"live\.example\s+\S\s+Yes\s+\S\s+default\b", out), out
        assert "\u2713" not in out and "\u2717" not in out


class TestDomainDelete:
    def test_soft_deletes_recipients_and_cancels_deliveries(self, run, db):
        domain_id = seed_domain(
            db, "example.com", recipients=("sales", None), pending_deliveries=1, ruleset=True
        )

        code, out = run("domain", "delete", "example.com", "--force")
        assert code == 0, out
        assert (
            "Deleted domain 'example.com' (2 recipient(s) deleted, 2 delivery(ies) cancelled; "
            "restore with: fastsmtp domain restore example.com)" in out
        )
        (domain,) = domains_named(db, "example.com")
        assert domain.deleted_at is not None
        recipients = fetch(db, Recipient, Recipient.domain_id == domain_id)
        assert [r.deleted_at for r in recipients] == [domain.deleted_at] * 2
        logs = fetch(db, DeliveryLog, DeliveryLog.domain_id == domain_id)
        assert {log.status for log in logs} == {DeliveryStatus.CANCELLED.value}
        assert all(log.recipient_id is not None for log in logs)
        # Rulesets carry no tombstone; they hide behind the domain and survive.
        assert len(fetch(db, RuleSet, RuleSet.domain_id == domain_id)) == 1

    def test_prompt_names_the_restore_command_and_declining_aborts(self, run, db):
        seed_domain(db, "example.com")
        code, out = run("domain", "delete", "example.com", input="n\n")
        assert code == 1
        assert (
            "Delete domain 'example.com'? (restorable with: fastsmtp domain restore example.com)"
            in out
        )
        (domain,) = domains_named(db, "example.com")
        assert domain.deleted_at is None

    def test_unknown_domain(self, run):
        code, out = run("domain", "delete", "example.com", "--force")
        assert code == 1
        assert "Domain 'example.com' not found" in out

    def test_id_without_purge_is_refused(self, run, db):
        dead = seed_domain(db, "example.com", deleted_at=OLDER)
        live = seed_domain(db, "example.com", recipients=("sales",))

        code, out = run("domain", "delete", "example.com", "--id", str(dead), "--force")
        assert code == 1
        assert ID_NEEDS_PURGE in out
        by_id = {d.id: d for d in domains_named(db, "example.com")}
        assert by_id[live].deleted_at is None
        (recipient,) = fetch(db, Recipient, Recipient.domain_id == live)
        assert recipient.deleted_at is None

    def test_name_is_reusable_after_delete(self, run, db):
        seed_domain(db, "example.com")
        assert run("domain", "delete", "example.com", "--force")[0] == 0

        code, out = run("domain", "create", "example.com")
        assert code == 0, out
        assert "Created domain 'example.com'" in out
        assert [d.deleted_at is None for d in domains_named(db, "example.com")] == [False, True]


class TestDomainPurge:
    def test_live_only_name_is_refused(self, run, db):
        seed_domain(db, "example.com")
        code, out = run("domain", "delete", "example.com", "--purge", "--force")
        assert code == 1
        assert "Domain 'example.com' is not deleted; delete it first, then --purge" in out
        assert len(domains_named(db, "example.com")) == 1

    def test_prompts_then_purges_with_cascades(self, run, db):
        alice = seed_user(db, "alice")
        domain_id = seed_domain(
            db,
            "example.com",
            deleted_at=NEWER,
            recipients=("sales",),
            pending_deliveries=1,
            ruleset=True,
            member=alice,
        )

        code, out = run("domain", "delete", "example.com", "--purge", input="y\n")
        assert code == 0, out
        assert (
            f"Permanently delete domain 'example.com' (deleted {NEWER_TEXT}) and all its "
            "recipients, rulesets and members? This cannot be undone." in out
        )
        assert "Purged domain 'example.com'" in out
        assert domains_named(db, "example.com") == []
        assert fetch(db, Recipient, Recipient.domain_id == domain_id) == []
        assert fetch(db, RuleSet, RuleSet.domain_id == domain_id) == []
        assert fetch(db, DomainMember, DomainMember.domain_id == domain_id) == []
        # History survives the purge with its links severed
        (log,) = fetch(db, DeliveryLog)
        assert log.domain_id is None and log.recipient_id is None

    def test_ambiguity_requires_id(self, run, db):
        older = seed_domain(db, "example.com", deleted_at=OLDER)
        newer = seed_domain(db, "example.com", deleted_at=NEWER)

        code, out = run("domain", "delete", "example.com", "--purge", "--force")
        assert code == 1
        assert "--id" in out and str(older) in out and str(newer) in out

        code, out = run("domain", "delete", "example.com", "--purge", "--force", "--id", str(newer))
        assert code == 0, out
        assert [d.id for d in domains_named(db, "example.com")] == [older]


class TestDomainRestore:
    def test_restores_the_domain_and_its_stamped_recipients(self, run, db):
        domain_id = seed_domain(db, "example.com", deleted_at=NEWER, recipients=("sales", "ops"))

        code, out = run("domain", "restore", "example.com")
        assert code == 0, out
        assert f"Restored domain 'example.com' (ID: {domain_id})" in out
        assert "2 recipient(s) restored" in out
        (domain,) = domains_named(db, "example.com")
        assert domain.deleted_at is None
        recipients = fetch(db, Recipient, Recipient.domain_id == domain_id)
        assert [r.deleted_at for r in recipients] == [None, None]

    def test_nothing_to_restore(self, run, db):
        seed_domain(db, "example.com")
        code, out = run("domain", "restore", "example.com")
        assert code == 1
        assert "No deleted domain 'example.com'" in out

    def test_ambiguity_and_id(self, run, db):
        older = seed_domain(db, "example.com", deleted_at=OLDER)
        newer = seed_domain(db, "example.com", deleted_at=NEWER)

        code, out = run("domain", "restore", "example.com")
        assert code == 1
        assert "pass --id" in out and str(older) in out and str(newer) in out

        code, out = run("domain", "restore", "example.com", "--id", str(newer))
        assert code == 0, out
        by_id = {d.id: d for d in domains_named(db, "example.com")}
        assert by_id[newer].deleted_at is None
        assert by_id[older].deleted_at is not None

    def test_live_namesake_blocks_restore(self, run, db):
        seed_domain(db, "example.com", deleted_at=OLDER)
        seed_domain(db, "example.com")

        code, out = run("domain", "restore", "example.com")
        assert code == 1
        assert "Domain 'example.com' already exists; rename or purge it first" in out

    def test_lost_race_hits_the_index_and_reports_the_same_conflict(self, run, db, monkeypatch):
        seed_domain(db, "example.com", deleted_at=OLDER)
        seed_domain(db, "example.com")

        monkeypatch.setattr(cli, "live_value_taken", name_is_free)
        code, out = run("domain", "restore", "example.com")
        assert code == 1
        assert "Domain 'example.com' already exists; rename or purge it first" in out
        assert [d.deleted_at is None for d in domains_named(db, "example.com")] == [False, True]


class TestDomainMembersRefuseTombstonedDomains:
    def test_add_member(self, run, db):
        seed_user(db, "alice")
        seed_domain(db, "example.com", deleted_at=OLDER)
        code, out = run("domain", "add-member", "example.com", "alice")
        assert code == 1
        assert "Domain 'example.com' not found" in out
        assert fetch(db, DomainMember) == []

    def test_remove_member(self, run, db):
        alice = seed_user(db, "alice")
        seed_domain(db, "example.com", deleted_at=OLDER, member=alice)
        code, out = run("domain", "remove-member", "example.com", "alice")
        assert code == 1
        assert "Domain 'example.com' not found" in out
        assert len(fetch(db, DomainMember)) == 1


# --- purge-deleted -----------------------------------------------------------


@pytest.fixture
def configure(test_settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Callable[..., Settings]:
    """Give the CLI a Settings with the given overrides."""

    def apply(**overrides: Any) -> Settings:
        settings = test_settings.model_copy(update=overrides)
        monkeypatch.setattr(cli, "get_settings", lambda: settings)
        return settings

    return apply


class TestPurgeDeleted:
    def test_unconfigured_is_decided_before_touching_the_database(
        self, run, db, configure, monkeypatch
    ):
        configure(soft_delete_retention_days=None)

        def no_session() -> AsyncSession:
            raise AssertionError("purge-deleted opened a session with no retention to apply")

        monkeypatch.setattr("fastsmtp.db.session.async_session", no_session)
        code, out = run("purge-deleted")
        assert code == 1
        assert (
            "No retention configured. Set FASTSMTP_SOFT_DELETE_RETENTION_DAYS or pass --older-than."
            in out
        )

    def test_a_service_error_is_not_relabelled_as_unconfigured(
        self, run, db, configure, monkeypatch
    ):
        """Only the unconfigured case is the CLI's to explain; anything else propagates."""
        from fastsmtp.cleanup.purge import SoftDeletePurgeService

        configure(soft_delete_retention_days=30)

        async def broken(self: Any, **kwargs: Any) -> Any:
            raise ValueError("boom")

        monkeypatch.setattr(SoftDeletePurgeService, "purge", broken)
        with pytest.raises(ValueError, match="^boom$"):
            run("purge-deleted")

    def test_dry_run_counts_without_deleting(self, run, db, configure):
        configure(soft_delete_retention_days=30)
        seed_user(db, "alice", deleted_at=OLDER, keys=1)
        seed_domain(db, "old.example", deleted_at=OLDER, recipients=("sales",))
        seed_domain(db, "fresh.example", deleted_at=datetime.now(UTC))

        code, out = run("purge-deleted", "--dry-run")
        assert code == 0, out
        assert re.search(
            r"Would purge 4 soft-deleted rows older than \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC "
            r"\(recipients=1, api_keys=1, domains=1, users=1\)",
            out,
        )
        assert len(users_named(db, "alice")) == 1
        assert len(fetch(db, Domain)) == 2

    def test_older_than_overrides_the_setting(self, run, db, configure):
        configure(soft_delete_retention_days=None)
        seed_user(db, "alice", deleted_at=OLDER)
        seed_domain(db, "fresh.example", deleted_at=datetime.now(UTC))

        code, out = run("purge-deleted", "--older-than", "7d")
        assert code == 0, out
        assert "Purged 1 soft-deleted rows older than" in out
        assert "(recipients=0, api_keys=0, domains=0, users=1)" in out
        assert users_named(db, "alice") == []
        assert len(domains_named(db, "fresh.example")) == 1

    def test_invalid_duration(self, run, db, configure):
        configure(soft_delete_retention_days=None)
        code, out = run("purge-deleted", "--older-than", "2w")
        assert code == 1
        assert "Invalid duration format: 2w" in out

    def test_help_lists_the_flags(self, run):
        code, out = run("purge-deleted", "--help")
        assert code == 0
        assert "--dry-run" in out and "--older-than" in out


# --- serve startup line ------------------------------------------------------


class TestCleanupWorkerStartupLine:
    def test_both_jobs(self, test_settings: Settings):
        settings = test_settings.model_copy(
            update={
                "delivery_log_cleanup_enabled": True,
                "delivery_log_retention_days": 30,
                "delivery_log_cleanup_interval_hours": 6,
                "soft_delete_retention_days": 90,
            }
        )
        assert cli._cleanup_worker_started_line(settings) == (
            "Cleanup worker started (interval: 6h, delivery-log retention: 30d, "
            "soft-delete retention: 90d)"
        )

    def test_purge_only(self, test_settings: Settings):
        settings = test_settings.model_copy(
            update={
                "delivery_log_cleanup_enabled": False,
                "delivery_log_cleanup_interval_hours": 24,
                "soft_delete_retention_days": 14,
            }
        )
        assert cli._cleanup_worker_started_line(settings) == (
            "Cleanup worker started (interval: 24h, delivery-log retention: off, "
            "soft-delete retention: 14d)"
        )

    def test_delivery_logs_only(self, test_settings: Settings):
        settings = test_settings.model_copy(
            update={
                "delivery_log_cleanup_enabled": True,
                "delivery_log_retention_days": 7,
                "delivery_log_cleanup_interval_hours": 1,
                "soft_delete_retention_days": None,
            }
        )
        assert cli._cleanup_worker_started_line(settings) == (
            "Cleanup worker started (interval: 1h, delivery-log retention: 7d, "
            "soft-delete retention: never)"
        )

    def test_serve_gates_the_line_on_the_worker_not_the_delivery_log_flag(self):
        """The console line must follow ``CleanupWorker.enabled`` (spec section 7.2)."""
        source = inspect.getsource(cli.serve)
        assert "cleanup_worker.enabled" in source
        assert "settings.delivery_log_cleanup_enabled" not in source
