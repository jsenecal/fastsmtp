"""Tests for ``fastsmtp.db.soft_delete``, the single soft-delete mutation module.

Every soft delete, restore and purge in the API routers and the server CLI goes
through these functions, so the cascade rules live here and nowhere else:
children are stamped with the parent's exact timestamp, restore is scoped to
that stamp, and keys revoked at delete time stay revoked.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
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
from fastsmtp.db.soft_delete import (
    purge_domain,
    purge_recipient,
    purge_user,
    restore_domain,
    restore_recipient,
    restore_user,
    soft_delete_api_key,
    soft_delete_domain,
    soft_delete_recipient,
    soft_delete_user,
    visible,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

LONG_AGO = datetime(2020, 1, 1, tzinfo=UTC)


async def make_domain(session: AsyncSession, name: str, **fields: object) -> Domain:
    domain = Domain(domain_name=name, **fields)
    session.add(domain)
    await session.flush()
    return domain


async def make_recipient(
    session: AsyncSession, domain: Domain, local_part: str | None, **fields: object
) -> Recipient:
    recipient = Recipient(
        domain_id=domain.id,
        local_part=local_part,
        webhook_url="https://example.com/hook",
        **fields,
    )
    session.add(recipient)
    await session.flush()
    return recipient


async def make_delivery(
    session: AsyncSession,
    domain: Domain,
    recipient: Recipient | None,
    status: DeliveryStatus = DeliveryStatus.PENDING,
) -> DeliveryLog:
    delivery = DeliveryLog(
        domain_id=domain.id,
        recipient_id=recipient.id if recipient else None,
        message_id=f"<{uuid.uuid4()}@example.com>",
        webhook_url="https://example.com/hook",
        payload_hash="abc123",
        payload={},
        status=status,
        attempts=0,
        next_retry_at=datetime.now(UTC),
        instance_id="test-instance",
    )
    session.add(delivery)
    await session.flush()
    return delivery


async def make_user(session: AsyncSession, username: str) -> User:
    user = User(username=username, is_active=True)
    session.add(user)
    await session.flush()
    return user


async def make_api_key(session: AsyncSession, user: User, name: str, **fields: object) -> APIKey:
    key = APIKey(
        user_id=user.id,
        key_hash=f"hash-{uuid.uuid4()}",
        key_prefix="fsk_test",
        name=name,
        **fields,
    )
    session.add(key)
    await session.flush()
    return key


async def reload(session: AsyncSession, obj: object) -> None:
    await session.commit()
    await session.refresh(obj)


class TestVisible:
    """``visible(Model, include_deleted)`` is the read-side switch."""

    @pytest.mark.asyncio
    async def test_hides_tombstones_by_default(self, test_session: AsyncSession):
        await make_domain(test_session, "visible-live.com")
        await make_domain(test_session, "visible-dead.com", deleted_at=datetime.now(UTC))

        result = await test_session.execute(
            select(Domain.domain_name).where(visible(Domain, include_deleted=False))
        )
        assert result.scalars().all() == ["visible-live.com"]

    @pytest.mark.asyncio
    async def test_shows_everything_when_included(self, test_session: AsyncSession):
        await make_domain(test_session, "visible-live.com")
        await make_domain(test_session, "visible-dead.com", deleted_at=datetime.now(UTC))

        result = await test_session.execute(
            select(Domain.domain_name)
            .where(visible(Domain, include_deleted=True))
            .order_by(Domain.domain_name)
        )
        assert result.scalars().all() == ["visible-dead.com", "visible-live.com"]


class TestSoftDeleteDomain:
    @pytest.mark.asyncio
    async def test_stamps_domain_and_live_recipients_with_one_timestamp(
        self, test_session: AsyncSession
    ):
        domain = await make_domain(test_session, "cascade.com")
        sales = await make_recipient(test_session, domain, "sales")
        catchall = await make_recipient(test_session, domain, None)

        stamped, cancelled = await soft_delete_domain(test_session, domain)
        await test_session.commit()

        assert (stamped, cancelled) == (2, 0)
        for row in (domain, sales, catchall):
            await test_session.refresh(row)
        assert domain.deleted_at is not None
        assert sales.deleted_at == domain.deleted_at
        assert catchall.deleted_at == domain.deleted_at

    @pytest.mark.asyncio
    async def test_honours_an_explicit_timestamp(self, test_session: AsyncSession):
        domain = await make_domain(test_session, "explicit-now.com")
        recipient = await make_recipient(test_session, domain, "sales")
        now = datetime(2026, 8, 24, 12, 0, 0, 123456, tzinfo=UTC)

        await soft_delete_domain(test_session, domain, now=now)
        await test_session.commit()

        await test_session.refresh(recipient)
        assert domain.deleted_at == now
        assert recipient.deleted_at == now

    @pytest.mark.asyncio
    async def test_recipient_tombstoned_earlier_keeps_its_own_stamp(
        self, test_session: AsyncSession
    ):
        domain = await make_domain(test_session, "older-tombstone.com")
        old = await make_recipient(test_session, domain, "old", deleted_at=LONG_AGO)
        live = await make_recipient(test_session, domain, "live")

        stamped, _ = await soft_delete_domain(test_session, domain)
        await test_session.commit()

        assert stamped == 1
        await test_session.refresh(old)
        await test_session.refresh(live)
        assert old.deleted_at == LONG_AGO
        assert live.deleted_at == domain.deleted_at

    @pytest.mark.asyncio
    async def test_cancels_pending_and_failed_deliveries_only(self, test_session: AsyncSession):
        domain = await make_domain(test_session, "cancel-on-delete.com")
        recipient = await make_recipient(test_session, domain, "sales")
        pending = await make_delivery(test_session, domain, recipient, DeliveryStatus.PENDING)
        failed = await make_delivery(test_session, domain, recipient, DeliveryStatus.FAILED)
        legacy = await make_delivery(test_session, domain, None, DeliveryStatus.PENDING)
        delivered = await make_delivery(test_session, domain, recipient, DeliveryStatus.DELIVERED)
        exhausted = await make_delivery(test_session, domain, recipient, DeliveryStatus.EXHAUSTED)

        _, cancelled = await soft_delete_domain(test_session, domain)
        await test_session.commit()

        assert cancelled == 3
        for row in (pending, failed, legacy):
            await test_session.refresh(row)
            assert row.status == DeliveryStatus.CANCELLED
            assert row.last_error == "Domain deleted"
            assert row.next_retry_at is None
            assert row.updated_at == domain.deleted_at
        await test_session.refresh(delivered)
        await test_session.refresh(exhausted)
        assert delivered.status == DeliveryStatus.DELIVERED
        assert exhausted.status == DeliveryStatus.EXHAUSTED

    @pytest.mark.asyncio
    async def test_leaves_rulesets_and_members_in_place(self, test_session: AsyncSession):
        """Non-mixin children are hidden through the parent, never touched."""
        domain = await make_domain(test_session, "children-stay.com")
        user = await make_user(test_session, "member")
        test_session.add(DomainMember(user_id=user.id, domain_id=domain.id, role="owner"))
        test_session.add(RuleSet(domain_id=domain.id, name="default"))
        await test_session.flush()

        await soft_delete_domain(test_session, domain)
        await test_session.commit()

        members = await test_session.execute(
            select(DomainMember).where(DomainMember.domain_id == domain.id)
        )
        rulesets = await test_session.execute(select(RuleSet).where(RuleSet.domain_id == domain.id))
        assert len(members.scalars().all()) == 1
        assert len(rulesets.scalars().all()) == 1


class TestSoftDeleteUser:
    @pytest.mark.asyncio
    async def test_stamps_user_and_revokes_live_keys(self, test_session: AsyncSession):
        user = await make_user(test_session, "alice")
        ci = await make_api_key(test_session, user, "ci")
        laptop = await make_api_key(test_session, user, "laptop")

        revoked = await soft_delete_user(test_session, user)
        await test_session.commit()

        assert revoked == 2
        await test_session.refresh(user)
        assert user.deleted_at is not None
        for key in (ci, laptop):
            await test_session.refresh(key)
            assert key.deleted_at == user.deleted_at
            assert key.is_active is False

    @pytest.mark.asyncio
    async def test_stamps_keys_retired_before_soft_delete_existed(self, test_session: AsyncSession):
        """A pre-0.5 retired key (is_active False, deleted_at NULL) is still live for
        the cascade: only rows already carrying a tombstone are left alone."""
        user = await make_user(test_session, "alice")
        retired = await make_api_key(test_session, user, "retired", is_active=False)
        tombstoned = await make_api_key(
            test_session, user, "gone", is_active=False, deleted_at=LONG_AGO
        )

        revoked = await soft_delete_user(test_session, user)
        await test_session.commit()

        assert revoked == 1
        await test_session.refresh(retired)
        await test_session.refresh(tombstoned)
        assert retired.deleted_at == user.deleted_at
        assert tombstoned.deleted_at == LONG_AGO

    @pytest.mark.asyncio
    async def test_leaves_memberships_in_place(self, test_session: AsyncSession):
        user = await make_user(test_session, "alice")
        domain = await make_domain(test_session, "membership-stays.com")
        test_session.add(DomainMember(user_id=user.id, domain_id=domain.id, role="admin"))
        await test_session.flush()

        await soft_delete_user(test_session, user)
        await test_session.commit()

        members = await test_session.execute(
            select(DomainMember).where(DomainMember.user_id == user.id)
        )
        assert len(members.scalars().all()) == 1

    @pytest.mark.asyncio
    async def test_user_without_keys(self, test_session: AsyncSession):
        user = await make_user(test_session, "keyless")
        assert await soft_delete_user(test_session, user) == 0
        await reload(test_session, user)
        assert user.is_deleted


class TestSoftDeleteRecipient:
    @pytest.mark.asyncio
    async def test_stamps_recipient_and_cancels_only_its_deliveries(
        self, test_session: AsyncSession
    ):
        domain = await make_domain(test_session, "recipient-cancel.com")
        sales = await make_recipient(test_session, domain, "sales")
        support = await make_recipient(test_session, domain, "support")
        sales_pending = await make_delivery(test_session, domain, sales, DeliveryStatus.PENDING)
        sales_failed = await make_delivery(test_session, domain, sales, DeliveryStatus.FAILED)
        sales_done = await make_delivery(test_session, domain, sales, DeliveryStatus.DELIVERED)
        support_pending = await make_delivery(test_session, domain, support)

        cancelled = await soft_delete_recipient(test_session, sales)
        await test_session.commit()

        assert cancelled == 2
        await test_session.refresh(sales)
        assert sales.deleted_at is not None
        for row in (sales_pending, sales_failed):
            await test_session.refresh(row)
            assert row.status == DeliveryStatus.CANCELLED
            assert row.last_error == "Recipient deleted"
        await test_session.refresh(sales_done)
        await test_session.refresh(support_pending)
        assert sales_done.status == DeliveryStatus.DELIVERED
        assert support_pending.status == DeliveryStatus.PENDING


class TestSoftDeleteApiKey:
    @pytest.mark.asyncio
    async def test_stamps_and_deactivates(self, test_session: AsyncSession):
        user = await make_user(test_session, "alice")
        key = await make_api_key(test_session, user, "ci")

        await soft_delete_api_key(test_session, key)
        await reload(test_session, key)

        assert key.deleted_at is not None
        assert key.is_active is False


class TestRestoreDomain:
    @pytest.mark.asyncio
    async def test_restores_recipients_stamped_with_the_domain(self, test_session: AsyncSession):
        domain = await make_domain(test_session, "restore.com")
        sales = await make_recipient(test_session, domain, "sales")
        older = await make_recipient(test_session, domain, "older", deleted_at=LONG_AGO)
        await soft_delete_domain(test_session, domain)
        await test_session.commit()

        restored = await restore_domain(test_session, domain)
        await test_session.commit()

        assert restored == 1
        for row in (domain, sales, older):
            await test_session.refresh(row)
        assert domain.deleted_at is None
        assert sales.deleted_at is None
        assert older.deleted_at == LONG_AGO

    @pytest.mark.asyncio
    async def test_never_touches_is_enabled(self, test_session: AsyncSession):
        domain = await make_domain(test_session, "disabled.com", is_enabled=False)
        recipient = await make_recipient(test_session, domain, "sales", is_enabled=False)
        await soft_delete_domain(test_session, domain)
        await test_session.commit()

        await restore_domain(test_session, domain)
        await test_session.commit()

        await test_session.refresh(domain)
        await test_session.refresh(recipient)
        assert domain.is_enabled is False
        assert recipient.is_enabled is False

    @pytest.mark.asyncio
    async def test_never_requeues_cancelled_deliveries(self, test_session: AsyncSession):
        """Re-arming a delivery is an operator decision (the retry endpoint)."""
        domain = await make_domain(test_session, "no-requeue.com")
        recipient = await make_recipient(test_session, domain, "sales")
        delivery = await make_delivery(test_session, domain, recipient)
        await soft_delete_domain(test_session, domain)
        await test_session.commit()

        await restore_domain(test_session, domain)
        await test_session.commit()

        await test_session.refresh(delivery)
        assert delivery.status == DeliveryStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_leaves_the_parent_unflushed_for_the_caller(self, test_session: AsyncSession):
        """The router's ``flush_or_http_conflict`` must be the flush that hits the
        partial unique index, so restore may not flush the parent itself."""
        domain = await make_domain(test_session, "unflushed.com")
        await soft_delete_domain(test_session, domain)
        await test_session.commit()

        await restore_domain(test_session, domain)

        assert domain in test_session.dirty
        await test_session.rollback()
        await test_session.refresh(domain)
        assert domain.is_deleted


class TestRestoreUser:
    @pytest.mark.asyncio
    async def test_restores_user_but_keys_stay_revoked(self, test_session: AsyncSession):
        user = await make_user(test_session, "alice")
        key = await make_api_key(test_session, user, "ci")
        await soft_delete_user(test_session, user)
        await test_session.commit()

        await restore_user(test_session, user)
        await test_session.commit()

        await test_session.refresh(user)
        await test_session.refresh(key)
        assert user.deleted_at is None
        assert key.deleted_at is not None
        assert key.is_active is False

    @pytest.mark.asyncio
    async def test_never_touches_is_active(self, test_session: AsyncSession):
        user = await make_user(test_session, "alice")
        user.is_active = False
        await soft_delete_user(test_session, user)
        await test_session.commit()

        await restore_user(test_session, user)
        await reload(test_session, user)

        assert user.is_active is False
        assert user.deleted_at is None


class TestRestoreRecipient:
    @pytest.mark.asyncio
    async def test_clears_tombstone_and_leaves_is_enabled(self, test_session: AsyncSession):
        domain = await make_domain(test_session, "restore-recipient.com")
        recipient = await make_recipient(test_session, domain, "sales", is_enabled=False)
        await soft_delete_recipient(test_session, recipient)
        await test_session.commit()

        await restore_recipient(test_session, recipient)
        await reload(test_session, recipient)

        assert recipient.deleted_at is None
        assert recipient.is_enabled is False


class TestPurge:
    """Purge is the v0.4.0 hard delete: ORM + FK cascades, SET NULL on history."""

    @pytest.mark.asyncio
    async def test_purge_recipient_orphans_its_history(self, test_session: AsyncSession):
        domain = await make_domain(test_session, "purge-recipient.com")
        recipient = await make_recipient(test_session, domain, "sales")
        delivery = await make_delivery(test_session, domain, recipient, DeliveryStatus.DELIVERED)
        await soft_delete_recipient(test_session, recipient)
        await test_session.commit()
        recipient_id = recipient.id

        await purge_recipient(test_session, recipient)
        await test_session.commit()

        assert await test_session.get(Recipient, recipient_id) is None
        await test_session.refresh(delivery)
        assert delivery.recipient_id is None
        assert delivery.domain_id == domain.id

    @pytest.mark.asyncio
    async def test_purge_domain_cascades_children_and_orphans_history(
        self, test_session: AsyncSession
    ):
        domain = await make_domain(test_session, "purge-domain.com")
        user = await make_user(test_session, "owner")
        recipient = await make_recipient(test_session, domain, "sales")
        member = DomainMember(user_id=user.id, domain_id=domain.id, role="owner")
        ruleset = RuleSet(domain_id=domain.id, name="default")
        test_session.add_all([member, ruleset])
        await test_session.flush()
        delivery = await make_delivery(test_session, domain, recipient, DeliveryStatus.DELIVERED)
        await soft_delete_domain(test_session, domain)
        await test_session.commit()
        ids = (domain.id, recipient.id, member.id, ruleset.id)

        await purge_domain(test_session, domain)
        await test_session.commit()

        domain_id, recipient_id, member_id, ruleset_id = ids
        assert await test_session.get(Domain, domain_id) is None
        assert await test_session.get(Recipient, recipient_id) is None
        assert await test_session.get(DomainMember, member_id) is None
        assert await test_session.get(RuleSet, ruleset_id) is None
        assert await test_session.get(User, user.id) is not None
        await test_session.refresh(delivery)
        assert delivery.domain_id is None
        assert delivery.recipient_id is None

    @pytest.mark.asyncio
    async def test_purge_user_cascades_keys_and_memberships(self, test_session: AsyncSession):
        user = await make_user(test_session, "alice")
        domain = await make_domain(test_session, "purge-user.com")
        key = await make_api_key(test_session, user, "ci")
        member = DomainMember(user_id=user.id, domain_id=domain.id, role="member")
        test_session.add(member)
        await test_session.flush()
        await soft_delete_user(test_session, user)
        await test_session.commit()
        ids = (user.id, key.id, member.id)

        await purge_user(test_session, user)
        await test_session.commit()

        user_id, key_id, member_id = ids
        assert await test_session.get(User, user_id) is None
        assert await test_session.get(APIKey, key_id) is None
        assert await test_session.get(DomainMember, member_id) is None
        assert await test_session.get(Domain, domain.id) is not None


class TestTimestampContract:
    """A tombstone written now is strictly newer than one written earlier."""

    @pytest.mark.asyncio
    async def test_default_stamp_is_utc_now(self, test_session: AsyncSession):
        domain = await make_domain(test_session, "utc-now.com")
        before = datetime.now(UTC) - timedelta(seconds=1)

        await soft_delete_domain(test_session, domain)

        assert domain.deleted_at is not None
        assert domain.deleted_at.tzinfo is not None
        assert before <= domain.deleted_at <= datetime.now(UTC)
