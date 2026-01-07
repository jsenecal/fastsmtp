"""Tests for soft delete functionality.

Tests follow TDD - written before implementation.
"""

from datetime import UTC, datetime

import pytest
from fastsmtp.db.models import APIKey, Domain, Recipient, User
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


class TestSoftDeleteMixin:
    """Test soft delete mixin on models."""

    @pytest.mark.asyncio
    async def test_domain_has_deleted_at_field(self, test_session: AsyncSession):
        """Domain model should have deleted_at field."""
        domain = Domain(domain_name="test-soft-delete.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        # Should have deleted_at field, initially None
        assert hasattr(domain, "deleted_at")
        assert domain.deleted_at is None

    @pytest.mark.asyncio
    async def test_domain_is_deleted_property(self, test_session: AsyncSession):
        """Domain should have is_deleted property."""
        domain = Domain(domain_name="test-is-deleted.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()

        # Should have is_deleted property
        assert hasattr(domain, "is_deleted")
        assert domain.is_deleted is False

    @pytest.mark.asyncio
    async def test_recipient_has_deleted_at_field(self, test_session: AsyncSession):
        """Recipient model should have deleted_at field."""
        domain = Domain(domain_name="recipient-soft-delete.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        recipient = Recipient(
            domain_id=domain.id,
            local_part="test",
            webhook_url="https://example.com/webhook",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.commit()
        await test_session.refresh(recipient)

        assert hasattr(recipient, "deleted_at")
        assert recipient.deleted_at is None
        assert hasattr(recipient, "is_deleted")
        assert recipient.is_deleted is False

    @pytest.mark.asyncio
    async def test_user_has_deleted_at_field(self, test_session: AsyncSession):
        """User model should have deleted_at field."""
        user = User(username="test-soft-delete-user", is_active=True)
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)

        assert hasattr(user, "deleted_at")
        assert user.deleted_at is None
        assert hasattr(user, "is_deleted")
        assert user.is_deleted is False

    @pytest.mark.asyncio
    async def test_api_key_has_deleted_at_field(self, test_session: AsyncSession):
        """APIKey model should have deleted_at field."""
        user = User(username="api-key-soft-delete-user", is_active=True)
        test_session.add(user)
        await test_session.flush()

        api_key = APIKey(
            user_id=user.id,
            key_hash="test_hash",
            key_prefix="test_prefix",
            name="Test Key",
            is_active=True,
        )
        test_session.add(api_key)
        await test_session.commit()
        await test_session.refresh(api_key)

        assert hasattr(api_key, "deleted_at")
        assert api_key.deleted_at is None
        assert hasattr(api_key, "is_deleted")
        assert api_key.is_deleted is False


class TestSoftDeleteBehavior:
    """Test soft delete behavior."""

    @pytest.mark.asyncio
    async def test_soft_delete_sets_deleted_at(self, test_session: AsyncSession):
        """Setting deleted_at should mark record as deleted."""
        domain = Domain(domain_name="soft-delete-behavior.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()

        # Soft delete by setting deleted_at
        domain.deleted_at = datetime.now(UTC)
        await test_session.commit()
        await test_session.refresh(domain)

        assert domain.deleted_at is not None
        assert domain.is_deleted is True

    @pytest.mark.asyncio
    async def test_soft_deleted_domain_still_exists_in_db(self, test_session: AsyncSession):
        """Soft deleted records should still exist in database."""
        domain = Domain(domain_name="still-exists.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        domain_id = domain.id

        # Soft delete
        domain.deleted_at = datetime.now(UTC)
        await test_session.commit()

        # Should still be queryable directly
        stmt = select(Domain).where(Domain.id == domain_id)
        result = await test_session.execute(stmt)
        found = result.scalar_one_or_none()

        assert found is not None
        assert found.is_deleted is True

    @pytest.mark.asyncio
    async def test_restore_soft_deleted_record(self, test_session: AsyncSession):
        """Setting deleted_at to None should restore a soft deleted record."""
        domain = Domain(domain_name="restore-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()

        # Soft delete
        domain.deleted_at = datetime.now(UTC)
        await test_session.commit()
        assert domain.is_deleted is True

        # Restore
        domain.deleted_at = None
        await test_session.commit()
        await test_session.refresh(domain)

        assert domain.deleted_at is None
        assert domain.is_deleted is False


class TestSoftDeleteQueries:
    """Test querying with soft deletes."""

    @pytest.mark.asyncio
    async def test_filter_out_deleted_domains(self, test_session: AsyncSession):
        """Queries can filter out soft deleted records."""
        # Create two domains
        active_domain = Domain(domain_name="active-domain.com", is_enabled=True)
        deleted_domain = Domain(domain_name="deleted-domain.com", is_enabled=True)
        test_session.add_all([active_domain, deleted_domain])
        await test_session.commit()

        # Soft delete one
        deleted_domain.deleted_at = datetime.now(UTC)
        await test_session.commit()

        # Query excluding deleted
        stmt = select(Domain).where(Domain.deleted_at.is_(None))
        result = await test_session.execute(stmt)
        domains = result.scalars().all()

        domain_names = [d.domain_name for d in domains]
        assert "active-domain.com" in domain_names
        assert "deleted-domain.com" not in domain_names

    @pytest.mark.asyncio
    async def test_include_deleted_in_query(self, test_session: AsyncSession):
        """Queries can include soft deleted records when needed."""
        # Create two domains
        active_domain = Domain(domain_name="include-active.com", is_enabled=True)
        deleted_domain = Domain(domain_name="include-deleted.com", is_enabled=True)
        test_session.add_all([active_domain, deleted_domain])
        await test_session.commit()

        # Soft delete one
        deleted_domain.deleted_at = datetime.now(UTC)
        await test_session.commit()

        # Query all (including deleted)
        stmt = select(Domain).where(
            Domain.domain_name.in_(["include-active.com", "include-deleted.com"])
        )
        result = await test_session.execute(stmt)
        domains = result.scalars().all()

        assert len(domains) == 2
        deleted_count = sum(1 for d in domains if d.is_deleted)
        assert deleted_count == 1


class TestSoftDeleteMixinIntegrity:
    """Test soft delete mixin doesn't break existing functionality."""

    @pytest.mark.asyncio
    async def test_domain_timestamps_still_work(self, test_session: AsyncSession):
        """TimestampMixin should still work with SoftDeleteMixin."""
        domain = Domain(domain_name="timestamps-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        # Should have timestamps
        assert domain.created_at is not None
        assert domain.updated_at is not None

        # Should have soft delete field
        assert domain.deleted_at is None

    @pytest.mark.asyncio
    async def test_domain_relationships_still_work(self, test_session: AsyncSession):
        """Relationships should still work with soft delete."""
        from sqlalchemy.orm import selectinload

        domain = Domain(domain_name="relationship-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        recipient = Recipient(
            domain_id=domain.id,
            local_part="test",
            webhook_url="https://example.com/webhook",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.commit()

        # Reload with relationship eagerly loaded (async SQLAlchemy requires this)
        stmt = select(Domain).where(Domain.id == domain.id).options(selectinload(Domain.recipients))
        result = await test_session.execute(stmt)
        domain = result.scalar_one()

        # Relationship should work
        assert len(domain.recipients) == 1
        assert domain.recipients[0].local_part == "test"

        # Soft delete fields should be present
        assert domain.deleted_at is None
        assert domain.recipients[0].deleted_at is None
