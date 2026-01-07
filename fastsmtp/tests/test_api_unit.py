"""Unit tests for API functions to improve coverage tracking.

These tests call the API functions directly rather than through HTTP,
which ensures coverage is properly tracked for async code.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.db.models import DeliveryLog, Domain, DomainMember, Recipient, RuleSet, Rule, User
from fastsmtp.schemas.recipient import RecipientCreate, RecipientUpdate
from fastsmtp.schemas.rule import RuleCreate, RuleSetCreate, RuleSetUpdate, RuleUpdate


class TestRecipientAPIUnit:
    """Unit tests for recipient API functions."""

    @pytest.fixture
    def mock_auth(self):
        """Create mock auth context."""
        auth = MagicMock()
        auth.is_superuser.return_value = True
        auth.require_scope = MagicMock()
        return auth

    @pytest.fixture
    def mock_session(self):
        """Create mock database session."""
        session = AsyncMock(spec=AsyncSession)
        return session

    @pytest.mark.asyncio
    async def test_list_recipients(self, mock_auth, mock_session, test_session):
        """Test list_recipients function."""
        from fastsmtp.api.recipients import list_recipients

        # Create test domain
        domain = Domain(domain_name="unit-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Create test recipients
        r1 = Recipient(
            domain_id=domain.id,
            local_part="user1",
            webhook_url="https://example.com/1",
            is_enabled=True,
        )
        r2 = Recipient(
            domain_id=domain.id,
            local_part="user2",
            webhook_url="https://example.com/2",
            is_enabled=True,
        )
        test_session.add_all([r1, r2])
        await test_session.commit()
        await test_session.refresh(domain)

        # Mock get_domain_with_access
        with patch("fastsmtp.api.recipients.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await list_recipients(
                domain_id=domain.id,
                auth=mock_auth,
                session=test_session,
            )

            assert len(result) == 2

    @pytest.mark.asyncio
    async def test_create_recipient(self, mock_auth, test_session):
        """Test create_recipient function."""
        from fastsmtp.api.recipients import create_recipient

        # Create test domain
        domain = Domain(domain_name="create-unit.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        data = RecipientCreate(
            local_part="newuser",
            webhook_url="https://example.com/webhook",
        )

        with patch("fastsmtp.api.recipients.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await create_recipient(
                domain_id=domain.id,
                data=data,
                auth=mock_auth,
                session=test_session,
            )

            assert result.local_part == "newuser"

    @pytest.mark.asyncio
    async def test_create_recipient_catchall(self, mock_auth, test_session):
        """Test create_recipient with catch-all pattern."""
        from fastsmtp.api.recipients import create_recipient

        domain = Domain(domain_name="catchall-unit.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        data = RecipientCreate(
            local_part="*",  # Should become None
            webhook_url="https://example.com/catchall",
        )

        with patch("fastsmtp.api.recipients.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await create_recipient(
                domain_id=domain.id,
                data=data,
                auth=mock_auth,
                session=test_session,
            )

            assert result.local_part is None

    @pytest.mark.asyncio
    async def test_create_recipient_duplicate(self, mock_auth, test_session):
        """Test create_recipient with duplicate fails."""
        from fastsmtp.api.recipients import create_recipient

        domain = Domain(domain_name="dup-unit.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Create existing recipient
        existing = Recipient(
            domain_id=domain.id,
            local_part="existing",
            webhook_url="https://example.com/existing",
            is_enabled=True,
        )
        test_session.add(existing)
        await test_session.commit()
        await test_session.refresh(domain)

        data = RecipientCreate(
            local_part="existing",
            webhook_url="https://example.com/new",
        )

        with patch("fastsmtp.api.recipients.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            with pytest.raises(HTTPException) as exc_info:
                await create_recipient(
                    domain_id=domain.id,
                    data=data,
                    auth=mock_auth,
                    session=test_session,
                )

            assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_get_recipient(self, mock_auth, test_session):
        """Test get_recipient function."""
        from fastsmtp.api.recipients import get_recipient

        domain = Domain(domain_name="get-unit.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        recipient = Recipient(
            domain_id=domain.id,
            local_part="getme",
            webhook_url="https://example.com/get",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.commit()
        await test_session.refresh(recipient)

        with patch("fastsmtp.api.recipients.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await get_recipient(
                domain_id=domain.id,
                recipient_id=recipient.id,
                auth=mock_auth,
                session=test_session,
            )

            assert result.local_part == "getme"

    @pytest.mark.asyncio
    async def test_get_recipient_not_found(self, mock_auth, test_session):
        """Test get_recipient with non-existent ID."""
        from fastsmtp.api.recipients import get_recipient

        domain = Domain(domain_name="notfound-unit.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        with patch("fastsmtp.api.recipients.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            with pytest.raises(HTTPException) as exc_info:
                await get_recipient(
                    domain_id=domain.id,
                    recipient_id=uuid.uuid4(),
                    auth=mock_auth,
                    session=test_session,
                )

            assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_update_recipient(self, mock_auth, test_session):
        """Test update_recipient function."""
        from fastsmtp.api.recipients import update_recipient

        domain = Domain(domain_name="update-unit.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        recipient = Recipient(
            domain_id=domain.id,
            local_part="updateme",
            webhook_url="https://example.com/old",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.commit()
        await test_session.refresh(recipient)

        data = RecipientUpdate(
            webhook_url="https://example.com/new",
            is_enabled=False,
        )

        with patch("fastsmtp.api.recipients.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await update_recipient(
                domain_id=domain.id,
                recipient_id=recipient.id,
                data=data,
                auth=mock_auth,
                session=test_session,
            )

            assert result.webhook_url == "https://example.com/new"
            assert result.is_enabled is False

    @pytest.mark.asyncio
    async def test_update_recipient_local_part(self, mock_auth, test_session):
        """Test update_recipient changing local_part."""
        from fastsmtp.api.recipients import update_recipient

        domain = Domain(domain_name="update-local.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        recipient = Recipient(
            domain_id=domain.id,
            local_part="oldlocal",
            webhook_url="https://example.com/hook",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.commit()
        await test_session.refresh(recipient)

        data = RecipientUpdate(local_part="newlocal")

        with patch("fastsmtp.api.recipients.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await update_recipient(
                domain_id=domain.id,
                recipient_id=recipient.id,
                data=data,
                auth=mock_auth,
                session=test_session,
            )

            assert result.local_part == "newlocal"

    @pytest.mark.asyncio
    async def test_delete_recipient(self, mock_auth, test_session):
        """Test delete_recipient function."""
        from fastsmtp.api.recipients import delete_recipient

        domain = Domain(domain_name="delete-unit.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        recipient = Recipient(
            domain_id=domain.id,
            local_part="deleteme",
            webhook_url="https://example.com/delete",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.commit()
        await test_session.refresh(recipient)

        with patch("fastsmtp.api.recipients.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await delete_recipient(
                domain_id=domain.id,
                recipient_id=recipient.id,
                auth=mock_auth,
                session=test_session,
            )

            assert "deleted" in result.message


class TestRulesAPIUnit:
    """Unit tests for rules API functions."""

    @pytest.fixture
    def mock_auth(self):
        """Create mock auth context."""
        auth = MagicMock()
        auth.is_superuser.return_value = True
        auth.require_scope = MagicMock()
        return auth

    @pytest.mark.asyncio
    async def test_list_rulesets(self, mock_auth, test_session):
        """Test list_rulesets function."""
        from fastsmtp.api.rules import list_rulesets

        domain = Domain(domain_name="rules-unit.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        rs1 = RuleSet(domain_id=domain.id, name="Rules 1", priority=10)
        rs2 = RuleSet(domain_id=domain.id, name="Rules 2", priority=5)
        test_session.add_all([rs1, rs2])
        await test_session.commit()
        await test_session.refresh(domain)

        with patch("fastsmtp.api.rules.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await list_rulesets(
                domain_id=domain.id,
                auth=mock_auth,
                session=test_session,
            )

            assert len(result) == 2

    @pytest.mark.asyncio
    async def test_create_ruleset(self, mock_auth, test_session):
        """Test create_ruleset function."""
        from fastsmtp.api.rules import create_ruleset

        domain = Domain(domain_name="create-rules.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        data = RuleSetCreate(name="New Rules", priority=10, stop_on_match=True)

        with patch("fastsmtp.api.rules.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await create_ruleset(
                domain_id=domain.id,
                data=data,
                auth=mock_auth,
                session=test_session,
            )

            assert result.name == "New Rules"
            assert result.priority == 10

    @pytest.mark.asyncio
    async def test_get_ruleset(self, mock_auth, test_session):
        """Test get_ruleset function."""
        from fastsmtp.api.rules import get_ruleset

        domain = Domain(domain_name="get-rules.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        ruleset = RuleSet(domain_id=domain.id, name="Get Rules", priority=0)
        test_session.add(ruleset)
        await test_session.commit()
        await test_session.refresh(ruleset)

        with patch("fastsmtp.api.rules.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await get_ruleset(
                domain_id=domain.id,
                ruleset_id=ruleset.id,
                auth=mock_auth,
                session=test_session,
            )

            assert result.name == "Get Rules"

    @pytest.mark.asyncio
    async def test_update_ruleset(self, mock_auth, test_session):
        """Test update_ruleset function."""
        from fastsmtp.api.rules import update_ruleset

        domain = Domain(domain_name="upd-rules.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        ruleset = RuleSet(domain_id=domain.id, name="Old Name", priority=0)
        test_session.add(ruleset)
        await test_session.commit()
        await test_session.refresh(ruleset)

        data = RuleSetUpdate(name="New Name", priority=20)

        with patch("fastsmtp.api.rules.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await update_ruleset(
                domain_id=domain.id,
                ruleset_id=ruleset.id,
                data=data,
                auth=mock_auth,
                session=test_session,
            )

            assert result.name == "New Name"
            assert result.priority == 20

    @pytest.mark.asyncio
    async def test_delete_ruleset(self, mock_auth, test_session):
        """Test delete_ruleset function."""
        from fastsmtp.api.rules import delete_ruleset

        domain = Domain(domain_name="del-rules.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        ruleset = RuleSet(domain_id=domain.id, name="Delete Me", priority=0)
        test_session.add(ruleset)
        await test_session.commit()
        await test_session.refresh(ruleset)

        with patch("fastsmtp.api.rules.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await delete_ruleset(
                domain_id=domain.id,
                ruleset_id=ruleset.id,
                auth=mock_auth,
                session=test_session,
            )

            assert "deleted" in result.message

    @pytest.mark.asyncio
    async def test_create_rule(self, mock_auth, test_session):
        """Test create_rule function."""
        from fastsmtp.api.rules import create_rule

        domain = Domain(domain_name="create-rule.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        ruleset = RuleSet(domain_id=domain.id, name="Rules", priority=0)
        test_session.add(ruleset)
        await test_session.commit()
        await test_session.refresh(ruleset)

        data = RuleCreate(
            field="from",
            operator="contains",
            value="@example.com",
            action="tag",
            add_tags=["external"],
        )

        with patch("fastsmtp.api.rules.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await create_rule(
                domain_id=domain.id,
                ruleset_id=ruleset.id,
                data=data,
                auth=mock_auth,
                session=test_session,
            )

            assert result.field == "from"
            assert result.action == "tag"

    @pytest.mark.asyncio
    async def test_update_rule(self, mock_auth, test_session):
        """Test update_rule function."""
        from fastsmtp.api.rules import update_rule

        domain = Domain(domain_name="upd-rule.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        ruleset = RuleSet(domain_id=domain.id, name="Rules", priority=0)
        test_session.add(ruleset)
        await test_session.flush()

        rule = Rule(
            ruleset_id=ruleset.id,
            order=0,
            field="from",
            operator="equals",
            value="old@example.com",
            action="tag",
        )
        test_session.add(rule)
        await test_session.commit()
        await test_session.refresh(rule)

        data = RuleUpdate(value="new@example.com")

        with patch("fastsmtp.api.rules.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await update_rule(
                domain_id=domain.id,
                rule_id=rule.id,
                data=data,
                auth=mock_auth,
                session=test_session,
            )

            assert result.value == "new@example.com"

    @pytest.mark.asyncio
    async def test_delete_rule(self, mock_auth, test_session):
        """Test delete_rule function."""
        from fastsmtp.api.rules import delete_rule

        domain = Domain(domain_name="del-rule.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        ruleset = RuleSet(domain_id=domain.id, name="Rules", priority=0)
        test_session.add(ruleset)
        await test_session.flush()

        rule = Rule(
            ruleset_id=ruleset.id,
            order=0,
            field="from",
            operator="equals",
            value="delete@example.com",
            action="drop",
        )
        test_session.add(rule)
        await test_session.commit()
        await test_session.refresh(rule)

        with patch("fastsmtp.api.rules.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await delete_rule(
                domain_id=domain.id,
                rule_id=rule.id,
                auth=mock_auth,
                session=test_session,
            )

            assert "deleted" in result.message


class TestDomainsAPIUnit:
    """Unit tests for domains API functions."""

    @pytest.fixture
    def mock_auth(self):
        """Create mock auth context."""
        auth = MagicMock()
        auth.is_superuser.return_value = True
        auth.require_scope = MagicMock()
        auth.user_id = uuid.uuid4()
        return auth

    @pytest.mark.asyncio
    async def test_list_domains(self, mock_auth, test_session):
        """Test list_domains function."""
        from fastsmtp.api.domains import list_domains

        # Create test domains
        d1 = Domain(domain_name="list-unit1.com", is_enabled=True)
        d2 = Domain(domain_name="list-unit2.com", is_enabled=True)
        test_session.add_all([d1, d2])
        await test_session.commit()

        result = await list_domains(
            auth=mock_auth,
            session=test_session,
        )

        # Should return at least 2 domains
        assert len(result) >= 2

    @pytest.mark.asyncio
    async def test_create_domain(self, mock_auth, test_session):
        """Test create_domain function."""
        from fastsmtp.api.domains import create_domain
        from fastsmtp.schemas.domain import DomainCreate

        data = DomainCreate(domain_name="create-unit.com")

        result = await create_domain(
            data=data,
            auth=mock_auth,
            session=test_session,
        )

        assert result.domain_name == "create-unit.com"
        assert result.is_enabled is True

    @pytest.mark.asyncio
    async def test_create_domain_duplicate(self, mock_auth, test_session):
        """Test create_domain with duplicate fails."""
        from fastsmtp.api.domains import create_domain
        from fastsmtp.schemas.domain import DomainCreate

        # Create existing domain
        existing = Domain(domain_name="dup-domain.com", is_enabled=True)
        test_session.add(existing)
        await test_session.commit()

        data = DomainCreate(domain_name="dup-domain.com")

        with pytest.raises(HTTPException) as exc_info:
            await create_domain(
                data=data,
                auth=mock_auth,
                session=test_session,
            )

        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_get_domain(self, mock_auth, test_session):
        """Test get_domain function."""
        from fastsmtp.api.domains import get_domain

        domain = Domain(domain_name="get-domain-unit.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        with patch("fastsmtp.api.domains.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await get_domain(
                domain_id=domain.id,
                auth=mock_auth,
                session=test_session,
            )

            assert result.domain_name == "get-domain-unit.com"

    @pytest.mark.asyncio
    async def test_update_domain(self, mock_auth, test_session):
        """Test update_domain function."""
        from fastsmtp.api.domains import update_domain
        from fastsmtp.schemas.domain import DomainUpdate

        domain = Domain(domain_name="upd-domain.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        data = DomainUpdate(is_enabled=False)

        with patch("fastsmtp.api.domains.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await update_domain(
                domain_id=domain.id,
                data=data,
                auth=mock_auth,
                session=test_session,
            )

            assert result.is_enabled is False

    @pytest.mark.asyncio
    async def test_delete_domain(self, mock_auth, test_session):
        """Test delete_domain function."""
        from fastsmtp.api.domains import delete_domain

        domain = Domain(domain_name="del-domain-unit.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        with patch("fastsmtp.api.domains.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await delete_domain(
                domain_id=domain.id,
                auth=mock_auth,
                session=test_session,
            )

            assert "deleted" in result.message


class TestUsersAPIUnit:
    """Unit tests for users API functions."""

    @pytest.fixture
    def mock_auth(self):
        """Create mock auth context."""
        auth = MagicMock()
        auth.require_superuser = MagicMock()
        auth.is_root = True  # For delete_user
        return auth

    @pytest.mark.asyncio
    async def test_list_users(self, mock_auth, test_session):
        """Test list_users function."""
        from fastsmtp.api.users import list_users

        # Create test users (User model doesn't have hashed_password)
        u1 = User(username="listuser1", email="list1@unit.com")
        u2 = User(username="listuser2", email="list2@unit.com")
        test_session.add_all([u1, u2])
        await test_session.commit()

        result = await list_users(
            auth=mock_auth,
            session=test_session,
        )

        # Should return at least 2 users
        assert len(result) >= 2

    @pytest.mark.asyncio
    async def test_create_user(self, mock_auth, test_session):
        """Test create_user function."""
        from fastsmtp.api.users import create_user
        from fastsmtp.schemas.user import UserCreate

        data = UserCreate(
            username="newuser",
            email="new@unit.com",
        )

        result = await create_user(
            data=data,
            auth=mock_auth,
            session=test_session,
        )

        assert result.username == "newuser"
        assert result.email == "new@unit.com"

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(self, mock_auth, test_session):
        """Test create_user with duplicate username fails."""
        from fastsmtp.api.users import create_user
        from fastsmtp.schemas.user import UserCreate

        # Create existing user
        existing = User(
            username="dupuser",
            email="existing@unit.com",
        )
        test_session.add(existing)
        await test_session.commit()

        data = UserCreate(
            username="dupuser",
            email="new@unit.com",
        )

        with pytest.raises(HTTPException) as exc_info:
            await create_user(
                data=data,
                auth=mock_auth,
                session=test_session,
            )

        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_get_user(self, mock_auth, test_session):
        """Test get_user function."""
        from fastsmtp.api.users import get_user

        user = User(
            username="getuser",
            email="get@unit.com",
        )
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)

        result = await get_user(
            user_id=user.id,
            auth=mock_auth,
            session=test_session,
        )

        assert result.username == "getuser"

    @pytest.mark.asyncio
    async def test_get_user_not_found(self, mock_auth, test_session):
        """Test get_user with non-existent ID."""
        from fastsmtp.api.users import get_user

        with pytest.raises(HTTPException) as exc_info:
            await get_user(
                user_id=uuid.uuid4(),
                auth=mock_auth,
                session=test_session,
            )

        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_update_user(self, mock_auth, test_session):
        """Test update_user function."""
        from fastsmtp.api.users import update_user
        from fastsmtp.schemas.user import UserUpdate

        user = User(
            username="upduser",
            email="upd@unit.com",
        )
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)

        data = UserUpdate(email="updated@unit.com")

        result = await update_user(
            user_id=user.id,
            data=data,
            auth=mock_auth,
            session=test_session,
        )

        assert result.email == "updated@unit.com"

    @pytest.mark.asyncio
    async def test_delete_user(self, mock_auth, test_session):
        """Test delete_user function."""
        from fastsmtp.api.users import delete_user

        user = User(
            username="deluser",
            email="del@unit.com",
        )
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)

        result = await delete_user(
            user_id=user.id,
            auth=mock_auth,
            session=test_session,
        )

        assert "deleted" in result.message


class TestOperationsAPIUnit:
    """Unit tests for operations API functions."""

    @pytest.fixture
    def mock_auth(self):
        """Create mock auth context."""
        auth = MagicMock()
        auth.is_superuser.return_value = True
        auth.require_scope = MagicMock()
        return auth

    @pytest.mark.asyncio
    async def test_list_delivery_logs(self, mock_auth, test_session):
        """Test list_delivery_logs function."""
        from fastsmtp.api.operations import list_delivery_logs
        import hashlib

        # Create domain
        domain = Domain(domain_name="logs-unit.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Create logs
        log = DeliveryLog(
            domain_id=domain.id,
            webhook_url="https://webhook.example.com",
            status="delivered",
            message_id="<test@unit.com>",
            payload={"test": True},
            payload_hash=hashlib.sha256(b"test").hexdigest(),
            instance_id="test-instance",
        )
        test_session.add(log)
        await test_session.commit()

        with patch("fastsmtp.api.operations.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            # Must pass all Query() parameter values explicitly
            result = await list_delivery_logs(
                domain_id=domain.id,
                auth=mock_auth,
                session=test_session,
                status_filter=None,
                message_id=None,
                limit=50,
                offset=0,
            )

            assert len(result) >= 1

    @pytest.mark.asyncio
    async def test_list_delivery_logs_with_filters(self, mock_auth, test_session):
        """Test list_delivery_logs with status filter."""
        from fastsmtp.api.operations import list_delivery_logs
        import hashlib

        domain = Domain(domain_name="logs-filter-unit.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Create logs with different statuses
        for status in ["pending", "delivered", "failed"]:
            log = DeliveryLog(
                domain_id=domain.id,
                webhook_url="https://webhook.example.com",
                status=status,
                message_id=f"<{status}@unit.com>",
                payload={"status": status},
                payload_hash=hashlib.sha256(status.encode()).hexdigest(),
                instance_id="test-instance",
            )
            test_session.add(log)
        await test_session.commit()

        with patch("fastsmtp.api.operations.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await list_delivery_logs(
                domain_id=domain.id,
                auth=mock_auth,
                session=test_session,
                status_filter="delivered",
                message_id=None,
                limit=50,
                offset=0,
            )

            assert len(result) == 1
            assert result[0].status == "delivered"

    @pytest.mark.asyncio
    async def test_get_delivery_log(self, mock_auth, test_session):
        """Test get_delivery_log function."""
        from fastsmtp.api.operations import get_delivery_log
        import hashlib

        domain = Domain(domain_name="get-log-unit.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        log = DeliveryLog(
            domain_id=domain.id,
            webhook_url="https://webhook.example.com",
            status="delivered",
            message_id="<getlog@unit.com>",
            payload={"key": "value"},
            payload_hash=hashlib.sha256(b"getlog").hexdigest(),
            instance_id="test-instance",
        )
        test_session.add(log)
        await test_session.commit()
        await test_session.refresh(log)

        with patch("fastsmtp.api.operations.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await get_delivery_log(
                log_id=log.id,
                auth=mock_auth,
                session=test_session,
            )

            assert result.id == log.id
            assert result.payload is not None

    @pytest.mark.asyncio
    async def test_get_delivery_log_not_found(self, mock_auth, test_session):
        """Test get_delivery_log with non-existent ID."""
        from fastsmtp.api.operations import get_delivery_log

        with pytest.raises(HTTPException) as exc_info:
            await get_delivery_log(
                log_id=uuid.uuid4(),
                auth=mock_auth,
                session=test_session,
            )

        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_retry_delivery_endpoint(self, mock_auth, test_session):
        """Test retry_delivery_endpoint function."""
        from fastsmtp.api.operations import retry_delivery_endpoint
        import hashlib

        domain = Domain(domain_name="retry-unit.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        log = DeliveryLog(
            domain_id=domain.id,
            webhook_url="https://webhook.example.com",
            status="failed",
            message_id="<retry@unit.com>",
            payload={"retry": True},
            payload_hash=hashlib.sha256(b"retry").hexdigest(),
            instance_id="test-instance",
        )
        test_session.add(log)
        await test_session.commit()
        await test_session.refresh(log)

        with patch("fastsmtp.api.operations.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await retry_delivery_endpoint(
                log_id=log.id,
                auth=mock_auth,
                session=test_session,
            )

            assert "retry" in result.message

    @pytest.mark.asyncio
    async def test_retry_delivery_not_failed(self, mock_auth, test_session):
        """Test retry_delivery_endpoint with non-failed delivery."""
        from fastsmtp.api.operations import retry_delivery_endpoint
        import hashlib

        domain = Domain(domain_name="retry-notfailed.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        log = DeliveryLog(
            domain_id=domain.id,
            webhook_url="https://webhook.example.com",
            status="delivered",
            message_id="<notfailed@unit.com>",
            payload={"test": True},
            payload_hash=hashlib.sha256(b"notfailed").hexdigest(),
            instance_id="test-instance",
        )
        test_session.add(log)
        await test_session.commit()
        await test_session.refresh(log)

        with patch("fastsmtp.api.operations.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            with pytest.raises(HTTPException) as exc_info:
                await retry_delivery_endpoint(
                    log_id=log.id,
                    auth=mock_auth,
                    session=test_session,
                )

            assert exc_info.value.status_code == 400


class TestDomainMembersAPIUnit:
    """Unit tests for domain member API functions."""

    @pytest.fixture
    def mock_auth(self):
        """Create mock auth context."""
        auth = MagicMock()
        auth.is_superuser.return_value = True
        auth.is_root = True
        auth.require_scope = MagicMock()
        auth.require_domain_owner = AsyncMock()
        auth.user = MagicMock()
        auth.user.id = uuid.uuid4()
        return auth

    @pytest.mark.asyncio
    async def test_list_members(self, mock_auth, test_session):
        """Test list_members function."""
        from fastsmtp.api.domains import list_members

        # Create domain and user
        domain = Domain(domain_name="members-list.com", is_enabled=True)
        test_session.add(domain)
        user = User(username="memberuser1", email="member1@test.com")
        test_session.add(user)
        await test_session.flush()

        # Add member
        member = DomainMember(domain_id=domain.id, user_id=user.id, role="admin")
        test_session.add(member)
        await test_session.commit()

        with patch("fastsmtp.api.domains.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await list_members(
                domain_id=domain.id,
                auth=mock_auth,
                session=test_session,
            )

            assert len(result) >= 1

    @pytest.mark.asyncio
    async def test_add_member(self, mock_auth, test_session):
        """Test add_member function."""
        from fastsmtp.api.domains import add_member
        from fastsmtp.schemas.domain import MemberCreate

        domain = Domain(domain_name="members-add.com", is_enabled=True)
        test_session.add(domain)
        user = User(username="newmember", email="newmember@test.com")
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)

        data = MemberCreate(user_id=user.id, role="member")

        with patch("fastsmtp.api.domains.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await add_member(
                domain_id=domain.id,
                data=data,
                auth=mock_auth,
                session=test_session,
            )

            assert result.user_id == user.id
            assert result.role == "member"

    @pytest.mark.asyncio
    async def test_add_member_user_not_found(self, mock_auth, test_session):
        """Test add_member with non-existent user."""
        from fastsmtp.api.domains import add_member
        from fastsmtp.schemas.domain import MemberCreate

        domain = Domain(domain_name="members-notfound.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()

        data = MemberCreate(user_id=uuid.uuid4(), role="member")

        with patch("fastsmtp.api.domains.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            with pytest.raises(HTTPException) as exc_info:
                await add_member(
                    domain_id=domain.id,
                    data=data,
                    auth=mock_auth,
                    session=test_session,
                )

            assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_add_member_duplicate(self, mock_auth, test_session):
        """Test add_member with duplicate membership."""
        from fastsmtp.api.domains import add_member
        from fastsmtp.schemas.domain import MemberCreate

        domain = Domain(domain_name="members-dup.com", is_enabled=True)
        test_session.add(domain)
        user = User(username="dupmember", email="dupmember@test.com")
        test_session.add(user)
        await test_session.flush()

        # Add existing member
        member = DomainMember(domain_id=domain.id, user_id=user.id, role="member")
        test_session.add(member)
        await test_session.commit()
        await test_session.refresh(user)

        data = MemberCreate(user_id=user.id, role="admin")

        with patch("fastsmtp.api.domains.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            with pytest.raises(HTTPException) as exc_info:
                await add_member(
                    domain_id=domain.id,
                    data=data,
                    auth=mock_auth,
                    session=test_session,
                )

            assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_update_member(self, mock_auth, test_session):
        """Test update_member function."""
        from fastsmtp.api.domains import update_member
        from fastsmtp.schemas.domain import MemberUpdate

        domain = Domain(domain_name="members-upd.com", is_enabled=True)
        test_session.add(domain)
        user = User(username="updmember", email="upd@test.com")
        test_session.add(user)
        await test_session.flush()

        member = DomainMember(domain_id=domain.id, user_id=user.id, role="member")
        test_session.add(member)
        await test_session.commit()
        await test_session.refresh(user)

        data = MemberUpdate(role="admin")

        with patch("fastsmtp.api.domains.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await update_member(
                domain_id=domain.id,
                user_id=user.id,
                data=data,
                auth=mock_auth,
                session=test_session,
            )

            assert result.role == "admin"

    @pytest.mark.asyncio
    async def test_update_member_not_found(self, mock_auth, test_session):
        """Test update_member with non-existent member."""
        from fastsmtp.api.domains import update_member
        from fastsmtp.schemas.domain import MemberUpdate

        domain = Domain(domain_name="members-upd-notfound.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()

        data = MemberUpdate(role="admin")

        with patch("fastsmtp.api.domains.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            with pytest.raises(HTTPException) as exc_info:
                await update_member(
                    domain_id=domain.id,
                    user_id=uuid.uuid4(),
                    data=data,
                    auth=mock_auth,
                    session=test_session,
                )

            assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_remove_member(self, mock_auth, test_session):
        """Test remove_member function."""
        from fastsmtp.api.domains import remove_member

        domain = Domain(domain_name="members-rem.com", is_enabled=True)
        test_session.add(domain)
        user = User(username="remmember", email="rem@test.com")
        test_session.add(user)
        await test_session.flush()

        member = DomainMember(domain_id=domain.id, user_id=user.id, role="member")
        test_session.add(member)
        await test_session.commit()
        await test_session.refresh(user)

        with patch("fastsmtp.api.domains.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            result = await remove_member(
                domain_id=domain.id,
                user_id=user.id,
                auth=mock_auth,
                session=test_session,
            )

            assert "removed" in result.message

    @pytest.mark.asyncio
    async def test_remove_member_not_found(self, mock_auth, test_session):
        """Test remove_member with non-existent member."""
        from fastsmtp.api.domains import remove_member

        domain = Domain(domain_name="members-rem-notfound.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()

        with patch("fastsmtp.api.domains.get_domain_with_access") as mock_get_domain:
            mock_get_domain.return_value = domain

            with pytest.raises(HTTPException) as exc_info:
                await remove_member(
                    domain_id=domain.id,
                    user_id=uuid.uuid4(),
                    auth=mock_auth,
                    session=test_session,
                )

            assert exc_info.value.status_code == 404


class TestAuthAPIUnit:
    """Unit tests for auth API functions."""

    @pytest.fixture
    def mock_auth_user(self, test_session):
        """Create mock auth context for regular user."""
        user = User(username="authuser", email="auth@unit.com")
        auth = MagicMock()
        auth.is_root = False
        auth.user = user
        auth.api_key = None
        return auth, user

    @pytest.fixture
    def mock_auth_root(self):
        """Create mock auth context for root user."""
        auth = MagicMock()
        auth.is_root = True
        return auth

    @pytest.mark.asyncio
    async def test_whoami(self, test_session):
        """Test whoami function for regular user."""
        from fastsmtp.api.auth import whoami

        # Create user and domain membership
        user = User(username="whoamiuser", email="whoami@unit.com")
        test_session.add(user)
        await test_session.flush()

        domain = Domain(domain_name="whoami-domain.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        member = DomainMember(domain_id=domain.id, user_id=user.id, role="member")
        test_session.add(member)
        await test_session.commit()
        await test_session.refresh(user)

        mock_auth = MagicMock()
        mock_auth.is_root = False
        mock_auth.user = user

        result = await whoami(
            auth=mock_auth,
            session=test_session,
        )

        assert result.is_root is False
        assert "whoami-domain.com" in result.domains

    @pytest.mark.asyncio
    async def test_list_keys(self, test_session):
        """Test list_keys function."""
        from fastsmtp.api.auth import list_keys
        from fastsmtp.db.models import APIKey

        user = User(username="keysuser", email="keys@unit.com")
        test_session.add(user)
        await test_session.flush()

        # Create API key
        api_key = APIKey(
            user_id=user.id,
            key_hash="hash123",
            key_prefix="prefix",
            name="Test Key",
            scopes=["read"],
            is_active=True,
        )
        test_session.add(api_key)
        await test_session.commit()
        await test_session.refresh(user)

        mock_auth = MagicMock()
        mock_auth.is_root = False
        mock_auth.user = user

        result = await list_keys(
            auth=mock_auth,
            session=test_session,
        )

        assert len(result) >= 1
        assert result[0].name == "Test Key"

    @pytest.mark.asyncio
    async def test_list_keys_root_user(self, mock_auth_root, test_session):
        """Test list_keys returns empty for root user."""
        from fastsmtp.api.auth import list_keys

        result = await list_keys(
            auth=mock_auth_root,
            session=test_session,
        )

        assert result == []

    @pytest.mark.asyncio
    async def test_create_key(self, test_session):
        """Test create_key function."""
        from fastsmtp.api.auth import create_key
        from fastsmtp.schemas.user import APIKeyCreate
        from fastsmtp.config import Settings

        user = User(username="createkeyuser", email="createkey@unit.com")
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)

        mock_auth = MagicMock()
        mock_auth.is_root = False
        mock_auth.user = user

        data = APIKeyCreate(name="New Key", scopes=["read", "write"])
        settings = Settings(root_api_key="test123")

        result = await create_key(
            data=data,
            auth=mock_auth,
            session=test_session,
            settings=settings,
        )

        assert result.name == "New Key"
        assert "read" in result.scopes
        assert result.key is not None  # Full key should be returned

    @pytest.mark.asyncio
    async def test_create_key_root_user(self, mock_auth_root, test_session):
        """Test create_key fails for root user."""
        from fastsmtp.api.auth import create_key
        from fastsmtp.schemas.user import APIKeyCreate
        from fastsmtp.config import Settings

        data = APIKeyCreate(name="New Key", scopes=[])
        settings = Settings(root_api_key="test123")

        with pytest.raises(HTTPException) as exc_info:
            await create_key(
                data=data,
                auth=mock_auth_root,
                session=test_session,
                settings=settings,
            )

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_delete_key(self, test_session):
        """Test delete_key function."""
        from fastsmtp.api.auth import delete_key
        from fastsmtp.db.models import APIKey

        user = User(username="delkeyuser", email="delkey@unit.com")
        test_session.add(user)
        await test_session.flush()

        api_key = APIKey(
            user_id=user.id,
            key_hash="hash123",
            key_prefix="prefix",
            name="Delete Key",
            scopes=[],
            is_active=True,
        )
        test_session.add(api_key)
        await test_session.commit()
        await test_session.refresh(user)
        await test_session.refresh(api_key)

        mock_auth = MagicMock()
        mock_auth.is_root = False
        mock_auth.user = user
        mock_auth.api_key = None

        result = await delete_key(
            key_id=api_key.id,
            auth=mock_auth,
            session=test_session,
        )

        assert "deleted" in result.message

    @pytest.mark.asyncio
    async def test_delete_key_not_found(self, test_session):
        """Test delete_key with non-existent key."""
        from fastsmtp.api.auth import delete_key

        user = User(username="delkeynotfound", email="delkeynotfound@unit.com")
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)

        mock_auth = MagicMock()
        mock_auth.is_root = False
        mock_auth.user = user

        with pytest.raises(HTTPException) as exc_info:
            await delete_key(
                key_id=uuid.uuid4(),
                auth=mock_auth,
                session=test_session,
            )

        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_rotate_key(self, test_session):
        """Test rotate_key function."""
        from fastsmtp.api.auth import rotate_key
        from fastsmtp.db.models import APIKey
        from fastsmtp.config import Settings

        user = User(username="rotatekeyuser", email="rotatekey@unit.com")
        test_session.add(user)
        await test_session.flush()

        old_key = APIKey(
            user_id=user.id,
            key_hash="oldhash",
            key_prefix="oldprefix",
            name="Old Key",
            scopes=["read"],
            is_active=True,
        )
        test_session.add(old_key)
        await test_session.commit()
        await test_session.refresh(user)
        await test_session.refresh(old_key)

        mock_auth = MagicMock()
        mock_auth.is_root = False
        mock_auth.user = user

        settings = Settings(root_api_key="test123")

        result = await rotate_key(
            key_id=old_key.id,
            auth=mock_auth,
            session=test_session,
            settings=settings,
        )

        assert "rotated" in result.name
        assert result.key is not None

    @pytest.mark.asyncio
    async def test_rotate_key_not_found(self, test_session):
        """Test rotate_key with non-existent key."""
        from fastsmtp.api.auth import rotate_key
        from fastsmtp.config import Settings

        user = User(username="rotatenotfound", email="rotatenotfound@unit.com")
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)

        mock_auth = MagicMock()
        mock_auth.is_root = False
        mock_auth.user = user

        settings = Settings(root_api_key="test123")

        with pytest.raises(HTTPException) as exc_info:
            await rotate_key(
                key_id=uuid.uuid4(),
                auth=mock_auth,
                session=test_session,
                settings=settings,
            )

        assert exc_info.value.status_code == 404


class TestAuthContextUnit:
    """Unit tests for AuthContext class."""

    @pytest.mark.asyncio
    async def test_has_scope_root(self):
        """Test has_scope returns True for root user."""
        from fastsmtp.auth.dependencies import AuthContext

        user = User(username="rootlike", email="root@test.com")
        ctx = AuthContext(user=user, api_key=None, is_root=True, scopes=set())

        assert ctx.has_scope("any:scope") is True

    @pytest.mark.asyncio
    async def test_has_scope_admin(self):
        """Test has_scope returns True for admin scope."""
        from fastsmtp.auth.dependencies import AuthContext

        user = User(username="adminuser", email="admin@test.com")
        ctx = AuthContext(user=user, api_key=None, is_root=False, scopes={"admin"})

        assert ctx.has_scope("any:scope") is True

    @pytest.mark.asyncio
    async def test_has_scope_specific(self):
        """Test has_scope for specific scope."""
        from fastsmtp.auth.dependencies import AuthContext

        user = User(username="scopeuser", email="scope@test.com")
        ctx = AuthContext(
            user=user,
            api_key=None,
            is_root=False,
            scopes={"recipients:read", "recipients:write"},
        )

        assert ctx.has_scope("recipients:read") is True
        assert ctx.has_scope("recipients:write") is True
        assert ctx.has_scope("domains:read") is False

    @pytest.mark.asyncio
    async def test_require_scope_missing(self):
        """Test require_scope raises HTTPException for missing scope."""
        from fastsmtp.auth.dependencies import AuthContext

        user = User(username="noscope", email="noscope@test.com")
        ctx = AuthContext(user=user, api_key=None, is_root=False, scopes=set())

        with pytest.raises(HTTPException) as exc_info:
            ctx.require_scope("domains:read")

        assert exc_info.value.status_code == 403
        assert "Missing required scope" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_is_superuser(self):
        """Test is_superuser method."""
        from fastsmtp.auth.dependencies import AuthContext

        # Root is superuser
        root_user = User(username="root", email="root@test.com", is_superuser=False)
        ctx1 = AuthContext(user=root_user, api_key=None, is_root=True, scopes=set())
        assert ctx1.is_superuser() is True

        # User with is_superuser=True
        super_user = User(username="super", email="super@test.com", is_superuser=True)
        ctx2 = AuthContext(user=super_user, api_key=None, is_root=False, scopes=set())
        assert ctx2.is_superuser() is True

        # Regular user
        reg_user = User(username="regular", email="reg@test.com", is_superuser=False)
        ctx3 = AuthContext(user=reg_user, api_key=None, is_root=False, scopes=set())
        assert ctx3.is_superuser() is False

    @pytest.mark.asyncio
    async def test_require_superuser_fails(self):
        """Test require_superuser raises HTTPException for non-superuser."""
        from fastsmtp.auth.dependencies import AuthContext

        user = User(username="regular", email="reg@test.com", is_superuser=False)
        ctx = AuthContext(user=user, api_key=None, is_root=False, scopes=set())

        with pytest.raises(HTTPException) as exc_info:
            ctx.require_superuser()

        assert exc_info.value.status_code == 403
        assert "Superuser access required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_get_domain_role_root(self, test_session):
        """Test get_domain_role returns owner for root user."""
        from fastsmtp.auth.dependencies import AuthContext

        user = User(username="rootrole", email="rootrole@test.com")
        ctx = AuthContext(user=user, api_key=None, is_root=True, scopes=set())

        role = await ctx.get_domain_role(uuid.uuid4(), test_session)
        assert role == "owner"

    @pytest.mark.asyncio
    async def test_get_domain_role_member(self, test_session):
        """Test get_domain_role returns correct role for member."""
        from fastsmtp.auth.dependencies import AuthContext

        # Create user and domain
        user = User(username="memberrole", email="memberrole@test.com")
        test_session.add(user)
        await test_session.flush()

        domain = Domain(domain_name="role-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        member = DomainMember(domain_id=domain.id, user_id=user.id, role="admin")
        test_session.add(member)
        await test_session.commit()
        await test_session.refresh(user)

        ctx = AuthContext(user=user, api_key=None, is_root=False, scopes=set())

        role = await ctx.get_domain_role(domain.id, test_session)
        assert role == "admin"

    @pytest.mark.asyncio
    async def test_get_domain_role_not_member(self, test_session):
        """Test get_domain_role returns None for non-member."""
        from fastsmtp.auth.dependencies import AuthContext

        user = User(username="nonmember", email="nonmember@test.com")
        test_session.add(user)
        await test_session.flush()

        domain = Domain(domain_name="no-access.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(user)

        ctx = AuthContext(user=user, api_key=None, is_root=False, scopes=set())

        role = await ctx.get_domain_role(domain.id, test_session)
        assert role is None

    @pytest.mark.asyncio
    async def test_require_domain_owner_superuser(self, test_session):
        """Test require_domain_owner passes for superuser."""
        from fastsmtp.auth.dependencies import AuthContext

        user = User(username="superowner", email="super@test.com", is_superuser=True)
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)

        ctx = AuthContext(user=user, api_key=None, is_root=False, scopes=set())

        # Should not raise
        await ctx.require_domain_owner(uuid.uuid4(), test_session)

    @pytest.mark.asyncio
    async def test_require_domain_owner_not_owner(self, test_session):
        """Test require_domain_owner raises for non-owner."""
        from fastsmtp.auth.dependencies import AuthContext

        user = User(username="notowner", email="notowner@test.com")
        test_session.add(user)
        await test_session.flush()

        domain = Domain(domain_name="owner-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Add user as admin, not owner
        member = DomainMember(domain_id=domain.id, user_id=user.id, role="admin")
        test_session.add(member)
        await test_session.commit()
        await test_session.refresh(user)

        ctx = AuthContext(user=user, api_key=None, is_root=False, scopes=set())

        with pytest.raises(HTTPException) as exc_info:
            await ctx.require_domain_owner(domain.id, test_session)

        assert exc_info.value.status_code == 403
        assert "Only owners" in exc_info.value.detail


class TestGetDomainWithAccessUnit:
    """Unit tests for get_domain_with_access function."""

    @pytest.mark.asyncio
    async def test_domain_not_found(self, test_session):
        """Test get_domain_with_access with non-existent domain."""
        from fastsmtp.auth.dependencies import get_domain_with_access, AuthContext

        user = User(username="domainnotfound", email="notfound@test.com")
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)

        auth = AuthContext(user=user, api_key=None, is_root=False, scopes=set())

        with pytest.raises(HTTPException) as exc_info:
            await get_domain_with_access(uuid.uuid4(), auth, test_session)

        assert exc_info.value.status_code == 404
        assert "Domain not found" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_superuser_access(self, test_session):
        """Test get_domain_with_access for superuser."""
        from fastsmtp.auth.dependencies import get_domain_with_access, AuthContext

        user = User(username="superaccess", email="super@test.com", is_superuser=True)
        test_session.add(user)

        domain = Domain(domain_name="super-access.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(user)
        await test_session.refresh(domain)

        auth = AuthContext(user=user, api_key=None, is_root=False, scopes=set())

        result = await get_domain_with_access(domain.id, auth, test_session)
        assert result.domain_name == "super-access.com"

    @pytest.mark.asyncio
    async def test_non_member_denied(self, test_session):
        """Test get_domain_with_access denies non-member."""
        from fastsmtp.auth.dependencies import get_domain_with_access, AuthContext

        user = User(username="nonmember2", email="nonmember2@test.com")
        test_session.add(user)

        domain = Domain(domain_name="restricted.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(user)
        await test_session.refresh(domain)

        auth = AuthContext(user=user, api_key=None, is_root=False, scopes=set())

        with pytest.raises(HTTPException) as exc_info:
            await get_domain_with_access(domain.id, auth, test_session)

        assert exc_info.value.status_code == 403
        assert "Access denied" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_role_hierarchy_admin_required(self, test_session):
        """Test get_domain_with_access enforces role hierarchy."""
        from fastsmtp.auth.dependencies import get_domain_with_access, AuthContext

        user = User(username="memberonly", email="member@test.com")
        test_session.add(user)

        domain = Domain(domain_name="hierarchy-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Add as member only
        member = DomainMember(domain_id=domain.id, user_id=user.id, role="member")
        test_session.add(member)
        await test_session.commit()
        await test_session.refresh(user)
        await test_session.refresh(domain)

        auth = AuthContext(user=user, api_key=None, is_root=False, scopes=set())

        # Should fail when admin required
        with pytest.raises(HTTPException) as exc_info:
            await get_domain_with_access(domain.id, auth, test_session, required_role="admin")

        assert exc_info.value.status_code == 403
        assert "admin role or higher" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_role_hierarchy_success(self, test_session):
        """Test get_domain_with_access allows higher roles."""
        from fastsmtp.auth.dependencies import get_domain_with_access, AuthContext

        user = User(username="adminuser2", email="admin2@test.com")
        test_session.add(user)

        domain = Domain(domain_name="hierarchy-success.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Add as admin
        member = DomainMember(domain_id=domain.id, user_id=user.id, role="admin")
        test_session.add(member)
        await test_session.commit()
        await test_session.refresh(user)
        await test_session.refresh(domain)

        auth = AuthContext(user=user, api_key=None, is_root=False, scopes=set())

        # Should succeed when admin has admin access
        result = await get_domain_with_access(domain.id, auth, test_session, required_role="admin")
        assert result.domain_name == "hierarchy-success.com"

        # Should succeed when admin has member access
        result = await get_domain_with_access(domain.id, auth, test_session, required_role="member")
        assert result.domain_name == "hierarchy-success.com"
