"""Extended tests for domain API endpoints to improve coverage."""

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastsmtp.auth import generate_api_key
from fastsmtp.db.enums import DeliveryStatus
from fastsmtp.db.models import (
    APIKey,
    DeliveryLog,
    Domain,
    DomainMember,
    Recipient,
    Rule,
    RuleSet,
    User,
)
from fastsmtp.db.soft_delete import soft_delete_domain, soft_delete_recipient, soft_delete_user
from httpx import ASGITransport, AsyncClient
from sqlalchemy import false, select
from sqlalchemy.ext.asyncio import AsyncSession


def api_client(app, api_key: str) -> AsyncClient:
    """A client that talks to ``app`` over ASGI as the holder of ``api_key``."""
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"X-API-Key": api_key},
    )


class TestDomainMembersExtended:
    """Extended tests for domain member operations."""

    @pytest_asyncio.fixture
    async def test_domain(self, test_session: AsyncSession) -> Domain:
        """Create a test domain."""
        domain = Domain(domain_name="members-extended.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)
        return domain

    @pytest_asyncio.fixture
    async def test_owner(self, test_session: AsyncSession) -> User:
        """Create a test owner user."""
        user = User(
            username="owner",
            email="owner@example.com",
            is_active=True,
            is_superuser=False,
        )
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)
        return user

    @pytest.mark.asyncio
    async def test_add_member_user_not_found(self, auth_client: AsyncClient, test_domain: Domain):
        """Test adding non-existent user as member fails."""
        fake_user_id = uuid.uuid4()
        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/members",
            json={"user_id": str(fake_user_id), "role": "member"},
        )
        assert response.status_code == 404
        assert "User not found" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_member_not_found(self, auth_client: AsyncClient, test_domain: Domain):
        """Test updating non-existent member fails."""
        fake_user_id = uuid.uuid4()
        response = await auth_client.put(
            f"/api/v1/domains/{test_domain.id}/members/{fake_user_id}",
            json={"role": "admin"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_remove_member_not_found(self, auth_client: AsyncClient, test_domain: Domain):
        """Test removing non-existent member fails."""
        fake_user_id = uuid.uuid4()
        response = await auth_client.delete(
            f"/api/v1/domains/{test_domain.id}/members/{fake_user_id}"
        )
        assert response.status_code == 404


class TestDomainAccessControl:
    """Tests for domain access control."""

    @pytest_asyncio.fixture
    async def non_superuser_with_domain(
        self, test_session: AsyncSession, app
    ) -> tuple[User, Domain, str]:
        """Create a non-superuser with domain access."""
        # Create user
        user = User(
            username="regular_user",
            email="regular@example.com",
            is_active=True,
            is_superuser=False,
        )
        test_session.add(user)
        await test_session.flush()

        # Create domain
        domain = Domain(domain_name="user-domain.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Add user as member
        member = DomainMember(
            domain_id=domain.id,
            user_id=user.id,
            role="member",
        )
        test_session.add(member)

        # Create API key
        full_key, key_prefix, key_hash, key_salt = generate_api_key()
        api_key = APIKey(
            user_id=user.id,
            key_hash=key_hash,
            key_salt=key_salt,
            key_prefix=key_prefix,
            name="User Key",
            scopes=[
                "domains:read",
                "domains:write",
                "recipients:read",
                "recipients:write",
            ],
            is_active=True,
        )
        test_session.add(api_key)
        await test_session.commit()
        await test_session.refresh(user)
        await test_session.refresh(domain)

        return user, domain, full_key

    @pytest.mark.asyncio
    async def test_list_domains_as_regular_user(
        self, app, non_superuser_with_domain: tuple[User, Domain, str]
    ):
        """Test regular user sees only their domains."""
        user, domain, api_key = non_superuser_with_domain

        async with api_client(app, api_key) as user_client:
            response = await user_client.get("/api/v1/domains")
            assert response.status_code == 200
            data = response.json()
            domain_names = {d["domain_name"] for d in data}
            assert "user-domain.com" in domain_names

    @pytest.mark.asyncio
    async def test_access_other_domain_denied(
        self, app, test_session: AsyncSession, non_superuser_with_domain: tuple[User, Domain, str]
    ):
        """Test regular user cannot access other domains."""
        user, _, api_key = non_superuser_with_domain

        # Create another domain that user is NOT a member of
        other_domain = Domain(domain_name="other-domain.com", is_enabled=True)
        test_session.add(other_domain)
        await test_session.commit()
        await test_session.refresh(other_domain)

        async with api_client(app, api_key) as user_client:
            response = await user_client.get(f"/api/v1/domains/{other_domain.id}")
            assert response.status_code == 403
            assert "Access denied" in response.json()["detail"]


class TestDomainRoleHierarchy:
    """Tests for domain role hierarchy."""

    @pytest_asyncio.fixture
    async def admin_user_with_domain(
        self, test_session: AsyncSession, app
    ) -> tuple[User, Domain, str]:
        """Create an admin user with domain access."""
        user = User(
            username="admin_user",
            email="admin@example.com",
            is_active=True,
            is_superuser=False,
        )
        test_session.add(user)
        await test_session.flush()

        domain = Domain(domain_name="admin-domain.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        member = DomainMember(
            domain_id=domain.id,
            user_id=user.id,
            role="admin",
        )
        test_session.add(member)

        full_key, key_prefix, key_hash, key_salt = generate_api_key()
        api_key = APIKey(
            user_id=user.id,
            key_hash=key_hash,
            key_salt=key_salt,
            key_prefix=key_prefix,
            name="Admin Key",
            scopes=["domains:read", "domains:write", "domains:delete"],
            is_active=True,
        )
        test_session.add(api_key)
        await test_session.commit()
        await test_session.refresh(user)
        await test_session.refresh(domain)

        return user, domain, full_key

    @pytest.mark.asyncio
    async def test_admin_can_update_domain(
        self, app, admin_user_with_domain: tuple[User, Domain, str]
    ):
        """Test admin can update domain settings."""
        user, domain, api_key = admin_user_with_domain

        async with api_client(app, api_key) as admin_client:
            response = await admin_client.put(
                f"/api/v1/domains/{domain.id}",
                json={"is_enabled": False},
            )
            assert response.status_code == 200
            assert response.json()["is_enabled"] is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "field", ["verify_dkim", "verify_spf", "reject_dkim_fail", "reject_spf_fail"]
    )
    async def test_admin_cannot_set_an_authentication_field(
        self,
        app,
        test_session: AsyncSession,
        admin_user_with_domain: tuple[User, Domain, str],
        field: str,
    ):
        """A domain admin may not opt their domain out of the server-wide policy."""
        user, domain, api_key = admin_user_with_domain

        async with api_client(app, api_key) as admin_client:
            response = await admin_client.put(
                f"/api/v1/domains/{domain.id}",
                json={field: False},
            )

        assert response.status_code == 403
        detail = response.json()["detail"]
        assert field in detail
        assert "superuser only" in detail
        await test_session.refresh(domain)
        assert getattr(domain, field) is None

    @pytest.mark.asyncio
    async def test_admin_may_set_an_authentication_field_back_to_inherit(
        self, app, admin_user_with_domain: tuple[User, Domain, str]
    ):
        """An explicit null is not an opt-out: it hands the decision back to the server."""
        user, domain, api_key = admin_user_with_domain

        async with api_client(app, api_key) as admin_client:
            response = await admin_client.put(
                f"/api/v1/domains/{domain.id}",
                json={"verify_dkim": None},
            )

        assert response.status_code == 200
        assert response.json()["verify_dkim"] is None

    @pytest.mark.asyncio
    async def test_superuser_can_set_the_authentication_fields(
        self, auth_client: AsyncClient, admin_user_with_domain: tuple[User, Domain, str]
    ):
        """The operator keeps the fields the domain admin is refused."""
        user, domain, _api_key = admin_user_with_domain

        response = await auth_client.put(
            f"/api/v1/domains/{domain.id}",
            json={"reject_dkim_fail": True},
        )

        assert response.status_code == 200
        assert response.json()["reject_dkim_fail"] is True

    @pytest.mark.asyncio
    async def test_admin_cannot_delete_domain(
        self, app, admin_user_with_domain: tuple[User, Domain, str]
    ):
        """Test admin cannot delete domain (requires owner)."""
        user, domain, api_key = admin_user_with_domain

        async with api_client(app, api_key) as admin_client:
            response = await admin_client.delete(f"/api/v1/domains/{domain.id}")
            assert response.status_code == 403
            assert "owner" in response.json()["detail"].lower()


class TestDomainConflictRace:
    """The loser of a concurrent duplicate write must get the pre-check's 409.

    create_domain and add_member are check-then-flush, so two concurrent
    requests can both pass the duplicate check; the loser then hits a unique
    index at flush time. The loser is simulated deterministically by patching
    the pre-check filter to match nothing, which is exactly what its stale
    read saw.
    """

    @pytest.fixture
    def losing_precheck(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Make the duplicate pre-checks see no conflict, as the race's loser does."""
        import fastsmtp.api.domains as domains_api

        async def name_is_free(
            session: AsyncSession, model, column, value, *, exclude_id=None
        ) -> bool:
            return False

        monkeypatch.setattr(domains_api, "live_value_taken", name_is_free)
        monkeypatch.setattr(domains_api, "_membership", lambda domain_id, user_id: false())

    @pytest.mark.asyncio
    async def test_raced_duplicate_domain_create_returns_409(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        losing_precheck: None,
    ):
        """A domain create that loses the race gets 409, not a 500 from the index."""
        test_session.add(Domain(domain_name="raced.example.com", is_enabled=True))
        await test_session.commit()

        response = await auth_client.post(
            "/api/v1/domains", json={"domain_name": "raced.example.com"}
        )
        assert response.status_code == 409
        assert response.json()["detail"] == "Domain already exists"

        # The translated conflict must leave the app serviceable
        fresh = await auth_client.post(
            "/api/v1/domains", json={"domain_name": "unraced.example.com"}
        )
        assert fresh.status_code == 201

    @pytest.mark.asyncio
    async def test_raced_duplicate_member_add_returns_409(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        losing_precheck: None,
    ):
        """A member add that loses the race gets 409 from uq_domain_member."""
        domain = Domain(domain_name="members-raced.example.com", is_enabled=True)
        user = User(username="raced-member", is_active=True)
        test_session.add_all([domain, user])
        await test_session.flush()
        test_session.add(DomainMember(domain_id=domain.id, user_id=user.id, role="member"))
        await test_session.commit()

        response = await auth_client.post(
            f"/api/v1/domains/{domain.id}/members",
            json={"user_id": str(user.id), "role": "admin"},
        )
        assert response.status_code == 409
        assert response.json()["detail"] == "User is already a member of this domain"

    @pytest.mark.asyncio
    async def test_raced_restore_returns_409(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        losing_precheck: None,
    ):
        """A restore that loses the race to a re-created name hits the 008 index -> 409.

        The partial unique index only covers live rows, so clearing the
        tombstone while a live row holds the name is the violation.
        """
        old = Domain(domain_name="phoenix.example.com", is_enabled=True)
        test_session.add(old)
        await test_session.commit()
        await soft_delete_domain(test_session, old)
        await test_session.commit()
        test_session.add(Domain(domain_name="phoenix.example.com", is_enabled=True))
        await test_session.commit()

        response = await auth_client.post(f"/api/v1/domains/{old.id}/restore")
        assert response.status_code == 409
        assert response.json()["detail"] == "Domain already exists"

        # The translated conflict must leave the app serviceable
        fresh = await auth_client.post(
            "/api/v1/domains", json={"domain_name": "unraced.example.com"}
        )
        assert fresh.status_code == 201


ClientFor = Callable[[User], Awaitable[AsyncClient]]


async def _persist(session: AsyncSession, *rows: object) -> None:
    session.add_all(rows)
    await session.commit()
    for row in rows:
        await session.refresh(row)


async def _add_delivery(
    session: AsyncSession,
    domain: Domain,
    recipient: Recipient | None,
    status: str,
) -> DeliveryLog:
    delivery = DeliveryLog(
        domain_id=domain.id,
        recipient_id=recipient.id if recipient else None,
        message_id=f"<{uuid.uuid4()}@example.com>",
        webhook_url="https://example.com/hook",
        payload_hash="abc123",
        payload={},
        status=status,
        attempts=1,
        next_retry_at=datetime.now(UTC) - timedelta(minutes=1),
        instance_id="test-instance",
    )
    session.add(delivery)
    await session.commit()
    await session.refresh(delivery)
    return delivery


class TestDomainSoftDelete:
    """DELETE tombstones (cascading to recipients and queued deliveries), restore
    clears it, purge is the old hard delete on a tombstone (spec #106 s4.3)."""

    @pytest_asyncio.fixture
    async def client_for(
        self, app: FastAPI, test_session: AsyncSession
    ) -> AsyncIterator[ClientFor]:
        """Build an authenticated client for a (persisted) user with a fresh key."""
        clients: list[AsyncClient] = []

        async def make(user: User) -> AsyncClient:
            full_key, key_prefix, key_hash, key_salt = generate_api_key()
            test_session.add(
                APIKey(
                    user_id=user.id,
                    key_hash=key_hash,
                    key_salt=key_salt,
                    key_prefix=key_prefix,
                    name=f"{user.username} key",
                    scopes=["admin"],
                    is_active=True,
                )
            )
            await test_session.commit()
            client = api_client(app, full_key)
            clients.append(client)
            return client

        yield make
        for client in clients:
            await client.aclose()

    @pytest_asyncio.fixture
    async def domain(self, test_session: AsyncSession) -> Domain:
        domain = Domain(domain_name="example.com", is_enabled=True)
        await _persist(test_session, domain)
        return domain

    @pytest_asyncio.fixture
    async def members(self, test_session: AsyncSession, domain: Domain) -> dict[str, User]:
        """One user per role on ``domain`` plus an outsider, keyed by role name."""
        users = {
            role: User(username=role, email=f"{role}@example.com", is_active=True)
            for role in ("owner", "admin", "member", "outsider")
        }
        await _persist(test_session, *users.values())
        for role in ("owner", "admin", "member"):
            test_session.add(DomainMember(domain_id=domain.id, user_id=users[role].id, role=role))
        await test_session.commit()
        return users

    @pytest_asyncio.fixture
    async def deleted_domain(
        self, auth_client: AsyncClient, test_session: AsyncSession, domain: Domain
    ) -> Domain:
        response = await auth_client.delete(f"/api/v1/domains/{domain.id}")
        assert response.status_code == 200
        await test_session.refresh(domain)
        assert domain.deleted_at is not None
        return domain

    # -- delete -------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_delete_tombstones_and_keeps_message(
        self, auth_client: AsyncClient, test_session: AsyncSession, domain: Domain
    ):
        response = await auth_client.delete(f"/api/v1/domains/{domain.id}")
        assert response.status_code == 200
        assert response.json()["message"] == "Domain example.com deleted"

        await test_session.refresh(domain)
        assert domain.deleted_at is not None

    @pytest.mark.asyncio
    async def test_delete_stamps_live_recipients_with_the_same_timestamp(
        self, auth_client: AsyncClient, test_session: AsyncSession, domain: Domain
    ):
        sales = Recipient(domain_id=domain.id, local_part="sales", webhook_url="https://x/s")
        catch_all = Recipient(domain_id=domain.id, local_part=None, webhook_url="https://x/c")
        earlier = Recipient(domain_id=domain.id, local_part="old", webhook_url="https://x/o")
        await _persist(test_session, sales, catch_all, earlier)
        await soft_delete_recipient(test_session, earlier)
        await test_session.commit()
        earlier_stamp = earlier.deleted_at

        assert (await auth_client.delete(f"/api/v1/domains/{domain.id}")).status_code == 200

        for row in (domain, sales, catch_all, earlier):
            await test_session.refresh(row)
        assert domain.deleted_at is not None
        assert sales.deleted_at == domain.deleted_at
        assert catch_all.deleted_at == domain.deleted_at
        # A recipient deleted independently earlier keeps its own tombstone
        assert earlier.deleted_at == earlier_stamp
        assert earlier.deleted_at != domain.deleted_at

    @pytest.mark.asyncio
    async def test_delete_cancels_queued_deliveries_only(
        self, auth_client: AsyncClient, test_session: AsyncSession, domain: Domain
    ):
        recipient = Recipient(domain_id=domain.id, local_part="sales", webhook_url="https://x/s")
        await _persist(test_session, recipient)
        pending = await _add_delivery(test_session, domain, recipient, DeliveryStatus.PENDING)
        failed = await _add_delivery(test_session, domain, recipient, DeliveryStatus.FAILED)
        legacy = await _add_delivery(test_session, domain, None, DeliveryStatus.PENDING)
        delivered = await _add_delivery(test_session, domain, recipient, DeliveryStatus.DELIVERED)
        exhausted = await _add_delivery(test_session, domain, recipient, DeliveryStatus.EXHAUSTED)

        assert (await auth_client.delete(f"/api/v1/domains/{domain.id}")).status_code == 200

        for row in (pending, failed, legacy, delivered, exhausted):
            await test_session.refresh(row)
        for row in (pending, failed, legacy):
            assert row.status == DeliveryStatus.CANCELLED
            assert row.next_retry_at is None
            assert row.last_error == "Domain deleted"
        assert delivered.status == DeliveryStatus.DELIVERED
        assert exhausted.status == DeliveryStatus.EXHAUSTED

    @pytest.mark.asyncio
    async def test_delete_tombstone_again_is_404(
        self, auth_client: AsyncClient, deleted_domain: Domain
    ):
        response = await auth_client.delete(f"/api/v1/domains/{deleted_domain.id}")
        assert response.status_code == 404
        assert response.json()["detail"] == "Domain not found"

    @pytest.mark.asyncio
    async def test_owner_can_delete_admin_and_member_cannot(
        self,
        test_session: AsyncSession,
        client_for: ClientFor,
        domain: Domain,
        members: dict[str, User],
    ):
        for role in ("member", "admin"):
            client = await client_for(members[role])
            response = await client.delete(f"/api/v1/domains/{domain.id}")
            assert response.status_code == 403, role
            assert "owner" in response.json()["detail"].lower()

        owner = await client_for(members["owner"])
        response = await owner.delete(f"/api/v1/domains/{domain.id}")
        assert response.status_code == 200

        await test_session.refresh(domain)
        assert domain.deleted_at is not None

    # -- reads --------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_get_hides_tombstone_unless_include_deleted(
        self, auth_client: AsyncClient, deleted_domain: Domain
    ):
        response = await auth_client.get(f"/api/v1/domains/{deleted_domain.id}")
        assert response.status_code == 404
        assert response.json()["detail"] == "Domain not found"

        response = await auth_client.get(
            f"/api/v1/domains/{deleted_domain.id}", params={"include_deleted": "true"}
        )
        assert response.status_code == 200
        assert response.json()["deleted_at"] is not None

    @pytest.mark.asyncio
    async def test_list_hides_tombstone_unless_include_deleted(
        self, auth_client: AsyncClient, deleted_domain: Domain
    ):
        response = await auth_client.get("/api/v1/domains")
        assert response.status_code == 200
        assert "example.com" not in {d["domain_name"] for d in response.json()}

        response = await auth_client.get("/api/v1/domains", params={"include_deleted": "true"})
        assert response.status_code == 200
        rows = {d["domain_name"]: d for d in response.json()}
        assert rows["example.com"]["deleted_at"] is not None

    @pytest.mark.asyncio
    async def test_member_list_shows_tombstones_only_to_owners(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        client_for: ClientFor,
        domain: Domain,
        members: dict[str, User],
    ):
        """S5: the member branch of GET /domains filters tombstones, and with the
        flag reveals a tombstoned domain only where the caller is its owner."""
        live = Domain(domain_name="live.example.com", is_enabled=True)
        await _persist(test_session, live)
        for role in ("owner", "admin", "member"):
            test_session.add(DomainMember(domain_id=live.id, user_id=members[role].id, role=role))
        await test_session.commit()
        clients = {role: await client_for(members[role]) for role in ("owner", "admin", "member")}

        assert (await auth_client.delete(f"/api/v1/domains/{domain.id}")).status_code == 200

        for role, client in clients.items():
            response = await client.get("/api/v1/domains")
            assert response.status_code == 200, role
            assert {d["domain_name"] for d in response.json()} == {"live.example.com"}, role

        for role in ("admin", "member"):
            response = await clients[role].get(
                "/api/v1/domains", params={"include_deleted": "true"}
            )
            assert response.status_code == 200, role
            assert {d["domain_name"] for d in response.json()} == {"live.example.com"}, role

        response = await clients["owner"].get("/api/v1/domains", params={"include_deleted": "true"})
        assert response.status_code == 200
        rows = {d["domain_name"]: d for d in response.json()}
        assert set(rows) == {"live.example.com", "example.com"}
        assert rows["example.com"]["deleted_at"] is not None
        assert rows["live.example.com"]["deleted_at"] is None

    @pytest.mark.asyncio
    async def test_get_include_deleted_is_owner_gated_up_front(
        self,
        auth_client: AsyncClient,
        client_for: ClientFor,
        domain: Domain,
        members: dict[str, User],
    ):
        """The flag elevates the role before the lookup: on a live domain a
        non-owner gets 403 whether member or outsider; once tombstoned, the
        same callers get the not-found answer and the owner sees the row."""
        clients = {role: await client_for(user) for role, user in members.items()}

        for role in ("admin", "member", "outsider"):
            response = await clients[role].get(
                f"/api/v1/domains/{domain.id}", params={"include_deleted": "true"}
            )
            assert response.status_code == 403, role

        assert (await auth_client.delete(f"/api/v1/domains/{domain.id}")).status_code == 200

        for role in ("admin", "member", "outsider"):
            for params in ({}, {"include_deleted": "true"}):
                response = await clients[role].get(f"/api/v1/domains/{domain.id}", params=params)
                assert response.status_code == 404, (role, params)
                assert response.json()["detail"] == "Domain not found"

        response = await clients["owner"].get(f"/api/v1/domains/{domain.id}")
        assert response.status_code == 404
        response = await clients["owner"].get(
            f"/api/v1/domains/{domain.id}", params={"include_deleted": "true"}
        )
        assert response.status_code == 200
        assert response.json()["deleted_at"] is not None

    @pytest.mark.asyncio
    async def test_update_tombstone_is_404(self, auth_client: AsyncClient, deleted_domain: Domain):
        response = await auth_client.put(
            f"/api/v1/domains/{deleted_domain.id}", json={"is_enabled": False}
        )
        assert response.status_code == 404

    NESTED_ROUTES = [
        ("GET", "/recipients", None),
        ("POST", "/recipients", {"local_part": "x", "webhook_url": "https://example.com/h"}),
        ("GET", "/recipients/{recipient_id}", None),
        ("PUT", "/recipients/{recipient_id}", {"is_enabled": False}),
        ("DELETE", "/recipients/{recipient_id}", None),
        ("GET", "/rulesets", None),
        ("POST", "/rulesets", {"name": "new"}),
        ("GET", "/rulesets/{ruleset_id}", None),
        ("PUT", "/rulesets/{ruleset_id}", {"name": "renamed"}),
        ("DELETE", "/rulesets/{ruleset_id}", None),
        (
            "POST",
            "/rulesets/{ruleset_id}/rules",
            {"field": "subject", "operator": "contains", "value": "x"},
        ),
        ("PUT", "/rules/{rule_id}", {"value": "y"}),
        ("DELETE", "/rules/{rule_id}", None),
        ("GET", "/members", None),
        ("POST", "/members", {"user_id": "{user_id}", "role": "member"}),
        ("PUT", "/members/{user_id}", {"role": "admin"}),
        ("DELETE", "/members/{user_id}", None),
        ("GET", "/delivery-log", None),
    ]

    @pytest.mark.asyncio
    async def test_every_nested_route_is_404_under_a_tombstoned_domain(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        domain: Domain,
        members: dict[str, User],
    ):
        """S4: rulesets, rules, recipients, members and history of a tombstoned
        domain are unreachable, even to a superuser without the flag."""
        recipient = Recipient(domain_id=domain.id, local_part="sales", webhook_url="https://x/s")
        ruleset = RuleSet(domain_id=domain.id, name="rs")
        await _persist(test_session, recipient, ruleset)
        rule = Rule(ruleset_id=ruleset.id, order=0, field="subject", operator="contains", value="a")
        await _persist(test_session, rule)
        ids = {
            "recipient_id": str(recipient.id),
            "ruleset_id": str(ruleset.id),
            "rule_id": str(rule.id),
            "user_id": str(members["outsider"].id),
        }

        assert (await auth_client.delete(f"/api/v1/domains/{domain.id}")).status_code == 200

        for method, suffix, body in self.NESTED_ROUTES:
            path = f"/api/v1/domains/{domain.id}" + suffix.format(**ids)
            json = {
                k: v.format(**ids) if isinstance(v, str) else v for k, v in (body or {}).items()
            }
            response = await auth_client.request(method, path, json=json or None)
            assert response.status_code == 404, (method, suffix, response.text)
            assert response.json()["detail"] == "Domain not found", (method, suffix)

    # -- name reuse (S18) ---------------------------------------------------

    @pytest.mark.asyncio
    async def test_create_after_delete_is_201(
        self, auth_client: AsyncClient, deleted_domain: Domain
    ):
        """Migration 008 frees the name, and the pre-check must not see the tombstone."""
        response = await auth_client.post("/api/v1/domains", json={"domain_name": "example.com"})
        assert response.status_code == 201
        assert response.json()["id"] != str(deleted_domain.id)

        # Both rows now share a name; every by-name path must stay unambiguous
        response = await auth_client.get("/api/v1/domains", params={"include_deleted": "true"})
        assert [d["domain_name"] for d in response.json()] == ["example.com", "example.com"]

    # -- restore ------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_restore_clears_tombstone_and_brings_back_children(
        self, auth_client: AsyncClient, test_session: AsyncSession, domain: Domain
    ):
        sales = Recipient(domain_id=domain.id, local_part="sales", webhook_url="https://x/s")
        earlier = Recipient(domain_id=domain.id, local_part="old", webhook_url="https://x/o")
        ruleset = RuleSet(domain_id=domain.id, name="rs")
        await _persist(test_session, sales, earlier, ruleset)
        rule = Rule(ruleset_id=ruleset.id, order=0, field="subject", operator="contains", value="a")
        await _persist(test_session, rule)
        await soft_delete_recipient(test_session, earlier)
        await test_session.commit()
        assert (await auth_client.delete(f"/api/v1/domains/{domain.id}")).status_code == 200

        response = await auth_client.post(f"/api/v1/domains/{domain.id}/restore")
        assert response.status_code == 200
        body = response.json()
        assert body["id"] == str(domain.id)
        assert body["deleted_at"] is None

        assert (await auth_client.get(f"/api/v1/domains/{domain.id}")).status_code == 200

        for row in (domain, sales, earlier):
            await test_session.refresh(row)
        assert domain.deleted_at is None
        assert sales.deleted_at is None
        # Restore is scoped to the domain's own stamp: the older tombstone survives
        assert earlier.deleted_at is not None

        response = await auth_client.get(f"/api/v1/domains/{domain.id}/rulesets")
        assert response.status_code == 200
        assert [rs["name"] for rs in response.json()] == ["rs"]
        response = await auth_client.get(f"/api/v1/domains/{domain.id}/rulesets/{ruleset.id}")
        assert [r["id"] for r in response.json()["rules"]] == [str(rule.id)]

    @pytest.mark.asyncio
    async def test_restore_live_is_409(self, auth_client: AsyncClient, domain: Domain):
        response = await auth_client.post(f"/api/v1/domains/{domain.id}/restore")
        assert response.status_code == 409
        assert response.json()["detail"] == "Domain is not deleted"

    @pytest.mark.asyncio
    async def test_restore_unknown_is_404(self, auth_client: AsyncClient):
        response = await auth_client.post(f"/api/v1/domains/{uuid.uuid4()}/restore")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_restore_retaken_name_is_409(
        self, auth_client: AsyncClient, test_session: AsyncSession, deleted_domain: Domain
    ):
        assert (
            await auth_client.post("/api/v1/domains", json={"domain_name": "example.com"})
        ).status_code == 201

        response = await auth_client.post(f"/api/v1/domains/{deleted_domain.id}/restore")
        assert response.status_code == 409
        assert response.json()["detail"] == "Domain already exists"

        await test_session.refresh(deleted_domain)
        assert deleted_domain.deleted_at is not None

    @pytest.mark.asyncio
    async def test_restore_permissions_mirror_delete(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        client_for: ClientFor,
        domain: Domain,
        members: dict[str, User],
    ):
        """Owner restores; below owner a tombstone is invisible (404, spec s3 step 4)."""
        clients = {role: await client_for(user) for role, user in members.items()}
        assert (await auth_client.delete(f"/api/v1/domains/{domain.id}")).status_code == 200

        for role in ("admin", "member", "outsider"):
            response = await clients[role].post(f"/api/v1/domains/{domain.id}/restore")
            assert response.status_code == 404, role
            assert response.json()["detail"] == "Domain not found"

        response = await clients["owner"].post(f"/api/v1/domains/{domain.id}/restore")
        assert response.status_code == 200
        await test_session.refresh(domain)
        assert domain.deleted_at is None

    # -- purge --------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_purge_live_is_409(
        self, auth_client: AsyncClient, test_session: AsyncSession, domain: Domain
    ):
        response = await auth_client.delete(
            f"/api/v1/domains/{domain.id}", params={"purge": "true"}
        )
        assert response.status_code == 409
        assert response.json()["detail"] == "Domain must be deleted before it can be purged"

        await test_session.refresh(domain)
        assert domain.deleted_at is None

    @pytest.mark.asyncio
    async def test_purge_below_superuser_is_403_regardless_of_state(
        self,
        auth_client: AsyncClient,
        client_for: ClientFor,
        domain: Domain,
        members: dict[str, User],
    ):
        owner = await client_for(members["owner"])

        response = await owner.delete(f"/api/v1/domains/{domain.id}", params={"purge": "true"})
        assert response.status_code == 403
        assert response.json()["detail"] == "Superuser access required"

        assert (await auth_client.delete(f"/api/v1/domains/{domain.id}")).status_code == 200

        response = await owner.delete(f"/api/v1/domains/{domain.id}", params={"purge": "true"})
        assert response.status_code == 403
        assert response.json()["detail"] == "Superuser access required"

    @pytest.mark.asyncio
    async def test_purge_tombstone_cascades_and_orphans_history(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        domain: Domain,
        members: dict[str, User],
    ):
        recipient = Recipient(domain_id=domain.id, local_part="sales", webhook_url="https://x/s")
        ruleset = RuleSet(domain_id=domain.id, name="rs")
        await _persist(test_session, recipient, ruleset)
        rule = Rule(ruleset_id=ruleset.id, order=0, field="subject", operator="contains", value="a")
        await _persist(test_session, rule)
        delivery = await _add_delivery(test_session, domain, recipient, DeliveryStatus.DELIVERED)
        assert (await auth_client.delete(f"/api/v1/domains/{domain.id}")).status_code == 200

        response = await auth_client.delete(
            f"/api/v1/domains/{domain.id}", params={"purge": "true"}
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Domain example.com purged"

        domain_id, rule_id = domain.id, rule.id
        test_session.expire_all()
        for model, column in (
            (Domain, Domain.id),
            (Recipient, Recipient.domain_id),
            (RuleSet, RuleSet.domain_id),
            (DomainMember, DomainMember.domain_id),
        ):
            rows = (await test_session.execute(select(model).where(column == domain_id))).all()
            assert rows == [], model.__name__
        assert (
            await test_session.execute(select(Rule).where(Rule.id == rule_id))
        ).scalar_one_or_none() is None
        # Users behind the memberships are untouched
        assert len((await test_session.execute(select(User))).scalars().all()) == 4

        await test_session.refresh(delivery)
        assert delivery.domain_id is None
        assert delivery.recipient_id is None

        response = await auth_client.get(
            f"/api/v1/domains/{domain_id}", params={"include_deleted": "true"}
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_purge_unknown_is_404(self, auth_client: AsyncClient):
        response = await auth_client.delete(
            f"/api/v1/domains/{uuid.uuid4()}", params={"purge": "true"}
        )
        assert response.status_code == 404

    # -- history survives (the #106 payoff) --------------------------------

    @pytest.mark.asyncio
    async def test_delivery_log_keeps_its_links_through_delete_and_restore(
        self, auth_client: AsyncClient, test_session: AsyncSession, domain: Domain
    ):
        recipient = Recipient(domain_id=domain.id, local_part="sales", webhook_url="https://x/s")
        await _persist(test_session, recipient)
        delivery = await _add_delivery(test_session, domain, recipient, DeliveryStatus.DELIVERED)
        log_url = f"/api/v1/domains/{domain.id}/delivery-log"
        assert [d["id"] for d in (await auth_client.get(log_url)).json()] == [str(delivery.id)]

        assert (await auth_client.delete(f"/api/v1/domains/{domain.id}")).status_code == 200

        await test_session.refresh(delivery)
        assert delivery.domain_id == domain.id
        assert delivery.recipient_id == recipient.id
        assert (await auth_client.get(log_url)).status_code == 404

        assert (await auth_client.post(f"/api/v1/domains/{domain.id}/restore")).status_code == 200

        response = await auth_client.get(log_url)
        assert response.status_code == 200
        assert [d["id"] for d in response.json()] == [str(delivery.id)]
        assert response.json()[0]["recipient_id"] == str(recipient.id)


class TestMembersHideTombstonedUsers:
    """S7/S8: a tombstoned user's membership is hidden and cannot be touched
    until the user is restored; a tombstone cannot be added as a member."""

    @pytest_asyncio.fixture
    async def domain(self, test_session: AsyncSession) -> Domain:
        domain = Domain(domain_name="members.example.com", is_enabled=True)
        await _persist(test_session, domain)
        return domain

    @pytest_asyncio.fixture
    async def deleted_member(self, test_session: AsyncSession, domain: Domain) -> User:
        """A user who is a member of ``domain`` and has since been tombstoned."""
        user = User(username="ghost", email="ghost@example.com", is_active=True)
        live = User(username="alive", email="alive@example.com", is_active=True)
        await _persist(test_session, user, live)
        test_session.add_all(
            [
                DomainMember(domain_id=domain.id, user_id=user.id, role="admin"),
                DomainMember(domain_id=domain.id, user_id=live.id, role="member"),
            ]
        )
        await test_session.commit()
        await soft_delete_user(test_session, user)
        await test_session.commit()
        return user

    @pytest.mark.asyncio
    async def test_list_members_omits_tombstoned_user(
        self, auth_client: AsyncClient, domain: Domain, deleted_member: User
    ):
        response = await auth_client.get(f"/api/v1/domains/{domain.id}/members")
        assert response.status_code == 200
        assert [m["username"] for m in response.json()] == ["alive"]

    @pytest.mark.asyncio
    async def test_update_and_remove_tombstoned_membership_are_404(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        domain: Domain,
        deleted_member: User,
    ):
        url = f"/api/v1/domains/{domain.id}/members/{deleted_member.id}"

        response = await auth_client.put(url, json={"role": "owner"})
        assert response.status_code == 404
        assert response.json()["detail"] == "Member not found"

        response = await auth_client.delete(url)
        assert response.status_code == 404
        assert response.json()["detail"] == "Member not found"

        # The edge itself is untouched, waiting for the user to come back
        membership = (
            await test_session.execute(
                select(DomainMember).where(
                    DomainMember.domain_id == domain.id, DomainMember.user_id == deleted_member.id
                )
            )
        ).scalar_one()
        assert membership.role == "admin"

    @pytest.mark.asyncio
    async def test_add_tombstoned_user_is_404(
        self, auth_client: AsyncClient, test_session: AsyncSession, deleted_member: User
    ):
        other = Domain(domain_name="other.example.com", is_enabled=True)
        await _persist(test_session, other)

        response = await auth_client.post(
            f"/api/v1/domains/{other.id}/members",
            json={"user_id": str(deleted_member.id), "role": "member"},
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "User not found"

    @pytest.mark.asyncio
    async def test_membership_returns_with_the_restored_user(
        self, auth_client: AsyncClient, domain: Domain, deleted_member: User
    ):
        assert (
            await auth_client.post(f"/api/v1/users/{deleted_member.id}/restore")
        ).status_code == 200

        response = await auth_client.get(f"/api/v1/domains/{domain.id}/members")
        assert {m["username"]: m["role"] for m in response.json()} == {
            "ghost": "admin",
            "alive": "member",
        }
