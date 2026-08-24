"""Extended tests for operations API endpoints to improve coverage."""

import hashlib
import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastsmtp.auth import generate_api_key
from fastsmtp.db.enums import DeliveryStatus
from fastsmtp.db.models import APIKey, DeliveryLog, Domain, DomainMember, Recipient, User
from fastsmtp.db.soft_delete import (
    restore_domain,
    restore_recipient,
    soft_delete_domain,
    soft_delete_recipient,
)
from fastsmtp.webhook.queue import RETRYABLE_STATUSES
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker


class TestDeliveryLogsExtended:
    """Extended tests for delivery log operations."""

    @pytest.mark.asyncio
    async def test_list_delivery_logs_with_status_filter(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
    ):
        """Test filtering delivery logs by status."""
        # Create domain
        domain = Domain(domain_name="logs-status-filter.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Create logs with different statuses
        for i, status in enumerate(["pending", "delivered", "failed"]):
            log = DeliveryLog(
                domain_id=domain.id,
                webhook_url="https://webhook.example.com",
                status=status,
                message_id=f"<msg{i}@test.com>",
                payload={"test": True},
                payload_hash=hashlib.sha256(f"test{i}".encode()).hexdigest(),
                instance_id="test-instance",
            )
            test_session.add(log)
        await test_session.commit()
        await test_session.refresh(domain)

        response = await auth_client.get(
            f"/api/v1/domains/{domain.id}/delivery-log",
            params={"status": "delivered"},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["status"] == "delivered"

    @pytest.mark.asyncio
    async def test_list_delivery_logs_with_message_id_filter(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
    ):
        """Test filtering delivery logs by message_id."""
        # Create domain
        domain = Domain(domain_name="logs-msgid-filter.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Create logs
        for i in range(3):
            log = DeliveryLog(
                domain_id=domain.id,
                webhook_url="https://webhook.example.com",
                status="delivered",
                message_id=f"<msg{i}@test.com>",
                payload={"test": True},
                payload_hash=hashlib.sha256(f"test{i}".encode()).hexdigest(),
                instance_id="test-instance",
            )
            test_session.add(log)
        await test_session.commit()
        await test_session.refresh(domain)

        response = await auth_client.get(
            f"/api/v1/domains/{domain.id}/delivery-log",
            params={"message_id": "<msg0@test.com>"},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["message_id"] == "<msg0@test.com>"

    @pytest.mark.asyncio
    async def test_get_delivery_log_success(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
    ):
        """Test getting a specific delivery log."""
        # Create domain
        domain = Domain(domain_name="logs-get-success.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Create log
        log = DeliveryLog(
            domain_id=domain.id,
            webhook_url="https://webhook.example.com",
            status="delivered",
            message_id="<test@test.com>",
            payload={"test": True},
            payload_hash=hashlib.sha256(b"test").hexdigest(),
            instance_id="test-instance",
        )
        test_session.add(log)
        await test_session.commit()
        await test_session.refresh(log)

        response = await auth_client.get(f"/api/v1/delivery-log/{log.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(log.id)
        assert "payload" in data

    @pytest.mark.asyncio
    async def test_get_delivery_log_not_found(self, auth_client: AsyncClient):
        """Test getting non-existent delivery log returns 404."""
        fake_id = uuid.uuid4()
        response = await auth_client.get(f"/api/v1/delivery-log/{fake_id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_retry_delivery_success(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
    ):
        """Test retrying a failed delivery."""
        # Create domain
        domain = Domain(domain_name="retry-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        log = DeliveryLog(
            domain_id=domain.id,
            webhook_url="https://webhook.example.com",
            status="failed",
            message_id="<retry@test.com>",
            payload={"test": True},
            payload_hash=hashlib.sha256(b"retry").hexdigest(),
            instance_id="test-instance",
        )
        test_session.add(log)
        await test_session.commit()
        await test_session.refresh(log)

        response = await auth_client.post(f"/api/v1/delivery-log/{log.id}/retry")
        assert response.status_code == 200
        assert "queued for retry" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_retry_delivery_exhausted(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
    ):
        """Test retrying an exhausted delivery."""
        # Create domain
        domain = Domain(domain_name="exhausted-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        log = DeliveryLog(
            domain_id=domain.id,
            webhook_url="https://webhook.example.com",
            status="exhausted",
            message_id="<exhausted@test.com>",
            payload={"test": True},
            payload_hash=hashlib.sha256(b"exhausted").hexdigest(),
            instance_id="test-instance",
        )
        test_session.add(log)
        await test_session.commit()
        await test_session.refresh(log)

        response = await auth_client.post(f"/api/v1/delivery-log/{log.id}/retry")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_retry_delivery_not_failed(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
    ):
        """Test retrying a non-failed delivery fails."""
        # Create domain
        domain = Domain(domain_name="delivered-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        log = DeliveryLog(
            domain_id=domain.id,
            webhook_url="https://webhook.example.com",
            status="delivered",
            message_id="<delivered@test.com>",
            payload={"test": True},
            payload_hash=hashlib.sha256(b"delivered").hexdigest(),
            instance_id="test-instance",
        )
        test_session.add(log)
        await test_session.commit()
        await test_session.refresh(log)

        response = await auth_client.post(f"/api/v1/delivery-log/{log.id}/retry")
        assert response.status_code == 400
        assert "Cannot retry" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_retry_delivery_not_found(self, auth_client: AsyncClient):
        """Test retrying non-existent delivery returns 404."""
        fake_id = uuid.uuid4()
        response = await auth_client.post(f"/api/v1/delivery-log/{fake_id}/retry")
        assert response.status_code == 404


class TestTestWebhook:
    """Tests for webhook testing endpoint."""

    @pytest.mark.asyncio
    async def test_test_webhook_success(self, auth_client: AsyncClient):
        """Test webhook testing with valid URL."""
        # Using httpbin.org for testing
        response = await auth_client.post(
            "/api/v1/test-webhook",
            json={
                "webhook_url": "https://httpbin.org/post",
                "from_address": "test@example.com",
                "to_address": "recipient@example.com",
                "subject": "Test Subject",
                "body": "Test body",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "success" in data
        assert "response_time_ms" in data

    @pytest.mark.asyncio
    async def test_test_webhook_invalid_url(self, auth_client: AsyncClient):
        """Test webhook testing with invalid URL."""
        response = await auth_client.post(
            "/api/v1/test-webhook",
            json={
                "webhook_url": "https://invalid.nonexistent.domain.example/webhook",
                "from_address": "test@example.com",
                "to_address": "recipient@example.com",
                "subject": "Test",
                "body": "Test",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "error" in data


class TestHealthCheckDepth:
    """Tests for health check depth feature (queue stats and SMTP check)."""

    @pytest.mark.asyncio
    async def test_ready_basic(self, auth_client: AsyncClient):
        """Test basic ready endpoint without optional parameters."""
        response = await auth_client.get("/api/v1/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["database"] == "ok"
        # Optional fields should not be present
        assert data.get("smtp") is None
        assert data.get("queue") is None

    @pytest.mark.asyncio
    async def test_ready_with_queue_stats_empty(self, auth_client: AsyncClient):
        """Test ready endpoint with queue stats when queue is empty."""
        response = await auth_client.get("/api/v1/ready", params={"include_queue": True})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["database"] == "ok"
        # Queue stats should be present
        assert data["queue"] is not None
        assert data["queue"]["pending"] >= 0
        assert data["queue"]["failed"] >= 0
        assert data["queue"]["exhausted"] >= 0

    @pytest.mark.asyncio
    async def test_ready_with_queue_stats_populated(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test ready endpoint with queue stats when there are deliveries."""
        # Create a domain for deliveries
        domain = Domain(domain_name="queue-stats-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Create deliveries with various statuses
        statuses = [
            (DeliveryStatus.PENDING, 3),
            (DeliveryStatus.FAILED, 2),
            (DeliveryStatus.EXHAUSTED, 1),
            (DeliveryStatus.DELIVERED, 5),  # Should not be counted
        ]
        for status, count in statuses:
            for i in range(count):
                log = DeliveryLog(
                    domain_id=domain.id,
                    webhook_url="https://webhook.example.com",
                    status=status,
                    message_id=f"<{status.value}{i}@test.com>",
                    payload={"test": True},
                    payload_hash=hashlib.sha256(f"{status.value}{i}".encode()).hexdigest(),
                    instance_id="test-instance",
                    next_retry_at=datetime.now(UTC) if status != DeliveryStatus.DELIVERED else None,
                )
                test_session.add(log)
        await test_session.commit()

        response = await auth_client.get("/api/v1/ready", params={"include_queue": True})
        assert response.status_code == 200
        data = response.json()
        assert data["queue"]["pending"] >= 3
        assert data["queue"]["failed"] >= 2
        assert data["queue"]["exhausted"] >= 1

    @pytest.mark.asyncio
    async def test_ready_with_smtp_check_unavailable(self, auth_client: AsyncClient):
        """Test ready endpoint with SMTP check when port is not listening."""
        # SMTP is not running during tests, so it should be unavailable
        # But we'll mock it to ensure predictable test results
        with patch("fastsmtp.api.operations._check_smtp_port") as mock_check:
            mock_check.return_value = "unavailable"

            response = await auth_client.get("/api/v1/ready", params={"include_smtp": True})
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ok"
            assert data["smtp"] == "unavailable"

    @pytest.mark.asyncio
    async def test_ready_with_smtp_check_ok(self, auth_client: AsyncClient):
        """Test ready endpoint with SMTP check when port is available."""
        with patch("fastsmtp.api.operations._check_smtp_port") as mock_check:
            mock_check.return_value = "ok"

            response = await auth_client.get("/api/v1/ready", params={"include_smtp": True})
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ok"
            assert data["smtp"] == "ok"

    @pytest.mark.asyncio
    async def test_ready_with_both_options(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test ready endpoint with both queue and SMTP options."""
        with patch("fastsmtp.api.operations._check_smtp_port") as mock_check:
            mock_check.return_value = "ok"

            response = await auth_client.get(
                "/api/v1/ready",
                params={"include_queue": True, "include_smtp": True},
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ok"
            assert data["database"] == "ok"
            assert data["smtp"] == "ok"
            assert data["queue"] is not None

    @pytest.mark.asyncio
    async def test_check_smtp_port_connection_refused(self):
        """Test _check_smtp_port returns unavailable when connection refused."""
        from fastsmtp.api.operations import _check_smtp_port

        # Port 1 requires root to bind, so nothing can be listening on it --
        # unlike an ephemeral-range port, which a concurrent test run's SMTP
        # server could legitimately occupy.
        result = await _check_smtp_port("127.0.0.1", 1, connect_timeout=1.0)
        assert result == "unavailable"

    @pytest.mark.asyncio
    async def test_check_smtp_port_timeout(self):
        """Test _check_smtp_port returns unavailable on timeout."""
        from fastsmtp.api.operations import _check_smtp_port

        # Use a non-routable IP to trigger timeout
        result = await _check_smtp_port("10.255.255.1", 25, connect_timeout=0.5)
        assert result == "unavailable"

    @pytest.mark.asyncio
    async def test_get_queue_stats_empty(self, test_session: AsyncSession):
        """Test _get_queue_stats with empty queue."""
        from fastsmtp.api.operations import _get_queue_stats

        stats = await _get_queue_stats(test_session)
        assert stats.pending >= 0
        assert stats.failed >= 0
        assert stats.exhausted >= 0

    @pytest.mark.asyncio
    async def test_get_queue_stats_counts_correctly(self, test_session: AsyncSession):
        """Test _get_queue_stats counts by status correctly."""
        from fastsmtp.api.operations import _get_queue_stats

        # Create a domain
        domain = Domain(domain_name="queue-stats-count.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Create specific counts of each status
        test_cases = [
            (DeliveryStatus.PENDING, 5),
            (DeliveryStatus.FAILED, 3),
            (DeliveryStatus.EXHAUSTED, 2),
            (DeliveryStatus.DELIVERED, 10),  # Should not affect counts
        ]

        for status, count in test_cases:
            for i in range(count):
                log = DeliveryLog(
                    domain_id=domain.id,
                    webhook_url="https://webhook.example.com",
                    status=status,
                    message_id=f"<count-{status.value}-{i}@test.com>",
                    payload={"test": True},
                    payload_hash=hashlib.sha256(f"count{status.value}{i}".encode()).hexdigest(),
                    instance_id="test-instance",
                )
                test_session.add(log)
        await test_session.flush()

        stats = await _get_queue_stats(test_session)
        # Note: may have other deliveries from other tests, so use >=
        assert stats.pending >= 5
        assert stats.failed >= 3
        assert stats.exhausted >= 2

    @pytest.mark.asyncio
    async def test_queue_stats_schema_defaults(self):
        """Test QueueStats schema has correct defaults."""
        from fastsmtp.schemas.common import QueueStats

        stats = QueueStats()
        assert stats.pending == 0
        assert stats.failed == 0
        assert stats.exhausted == 0

    @pytest.mark.asyncio
    async def test_ready_response_schema_optional_fields(self):
        """Test ReadyResponse schema optional fields."""
        from fastsmtp.schemas.common import QueueStats, ReadyResponse

        # Without optional fields
        response = ReadyResponse(status="ok", database="ok")
        assert response.smtp is None
        assert response.queue is None

        # With optional fields
        response_full = ReadyResponse(
            status="ok",
            database="ok",
            smtp="ok",
            queue=QueueStats(pending=5, failed=2, exhausted=1),
        )
        assert response_full.smtp == "ok"
        assert response_full.queue.pending == 5
        assert response_full.queue.failed == 2
        assert response_full.queue.exhausted == 1


def user_client(app: FastAPI, api_key: str) -> AsyncClient:
    """HTTP client authenticating with ``api_key`` instead of the root key."""
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"X-API-Key": api_key},
    )


async def add_member_with_key(
    session: AsyncSession, domain: Domain, username: str, role: str
) -> str:
    """Create a user holding ``role`` on ``domain``; return their API key secret."""
    user = User(username=username, email=f"{username}@example.com", is_active=True)
    session.add(user)
    await session.flush()
    session.add(DomainMember(domain_id=domain.id, user_id=user.id, role=role))
    full_key, key_prefix, key_hash, key_salt = generate_api_key()
    session.add(
        APIKey(
            user_id=user.id,
            key_hash=key_hash,
            key_salt=key_salt,
            key_prefix=key_prefix,
            name=f"{username} key",
            scopes=["logs:read"],
        )
    )
    await session.flush()
    return full_key


async def make_log(
    session: AsyncSession,
    domain: Domain,
    status: DeliveryStatus,
    recipient: Recipient | None = None,
) -> DeliveryLog:
    log = DeliveryLog(
        domain_id=domain.id,
        recipient_id=recipient.id if recipient else None,
        webhook_url="https://webhook.example.com",
        status=status,
        message_id=f"<{uuid.uuid4()}@test.com>",
        payload={"test": True},
        payload_hash=hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
        instance_id="test-instance",
    )
    session.add(log)
    await session.flush()
    return log


class TestDeliveryLogOfTombstonedDomain:
    """History of a soft-deleted domain stays reachable to those who could
    delete it (spec §4.6): superusers and owners read it, plain members get
    the same 404 as for a domain that never existed.
    """

    @pytest_asyncio.fixture
    async def tombstoned(self, test_session: AsyncSession) -> tuple[Domain, DeliveryLog, str, str]:
        """A tombstoned domain with one cancelled delivery; owner and member keys."""
        domain = Domain(domain_name="tombstoned-history.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()
        owner_key = await add_member_with_key(test_session, domain, "history-owner", "owner")
        member_key = await add_member_with_key(test_session, domain, "history-member", "member")
        log = await make_log(test_session, domain, DeliveryStatus.PENDING)
        await soft_delete_domain(test_session, domain)
        await test_session.commit()
        await test_session.refresh(log)
        assert log.status == DeliveryStatus.CANCELLED
        return domain, log, owner_key, member_key

    @pytest.mark.asyncio
    async def test_get_delivery_log_superuser_reads_history(
        self, auth_client: AsyncClient, tombstoned: tuple[Domain, DeliveryLog, str, str]
    ):
        domain, log, _, _ = tombstoned
        response = await auth_client.get(f"/api/v1/delivery-log/{log.id}")
        assert response.status_code == 200
        # The #106 payoff: the soft delete did not sever the FK.
        assert response.json()["domain_id"] == str(domain.id)

    @pytest.mark.asyncio
    async def test_get_delivery_log_owner_reads_history(
        self, app: FastAPI, tombstoned: tuple[Domain, DeliveryLog, str, str]
    ):
        _, log, owner_key, _ = tombstoned
        async with user_client(app, owner_key) as client:
            response = await client.get(f"/api/v1/delivery-log/{log.id}")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_get_delivery_log_member_gets_404(
        self, app: FastAPI, tombstoned: tuple[Domain, DeliveryLog, str, str]
    ):
        _, log, _, member_key = tombstoned
        async with user_client(app, member_key) as client:
            response = await client.get(f"/api/v1/delivery-log/{log.id}")
        assert response.status_code == 404
        assert response.json()["detail"] == "Domain not found"

    @pytest.mark.asyncio
    async def test_list_delivery_logs_requires_include_deleted(
        self, auth_client: AsyncClient, tombstoned: tuple[Domain, DeliveryLog, str, str]
    ):
        domain, _, _, _ = tombstoned
        response = await auth_client.get(f"/api/v1/domains/{domain.id}/delivery-log")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_list_delivery_logs_include_deleted_returns_history(
        self, app: FastAPI, tombstoned: tuple[Domain, DeliveryLog, str, str]
    ):
        domain, log, owner_key, _ = tombstoned
        async with user_client(app, owner_key) as client:
            response = await client.get(
                f"/api/v1/domains/{domain.id}/delivery-log",
                params={"include_deleted": "true", "status": "cancelled"},
            )
        assert response.status_code == 200
        assert [entry["id"] for entry in response.json()] == [str(log.id)]

    @pytest.mark.asyncio
    async def test_list_delivery_logs_include_deleted_member_gets_404(
        self, app: FastAPI, tombstoned: tuple[Domain, DeliveryLog, str, str]
    ):
        domain, _, _, member_key = tombstoned
        async with user_client(app, member_key) as client:
            response = await client.get(
                f"/api/v1/domains/{domain.id}/delivery-log",
                params={"include_deleted": "true"},
            )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_list_delivery_logs_include_deleted_is_owner_gated_on_live_domain(
        self, app: FastAPI, test_session: AsyncSession
    ):
        """The flag elevates the role up front, so a member is refused (403)
        before any lookup - it is not an existence oracle."""
        domain = Domain(domain_name="live-history.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()
        member_key = await add_member_with_key(test_session, domain, "live-member", "member")
        await test_session.commit()

        async with user_client(app, member_key) as client:
            without_flag = await client.get(f"/api/v1/domains/{domain.id}/delivery-log")
            with_flag = await client.get(
                f"/api/v1/domains/{domain.id}/delivery-log",
                params={"include_deleted": "true"},
            )
        assert without_flag.status_code == 200
        assert with_flag.status_code == 403


class TestRetryWithTombstones:
    """Retry accepts ``cancelled`` once recipient and domain are live again,
    and refuses (409) while either is tombstoned (spec §4.6, S14).
    """

    @pytest_asyncio.fixture
    async def cancelled_delivery(
        self, test_session: AsyncSession
    ) -> tuple[Domain, Recipient, DeliveryLog]:
        domain = Domain(domain_name="retry-tombstones.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()
        recipient = Recipient(
            domain_id=domain.id,
            local_part="sales",
            webhook_url="https://webhook.example.com",
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.flush()
        log = await make_log(test_session, domain, DeliveryStatus.PENDING, recipient)
        await test_session.commit()
        return domain, recipient, log

    @pytest.mark.asyncio
    async def test_retry_refused_while_domain_tombstoned(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        cancelled_delivery: tuple[Domain, Recipient, DeliveryLog],
    ):
        domain, _, log = cancelled_delivery
        await soft_delete_domain(test_session, domain)
        await test_session.commit()

        response = await auth_client.post(f"/api/v1/delivery-log/{log.id}/retry")
        assert response.status_code == 409
        assert response.json()["detail"] == "Domain is deleted; restore it before retrying"

    @pytest.mark.asyncio
    async def test_retry_refused_while_recipient_tombstoned(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        cancelled_delivery: tuple[Domain, Recipient, DeliveryLog],
    ):
        _, recipient, log = cancelled_delivery
        await soft_delete_recipient(test_session, recipient)
        await test_session.commit()

        response = await auth_client.post(f"/api/v1/delivery-log/{log.id}/retry")
        assert response.status_code == 409
        assert response.json()["detail"] == "Recipient is deleted; restore it before retrying"

    @pytest.mark.asyncio
    async def test_retry_accepts_cancelled_after_domain_restore(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        cancelled_delivery: tuple[Domain, Recipient, DeliveryLog],
    ):
        domain, _, log = cancelled_delivery
        await soft_delete_domain(test_session, domain)
        await test_session.commit()
        await restore_domain(test_session, domain)
        await test_session.commit()
        await test_session.refresh(log)
        assert log.status == DeliveryStatus.CANCELLED  # restore never re-queues

        response = await auth_client.post(f"/api/v1/delivery-log/{log.id}/retry")
        assert response.status_code == 200
        await test_session.refresh(log)
        assert log.status == DeliveryStatus.PENDING

    @pytest.mark.asyncio
    async def test_retry_accepts_cancelled_after_recipient_restore(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        cancelled_delivery: tuple[Domain, Recipient, DeliveryLog],
    ):
        _, recipient, log = cancelled_delivery
        await soft_delete_recipient(test_session, recipient)
        await test_session.commit()
        await restore_recipient(test_session, recipient)
        await test_session.commit()

        response = await auth_client.post(f"/api/v1/delivery-log/{log.id}/retry")
        assert response.status_code == 200
        await test_session.refresh(log)
        assert log.status == DeliveryStatus.PENDING

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", RETRYABLE_STATUSES, ids=lambda s: s.value)
    async def test_retry_accepts_every_retryable_status(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        cancelled_delivery: tuple[Domain, Recipient, DeliveryLog],
        status: DeliveryStatus,
    ):
        """The endpoint's 400 and the queue's UPDATE filter on the same tuple."""
        domain, recipient, _ = cancelled_delivery
        log = await make_log(test_session, domain, status, recipient)
        await test_session.commit()

        response = await auth_client.post(f"/api/v1/delivery-log/{log.id}/retry")
        assert response.status_code == 200
        await test_session.refresh(log)
        assert log.status == DeliveryStatus.PENDING

    @pytest.mark.asyncio
    async def test_wrong_status_is_still_400_under_a_tombstone(
        self,
        auth_client: AsyncClient,
        test_session: AsyncSession,
        cancelled_delivery: tuple[Domain, Recipient, DeliveryLog],
    ):
        """The status check runs before the tombstone checks (spec §4.6)."""
        domain, _, _ = cancelled_delivery
        delivered = await make_log(test_session, domain, DeliveryStatus.DELIVERED)
        await soft_delete_domain(test_session, domain)
        await test_session.commit()

        response = await auth_client.post(f"/api/v1/delivery-log/{delivered.id}/retry")
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_retry_refused_when_the_recipient_is_tombstoned_under_the_request(
        self,
        auth_client: AsyncClient,
        test_engine: AsyncEngine,
        test_session: AsyncSession,
        cancelled_delivery: tuple[Domain, Recipient, DeliveryLog],
        monkeypatch: pytest.MonkeyPatch,
    ):
        """The 409 comes from the guarded UPDATE, not from a check that ran
        earlier in the request: the recipient is live when the endpoint loads
        it and tombstoned by another transaction before the retry statement.
        The wrapper stands in for that other transaction's timing."""
        import fastsmtp.api.operations as operations_api

        domain, recipient, _ = cancelled_delivery
        failed = await make_log(test_session, domain, DeliveryStatus.FAILED, recipient)
        await test_session.commit()
        real_retry = operations_api.retry_delivery

        async def tombstone_then_retry(session: AsyncSession, delivery_id: uuid.UUID):
            other = async_sessionmaker(test_engine, class_=AsyncSession)()
            try:
                await soft_delete_recipient(other, await other.get_one(Recipient, recipient.id))
                await other.commit()
            finally:
                await other.close()
            return await real_retry(session, delivery_id)

        monkeypatch.setattr(operations_api, "retry_delivery", tombstone_then_retry)

        response = await auth_client.post(f"/api/v1/delivery-log/{failed.id}/retry")
        assert response.status_code == 409
        assert response.json()["detail"] == "Recipient is deleted; restore it before retrying"
        await test_session.refresh(failed)
        assert (
            failed.status == DeliveryStatus.CANCELLED
        )  # the delete cancelled it; retry did not re-arm

    @pytest.mark.asyncio
    async def test_retry_on_tombstoned_domain_is_invisible_below_owner(
        self,
        app: FastAPI,
        test_session: AsyncSession,
        cancelled_delivery: tuple[Domain, Recipient, DeliveryLog],
    ):
        domain, _, log = cancelled_delivery
        admin_key = await add_member_with_key(test_session, domain, "retry-admin", "admin")
        await soft_delete_domain(test_session, domain)
        await test_session.commit()

        async with user_client(app, admin_key) as client:
            response = await client.post(f"/api/v1/delivery-log/{log.id}/retry")
        assert response.status_code == 404
