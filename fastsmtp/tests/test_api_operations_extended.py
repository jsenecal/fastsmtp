"""Extended tests for operations API endpoints to improve coverage."""

import hashlib
import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.db.enums import DeliveryStatus
from fastsmtp.db.models import DeliveryLog, Domain


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

        # Use a port that's almost certainly not listening
        result = await _check_smtp_port("127.0.0.1", 59999, connect_timeout=1.0)
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
