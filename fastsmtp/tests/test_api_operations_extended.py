"""Extended tests for operations API endpoints to improve coverage."""

import hashlib
import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

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
