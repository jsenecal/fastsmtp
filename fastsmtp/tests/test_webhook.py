"""Tests for webhook dispatcher and queue modules."""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from fastsmtp.config import Settings
from fastsmtp.db.models import DeliveryLog, Domain, Recipient
from fastsmtp.webhook.dispatcher import (
    WebhookWorker,
    process_delivery,
    send_webhook,
)
from fastsmtp.webhook.queue import (
    check_queue_backpressure,
    compute_payload_hash,
    enqueue_delivery,
    get_pending_count,
    get_pending_deliveries,
    mark_delivered,
    mark_failed,
    retry_delivery,
)
from sqlalchemy.ext.asyncio import AsyncSession


class TestComputePayloadHash:
    """Tests for payload hashing."""

    def test_deterministic_hash(self):
        """Same payload produces same hash."""
        payload = {"key": "value", "nested": {"a": 1}}
        hash1 = compute_payload_hash(payload)
        hash2 = compute_payload_hash(payload)
        assert hash1 == hash2

    def test_different_payloads_different_hashes(self):
        """Different payloads produce different hashes."""
        hash1 = compute_payload_hash({"key": "value1"})
        hash2 = compute_payload_hash({"key": "value2"})
        assert hash1 != hash2

    def test_order_independent(self):
        """Key order doesn't affect hash (sorted keys)."""
        hash1 = compute_payload_hash({"b": 2, "a": 1})
        hash2 = compute_payload_hash({"a": 1, "b": 2})
        assert hash1 == hash2

    def test_hash_length(self):
        """Hash is SHA256 hex (64 chars)."""
        hash_val = compute_payload_hash({"test": "data"})
        assert len(hash_val) == 64


class TestSendWebhook:
    """Tests for send_webhook function."""

    @pytest.mark.asyncio
    async def test_successful_webhook(self):
        """Test successful webhook delivery."""
        mock_response = AsyncMock()
        mock_response.is_success = True
        mock_response.status_code = 200

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=mock_response)

        success, status_code, error = await send_webhook(
            url="https://example.com/webhook",
            payload={"test": "data"},
            client=mock_client,
        )

        assert success is True
        assert status_code == 200
        assert error is None
        mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_failed_webhook_http_error(self):
        """Test webhook with HTTP error response."""
        mock_response = AsyncMock()
        mock_response.is_success = False
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=mock_response)

        success, status_code, error = await send_webhook(
            url="https://example.com/webhook",
            payload={"test": "data"},
            client=mock_client,
        )

        assert success is False
        assert status_code == 500
        assert "HTTP 500" in error

    @pytest.mark.asyncio
    async def test_webhook_timeout(self):
        """Test webhook timeout handling."""
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        success, status_code, error = await send_webhook(
            url="https://example.com/webhook",
            payload={"test": "data"},
            client=mock_client,
        )

        assert success is False
        assert status_code is None
        assert "timed out" in error

    @pytest.mark.asyncio
    async def test_webhook_connection_error(self):
        """Test webhook connection error handling."""
        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

        success, status_code, error = await send_webhook(
            url="https://example.com/webhook",
            payload={"test": "data"},
            client=mock_client,
        )

        assert success is False
        assert status_code is None
        assert "Connection error" in error

    @pytest.mark.asyncio
    async def test_webhook_with_custom_headers(self):
        """Test webhook with custom headers."""
        mock_response = AsyncMock()
        mock_response.is_success = True
        mock_response.status_code = 200

        mock_client = AsyncMock(spec=httpx.AsyncClient)
        mock_client.post = AsyncMock(return_value=mock_response)

        await send_webhook(
            url="https://example.com/webhook",
            payload={"test": "data"},
            headers={"X-Custom": "value"},
            client=mock_client,
        )

        call_kwargs = mock_client.post.call_args.kwargs
        assert call_kwargs["headers"]["X-Custom"] == "value"
        assert call_kwargs["headers"]["Content-Type"] == "application/json"


class TestWorkerHttpClientLifecycle:
    """Tests for WebhookWorker HTTP client management."""

    @pytest.fixture
    def test_settings(self) -> Settings:
        """Create test settings."""
        return Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            secret_key="test-secret",
            webhook_timeout=5.0,
        )

    @pytest.mark.asyncio
    async def test_worker_creates_client_on_demand(self, test_settings: Settings):
        """Test that worker creates HTTP client when needed."""
        worker = WebhookWorker(settings=test_settings)
        assert worker._http_client is None

        client = await worker._get_http_client()
        assert client is not None
        assert isinstance(client, httpx.AsyncClient)

        # Cleanup
        await worker._close_http_client()

    @pytest.mark.asyncio
    async def test_worker_reuses_client(self, test_settings: Settings):
        """Test that worker reuses the same HTTP client."""
        worker = WebhookWorker(settings=test_settings)

        client1 = await worker._get_http_client()
        client2 = await worker._get_http_client()
        assert client1 is client2

        # Cleanup
        await worker._close_http_client()

    @pytest.mark.asyncio
    async def test_worker_close_client(self, test_settings: Settings):
        """Test that worker closes client properly."""
        worker = WebhookWorker(settings=test_settings)

        client1 = await worker._get_http_client()
        await worker._close_http_client()

        # After close, should get a new client
        client2 = await worker._get_http_client()
        assert client1 is not client2
        assert worker._http_client is client2

        # Cleanup
        await worker._close_http_client()


class TestEnqueueDelivery:
    """Tests for enqueue_delivery function."""

    @pytest_asyncio.fixture
    async def test_domain(self, test_session: AsyncSession) -> Domain:
        """Create a test domain."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="test-webhook.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()
        return domain

    @pytest.mark.asyncio
    async def test_enqueue_creates_delivery(
        self, test_session: AsyncSession, test_domain: Domain, test_settings: Settings
    ):
        """Test that enqueue_delivery creates a delivery log."""
        payload = {"message_id": "<test@example.com>", "subject": "Test"}

        delivery = await enqueue_delivery(
            session=test_session,
            domain_id=test_domain.id,
            recipient_id=None,
            message_id="<test@example.com>",
            webhook_url="https://example.com/webhook",
            payload=payload,
            settings=test_settings,
        )

        assert delivery.id is not None
        assert delivery.domain_id == test_domain.id
        assert delivery.status == "pending"
        assert delivery.attempts == 0
        assert delivery.webhook_url == "https://example.com/webhook"
        assert delivery.payload == payload
        assert delivery.payload_hash == compute_payload_hash(payload)

    @pytest.mark.asyncio
    async def test_enqueue_with_auth_result(
        self, test_session: AsyncSession, test_domain: Domain, test_settings: Settings
    ):
        """Test enqueue with email auth result."""
        from fastsmtp.smtp.validation import EmailAuthResult

        auth_result = EmailAuthResult(
            dkim_result="pass",
            dkim_domain="example.com",
            dkim_selector="default",
            spf_result="pass",
            spf_domain="example.com",
            client_ip="127.0.0.1",
        )

        delivery = await enqueue_delivery(
            session=test_session,
            domain_id=test_domain.id,
            recipient_id=None,
            message_id="<test@example.com>",
            webhook_url="https://example.com/webhook",
            payload={"test": "data"},
            auth_result=auth_result,
            settings=test_settings,
        )

        assert delivery.dkim_result == "pass"
        assert delivery.spf_result == "pass"


class TestGetPendingDeliveries:
    """Tests for get_pending_deliveries function."""

    @pytest_asyncio.fixture
    async def pending_deliveries(self, test_session: AsyncSession) -> list[DeliveryLog]:
        """Create test pending deliveries."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="pending-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        deliveries = []
        for i in range(5):
            delivery = DeliveryLog(
                id=uuid.uuid4(),
                domain_id=domain.id,
                message_id=f"<test{i}@example.com>",
                webhook_url="https://example.com/webhook",
                payload_hash="abc123",
                payload={"index": i},
                status="pending",
                attempts=0,
                next_retry_at=datetime.now(UTC) - timedelta(minutes=1),
                instance_id="test-instance",
            )
            test_session.add(delivery)
            deliveries.append(delivery)

        await test_session.flush()
        return deliveries

    @pytest.mark.asyncio
    async def test_get_pending_returns_due_deliveries(
        self, test_session: AsyncSession, pending_deliveries: list[DeliveryLog]
    ):
        """Test that get_pending_deliveries returns deliveries due for processing."""
        deliveries = await get_pending_deliveries(
            test_session,
            batch_size=10,
            instance_id="worker-1",
        )

        assert len(deliveries) == 5

    @pytest.mark.asyncio
    async def test_get_pending_respects_batch_size(
        self, test_session: AsyncSession, pending_deliveries: list[DeliveryLog]
    ):
        """Test that batch_size limits results."""
        deliveries = await get_pending_deliveries(
            test_session,
            batch_size=2,
            instance_id="worker-1",
        )

        assert len(deliveries) == 2

    @pytest.mark.asyncio
    async def test_get_pending_skips_future_retries(self, test_session: AsyncSession):
        """Test that deliveries scheduled for future are skipped."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="future-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        delivery = DeliveryLog(
            id=uuid.uuid4(),
            domain_id=domain.id,
            message_id="<future@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={},
            status="pending",
            attempts=0,
            next_retry_at=datetime.now(UTC) + timedelta(hours=1),
            instance_id="test-instance",
        )
        test_session.add(delivery)
        await test_session.flush()

        deliveries = await get_pending_deliveries(test_session, batch_size=10)
        assert len(deliveries) == 0


class TestMarkDelivered:
    """Tests for mark_delivered function."""

    @pytest_asyncio.fixture
    async def test_delivery(self, test_session: AsyncSession) -> DeliveryLog:
        """Create a test delivery."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="mark-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        delivery = DeliveryLog(
            id=uuid.uuid4(),
            domain_id=domain.id,
            message_id="<mark@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={},
            status="pending",
            attempts=1,
            next_retry_at=datetime.now(UTC),
            instance_id="test-instance",
        )
        test_session.add(delivery)
        await test_session.flush()
        return delivery

    @pytest.mark.asyncio
    async def test_mark_delivered_updates_status(
        self, test_session: AsyncSession, test_delivery: DeliveryLog
    ):
        """Test that mark_delivered updates delivery status."""
        await mark_delivered(test_session, test_delivery.id)
        await test_session.flush()

        # Refresh to get updated values
        await test_session.refresh(test_delivery)

        assert test_delivery.status == "delivered"
        assert test_delivery.delivered_at is not None
        assert test_delivery.next_retry_at is None
        assert test_delivery.last_error is None


class TestMarkFailed:
    """Tests for mark_failed function."""

    @pytest_asyncio.fixture
    async def test_delivery(self, test_session: AsyncSession) -> DeliveryLog:
        """Create a test delivery."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="fail-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        delivery = DeliveryLog(
            id=uuid.uuid4(),
            domain_id=domain.id,
            message_id="<fail@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={},
            status="pending",
            attempts=0,
            next_retry_at=datetime.now(UTC),
            instance_id="test-instance",
        )
        test_session.add(delivery)
        await test_session.flush()
        return delivery

    @pytest.mark.asyncio
    async def test_mark_failed_schedules_retry(
        self, test_session: AsyncSession, test_delivery: DeliveryLog, test_settings: Settings
    ):
        """Test that mark_failed schedules a retry."""
        await mark_failed(
            test_session,
            test_delivery.id,
            "Connection refused",
            status_code=None,
            settings=test_settings,
        )
        await test_session.flush()
        await test_session.refresh(test_delivery)

        assert test_delivery.status == "failed"
        assert test_delivery.attempts == 1
        assert test_delivery.last_error == "Connection refused"
        assert test_delivery.next_retry_at is not None
        # Verify retry is scheduled in the future (comparing timestamps)
        now = datetime.now(UTC)
        next_retry = test_delivery.next_retry_at
        if next_retry.tzinfo:
            retry_ts = next_retry.timestamp()
        else:
            retry_ts = next_retry.replace(tzinfo=UTC).timestamp()
        assert retry_ts > now.timestamp() - 1  # Allow 1 second tolerance

    @pytest.mark.asyncio
    async def test_mark_failed_exhausts_after_max_retries(
        self, test_session: AsyncSession, test_settings: Settings
    ):
        """Test that delivery is exhausted after max retries."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="exhaust-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        # Create delivery at max retries - 1
        delivery = DeliveryLog(
            id=uuid.uuid4(),
            domain_id=domain.id,
            message_id="<exhaust@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={},
            status="failed",
            attempts=test_settings.webhook_max_retries - 1,
            next_retry_at=datetime.now(UTC),
            instance_id="test-instance",
        )
        test_session.add(delivery)
        await test_session.flush()

        await mark_failed(
            test_session,
            delivery.id,
            "Final failure",
            status_code=500,
            settings=test_settings,
        )
        await test_session.flush()
        await test_session.refresh(delivery)

        assert delivery.status == "exhausted"
        assert delivery.attempts == test_settings.webhook_max_retries
        assert delivery.next_retry_at is None


class TestRetryDelivery:
    """Tests for retry_delivery function."""

    @pytest.mark.asyncio
    async def test_retry_resets_failed_delivery(self, test_session: AsyncSession):
        """Test that retry_delivery resets a failed delivery."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="retry-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        delivery = DeliveryLog(
            id=uuid.uuid4(),
            domain_id=domain.id,
            message_id="<retry@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={},
            status="exhausted",
            attempts=5,
            next_retry_at=None,
            instance_id="test-instance",
        )
        test_session.add(delivery)
        await test_session.flush()

        result = await retry_delivery(test_session, delivery.id)
        await test_session.flush()
        await test_session.refresh(delivery)

        assert result is not None
        assert delivery.status == "pending"
        assert delivery.next_retry_at is not None

    @pytest.mark.asyncio
    async def test_retry_returns_none_for_nonexistent(self, test_session: AsyncSession):
        """Test that retry_delivery returns None for nonexistent delivery."""
        result = await retry_delivery(test_session, uuid.uuid4())
        assert result is None

    @pytest.mark.asyncio
    async def test_retry_skips_delivered(self, test_session: AsyncSession):
        """Test that retry_delivery doesn't reset delivered deliveries."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="skip-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        delivery = DeliveryLog(
            id=uuid.uuid4(),
            domain_id=domain.id,
            message_id="<skip@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={},
            status="delivered",
            attempts=1,
            next_retry_at=None,
            delivered_at=datetime.now(UTC),
            instance_id="test-instance",
        )
        test_session.add(delivery)
        await test_session.flush()

        result = await retry_delivery(test_session, delivery.id)
        await test_session.refresh(delivery)

        # Should return the delivery but not change status
        assert result is not None
        assert delivery.status == "delivered"


class TestProcessDelivery:
    """Tests for process_delivery function."""

    @pytest.mark.asyncio
    async def test_process_delivery_success(
        self, test_session: AsyncSession, test_settings: Settings
    ):
        """Test successful delivery processing."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="process-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        delivery = DeliveryLog(
            id=uuid.uuid4(),
            domain_id=domain.id,
            message_id="<process@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={"test": "data"},
            status="pending",
            attempts=0,
            next_retry_at=datetime.now(UTC),
            instance_id="test-instance",
        )
        test_session.add(delivery)
        await test_session.flush()

        # Mock successful webhook
        with patch("fastsmtp.webhook.dispatcher.send_webhook") as mock_send:
            mock_send.return_value = (True, 200, None)

            await process_delivery(delivery, test_settings, test_session)
            await test_session.flush()
            await test_session.refresh(delivery)

        assert delivery.status == "delivered"

    @pytest.mark.asyncio
    async def test_process_delivery_failure(
        self, test_session: AsyncSession, test_settings: Settings
    ):
        """Test failed delivery processing."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="fail-process-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        delivery = DeliveryLog(
            id=uuid.uuid4(),
            domain_id=domain.id,
            message_id="<fail-process@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={"test": "data"},
            status="pending",
            attempts=0,
            next_retry_at=datetime.now(UTC),
            instance_id="test-instance",
        )
        test_session.add(delivery)
        await test_session.flush()

        # Mock failed webhook
        with patch("fastsmtp.webhook.dispatcher.send_webhook") as mock_send:
            mock_send.return_value = (False, 500, "Server Error")

            await process_delivery(delivery, test_settings, test_session)
            await test_session.flush()
            await test_session.refresh(delivery)

        assert delivery.status == "failed"
        assert delivery.last_error == "Server Error"

    @pytest.mark.asyncio
    async def test_process_delivery_with_recipient_headers(
        self, test_session: AsyncSession, test_settings: Settings
    ):
        """Test delivery processing fetches recipient headers."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="headers-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        recipient = Recipient(
            id=uuid.uuid4(),
            domain_id=domain.id,
            local_part="test",
            webhook_url="https://example.com/webhook",
            webhook_headers={"X-Auth": "secret123"},
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.flush()

        delivery = DeliveryLog(
            id=uuid.uuid4(),
            domain_id=domain.id,
            recipient_id=recipient.id,
            message_id="<headers@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={"test": "data"},
            status="pending",
            attempts=0,
            next_retry_at=datetime.now(UTC),
            instance_id="test-instance",
        )
        test_session.add(delivery)
        await test_session.flush()

        # Re-fetch delivery with recipient relationship eagerly loaded
        # (simulates how get_pending_deliveries loads deliveries in production)
        stmt = (
            select(DeliveryLog)
            .options(selectinload(DeliveryLog.recipient))
            .where(DeliveryLog.id == delivery.id)
        )
        result = await test_session.execute(stmt)
        loaded_delivery = result.scalar_one()

        with patch("fastsmtp.webhook.dispatcher.send_webhook") as mock_send:
            mock_send.return_value = (True, 200, None)

            await process_delivery(loaded_delivery, test_settings, test_session)

            # Verify headers were passed
            call_kwargs = mock_send.call_args.kwargs
            assert call_kwargs["headers"]["X-Auth"] == "secret123"

    @pytest.mark.asyncio
    async def test_process_delivery_adds_idempotency_key(
        self, test_session: AsyncSession, test_settings: Settings
    ):
        """Test that process_delivery adds X-Idempotency-Key header."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="idempotency-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        delivery_id = uuid.uuid4()
        delivery = DeliveryLog(
            id=delivery_id,
            domain_id=domain.id,
            message_id="<idempotency@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={"test": "data"},
            status="pending",
            attempts=0,
            next_retry_at=datetime.now(UTC),
            instance_id="test-instance",
        )
        test_session.add(delivery)
        await test_session.flush()

        with patch("fastsmtp.webhook.dispatcher.send_webhook") as mock_send:
            mock_send.return_value = (True, 200, None)

            await process_delivery(delivery, test_settings, test_session)

            # Verify idempotency key header is set to delivery ID
            call_kwargs = mock_send.call_args.kwargs
            assert "X-Idempotency-Key" in call_kwargs["headers"]
            assert call_kwargs["headers"]["X-Idempotency-Key"] == str(delivery_id)

    @pytest.mark.asyncio
    async def test_process_delivery_idempotency_key_with_recipient_headers(
        self, test_session: AsyncSession, test_settings: Settings
    ):
        """Test that idempotency key is added alongside recipient headers."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="idempotency-headers-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        recipient = Recipient(
            id=uuid.uuid4(),
            domain_id=domain.id,
            local_part="test",
            webhook_url="https://example.com/webhook",
            webhook_headers={"X-Custom-Auth": "token123"},
            is_enabled=True,
        )
        test_session.add(recipient)
        await test_session.flush()

        delivery_id = uuid.uuid4()
        delivery = DeliveryLog(
            id=delivery_id,
            domain_id=domain.id,
            recipient_id=recipient.id,
            message_id="<idempotency-headers@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={"test": "data"},
            status="pending",
            attempts=0,
            next_retry_at=datetime.now(UTC),
            instance_id="test-instance",
        )
        test_session.add(delivery)
        await test_session.flush()

        # Re-fetch delivery with recipient relationship eagerly loaded
        stmt = (
            select(DeliveryLog)
            .options(selectinload(DeliveryLog.recipient))
            .where(DeliveryLog.id == delivery.id)
        )
        result = await test_session.execute(stmt)
        loaded_delivery = result.scalar_one()

        with patch("fastsmtp.webhook.dispatcher.send_webhook") as mock_send:
            mock_send.return_value = (True, 200, None)

            await process_delivery(loaded_delivery, test_settings, test_session)

            # Verify both custom headers and idempotency key are present
            call_kwargs = mock_send.call_args.kwargs
            headers = call_kwargs["headers"]
            assert headers["X-Custom-Auth"] == "token123"
            assert headers["X-Idempotency-Key"] == str(delivery_id)

    @pytest.mark.asyncio
    async def test_process_delivery_idempotency_key_consistent_on_retry(
        self, test_session: AsyncSession, test_settings: Settings
    ):
        """Test that idempotency key remains consistent across retries."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="idempotency-retry-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        delivery_id = uuid.uuid4()
        delivery = DeliveryLog(
            id=delivery_id,
            domain_id=domain.id,
            message_id="<idempotency-retry@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={"test": "data"},
            status="failed",
            attempts=2,  # Already retried twice
            next_retry_at=datetime.now(UTC),
            instance_id="test-instance",
        )
        test_session.add(delivery)
        await test_session.flush()

        with patch("fastsmtp.webhook.dispatcher.send_webhook") as mock_send:
            mock_send.return_value = (True, 200, None)

            await process_delivery(delivery, test_settings, test_session)

            # Idempotency key should still be the same delivery ID
            call_kwargs = mock_send.call_args.kwargs
            assert call_kwargs["headers"]["X-Idempotency-Key"] == str(delivery_id)


class TestWebhookWorker:
    """Tests for WebhookWorker class."""

    @pytest.mark.asyncio
    async def test_worker_process_batch_empty(self, test_settings: Settings):
        """Test worker handles empty batch."""
        worker = WebhookWorker(settings=test_settings)

        with patch("fastsmtp.webhook.dispatcher.get_pending_deliveries") as mock_get:
            mock_get.return_value = []

            with patch("fastsmtp.webhook.dispatcher.async_session") as mock_session_ctx:
                mock_session = AsyncMock()
                mock_session_ctx.return_value.__aenter__.return_value = mock_session
                mock_get.return_value = []

                count = await worker.process_batch()

        assert count == 0

    @pytest.mark.asyncio
    async def test_worker_start_stop(self, test_settings: Settings):
        """Test worker start and stop."""
        worker = WebhookWorker(settings=test_settings)

        # Mock to prevent actual processing
        with patch.object(worker, "process_batch", new_callable=AsyncMock) as mock_process:
            mock_process.return_value = 0

            worker.start()
            assert worker._task is not None

            # Give the task time to start running
            await asyncio.sleep(0.05)
            assert worker._running is True

            await worker.stop()
            await worker.wait()
            assert worker._running is False


class TestDeadLetterQueue:
    """Tests for Dead Letter Queue (DLQ) notification feature."""

    @pytest_asyncio.fixture
    async def exhausted_delivery(self, test_session: AsyncSession) -> DeliveryLog:
        """Create a delivery that's about to be exhausted."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="dlq-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        delivery = DeliveryLog(
            id=uuid.uuid4(),
            domain_id=domain.id,
            message_id="<dlq@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={"test": "data"},
            status="failed",
            attempts=4,  # One more failure will exhaust (default max is 5)
            next_retry_at=datetime.now(UTC),
            instance_id="test-instance",
        )
        test_session.add(delivery)
        await test_session.flush()
        return delivery

    @pytest.mark.asyncio
    async def test_no_dlq_notification_when_url_not_configured(
        self, test_session: AsyncSession, exhausted_delivery: DeliveryLog, test_settings: Settings
    ):
        """Test that no DLQ notification is sent when dlq_webhook_url is not configured."""
        # Ensure DLQ URL is not set
        assert test_settings.dlq_webhook_url is None

        with patch("fastsmtp.webhook.queue._send_dlq_notification") as mock_dlq:
            await mark_failed(
                test_session,
                exhausted_delivery.id,
                "Final failure",
                status_code=500,
                settings=test_settings,
            )
            await test_session.flush()

            # DLQ notification should not be called when URL is not configured
            mock_dlq.assert_not_called()

    @pytest.mark.asyncio
    async def test_dlq_notification_sent_when_exhausted(
        self, test_session: AsyncSession, exhausted_delivery: DeliveryLog
    ):
        """Test that DLQ notification is sent when delivery is exhausted."""
        # Create settings with DLQ URL configured
        settings_with_dlq = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            dlq_webhook_url="https://alerts.example.com/dlq",
            webhook_max_retries=5,
        )

        with patch("fastsmtp.webhook.queue._send_dlq_notification") as mock_dlq:
            await mark_failed(
                test_session,
                exhausted_delivery.id,
                "Final failure",
                status_code=500,
                settings=settings_with_dlq,
            )
            await test_session.flush()

            # DLQ notification should be called via asyncio.create_task
            # We're patching the function, so create_task will call the mock
            mock_dlq.assert_called_once()

    @pytest.mark.asyncio
    async def test_dlq_notification_not_sent_for_non_exhausted(
        self, test_session: AsyncSession
    ):
        """Test that DLQ notification is NOT sent when delivery still has retries."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="dlq-retry-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()

        # Create delivery with only 1 attempt - still has retries left
        delivery = DeliveryLog(
            id=uuid.uuid4(),
            domain_id=domain.id,
            message_id="<retry@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={"test": "data"},
            status="pending",
            attempts=1,
            next_retry_at=datetime.now(UTC),
            instance_id="test-instance",
        )
        test_session.add(delivery)
        await test_session.flush()

        settings_with_dlq = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            dlq_webhook_url="https://alerts.example.com/dlq",
            webhook_max_retries=5,
        )

        with patch("fastsmtp.webhook.queue._send_dlq_notification") as mock_dlq:
            await mark_failed(
                test_session,
                delivery.id,
                "Temporary failure",
                status_code=503,
                settings=settings_with_dlq,
            )
            await test_session.flush()
            await test_session.refresh(delivery)

            # Should NOT call DLQ because delivery still has retries
            mock_dlq.assert_not_called()
            assert delivery.status == "failed"  # Not exhausted

    @pytest.mark.asyncio
    async def test_dlq_payload_structure(
        self, test_session: AsyncSession, exhausted_delivery: DeliveryLog
    ):
        """Test that DLQ notification payload has correct structure."""
        from fastsmtp.webhook.queue import _send_dlq_notification

        settings_with_dlq = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            dlq_webhook_url="https://alerts.example.com/dlq",
        )

        # Update the delivery to simulate exhaustion
        exhausted_delivery.attempts = 5
        exhausted_delivery.last_error = "Connection refused"
        exhausted_delivery.last_status_code = None

        # Patch at source location since _send_dlq_notification imports locally
        with patch("fastsmtp.webhook.dispatcher.send_webhook") as mock_send:
            mock_send.return_value = (True, 200, None)

            with patch("fastsmtp.webhook.url_validator.create_ssrf_safe_client") as mock_client:
                mock_client.return_value.__aenter__ = AsyncMock()
                mock_client.return_value.__aexit__ = AsyncMock()

                await _send_dlq_notification(exhausted_delivery, settings_with_dlq)

                # Verify send_webhook was called
                mock_send.assert_called_once()
                call_kwargs = mock_send.call_args.kwargs

                # Check URL
                assert call_kwargs["url"] == "https://alerts.example.com/dlq"

                # Check payload structure
                payload = call_kwargs["payload"]
                assert payload["event"] == "delivery.exhausted"
                assert payload["delivery_id"] == str(exhausted_delivery.id)
                assert payload["message_id"] == exhausted_delivery.message_id
                assert payload["webhook_url"] == exhausted_delivery.webhook_url
                assert payload["attempts"] == 5
                assert payload["last_error"] == "Connection refused"
                assert payload["last_status_code"] is None
                assert "exhausted_at" in payload

                # Check headers
                assert call_kwargs["headers"]["X-FastSMTP-Event"] == "dlq"

    @pytest.mark.asyncio
    async def test_dlq_notification_failure_is_logged_not_raised(
        self, test_session: AsyncSession, exhausted_delivery: DeliveryLog
    ):
        """Test that DLQ notification failures don't propagate (fire-and-forget)."""
        from fastsmtp.webhook.queue import _send_dlq_notification

        settings_with_dlq = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            dlq_webhook_url="https://alerts.example.com/dlq",
        )

        exhausted_delivery.attempts = 5
        exhausted_delivery.last_error = "Test error"

        with patch("fastsmtp.webhook.dispatcher.send_webhook") as mock_send:
            # Simulate webhook failure
            mock_send.return_value = (False, 500, "Server error")

            with patch("fastsmtp.webhook.url_validator.create_ssrf_safe_client") as mock_client:
                mock_client.return_value.__aenter__ = AsyncMock()
                mock_client.return_value.__aexit__ = AsyncMock()

                # Should not raise exception even though webhook failed
                await _send_dlq_notification(exhausted_delivery, settings_with_dlq)

    @pytest.mark.asyncio
    async def test_dlq_notification_exception_is_caught(
        self, test_session: AsyncSession, exhausted_delivery: DeliveryLog
    ):
        """Test that exceptions in DLQ notification are caught and logged."""
        from fastsmtp.webhook.queue import _send_dlq_notification

        settings_with_dlq = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            dlq_webhook_url="https://alerts.example.com/dlq",
        )

        exhausted_delivery.attempts = 5
        exhausted_delivery.last_error = "Test error"

        with patch("fastsmtp.webhook.url_validator.create_ssrf_safe_client") as mock_client:
            # Simulate exception during client creation
            mock_client.side_effect = Exception("Network error")

            # Should not raise exception
            await _send_dlq_notification(exhausted_delivery, settings_with_dlq)

    @pytest.mark.asyncio
    async def test_dlq_notification_skipped_when_no_url(
        self, test_session: AsyncSession, exhausted_delivery: DeliveryLog
    ):
        """Test that DLQ notification is skipped when no URL is configured."""
        from fastsmtp.webhook.queue import _send_dlq_notification

        settings_no_dlq = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            dlq_webhook_url=None,
        )

        with patch("fastsmtp.webhook.dispatcher.send_webhook") as mock_send:
            await _send_dlq_notification(exhausted_delivery, settings_no_dlq)

            # Should not call send_webhook when no URL configured
            mock_send.assert_not_called()


class TestQueueBackpressure:
    """Tests for queue backpressure feature."""

    @pytest_asyncio.fixture
    async def test_domain(self, test_session: AsyncSession) -> Domain:
        """Create a test domain for deliveries."""
        domain = Domain(
            id=uuid.uuid4(),
            domain_name="backpressure-test.com",
            is_enabled=True,
        )
        test_session.add(domain)
        await test_session.flush()
        return domain

    @pytest.mark.asyncio
    async def test_get_pending_count_empty(self, test_session: AsyncSession):
        """Test get_pending_count returns 0 when no deliveries exist."""
        count = await get_pending_count(test_session)
        assert count == 0

    @pytest.mark.asyncio
    async def test_get_pending_count_counts_pending(
        self, test_session: AsyncSession, test_domain: Domain
    ):
        """Test get_pending_count counts pending deliveries."""
        # Create 3 pending deliveries
        for i in range(3):
            delivery = DeliveryLog(
                id=uuid.uuid4(),
                domain_id=test_domain.id,
                message_id=f"<pending{i}@example.com>",
                webhook_url="https://example.com/webhook",
                payload_hash="abc123",
                payload={"index": i},
                status="pending",
                attempts=0,
                next_retry_at=datetime.now(UTC),
                instance_id="test-instance",
            )
            test_session.add(delivery)
        await test_session.flush()

        count = await get_pending_count(test_session)
        assert count == 3

    @pytest.mark.asyncio
    async def test_get_pending_count_counts_failed(
        self, test_session: AsyncSession, test_domain: Domain
    ):
        """Test get_pending_count counts failed deliveries (for retry)."""
        # Create 2 failed deliveries (will be retried)
        for i in range(2):
            delivery = DeliveryLog(
                id=uuid.uuid4(),
                domain_id=test_domain.id,
                message_id=f"<failed{i}@example.com>",
                webhook_url="https://example.com/webhook",
                payload_hash="abc123",
                payload={"index": i},
                status="failed",
                attempts=2,
                next_retry_at=datetime.now(UTC) + timedelta(minutes=5),
                instance_id="test-instance",
            )
            test_session.add(delivery)
        await test_session.flush()

        count = await get_pending_count(test_session)
        assert count == 2

    @pytest.mark.asyncio
    async def test_get_pending_count_excludes_delivered(
        self, test_session: AsyncSession, test_domain: Domain
    ):
        """Test get_pending_count excludes delivered messages."""
        # Create 1 pending and 1 delivered
        pending = DeliveryLog(
            id=uuid.uuid4(),
            domain_id=test_domain.id,
            message_id="<pending@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={},
            status="pending",
            attempts=0,
            next_retry_at=datetime.now(UTC),
            instance_id="test-instance",
        )
        delivered = DeliveryLog(
            id=uuid.uuid4(),
            domain_id=test_domain.id,
            message_id="<delivered@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="def456",
            payload={},
            status="delivered",
            attempts=1,
            delivered_at=datetime.now(UTC),
            instance_id="test-instance",
        )
        test_session.add(pending)
        test_session.add(delivered)
        await test_session.flush()

        count = await get_pending_count(test_session)
        assert count == 1  # Only pending, not delivered

    @pytest.mark.asyncio
    async def test_get_pending_count_excludes_exhausted(
        self, test_session: AsyncSession, test_domain: Domain
    ):
        """Test get_pending_count excludes exhausted deliveries."""
        # Create 1 pending and 1 exhausted
        pending = DeliveryLog(
            id=uuid.uuid4(),
            domain_id=test_domain.id,
            message_id="<pending@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="abc123",
            payload={},
            status="pending",
            attempts=0,
            next_retry_at=datetime.now(UTC),
            instance_id="test-instance",
        )
        exhausted = DeliveryLog(
            id=uuid.uuid4(),
            domain_id=test_domain.id,
            message_id="<exhausted@example.com>",
            webhook_url="https://example.com/webhook",
            payload_hash="def456",
            payload={},
            status="exhausted",
            attempts=5,
            last_error="Max retries exceeded",
            instance_id="test-instance",
        )
        test_session.add(pending)
        test_session.add(exhausted)
        await test_session.flush()

        count = await get_pending_count(test_session)
        assert count == 1  # Only pending, not exhausted

    @pytest.mark.asyncio
    async def test_get_pending_count_mixed_statuses(
        self, test_session: AsyncSession, test_domain: Domain
    ):
        """Test get_pending_count with mixed delivery statuses."""
        # Create deliveries with various statuses
        statuses = [
            ("pending", 0, None),
            ("pending", 0, None),
            ("failed", 2, datetime.now(UTC) + timedelta(minutes=5)),
            ("delivered", 1, None),
            ("exhausted", 5, None),
        ]
        for i, (status, attempts, next_retry) in enumerate(statuses):
            delivery = DeliveryLog(
                id=uuid.uuid4(),
                domain_id=test_domain.id,
                message_id=f"<msg{i}@example.com>",
                webhook_url="https://example.com/webhook",
                payload_hash=f"hash{i}",
                payload={},
                status=status,
                attempts=attempts,
                next_retry_at=next_retry,
                instance_id="test-instance",
            )
            if status == "delivered":
                delivery.delivered_at = datetime.now(UTC)
            test_session.add(delivery)
        await test_session.flush()

        count = await get_pending_count(test_session)
        assert count == 3  # 2 pending + 1 failed

    @pytest.mark.asyncio
    async def test_check_backpressure_no_limit_configured(
        self, test_session: AsyncSession, test_domain: Domain
    ):
        """Test check_queue_backpressure returns False when no limit is configured."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            queue_max_pending=None,  # No limit
        )

        # Create some pending deliveries
        for i in range(10):
            delivery = DeliveryLog(
                id=uuid.uuid4(),
                domain_id=test_domain.id,
                message_id=f"<nolimit{i}@example.com>",
                webhook_url="https://example.com/webhook",
                payload_hash=f"hash{i}",
                payload={},
                status="pending",
                attempts=0,
                next_retry_at=datetime.now(UTC),
                instance_id="test-instance",
            )
            test_session.add(delivery)
        await test_session.flush()

        is_backpressured, count = await check_queue_backpressure(test_session, settings)
        assert is_backpressured is False
        assert count == 0  # Returns 0 when no limit configured

    @pytest.mark.asyncio
    async def test_check_backpressure_under_limit(
        self, test_session: AsyncSession, test_domain: Domain
    ):
        """Test check_queue_backpressure returns False when under limit."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            queue_max_pending=10,
        )

        # Create 5 pending deliveries (under limit of 10)
        for i in range(5):
            delivery = DeliveryLog(
                id=uuid.uuid4(),
                domain_id=test_domain.id,
                message_id=f"<under{i}@example.com>",
                webhook_url="https://example.com/webhook",
                payload_hash=f"hash{i}",
                payload={},
                status="pending",
                attempts=0,
                next_retry_at=datetime.now(UTC),
                instance_id="test-instance",
            )
            test_session.add(delivery)
        await test_session.flush()

        is_backpressured, count = await check_queue_backpressure(test_session, settings)
        assert is_backpressured is False
        assert count == 5

    @pytest.mark.asyncio
    async def test_check_backpressure_at_limit(
        self, test_session: AsyncSession, test_domain: Domain
    ):
        """Test check_queue_backpressure returns True when at limit."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            queue_max_pending=5,
        )

        # Create exactly 5 pending deliveries (at limit)
        for i in range(5):
            delivery = DeliveryLog(
                id=uuid.uuid4(),
                domain_id=test_domain.id,
                message_id=f"<atlimit{i}@example.com>",
                webhook_url="https://example.com/webhook",
                payload_hash=f"hash{i}",
                payload={},
                status="pending",
                attempts=0,
                next_retry_at=datetime.now(UTC),
                instance_id="test-instance",
            )
            test_session.add(delivery)
        await test_session.flush()

        is_backpressured, count = await check_queue_backpressure(test_session, settings)
        assert is_backpressured is True
        assert count == 5

    @pytest.mark.asyncio
    async def test_check_backpressure_over_limit(
        self, test_session: AsyncSession, test_domain: Domain
    ):
        """Test check_queue_backpressure returns True when over limit."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            queue_max_pending=5,
        )

        # Create 8 pending deliveries (over limit of 5)
        for i in range(8):
            delivery = DeliveryLog(
                id=uuid.uuid4(),
                domain_id=test_domain.id,
                message_id=f"<over{i}@example.com>",
                webhook_url="https://example.com/webhook",
                payload_hash=f"hash{i}",
                payload={},
                status="pending",
                attempts=0,
                next_retry_at=datetime.now(UTC),
                instance_id="test-instance",
            )
            test_session.add(delivery)
        await test_session.flush()

        is_backpressured, count = await check_queue_backpressure(test_session, settings)
        assert is_backpressured is True
        assert count == 8

    @pytest.mark.asyncio
    async def test_check_backpressure_counts_failed_towards_limit(
        self, test_session: AsyncSession, test_domain: Domain
    ):
        """Test check_queue_backpressure includes failed deliveries in count."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            queue_max_pending=5,
        )

        # Create 3 pending + 3 failed = 6 total (over limit of 5)
        for i in range(3):
            pending = DeliveryLog(
                id=uuid.uuid4(),
                domain_id=test_domain.id,
                message_id=f"<pending{i}@example.com>",
                webhook_url="https://example.com/webhook",
                payload_hash=f"pending{i}",
                payload={},
                status="pending",
                attempts=0,
                next_retry_at=datetime.now(UTC),
                instance_id="test-instance",
            )
            failed = DeliveryLog(
                id=uuid.uuid4(),
                domain_id=test_domain.id,
                message_id=f"<failed{i}@example.com>",
                webhook_url="https://example.com/webhook",
                payload_hash=f"failed{i}",
                payload={},
                status="failed",
                attempts=2,
                next_retry_at=datetime.now(UTC) + timedelta(minutes=5),
                instance_id="test-instance",
            )
            test_session.add(pending)
            test_session.add(failed)
        await test_session.flush()

        is_backpressured, count = await check_queue_backpressure(test_session, settings)
        assert is_backpressured is True
        assert count == 6  # 3 pending + 3 failed

    @pytest.mark.asyncio
    async def test_backpressure_action_reject_is_default(self):
        """Test that default backpressure action is 'reject'."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
        )
        assert settings.queue_backpressure_action == "reject"

    @pytest.mark.asyncio
    async def test_backpressure_action_drop_configurable(self):
        """Test that backpressure action can be set to 'drop'."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            queue_backpressure_action="drop",
        )
        assert settings.queue_backpressure_action == "drop"

    @pytest.mark.asyncio
    async def test_queue_max_pending_default_is_none(self):
        """Test that default queue_max_pending is None (unlimited)."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
        )
        assert settings.queue_max_pending is None
