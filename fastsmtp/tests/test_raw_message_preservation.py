"""Tests for raw MIME message preservation."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from aiosmtpd.smtp import Envelope
from fastsmtp.config import Settings
from fastsmtp.db.models import Domain, Recipient, Rule, RuleSet
from fastsmtp.smtp.server import FastSMTPHandler
from fastsmtp.storage.raw_message import RawMessagePreserver, should_preserve_raw
from fastsmtp.storage.s3 import S3RawMessageInfo, S3Storage, S3UploadError


def _handler(settings: Settings, s3: S3Storage | None) -> FastSMTPHandler:
    """Build a handler whose S3 client is the given (mock) storage."""
    handler = FastSMTPHandler(settings)
    handler._s3_storage = s3
    return handler


def _envelope(*rcpt_tos: str) -> Envelope:
    """An envelope as it stands after MAIL FROM and the given RCPT TOs."""
    envelope = Envelope()
    envelope.mail_from = "sender@external.com"
    envelope.rcpt_tos = list(rcpt_tos)
    return envelope


def make_settings(**overrides) -> Settings:
    """Build settings with S3 credentials present."""
    base = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "root_api_key": "test_key_12345",
        "s3_bucket": "test-bucket",
        "s3_access_key": "key",
        "s3_secret_key": "secret",
    }
    base.update(overrides)
    return Settings(**base)


class TestShouldPreserveRaw:
    """Tests for the per-recipient preservation decision."""

    def test_rule_match_forces_preservation(self):
        """Test a matching rule enables preservation even when the domain is off."""
        domain = Domain(domain_name="example.com", preserve_raw_message=False)
        settings = make_settings(preserve_raw_message=False)

        assert should_preserve_raw(domain, rule_preserve_raw=True, settings=settings) is True

    def test_domain_override_enables_preservation(self):
        """Test a domain opt-in enables preservation when the global default is off."""
        domain = Domain(domain_name="example.com", preserve_raw_message=True)
        settings = make_settings(preserve_raw_message=False)

        assert should_preserve_raw(domain, rule_preserve_raw=False, settings=settings) is True

    def test_domain_override_disables_preservation(self):
        """Test a domain opt-out wins over the global default."""
        domain = Domain(domain_name="example.com", preserve_raw_message=False)
        settings = make_settings(preserve_raw_message=True)

        assert should_preserve_raw(domain, rule_preserve_raw=False, settings=settings) is False

    def test_unset_domain_inherits_global_default(self):
        """Test a domain with no override inherits the global setting."""
        domain = Domain(domain_name="example.com", preserve_raw_message=None)

        assert (
            should_preserve_raw(
                domain, rule_preserve_raw=False, settings=make_settings(preserve_raw_message=True)
            )
            is True
        )
        assert (
            should_preserve_raw(
                domain, rule_preserve_raw=False, settings=make_settings(preserve_raw_message=False)
            )
            is False
        )


class TestRawMessagePreserver:
    """Tests for the once-per-message lazy uploader."""

    @pytest.fixture
    def raw_info(self) -> S3RawMessageInfo:
        """Build a successful upload result."""
        return S3RawMessageInfo(
            bucket="test-bucket",
            key="raw/example.com/2026/03/07/abc.eml",
            url="https://s3.amazonaws.com/test-bucket/raw/example.com/2026/03/07/abc.eml",
            size=42,
        )

    @pytest.mark.asyncio
    async def test_uploads_once_and_caches_result(self, raw_info):
        """Test repeated preserve calls upload the message only once."""
        storage = AsyncMock(spec=S3Storage)
        storage.upload_raw_message.return_value = raw_info
        preserver = RawMessagePreserver(
            content=b"raw bytes",
            message_id="<abc@example.com>",
            s3_storage=storage,
            settings=make_settings(),
            received_at=datetime(2026, 3, 7, tzinfo=UTC),
        )

        first = await preserver.preserve("example.com")
        second = await preserver.preserve("other.example")

        assert first is raw_info
        assert second is raw_info
        storage.upload_raw_message.assert_awaited_once()
        assert storage.upload_raw_message.await_args.kwargs["domain"] == "example.com"

    @pytest.mark.asyncio
    async def test_passes_content_and_received_at_to_storage(self, raw_info):
        """Test the raw bytes and receive time reach the storage layer unchanged."""
        storage = AsyncMock(spec=S3Storage)
        storage.upload_raw_message.return_value = raw_info
        received_at = datetime(2026, 3, 7, 9, 15, tzinfo=UTC)
        preserver = RawMessagePreserver(
            content=b"From: a@example.com\r\n\r\nbody",
            message_id="<abc@example.com>",
            s3_storage=storage,
            settings=make_settings(),
            received_at=received_at,
        )

        await preserver.preserve("example.com")

        kwargs = storage.upload_raw_message.await_args.kwargs
        assert kwargs["content"] == b"From: a@example.com\r\n\r\nbody"
        assert kwargs["message_id"] == "<abc@example.com>"
        assert kwargs["received_at"] == received_at

    @pytest.mark.asyncio
    async def test_returns_none_without_storage(self):
        """Test preservation is skipped when no S3 storage is available."""
        preserver = RawMessagePreserver(
            content=b"raw",
            message_id="<abc@example.com>",
            s3_storage=None,
            settings=make_settings(),
        )

        assert await preserver.preserve("example.com") is None

    @pytest.mark.asyncio
    async def test_returns_none_on_failure_when_optional(self):
        """Test an upload failure is swallowed when preservation is not required."""
        storage = AsyncMock(spec=S3Storage)
        storage.upload_raw_message.side_effect = S3UploadError("boom", "key")
        preserver = RawMessagePreserver(
            content=b"raw",
            message_id="<abc@example.com>",
            s3_storage=storage,
            settings=make_settings(preserve_raw_required=False),
        )

        assert await preserver.preserve("example.com") is None

    @pytest.mark.asyncio
    async def test_does_not_retry_after_optional_failure(self):
        """Test a failed upload is not retried for every remaining recipient."""
        storage = AsyncMock(spec=S3Storage)
        storage.upload_raw_message.side_effect = S3UploadError("boom", "key")
        preserver = RawMessagePreserver(
            content=b"raw",
            message_id="<abc@example.com>",
            s3_storage=storage,
            settings=make_settings(preserve_raw_required=False),
        )

        await preserver.preserve("example.com")
        await preserver.preserve("example.com")

        storage.upload_raw_message.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_raises_on_failure_when_required(self):
        """Test an upload failure propagates when preservation is required."""
        storage = AsyncMock(spec=S3Storage)
        storage.upload_raw_message.side_effect = S3UploadError("boom", "key")
        preserver = RawMessagePreserver(
            content=b"raw",
            message_id="<abc@example.com>",
            s3_storage=storage,
            settings=make_settings(preserve_raw_required=True),
        )

        with pytest.raises(S3UploadError):
            await preserver.preserve("example.com")

    @pytest.mark.asyncio
    async def test_raises_when_required_without_storage(self):
        """Test a missing S3 client is an error when preservation is required."""
        preserver = RawMessagePreserver(
            content=b"raw",
            message_id="<abc@example.com>",
            s3_storage=None,
            settings=make_settings(preserve_raw_required=True),
        )

        with pytest.raises(S3UploadError):
            await preserver.preserve("example.com")

    def test_payload_block_describes_stored_object(self, raw_info):
        """Test the webhook payload block exposes the archive location."""
        raw_info.presigned_url = "https://presigned"
        block = RawMessagePreserver.payload_block(raw_info)

        assert block == {
            "storage": "s3",
            "bucket": "test-bucket",
            "key": "raw/example.com/2026/03/07/abc.eml",
            "url": raw_info.url,
            "size": 42,
            "presigned_url": "https://presigned",
        }

    def test_payload_block_omits_absent_presigned_url(self, raw_info):
        """Test the payload block leaves out an unset presigned URL."""
        assert "presigned_url" not in RawMessagePreserver.payload_block(raw_info)


class TestHandlerRawPreservation:
    """Tests for raw preservation inside the SMTP handler."""

    def test_s3_client_initialized_for_inline_attachments(self, postgres_url):
        """Test S3 is available for archiving even when attachments stay inline."""
        settings = Settings(
            database_url=postgres_url,
            root_api_key="test_key_12345",
            attachment_storage="inline",
            s3_bucket="bucket",
            s3_access_key="key",
            s3_secret_key="secret",
        )

        handler = FastSMTPHandler(settings)

        assert handler._s3_storage is not None

    def test_s3_client_absent_without_credentials(self, postgres_url):
        """Test no S3 client is built when S3 is not configured."""
        handler = FastSMTPHandler(
            Settings(database_url=postgres_url, root_api_key="test_key_12345")
        )

        assert handler._s3_storage is None

    @pytest_asyncio.fixture
    async def preserving_domain(self, session_factory):
        """Create a domain that preserves raw messages, with a catch-all recipient."""
        async with session_factory() as session:
            domain = Domain(
                domain_name="archive.example.com",
                is_enabled=True,
                preserve_raw_message=True,
            )
            session.add(domain)
            await session.flush()
            session.add(
                Recipient(
                    domain_id=domain.id,
                    local_part=None,
                    webhook_url="https://webhook.example.com/hook",
                    is_enabled=True,
                )
            )
            await session.commit()
        return domain

    @pytest_asyncio.fixture
    async def plain_domain(self, session_factory):
        """Create a domain that does not preserve raw messages."""
        async with session_factory() as session:
            domain = Domain(
                domain_name="plain.example.com",
                is_enabled=True,
                preserve_raw_message=False,
            )
            session.add(domain)
            await session.flush()
            session.add(
                Recipient(
                    domain_id=domain.id,
                    local_part=None,
                    webhook_url="https://webhook.example.com/hook",
                    is_enabled=True,
                )
            )
            await session.commit()
        return domain

    @pytest.fixture
    def mock_s3(self):
        """Mock S3 storage that succeeds."""
        storage = AsyncMock(spec=S3Storage)
        storage.upload_raw_message.return_value = S3RawMessageInfo(
            bucket="test-bucket",
            key="raw/archive.example.com/2026/03/07/archive-me@external.com.eml",
            url="https://s3.amazonaws.com/test-bucket/raw/archive.example.com/x.eml",
            size=128,
        )
        return storage

    @pytest.mark.asyncio
    async def test_preserving_domain_adds_raw_message_to_payload(
        self, test_settings, preserving_domain, mock_s3, run_smtp_handler
    ):
        """Test payloads for a preserving domain carry the archive location."""
        run = await run_smtp_handler(
            _handler(test_settings, mock_s3), _envelope("user@archive.example.com")
        )

        assert len(run.payloads) == 1
        assert run.payloads[0]["raw_message"]["storage"] == "s3"
        assert run.payloads[0]["raw_message"]["bucket"] == "test-bucket"
        mock_s3.upload_raw_message.assert_awaited_once()
        assert mock_s3.upload_raw_message.await_args.kwargs["content"] == run.raw

    @pytest.mark.asyncio
    async def test_non_preserving_domain_has_no_raw_message(
        self, test_settings, plain_domain, mock_s3, run_smtp_handler
    ):
        """Test payloads for a non-preserving domain are unchanged."""
        run = await run_smtp_handler(
            _handler(test_settings, mock_s3), _envelope("user@plain.example.com")
        )

        assert len(run.payloads) == 1
        assert "raw_message" not in run.payloads[0]
        mock_s3.upload_raw_message.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_single_upload_across_multiple_recipients(
        self, test_settings, preserving_domain, plain_domain, mock_s3, run_smtp_handler
    ):
        """Test one message archived once even with several matching recipients."""
        run = await run_smtp_handler(
            _handler(test_settings, mock_s3),
            _envelope("a@archive.example.com", "b@archive.example.com", "c@plain.example.com"),
        )

        assert len(run.payloads) == 3
        mock_s3.upload_raw_message.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_dropped_message_is_still_archived(
        self, test_settings, preserving_domain, mock_s3, session_factory, run_smtp_handler
    ):
        """Test a rule that drops the message still preserves the raw MIME first."""
        async with session_factory() as session:
            ruleset = RuleSet(
                domain_id=preserving_domain.id,
                name="Archive then drop",
                priority=10,
                is_enabled=True,
            )
            session.add(ruleset)
            await session.flush()
            session.add(
                Rule(
                    ruleset_id=ruleset.id,
                    order=0,
                    field="subject",
                    operator="contains",
                    value="invoice",
                    action="drop",
                    preserve_raw=True,
                )
            )
            await session.commit()

        run = await run_smtp_handler(
            _handler(test_settings, mock_s3),
            _envelope("user@archive.example.com"),
            subject="Quarterly invoice",
        )

        assert run.payloads == []
        mock_s3.upload_raw_message.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_required_preservation_failure_propagates(
        self, test_settings, preserving_domain, run_smtp_handler
    ):
        """Test a required-archive failure aborts the transaction so the sender retries."""
        settings = test_settings.model_copy(
            update={
                "s3_bucket": "bucket",
                "preserve_raw_required": True,
            }
        )
        storage = AsyncMock(spec=S3Storage)
        storage.upload_raw_message.side_effect = S3UploadError("boom", "key")

        with pytest.raises(S3UploadError):
            await run_smtp_handler(
                _handler(settings, storage), _envelope("user@archive.example.com")
            )
