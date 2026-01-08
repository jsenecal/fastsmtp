"""Tests for S3 storage module."""

from unittest.mock import AsyncMock, patch

import pytest
from fastsmtp.config import Settings
from fastsmtp.storage.s3 import (
    S3AttachmentInfo,
    S3Storage,
    S3UploadError,
    sanitize_key_component,
)


class TestSanitizeKeyComponent:
    """Tests for S3 key sanitization."""

    def test_removes_angle_brackets(self):
        """Test that angle brackets are removed from message IDs."""
        result = sanitize_key_component("<abc123@example.com>")
        assert result == "abc123@example.com"

    def test_removes_special_characters(self):
        """Test that special characters are removed."""
        result = sanitize_key_component('file"name|with?special*chars')
        assert result == "filenamewithspecialchars"

    def test_replaces_whitespace_with_underscore(self):
        """Test that whitespace becomes underscores."""
        result = sanitize_key_component("file name with spaces")
        assert result == "file_name_with_spaces"

    def test_collapses_multiple_underscores(self):
        """Test that multiple underscores are collapsed."""
        result = sanitize_key_component("file___name")
        assert result == "file_name"

    def test_strips_leading_trailing_underscores(self):
        """Test that leading/trailing underscores are stripped."""
        result = sanitize_key_component("_filename_")
        assert result == "filename"

    def test_returns_unnamed_for_empty(self):
        """Test that empty strings become 'unnamed'."""
        result = sanitize_key_component("<>")
        assert result == "unnamed"

    def test_preserves_valid_characters(self):
        """Test that valid characters are preserved."""
        result = sanitize_key_component("report-2024.pdf")
        assert result == "report-2024.pdf"


class TestS3AttachmentInfo:
    """Tests for S3AttachmentInfo dataclass."""

    def test_create_without_presigned_url(self):
        """Test creating info without presigned URL."""
        info = S3AttachmentInfo(
            bucket="my-bucket",
            key="attachments/file.pdf",
            url="https://s3.amazonaws.com/my-bucket/attachments/file.pdf",
        )
        assert info.bucket == "my-bucket"
        assert info.key == "attachments/file.pdf"
        assert info.presigned_url is None

    def test_create_with_presigned_url(self):
        """Test creating info with presigned URL."""
        info = S3AttachmentInfo(
            bucket="my-bucket",
            key="attachments/file.pdf",
            url="https://s3.amazonaws.com/my-bucket/attachments/file.pdf",
            presigned_url="https://s3.amazonaws.com/my-bucket/attachments/file.pdf?X-Amz-...",
        )
        assert info.presigned_url is not None


class TestS3UploadError:
    """Tests for S3UploadError exception."""

    def test_error_with_cause(self):
        """Test creating error with underlying cause."""
        cause = ConnectionError("Network error")
        error = S3UploadError("Upload failed", "report.pdf", cause=cause)
        assert error.filename == "report.pdf"
        assert error.cause is cause
        assert "Upload failed" in str(error)

    def test_error_without_cause(self):
        """Test creating error without cause."""
        error = S3UploadError("Upload failed", "report.pdf")
        assert error.filename == "report.pdf"
        assert error.cause is None


class TestS3Storage:
    """Tests for S3Storage class."""

    @pytest.fixture
    def s3_settings(self):
        """Create settings with S3 configured."""
        return Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            attachment_storage="s3",
            s3_bucket="test-bucket",
            s3_access_key="test-access-key",
            s3_secret_key="test-secret-key",
            s3_region="us-west-2",
            s3_prefix="attachments",
        )

    def test_build_key(self, s3_settings):
        """Test S3 key building."""
        storage = S3Storage(s3_settings)
        key = storage._build_key(
            domain="example.com",
            message_id="<abc123@example.com>",
            filename="report.pdf",
        )
        assert key == "attachments/example.com/abc123@example.com/report.pdf"

    def test_build_key_sanitizes_components(self, s3_settings):
        """Test that key components are sanitized."""
        storage = S3Storage(s3_settings)
        key = storage._build_key(
            domain="example.com",
            message_id="<msg with spaces>",
            filename="file|name?.pdf",
        )
        assert "|" not in key
        assert "?" not in key
        assert "<" not in key
        assert ">" not in key

    def test_build_url_aws(self, s3_settings):
        """Test URL building for AWS S3."""
        storage = S3Storage(s3_settings)
        url = storage._build_url("attachments/example.com/abc/file.pdf")
        assert (
            url
            == "https://s3.us-west-2.amazonaws.com/test-bucket/attachments/example.com/abc/file.pdf"
        )

    def test_build_url_custom_endpoint(self):
        """Test URL building for custom endpoint (MinIO/Ceph)."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            attachment_storage="s3",
            s3_bucket="test-bucket",
            s3_access_key="test-access-key",
            s3_secret_key="test-secret-key",
            s3_endpoint_url="https://minio.example.com",
        )
        storage = S3Storage(settings)
        url = storage._build_url("attachments/file.pdf")
        assert url == "https://minio.example.com/test-bucket/attachments/file.pdf"

    @pytest.mark.asyncio
    async def test_upload_attachment_success(self, s3_settings):
        """Test successful attachment upload."""
        storage = S3Storage(s3_settings)

        mock_client = AsyncMock()
        mock_client.put_object = AsyncMock()
        mock_client.generate_presigned_url = AsyncMock(return_value="https://presigned-url")

        with patch.object(storage._session, "create_client") as mock_create:
            mock_create.return_value.__aenter__.return_value = mock_client

            result = await storage.upload_attachment(
                content=b"PDF content here",
                domain="example.com",
                message_id="<abc123@example.com>",
                filename="report.pdf",
                content_type="application/pdf",
            )

            assert result.bucket == "test-bucket"
            assert "example.com" in result.key
            assert "report.pdf" in result.key
            mock_client.put_object.assert_called_once()

    @pytest.mark.asyncio
    async def test_upload_attachment_with_presigned_url(self):
        """Test upload with presigned URL enabled."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            attachment_storage="s3",
            s3_bucket="test-bucket",
            s3_access_key="test-access-key",
            s3_secret_key="test-secret-key",
            s3_presigned_urls=True,
            s3_presigned_url_expiry=7200,
        )
        storage = S3Storage(settings)

        mock_client = AsyncMock()
        mock_client.put_object = AsyncMock()
        mock_client.generate_presigned_url = AsyncMock(
            return_value="https://bucket.s3.amazonaws.com/key?X-Amz-Signature=..."
        )

        with patch.object(storage._session, "create_client") as mock_create:
            mock_create.return_value.__aenter__.return_value = mock_client

            result = await storage.upload_attachment(
                content=b"content",
                domain="example.com",
                message_id="<msg@example.com>",
                filename="file.pdf",
                content_type="application/pdf",
            )

            assert result.presigned_url is not None
            mock_client.generate_presigned_url.assert_called_once()

    @pytest.mark.asyncio
    async def test_upload_attachment_failure(self, s3_settings):
        """Test upload failure raises S3UploadError."""
        storage = S3Storage(s3_settings)

        mock_client = AsyncMock()
        mock_client.put_object = AsyncMock(side_effect=Exception("Network error"))

        with patch.object(storage._session, "create_client") as mock_create:
            mock_create.return_value.__aenter__.return_value = mock_client

            with pytest.raises(S3UploadError) as exc_info:
                await storage.upload_attachment(
                    content=b"content",
                    domain="example.com",
                    message_id="<msg@example.com>",
                    filename="file.pdf",
                    content_type="application/pdf",
                )

            assert exc_info.value.filename == "file.pdf"
            assert exc_info.value.cause is not None
