# S3 Attachment Storage Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add optional S3-compatible storage for email attachments with fallback to inline base64.

**Architecture:** When `attachment_storage=s3`, upload attachments to S3 during email processing and include bucket/key metadata in webhook payloads instead of base64 content. Falls back to inline if upload fails.

**Tech Stack:** aiobotocore for async S3 operations, pydantic for config validation, pytest with mocked S3 for unit tests.

---

## Task 1: Add aiobotocore Dependency

**Files:**
- Modify: `pyproject.toml`

**Step 1: Add dependency**

Add to `[project.dependencies]` in pyproject.toml:

```toml
"aiobotocore>=2.9.0",
```

**Step 2: Sync dependencies**

Run: `uv sync`
Expected: Dependencies install successfully

**Step 3: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "chore: add aiobotocore dependency for S3 storage"
```

---

## Task 2: Rename Existing Size Limit Settings

**Files:**
- Modify: `src/fastsmtp/config.py`
- Modify: `src/fastsmtp/smtp/server.py`

**Step 1: Rename settings in config.py**

Change `webhook_max_attachment_size` to `webhook_max_inline_attachment_size`:

```python
webhook_max_inline_attachment_size: int = Field(
    default=10 * 1024 * 1024,  # 10MB
    description="Maximum attachment size to include inline in webhook payload (bytes). "
    "Only applies when attachment_storage='inline'. Larger attachments include metadata only.",
)
webhook_max_inline_payload_size: int = Field(
    default=50 * 1024 * 1024,  # 50MB
    description="Maximum total webhook payload size for inline storage (bytes). "
    "Payloads exceeding this will have body/attachments truncated.",
)
```

**Step 2: Update references in server.py**

Find and replace in `src/fastsmtp/smtp/server.py`:
- `webhook_max_attachment_size` → `webhook_max_inline_attachment_size`
- `webhook_max_payload_size` → `webhook_max_inline_payload_size`

**Step 3: Run tests to verify nothing broke**

Run: `FASTSMTP_ROOT_API_KEY=test123 uv run pytest tests/ -v --tb=short -x`
Expected: All tests pass

**Step 4: Commit**

```bash
git add src/fastsmtp/config.py src/fastsmtp/smtp/server.py
git commit -m "refactor: rename webhook size limits to clarify inline-only scope"
```

---

## Task 3: Add S3 Configuration Settings

**Files:**
- Modify: `src/fastsmtp/config.py`

**Step 1: Add S3 settings after webhook settings**

Add after `webhook_allowed_internal_domains`:

```python
# Attachment Storage
attachment_storage: Literal["inline", "s3"] = Field(
    default="inline",
    description="Storage backend for attachments: 'inline' (base64 in payload) or 's3'",
)
s3_endpoint_url: str | None = Field(
    default=None,
    description="S3 endpoint URL (for MinIO/Ceph). None = AWS default",
)
s3_bucket: str | None = Field(
    default=None,
    description="S3 bucket name for attachments",
)
s3_access_key: SecretStr | None = Field(
    default=None,
    description="S3 access key ID",
)
s3_secret_key: SecretStr | None = Field(
    default=None,
    description="S3 secret access key",
)
s3_region: str = Field(
    default="us-east-1",
    description="S3 region",
)
s3_prefix: str = Field(
    default="attachments",
    description="S3 key prefix for attachments",
)
s3_presigned_urls: bool = Field(
    default=False,
    description="Include presigned URLs in webhook payload",
)
s3_presigned_url_expiry: int = Field(
    default=3600,
    description="Presigned URL expiry in seconds",
)
```

**Step 2: Add Literal import**

Add to imports at top of file:

```python
from typing import Literal
```

**Step 3: Add model validator for S3 config**

Add after the class fields but before `@lru_cache`:

```python
from pydantic import model_validator

# Inside Settings class, at the end:
@model_validator(mode="after")
def validate_s3_config(self) -> "Settings":
    """Validate S3 configuration when attachment_storage is 's3'."""
    if self.attachment_storage == "s3":
        missing = []
        if not self.s3_bucket:
            missing.append("s3_bucket")
        if not self.s3_access_key:
            missing.append("s3_access_key")
        if not self.s3_secret_key:
            missing.append("s3_secret_key")
        if missing:
            raise ValueError(
                f"S3 storage requires: {', '.join(missing)}"
            )
    return self
```

**Step 4: Run tests**

Run: `FASTSMTP_ROOT_API_KEY=test123 uv run pytest tests/test_config.py -v`
Expected: Tests pass

**Step 5: Commit**

```bash
git add src/fastsmtp/config.py
git commit -m "feat: add S3 attachment storage configuration settings"
```

---

## Task 4: Create S3 Storage Module - Data Classes and Exceptions

**Files:**
- Create: `src/fastsmtp/storage/__init__.py`
- Create: `src/fastsmtp/storage/s3.py`

**Step 1: Create storage package init**

Create `src/fastsmtp/storage/__init__.py`:

```python
"""Storage backends for attachments."""

from fastsmtp.storage.s3 import S3AttachmentInfo, S3Storage, S3UploadError

__all__ = ["S3AttachmentInfo", "S3Storage", "S3UploadError"]
```

**Step 2: Create S3 module with data classes**

Create `src/fastsmtp/storage/s3.py`:

```python
"""S3-compatible storage for email attachments."""

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class S3AttachmentInfo:
    """Information about an attachment stored in S3."""

    bucket: str
    key: str
    url: str
    presigned_url: str | None = None


class S3UploadError(Exception):
    """Raised when S3 upload fails."""

    def __init__(self, message: str, filename: str, cause: Exception | None = None):
        self.filename = filename
        self.cause = cause
        super().__init__(message)


def sanitize_key_component(value: str) -> str:
    """Sanitize a string for use in S3 key.

    Removes characters that are problematic in S3 keys.
    """
    # Remove < > and other problematic characters
    sanitized = re.sub(r"[<>\"'\\|?*\x00-\x1f]", "", value)
    # Replace spaces and other whitespace with underscores
    sanitized = re.sub(r"\s+", "_", sanitized)
    # Collapse multiple underscores
    sanitized = re.sub(r"_+", "_", sanitized)
    # Remove leading/trailing underscores
    sanitized = sanitized.strip("_")
    return sanitized or "unnamed"
```

**Step 3: Commit**

```bash
git add src/fastsmtp/storage/
git commit -m "feat: add S3 storage module with data classes and exceptions"
```

---

## Task 5: Write Tests for S3 Key Sanitization

**Files:**
- Create: `tests/test_storage_s3.py`

**Step 1: Write sanitization tests**

Create `tests/test_storage_s3.py`:

```python
"""Tests for S3 storage module."""

import pytest
from fastsmtp.storage.s3 import S3AttachmentInfo, S3UploadError, sanitize_key_component


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
```

**Step 2: Run tests to verify they pass**

Run: `FASTSMTP_ROOT_API_KEY=test123 uv run pytest tests/test_storage_s3.py -v`
Expected: All tests pass

**Step 3: Commit**

```bash
git add tests/test_storage_s3.py
git commit -m "test: add tests for S3 key sanitization and data classes"
```

---

## Task 6: Implement S3Storage Class

**Files:**
- Modify: `src/fastsmtp/storage/s3.py`

**Step 1: Add S3Storage class implementation**

Add to `src/fastsmtp/storage/s3.py` after the existing code:

```python
from typing import TYPE_CHECKING

from aiobotocore.session import get_session

if TYPE_CHECKING:
    from fastsmtp.config import Settings


class S3Storage:
    """Async S3 storage client for attachments."""

    def __init__(self, settings: "Settings"):
        self.settings = settings
        self._session = get_session()

    def _build_key(self, domain: str, message_id: str, filename: str) -> str:
        """Build S3 key for attachment."""
        safe_message_id = sanitize_key_component(message_id)
        safe_filename = sanitize_key_component(filename)
        prefix = self.settings.s3_prefix.strip("/")
        return f"{prefix}/{domain}/{safe_message_id}/{safe_filename}"

    def _build_url(self, key: str) -> str:
        """Build public URL for S3 object."""
        bucket = self.settings.s3_bucket
        if self.settings.s3_endpoint_url:
            endpoint = self.settings.s3_endpoint_url.rstrip("/")
            return f"{endpoint}/{bucket}/{key}"
        else:
            region = self.settings.s3_region
            return f"https://s3.{region}.amazonaws.com/{bucket}/{key}"

    async def upload_attachment(
        self,
        content: bytes,
        domain: str,
        message_id: str,
        filename: str,
        content_type: str,
    ) -> S3AttachmentInfo:
        """Upload attachment to S3.

        Args:
            content: File content as bytes
            domain: Email domain for key path
            message_id: Email Message-ID for key path
            filename: Original filename
            content_type: MIME content type

        Returns:
            S3AttachmentInfo with bucket, key, url, and optional presigned_url

        Raises:
            S3UploadError: If upload fails
        """
        key = self._build_key(domain, message_id, filename)
        bucket = self.settings.s3_bucket

        client_config = {
            "region_name": self.settings.s3_region,
        }
        if self.settings.s3_endpoint_url:
            client_config["endpoint_url"] = self.settings.s3_endpoint_url

        try:
            async with self._session.create_client(
                "s3",
                aws_access_key_id=self.settings.s3_access_key.get_secret_value(),
                aws_secret_access_key=self.settings.s3_secret_key.get_secret_value(),
                **client_config,
            ) as client:
                await client.put_object(
                    Bucket=bucket,
                    Key=key,
                    Body=content,
                    ContentType=content_type,
                )

                presigned_url = None
                if self.settings.s3_presigned_urls:
                    presigned_url = await client.generate_presigned_url(
                        "get_object",
                        Params={"Bucket": bucket, "Key": key},
                        ExpiresIn=self.settings.s3_presigned_url_expiry,
                    )

                logger.info(f"Uploaded attachment {filename} to s3://{bucket}/{key}")

                return S3AttachmentInfo(
                    bucket=bucket,
                    key=key,
                    url=self._build_url(key),
                    presigned_url=presigned_url,
                )

        except Exception as e:
            logger.warning(f"S3 upload failed for {filename}: {e}")
            raise S3UploadError(f"Failed to upload {filename}: {e}", filename, cause=e)
```

**Step 2: Run linting**

Run: `uv run ruff check src/fastsmtp/storage/`
Expected: No errors

**Step 3: Commit**

```bash
git add src/fastsmtp/storage/s3.py
git commit -m "feat: implement S3Storage class with upload and presigned URL support"
```

---

## Task 7: Write Tests for S3Storage with Mocked Client

**Files:**
- Modify: `tests/test_storage_s3.py`

**Step 1: Add S3Storage tests with mocking**

Add to `tests/test_storage_s3.py`:

```python
from unittest.mock import AsyncMock, MagicMock, patch

from fastsmtp.config import Settings
from fastsmtp.storage.s3 import S3Storage


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
        assert url == "https://s3.us-west-2.amazonaws.com/test-bucket/attachments/example.com/abc/file.pdf"

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
```

**Step 2: Run tests**

Run: `FASTSMTP_ROOT_API_KEY=test123 uv run pytest tests/test_storage_s3.py -v`
Expected: All tests pass

**Step 3: Commit**

```bash
git add tests/test_storage_s3.py
git commit -m "test: add unit tests for S3Storage with mocked client"
```

---

## Task 8: Update extract_email_payload to Support S3

**Files:**
- Modify: `src/fastsmtp/smtp/server.py`

**Step 1: Make extract_email_payload async and add S3 support**

Update the function signature and implementation in `src/fastsmtp/smtp/server.py`:

```python
async def extract_email_payload(
    message: Message,
    envelope: Envelope,
    settings: Settings | None = None,
    s3_storage: "S3Storage | None" = None,
    domain: str | None = None,
) -> dict:
    """Extract email content into a webhook payload.

    Args:
        message: Parsed email message
        envelope: SMTP envelope
        settings: Application settings
        s3_storage: S3 storage client (if S3 enabled)
        domain: Email domain for S3 key path
    """
```

For the attachment handling section, replace the existing attachment logic:

```python
if "attachment" in content_disposition:
    # Handle attachment
    filename = part.get_filename() or "unnamed"
    part_payload = part.get_payload(decode=True)
    size = len(part_payload) if isinstance(part_payload, bytes) else 0

    attachment_info: dict[str, Any] = {
        "filename": filename,
        "content_type": content_type,
        "size": size,
    }

    if isinstance(part_payload, bytes) and s3_storage and domain:
        # Upload to S3
        try:
            s3_info = await s3_storage.upload_attachment(
                content=part_payload,
                domain=domain,
                message_id=message.get("Message-ID", "unknown"),
                filename=filename,
                content_type=content_type,
            )
            attachment_info["storage"] = "s3"
            attachment_info["bucket"] = s3_info.bucket
            attachment_info["key"] = s3_info.key
            attachment_info["url"] = s3_info.url
            if s3_info.presigned_url:
                attachment_info["presigned_url"] = s3_info.presigned_url
        except Exception as e:
            # Fallback to inline on S3 failure
            logger.warning(f"S3 upload failed for {filename}, falling back to inline: {e}")
            attachment_info["storage"] = "inline"
            attachment_info["storage_fallback"] = True
            if size <= max_inline_attachment_size:
                attachment_info["content"] = base64.b64encode(part_payload).decode("ascii")
                attachment_info["content_transfer_encoding"] = "base64"
    elif isinstance(part_payload, bytes) and size <= max_inline_attachment_size:
        # Inline storage
        attachment_info["storage"] = "inline"
        attachment_info["content"] = base64.b64encode(part_payload).decode("ascii")
        attachment_info["content_transfer_encoding"] = "base64"
    else:
        # Metadata only (too large for inline, no S3)
        attachment_info["storage"] = "inline"

    attachments.append(attachment_info)
```

**Step 2: Add TYPE_CHECKING import for S3Storage**

Add at top of file:

```python
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastsmtp.storage.s3 import S3Storage
```

**Step 3: Update callers of extract_email_payload to use await**

In `handle_DATA` method, update the call:

```python
# Change from:
payload = extract_email_payload(message, session.envelope, self.settings)

# To:
payload = await extract_email_payload(
    message,
    session.envelope,
    self.settings,
    s3_storage=self._s3_storage if self.settings.attachment_storage == "s3" else None,
    domain=recipient_domain,
)
```

**Step 4: Run tests**

Run: `FASTSMTP_ROOT_API_KEY=test123 uv run pytest tests/test_smtp_server.py -v --tb=short`
Expected: Tests pass (may need minor adjustments)

**Step 5: Commit**

```bash
git add src/fastsmtp/smtp/server.py
git commit -m "feat: integrate S3 storage with extract_email_payload"
```

---

## Task 9: Add S3Storage Initialization to SMTP Server

**Files:**
- Modify: `src/fastsmtp/smtp/server.py`

**Step 1: Add S3Storage initialization in SMTPServer class**

Add to `SMTPServer.__init__`:

```python
# S3 storage client
self._s3_storage: S3Storage | None = None
if self.settings.attachment_storage == "s3":
    try:
        from fastsmtp.storage.s3 import S3Storage
        self._s3_storage = S3Storage(self.settings)
        logger.info("S3 attachment storage initialized")
    except Exception as e:
        logger.error(f"Failed to initialize S3 storage: {e}")
```

**Step 2: Run tests**

Run: `FASTSMTP_ROOT_API_KEY=test123 uv run pytest tests/ -v --tb=short -x`
Expected: All tests pass

**Step 3: Commit**

```bash
git add src/fastsmtp/smtp/server.py
git commit -m "feat: initialize S3Storage in SMTP server when configured"
```

---

## Task 10: Add Config Validation Tests

**Files:**
- Modify: `tests/test_config.py` (or create if not exists)

**Step 1: Add S3 config validation tests**

```python
class TestS3ConfigValidation:
    """Tests for S3 configuration validation."""

    def test_s3_storage_requires_bucket(self):
        """Test that S3 storage requires bucket."""
        with pytest.raises(ValueError, match="s3_bucket"):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                root_api_key="test_key_12345",
                attachment_storage="s3",
                s3_access_key="key",
                s3_secret_key="secret",
            )

    def test_s3_storage_requires_access_key(self):
        """Test that S3 storage requires access key."""
        with pytest.raises(ValueError, match="s3_access_key"):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                root_api_key="test_key_12345",
                attachment_storage="s3",
                s3_bucket="bucket",
                s3_secret_key="secret",
            )

    def test_s3_storage_requires_secret_key(self):
        """Test that S3 storage requires secret key."""
        with pytest.raises(ValueError, match="s3_secret_key"):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                root_api_key="test_key_12345",
                attachment_storage="s3",
                s3_bucket="bucket",
                s3_access_key="key",
            )

    def test_s3_storage_valid_config(self):
        """Test valid S3 configuration."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            attachment_storage="s3",
            s3_bucket="my-bucket",
            s3_access_key="access-key",
            s3_secret_key="secret-key",
        )
        assert settings.attachment_storage == "s3"
        assert settings.s3_bucket == "my-bucket"

    def test_inline_storage_no_s3_required(self):
        """Test inline storage doesn't require S3 config."""
        settings = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_key_12345",
            attachment_storage="inline",
        )
        assert settings.attachment_storage == "inline"
```

**Step 2: Run tests**

Run: `FASTSMTP_ROOT_API_KEY=test123 uv run pytest tests/test_config.py -v`
Expected: All tests pass

**Step 3: Commit**

```bash
git add tests/test_config.py
git commit -m "test: add S3 configuration validation tests"
```

---

## Task 11: Add SMTP Server Tests with S3 Storage

**Files:**
- Modify: `tests/test_smtp_server.py` or `tests/test_smtp_server_extended.py`

**Step 1: Add test for attachment with S3 storage**

```python
@pytest.mark.asyncio
async def test_extract_email_payload_s3_attachment():
    """Test email payload extraction with S3 storage."""
    from email.message import EmailMessage
    from unittest.mock import AsyncMock, patch

    from aiosmtpd.smtp import Envelope

    from fastsmtp.config import Settings
    from fastsmtp.smtp.server import extract_email_payload
    from fastsmtp.storage.s3 import S3AttachmentInfo, S3Storage

    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        root_api_key="test123",
        attachment_storage="s3",
        s3_bucket="test-bucket",
        s3_access_key="key",
        s3_secret_key="secret",
    )

    # Create email with attachment
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test with attachment"
    msg["Message-ID"] = "<test123@example.com>"
    msg.set_content("Body text")
    msg.add_attachment(
        b"PDF content here",
        maintype="application",
        subtype="pdf",
        filename="report.pdf",
    )

    envelope = Envelope()
    envelope.mail_from = "sender@example.com"
    envelope.rcpt_tos = ["recipient@example.com"]

    # Mock S3 storage
    mock_s3 = AsyncMock(spec=S3Storage)
    mock_s3.upload_attachment.return_value = S3AttachmentInfo(
        bucket="test-bucket",
        key="attachments/example.com/test123/report.pdf",
        url="https://s3.amazonaws.com/test-bucket/attachments/example.com/test123/report.pdf",
        presigned_url=None,
    )

    payload = await extract_email_payload(
        msg, envelope, settings, s3_storage=mock_s3, domain="example.com"
    )

    assert len(payload["attachments"]) == 1
    att = payload["attachments"][0]
    assert att["storage"] == "s3"
    assert att["bucket"] == "test-bucket"
    assert "key" in att
    assert "url" in att
    assert "content" not in att  # No inline content


@pytest.mark.asyncio
async def test_extract_email_payload_s3_fallback():
    """Test email payload falls back to inline when S3 fails."""
    from email.message import EmailMessage
    from unittest.mock import AsyncMock

    from aiosmtpd.smtp import Envelope

    from fastsmtp.config import Settings
    from fastsmtp.smtp.server import extract_email_payload
    from fastsmtp.storage.s3 import S3Storage, S3UploadError

    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        root_api_key="test123",
        attachment_storage="s3",
        s3_bucket="test-bucket",
        s3_access_key="key",
        s3_secret_key="secret",
    )

    # Create email with attachment
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test"
    msg["Message-ID"] = "<test@example.com>"
    msg.set_content("Body")
    msg.add_attachment(b"content", maintype="application", subtype="pdf", filename="file.pdf")

    envelope = Envelope()
    envelope.mail_from = "sender@example.com"
    envelope.rcpt_tos = ["recipient@example.com"]

    # Mock S3 storage to fail
    mock_s3 = AsyncMock(spec=S3Storage)
    mock_s3.upload_attachment.side_effect = S3UploadError("Failed", "file.pdf")

    payload = await extract_email_payload(
        msg, envelope, settings, s3_storage=mock_s3, domain="example.com"
    )

    assert len(payload["attachments"]) == 1
    att = payload["attachments"][0]
    assert att["storage"] == "inline"
    assert att["storage_fallback"] is True
    assert "content" in att
```

**Step 2: Run tests**

Run: `FASTSMTP_ROOT_API_KEY=test123 uv run pytest tests/test_smtp_server.py -v -k attachment`
Expected: Tests pass

**Step 3: Commit**

```bash
git add tests/test_smtp_server.py
git commit -m "test: add SMTP server tests for S3 attachment storage and fallback"
```

---

## Task 12: Run Full Test Suite and Final Commit

**Step 1: Run full test suite**

Run: `FASTSMTP_ROOT_API_KEY=test123 uv run pytest tests/ -v --tb=short`
Expected: All tests pass

**Step 2: Run linting**

Run: `uv run ruff check src/ tests/`
Expected: No errors

**Step 3: Create final feature commit if needed**

```bash
git status
# If any uncommitted changes:
git add -A
git commit -m "feat: complete S3 attachment storage implementation"
```

---

## Summary

After completing all tasks, you will have:

1. **aiobotocore** dependency for async S3 operations
2. **Renamed settings**: `webhook_max_inline_attachment_size`, `webhook_max_inline_payload_size`
3. **New S3 settings**: `attachment_storage`, `s3_bucket`, `s3_access_key`, etc.
4. **S3Storage class** with upload and presigned URL support
5. **Updated extract_email_payload** (now async) with S3 integration
6. **Fallback behavior**: S3 failure → inline with `storage_fallback: true`
7. **Comprehensive tests** for all new functionality

Total estimated tasks: 12
Total estimated commits: 12
